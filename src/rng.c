/* RNG pool — combines N iso7816 cards with M Infinite Noise TRNGs.
 *
 *   N = ISO7816_CARDS     (compile-time, default 1)
 *   M = INFNOISE_DEVICES  (compile-time, default 0; max 1 — the upstream
 *                          core has process-global state)
 *
 * Behavior:
 *
 *   N + M == 1     pool is a single source, raw passthrough — no SHA3
 *                  post-processing, no libcrypto dependency. The session
 *                  sees the raw GET CHALLENGE bytes (or raw infnoise
 *                  bytes) at full source bandwidth.
 *
 *   N + M >= 2     each output round is built by fetching 32 bytes from
 *                  every source in parallel (one pthread per source) and
 *                  combining via a SHA3-256 chain analogous to infnoise's
 *                  internal SHA3-512 chain:
 *
 *                      S_0       = 0^256
 *                      E         = concat( 32 bytes per source )
 *                      output_i  = SHA3-256( S_i || 0x11 || E )
 *                      S_{i+1}   = SHA3-256( S_i || 0x00 || E )
 *
 * Removal / insertion: each round catches per-source read failures, calls
 * rebind() on the failed slot, and retries serially. rebind() closes the
 * dead source and opens a different reader (or reopens infnoise) that
 * isn't already held by another live slot. If the system genuinely no
 * longer has enough usable sources, rng_read returns an error and the
 * caller can retry later (e.g., once the user reinserts a card).
 */

#define _GNU_SOURCE
#include "rng.h"

#ifndef ISO7816_CARDS
#  define ISO7816_CARDS 0
#endif
#ifndef INFNOISE_DEVICES
#  define INFNOISE_DEVICES 0
#endif

#define POOL_SIZE (ISO7816_CARDS + INFNOISE_DEVICES)

#if POOL_SIZE < 1
#  error "Need at least one source: iso7816_cards or infnoise_devices >= 1"
#endif

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if ISO7816_CARDS > 0
#  include "source_iso7816.h"
#endif
#if INFNOISE_DEVICES > 0
#  include "source_infnoise.h"
#endif

#ifndef ISO7816_INPUT_BYTES
#  define ISO7816_INPUT_BYTES 32u
#endif
#ifndef INFNOISE_INPUT_BYTES
#  define INFNOISE_INPUT_BYTES 32u
#endif

/* SHA3-256 post-processing engages when either the pool combines more
 * than one source, or any source is oversampled (>32 B per round). The
 * latter case fires even with N+M=1: the chain is what compresses the
 * oversampled input down to the 32-byte output round. */
#define ISO_OVERSAMPLED   (ISO7816_CARDS    > 0 && ISO7816_INPUT_BYTES   > 32u)
#define INF_OVERSAMPLED   (INFNOISE_DEVICES > 0 && INFNOISE_INPUT_BYTES  > 32u)

#if POOL_SIZE > 1 || ISO_OVERSAMPLED || INF_OVERSAMPLED
#  define USE_CHAIN 1
#else
#  define USE_CHAIN 0
#endif

#if USE_CHAIN
#  include <openssl/crypto.h>
#  include <openssl/evp.h>
#  define ROUND_BYTES 32u
#endif

#define LOG_PREFIX "p11rand[pool]: "
static int g_debug;
#define LOGD(...) do { if (g_debug) fprintf(stderr, LOG_PREFIX __VA_ARGS__); } while (0)

enum source_kind { SK_ISO7816, SK_INFNOISE };

struct pool_slot {
    enum source_kind kind;
    void            *src;     /* iso7816_source* or infnoise_source* */
    char            *name;    /* owned; reader name or "infnoise" */
};

struct rng_dev {
    struct pool_slot sources[POOL_SIZE];
#if USE_CHAIN
    uint8_t          state[ROUND_BYTES];
#endif
};

/* --- global init / shutdown ------------------------------------------- */

int rng_global_init(void)
{
    if (getenv("P11RAND_DEBUG")) g_debug = 1;

#if ISO7816_CARDS > 0
    if (iso7816_global_init() < 0) return -1;
#endif
#if INFNOISE_DEVICES > 0
    if (infnoise_global_init() < 0) {
#  if ISO7816_CARDS > 0
        iso7816_global_shutdown();
#  endif
        return -1;
    }
#endif
    return 0;
}

void rng_global_shutdown(void)
{
#if INFNOISE_DEVICES > 0
    infnoise_global_shutdown();
#endif
#if ISO7816_CARDS > 0
    iso7816_global_shutdown();
#endif
}

/* --- slot helpers ----------------------------------------------------- */

static void slot_close(struct pool_slot *s)
{
    if (!s->src) {
        free(s->name);
        s->name = NULL;
        return;
    }
    switch (s->kind) {
#if ISO7816_CARDS > 0
        case SK_ISO7816:  iso7816_close(s->src);          break;
#endif
#if INFNOISE_DEVICES > 0
        case SK_INFNOISE: infnoise_source_close(s->src);  break;
#endif
        default: break;
    }
    s->src = NULL;
    free(s->name);
    s->name = NULL;
}

static int slot_read(struct pool_slot *s, uint8_t *buf, size_t n)
{
    if (!s->src) return -1;
    switch (s->kind) {
#if ISO7816_CARDS > 0
        case SK_ISO7816:  return iso7816_read(s->src, buf, n);
#endif
#if INFNOISE_DEVICES > 0
        case SK_INFNOISE: return infnoise_source_read(s->src, buf, n);
#endif
        default:          return -1;
    }
}

/* Returns 1 iff `name` is currently held by a pool slot of kind `kind`
 * other than `skip_idx`. Used by rebind() and fill_pool() to avoid
 * binding the same physical device twice. */
static int name_in_use(const struct pool_slot pool[POOL_SIZE],
                       size_t skip_idx, enum source_kind kind,
                       const char *name)
{
    for (size_t j = 0; j < POOL_SIZE; j++) {
        if (j == skip_idx) continue;
        if (pool[j].kind == kind && pool[j].name &&
            strcmp(pool[j].name, name) == 0)
            return 1;
    }
    return 0;
}

/* --- pool fill / rebind ----------------------------------------------- */

#if ISO7816_CARDS > 0
static int slot_open_iso(struct pool_slot *s, const char *reader)
{
    iso7816_source *src = NULL;
    int rv = iso7816_open(reader, &src);
    if (rv != 0) return rv;
    s->kind = SK_ISO7816;
    s->src  = src;
    s->name = strdup(reader);
    if (!s->name) { iso7816_close(src); s->src = NULL; return -1; }
    return 0;
}
#endif

#if INFNOISE_DEVICES > 0
static int slot_open_inf(struct pool_slot *s, const char *path)
{
    infnoise_source *src = NULL;
    int rv = infnoise_source_open(path, &src);
    if (rv != 0) return rv;
    s->kind = SK_INFNOISE;
    s->src  = src;
    s->name = strdup(path);
    if (!s->name) { infnoise_source_close(src); s->src = NULL; return -1; }
    return 0;
}
#endif

/* Return 0 iff the pool can be filled right now from currently-available
 * devices. Pool is left empty on return; this is the test used by
 * rng_list / rng_probe. */
static int pool_fillable(void)
{
#if ISO7816_CARDS > 0
    char **rdrs = NULL; size_t nrdrs = 0;
    if (iso7816_list_readers(&rdrs, &nrdrs) < 0) return -1;
    size_t usable = 0;
    for (size_t i = 0; i < nrdrs && usable < ISO7816_CARDS; i++) {
        iso7816_source *src = NULL;
        if (iso7816_open(rdrs[i], &src) == 0) { usable++; iso7816_close(src); }
    }
    iso7816_free_readers(rdrs, nrdrs);
    if (usable < ISO7816_CARDS) return 0;
#endif
#if INFNOISE_DEVICES > 0
    char **paths = NULL; size_t npaths = 0;
    if (infnoise_list_devices(&paths, &npaths) < 0) return -1;
    int enough = (npaths >= INFNOISE_DEVICES);
    infnoise_free_devices(paths, npaths);
    if (!enough) return 0;
#endif
    return 1;
}

/* Open a fresh source for slot `idx`, replacing whatever was there.
 * Picks the first reader / FT240X path not currently held by another
 * live slot. */
static int rebind(struct rng_dev *d, size_t idx)
{
    struct pool_slot *s = &d->sources[idx];
    enum source_kind kind = s->kind;
    slot_close(s);
    s->kind = kind;        /* slot_close does not preserve kind */

    int rv = -1;
    char **list = NULL; size_t n = 0;

    switch (kind) {
#if ISO7816_CARDS > 0
    case SK_ISO7816:
        if (iso7816_list_readers(&list, &n) < 0) return -1;
        for (size_t i = 0; i < n; i++) {
            if (name_in_use(d->sources, idx, SK_ISO7816, list[i])) continue;
            if (slot_open_iso(s, list[i]) == 0) { rv = 0; break; }
        }
        iso7816_free_readers(list, n);
        break;
#endif
#if INFNOISE_DEVICES > 0
    case SK_INFNOISE:
        if (infnoise_list_devices(&list, &n) < 0) return -1;
        for (size_t i = 0; i < n; i++) {
            if (name_in_use(d->sources, idx, SK_INFNOISE, list[i])) continue;
            if (slot_open_inf(s, list[i]) == 0) { rv = 0; break; }
        }
        infnoise_free_devices(list, n);
        break;
#endif
    default:
        return -1;
    }

    if (rv == 0) LOGD("rebound slot %zu -> %s\n", idx, s->name);
    else         LOGD("rebind slot %zu: no usable replacement\n", idx);
    return rv;
}

/* Fill all POOL_SIZE slots. Returns 0 on success, -2 if not enough
 * usable sources, -1 on resource error. Slots are left empty on
 * failure. */
static int fill_pool(struct rng_dev *d)
{
    size_t idx = 0;

#if ISO7816_CARDS > 0
    char **rdrs = NULL; size_t nrdrs = 0;
    if (iso7816_list_readers(&rdrs, &nrdrs) < 0) goto fail_resource;

    for (size_t i = 0; i < nrdrs && idx < ISO7816_CARDS; i++) {
        if (slot_open_iso(&d->sources[idx], rdrs[i]) == 0) idx++;
    }
    iso7816_free_readers(rdrs, nrdrs);

    if (idx < ISO7816_CARDS) {
        for (size_t i = 0; i < idx; i++) slot_close(&d->sources[i]);
        return -2;
    }
#endif

#if INFNOISE_DEVICES > 0
    {
        char **paths = NULL; size_t npaths = 0;
        if (infnoise_list_devices(&paths, &npaths) < 0) {
            for (size_t i = 0; i < idx; i++) slot_close(&d->sources[i]);
            return -1;
        }
        size_t got = 0;
        for (size_t i = 0; i < npaths && got < INFNOISE_DEVICES; i++) {
            if (slot_open_inf(&d->sources[idx + got], paths[i]) == 0) got++;
        }
        infnoise_free_devices(paths, npaths);
        if (got < INFNOISE_DEVICES) {
            for (size_t i = 0; i < idx + got; i++) slot_close(&d->sources[i]);
            return -2;
        }
        idx += got;
    }
#endif

    (void)idx;   /* silence warning when only one branch is compiled */
    return 0;

#if ISO7816_CARDS > 0
fail_resource:
    return -1;
#endif
}

/* --- public list / probe / open --------------------------------------- */

static const char *pool_slot_name(void)
{
    static char buf[64];
    if (buf[0]) return buf;
#if ISO7816_CARDS > 0 && INFNOISE_DEVICES > 0
    snprintf(buf, sizeof(buf),
             "rng-pool[iso7816=%d,infnoise=%d]",
             ISO7816_CARDS, INFNOISE_DEVICES);
#elif ISO7816_CARDS > 0
    if (ISO7816_CARDS == 1) snprintf(buf, sizeof(buf), "iso7816");
    else                    snprintf(buf, sizeof(buf),
                                     "rng-pool[iso7816=%d]", ISO7816_CARDS);
#else
    if (INFNOISE_DEVICES == 1) snprintf(buf, sizeof(buf), "infnoise");
    else                       snprintf(buf, sizeof(buf),
                                        "rng-pool[infnoise=%d]",
                                        INFNOISE_DEVICES);
#endif
    return buf;
}

int rng_list(char ***names_out, size_t *count_out)
{
    if (!names_out || !count_out) return -1;
    *names_out = NULL;
    *count_out = 0;

    int ok = pool_fillable();
    if (ok < 0) return -1;
    if (!ok)    return 0;

    char **names = calloc(1, sizeof(*names));
    if (!names) return -1;
    names[0] = strdup(pool_slot_name());
    if (!names[0]) { free(names); return -1; }
    *names_out = names;
    *count_out = 1;
    return 0;
}

void rng_free_names(char **names, size_t count)
{
    if (!names) return;
    for (size_t i = 0; i < count; i++) free(names[i]);
    free(names);
}

int rng_probe(const char *name)
{
    if (!name) return -1;
    if (strcmp(name, pool_slot_name()) != 0) return 0;
    int ok = pool_fillable();
    if (ok < 0) return -1;
    return ok;
}

int rng_open(const char *name, rng_dev **out)
{
    if (!name || !out) return -1;
    if (strcmp(name, pool_slot_name()) != 0) return -2;
    *out = NULL;

    rng_dev *d = calloc(1, sizeof(*d));
    if (!d) return -1;
    int rv = fill_pool(d);
    if (rv != 0) { free(d); return rv; }
    *out = d;
    return 0;
}

void rng_close(rng_dev *d)
{
    if (!d) return;
    for (size_t i = 0; i < POOL_SIZE; i++) slot_close(&d->sources[i]);
#if USE_CHAIN
    OPENSSL_cleanse(d->state, sizeof(d->state));
#endif
    free(d);
}

/* --- pooled read with parallel fan-out -------------------------------- */

#if USE_CHAIN

#define TICK_BYTES 32u  /* SHA3-256 input block per source per tick */

#if ISO7816_CARDS > 0
#  if (ISO7816_INPUT_BYTES % TICK_BYTES) != 0
#    error "ISO7816_INPUT_BYTES must be a multiple of 32"
#  endif
#  define ISO_TICKS (ISO7816_INPUT_BYTES / TICK_BYTES)
#else
#  define ISO_TICKS 0u
#endif

#if INFNOISE_DEVICES > 0
#  if (INFNOISE_INPUT_BYTES % TICK_BYTES) != 0
#    error "INFNOISE_INPUT_BYTES must be a multiple of 32"
#  endif
#  define INF_TICKS (INFNOISE_INPUT_BYTES / TICK_BYTES)
#else
#  define INF_TICKS 0u
#endif

#define MAX_TICKS ((ISO_TICKS > INF_TICKS) ? ISO_TICKS : INF_TICKS)

struct fetch_arg {
    struct pool_slot *s;
    int               rv;
    uint8_t           buf[TICK_BYTES];
};

static void *fetch_thread(void *ap)
{
    struct fetch_arg *a = ap;
    a->rv = slot_read(a->s, a->buf, TICK_BYTES);
    return NULL;
}

/* Number of TICK_BYTES-sized chunks slot `i` contributes per round. */
static unsigned slot_ticks(size_t i)
{
#if ISO7816_CARDS > 0
    if (i < ISO7816_CARDS) return ISO_TICKS;
#else
    (void)i;
#endif
    return INF_TICKS;
}

/* Build one ROUND_BYTES output round.
 *
 * Per round: MAX_TICKS ticks. On each tick we spawn one worker per
 * source whose own quota for the round is not yet exhausted; each
 * worker fetches exactly TICK_BYTES into its 32-byte scratch. We
 * pthread_join in slot index order and absorb each scratch into both
 * SHA3-256 contexts (output, state-update) immediately, in slot order,
 * then proceed to the next tick. Sources that fail mid-round are
 * rebound from currently-available devices and the failed tick is
 * retried serially before moving on.
 *
 * Absorption order is tick-major:
 *
 *     E_round = concat over t in 0..MAX_TICKS-1
 *                  over slot i in 0..POOL_SIZE-1 with slot_ticks(i) > t
 *                  of the t-th 32-byte fetch from slot i
 *
 * That ordering is a deliberate consequence of keeping the per-thread
 * scratch at TICK_BYTES regardless of oversample factor — buffering a
 * slot's full per-round contribution would defeat the small-buffer
 * goal. SHA3 is order-sensitive, so this changes byte-for-byte output
 * vs. a slot-major absorption; entropy preservation is unaffected.
 *
 * Total scratch footprint per round: POOL_SIZE * TICK_BYTES, plus
 * two EVP_MD_CTX, regardless of how aggressively each source is
 * oversampled. */
static int do_round_chain(struct rng_dev *d, uint8_t out[ROUND_BYTES])
{
    EVP_MD_CTX *ctx_out   = EVP_MD_CTX_new();
    EVP_MD_CTX *ctx_state = EVP_MD_CTX_new();
    int rv = -1;
    if (!ctx_out || !ctx_state) goto done;

    if (EVP_DigestInit_ex(ctx_out,   EVP_sha3_256(), NULL) != 1 ||
        EVP_DigestInit_ex(ctx_state, EVP_sha3_256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx_out,   d->state, ROUND_BYTES) != 1 ||
        EVP_DigestUpdate(ctx_state, d->state, ROUND_BYTES) != 1)
        goto done;

    static const uint8_t tag_out_v   = 0x11;
    static const uint8_t tag_state_v = 0x00;
    if (EVP_DigestUpdate(ctx_out,   &tag_out_v,   1) != 1 ||
        EVP_DigestUpdate(ctx_state, &tag_state_v, 1) != 1)
        goto done;

    pthread_t        threads[POOL_SIZE];
    struct fetch_arg args[POOL_SIZE];
    int              spawned[POOL_SIZE];

    for (size_t i = 0; i < POOL_SIZE; i++) args[i].s = &d->sources[i];

    for (unsigned t = 0; t < MAX_TICKS; t++) {
        /* Fan out: one worker per source still owing bytes this round. */
        for (size_t i = 0; i < POOL_SIZE; i++) {
            spawned[i] = 0;
            if (t >= slot_ticks(i)) continue;
            args[i].rv = -1;
            spawned[i] = pthread_create(&threads[i], NULL,
                                        fetch_thread, &args[i]) == 0;
            if (!spawned[i]) {
                /* pthread_create exhaustion is rare; degrade to inline. */
                args[i].rv = slot_read(args[i].s, args[i].buf, TICK_BYTES);
            }
        }

        /* Join + absorb in slot index order. SHA3 is order-sensitive,
         * so the join order is what defines the chain ordering. */
        for (size_t i = 0; i < POOL_SIZE; i++) {
            if (t >= slot_ticks(i)) continue;
            if (spawned[i]) pthread_join(threads[i], NULL);
            if (args[i].rv != 0) {
                LOGD("source %zu (%s) tick %u failed; rebinding\n",
                     i, d->sources[i].name ? d->sources[i].name : "?", t);
                if (rebind(d, i) < 0) goto cleanse;
                args[i].s = &d->sources[i];
                if (slot_read(args[i].s, args[i].buf, TICK_BYTES) < 0)
                    goto cleanse;
            }
            if (EVP_DigestUpdate(ctx_out,   args[i].buf, TICK_BYTES) != 1 ||
                EVP_DigestUpdate(ctx_state, args[i].buf, TICK_BYTES) != 1)
                goto cleanse;
        }
    }

    unsigned int n;
    if (EVP_DigestFinal_ex(ctx_out,   out,      &n) != 1 || n != ROUND_BYTES) goto cleanse;
    if (EVP_DigestFinal_ex(ctx_state, d->state, &n) != 1 || n != ROUND_BYTES) goto cleanse;
    rv = 0;

cleanse:
    OPENSSL_cleanse(args, sizeof args);
done:
    if (ctx_out)   EVP_MD_CTX_free(ctx_out);
    if (ctx_state) EVP_MD_CTX_free(ctx_state);
    return rv;
}

int rng_read(rng_dev *d, uint8_t *buf, size_t len)
{
    if (!d || (!buf && len)) return -1;

    uint8_t out[ROUND_BYTES];
    while (len) {
        if (do_round_chain(d, out) < 0) {
            OPENSSL_cleanse(out, sizeof out);
            return -1;
        }
        size_t take = (len < ROUND_BYTES) ? len : ROUND_BYTES;
        memcpy(buf, out, take);
        buf += take;
        len -= take;
    }
    OPENSSL_cleanse(out, sizeof out);
    return 0;
}

#else  /* !USE_CHAIN: single source, no oversampling, raw passthrough */

int rng_read(rng_dev *d, uint8_t *buf, size_t len)
{
    if (!d || (!buf && len)) return -1;
    /* Single-source raw mode: rebind on failure, retry once, then bubble up. */
    if (slot_read(&d->sources[0], buf, len) == 0) return 0;
    LOGD("source 0 (%s) failed; rebinding\n",
         d->sources[0].name ? d->sources[0].name : "?");
    if (rebind(d, 0) < 0) return -1;
    return slot_read(&d->sources[0], buf, len);
}

#endif /* USE_CHAIN */

/* --- backend identification ------------------------------------------- */

const char *rng_backend_label(void)
{
#if !USE_CHAIN
#  if ISO7816_CARDS == 1
    return "GET CHALLENGE RNG";
#  else
    return "Infinite Noise TRNG";
#  endif
#else
    static char buf[33];
    if (buf[0]) return buf;
#  if ISO7816_CARDS > 0 && INFNOISE_DEVICES > 0
    snprintf(buf, sizeof(buf), "%dx iso7816 + %dx inf + SHA3",
             ISO7816_CARDS, INFNOISE_DEVICES);
#  elif ISO7816_CARDS > 0
    snprintf(buf, sizeof(buf), "%dx iso7816 + SHA3-256", ISO7816_CARDS);
#  else
    snprintf(buf, sizeof(buf), "%dx infnoise + SHA3-256", INFNOISE_DEVICES);
#  endif
    return buf;
#endif
}

const char *rng_backend_model(void)
{
#if !USE_CHAIN && ISO7816_CARDS == 1
    return "ISO7816-RNG";
#elif !USE_CHAIN
    return "INFNOISE";
#else
    return "RNG-POOL";
#endif
}
