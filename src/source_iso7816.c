/* iso7816 source: PC/SC + ISO 7816-4 GET CHALLENGE.
 *
 * On open we probe applets in this order: Yubikey PIV, OpenPGP (Nitrokey
 * 3, OpenPGP cards), then bare card. CTAP2 has no standard GetRandom,
 * so FIDO2 tokens are reached via their CCID/PC/SC interface.
 *
 * The PC/SC user context is process-wide and refcounted across multiple
 * sessions. SCardConnect / SCardTransmit can be called concurrently from
 * different threads as long as each thread holds its own SCARDHANDLE,
 * which is what the pool layer arranges (one source per thread per
 * round). */

#define _GNU_SOURCE
#include "source_iso7816.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>

#define LOG_PREFIX "p11rand[iso7816]: "
static int g_debug;
#define LOGD(...) do { if (g_debug) fprintf(stderr, LOG_PREFIX __VA_ARGS__); } while (0)
#define LOGE(...) do { fprintf(stderr, LOG_PREFIX __VA_ARGS__); } while (0)

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static SCARDCONTEXT    g_ctx;
static int             g_ctx_refs;

typedef enum {
    APP_UNKNOWN = 0,
    APP_PIV,
    APP_OPENPGP,
    APP_NONE,
} app_id;

struct iso7816_source {
    SCARDHANDLE h;
    DWORD       proto;
    app_id      app;
    /* Largest GET CHALLENGE Le the card has accepted so far. Some cards
     * (notably some ID and transport cards) cap the challenge at well
     * below the 255-byte short-Le maximum and reject larger requests
     * with SW=6700 (wrong length) or SW=6Cxx. We start optimistic and
     * halve on rejection in iso7816_read; the learned value sticks for
     * the lifetime of the source. */
    size_t      max_chunk;
};

int iso7816_global_init(void)
{
    if (getenv("P11RAND_DEBUG")) g_debug = 1;
    pthread_mutex_lock(&g_lock);
    if (g_ctx_refs > 0) { g_ctx_refs++; pthread_mutex_unlock(&g_lock); return 0; }
    LONG rv = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &g_ctx);
    if (rv != SCARD_S_SUCCESS) {
        pthread_mutex_unlock(&g_lock);
        LOGE("SCardEstablishContext failed: 0x%lx\n", (unsigned long)rv);
        return -1;
    }
    g_ctx_refs = 1;
    pthread_mutex_unlock(&g_lock);
    return 0;
}

void iso7816_global_shutdown(void)
{
    pthread_mutex_lock(&g_lock);
    if (g_ctx_refs == 0) { pthread_mutex_unlock(&g_lock); return; }
    if (--g_ctx_refs == 0) { SCardReleaseContext(g_ctx); g_ctx = 0; }
    pthread_mutex_unlock(&g_lock);
}

/* --- per-card APDU helpers --------------------------------------------- */

static int xmit(iso7816_source *c,
                const uint8_t *capdu, size_t capdu_len,
                uint8_t *resp, size_t *resp_len)
{
    SCARD_IO_REQUEST send_pci;
    if (c->proto == SCARD_PROTOCOL_T1)      send_pci = *SCARD_PCI_T1;
    else if (c->proto == SCARD_PROTOCOL_T0) send_pci = *SCARD_PCI_T0;
    else                                    send_pci = *SCARD_PCI_RAW;

    DWORD rl = (DWORD)*resp_len;
    LONG rv = SCardTransmit(c->h, &send_pci, capdu, (DWORD)capdu_len,
                            NULL, resp, &rl);
    if (rv != SCARD_S_SUCCESS) {
        LOGE("SCardTransmit failed: 0x%lx\n", (unsigned long)rv);
        return -1;
    }
    *resp_len = rl;
    return 0;
}

static unsigned sw_of(const uint8_t *resp, size_t n)
{
    return n < 2 ? 0 : (((unsigned)resp[n - 2] << 8) | resp[n - 1]);
}

static int select_aid(iso7816_source *c, const uint8_t *aid, size_t aid_len)
{
    uint8_t apdu[5 + 32];
    if (aid_len > sizeof(apdu) - 5) return -1;
    apdu[0] = 0x00; apdu[1] = 0xA4; apdu[2] = 0x04; apdu[3] = 0x00;
    apdu[4] = (uint8_t)aid_len;
    memcpy(apdu + 5, aid, aid_len);

    uint8_t resp[258];
    size_t  rl = sizeof(resp);
    if (xmit(c, apdu, 5 + aid_len, resp, &rl) < 0) return -1;
    unsigned sw = sw_of(resp, rl);
    LOGD("SELECT AID -> SW=%04X\n", sw);
    return (sw == 0x9000 || (sw & 0xFF00) == 0x6100) ? 0 : 1;
}

/* GET CHALLENGE for n bytes (1..255). Returns n on success, -2 on
 * SW != 9000, -1 on transport. */
static int try_get_challenge(iso7816_source *c, size_t n, uint8_t *out)
{
    if (n == 0 || n > 255) return -1;
    uint8_t apdu[5] = { 0x00, 0x84, 0x00, 0x00, (uint8_t)n };
    uint8_t resp[256 + 2];
    size_t  rl = sizeof(resp);
    if (xmit(c, apdu, sizeof(apdu), resp, &rl) < 0) return -1;
    unsigned sw = sw_of(resp, rl);
    if (sw != 0x9000 || rl - 2 != n) {
        LOGD("GET CHALLENGE(%zu) -> SW=%04X len=%zu\n", n, sw, rl - 2);
        return -2;
    }
    memcpy(out, resp, n);
    return (int)n;
}

static const struct {
    app_id  app;
    uint8_t aid[16];
    size_t  aid_len;
} k_apps[] = {
    { APP_PIV,
      { 0xA0,0x00,0x00,0x03,0x08,0x00,0x00,0x10,0x00,0x01,0x00 }, 11 },
    { APP_OPENPGP,
      { 0xD2,0x76,0x00,0x01,0x24,0x01 }, 6 },
};

static int probe_app(iso7816_source *c)
{
    uint8_t throwaway[8];

    /* Try GET CHALLENGE on the card's default selection first.
     * SCardConnect powers the card up with the master file selected on
     * most ISO 7816-4 implementations; plain identity / transport /
     * insurance cards typically support GET CHALLENGE there directly,
     * and skipping the SELECT dance avoids leaving the card in an
     * applet-specific state when no applet matches. */
    if (try_get_challenge(c, sizeof(throwaway), throwaway) > 0) {
        c->app = APP_NONE;
        return 0;
    }

    /* Fall back to applet-specific paths for tokens that don't expose
     * GET CHALLENGE on their default applet (Yubikey CM, etc.). */
    for (size_t i = 0; i < sizeof(k_apps) / sizeof(k_apps[0]); i++) {
        int rv = select_aid(c, k_apps[i].aid, k_apps[i].aid_len);
        if (rv < 0) return -1;
        if (rv != 0) continue;
        if (try_get_challenge(c, sizeof(throwaway), throwaway) > 0) {
            c->app = k_apps[i].app;
            return 0;
        }
    }

    LOGD("card does not support GET CHALLENGE on default/PIV/OpenPGP\n");
    c->app = APP_UNKNOWN;
    return -1;
}

/* Distinguish "no card / removed / unpowered" from a real transport error. */
static int connect_card_raw(const char *reader, iso7816_source *c)
{
    LONG rv = SCardConnect(g_ctx, reader, SCARD_SHARE_SHARED,
                           SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                           &c->h, &c->proto);
    if (rv == SCARD_S_SUCCESS) return 0;
    if (rv == (LONG)SCARD_E_NO_SMARTCARD ||
        rv == (LONG)SCARD_W_REMOVED_CARD ||
        rv == (LONG)SCARD_W_UNPOWERED_CARD ||
        rv == (LONG)SCARD_W_UNRESPONSIVE_CARD) {
        LOGD("SCardConnect(%s): no card (0x%lx)\n", reader, (unsigned long)rv);
        return 1;
    }
    LOGE("SCardConnect(%s) failed: 0x%lx\n", reader, (unsigned long)rv);
    return -1;
}

int iso7816_open(const char *reader, iso7816_source **out)
{
    if (!reader || !out) return -1;
    *out = NULL;

    iso7816_source *c = calloc(1, sizeof(*c));
    if (!c) return -1;
    /* Largest power of two that fits in the APDU short-Le field. Starting
     * here (rather than at 255) keeps subsequent halvings on power-of-two
     * boundaries, so cards that only accept exactly 8 / 16 / 32-byte
     * challenges converge to a working chunk instead of overshooting
     * (255 → 127 → 63 → 31 → 15 → 7 misses 8 entirely). */
    c->max_chunk = 128;

    int crv = connect_card_raw(reader, c);
    if (crv != 0) {
        free(c);
        return crv > 0 ? -2 : -1;     /* -2 = empty reader, -1 = error */
    }
    if (probe_app(c) < 0) {
        SCardDisconnect(c->h, SCARD_LEAVE_CARD);
        free(c);
        return -3;                    /* card present, unsupported */
    }
    *out = c;
    return 0;
}

void iso7816_close(iso7816_source *c)
{
    if (!c) return;
    SCardDisconnect(c->h, SCARD_LEAVE_CARD);
    free(c);
}

int iso7816_read_atr(const char *reader, char *out, size_t cap)
{
    if (!reader || !out || cap == 0) return -1;
    out[0] = '\0';

    SCARDHANDLE h;
    DWORD       proto;
    LONG rv = SCardConnect(g_ctx, reader, SCARD_SHARE_SHARED,
                           SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                           &h, &proto);
    if (rv != SCARD_S_SUCCESS) return -1;

    DWORD   state, atr_len = MAX_ATR_SIZE;
    BYTE    atr[MAX_ATR_SIZE];
    char    nm_buf[256];
    DWORD   nm_len = sizeof nm_buf;
    rv = SCardStatus(h, nm_buf, &nm_len, &state, &proto, atr, &atr_len);
    SCardDisconnect(h, SCARD_LEAVE_CARD);
    if (rv != SCARD_S_SUCCESS || atr_len == 0) return -1;

    /* "XX " per byte except no trailing space, plus NUL → 3*N bytes. */
    if ((size_t)atr_len * 3 > cap) return -1;

    size_t off = 0;
    for (DWORD i = 0; i < atr_len; i++) {
        const char *sep = (i + 1 < atr_len) ? " " : "";
        int n = snprintf(out + off, cap - off, "%02X%s", atr[i], sep);
        if (n < 0 || (size_t)n >= cap - off) return -1;
        off += (size_t)n;
    }
    return 0;
}

int iso7816_read(iso7816_source *c, uint8_t *buf, size_t n)
{
    if (!c || (!buf && n)) return -1;

    /* The card's accepted Le is unknown on the first call; we start at
     * a power-of-two upper bound (max_chunk = 128) and halve on every
     * SW != 9000 response until something works. The learned size is
     * sticky on the source.
     *
     * Some cards (notably some national-ID cards) require a *fixed*
     * Le rather than a maximum: GET CHALLENGE(8) is the only accepted
     * form, and a tail less than max_chunk is rejected. We handle that
     * by always issuing exactly max_chunk bytes — fetching into a
     * stack scratch when the caller wants fewer — and discarding the
     * over-shoot. The cost is at most max_chunk-1 extra random bytes
     * per logical read; for an 8-byte fixed-Le card that's negligible.
     *
     * The discard is deliberate: over-fetched bytes are not preserved
     * across reads. Carrying state forward would require another path
     * for invalidating it on session close / rebind, and the savings
     * are small enough not to be worth it. */
    while (n) {
        if (c->max_chunk == 0) return -1;
        size_t chunk = c->max_chunk;
        int    truncating = (n < chunk);
        uint8_t  scratch[256];
        uint8_t *target = truncating ? scratch : buf;

        int rv = try_get_challenge(c, chunk, target);
        if (rv > 0) {
            if (truncating) {
                memcpy(buf, scratch, n);
                buf += n;
                n = 0;
            } else {
                buf += chunk;
                n -= chunk;
            }
            continue;
        }
        if (rv != -2) return -1;        /* hard transport error */

        /* SW != 9000 — halve max_chunk and retry on the next loop. */
        if (c->max_chunk > 1) {
            c->max_chunk /= 2;
            LOGD("card refused GET CHALLENGE(%zu); narrowing chunk to %zu\n",
                 chunk, c->max_chunk);
            continue;
        }
        return -1;
    }
    return 0;
}

/* --- reader enumeration ------------------------------------------------ */

int iso7816_list_readers(char ***names_out, size_t *count_out)
{
    if (!names_out || !count_out) return -1;
    *names_out = NULL;
    *count_out = 0;

    DWORD len = 0;
    LONG rv = SCardListReaders(g_ctx, NULL, NULL, &len);
    if (rv == SCARD_E_NO_READERS_AVAILABLE || len <= 1) return 0;
    if (rv != SCARD_S_SUCCESS) {
        LOGE("SCardListReaders(size) failed: 0x%lx\n", (unsigned long)rv);
        return -1;
    }

    char *buf = malloc(len);
    if (!buf) return -1;
    rv = SCardListReaders(g_ctx, NULL, buf, &len);
    if (rv != SCARD_S_SUCCESS) {
        free(buf);
        LOGE("SCardListReaders failed: 0x%lx\n", (unsigned long)rv);
        return -1;
    }

    size_t n = 0;
    for (const char *p = buf; *p; p += strlen(p) + 1) n++;

    char **names = calloc(n ? n : 1, sizeof(*names));
    if (!names) { free(buf); return -1; }

    size_t i = 0;
    for (const char *p = buf; *p; p += strlen(p) + 1) {
        names[i] = strdup(p);
        if (!names[i]) {
            for (size_t j = 0; j < i; j++) free(names[j]);
            free(names);
            free(buf);
            return -1;
        }
        i++;
    }
    free(buf);

    *names_out = names;
    *count_out = n;
    return 0;
}

void iso7816_free_readers(char **names, size_t count)
{
    if (!names) return;
    for (size_t i = 0; i < count; i++) free(names[i]);
    free(names);
}
