/*
 * p11rand-read — pipe random bytes from a PKCS#11 module to stdout.
 *
 * Loads the module, opens a session on the first usable slot, and
 * writes the result of C_GenerateRandom to stdout. Default 32 bytes
 * raw; -n N for a specific length, -n 0 for an open-ended stream
 * (until SIGINT or stdout closes), -x for lowercase hex output.
 *
 * Pair with p11rand-wait if your sources may not be present yet:
 *     p11rand-wait /usr/local/lib/libp11rand.so.0 \
 *         && p11rand-read -n 64 /usr/local/lib/libp11rand.so.0 | xxd
 *
 * Usage:
 *     p11rand-read [-n BYTES] [-x] [-q] <module.so>
 *
 *       -n BYTES      total bytes to output; default 32. Use 0 for
 *                     an open-ended stream until SIGINT or stdout
 *                     closes (e.g. piped through `head -c`).
 *       -x            lowercase hex output, one continuous string
 *                     followed by a single trailing newline.
 *       -q            quiet — suppress informational stderr lines.
 *
 * Cancellation:
 *     The first SIGINT (Ctrl-C) or SIGTERM lets the current 256-byte
 *     C_GenerateRandom call finish, then the loop exits cleanly so
 *     PC/SC and infnoise resources get released. A second signal
 *     short-circuits the process with _exit(130) — useful when a
 *     misbehaving card has the in-flight SCardTransmit stuck waiting
 *     for a timeout.
 *
 * Exit status:
 *     0    requested bytes delivered, or stream cleanly interrupted
 *          (SIGINT / SIGTERM / stdout closed).
 *     1    fatal runtime failure (no slot, C_GenerateRandom error,
 *          write error not caused by EPIPE).
 *     2    command-line / module-load error.
 *     130  forced exit from a second signal during graceful shutdown.
 */

#define _POSIX_C_SOURCE 200809L

#include "../include/pkcs11.h"

#include <dlfcn.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_quiet;
static int g_hex;
static volatile sig_atomic_t g_stop;

/* Two-strikes signal handling. The first SIGINT / SIGTERM sets g_stop
 * and lets the current C_GenerateRandom call finish before exiting
 * cleanly — important so OPENSSL/PCSC state and the per-source flock
 * get released. The second signal short-circuits with _exit(130),
 * giving the user a guaranteed escape from a stuck / very slow card
 * without having to reach for SIGKILL. */
static void on_signal(int sig)
{
    (void)sig;
    if (g_stop) _exit(130);
    g_stop = 1;
}

static void info(const char *fmt, ...)
{
    if (g_quiet) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s [-n BYTES] [-x] [-q] <module.so>\n"
        "  -n BYTES   total bytes to output; default 32; 0 = open-ended stream\n"
        "  -x         lowercase hex output (one continuous string + newline)\n"
        "  -q         quiet — no informational stderr\n",
        argv0);
}

/* write(2) loop that retries on EINTR. Returns 0 success, -1 on real
 * write error, -2 on EPIPE (stdout closed; clean exit). */
static int write_full(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            if (errno == EPIPE) return -2;
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static int write_hex(int fd, const uint8_t *buf, size_t n)
{
    static const char H[] = "0123456789abcdef";
    char tmp[1024];
    size_t off = 0;
    for (size_t i = 0; i < n; i++) {
        if (off + 2 > sizeof tmp) {
            int rv = write_full(fd, tmp, off);
            if (rv != 0) return rv;
            off = 0;
        }
        tmp[off++] = H[buf[i] >> 4];
        tmp[off++] = H[buf[i] & 0xf];
    }
    if (off) return write_full(fd, tmp, off);
    return 0;
}

int main(int argc, char **argv)
{
    long long n_total = 32;     /* -1 = open-ended stream */

    int opt;
    while ((opt = getopt(argc, argv, "n:xqh")) != -1) {
        switch (opt) {
        case 'n': {
            char *end = NULL;
            long long v = strtoll(optarg, &end, 10);
            if (end == optarg || v < 0) {
                fprintf(stderr, "invalid -n value: %s\n", optarg);
                return 2;
            }
            n_total = (v == 0) ? -1 : v;
            break;
        }
        case 'x': g_hex   = 1; break;
        case 'q': g_quiet = 1; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 2;
        }
    }
    if (optind >= argc) { usage(argv[0]); return 2; }
    const char *module = argv[optind];

    void *h = dlopen(module, RTLD_NOW);
    if (!h) {
        fprintf(stderr, "dlopen %s: %s\n", module, dlerror());
        return 2;
    }
    CK_RV (*GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
    *(void **)&GetFunctionList = dlsym(h, "C_GetFunctionList");
    if (!GetFunctionList) {
        fprintf(stderr, "dlsym C_GetFunctionList: %s\n", dlerror());
        return 2;
    }
    CK_FUNCTION_LIST_PTR f = NULL;
    if (GetFunctionList(&f) != CKR_OK || !f) {
        fprintf(stderr, "C_GetFunctionList failed\n");
        return 2;
    }
    if (f->C_Initialize(NULL) != CKR_OK) {
        fprintf(stderr, "C_Initialize failed\n");
        return 2;
    }

    CK_ULONG nslots = 0;
    if (f->C_GetSlotList(CK_TRUE, NULL, &nslots) != CKR_OK || nslots == 0) {
        fprintf(stderr, "no usable PKCS#11 slot — pool not fillable yet?\n");
        f->C_Finalize(NULL); dlclose(h);
        return 1;
    }
    CK_SLOT_ID *slots = calloc(nslots, sizeof(*slots));
    if (!slots) { f->C_Finalize(NULL); dlclose(h); return 1; }
    if (f->C_GetSlotList(CK_TRUE, slots, &nslots) != CKR_OK) {
        fprintf(stderr, "C_GetSlotList failed\n");
        free(slots); f->C_Finalize(NULL); dlclose(h);
        return 1;
    }
    CK_SLOT_ID slot = slots[0];
    free(slots);

    CK_SESSION_HANDLE sess = 0;
    if (f->C_OpenSession(slot, CKF_SERIAL_SESSION,
                         NULL, NULL, &sess) != CKR_OK) {
        fprintf(stderr, "C_OpenSession failed\n");
        f->C_Finalize(NULL); dlclose(h);
        return 1;
    }

    /* If stdout is a pipe and the consumer closes early, write(2) sees
     * EPIPE; without ignoring SIGPIPE the kernel kills us first. */
    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (n_total < 0)
        info("p11rand-read: streaming %s output (Ctrl-C to stop)\n",
             g_hex ? "hex" : "raw");
    else
        info("p11rand-read: %lld bytes (%s)\n",
             n_total, g_hex ? "hex" : "raw");

    /* Per-call request is intentionally small so SIGINT / SIGTERM take
     * effect within a few hundred milliseconds even during long
     * streams. The C_GenerateRandom inside the module may run several
     * card APDUs / USB cycles; we can't preempt it, but capping the
     * request size to a few SHA3 rounds keeps the worst-case cancel
     * latency bounded by one chunk's worth of I/O instead of one
     * 4 KB chunk's worth. */
    uint8_t buf[256];
    int  exit_rv  = 0;
    long long produced = 0;

    while (!g_stop && (n_total < 0 || produced < n_total)) {
        size_t want = sizeof buf;
        if (n_total >= 0 && (long long)want > n_total - produced)
            want = (size_t)(n_total - produced);

        if (f->C_GenerateRandom(sess, buf, (CK_ULONG)want) != CKR_OK) {
            if (g_stop) break;
            fprintf(stderr, "C_GenerateRandom failed\n");
            exit_rv = 1;
            break;
        }

        /* A signal that arrived while we were inside C_GenerateRandom
         * shows up here; bail before committing the read to stdout. */
        if (g_stop) break;

        int wr = g_hex ? write_hex (STDOUT_FILENO, buf, want)
                       : write_full(STDOUT_FILENO, buf, want);
        if (wr == -2) break;        /* stdout closed; exit cleanly */
        if (wr <  0) {
            fprintf(stderr, "write: %s\n", strerror(errno));
            exit_rv = 1;
            break;
        }
        produced += (long long)want;
    }

    if (g_hex && produced > 0)
        (void)write(STDOUT_FILENO, "\n", 1);

    f->C_CloseSession(sess);
    f->C_Finalize(NULL);
    dlclose(h);

    /* Wipe the buffer so the last cycle's bytes don't sit on the stack. */
    memset(buf, 0, sizeof buf);
    return exit_rv;
}
