/*
 * p11rand-wait — block until the PKCS#11 module reports a usable RNG.
 *
 * Loads the module, calls C_Initialize, then polls
 * C_GetSlotList(tokenPresent=TRUE) until the count rises to 1 — meaning
 * the pool is fillable (all configured N smartcards + M FT240X devices
 * are present and respond). Useful as a systemd ExecStartPre or a shell
 * gate that holds startup until the entropy pool is ready.
 *
 * Usage:
 *     p11rand-wait [-t SECONDS] [-i POLL_MS] [-q] <module.so>
 *
 *       -t SECONDS    give up after SECONDS; default: wait forever.
 *                     Fractional seconds OK (e.g. -t 0.5).
 *       -i POLL_MS    poll interval, default 500 ms.
 *       -q            suppress informational stderr output.
 *
 * Exit status:
 *     0  pool fillable.
 *     1  timeout reached without the pool becoming fillable.
 *     2  command-line / module-load error.
 */

#define _POSIX_C_SOURCE 200809L

#include "../include/pkcs11.h"

#include <dlfcn.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static int g_quiet;

static void info(const char *fmt, ...)
{
    if (g_quiet) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static double mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static volatile sig_atomic_t g_stop;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s [-t SECONDS] [-i POLL_MS] [-q] <module.so>\n"
        "  -t SECONDS    give up after SECONDS (fractional OK); default: wait forever\n"
        "  -i POLL_MS    poll interval, default 500\n"
        "  -q            quiet; no informational stderr output\n",
        argv0);
}

int main(int argc, char **argv)
{
    double timeout = -1.0;          /* negative ⇒ no timeout */
    long   poll_ms = 500;
    int    opt;

    while ((opt = getopt(argc, argv, "t:i:qh")) != -1) {
        switch (opt) {
        case 't': {
            char *end = NULL;
            timeout = strtod(optarg, &end);
            if (end == optarg || timeout < 0) {
                fprintf(stderr, "invalid -t value: %s\n", optarg);
                return 2;
            }
            break;
        }
        case 'i': {
            char *end = NULL;
            poll_ms = strtol(optarg, &end, 10);
            if (end == optarg || poll_ms <= 0) {
                fprintf(stderr, "invalid -i value: %s\n", optarg);
                return 2;
            }
            break;
        }
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

    /* Honor SIGINT/SIGTERM so a Ctrl-C from a shell or a stop from
     * systemd exits cleanly without waiting out the timeout. */
    struct sigaction sa = { .sa_handler = on_signal };
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (timeout >= 0)
        info("waiting for PKCS#11 pool slot (poll=%ld ms, timeout=%.3f s)\n",
             poll_ms, timeout);
    else
        info("waiting for PKCS#11 pool slot (poll=%ld ms)\n", poll_ms);

    double start = mono();
    struct timespec sleep_ts = {
        .tv_sec  =  poll_ms / 1000,
        .tv_nsec = (poll_ms % 1000) * 1000000L,
    };

    int rv = 1;
    for (;;) {
        CK_ULONG count = 0;
        CK_RV r = f->C_GetSlotList(CK_TRUE, NULL, &count);
        if (r == CKR_OK && count >= 1) {
            info("pool fillable after %.2f s\n", mono() - start);
            rv = 0;
            break;
        }

        if (g_stop) {
            info("interrupted by signal\n");
            rv = 1;
            break;
        }
        if (timeout >= 0 && (mono() - start) >= timeout) {
            fprintf(stderr, "timeout after %.2f s; pool not fillable\n", timeout);
            rv = 1;
            break;
        }

        /* nanosleep returns -1 / EINTR if a signal arrived; the next
         * loop iteration picks up g_stop and bails. */
        (void)nanosleep(&sleep_ts, NULL);
    }

    f->C_Finalize(NULL);
    dlclose(h);
    return rv;
}
