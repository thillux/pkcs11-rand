/*
 * p11rand-seed — seed the Linux kernel RNG from a PKCS#11 module.
 *
 * Opens the module, picks the first usable slot (which is the configured
 * pool), opens a session, and then periodically calls C_GenerateRandom
 * for N bytes and pushes those bytes into /dev/random. By default the
 * insertion uses the RNDADDENTROPY ioctl, which both adds the bytes and
 * credits N*8 bits of entropy to the kernel pool — that requires
 * CAP_SYS_ADMIN (typically root). Pass --no-credit to fall back to a
 * plain write(2), which still mixes the bytes in but credits no
 * entropy; useful for non-root testing or as a hedge.
 *
 * The pool slot must already be present at startup; pair this with
 * p11rand-wait if your sources may not be ready yet (e.g. a systemd
 * unit ordered after card insertion).
 *
 * After each successful RNDADDENTROPY the seeder also issues the
 * RNDRESEEDCRNG ioctl, forcing the kernel's CRNG to mix the newly
 * credited entropy in right away rather than waiting for its next
 * scheduled reseed. Both ioctls share the CAP_SYS_ADMIN requirement;
 * either falls back gracefully if the kernel returns EPERM.
 *
 * Usage:
 *     p11rand-seed [-t SECONDS] [-n BYTES] [--no-credit] [--no-reseed] [-q] <module.so>
 *
 *       -t SECONDS    interval between insertions; fractional OK; default 60
 *       -n BYTES      bytes per insertion; 1..4096; default 64
 *       --no-credit   write(2) without entropy credit (skips RNDADDENTROPY)
 *       --no-reseed   skip the RNDRESEEDCRNG follow-up after each credit
 *       -q            suppress informational stderr output
 *
 * Exit status:
 *     0  clean exit on SIGINT / SIGTERM
 *     1  fatal runtime failure
 *     2  command-line / module-load error
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE   /* for explicit_bzero(3) */

#include "../include/pkcs11.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <linux/random.h>

#define DEFAULT_INTERVAL 60.0
#define DEFAULT_NBYTES   64
#define MAX_NBYTES       4096

static int g_quiet, g_no_credit, g_no_reseed;
static volatile sig_atomic_t g_stop;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

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
        "usage: %s [-t SECONDS] [-n BYTES] [--no-credit] [--no-reseed] [-q] <module.so>\n"
        "  -t SECONDS    interval between insertions (fractional OK); default %.0f\n"
        "  -n BYTES      bytes per insertion (1..%d); default %d\n"
        "  --no-credit   plain write(2) instead of RNDADDENTROPY (no root needed)\n"
        "  --no-reseed   skip RNDRESEEDCRNG after each successful credit\n"
        "  -q            quiet; no informational stderr output\n",
        argv0, DEFAULT_INTERVAL, MAX_NBYTES, DEFAULT_NBYTES);
}

/* nanosleep that wakes early on g_stop. */
static void interruptible_sleep(double seconds)
{
    if (seconds <= 0) return;
    struct timespec rem, ts = {
        .tv_sec  = (time_t)seconds,
        .tv_nsec = (long)((seconds - (double)(time_t)seconds) * 1e9),
    };
    while (!g_stop && nanosleep(&ts, &rem) < 0 && errno == EINTR)
        ts = rem;
}

int main(int argc, char **argv)
{
    double interval = DEFAULT_INTERVAL;
    long   nbytes   = DEFAULT_NBYTES;

    static struct option longopts[] = {
        { "no-credit", no_argument, NULL, 1 },
        { "no-reseed", no_argument, NULL, 2 },
        { "help",      no_argument, NULL, 'h' },
        { 0, 0, 0, 0 },
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "t:n:qh", longopts, NULL)) != -1) {
        switch (opt) {
        case 't': {
            char *end = NULL;
            interval = strtod(optarg, &end);
            if (end == optarg || interval <= 0) {
                fprintf(stderr, "invalid -t value: %s\n", optarg);
                return 2;
            }
            break;
        }
        case 'n': {
            char *end = NULL;
            nbytes = strtol(optarg, &end, 10);
            if (end == optarg || nbytes <= 0 || nbytes > MAX_NBYTES) {
                fprintf(stderr, "invalid -n value: %s (1..%d)\n",
                        optarg, MAX_NBYTES);
                return 2;
            }
            break;
        }
        case 'q': g_quiet = 1; break;
        case 1:   g_no_credit = 1; break;
        case 2:   g_no_reseed = 1; break;
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
        f->C_Finalize(NULL);
        dlclose(h);
        return 1;
    }
    CK_SLOT_ID *slots = calloc(nslots, sizeof(*slots));
    if (!slots) { f->C_Finalize(NULL); dlclose(h); return 1; }
    if (f->C_GetSlotList(CK_TRUE, slots, &nslots) != CKR_OK) {
        fprintf(stderr, "C_GetSlotList failed\n");
        free(slots); f->C_Finalize(NULL); dlclose(h); return 1;
    }

    CK_SESSION_HANDLE sess = 0;
    if (f->C_OpenSession(slots[0], CKF_SERIAL_SESSION,
                         NULL, NULL, &sess) != CKR_OK) {
        fprintf(stderr, "C_OpenSession failed\n");
        free(slots); f->C_Finalize(NULL); dlclose(h); return 1;
    }
    free(slots);

    int rfd = open("/dev/random", O_WRONLY);
    if (rfd < 0) {
        fprintf(stderr, "open /dev/random: %s\n", strerror(errno));
        f->C_CloseSession(sess); f->C_Finalize(NULL); dlclose(h); return 1;
    }

    /* One contiguous allocation: rand_pool_info header followed by the
     * byte buffer (the trailing flex array). C_GenerateRandom writes
     * straight into rpi->buf, RNDADDENTROPY consumes the same memory. */
    size_t rpi_size = sizeof(struct rand_pool_info) + (size_t)nbytes;
    struct rand_pool_info *rpi = calloc(1, rpi_size);
    if (!rpi) {
        close(rfd); f->C_CloseSession(sess); f->C_Finalize(NULL); dlclose(h);
        return 1;
    }
    rpi->entropy_count = (int)(nbytes * 8);
    rpi->buf_size      = (int)nbytes;

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    info("seeding /dev/random: %ld B every %.2f s%s\n",
         nbytes, interval,
         g_no_credit ? " (no entropy credit)" : "");

    int rv = 0;
    while (!g_stop) {
        if (f->C_GenerateRandom(sess,
                                (CK_BYTE_PTR)rpi->buf,
                                (CK_ULONG)nbytes) != CKR_OK) {
            if (g_stop) break;
            fprintf(stderr, "C_GenerateRandom failed; retrying after interval\n");
            interruptible_sleep(interval);
            continue;
        }

        if (g_no_credit) {
            ssize_t w = write(rfd, rpi->buf, (size_t)nbytes);
            if (w < 0) {
                fprintf(stderr, "write /dev/random: %s\n", strerror(errno));
            } else {
                info("wrote %zd B (uncredited)\n", w);
            }
        } else if (ioctl(rfd, RNDADDENTROPY, rpi) < 0) {
            if (errno == EPERM) {
                fprintf(stderr,
                    "RNDADDENTROPY: EPERM — falling back to uncredited write "
                    "(run as root or with CAP_SYS_ADMIN to credit entropy)\n");
                g_no_credit = 1;
                ssize_t w = write(rfd, rpi->buf, (size_t)nbytes);
                if (w < 0)
                    fprintf(stderr, "write /dev/random: %s\n", strerror(errno));
            } else {
                fprintf(stderr, "RNDADDENTROPY: %s\n", strerror(errno));
            }
        } else {
            info("credited %ld B (%d bits) to kernel pool\n",
                 nbytes, rpi->entropy_count);
#ifdef RNDRESEEDCRNG
            if (!g_no_reseed) {
                if (ioctl(rfd, RNDRESEEDCRNG) < 0) {
                    if (errno == EPERM) {
                        fprintf(stderr,
                            "RNDRESEEDCRNG: EPERM — disabling for the run\n");
                        g_no_reseed = 1;
                    } else {
                        fprintf(stderr, "RNDRESEEDCRNG: %s\n", strerror(errno));
                    }
                } else {
                    info("forced CRNG reseed\n");
                }
            }
#else
            (void)g_no_reseed;
#endif
        }

        interruptible_sleep(interval);
    }

    info("exiting\n");

    /* Don't leave the byte buffer in memory after exit. */
    explicit_bzero(rpi, rpi_size);
    free(rpi);
    close(rfd);
    f->C_CloseSession(sess);
    f->C_Finalize(NULL);
    dlclose(h);
    return rv;
}
