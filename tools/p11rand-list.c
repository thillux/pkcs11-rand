/*
 * p11rand-list — inventory of TRNG sources visible on this host.
 *
 * Probes every PC/SC reader for a card that responds to GET CHALLENGE
 * (the iso7816 backend's usability test) and every /dev/infnoiseN node
 * exposed by the in-kernel Infinite Noise driver. The output is
 * independent of the pool configuration baked into libp11rand.so —
 * useful for picking sensible -Diso7816_cards / -Dinfnoise_devices
 * values, debugging missing permissions, or sanity-checking before
 * starting the seeder.
 *
 * Probe semantics:
 *   - iso7816: SCardConnect(SHARE_SHARED) + select-and-GET-CHALLENGE
 *     handshake. SHARE_SHARED is intentional — a passing probe doesn't
 *     kick out other PKCS#11 consumers; "usable" means the card
 *     actually answers a GET CHALLENGE round.
 *   - infnoise: open(2) the /dev/infnoiseN node via the source layer.
 *     "usable" = open succeeded; "unusable" = permission denied,
 *     transient EBUSY, or the kernel driver rejected the open.
 *
 * Usage:
 *     p11rand-list [-q] [-v]
 *
 *       -q    machine-readable output: one tab-separated record per
 *             device (kind \t name \t status), no headings, no summary.
 *       -v    verbose: enable the per-APDU trace from the iso7816
 *             source layer and the open-time logging from the infnoise
 *             core (equivalent to setting P11RAND_DEBUG=1). Useful for
 *             diagnosing why an inserted card is flagged unusable
 *             (e.g. unsupported GET CHALLENGE, unrecognized applet).
 */

#define _POSIX_C_SOURCE 200809L

#include "../src/source_iso7816.h"
#include "../src/source_infnoise.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_quiet;

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s [-q] [-v]\n"
        "  -q    tab-separated output (kind\\tname\\tstatus); no headings\n"
        "  -v    verbose: per-APDU / USB trace from the source layers\n"
        "        (same effect as setting P11RAND_DEBUG=1 in the env)\n",
        argv0);
}

/* `extra` may be NULL or "" — when present it's appended to both the
 * human-readable and tab-separated output as a free-form annotation
 * (e.g. "serial=FT9X8YIK" for FT240X devices). */
static void emit(const char *kind, const char *name, const char *status,
                 const char *extra)
{
    int has_extra = extra && extra[0];
    if (g_quiet) {
        if (has_extra) printf("%s\t%s\t%s\t%s\n", kind, name, status, extra);
        else           printf("%s\t%s\t%s\n",      kind, name, status);
    } else {
        if (has_extra) printf("  [%-8s] %s  (%s)\n", status, name, extra);
        else           printf("  [%-8s] %s\n",       status, name);
    }
}

int main(int argc, char **argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "qvh")) != -1) {
        switch (opt) {
        case 'q': g_quiet = 1; break;
        case 'v': /* The source layers (iso7816, infnoise) read the
                   * env at global_init time. Setting it here, before
                   * the init calls below, is enough. */
                  setenv("P11RAND_DEBUG", "1", 1);
                  break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 2;
        }
    }

    unsigned iso_total = 0, iso_usable = 0;
    unsigned inf_total = 0, inf_usable = 0;

    /* -------- iso7816 / PC/SC -------- */
    if (iso7816_global_init() == 0) {
        char  **readers = NULL;
        size_t  n = 0;
        if (iso7816_list_readers(&readers, &n) == 0) {
            iso_total = (unsigned)n;
            if (n && !g_quiet) printf("iso7816 (PC/SC):\n");
            for (size_t i = 0; i < n; i++) {
                iso7816_source *src = NULL;
                int rv = iso7816_open(readers[i], &src);
                const char *status;
                switch (rv) {
                case  0: status = "usable";      iso_usable++;
                         iso7816_close(src); break;
                case -2: status = "no-card";     break;
                case -3: status = "unsupported"; break;
                default: status = "error";       break;
                }

                /* Annotate every slot that actually has a card with
                 * its ATR — gives the user something to grep against
                 * an ATR database when a card is rejected as
                 * unsupported, or just to label the slot at a glance. */
                char extra[120] = "";
                if (rv == 0 || rv == -3) {
                    char atr[100];
                    if (iso7816_read_atr(readers[i], atr, sizeof atr) == 0
                        && atr[0]) {
                        snprintf(extra, sizeof extra, "ATR=%s", atr);
                    }
                }
                emit("iso7816", readers[i], status, extra);
            }
            iso7816_free_readers(readers, n);
        } else if (!g_quiet) {
            fprintf(stderr, "iso7816: enumeration failed\n");
        }
        iso7816_global_shutdown();
    } else if (!g_quiet) {
        fprintf(stderr, "iso7816: PC/SC context init failed (is pcscd running?)\n");
    }

    /* -------- infnoise / /dev/infnoiseN -------- */
    if (infnoise_global_init() == 0) {
        char  **paths = NULL;
        size_t  n = 0;
        if (infnoise_list_devices(&paths, &n) == 0) {
            inf_total = (unsigned)n;
            if (n && !g_quiet) {
                if (iso_total) puts("");
                puts("infnoise (/dev/infnoiseN):");
            }
            for (size_t i = 0; i < n; i++) {
                infnoise_source *src = NULL;
                const char *status;
                if (infnoise_source_open(paths[i], &src) == 0) {
                    status = "usable";
                    inf_usable++;
                    infnoise_source_close(src);
                } else {
                    /* Permission, transient busy, or kernel driver
                     * rejecting the open — we don't try to distinguish. */
                    status = "unusable";
                }
                emit("infnoise", paths[i], status, "");
            }
            infnoise_free_devices(paths, n);
        } else if (!g_quiet) {
            fprintf(stderr, "infnoise: enumeration failed\n");
        }
        infnoise_global_shutdown();
    }

    if (!g_quiet) {
        if (iso_total + inf_total == 0) {
            puts("(no PC/SC readers and no FT240X devices found)");
        } else {
            printf("\nsummary: iso7816 %u/%u usable, infnoise %u/%u usable\n",
                   iso_usable, iso_total, inf_usable, inf_total);
        }
    }
    return (iso_usable + inf_usable) > 0 ? 0 : 1;
}
