/*
 * p11rand-list — inventory of TRNG sources visible on this host.
 *
 * Probes every PC/SC reader for a card that responds to GET CHALLENGE
 * (the iso7816 backend's usability test) and every FT240X device on the
 * USB bus for the Infinite Noise driver. The output is independent of
 * the pool configuration baked into libp11rand.so — useful for picking
 * sensible -Diso7816_cards / -Dinfnoise_devices values, debugging missing
 * permissions, or sanity-checking before starting the seeder.
 *
 * Probe semantics:
 *   - iso7816: SCardConnect(SHARE_SHARED) + select-and-GET-CHALLENGE
 *     handshake. SHARE_SHARED is intentional — a passing probe doesn't
 *     kick out other PKCS#11 consumers; "usable" means the card
 *     actually answers a GET CHALLENGE round.
 *   - infnoise: open the FT240X via raw USB and run setup_ftdi(). The
 *     kernel ftdi_sio driver, if bound, is auto-detached. We can't
 *     detect another userspace process holding the same device:
 *     USBDEVFS_CLAIMINTERFACE is only advisory between userspace
 *     processes (it only excludes kernel drivers). "usable" therefore
 *     means "this process can open and configure the device right
 *     now"; a seeder already running in another process does not flip
 *     the device's status.
 *
 * Usage:
 *     p11rand-list [-q]
 *
 *       -q    machine-readable output: one tab-separated record per
 *             device (kind \t name \t status), no headings, no summary.
 */

#define _POSIX_C_SOURCE 200809L

#include "../src/source_iso7816.h"
#include "../src/source_infnoise.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_quiet;

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s [-q]\n"
        "  -q    tab-separated output (kind\\tname\\tstatus); no headings\n",
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
    while ((opt = getopt(argc, argv, "qh")) != -1) {
        switch (opt) {
        case 'q': g_quiet = 1; break;
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
                if (rv == 0) {
                    status = "usable";
                    iso_usable++;
                    iso7816_close(src);
                } else if (rv == -2) {
                    /* No card, or card present but no applet supports
                     * GET CHALLENGE — both render the slot unusable for
                     * this RNG. */
                    status = "unusable";
                } else {
                    status = "error";
                }
                emit("iso7816", readers[i], status, NULL);
            }
            iso7816_free_readers(readers, n);
        } else if (!g_quiet) {
            fprintf(stderr, "iso7816: enumeration failed\n");
        }
        iso7816_global_shutdown();
    } else if (!g_quiet) {
        fprintf(stderr, "iso7816: PC/SC context init failed (is pcscd running?)\n");
    }

    /* -------- infnoise / FT240X -------- */
    if (infnoise_global_init() == 0) {
        char  **paths = NULL;
        size_t  n = 0;
        if (infnoise_list_devices(&paths, &n) == 0) {
            inf_total = (unsigned)n;
            if (n && !g_quiet) {
                if (iso_total) puts("");
                puts("infnoise (FT240X):");
            }
            for (size_t i = 0; i < n; i++) {
                infnoise_source *src = NULL;
                int rv = infnoise_source_open(paths[i], &src);
                const char *status;
                if (rv == 0) {
                    status = "usable";
                    inf_usable++;
                    infnoise_source_close(src);
                } else {
                    /* No permission, transient busy, or hardware
                     * misbehaving — we can't tell them apart cleanly. */
                    status = "unusable";
                }

                char serial[64] = "";
                char extra[80]  = "";
                if (infnoise_source_read_serial(paths[i],
                                                serial, sizeof serial) == 0
                    && serial[0]) {
                    snprintf(extra, sizeof extra, "serial=%s", serial);
                }
                emit("infnoise", paths[i], status, extra);
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
