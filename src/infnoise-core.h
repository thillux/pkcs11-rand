/*
 * infnoise-core  --  reusable wrapper around the /dev/infnoiseN character
 *                    device exposed by the in-kernel Infinite Noise driver.
 *
 * The kernel side owns the FT240X transport, the sync bit-bang sequencing,
 * and the running health monitor. Userspace just open(2)s the char node
 * and read(2)s post-health-check entropy bytes. Whitening / extraction is
 * left to the caller — in this project the pool layer in src/rng.c
 * SHA3-256-chains across all sources.
 *
 * Multiple independent contexts can coexist in one process: every
 * `struct infnoise_ctx` holds its own fd, so the only process-wide knob
 * is the logging destination.
 */

#ifndef INFNOISE_CORE_H
#define INFNOISE_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct infnoise_ctx infnoise_ctx;

/* --- Process-wide configuration ----------------------------------------- */

/* Logging destination. Default: stderr, all priorities. */
void infnoise_set_logging(bool use_syslog, bool quiet);

/* --- Per-device contexts ------------------------------------------------ */

infnoise_ctx *infnoise_new(void);
void          infnoise_free(infnoise_ctx *c);

/* Open the kernel infnoise node at `path` (e.g. "/dev/infnoise0") for
 * reading. `path == NULL` selects the lowest-numbered node currently
 * present. Returns 0 on success, -1 on failure. */
int  infnoise_open(infnoise_ctx *c, const char *path);

/* Close the device. Safe to call when not open. */
void infnoise_close(infnoise_ctx *c);

/* Block until exactly `n` bytes of entropy have been read from the
 * kernel driver. Returns n on success, -1 on hard failure. */
ssize_t infnoise_read(infnoise_ctx *c, uint8_t *buf, size_t n);

/* Enumerate /dev/infnoiseN nodes currently exposed by the kernel.
 * Caller frees the resulting array with infnoise_free_paths(). Paths
 * are returned in numeric order (infnoise0, infnoise1, ...). Returns
 * 0 on success (count may be 0), -1 on enumeration error. */
int  infnoise_list_paths(char ***paths, size_t *count);
void infnoise_free_paths(char **paths, size_t count);

#ifdef __cplusplus
}
#endif
#endif /* INFNOISE_CORE_H */
