/*
 * infnoise-core  --  reusable RNG core for the Infinite Noise Multiplier.
 *
 * Drives the FT240X over the OS's raw-USB interface and runs the running
 * health monitor. Whitening / extraction is left to the caller (the pool
 * layer in this project SHA3-256-chains across all sources).
 *
 * Multiple independent contexts can coexist in one process: each
 * `struct infnoise_ctx` holds its own device handle, sample / packet
 * walker, and health-monitor counters. The logging destination is the
 * only remaining process-wide knob.
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

/* Open the FT240X identified by `path` and configure it for synchronous
 * bit-bang. `path` may be NULL, meaning "first FT240X found on the bus".
 *
 *   Linux : usbfs node such as "/dev/bus/usb/001/004".
 *   BSDs  : ugen control endpoint such as "/dev/ugen0.00".
 *
 * Returns 0 on success, -1 on failure. */
int  infnoise_open(infnoise_ctx *c, const char *path);

/* Close the device. Safe to call when not open. */
void infnoise_close(infnoise_ctx *c);

/* Block until exactly `n` post-health-check raw entropy bytes have been
 * produced. Each output byte is 8 packed FT240X comparator bits with
 * roughly 0.88 bits of entropy per bit; the caller must extract full
 * entropy through its own whitener (e.g. SHA3 chaining). Returns n on
 * success, -1 on hard failure. The first call blocks until the health
 * monitor's warm-up completes (~80k samples). */
ssize_t infnoise_read(infnoise_ctx *c, uint8_t *buf, size_t n);

/* Enumerate FT240X devices currently visible to the OS. Caller frees
 * the resulting array with infnoise_free_paths(). Returns 0 on success
 * (count may be 0), -1 on enumeration error. */
int  infnoise_list_paths(char ***paths, size_t *count);
void infnoise_free_paths(char **paths, size_t count);

#ifdef __cplusplus
}
#endif
#endif /* INFNOISE_CORE_H */
