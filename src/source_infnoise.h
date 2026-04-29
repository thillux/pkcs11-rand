/* Infinite Noise TRNG entropy source.
 *
 * Each `infnoise_source` wraps one infnoise-core context bound to one
 * physical FT240X. Arbitrarily many can coexist in the same process.
 * The pool layer allocates one source per device path picked from
 * infnoise_list_devices() and keeps it alive for the session's lifetime. */

#ifndef P11RAND_SOURCE_INFNOISE_H
#define P11RAND_SOURCE_INFNOISE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct infnoise_source infnoise_source;

int  infnoise_global_init(void);
void infnoise_global_shutdown(void);

/* Enumerate FT240X device paths visible to the OS right now. Caller
 * frees with infnoise_free_devices(). Returns 0 on success, -1 on error. */
int  infnoise_list_devices(char ***paths, size_t *count);
void infnoise_free_devices(char **paths, size_t count);

/* Read the FT240X iManufacturer / iProduct / iSerialNumber strings.
 * See infnoise_read_dev_info() for semantics. */
struct infnoise_dev_info;
int  infnoise_source_read_dev_info(const char *path,
                                   struct infnoise_dev_info *out);

/* Open a specific FT240X by path (Linux usbfs node or BSD ugen control
 * endpoint). Returns 0 on success, -2 if absent / not usable, -1 on
 * resource error. */
int  infnoise_source_open(const char *path, infnoise_source **out);
void infnoise_source_close(infnoise_source *s);
int  infnoise_source_read(infnoise_source *s, uint8_t *buf, size_t n);

#ifdef __cplusplus
}
#endif
#endif /* P11RAND_SOURCE_INFNOISE_H */
