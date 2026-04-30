/* Infinite Noise TRNG entropy source.
 *
 * Each `infnoise_source` wraps one infnoise-core context bound to one
 * /dev/infnoiseN character device exposed by the kernel driver.
 * Arbitrarily many can coexist in the same process. The pool layer
 * allocates one source per device path picked from
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

/* Enumerate /dev/infnoiseN nodes visible to the OS right now. Caller
 * frees with infnoise_free_devices(). Returns 0 on success, -1 on error. */
int  infnoise_list_devices(char ***paths, size_t *count);
void infnoise_free_devices(char **paths, size_t count);

/* Open a specific /dev/infnoiseN by path. Returns 0 on success, -2 if
 * absent / not usable, -1 on resource error. */
int  infnoise_source_open(const char *path, infnoise_source **out);
void infnoise_source_close(infnoise_source *s);
int  infnoise_source_read(infnoise_source *s, uint8_t *buf, size_t n);

#ifdef __cplusplus
}
#endif
#endif /* P11RAND_SOURCE_INFNOISE_H */
