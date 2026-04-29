/* Generic RNG-backend interface.
 *
 * One of `rng_iso7816.c` / `rng_infnoise.c` is compiled in, selected by the
 * build system. The PKCS#11 dispatch in `module.c` only sees this header. */

#ifndef P11RAND_RNG_H
#define P11RAND_RNG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rng_dev rng_dev;   /* opaque per-open handle */

/* Process-wide context. Idempotent / refcounted. */
int  rng_global_init(void);
void rng_global_shutdown(void);

/* Enumerate devices (smartcard readers, FT240X TRNGs, ...). The returned
 * `names` array and its strings are owned by the rng layer; release with
 * rng_free_names(). Returns 0 on success (count may be 0), -1 on error. */
int  rng_list(char ***names, size_t *count);
void rng_free_names(char **names, size_t count);

/* Live presence/usability probe for the device identified by `name`.
 *  +1 = device present and able to deliver random bytes
 *   0 = empty slot / device unsupported / no card
 *  -1 = transport / context error */
int  rng_probe(const char *name);

/* Open the device at `name` for reading. Returns
 *   0 = success (*out non-NULL)
 *  -2 = not present / not usable now
 *  -1 = transport error */
int  rng_open(const char *name, rng_dev **out);
void rng_close(rng_dev *dev);    /* NULL-safe */

/* Read exactly `len` bytes of TRNG output into `buf`. Returns 0 on success,
 * negative on transport error. */
int  rng_read(rng_dev *dev, uint8_t *buf, size_t len);

/* Backend-identifying strings, used to populate CK_TOKEN_INFO fields.
 * They live for the lifetime of the process. */
const char *rng_backend_label(void);   /* short token label, <= 32 bytes */
const char *rng_backend_model(void);   /* token model, <= 16 bytes */

#ifdef __cplusplus
}
#endif

#endif /* P11RAND_RNG_H */
