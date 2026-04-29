/* iso7816 GET CHALLENGE entropy source.
 *
 * Each `iso7816_source` represents one SCARD connection to one PC/SC
 * reader's currently-inserted card whose default applet (PIV, OpenPGP,
 * or bare card) responds to ISO 7816-4 GET CHALLENGE. The pool layer
 * (rng.c) holds one of these per usable card. */

#ifndef P11RAND_SOURCE_ISO7816_H
#define P11RAND_SOURCE_ISO7816_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct iso7816_source iso7816_source;

int  iso7816_global_init(void);
void iso7816_global_shutdown(void);

/* Enumerate PC/SC reader names. Caller frees with iso7816_free_readers().
 * Returns 0 on success (count may be 0), -1 on transport error. */
int  iso7816_list_readers(char ***names, size_t *count);
void iso7816_free_readers(char **names, size_t count);

/* Open `reader` and probe for an applet that supports GET CHALLENGE.
 * On success *out is heap-allocated; caller frees with iso7816_close().
 * Returns 0 on success, -2 if no card / unsupported, -1 on transport. */
int  iso7816_open(const char *reader, iso7816_source **out);
void iso7816_close(iso7816_source *s);

/* Read exactly `n` raw GET CHALLENGE bytes; chunks at the APDU short-Le
 * limit (255 bytes/call). Returns 0 on success, negative on error. */
int  iso7816_read(iso7816_source *s, uint8_t *buf, size_t n);

#ifdef __cplusplus
}
#endif
#endif /* P11RAND_SOURCE_ISO7816_H */
