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
 * Returns:
 *    0  success
 *   -1  transport / PC/SC error
 *   -2  no card in the reader
 *   -3  card present but exposes no GET-CHALLENGE-capable applet */
int  iso7816_open(const char *reader, iso7816_source **out);
void iso7816_close(iso7816_source *s);

/* Read exactly `n` raw GET CHALLENGE bytes; chunks at the APDU short-Le
 * limit (255 bytes/call). Returns 0 on success, negative on error. */
int  iso7816_read(iso7816_source *s, uint8_t *buf, size_t n);

/* Power up the card in `reader` just long enough to retrieve its ATR
 * (Answer to Reset) and writes a space-separated uppercase hex string
 * into `out` (e.g. "3B 8F 01 80 5D 4E …"). Returns 0 on success, -1
 * if the reader has no card / transport failure / output buffer too
 * small. Independent of iso7816_open(); cheap enough to call from the
 * list helper for every reader. */
int  iso7816_read_atr(const char *reader, char *out, size_t cap);

#ifdef __cplusplus
}
#endif
#endif /* P11RAND_SOURCE_ISO7816_H */
