/* Infinite Noise TRNG source: thin per-device wrapper around the now-
 * reentrant infnoise-core. Each open() consumes one path from the list
 * returned by infnoise_list_devices() and produces an independent context
 * that drives that single FT240X. Multiple sources may run in parallel
 * because they no longer share any global state. */

#define _POSIX_C_SOURCE 200809L
#include "source_infnoise.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "infnoise-core.h"

#define LOG_PREFIX "p11rand[infnoise]: "
static int g_debug;
#define LOGD(...) do { if (g_debug) fprintf(stderr, LOG_PREFIX __VA_ARGS__); } while (0)

struct infnoise_source {
    infnoise_ctx *ctx;
};

int infnoise_global_init(void)
{
    if (getenv("P11RAND_DEBUG")) g_debug = 1;
    /* Quiet by default — PKCS#11 consumers shouldn't get surprise stderr
     * lines just because there's no device plugged in. */
    infnoise_set_logging(/*use_syslog=*/false, /*quiet=*/!g_debug);
    return 0;
}

void infnoise_global_shutdown(void) { }

int infnoise_list_devices(char ***paths_out, size_t *count_out)
{
    return infnoise_list_paths(paths_out, count_out);
}

void infnoise_free_devices(char **paths, size_t count)
{
    infnoise_free_paths(paths, count);
}

int infnoise_source_open(const char *path, infnoise_source **out)
{
    if (!out) return -1;
    *out = NULL;

    infnoise_source *s = calloc(1, sizeof(*s));
    if (!s) return -1;
    s->ctx = infnoise_new();
    if (!s->ctx) { free(s); return -1; }

    if (infnoise_open(s->ctx, path) < 0) {
        infnoise_free(s->ctx);
        free(s);
        LOGD("open failed for %s\n", path ? path : "<first>");
        return -2;
    }
    *out = s;
    return 0;
}

void infnoise_source_close(infnoise_source *s)
{
    if (!s) return;
    if (s->ctx) {
        infnoise_close(s->ctx);
        infnoise_free(s->ctx);
    }
    free(s);
}

int infnoise_source_read(infnoise_source *s, uint8_t *buf, size_t n)
{
    if (!s || !s->ctx || (!buf && n)) return -1;
    while (n) {
        ssize_t got = infnoise_read(s->ctx, buf, n);
        if (got <= 0) return -1;
        buf += (size_t)got;
        n   -= (size_t)got;
    }
    return 0;
}
