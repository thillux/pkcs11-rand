/*
 * infnoise-core  --  thin wrapper around the /dev/infnoiseN character
 *                    device. The kernel-side driver owns the FT240X
 *                    transport, the sync bit-bang, and the running health
 *                    monitor; userspace just open(2)s the node and pulls
 *                    post-health-check bytes via read(2).
 *
 * Multiple independent contexts can coexist in one process — every
 * piece of per-device state lives in `struct infnoise_ctx`, and the
 * only process-wide knob is the logging destination.
 *
 * Permissions: udev rule granting rw to the desired group, e.g.
 *     KERNEL=="infnoise[0-9]*", MODE="0660", GROUP="plugdev"
 */

#if !defined(__linux__)
# error "infnoise-core targets the Linux /dev/infnoiseN character device"
#endif

#define _POSIX_C_SOURCE 200809L

#include "infnoise-core.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

/* --- Logging ------------------------------------------------------------ */

static bool g_use_syslog = false;
static bool g_quiet      = false;
static bool g_log_open   = false;

void infnoise_set_logging(bool use_syslog, bool quiet) {
    if (g_log_open && g_use_syslog && !use_syslog) {
        closelog();
        g_log_open = false;
    }
    g_use_syslog = use_syslog;
    g_quiet      = quiet;
    if (g_use_syslog && !g_log_open) {
        openlog("infnoise", LOG_PID | LOG_NDELAY, LOG_DAEMON);
        g_log_open = true;
    }
}

static void log_vmsg(int prio, const char *fmt, va_list ap) {
    if (prio >= LOG_INFO && g_quiet) return;
    if (g_use_syslog) {
        char buf[512];
        vsnprintf(buf, sizeof buf, fmt, ap);
        syslog(prio, "%s", buf);
        return;
    }
    const char *lbl;
    switch (prio) {
    case LOG_ERR:     lbl = "error";   break;
    case LOG_WARNING: lbl = "warning"; break;
    case LOG_NOTICE:  lbl = "notice";  break;
    case LOG_INFO:    lbl = "info";    break;
    default:          lbl = "debug";   break;
    }
    char ts[32] = "";
    time_t now = time(NULL);
    struct tm tm;
    if (localtime_r(&now, &tm))
        strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%S%z", &tm);
    fprintf(stderr, "%s [%s] ", ts, lbl);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}

static void log_msg(int prio, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_vmsg(prio, fmt, ap);
    va_end(ap);
}

static void log_perror(const char *what) {
    int e = errno;
    log_msg(LOG_ERR, "%s: %s", what, strerror(e));
}

/* --- Per-device context ------------------------------------------------- */

struct infnoise_ctx {
    int   fd;
    bool  opened;
    char *path;     /* identifying device path, owned */
};

infnoise_ctx *infnoise_new(void) {
    infnoise_ctx *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->fd = -1;
    return c;
}

void infnoise_free(infnoise_ctx *c) {
    if (!c) return;
    if (c->opened) infnoise_close(c);
    if (c->fd >= 0) { close(c->fd); c->fd = -1; }
    free(c->path);
    free(c);
}

/* --- Device enumeration ------------------------------------------------- */

#define DEV_DIR    "/dev"
#define DEV_PREFIX "infnoise"

static int parse_dev_index(const char *name, long *idx_out)
{
    size_t plen = sizeof(DEV_PREFIX) - 1;
    if (strncmp(name, DEV_PREFIX, plen) != 0) return -1;
    const char *suffix = name + plen;
    if (!*suffix) return -1;
    for (const char *s = suffix; *s; s++)
        if (!isdigit((unsigned char)*s)) return -1;
    *idx_out = strtol(suffix, NULL, 10);
    return 0;
}

static int path_index_cmp(const void *a, const void *b)
{
    const char *pa = *(const char *const *)a;
    const char *pb = *(const char *const *)b;
    const char *na = strrchr(pa, '/'); na = na ? na + 1 : pa;
    const char *nb = strrchr(pb, '/'); nb = nb ? nb + 1 : pb;
    long ia = 0, ib = 0;
    (void)parse_dev_index(na, &ia);
    (void)parse_dev_index(nb, &ib);
    if (ia < ib) return -1;
    if (ia > ib) return  1;
    return 0;
}

int infnoise_list_paths(char ***paths_out, size_t *count_out) {
    if (!paths_out || !count_out) return -1;
    *paths_out = NULL;
    *count_out = 0;

    DIR *d = opendir(DEV_DIR);
    if (!d) {
        if (errno == ENOENT) return 0;
        log_perror(DEV_DIR);
        return -1;
    }

    char **arr = NULL;
    size_t cap = 0, n = 0;
    int rv = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        long idx;
        if (parse_dev_index(e->d_name, &idx) < 0) continue;

        char buf[64];
        int bn = snprintf(buf, sizeof buf, "%s/%s", DEV_DIR, e->d_name);
        if (bn < 0 || (size_t)bn >= sizeof buf) continue;

        if (n == cap) {
            size_t new_cap = cap ? cap * 2 : 4;
            char **na = realloc(arr, new_cap * sizeof *na);
            if (!na) { rv = -1; break; }
            arr = na; cap = new_cap;
        }
        arr[n] = strdup(buf);
        if (!arr[n]) { rv = -1; break; }
        n++;
    }
    closedir(d);

    if (rv < 0) {
        for (size_t i = 0; i < n; i++) free(arr[i]);
        free(arr);
        return -1;
    }

    if (n > 1) qsort(arr, n, sizeof *arr, path_index_cmp);
    *paths_out = arr;
    *count_out = n;
    return 0;
}

void infnoise_free_paths(char **paths, size_t count) {
    if (!paths) return;
    for (size_t i = 0; i < count; i++) free(paths[i]);
    free(paths);
}

/* --- Public API: open / read / close ------------------------------------ */

int infnoise_open(infnoise_ctx *c, const char *path) {
    if (!c) return -1;
    if (c->opened) return 0;

    char chosen[64];
    if (!path) {
        char **paths = NULL;
        size_t n = 0;
        if (infnoise_list_paths(&paths, &n) < 0) return -1;
        if (n == 0) {
            infnoise_free_paths(paths, n);
            log_msg(LOG_ERR, "no /dev/" DEV_PREFIX "N nodes available");
            return -1;
        }
        snprintf(chosen, sizeof chosen, "%s", paths[0]);
        infnoise_free_paths(paths, n);
        path = chosen;
    }

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { log_perror(path); return -1; }

    free(c->path);
    c->path = strdup(path);    /* strdup failure is non-fatal */
    c->fd = fd;
    c->opened = true;
    log_msg(LOG_INFO, "opened %s", path);
    return 0;
}

void infnoise_close(infnoise_ctx *c) {
    if (!c || !c->opened) return;
    if (c->fd >= 0) { close(c->fd); c->fd = -1; }
    c->opened = false;
}

ssize_t infnoise_read(infnoise_ctx *c, uint8_t *buf, size_t n) {
    if (!c || !c->opened || (!buf && n)) {
        log_msg(LOG_ERR, "infnoise_read: bad arguments");
        return -1;
    }
    size_t produced = 0;
    while (produced < n) {
        ssize_t got = read(c->fd, buf + produced, n - produced);
        if (got > 0) {
            produced += (size_t)got;
            continue;
        }
        if (got == 0) {
            log_msg(LOG_ERR, "%s: unexpected EOF",
                    c->path ? c->path : "/dev/infnoise");
            return -1;
        }
        if (errno == EINTR) continue;
        log_perror(c->path ? c->path : "/dev/infnoise");
        return -1;
    }
    return (ssize_t)produced;
}
