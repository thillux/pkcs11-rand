/*
 * infnoise-core  --  read the Infinite Noise Multiplier USB TRNG without
 *                    libusb/libftdi. Talks directly to the FT240X over the
 *                    OS's raw-USB interface:
 *
 *   Linux    : /dev/bus/usb/<bus>/<dev>   (usbfs, USBDEVFS_* ioctls)
 *   OpenBSD  : /dev/ugenN.{00,01,02}      (ugen(4), USB_DO_REQUEST + read/write)
 *
 * Each raw comparator bit carries roughly 0.88 bits of entropy and is
 * correlated with its neighbours. This module emits the raw post-health-
 * check byte stream; entropy extraction (whitening, conditioning) is the
 * caller's responsibility. In this project the pool layer in src/rng.c
 * SHA3-256-chains across all sources, so the older internal SHA3-512
 * extractor is no longer compiled in here.
 *
 * Multiple independent FT240X devices can be driven concurrently: every
 * piece of per-device state lives in `struct infnoise_ctx`, and the only
 * process-wide knob is the logging destination.
 *
 * Permissions:
 *   Linux:
 *     - udev rule granting rw to the plugdev group, or run as root, e.g.
 *         SUBSYSTEM=="usb", ATTR{idVendor}=="0403", ATTR{idProduct}=="6015", \
 *             MODE="0660", GROUP="plugdev"
 *     - the ftdi_sio kernel driver, if bound, is auto-detached.
 *   OpenBSD:
 *     - /dev/ugenN.* must be rw for the user.
 *     - uftdi(4) must NOT claim the device — disable uftdi in config(8)
 *       or attach the device explicitly to ugen(4).
 */

#if defined(__linux__)
# define _POSIX_C_SOURCE 200809L
#endif

#include "infnoise-core.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

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

/* --- FTDI / INM constants ----------------------------------------------- */

#define FTDI_VID         0x0403
#define FT240X_PID       0x6015

#define SIO_RESET         0x00
#define SIO_SET_BAUDRATE  0x03
#define SIO_SET_LATENCY   0x09
#define SIO_SET_BITMODE   0x0B

#define SIO_RESET_SIO      0
#define SIO_RESET_PURGE_RX 1
#define SIO_RESET_PURGE_TX 2

#define BITMODE_RESET    0x00
#define BITMODE_SYNCBB   0x04

#define INM_MASK         0xED
#define PIN_SWEN1        0x04
#define PIN_SWEN2        0x01
#define PIN_COMP1_SHIFT  1
#define PIN_COMP2_SHIFT  4

#define FTDI_PORT_A      1
#define BAUD_VALUE       100
#define BAUD_INDEX       0

#define SAMPLES_PER_XFER 60
#define IN_MAX_PACKET    64
#define IN_BUF_BYTES     512
#define FTDI_STATUS      2

/* --- Health monitor constants ------------------------------------------- */

#define HC_N          14u
#define HC_EXPECTED   0.8796660706656493
#define HC_ACCURACY   1.03
#define HC_WARMUP     80000u
#define HC_MAX_SEQ    20u
#define HC_MAX_COUNT  (1u << 14)
#define HC_CTX        (1u << HC_N)

/* --- Per-device context ------------------------------------------------- */

struct infnoise_ctx {
#if defined(__linux__)
    int fd;
#else
    int ctl, in, out;
#endif

    bool    opened;
    char   *path;                       /* identifying device path, owned */

    uint8_t clock_pattern[SAMPLES_PER_XFER];
    uint8_t in_buf[IN_BUF_BYTES];
    int     in_n, in_pkt_off, in_pos, in_pkt_end, sample_idx;

    uint8_t bit_acc;
    int     bit_n;

    bool    health_announced;

    uint32_t hc_ones[HC_CTX];
    uint32_t hc_zeros[HC_CTX];
    uint32_t hc_prev_bits, hc_sampled, hc_ent_bits;
    uint64_t hc_total;
    uint32_t hc_run0, hc_run1;
    double   hc_prob;
    int      hc_prev_bit;
};

static void dev_close_fds(infnoise_ctx *c);

infnoise_ctx *infnoise_new(void) {
    infnoise_ctx *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
#if defined(__linux__)
    c->fd = -1;
#else
    c->ctl = c->in = c->out = -1;
#endif
    c->hc_prob = 1.0;
    return c;
}

void infnoise_free(infnoise_ctx *c) {
    if (!c) return;
    if (c->opened) infnoise_close(c);
    dev_close_fds(c);     /* covers the partially-opened case */
    free(c->path);
    free(c);
}

/* --- Platform-specific I/O layer ---------------------------------------- */

static int  dev_open_path(infnoise_ctx *c, const char *path);
static int  dev_find_first(char *path_out, size_t cap);
static int  dev_control(infnoise_ctx *c, uint8_t req, uint16_t val, uint16_t idx);
static int  dev_bulk_out(infnoise_ctx *c, const uint8_t *buf, int len);
static int  dev_bulk_in (infnoise_ctx *c, uint8_t *buf, int len);

#if defined(__linux__)

#include <dirent.h>
#include <linux/usbdevice_fs.h>
#include <linux/usb/ch9.h>

static int linux_match(const char *path) {
    int fd = open(path, O_RDWR);
    if (fd < 0) return -1;
    uint8_t d[18];
    if (read(fd, d, 18) != 18 || d[0] != 18 || d[1] != 1) {
        close(fd); return -1;
    }
    uint16_t vid = d[8]  | ((uint16_t)d[9]  << 8);
    uint16_t pid = d[10] | ((uint16_t)d[11] << 8);
    if (vid != FTDI_VID || pid != FT240X_PID) {
        close(fd); return -1;
    }
    return fd;
}

typedef int (*dev_walk_cb)(const char *path, void *user);

static int linux_walk(dev_walk_cb cb, void *user) {
    DIR *busdir = opendir("/dev/bus/usb");
    if (!busdir) { log_perror("/dev/bus/usb"); return -1; }
    int rv = 0;
    struct dirent *be;
    while (rv == 0 && (be = readdir(busdir))) {
        if (be->d_name[0] == '.') continue;
        char busp[64];
        int bn = snprintf(busp, sizeof busp, "/dev/bus/usb/%s", be->d_name);
        if (bn < 0 || (size_t)bn >= sizeof busp) continue;
        DIR *dd = opendir(busp);
        if (!dd) continue;
        struct dirent *de;
        while ((de = readdir(dd))) {
            if (de->d_name[0] == '.') continue;
            char p[128];
            int pn = snprintf(p, sizeof p, "%s/%s", busp, de->d_name);
            if (pn < 0 || (size_t)pn >= sizeof p) continue;
            int fd = linux_match(p);
            if (fd >= 0) {
                close(fd);
                rv = cb(p, user);
                if (rv != 0) break;
            }
        }
        closedir(dd);
    }
    closedir(busdir);
    return rv;
}

struct first_match { char *out; size_t cap; };
static int first_match_cb(const char *path, void *user) {
    struct first_match *m = user;
    snprintf(m->out, m->cap, "%s", path);
    return 1;   /* stop walk */
}

static int dev_find_first(char *path_out, size_t cap) {
    struct first_match m = { .out = path_out, .cap = cap };
    int rv = linux_walk(first_match_cb, &m);
    return rv > 0 ? 0 : -1;
}

struct paths_acc {
    char  **arr;
    size_t  cap;
    size_t  n;
    int     err;
};

static int paths_acc_cb(const char *path, void *user) {
    struct paths_acc *a = user;
    if (a->n == a->cap) {
        size_t cap = a->cap ? a->cap * 2 : 4;
        char **arr = realloc(a->arr, cap * sizeof(*arr));
        if (!arr) { a->err = 1; return 1; }
        a->arr = arr;
        a->cap = cap;
    }
    a->arr[a->n] = strdup(path);
    if (!a->arr[a->n]) { a->err = 1; return 1; }
    a->n++;
    return 0;
}

int infnoise_list_paths(char ***paths_out, size_t *count_out) {
    if (!paths_out || !count_out) return -1;
    *paths_out = NULL;
    *count_out = 0;
    struct paths_acc a = { 0 };
    int rv = linux_walk(paths_acc_cb, &a);
    if (rv < 0 || a.err) {
        for (size_t i = 0; i < a.n; i++) free(a.arr[i]);
        free(a.arr);
        return -1;
    }
    *paths_out = a.arr;
    *count_out = a.n;
    return 0;
}

static int dev_open_path(infnoise_ctx *c, const char *path) {
    int fd = linux_match(path);
    if (fd < 0) {
        log_msg(LOG_ERR, "no FT240X (%04x:%04x) at %s",
                FTDI_VID, FT240X_PID, path);
        return -1;
    }
    struct usbdevfs_ioctl u = { .ifno = 0,
                                .ioctl_code = USBDEVFS_DISCONNECT,
                                .data = NULL };
    (void)ioctl(fd, USBDEVFS_IOCTL, &u);

    int iface = 0;
    if (ioctl(fd, USBDEVFS_CLAIMINTERFACE, &iface) < 0) {
        log_perror("USBDEVFS_CLAIMINTERFACE");
        close(fd);
        return -1;
    }
    unsigned int ep_in  = 0x81;
    unsigned int ep_out = 0x02;
    (void)ioctl(fd, USBDEVFS_CLEAR_HALT, &ep_in);
    (void)ioctl(fd, USBDEVFS_CLEAR_HALT, &ep_out);

    c->fd = fd;
    log_msg(LOG_INFO, "opened FT240X at %s (vid=%04x pid=%04x)",
            path, FTDI_VID, FT240X_PID);
    return 0;
}

static void dev_close_fds(infnoise_ctx *c) {
    if (c->fd < 0) return;
    int iface = 0;
    (void)ioctl(c->fd, USBDEVFS_RELEASEINTERFACE, &iface);
    close(c->fd);
    c->fd = -1;
}

static int dev_control(infnoise_ctx *c, uint8_t req, uint16_t val, uint16_t idx) {
    struct usbdevfs_ctrltransfer ct = {
        .bRequestType = 0x40,
        .bRequest     = req,
        .wValue       = val,
        .wIndex       = idx,
        .wLength      = 0,
        .timeout      = 1000,
        .data         = NULL,
    };
    return ioctl(c->fd, USBDEVFS_CONTROL, &ct);
}

static int linux_bulk(infnoise_ctx *c, uint8_t ep, uint8_t *buf, int len) {
    struct usbdevfs_bulktransfer b = {
        .ep = ep, .len = len, .timeout = 2000, .data = buf,
    };
    return ioctl(c->fd, USBDEVFS_BULK, &b);
}

static int dev_bulk_out(infnoise_ctx *c, const uint8_t *buf, int len) {
    return linux_bulk(c, 0x02, (uint8_t *)buf, len);
}
static int dev_bulk_in(infnoise_ctx *c, uint8_t *buf, int len) {
    return linux_bulk(c, 0x81, buf, len);
}

int infnoise_read_serial(const char *path, char *out, size_t cap)
{
    if (!path || !out || cap == 0) return -1;
    out[0] = '\0';

    int fd = open(path, O_RDWR);
    if (fd < 0) return -1;

    /* Pull the device descriptor via control transfer rather than the
     * read(2) shortcut so a freshly-opened fd is in a known state. The
     * descriptor's byte 16 is iSerialNumber: an index into the string
     * descriptor table, or 0 if the device exposes no serial. */
    uint8_t dd[18];
    struct usbdevfs_ctrltransfer ct = {
        .bRequestType = 0x80,            /* dev->host, standard, device */
        .bRequest     = 0x06,            /* GET_DESCRIPTOR              */
        .wValue       = (uint16_t)(0x01u << 8),  /* DEVICE, index 0     */
        .wIndex       = 0,
        .wLength      = sizeof dd,
        .timeout      = 1000,
        .data         = dd,
    };
    if (ioctl(fd, USBDEVFS_CONTROL, &ct) < 0) {
        close(fd); return -1;
    }
    uint8_t i_serial = dd[16];
    if (i_serial == 0) { close(fd); return 0; }   /* no serial exposed */

    /* String descriptor: bLength byte, type byte (0x03), then UTF-16 LE.
     * Request in US English (langid 0x0409); FT240X serials are ASCII
     * so we just drop the high byte after a sanity check. */
    uint8_t buf[256];
    ct = (struct usbdevfs_ctrltransfer){
        .bRequestType = 0x80,
        .bRequest     = 0x06,            /* GET_DESCRIPTOR */
        .wValue       = (uint16_t)((0x03u << 8) | i_serial),  /* STRING */
        .wIndex       = 0x0409,
        .wLength      = sizeof buf,
        .timeout      = 1000,
        .data         = buf,
    };
    int n = ioctl(fd, USBDEVFS_CONTROL, &ct);
    close(fd);
    if (n < 2 || buf[0] < 2 || buf[0] > n || buf[1] != 0x03)
        return -1;

    size_t out_i = 0;
    for (int i = 2; i + 1 < buf[0] && out_i + 1 < cap; i += 2) {
        uint16_t cp = buf[i] | ((uint16_t)buf[i + 1] << 8);
        out[out_i++] = (cp < 0x80) ? (char)cp : '?';
    }
    out[out_i] = '\0';
    return 0;
}

#elif defined(__OpenBSD__) || defined(__NetBSD__) || defined(__FreeBSD__)

#include <dev/usb/usb.h>

int infnoise_list_paths(char ***paths_out, size_t *count_out) {
    if (!paths_out || !count_out) return -1;
    *paths_out = NULL;
    *count_out = 0;
    char  **arr = NULL;
    size_t  cap = 0, n = 0;
    for (int idx = 0; idx < 16; idx++) {
        char p[32];
        snprintf(p, sizeof p, "/dev/ugen%d.00", idx);
        int fd = open(p, O_RDWR);
        if (fd < 0) continue;
        struct usb_device_info di;
        int ok = ioctl(fd, USB_GET_DEVICEINFO, &di) == 0
              && di.udi_vendorNo  == FTDI_VID
              && di.udi_productNo == FT240X_PID;
        close(fd);
        if (!ok) continue;
        if (n == cap) {
            cap = cap ? cap * 2 : 4;
            char **na = realloc(arr, cap * sizeof(*na));
            if (!na) goto fail;
            arr = na;
        }
        arr[n] = strdup(p);
        if (!arr[n]) goto fail;
        n++;
    }
    *paths_out = arr;
    *count_out = n;
    return 0;
fail:
    for (size_t i = 0; i < n; i++) free(arr[i]);
    free(arr);
    return -1;
}

static int dev_find_first(char *path_out, size_t cap) {
    char **arr = NULL;
    size_t n = 0;
    if (infnoise_list_paths(&arr, &n) < 0 || n == 0) {
        infnoise_free_paths(arr, n);
        return -1;
    }
    snprintf(path_out, cap, "%s", arr[0]);
    infnoise_free_paths(arr, n);
    return 0;
}

static int dev_open_path(infnoise_ctx *c, const char *ctl_path) {
    int ctl = open(ctl_path, O_RDWR);
    if (ctl < 0) { log_perror(ctl_path); return -1; }
    struct usb_device_info di;
    if (ioctl(ctl, USB_GET_DEVICEINFO, &di) < 0
        || di.udi_vendorNo  != FTDI_VID
        || di.udi_productNo != FT240X_PID) {
        log_msg(LOG_ERR, "no FT240X at %s", ctl_path);
        close(ctl);
        return -1;
    }
    char in_path[64], out_path[64];
    size_t L = strlen(ctl_path);
    if (L < 3 || strcmp(ctl_path + L - 3, ".00") != 0) {
        log_msg(LOG_ERR, "expected ugenN.00 path, got %s", ctl_path);
        close(ctl);
        return -1;
    }
    snprintf(in_path,  sizeof in_path,  "%.*s.01", (int)(L - 3), ctl_path);
    snprintf(out_path, sizeof out_path, "%.*s.02", (int)(L - 3), ctl_path);

    int in  = open(in_path,  O_RDONLY);
    int out = open(out_path, O_WRONLY);
    if (in < 0 || out < 0) {
        log_perror("ugenN.{01,02}");
        if (in  >= 0) close(in);
        if (out >= 0) close(out);
        close(ctl);
        return -1;
    }
    int ms = 2000, sh = 1;
    (void)ioctl(ctl, USB_SET_TIMEOUT,    &ms);
    (void)ioctl(in,  USB_SET_TIMEOUT,    &ms);
    (void)ioctl(out, USB_SET_TIMEOUT,    &ms);
    (void)ioctl(in,  USB_SET_SHORT_XFER, &sh);

    c->ctl = ctl;
    c->in  = in;
    c->out = out;
    log_msg(LOG_INFO, "opened FT240X at %s (vid=%04x pid=%04x)",
            ctl_path, FTDI_VID, FT240X_PID);
    return 0;
}

static void dev_close_fds(infnoise_ctx *c) {
    if (c->in  >= 0) close(c->in);
    if (c->out >= 0) close(c->out);
    if (c->ctl >= 0) close(c->ctl);
    c->in = c->out = c->ctl = -1;
}

static int dev_control(infnoise_ctx *c, uint8_t req, uint16_t val, uint16_t idx) {
    struct usb_ctl_request r;
    memset(&r, 0, sizeof r);
    r.ucr_request.bmRequestType = 0x40;
    r.ucr_request.bRequest      = req;
    USETW(r.ucr_request.wValue,  val);
    USETW(r.ucr_request.wIndex,  idx);
    USETW(r.ucr_request.wLength, 0);
    r.ucr_data  = NULL;
    r.ucr_flags = 0;
    return ioctl(c->ctl, USB_DO_REQUEST, &r);
}

static int dev_bulk_out(infnoise_ctx *c, const uint8_t *buf, int len) {
    return (int)write(c->out, buf, (size_t)len);
}
static int dev_bulk_in(infnoise_ctx *c, uint8_t *buf, int len) {
    return (int)read(c->in, buf, (size_t)len);
}

int infnoise_read_serial(const char *path, char *out, size_t cap)
{
    if (!path || !out || cap == 0) return -1;
    out[0] = '\0';
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct usb_device_info di;
    int rv = ioctl(fd, USB_GET_DEVICEINFO, &di);
    close(fd);
    if (rv < 0) return -1;
    snprintf(out, cap, "%s", di.udi_serial);
    return 0;
}

#else
# error "unsupported platform: need Linux or a BSD with ugen(4)"
#endif

void infnoise_free_paths(char **paths, size_t count) {
    if (!paths) return;
    for (size_t i = 0; i < count; i++) free(paths[i]);
    free(paths);
}

/* --- Health monitor (per-context) --------------------------------------- */

static void hc_scale_tables(infnoise_ctx *c) {
    for (uint32_t i = 0; i < HC_CTX; i++) {
        c->hc_ones[i]  >>= 1;
        c->hc_zeros[i] >>= 1;
    }
}

static bool health_add_bit(infnoise_ctx *c, int bit) {
    bit &= 1;
    c->hc_total++;
    c->hc_prev_bits = ((c->hc_prev_bits << 1) | (unsigned)(c->hc_prev_bit & 1))
                    & (HC_CTX - 1u);
    c->hc_prev_bit = bit;

    if (c->hc_sampled > 100u) {
        if (bit) {
            c->hc_run1++; c->hc_run0 = 0;
            if (c->hc_run1 > HC_MAX_SEQ) return false;
        } else {
            c->hc_run0++; c->hc_run1 = 0;
            if (c->hc_run0 > HC_MAX_SEQ) return false;
        }
    }

    uint32_t z = c->hc_zeros[c->hc_prev_bits];
    uint32_t o = c->hc_ones [c->hc_prev_bits];
    uint32_t tot = z + o;
    if (tot > 0) {
        if      ( bit && o > 0) c->hc_prob *= (double)o / (double)tot;
        else if (!bit && z > 0) c->hc_prob *= (double)z / (double)tot;
    }
    while (c->hc_prob > 0.0 && c->hc_prob <= 0.5) {
        c->hc_prob *= 2.0;
        c->hc_ent_bits++;
    }

    c->hc_sampled++;
    uint32_t *cell = bit ? &c->hc_ones[c->hc_prev_bits]
                         : &c->hc_zeros[c->hc_prev_bits];
    if (++(*cell) >= HC_MAX_COUNT) hc_scale_tables(c);

    if (c->hc_sampled == HC_WARMUP) {
        c->hc_ent_bits >>= 1;
        c->hc_sampled  >>= 1;
    }
    return true;
}

static bool health_ok(infnoise_ctx *c) {
    if (c->hc_total < HC_WARMUP) return false;
    uint32_t denom = c->hc_sampled ? c->hc_sampled : 1u;
    double e = (double)c->hc_ent_bits / (double)denom;
    return e * HC_ACCURACY >= HC_EXPECTED
        && e / HC_ACCURACY <= HC_EXPECTED;
}

/* --- FTDI sync-bitbang configuration ------------------------------------ */

static int setup_ftdi(infnoise_ctx *c) {
    if (dev_control(c, SIO_RESET, SIO_RESET_SIO, FTDI_PORT_A) < 0) {
        log_perror("SIO_RESET"); return -1;
    }
    if (dev_control(c, SIO_SET_BITMODE,
                    ((uint16_t)BITMODE_RESET << 8), FTDI_PORT_A) < 0) {
        log_perror("SIO_SET_BITMODE (reset)"); return -1;
    }
    if (dev_control(c, SIO_RESET, SIO_RESET_PURGE_RX, FTDI_PORT_A) < 0) {
        log_perror("SIO_RESET PURGE_RX"); return -1;
    }
    if (dev_control(c, SIO_RESET, SIO_RESET_PURGE_TX, FTDI_PORT_A) < 0) {
        log_perror("SIO_RESET PURGE_TX"); return -1;
    }
    if (dev_control(c, SIO_SET_LATENCY, 1, FTDI_PORT_A) < 0) {
        int e = errno;
        log_msg(LOG_WARNING, "SIO_SET_LATENCY rejected: %s "
                "(continuing with default timer)", strerror(e));
    }
    uint16_t bm = ((uint16_t)BITMODE_SYNCBB << 8) | INM_MASK;
    if (dev_control(c, SIO_SET_BITMODE, bm, FTDI_PORT_A) < 0) {
        log_perror("SIO_SET_BITMODE"); return -1;
    }
    if (dev_control(c, SIO_SET_BAUDRATE, BAUD_VALUE, BAUD_INDEX) < 0) {
        log_perror("SIO_SET_BAUDRATE"); return -1;
    }
    log_msg(LOG_INFO, "FTDI configured: sync bit-bang, %d baud", 30000);
    return 0;
}

/* --- Public API: open / read / close ------------------------------------ */

int infnoise_open(infnoise_ctx *c, const char *path) {
    if (!c) return -1;
    if (c->opened) return 0;

    char first[128];
    if (!path) {
        if (dev_find_first(first, sizeof first) < 0) {
            log_msg(LOG_ERR, "no FT240X (%04x:%04x) on USB",
                    FTDI_VID, FT240X_PID);
            return -1;
        }
        path = first;
    }

    if (dev_open_path(c, path) < 0) return -1;
    if (setup_ftdi(c) < 0) {
        dev_close_fds(c);
        return -1;
    }
    free(c->path);
    c->path = strdup(path);    /* strdup failure is non-fatal */

    for (int i = 0; i < SAMPLES_PER_XFER; i++)
        c->clock_pattern[i] = (i & 1) ? PIN_SWEN2 : PIN_SWEN1;

    /* Priming drain: absorb anything queued around the mode switch. */
    (void)dev_bulk_out(c, c->clock_pattern, SAMPLES_PER_XFER);
    (void)dev_bulk_in (c, c->in_buf, IN_BUF_BYTES);

    c->in_n = c->in_pkt_off = c->in_pkt_end = c->in_pos = 0;
    c->sample_idx = 0;
    c->bit_acc = 0; c->bit_n = 0;
    c->health_announced = false;
    c->opened = true;
    return 0;
}

void infnoise_close(infnoise_ctx *c) {
    if (!c || !c->opened) return;
    dev_close_fds(c);
    c->opened = false;
}

static int usb_cycle(infnoise_ctx *c) {
    if (dev_bulk_out(c, c->clock_pattern, SAMPLES_PER_XFER)
        != SAMPLES_PER_XFER) {
        log_perror("bulk OUT"); return -1;
    }
    int n = dev_bulk_in(c, c->in_buf, IN_BUF_BYTES);
    if (n < 0) { log_perror("bulk IN"); return -1; }
    c->in_n       = n;
    c->in_pkt_off = 0;
    c->in_pkt_end = (n < IN_MAX_PACKET) ? n : IN_MAX_PACKET;
    c->in_pos     = FTDI_STATUS;
    c->sample_idx = 0;
    return 0;
}

ssize_t infnoise_read(infnoise_ctx *c, uint8_t *buf, size_t n) {
    if (!c || !c->opened) {
        log_msg(LOG_ERR, "infnoise_read called before infnoise_open");
        return -1;
    }
    size_t produced = 0;

    while (produced < n) {
        /* If the IN buffer is exhausted, pump another USB cycle. */
        if (c->in_pos >= c->in_pkt_end) {
            if (c->in_pkt_end < c->in_n) {
                c->in_pkt_off = c->in_pkt_end;
                c->in_pkt_end = c->in_pkt_off + IN_MAX_PACKET;
                if (c->in_pkt_end > c->in_n) c->in_pkt_end = c->in_n;
                c->in_pos = c->in_pkt_off + FTDI_STATUS;
                if (c->in_pos >= c->in_pkt_end) continue;
            } else {
                if (usb_cycle(c) < 0) return -1;
                if (c->in_n <= FTDI_STATUS) continue;
            }
        }

        /* Process one byte of the current packet. */
        uint8_t raw = c->in_buf[c->in_pos++];
        uint8_t bit = (c->sample_idx & 1)
            ? (uint8_t)((raw >> PIN_COMP2_SHIFT) & 1)
            : (uint8_t)((raw >> PIN_COMP1_SHIFT) & 1);
        c->sample_idx++;

        if (!health_add_bit(c, bit)) {
            log_msg(LOG_ERR, "health check FAILED "
                "(>%u identical bits in a row)", HC_MAX_SEQ);
            return -1;
        }
        c->bit_acc = (uint8_t)((c->bit_acc << 1) | bit);
        if (++c->bit_n != 8) continue;
        c->bit_n = 0;
        uint8_t done_byte = c->bit_acc;
        c->bit_acc = 0;
        if (!health_ok(c)) continue;
        if (!c->health_announced) {
            log_msg(LOG_INFO, "health check warm-up passed "
                "(%u samples, entropy in band)", HC_WARMUP);
            c->health_announced = true;
        }

        buf[produced++] = done_byte;
    }
    return (ssize_t)produced;
}
