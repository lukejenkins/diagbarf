/* SPDX-License-Identifier: Apache-2.0 */
/* diagbarf — native multi-protocol on-device DIAG egress daemon (#N)
 *
 * Shared across modules — validated on the Wistron LV55 (SDX55, #N) and the
 * Casa Systems CFW-3212 (SDX62, #N). The CFW-3212 has NO /dev/diag (DIAG runs
 * entirely in userspace via diag-router); diagbarf works there unchanged because
 * it never touches /dev/diag directly — it drives the OEM diag_socket_log, which
 * abstracts the underlying transport (kernel /dev/diag on SDX55, diag-router IPC
 * on SDX62). The single-MD-reader constraint below holds identically on both.
 *
 * One MD-mode DIAG reader that fans the firehose out to multiple sinks:
 *   - TCP listener (host dials in)         — raw HDLC, multi-client   [default ON]
 *   - UDP broadcast to the LAN iface       — DGE1 seq-framed          [default ON]
 *   - UDP unicast to a host:port           — DGE1 seq-framed          [opt]
 *   - TCP dial-out (back-compat #N)      — raw HDLC                 [opt]
 *
 * Why this shape (load-bearing constraint, see #N / <redacted-ref>):
 * /dev/diag has ONE memory-device (MD) consumer slot — two MD streamers
 * collide on the shared global DIAG_LOG_CONFIG_F mask and steal each other's
 * buffer bytes (broken HDLC for both). So there must be exactly ONE MD reader
 * that fans out internally. DCI recorders (diag_dci_recorder_wnc, ...) are
 * unaffected — they get private filtered copies.
 *
 * How we are the single MD reader without reimplementing libdiag:
 * the OEM `diag_socket_log` is the only on-device tool that does
 * Diag_LSM_Init() correctly. It is a TRANSPARENT bidirectional bridge between
 * a TCP socket and the DIAG transport (kernel /dev/diag on SDX55; diag-router
 * IPC on SDX62, where there is no /dev/diag) — it does NOT set the log mask
 * itself; the TCP peer drives the DIAG_LOG_CONFIG_F handshake (that is why
 * host `diaggulp`
 * owns it in the #N flow). We therefore spawn `diag_socket_log` as a captive
 * child dialing 127.0.0.1:<internal>, accept that one connection, ARM THE MASK
 * OURSELVES (port of diaggulp._build_all_logs_mask), then fan the resulting
 * raw HDLC stream out to all sinks. diag_socket_log stays the single
 * Diag_LSM_Init() MD reader; we are its sole peer + the fan-out hub.
 *
 * Language/runtime: C only, static armv7l hard-float (both SDX55 and SDX62 app
 * processors are armv7l). Lives in apps/diagbarf/ alongside the other on-device
 * DIAG C apps (apps/diag_udp_bridge, apps/diaggulp-native, apps/diagrooter).
 *
 * Build (host):  make -C apps/diagbarf
 *   == arm-linux-gnueabihf-gcc -static -O2 -Wall -Wextra -o diagbarf diagbarf.c
 *   readelf -A diagbarf   # must show Tag_CPU_arch: v7 + Tag_ABI_VFP_args: VFP registers
 *
 * Config + flags: see diagbarf.sh (sources /data/diagbarf/diagbarf.conf and
 * exec's this binary with derived flags). Flags override config.
 *
 * READ-ONLY w.r.t. the device: we set the global log mask (required for MD
 * capture) but write no NV, trigger no reboot, store nothing on device. The
 * DLF lands on the collector host(s).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <termios.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "diagchar_md.h"

/* ----------------------------------------------------------------------- */
/* Constants                                                               */
/* ----------------------------------------------------------------------- */

#define DEFAULT_PUBLIC_PORT   12399
#define DEFAULT_INTERNAL_PORT 12398
#define DEFAULT_RETRY         20
#define DEFAULT_BCAST_IFACE   "bridge0"

#define MAX_CLIENTS           32
#define READ_CHUNK            65536

/* UDP datagram framing — "DGE1" header (12 bytes), see #N spec. */
#define DGE_MAGIC             "DGE1"
#define DGE_VERSION           0x01
#define DGE_FLAG_RESTART      0x01    /* first datagram after an src re-spawn */
#define DGE_HDR_LEN           12
#define DGE_MAX_PAYLOAD       1400    /* MTU-safe: 1500 - 20 IP - 8 UDP, margin */

/* Software build/version string — the daemon's *source* version, NOT the
 * on-wire DGE framing version (DGE_VERSION above). Injected at compile time by
 * the Makefile via -DDIAGBARF_VERSION (git describe --always --dirty) and
 * -DDIAGBARF_BUILD_DATE. Fallbacks keep a non-git / hand-compiled build honest
 * rather than silently reporting a wrong version. See #N. */
#ifndef DIAGBARF_VERSION
#define DIAGBARF_VERSION      "unknown"
#endif
#ifndef DIAGBARF_BUILD_DATE
#define DIAGBARF_BUILD_DATE   "unknown"
#endif

/* DIAG opcodes / log-config subcommands (mirror tools/diaggulp.py). */
#define DIAG_LOG_CONFIG_F        115
#define DIAG_EXT_MSG_CONFIG_F    0x7D
#define DIAG_BAD_CMD_F           0x13
#define LOG_CFG_RETRIEVE_RANGES  1
#define LOG_CFG_SET_MASK         3
#define LOG_CFG_SUCCESS          0
#define EXT_MSG_SET_ALL_RT_MASKS 5
#define EXT_MSG_ALL_LEVELS       0xFFFFFFFFu
#define NUM_LOG_TYPES            16

/* ----------------------------------------------------------------------- */
/* CRC-16/MCRF4XX (== CRC-16/X.25) — Qualcomm DIAG/HDLC FCS.               */
/* Ported byte-for-byte from apps/diaggpsd/diag.py _crc16.                 */
/* ----------------------------------------------------------------------- */

static uint16_t crc16_table[256];

static void crc16_init(void)
{
    for (int i = 0; i < 256; i++) {
        uint16_t crc = (uint16_t)i;
        for (int j = 0; j < 8; j++)
            crc = (crc & 1) ? (uint16_t)((crc >> 1) ^ 0x8408) : (uint16_t)(crc >> 1);
        crc16_table[i] = crc;
    }
}

static uint16_t crc16(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++)
        crc = (uint16_t)((crc >> 8) ^ crc16_table[(crc ^ data[i]) & 0xFF]);
    return (uint16_t)(crc ^ 0xFFFF);
}

/* ----------------------------------------------------------------------- */
/* Config (populated by argv; defaults match the #N spec)               */
/* ----------------------------------------------------------------------- */

struct config {
    int tcp_listen_enabled;
    struct sockaddr_in tcp_listen_addr;

    int udp_bcast_enabled;
    struct sockaddr_in udp_bcast_addr;     /* resolved broadcast dest */
    char bcast_iface[IFNAMSIZ];            /* iface name, if resolution deferred */
    int bcast_iface_resolve;               /* 1 = resolve iface -> bcast at runtime */
    int bcast_port;

    int udp_unicast_enabled;
    struct sockaddr_in udp_unicast_addr;

    int tcp_dial_enabled;
    struct sockaddr_in tcp_dial_addr;

    int internal_port;
    int retry;
    int ext_msg_f3;
    int mask_max;                          /* 1 = max mask (only supported mode) */
    const char *diag_socket_log;           /* path/name of OEM binary */
    const char *source;                    /* "socket-log" (default) | "diag-dev" */
    const char *diag_dev;                  /* kernel diag node when source=diag-dev */
};

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int s) { (void)s; g_stop = 1; }

/* ----------------------------------------------------------------------- */
/* Small logging helper (stderr, line-buffered under systemd journal)      */
/* ----------------------------------------------------------------------- */

static void logmsg(const char *fmt, ...)
{
    va_list ap;
    char buf[1024];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    fprintf(stderr, "diagbarf: %s\n", buf);
    fflush(stderr);
}

/* ----------------------------------------------------------------------- */
/* host:port / addr parsing (numeric only — no getaddrinfo/NSS for static) */
/* ----------------------------------------------------------------------- */

/* Parse "[addr:]port" or "addr:port" into sa. If no addr part, use def_addr
 * (e.g. INADDR_ANY for a listener). Returns 0 on success, -1 on parse error. */
static int parse_hostport(const char *s, struct sockaddr_in *sa,
                          uint32_t def_addr)
{
    char tmp[128];
    snprintf(tmp, sizeof tmp, "%s", s);
    char *colon = strrchr(tmp, ':');
    const char *addr_str = NULL;
    const char *port_str;
    if (colon) {
        *colon = '\0';
        addr_str = tmp;
        port_str = colon + 1;
    } else {
        port_str = tmp;     /* bare port */
    }
    int port = atoi(port_str);
    if (port <= 0 || port > 65535)
        return -1;
    memset(sa, 0, sizeof *sa);
    sa->sin_family = AF_INET;
    sa->sin_port = htons((uint16_t)port);
    if (addr_str && *addr_str) {
        if (inet_pton(AF_INET, addr_str, &sa->sin_addr) != 1)
            return -1;
    } else {
        sa->sin_addr.s_addr = htonl(def_addr);
    }
    return 0;
}

/* Resolve an interface name to its IPv4 broadcast address (SIOCGIFBRDADDR). */
static int iface_broadcast(const char *iface, struct in_addr *out)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", iface);
    int rc = ioctl(fd, SIOCGIFBRDADDR, &ifr);
    close(fd);
    if (rc < 0)
        return -1;
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_broadaddr;
    *out = sin->sin_addr;
    return 0;
}

/* ----------------------------------------------------------------------- */
/* HDLC framing for the mask handshake (the ONLY deframing we ever do).    */
/* Mirrors apps/diaggpsd/diag.py _hdlc_encapsulate / _hdlc_decapsulate     */
/* (TCP/no-CRC mode for inbound: strip trailing 2 bytes without verify).   */
/* ----------------------------------------------------------------------- */

/* Encapsulate a DIAG packet (opcode byte already at payload[0]): append
 * CRC-16 (LE), byte-stuff 0x7D then 0x7E, append 0x7E delimiter. Writes into
 * out (must be >= 2*(len+2)+1). Returns encoded length. */
static size_t hdlc_encap(const uint8_t *payload, size_t len,
                         uint8_t *out, size_t outcap)
{
    uint8_t buf[2048];
    if (len + 2 > sizeof buf)
        return 0;
    memcpy(buf, payload, len);
    uint16_t c = crc16(payload, len);
    buf[len]     = (uint8_t)(c & 0xFF);
    buf[len + 1] = (uint8_t)((c >> 8) & 0xFF);
    size_t total = len + 2;

    size_t o = 0;
    for (size_t i = 0; i < total; i++) {
        uint8_t b = buf[i];
        if (b == 0x7D) {
            if (o + 2 > outcap) return 0;
            out[o++] = 0x7D; out[o++] = 0x5D;
        } else if (b == 0x7E) {
            if (o + 2 > outcap) return 0;
            out[o++] = 0x7D; out[o++] = 0x5E;
        } else {
            if (o + 1 > outcap) return 0;
            out[o++] = b;
        }
    }
    if (o + 1 > outcap) return 0;
    out[o++] = 0x7E;
    return o;
}

/* Decapsulate one raw frame (delimiter already removed, no trailing 0x7E):
 * unescape 0x7E then 0x7D, strip trailing 2 bytes (no-CRC TCP mode). Writes
 * the decoded packet (opcode at [0]) into out. Returns decoded length, or -1
 * on a too-short/empty frame. */
static int hdlc_decap(const uint8_t *frame, size_t len,
                      uint8_t *out, size_t outcap)
{
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t b = frame[i];
        if (b == 0x7D && i + 1 < len) {
            uint8_t n = frame[++i];
            if (o >= outcap) return -1;
            out[o++] = (uint8_t)(n ^ 0x20);
        } else {
            if (o >= outcap) return -1;
            out[o++] = b;
        }
    }
    if (o < 2)
        return -1;          /* too short to hold even the 2 trailer bytes */
    return (int)(o - 2);    /* strip the 2-byte trailer (CRC, unverified) */
}

/* ----------------------------------------------------------------------- */
/* Mask handshake over the captive src socket                              */
/* ----------------------------------------------------------------------- */

/* A pending receive buffer for frame reassembly during the handshake. */
struct rxbuf {
    uint8_t buf[262144];
    size_t len;
};

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* Write all bytes to fd (blocking). Returns 0 / -1. */
static int write_all(int fd, const uint8_t *p, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, p + off, n - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

/* ---- diagchar /dev/diag message framing (kernel MEMORY_DEVICE path) ----
 * Empirically pinned on the M2000 (SDX55, kernel 4.14.117) — see session note.
 *
 * Data-type word: the *kernel char-device* value differs from the diag-router
 * Unix-socket value used in diagrooter.c (0). QCSuper's USER_SPACE_DATA_TYPE
 * (0x20) is the one /dev/diag uses.
 *
 * WRITE format:  [type:u32 = USER_SPACE_DATA_TYPE][HDLC-encoded command].
 *   write() to /dev/diag is all-or-nothing and returns 0 (accepted/queued),
 *   the count, or <0 — it is NOT a partial-write fd (write_all would spin).
 *
 * READ format (MEMORY_DEVICE mode): for USER_SPACE_DATA_TYPE buffers,
 *   [type:u32 = 0x20][num_data:u32][ (len:u32)(HDLC frame) ] * num_data.
 *   Other read types (DCI 0x04, masks 0x02/0x08/0x10, and 0x100/0x200 control
 *   buffers) are not log/response traffic and are skipped. */
#define USER_SPACE_DATA_TYPE     0x20u
#define DCI_DATA_TYPE            0x04u
#define MSG_MASKS_TYPE           0x02u
#define LOG_MASKS_TYPE           0x08u
#define EVENT_MASKS_TYPE         0x10u

/* Prepend the USER_SPACE_DATA_TYPE word to an HDLC command frame.
 * Returns bytes written to out, or 0 if out too small. */
static size_t diagdev_wrap_cmd(const uint8_t *frame, size_t len,
                               uint8_t *out, size_t outcap) {
    if (outcap < 4 + len) return 0;
    uint32_t t = USER_SPACE_DATA_TYPE;
    memcpy(out, &t, 4);
    memcpy(out + 4, frame, len);
    return 4 + len;
}

/* For a kernel read() buffer: if it is a USER_SPACE_DATA_TYPE buffer, return the
 * message count (>=0) and point *msgs at the first per-message record (buf+8).
 * Returns -1 for any other (control/DCI/mask) buffer, which the caller skips. */
static int diagdev_user_msgs(const uint8_t *buf, size_t n, const uint8_t **msgs) {
    if (n < 8) return -1;
    uint32_t t; memcpy(&t, buf, 4);
    if (t != USER_SPACE_DATA_TYPE) return -1;
    uint32_t num; memcpy(&num, buf + 4, 4);
    *msgs = buf + 8;
    return (int)num;
}

/* Pull the next length-prefixed [len:u32][frame:len] record from msgs[0..n),
 * advancing off. Sets fp and flen to the HDLC frame. Returns 1 on success, 0
 * when no complete record remains. */
static int diagdev_next_msg(const uint8_t *msgs, size_t n, size_t *off,
                            const uint8_t **fp, size_t *flen) {
    if (*off + 4 > n) return 0;
    uint32_t len; memcpy(&len, msgs + *off, 4);
    *off += 4;
    if (len == 0 || *off + len > n) return 0;
    *fp = msgs + *off; *flen = len;
    *off += len;
    return 1;
}

/* Advance *off to consume one complete 0x7E-terminated frame in buf[0..n).
 * On success sets *flen (incl. trailing 0x7E) and returns 1. Returns 0 when
 * only a partial frame remains (leaves *off at the start of the remainder). */
static int diagdev_next_frame(const uint8_t *buf, size_t n,
                              size_t *off, size_t *flen) {
    const uint8_t *start = buf + *off;
    size_t avail = n - *off;
    const uint8_t *d = memchr(start, 0x7E, avail);
    if (!d) return 0;
    *flen = (size_t)(d - start) + 1;
    *off += *flen;
    return 1;
}

#ifndef DIAGBARF_FRAMING_TEST
/* ---- native /dev/diag source: in-process diag_socket_log replacement ----
 * A bridge thread owns the kernel /dev/diag fd (in MEMORY_DEVICE mode) and
 * translates between the kernel's 4-byte-type-prefixed messages and a
 * socketpair carrying a raw-HDLC byte stream. The far end of the socketpair
 * becomes diagbarf's `src`, so arm_mask()/recv_frame()/fan-out are unchanged. */
struct diagdev_ctx { int diag_fd; int sp_fd; };

static void *diagdev_bridge(void *arg) {
    struct diagdev_ctx *c = arg;
    uint8_t rd[262144];                 /* from /dev/diag */
    uint8_t wr[8192];                   /* accumulate cmd frames from src side */
    size_t wlen = 0;
    struct pollfd pfd[2] = {
        { .fd = c->diag_fd, .events = POLLIN, .revents = 0 },
        { .fd = c->sp_fd,   .events = POLLIN, .revents = 0 },
    };
    for (;;) {
        if (poll(pfd, 2, 1000) < 0) {
            if (errno == EINTR) { if (g_stop) break; continue; }
            break;
        }
        /* /dev/diag -> src: forward HDLC frames from USER_SPACE_DATA_TYPE reads */
        if (pfd[0].revents & POLLIN) {
            ssize_t n = read(c->diag_fd, rd, sizeof rd);
            if (n <= 0) break;
#ifdef DIAGDEV_DEBUG
            { static int dbg = 0; if (dbg++ < 12) {
                uint32_t t0 = 0; if (n >= 4) memcpy(&t0, rd, 4);
                logmsg("DBG read#%d n=%zd type=%u", dbg, n, t0); } }
#endif
            const uint8_t *msgs;
            int num = diagdev_user_msgs(rd, (size_t)n, &msgs);
            if (num > 0) {
                size_t moff = 0, mn = (size_t)n - 8;
                const uint8_t *fp; size_t fl;
                int got = 0, berr = 0;
                while (got < num && diagdev_next_msg(msgs, mn, &moff, &fp, &fl)) {
                    if (write_all(c->sp_fd, fp, fl) < 0) { berr = 1; break; }
                    got++;
                }
                if (berr) break;
            }
        }
        /* src -> /dev/diag: split on 0x7E, wrap each frame with type word */
        if (pfd[1].revents & POLLIN) {
            if (wlen >= sizeof wr) wlen = 0;   /* runaway guard */
            ssize_t n = read(c->sp_fd, wr + wlen, sizeof wr - wlen);
            if (n <= 0) break;
            wlen += (size_t)n;
#ifdef DIAGDEV_DEBUG
            { char hx[3*64+1]; size_t k=0; for (size_t i=0;i<wlen && i<64;i++) k+=snprintf(hx+k,sizeof hx-k,"%02x ",wr[i]);
              logmsg("DBG src->diag: read %zd wlen=%zu hex: %s", n, wlen, hx); }
#endif
            size_t off = 0, flen;
            int err = 0;
            int nframes = 0;
            while (diagdev_next_frame(wr, wlen, &off, &flen)) {
                uint8_t msg[8192];
                size_t m = diagdev_wrap_cmd(wr + off - flen, flen, msg, sizeof msg);
                nframes++;
                /* diagchar write() is all-or-nothing: it returns the count, or 0
                 * (accepted/queued), or <0 on error. /dev/diag is NOT a
                 * partial-write fd, so a single write() is correct — write_all()
                 * would spin forever on a 0 return. */
                ssize_t raww = m ? write(c->diag_fd, msg, m) : -1;
#ifdef DIAGDEV_DEBUG
                logmsg("DBG diag<-cmd: frame=%zu wrapped=%zu write()=%zd errno=%d op=0x%02x",
                       flen, m, raww, errno, (wr+off-flen)[0]);
#endif
                if (raww < 0) { err = 1; break; }
            }
#ifdef DIAGDEV_DEBUG
            if (nframes == 0) logmsg("DBG src->diag: no complete frame yet (wlen=%zu)", wlen);
#endif
            if (err) break;
            memmove(wr, wr + off, wlen - off);
            wlen -= off;
        }
        if (g_stop) break;
    }
    close(c->diag_fd);
    close(c->sp_fd);
    free(c);
    return NULL;
}

/* Open /dev/diag, switch to MEMORY_DEVICE mode, spawn the bridge thread.
 * Returns the caller-side socketpair fd to use as `src`, or -1. */
static int start_diag_dev_source(const char *path, pthread_t *tid_out) {
    int dfd = open(path, O_RDWR);
    if (dfd < 0) { logmsg("open %s: %s", path, strerror(errno)); return -1; }

    struct diag_logging_mode_param_t lp;
    memset(&lp, 0, sizeof lp);
    lp.req_mode = DIAG_MEMORY_DEVICE_MODE;
    lp.peripheral_mask = DIAG_CON_ALL;
    lp.pd_mask = 0;
    lp.mode_param = 0;
    lp.device_mask = 1 << DIAG_MD_LOCAL;
    if (ioctl(dfd, DIAG_IOCTL_SWITCH_LOGGING, &lp) < 0) {
        logmsg("SWITCH_LOGGING(MEMORY_DEVICE) failed: %s", strerror(errno));
        close(dfd); return -1;
    }
    logmsg("diag-dev: %s in MEMORY_DEVICE mode (peripheral_mask=0x%x)",
           path, lp.peripheral_mask);

    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) {
        logmsg("socketpair: %s", strerror(errno)); close(dfd); return -1;
    }
    struct diagdev_ctx *c = malloc(sizeof *c);
    if (!c) { logmsg("diag-dev: OOM"); close(dfd); close(sp[0]); close(sp[1]); return -1; }
    c->diag_fd = dfd; c->sp_fd = sp[1];
    if (pthread_create(tid_out, NULL, diagdev_bridge, c) != 0) {
        logmsg("pthread_create bridge failed");
        close(dfd); close(sp[0]); close(sp[1]); free(c); return -1;
    }
    return sp[0];   /* diagbarf's `src` */
}

/* ---- host-side serial-like DIAG chardev source (#N) ------------------
 * On a jump box, the modem's DIAG stream is exposed at a serial-like HDLC
 * chardev: /dev/mhi_DIAG (PCIe/MHI Quectel) or /dev/ttyUSB2 (USB modems).
 * Unlike the modem-kernel /dev/diag (diag-dev mode, which uses CRC-less
 * type-0x20 diagchar framing and needs the MEMORY_DEVICE ioctl + a bridge
 * thread), this chardev IS the transport: it already speaks full HDLC with a
 * CRC-16 FCS in both directions. So there is no captive OEM binary, no ioctl,
 * and no bridge thread — we open the device and hand the raw fd straight to
 * arm_mask()/recv_frame() as `src`. hdlc_encap() already appends the CRC the
 * MHI/USB config path requires (this is the #N CRC-HDLC transport lesson:
 * diaggulp's CRC-less tcp/tcp-connect modes silently break the F3-enable
 * handshake against an MHI device; only the CRC'd serial path works).
 *
 * The fd is left BLOCKING to match the socket-log (accept'd TCP) and diag-dev
 * (socketpair) srcs: recv_frame()/the pump both poll() before every read(),
 * so a blocking fd never stalls and recv_frame()'s read loop (which does not
 * special-case EAGAIN) stays correct.
 *
 * Returns the chardev fd to use as `src`, or -1 on open failure. */
static int start_hdlc_chardev_source(const char *path) {
    int fd = open(path, O_RDWR | O_NOCTTY);
    if (fd < 0) { logmsg("open %s: %s", path, strerror(errno)); return -1; }

    /* Put a real tty (USB /dev/ttyUSB*) into raw 8N1 @115200 with no line
     * discipline processing. MHI chardevs (/dev/mhi_DIAG) are not ttys —
     * tcgetattr fails with ENOTTY; the bare raw fd is correct there (the HDLC
     * framing is entirely software-side). Mirrors DiagClient.from_serial's
     * raw-termios path in apps/diaggpsd/diag.py. */
    struct termios tio;
    if (tcgetattr(fd, &tio) == 0) {
        tio.c_iflag = 0;
        tio.c_oflag = 0;
        tio.c_cflag = CS8 | CREAD | CLOCAL;
        tio.c_lflag = 0;
        cfsetispeed(&tio, B115200);
        cfsetospeed(&tio, B115200);
        tio.c_cc[VMIN]  = 0;
        tio.c_cc[VTIME] = 0;
        if (tcsetattr(fd, TCSANOW, &tio) == 0) {
            tcflush(fd, TCIOFLUSH);
            logmsg("hdlc-chardev: %s configured raw 8N1 @115200 (tty)", path);
        } else {
            logmsg("hdlc-chardev: %s tcsetattr failed (%s); using bare raw fd",
                   path, strerror(errno));
        }
    } else {
        logmsg("hdlc-chardev: %s not a tty (%s); using bare raw fd (MHI chardev)",
               path, strerror(errno));
    }
    return fd;
}
#endif /* DIAGBARF_FRAMING_TEST */

/* Receive the next complete HDLC frame from src into out. Skips empty
 * inter-frame delimiters. Returns decoded packet length (opcode at out[0]),
 * 0 on timeout, -1 on EOF/error. */
static int recv_frame(int src, struct rxbuf *rx, int timeout_ms,
                      uint8_t *out, size_t outcap)
{
    long deadline = now_ms() + timeout_ms;
    for (;;) {
        /* Is there a complete frame already buffered? */
        uint8_t *delim = memchr(rx->buf, 0x7E, rx->len);
        if (delim) {
            size_t flen = (size_t)(delim - rx->buf);
            int dec = -1;
            if (flen > 0)
                dec = hdlc_decap(rx->buf, flen, out, outcap);
            /* shift remainder down past the delimiter */
            size_t consumed = flen + 1;
            memmove(rx->buf, rx->buf + consumed, rx->len - consumed);
            rx->len -= consumed;
            if (dec >= 1)
                return dec;
            continue;       /* empty/malformed frame — keep scanning */
        }

        long rem = deadline - now_ms();
        if (rem <= 0)
            return 0;
        struct pollfd pfd = { .fd = src, .events = POLLIN };
        int pr = poll(&pfd, 1, (int)(rem > 1000 ? 1000 : rem));
        if (pr < 0) {
            if (errno == EINTR) { if (g_stop) return -1; continue; }
            return -1;
        }
        if (pr == 0)
            continue;
        if (rx->len >= sizeof rx->buf)
            return -1;      /* runaway — no delimiter in 256K, give up */
        ssize_t n = read(src, rx->buf + rx->len, sizeof rx->buf - rx->len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0)
            return -1;      /* EOF */
        rx->len += (size_t)n;
    }
}

/* Send a DIAG command (opcode + payload) and wait for the matching-opcode
 * response. Returns response body length (excluding opcode) into resp, or
 * -1 on timeout/error/BAD_CMD. */
static int send_recv(int src, struct rxbuf *rx, uint8_t opcode,
                     const uint8_t *payload, size_t plen,
                     int timeout_ms, uint8_t *resp, size_t respcap)
{
    uint8_t pkt[2048], enc[4096];
    if (1 + plen > sizeof pkt)
        return -1;
    pkt[0] = opcode;
    memcpy(pkt + 1, payload, plen);
    size_t enclen = hdlc_encap(pkt, 1 + plen, enc, sizeof enc);
    if (enclen == 0 || write_all(src, enc, enclen) < 0)
        return -1;

    long deadline = now_ms() + timeout_ms;
    uint8_t frame[8192];
    for (;;) {
        long rem = deadline - now_ms();
        if (rem <= 0)
            return -1;
        int flen = recv_frame(src, rx, (int)rem, frame, sizeof frame);
        if (flen < 0)
            return -1;
        if (flen == 0)
            return -1;      /* timeout */
        uint8_t op = frame[0];
        if (op == opcode) {
            size_t body = (size_t)flen - 1;
            if (body > respcap) body = respcap;
            memcpy(resp, frame + 1, body);
            return (int)body;
        }
        if (op == DIAG_BAD_CMD_F) {
            logmsg("modem returned DIAG_BAD_CMD_F (0x13) for opcode 0x%02x", opcode);
            return -1;
        }
        /* else: unsolicited LOG (0x10) / status frame — discard, keep waiting */
    }
}

/* Arm the global log mask to "everything" (port of
 * diaggulp._build_all_logs_mask). Returns 0 on success, -1 on failure
 * (caller treats failure as non-fatal and pumps anyway). */
static int arm_mask(int src, struct rxbuf *rx, int ext_msg_f3)
{
    uint8_t resp[8192];

    /* RETRIEVE_RANGES: payload = 3 pad + uint32(op=1) */
    uint8_t rr[7] = { 0, 0, 0, 0, 0, 0, 0 };
    rr[3] = LOG_CFG_RETRIEVE_RANGES;     /* LE uint32 in rr[3..6] */
    int rlen = send_recv(src, rx, DIAG_LOG_CONFIG_F, rr, sizeof rr, 10000,
                         resp, sizeof resp);
    if (rlen < 0) {
        logmsg("mask: RETRIEVE_RANGES failed/timeout");
        return -1;
    }
    /* body layout: 3 pad + uint32 operation + uint32 status + 16 * uint32 bitsizes */
    if (rlen < 11 + (int)(NUM_LOG_TYPES * 4)) {
        logmsg("mask: RETRIEVE_RANGES response too short (%d bytes)", rlen);
        return -1;
    }
    uint32_t operation, status;
    memcpy(&operation, resp + 3, 4);
    memcpy(&status, resp + 7, 4);
    if (operation != LOG_CFG_RETRIEVE_RANGES || status != LOG_CFG_SUCCESS) {
        logmsg("mask: RETRIEVE_RANGES op=%u status=%u (expected 1/0)",
               operation, status);
        return -1;
    }
    uint32_t bitsizes[NUM_LOG_TYPES];
    memcpy(bitsizes, resp + 11, NUM_LOG_TYPES * 4);

    int groups = 0;
    long total_codes = 0;
    for (uint32_t lt = 0; lt < NUM_LOG_TYPES; lt++) {
        uint32_t bs = bitsizes[lt];
        if (!bs)
            continue;
        size_t mbytes = (bs + 7) / 8;
        /* payload = 3 pad + op(3) + log_type + bitsize + mask[mbytes] */
        size_t plen = 3 + 4 + 4 + 4 + mbytes;
        uint8_t *p = malloc(plen);
        if (!p) { logmsg("mask: OOM"); return -1; }
        memset(p, 0, 3);
        uint32_t op3 = LOG_CFG_SET_MASK;
        memcpy(p + 3, &op3, 4);
        memcpy(p + 7, &lt, 4);
        memcpy(p + 11, &bs, 4);
        memset(p + 15, 0xFF, mbytes);
        if (bs % 8) {                     /* trim extra bits in the last byte */
            int extra = 8 - (int)(bs % 8);
            p[15 + mbytes - 1] = (uint8_t)(0xFF >> extra);
        }
        int sr = send_recv(src, rx, DIAG_LOG_CONFIG_F, p, plen, 10000,
                           resp, sizeof resp);
        free(p);
        if (sr < 0) {
            logmsg("mask: SET_MASK log_type=%u failed/timeout", lt);
            return -1;
        }
        groups++;
        total_codes += bs;
    }
    logmsg("mask: subscribed to all %ld log codes across %d groups",
           total_codes, groups);

    if (ext_msg_f3) {
        /* DIAG_EXT_MSG_CONFIG_F / SET_ALL_RT_MASKS: byte(5) + 2 pad + uint32(0xFFFFFFFF) */
        uint8_t e[7];
        e[0] = EXT_MSG_SET_ALL_RT_MASKS;
        e[1] = 0; e[2] = 0;
        uint32_t all = EXT_MSG_ALL_LEVELS;
        memcpy(e + 3, &all, 4);
        int er = send_recv(src, rx, DIAG_EXT_MSG_CONFIG_F, e, sizeof e, 10000,
                           resp, sizeof resp);
        if (er < 0)
            logmsg("mask: F3 ext-msg enable failed (non-fatal)");
        else
            logmsg("mask: enabled all F3 ext-msg runtime levels");
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* Sinks                                                                   */
/* ----------------------------------------------------------------------- */

struct udp_sink {
    int enabled;
    int fd;
    struct sockaddr_in dest;
    uint32_t seq;
};

struct tcp_out {                  /* tcp-dial back-compat sink */
    int enabled;
    int fd;                       /* -1 when disconnected */
    struct sockaddr_in dest;
    long next_retry_ms;
};

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* Remove closed (-1) slots from clients[0..n), preserving the survivors'
 * order, and clear the freed tail. Returns the survivor count. Used by the
 * fan-out loop so client removal is a tombstone-then-compact pass rather than
 * a swap-during-iterate (which desynced the poll-slot map — the #N live-USB
 * crash: a client accepted mid-cycle was drained against an uninitialized
 * pfds index). Pure/testable: no fd side effects. */
static int compact_clients(int *clients, int n)
{
    int w = 0;
    for (int r = 0; r < n; r++)
        if (clients[r] >= 0)
            clients[w++] = clients[r];
    for (int i = w; i < n; i++)
        clients[i] = -1;
    return w;
}

/* Send a byte-stream chunk over a UDP sink as DGE1-framed datagrams. */
static void udp_send_chunk(struct udp_sink *s, const uint8_t *data, size_t len,
                           int restart)
{
    if (!s->enabled)
        return;
    size_t off = 0;
    int first = restart;
    while (off < len) {
        size_t take = len - off;
        if (take > DGE_MAX_PAYLOAD)
            take = DGE_MAX_PAYLOAD;
        uint8_t dgram[DGE_HDR_LEN + DGE_MAX_PAYLOAD];
        memcpy(dgram, DGE_MAGIC, 4);
        dgram[4] = DGE_VERSION;
        dgram[5] = (uint8_t)(first ? DGE_FLAG_RESTART : 0);
        uint32_t seq = s->seq++;
        memcpy(dgram + 6, &seq, 4);          /* host LE (armv7 LE); host==wire */
        uint16_t l16 = (uint16_t)take;
        memcpy(dgram + 10, &l16, 2);
        memcpy(dgram + DGE_HDR_LEN, data + off, take);
        ssize_t w = sendto(s->fd, dgram, DGE_HDR_LEN + take, 0,
                           (struct sockaddr *)&s->dest, sizeof s->dest);
        (void)w;     /* UDP best-effort: ignore transient send errors */
        off += take;
        first = 0;
    }
}

/* ----------------------------------------------------------------------- */
/* diag_socket_log child management                                        */
/* ----------------------------------------------------------------------- */

static pid_t spawn_diag_socket_log(const char *bin, int port, int retry)
{
    char portbuf[16], retrybuf[16];
    snprintf(portbuf, sizeof portbuf, "%d", port);
    snprintf(retrybuf, sizeof retrybuf, "%d", retry);
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        /* child: silence diag_socket_log's verbose DIAG pool/debug chatter —
         * it inherits our stdout/stderr otherwise and floods the journal. The
         * DIAG stream itself flows over the TCP socket, NOT stdout, so this is
         * safe. (Keep stderr->/dev/null too; an exec failure is reported via
         * the _exit(127) status, which the parent's accept-timeout handles.) */
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, 1);
            dup2(devnull, 2);
            if (devnull > 2) close(devnull);
        }
        execlp(bin, bin, "-a", "127.0.0.1", "-p", portbuf, "-r", retrybuf,
               (char *)NULL);
        _exit(127);
    }
    return pid;
}

static void kill_diag_socket_log(const char *bin)
{
    /* Ask the OEM binary to clean up its own prior instance (-k), like
     * diag_collector.sh. Best-effort. */
    pid_t pid = fork();
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 2); }
        execlp(bin, bin, "-k", (char *)NULL);
        _exit(127);
    } else if (pid > 0) {
        int st;
        waitpid(pid, &st, 0);
    }
}

/* ----------------------------------------------------------------------- */
/* Usage                                                                   */
/* ----------------------------------------------------------------------- */

/* Print the software version to stdout. Deliberately distinguishes the daemon's
 * build version from the DGE1 on-wire framing version (DGE_VERSION) — they are
 * unrelated and were conflated before #N (the only embedded "version" was
 * DGE_VERSION, the wire byte, which is useless for "what build is installed?"). */
static void print_version(void)
{
    printf("diagbarf %s\n", DIAGBARF_VERSION);
    printf("  build date:      %s\n", DIAGBARF_BUILD_DATE);
    printf("  DGE wire proto:  0x%02X\n", DGE_VERSION);
}

static void usage(const char *argv0)
{
    fprintf(stderr,
"Usage: %s [options]   (#N — multi-protocol on-device DIAG egress)\n"
"\n"
"  --tcp-listen [ADDR:]PORT   TCP listener (host dials in, raw HDLC).\n"
"                             Default 0.0.0.0:%d (ON).\n"
"  --no-tcp-listen            Disable the TCP listener.\n"
"  --udp-broadcast SPEC       UDP broadcast. SPEC = IFACE | IFACE:PORT |\n"
"                             BCAST:PORT. Default %s:%d (ON).\n"
"  --no-udp-broadcast         Disable UDP broadcast.\n"
"  --udp-unicast HOST:PORT    Directed UDP datagrams (off by default).\n"
"  --tcp-dial HOST:PORT       Back-compat dial-out, raw HDLC (off by default).\n"
"  --mask max                 Log mask mode (only 'max' supported; default).\n"
"  --ext-msg-f3               Also enable the F3 ext-msg debug stream.\n"
"  --internal-port PORT       Loopback port for the captive diag_socket_log\n"
"                             (default %d).\n"
"  --retry N                  diag_socket_log connect retries (default %d).\n"
"  --diag-socket-log PATH     Path/name of the OEM binary (default in PATH).\n"
"  --source MODE              DIAG source: socket-log (default, captive OEM\n"
"                             diag_socket_log) | diag-dev (native kernel /dev/diag,\n"
"                             zero-dependency; SDX55 M2000) | hdlc-chardev (host-side\n"
"                             jump box: serial-like CRC-HDLC DIAG chardev #N).\n"
"  --diag-dev PATH            Device node for --source diag-dev (kernel diag node,\n"
"                             default /dev/diag) OR --source hdlc-chardev (the DIAG\n"
"                             chardev, e.g. /dev/mhi_DIAG or /dev/ttyUSB2).\n"
"  -V, --version              Print version (build version + date + DGE proto).\n"
"  -h, --help                 This help.\n"
"\n"
"UDP sinks are DGE1 seq-framed (host side: diaggulp --transport udp-listen).\n"
"TCP sinks are raw HDLC (host side: diaggulp --transport tcp-connect --no-mask).\n",
        argv0, DEFAULT_PUBLIC_PORT, DEFAULT_BCAST_IFACE, DEFAULT_PUBLIC_PORT,
        DEFAULT_INTERNAL_PORT, DEFAULT_RETRY);
}

/* ----------------------------------------------------------------------- */
/* main                                                                    */
/* ----------------------------------------------------------------------- */

/* DIAGBARF_BRIDGE_TEST keeps the diag-dev bridge thread (above) compiled but
 * swaps out main() so tests/test_diagdev_teardown.c can drive diagdev_bridge
 * directly (the #N SIGTERM-wedge regression test). */
#if !defined(DIAGBARF_FRAMING_TEST) && !defined(DIAGBARF_BRIDGE_TEST)
int main(int argc, char **argv)
{
    crc16_init();
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    struct config cfg;
    memset(&cfg, 0, sizeof cfg);
    /* defaults: TCP-listen :12399 + UDP broadcast bridge0:12399 */
    cfg.tcp_listen_enabled = 1;
    parse_hostport("0.0.0.0", &cfg.tcp_listen_addr, INADDR_ANY);
    cfg.tcp_listen_addr.sin_port = htons(DEFAULT_PUBLIC_PORT);
    cfg.udp_bcast_enabled = 1;
    snprintf(cfg.bcast_iface, IFNAMSIZ, "%s", DEFAULT_BCAST_IFACE);
    cfg.bcast_iface_resolve = 1;
    cfg.bcast_port = DEFAULT_PUBLIC_PORT;
    cfg.internal_port = DEFAULT_INTERNAL_PORT;
    cfg.retry = DEFAULT_RETRY;
    cfg.mask_max = 1;
    cfg.diag_socket_log = "diag_socket_log";
    cfg.source = "socket-log";
    cfg.diag_dev = "/dev/diag";

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--no-tcp-listen")) {
            cfg.tcp_listen_enabled = 0;
        } else if (!strcmp(a, "--tcp-listen") && i + 1 < argc) {
            cfg.tcp_listen_enabled = 1;
            if (parse_hostport(argv[++i], &cfg.tcp_listen_addr, INADDR_ANY) < 0) {
                logmsg("bad --tcp-listen %s", argv[i]); return 2;
            }
        } else if (!strcmp(a, "--no-udp-broadcast")) {
            cfg.udp_bcast_enabled = 0;
        } else if (!strcmp(a, "--udp-broadcast") && i + 1 < argc) {
            cfg.udp_bcast_enabled = 1;
            /* SPEC = IFACE | IFACE:PORT | BCAST:PORT */
            char tmp[128];
            snprintf(tmp, sizeof tmp, "%s", argv[++i]);
            char *colon = strrchr(tmp, ':');
            if (colon) *colon = '\0';
            const char *head = tmp;
            int port = colon ? atoi(colon + 1) : DEFAULT_PUBLIC_PORT;
            cfg.bcast_port = port;
            struct in_addr probe;
            if (inet_pton(AF_INET, head, &probe) == 1) {
                cfg.bcast_iface_resolve = 0;
                memset(&cfg.udp_bcast_addr, 0, sizeof cfg.udp_bcast_addr);
                cfg.udp_bcast_addr.sin_family = AF_INET;
                cfg.udp_bcast_addr.sin_port = htons((uint16_t)port);
                cfg.udp_bcast_addr.sin_addr = probe;
            } else {
                if (strlen(head) >= IFNAMSIZ) {
                    logmsg("bad --udp-broadcast: iface name too long: %s", head);
                    return 2;
                }
                cfg.bcast_iface_resolve = 1;
                snprintf(cfg.bcast_iface, IFNAMSIZ, "%s", head);
            }
        } else if (!strcmp(a, "--udp-unicast") && i + 1 < argc) {
            cfg.udp_unicast_enabled = 1;
            if (parse_hostport(argv[++i], &cfg.udp_unicast_addr, INADDR_ANY) < 0) {
                logmsg("bad --udp-unicast %s", argv[i]); return 2;
            }
        } else if (!strcmp(a, "--tcp-dial") && i + 1 < argc) {
            cfg.tcp_dial_enabled = 1;
            if (parse_hostport(argv[++i], &cfg.tcp_dial_addr, INADDR_ANY) < 0) {
                logmsg("bad --tcp-dial %s", argv[i]); return 2;
            }
        } else if (!strcmp(a, "--mask") && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "max") != 0)
                logmsg("warning: --mask %s unsupported; using 'max'", argv[i]);
            cfg.mask_max = 1;
        } else if (!strcmp(a, "--ext-msg-f3")) {
            cfg.ext_msg_f3 = 1;
        } else if (!strcmp(a, "--internal-port") && i + 1 < argc) {
            cfg.internal_port = atoi(argv[++i]);
        } else if (!strcmp(a, "--retry") && i + 1 < argc) {
            cfg.retry = atoi(argv[++i]);
        } else if (!strcmp(a, "--diag-socket-log") && i + 1 < argc) {
            cfg.diag_socket_log = argv[++i];
        } else if (!strcmp(a, "--source") && i + 1 < argc) {
            cfg.source = argv[++i];
        } else if (!strcmp(a, "--diag-dev") && i + 1 < argc) {
            cfg.diag_dev = argv[++i];
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            print_version(); return 0;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(argv[0]); return 0;
        } else {
            logmsg("unknown/incomplete argument: %s", a);
            usage(argv[0]); return 2;
        }
    }

    if (strcmp(cfg.source, "socket-log") != 0 &&
        strcmp(cfg.source, "diag-dev") != 0 &&
        strcmp(cfg.source, "hdlc-chardev") != 0) {
        logmsg("unknown --source '%s' (expected socket-log | diag-dev | hdlc-chardev)",
               cfg.source);
        return 2;
    }

    if (!cfg.tcp_listen_enabled && !cfg.udp_bcast_enabled &&
        !cfg.udp_unicast_enabled && !cfg.tcp_dial_enabled) {
        logmsg("no sinks enabled — nothing to do");
        return 2;
    }

    /* Emit the build version once at startup so journald answers "what's
     * running?" without a flag or an on-device binary hash (#N). */
    logmsg("diagbarf %s (built %s, DGE proto 0x%02X) starting",
           DIAGBARF_VERSION, DIAGBARF_BUILD_DATE, DGE_VERSION);

    /* --- Set up the UDP sinks --- */
    struct udp_sink bcast = {0}, unicast = {0};
    if (cfg.udp_bcast_enabled) {
        if (cfg.bcast_iface_resolve) {
            struct in_addr b;
            if (iface_broadcast(cfg.bcast_iface, &b) < 0) {
                logmsg("cannot resolve broadcast addr for iface %s: %s",
                       cfg.bcast_iface, strerror(errno));
                return 1;
            }
            memset(&cfg.udp_bcast_addr, 0, sizeof cfg.udp_bcast_addr);
            cfg.udp_bcast_addr.sin_family = AF_INET;
            cfg.udp_bcast_addr.sin_port = htons((uint16_t)cfg.bcast_port);
            cfg.udp_bcast_addr.sin_addr = b;
        }
        bcast.fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (bcast.fd < 0) { logmsg("udp bcast socket: %s", strerror(errno)); return 1; }
        int on = 1;
        setsockopt(bcast.fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof on);
        bcast.dest = cfg.udp_bcast_addr;
        bcast.enabled = 1;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &bcast.dest.sin_addr, ip, sizeof ip);
        logmsg("sink: UDP broadcast -> %s:%d", ip, ntohs(bcast.dest.sin_port));
    }
    if (cfg.udp_unicast_enabled) {
        unicast.fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (unicast.fd < 0) { logmsg("udp unicast socket: %s", strerror(errno)); return 1; }
        unicast.dest = cfg.udp_unicast_addr;
        unicast.enabled = 1;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &unicast.dest.sin_addr, ip, sizeof ip);
        logmsg("sink: UDP unicast -> %s:%d", ip, ntohs(unicast.dest.sin_port));
    }

    /* --- Set up the TCP listener --- */
    int listen_fd = -1;
    if (cfg.tcp_listen_enabled) {
        listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0) { logmsg("tcp listen socket: %s", strerror(errno)); return 1; }
        int on = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
        if (bind(listen_fd, (struct sockaddr *)&cfg.tcp_listen_addr,
                 sizeof cfg.tcp_listen_addr) < 0) {
            logmsg("tcp listen bind: %s", strerror(errno)); return 1;
        }
        if (listen(listen_fd, 8) < 0) { logmsg("listen: %s", strerror(errno)); return 1; }
        set_nonblock(listen_fd);
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cfg.tcp_listen_addr.sin_addr, ip, sizeof ip);
        logmsg("sink: TCP listener on %s:%d", ip, ntohs(cfg.tcp_listen_addr.sin_port));
    }

    /* --- TCP dial-out (back-compat) --- */
    struct tcp_out dial = {0};
    dial.fd = -1;                  /* -1 even when disabled: write gates check fd>=0 */
    if (cfg.tcp_dial_enabled) {
        dial.enabled = 1;
        dial.fd = -1;
        dial.dest = cfg.tcp_dial_addr;
        dial.next_retry_ms = 0;     /* connect on first loop pass */
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &dial.dest.sin_addr, ip, sizeof ip);
        logmsg("sink: TCP dial-out -> %s:%d (back-compat)", ip, ntohs(dial.dest.sin_port));
    }

    int clients[MAX_CLIENTS];
    int nclients = 0;
    for (int i = 0; i < MAX_CLIENTS; i++) clients[i] = -1;

    /* ===================================================================== */
    /* Outer loop: (re)spawn the captive diag_socket_log, arm the mask, pump */
    /* ===================================================================== */
    while (!g_stop) {
        int src = -1;
        pid_t child = -1;
        pthread_t bridge_tid = 0;
        int using_diag_dev = (strcmp(cfg.source, "diag-dev") == 0);
        int using_chardev  = (strcmp(cfg.source, "hdlc-chardev") == 0);

        if (using_chardev) {
            src = start_hdlc_chardev_source(cfg.diag_dev);
            if (src < 0) { if (g_stop) break; sleep(5); continue; }
            logmsg("hdlc-chardev source ready: %s (src fd %d)", cfg.diag_dev, src);
        } else if (using_diag_dev) {
            src = start_diag_dev_source(cfg.diag_dev, &bridge_tid);
            if (src < 0) { if (g_stop) break; sleep(5); continue; }
            logmsg("diag-dev source ready (src fd %d)", src);
        } else {
        /* Internal loopback listener for the captive diag_socket_log. */
        int internal_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (internal_fd < 0) { logmsg("internal socket: %s", strerror(errno)); break; }
        int on = 1;
        setsockopt(internal_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
        struct sockaddr_in la;
        memset(&la, 0, sizeof la);
        la.sin_family = AF_INET;
        la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        la.sin_port = htons((uint16_t)cfg.internal_port);
        if (bind(internal_fd, (struct sockaddr *)&la, sizeof la) < 0) {
            logmsg("internal bind %d: %s", cfg.internal_port, strerror(errno));
            close(internal_fd);
            sleep(5);
            continue;
        }
        listen(internal_fd, 1);

        kill_diag_socket_log(cfg.diag_socket_log);
        child = spawn_diag_socket_log(cfg.diag_socket_log,
                                            cfg.internal_port, cfg.retry);
        if (child < 0) {
            logmsg("fork diag_socket_log failed: %s", strerror(errno));
            close(internal_fd);
            sleep(5);
            continue;
        }
        logmsg("spawned diag_socket_log (pid %d) dialing 127.0.0.1:%d",
               (int)child, cfg.internal_port);

        /* Accept the one MD source connection (bounded wait). */
        for (int waited = 0; waited < 60 && !g_stop; waited++) {
            struct pollfd pfd = { .fd = internal_fd, .events = POLLIN };
            int pr = poll(&pfd, 1, 1000);
            if (pr > 0) {
                src = accept(internal_fd, NULL, NULL);
                break;
            }
        }
        close(internal_fd);
        if (src < 0) {
            logmsg("captive diag_socket_log did not connect — retrying");
            kill(child, SIGTERM);
            waitpid(child, NULL, 0);
            kill_diag_socket_log(cfg.diag_socket_log);
            if (g_stop) break;
            sleep(3);
            continue;
        }
        logmsg("captive diag_socket_log connected (src fd %d)", src);
        }   /* end socket-log source branch */

        /* Arm the global log mask (non-fatal on failure). */
        struct rxbuf rx;
        rx.len = 0;
        if (arm_mask(src, &rx, cfg.ext_msg_f3) < 0)
            logmsg("warning: mask handshake failed — fanning out whatever flows");

        /* Flush any bytes left in the handshake buffer to the sinks, then
         * switch to the raw byte pump for the rest of the stream. */
        int restart = 1;
        if (rx.len > 0) {
            for (int i = 0; i < nclients; i++)
                if (clients[i] >= 0) (void)!write(clients[i], rx.buf, rx.len);
            if (dial.fd >= 0) (void)!write(dial.fd, rx.buf, rx.len);
            udp_send_chunk(&bcast, rx.buf, rx.len, restart);
            udp_send_chunk(&unicast, rx.buf, rx.len, restart);
            restart = 0;
            rx.len = 0;
        }

        /* ---------------- Fan-out pump ---------------- */
        uint8_t chunk[READ_CHUNK];
        int src_alive = 1;
        while (src_alive && !g_stop) {
            struct pollfd pfds[2 + MAX_CLIENTS];
            int np = 0;
            int idx_src = np;
            pfds[np].fd = src; pfds[np].events = POLLIN; np++;
            int idx_listen = -1;
            if (listen_fd >= 0) { idx_listen = np; pfds[np].fd = listen_fd; pfds[np].events = POLLIN; np++; }
            /* Clients occupy a contiguous run of pfds starting here, in
             * clients[] order, so the poll slot of polled client i is exactly
             * idx_first_client + i — no separate index map to keep in sync. */
            int idx_first_client = np;
            int npoll_clients = nclients;
            for (int i = 0; i < nclients; i++) {
                pfds[np].fd = clients[i]; pfds[np].events = POLLIN; np++;
            }

            /* Opportunistic tcp-dial (re)connect. */
            if (dial.enabled && dial.fd < 0 && now_ms() >= dial.next_retry_ms) {
                int df = socket(AF_INET, SOCK_STREAM, 0);
                if (df >= 0) {
                    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
                    setsockopt(df, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
                    if (connect(df, (struct sockaddr *)&dial.dest, sizeof dial.dest) == 0) {
                        dial.fd = df;
                        set_nonblock(df);
                        logmsg("tcp-dial connected");
                    } else {
                        close(df);
                        dial.next_retry_ms = now_ms() + 5000;
                    }
                }
            }

            int pr = poll(pfds, np, 1000);
            if (pr < 0) {
                if (errno == EINTR) continue;
                break;
            }

            /* Drain+drop any client that sent data or closed (read-only
             * consumers). Process ONLY the clients that were in this cycle's
             * pfds (the first npoll_clients); their slot is idx_first_client+i.
             * Closed clients are tombstoned (-1) and compacted out afterward —
             * no swap-during-iterate. */
            for (int i = 0; i < npoll_clients; i++) {
                if (pfds[idx_first_client + i].revents & (POLLIN | POLLHUP | POLLERR)) {
                    uint8_t junk[512];
                    ssize_t r = read(clients[i], junk, sizeof junk);
                    if (r <= 0) {
                        close(clients[i]);
                        clients[i] = -1;   /* tombstone; compacted below */
                    }
                    /* else: ignore client input (we are the sole mask arbiter) */
                }
            }
            {
                int before = nclients;
                nclients = compact_clients(clients, nclients);
                if (nclients < before)
                    logmsg("tcp-listen client closed (%d active)", nclients);
            }

            /* New TCP-listen client? Accept AFTER draining so a freshly
             * accepted fd is never indexed against this cycle's pfds (it is
             * simply polled next cycle). */
            if (idx_listen >= 0 && (pfds[idx_listen].revents & POLLIN)) {
                int c = accept(listen_fd, NULL, NULL);
                if (c >= 0) {
                    if (nclients < MAX_CLIENTS) {
                        set_nonblock(c);
                        int one = 1;
                        setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
                        clients[nclients++] = c;
                        logmsg("tcp-listen client connected (%d active)", nclients);
                    } else {
                        close(c);
                        logmsg("tcp-listen client refused (max %d)", MAX_CLIENTS);
                    }
                }
            }

            /* Source data → fan out. */
            if (pfds[idx_src].revents & (POLLIN | POLLHUP | POLLERR)) {
                ssize_t n = read(src, chunk, sizeof chunk);
                if (n <= 0) {
                    if (n < 0 && errno == EINTR) continue;
                    logmsg("src closed/error — re-spawning diag_socket_log");
                    src_alive = 0;
                } else {
                    /* TCP sinks: raw bytes, best-effort, drop on hard error. */
                    for (int i = 0; i < nclients; i++) {
                        ssize_t w = write(clients[i], chunk, (size_t)n);
                        if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                            close(clients[i]);
                            clients[i] = clients[--nclients];
                            clients[nclients] = -1;
                            i--;
                        }
                    }
                    if (dial.fd >= 0) {
                        ssize_t w = write(dial.fd, chunk, (size_t)n);
                        if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                            close(dial.fd);
                            dial.fd = -1;
                            dial.next_retry_ms = now_ms() + 5000;
                            logmsg("tcp-dial dropped");
                        }
                    }
                    /* UDP sinks: DGE1-framed. */
                    udp_send_chunk(&bcast, chunk, (size_t)n, 0);
                    udp_send_chunk(&unicast, chunk, (size_t)n, 0);
                }
            }
        }

        /* src loop ended — tear down the source before respawn. */
        if (using_chardev) {
            if (src >= 0) close(src);   /* no captive process / bridge; the
                                         * chardev IS the transport */
        } else if (using_diag_dev) {
            if (src >= 0) close(src);   /* closing src ends the bridge thread;
                                         * kernel reverts the MD session on fd close */
            if (bridge_tid) pthread_join(bridge_tid, NULL);
        } else {
            close(src);
            kill(child, SIGTERM);
            waitpid(child, NULL, 0);
            kill_diag_socket_log(cfg.diag_socket_log);
        }
        if (!g_stop)
            sleep(2);
    }

    logmsg("shutting down");
    for (int i = 0; i < nclients; i++) if (clients[i] >= 0) close(clients[i]);
    if (dial.fd >= 0) close(dial.fd);
    if (bcast.enabled) close(bcast.fd);
    if (unicast.enabled) close(unicast.fd);
    if (listen_fd >= 0) close(listen_fd);
    return 0;
}
#endif /* !DIAGBARF_FRAMING_TEST && !DIAGBARF_BRIDGE_TEST */
