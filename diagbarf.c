/* SPDX-License-Identifier: Apache-2.0 */
/* diagbarf — native multi-protocol on-device DIAG egress daemon
 *
 * Shared across modules — validated on the Wistron LV55 (SDX55) and the
 * Casa Systems CFW-3212 (SDX62). The CFW-3212 has NO /dev/diag (DIAG runs
 * entirely in userspace via diag-router); diagbarf works there unchanged because
 * it never touches /dev/diag directly — it drives the OEM diag_socket_log, which
 * abstracts the underlying transport (kernel /dev/diag on SDX55, diag-router IPC
 * on SDX62). The single-MD-reader constraint below holds identically on both.
 *
 * One MD-mode DIAG reader that fans the firehose out to multiple sinks:
 *   - TCP listener (host dials in)         — raw HDLC, multi-client   [default ON]
 *   - UDP broadcast to the LAN iface       — DGE1 seq-framed          [default ON]
 *   - UDP unicast to a host:port           — DGE1 seq-framed          [opt]
 *   - TCP dial-out (back-compat)           — raw HDLC                 [opt]
 *
 * Why this shape (load-bearing constraint):
 * /dev/diag has ONE memory-device (MD) consumer slot — two MD streamers
 * collide on the shared global DIAG_LOG_CONFIG_F mask and steal each other's
 * buffer bytes (broken HDLC for both). So there must be exactly ONE MD reader
 * that fans out internally. DCI recorders (diag_dci_recorder_wnc, ...) are
 * unaffected — they get private filtered copies.
 *
 * `--source stdin` is the egress-only exception to all of the above: it
 * reads an ALREADY-ARMED raw-HDLC stream from fd 0 and only fans out — it opens
 * no DIAG transport and does NOT arm. This is for the CARCOM-G1, where the
 * DIAG-owning MDM9250 has no LAN egress: diaggulp runs on the host ST (arms the
 * log+F3 masks over adb-reverse, writes HDLC to stdout) and pipes into a local
 * diagbarf that egresses off-box:  diaggulp ... -o - | diagbarf --source stdin
 * --udp-unicast <collector>:<port>.
 *
 * How we are the single MD reader without reimplementing libdiag:
 * the OEM `diag_socket_log` is the only on-device tool that does
 * Diag_LSM_Init() correctly. It is a TRANSPARENT bidirectional bridge between
 * a TCP socket and the DIAG transport (kernel /dev/diag on SDX55; diag-router
 * IPC on SDX62, where there is no /dev/diag) — it does NOT set the log mask
 * itself; the TCP peer drives the DIAG_LOG_CONFIG_F handshake (that is why
 * host `diaggulp`
 * owns it in the TCP dial-out flow). We therefore spawn `diag_socket_log` as a captive
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
 * DLF lands on the collector host(s). The ONE opt-in exception is
 * --cmd-listen (OFF by default): a separate loopback-default listener
 * whose single client may send EFS2 / NV / read-only identity requests to the
 * modem through a default allow-list (mask config, CONTROL, FTM always
 * refused). Without the flag, behaviour is unchanged.
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
#include <dirent.h>
#include <poll.h>
#include <time.h>
#include <termios.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "diagchar_md.h"
#include "presets_gnss.h"   /* generated from the diagmunge GNSS preset */

/* ----------------------------------------------------------------------- */
/* Constants                                                               */
/* ----------------------------------------------------------------------- */

#define DEFAULT_PUBLIC_PORT   12399
#define DEFAULT_INTERNAL_PORT 12398
#define DEFAULT_RETRY         20
#define DEFAULT_BCAST_IFACE   "bridge0"

#define MAX_CLIENTS           32
#define READ_CHUNK            65536

/* UDP datagram framing — "DGE1" header (12 bytes). */
#define DGE_MAGIC             "DGE1"
#define DGE_VERSION           0x01
#define DGE_FLAG_RESTART      0x01    /* first datagram after an src re-spawn */
#define DGE_HDR_LEN           12
#define DGE_MAX_PAYLOAD       1400    /* MTU-safe: 1500 - 20 IP - 8 UDP, margin */

/* Plane B mux framing — "BMX1" tagged records (RIS-9260). Plane A is
 * the modem DIAG firehose (raw HDLC / DGE1 on the sinks above); Plane B is the
 * RSU's own daemon logs (acme/kapschrsu, cv2x-daemon, cv2x_rx_app, gpsd, ntpd).
 * The two must land in ONE host pcap yet never share a byte stream — Plane A
 * parity is the acceptance gate — so Plane B rides a SEPARATE UDP port and each
 * record is self-delimiting and source-TAGGED. The tag byte (0x00 = manifest,
 * 0x01.. = a registered log source, and any unused value = a future third
 * plane) is the "room for a third tagged source" the design calls
 * for; it survives pcaplogd turning out to be a dead end.
 *
 *   off  len  field
 *    0    4   magic "BMX1"
 *    4    1   version (0x01)
 *    5    1   source tag (0x00 manifest | 0x01.. log source)
 *    6    1   flags (bit0 = RESTART: first record after (re)start)
 *    7    1   reserved (0)
 *    8    4   seq   (u32 LE, per-source)
 *   12    2   payload length (u16 LE)
 *   14   ..   payload (one log line, newline stripped; or a manifest blob)
 */
#define BMX_MAGIC             "BMX1"
#define BMX_VERSION           0x01
#define BMX_HDR_LEN           14
#define BMX_MAX_PAYLOAD       1400    /* same MTU-safe budget as DGE1 */
#define BMX_FLAG_RESTART      0x01
#define BMX_SRC_MANIFEST      0x00    /* tag→name/path self-describing record */
#define BMX_SRC_FIRST         0x01    /* first registered log source */
#define MAX_LOG_SRC           16      /* registered --plane-b-log sources */
#define DEFAULT_MUX_PORT      12400   /* Plane B UDP port (Plane A default+1) */

/* Software build/version string — the daemon's *source* version, NOT the
 * on-wire DGE framing version (DGE_VERSION above). Injected at compile time by
 * the Makefile via -DDIAGBARF_VERSION (git describe --always --dirty) and
 * -DDIAGBARF_BUILD_DATE. Fallbacks keep a non-git / hand-compiled build honest
 * rather than silently reporting a wrong version. */
#ifndef DIAGBARF_VERSION
#define DIAGBARF_VERSION      "unknown"
#endif
#ifndef DIAGBARF_BUILD_DATE
#define DIAGBARF_BUILD_DATE   "unknown"
#endif

/* DIAG opcodes / log-config subcommands (mirror diaggulp). */
#define DIAG_LOG_CONFIG_F        115
#define DIAG_EXT_MSG_CONFIG_F    0x7D
#define DIAG_SUBSYS_CMD_F        0x4B
#define DIAG_BAD_CMD_F           0x13
#define LOG_CFG_RETRIEVE_RANGES  1
#define LOG_CFG_SET_MASK         3
#define LOG_CFG_SUCCESS          0
#define EXT_MSG_SET_ALL_RT_MASKS 5
#define EXT_MSG_ALL_LEVELS       0xFFFFFFFFu
#define NUM_LOG_TYPES            16

/* DIAG_EXT_MSG_CONFIG_F (0x7D) mask-table sub-commands (mirror diaggulp +
 * diagmunge; hardware-verified):
 *   1 QUERY_SSID_RANGES  2 GET_BUILD_MASK  3 GET_RT_MASK  4 SET_RT_MASK  5 SET_ALL
 * These back the per-SSID F3 fallback: SET_ALL_RT_MASKS is a silent no-op on the
 * MDM9250 MPSS (no reply, no F3), so arm_mask() falls back to per-SSID
 * SET_RT_MASK over the ss_ids the build-capability mask reports. */
#define EXT_MSG_GET_BUILD_MASK   2       /* build-time per-SSID capability */
#define EXT_MSG_GET_RT_MASK      3       /* runtime mask (what F3 is armed to now) */
#define EXT_MSG_SET_RT_MASK      4       /* per-SSID-range runtime SET */
#define EXT_MSG_SS_RANGE0_LAST   120     /* highest ss_id in the always-present range */
/* 0x7D mask-table reply header: u8 sub_cmd, u16 first, u16 last, u16 status; the
 * u32 mask array starts at offset 7 (NOT 9 — a 16-bit-rotation-invisible error). */
#define EXT_MSG_MASK_TABLE_HDR_LEN 7
/* --ext-msg-f3-mute: SSID ranges forced to runtime level 0 after F3 is
 * armed. MAX_F3_MUTE ranges, each at most F3_MUTE_SPAN ss_ids (one SET frame). */
#define MAX_F3_MUTE              16
#define F3_MUTE_SPAN             256

/* Opcodes of the OPT-IN command passthrough (--cmd-listen): what a
 * command client may send, plus the reply-only error opcodes routed back to it.
 * Names follow the conventional DIAG command names (cf. diaggrok's hdlc). */
#define DIAG_VERNO_F             0x00
#define DIAG_STATUS_F            0x0C
#define DIAG_BAD_PARM_F          0x14
#define DIAG_BAD_LEN_F           0x15
#define DIAG_BAD_MODE_F          0x18
#define DIAG_NV_READ_F           0x26
#define DIAG_NV_WRITE_F          0x27
#define DIAG_EXT_BUILD_ID_F      0x7C
#define DIAG_TS_F                0x1D    /* read the modem's ts64 clock */
#define DIAG_SUBSYS_CMD_VER_2_F  0x80
#define DIAG_SUBSYS_EFS2         0x13    /* 0x4B subsystem: EFS2 (standard) */
#define DIAG_SUBSYS_EFS2_ALT     0x3E    /* 0x4B subsystem: EFS2 (alternate) */
/* DIAG_SERV (subsystem 0x12): the QShrink4 qdb file server. Requests are
 * [0x80][0x12][cmd 0x16][ver][format_id u16][record_type u16], record_type
 * 0..3 = FILE_LIST / OPEN / READ / CLOSE — a read-only file pull. The diag_id
 * binding query rides 0x4B/0x12 cmd 0x0222 (libs/diaggrok diag_serv_client.py). */
#define DIAG_SUBSYS_DIAG_SERV    0x12
#define DIAG_SERV_FILE_CMD       0x16
#define DIAG_SERV_RECORD_MAX     3       /* CLOSE */
#define DIAG_SERV_BINDING_CMD    0x0222

/* ----------------------------------------------------------------------- */
/* CRC-16/MCRF4XX (== CRC-16/X.25) — the DIAG/HDLC FCS.                    */
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
/* Config (populated by argv; defaults match the original design)          */
/* ----------------------------------------------------------------------- */

struct config {
    int tcp_listen_enabled;
    struct sockaddr_storage tcp_listen_addr;
    socklen_t tcp_listen_len;

    /* UDP broadcast stays IPv4-only: broadcast is a v4 concept (IPv6 uses
     * multicast instead), and SIOCGIFBRDADDR returns a v4 address. */
    int udp_bcast_enabled;
    struct sockaddr_in udp_bcast_addr;     /* resolved broadcast dest */
    char bcast_iface[IFNAMSIZ];            /* iface name, if resolution deferred */
    int bcast_iface_resolve;               /* 1 = resolve iface -> bcast at runtime */
    int bcast_port;

    int udp_unicast_enabled;
    struct sockaddr_storage udp_unicast_addr;
    socklen_t udp_unicast_len;

    int tcp_dial_enabled;
    struct sockaddr_storage tcp_dial_addr;
    socklen_t tcp_dial_len;

    /* OPT-IN DIAG command passthrough. NOT a sink: off unless
     * --cmd-listen is given; a bare PORT binds 127.0.0.1. */
    int cmd_listen_enabled;
    struct sockaddr_storage cmd_listen_addr;
    socklen_t cmd_listen_len;

    int internal_port;
    int retry;
    int ext_msg_f3;
    uint16_t f3_mute_first[MAX_F3_MUTE];   /* --ext-msg-f3-mute ranges */
    uint16_t f3_mute_last[MAX_F3_MUTE];
    int nf3_mute;
    int qsh_trace;                         /* arm the 0x9D QSH-trace maskset */
    int log_types[NUM_LOG_TYPES];          /* --log-types: arm these first */
    int nlog_types;                        /* count in log_types[] */
    int only;                              /* --only: arm nothing outside log_types */
    int mask_mode;                         /* MASK_MAX (default) | MASK_GNSS | MASK_NONE */
    int client_filters;                    /* --client-filters: SUB lines */
    int sub_grace_ms;                      /* --sub-grace-ms (default 500) */
    const char *diag_socket_log;           /* path/name of OEM binary */
    const char *source;                    /* "socket-log" (default) | "diag-dev" */
    const char *diag_dev;                  /* kernel diag node when source=diag-dev */

    /* Plane B — RSU daemon-log multiplexer. Off unless --plane-b-udp
     * is given; independent of the DIAG sinks above. */
    int planeb_enabled;
    struct sockaddr_storage planeb_dest;   /* BMX1 UDP destination */
    socklen_t planeb_destlen;
    const char *planeb_logs[MAX_LOG_SRC];  /* NAME=PATH specs (repeatable) */
    int planeb_nlogs;
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

/* Parse a numeric string port ("12399") into a host-order uint16, rejecting
 * empties, trailing junk, and out-of-range values (0 and >65535). Stricter
 * than atoi(), which silently accepts "80x" and returns 0 for "notaport". */
static int parse_port_str(const char *s, uint16_t *out)
{
    if (!s || !*s)
        return -1;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (end == s || *end != '\0' || v <= 0 || v > 65535)
        return -1;
    *out = (uint16_t)v;
    return 0;
}

/* Parse a numeric host/port spec into ss (+*slen), dual-stack. Accepted forms:
 *   "PORT"                  -> def_family wildcard (INADDR_ANY / in6addr_any)
 *   "A.B.C.D:PORT"          -> AF_INET
 *   "[V6]:PORT"             -> AF_INET6
 *   "[V6%zone]:PORT"        -> AF_INET6, sin6_scope_id = if_nametoindex(zone)
 *                              (this is the RIS-9260 eth1 case: fe80::../eth1)
 * IPv6 literals MUST be bracketed — a bare "fe80::1:5000" is ambiguous with
 * addr:port and is rejected rather than mis-split. Numeric only: no
 * getaddrinfo/NSS, so the -static binary carries no resolver. Returns 0 on
 * success, -1 on any parse error. */
static int parse_hostport(const char *s, struct sockaddr_storage *ss,
                          socklen_t *slen, int def_family)
{
    char tmp[160];
    if (strlen(s) >= sizeof tmp)
        return -1;
    snprintf(tmp, sizeof tmp, "%s", s);
    memset(ss, 0, sizeof *ss);

    if (tmp[0] == '[') {
        /* Bracketed IPv6 literal: [addr]:port or [addr%zone]:port. */
        char *rb = strchr(tmp, ']');
        if (!rb || rb[1] != ':')
            return -1;
        *rb = '\0';
        const char *addr = tmp + 1;         /* between '[' and ']' */
        const char *port_str = rb + 2;      /* past "]:" */
        uint16_t port;
        if (parse_port_str(port_str, &port) < 0)
            return -1;
        uint32_t scope = 0;
        char *pct = strchr(tmp + 1, '%');
        if (pct) {
            *pct = '\0';                     /* addr now ends before '%' */
            const char *zone = pct + 1;
            scope = if_nametoindex(zone);    /* pure ioctl/netlink; static-safe */
            if (scope == 0)                  /* no such interface */
                return -1;
        }
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)ss;
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(port);
        v6->sin6_scope_id = scope;
        if (inet_pton(AF_INET6, addr, &v6->sin6_addr) != 1)
            return -1;
        *slen = sizeof *v6;
        return 0;
    }

    /* Not bracketed: either a bare port, or A.B.C.D:port. A bare token with
     * more than one ':' is an unbracketed IPv6 literal — reject it. */
    char *colon = strrchr(tmp, ':');
    const char *addr_str = NULL;
    const char *port_str;
    if (colon) {
        if (strchr(tmp, ':') != colon)       /* >1 colon: unbracketed v6 */
            return -1;
        *colon = '\0';
        addr_str = tmp;
        port_str = colon + 1;
    } else {
        port_str = tmp;                      /* bare port */
    }
    uint16_t port;
    if (parse_port_str(port_str, &port) < 0)
        return -1;

    if (addr_str && *addr_str) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)ss;
        v4->sin_family = AF_INET;
        v4->sin_port = htons(port);
        if (inet_pton(AF_INET, addr_str, &v4->sin_addr) != 1)
            return -1;
        *slen = sizeof *v4;
        return 0;
    }

    /* Bare port -> wildcard bind of the default family. */
    if (def_family == AF_INET6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)ss;
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(port);
        v6->sin6_addr = in6addr_any;
        *slen = sizeof *v6;
    } else {
        struct sockaddr_in *v4 = (struct sockaddr_in *)ss;
        v4->sin_family = AF_INET;
        v4->sin_port = htons(port);
        v4->sin_addr.s_addr = htonl(INADDR_ANY);
        *slen = sizeof *v4;
    }
    return 0;
}

/* Render a sockaddr_storage as "A.B.C.D:port" (v4) or "[v6]:port" /
 * "[v6%zone]:port" (v6, zone as the interface NAME) for log lines. Best-effort:
 * writes "?" on an unknown family. */
static void sa_ntop(const struct sockaddr_storage *ss, char *out, size_t outlen)
{
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)ss;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &v4->sin_addr, ip, sizeof ip);
        snprintf(out, outlen, "%s:%d", ip, ntohs(v4->sin_port));
    } else if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)ss;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &v6->sin6_addr, ip, sizeof ip);
        if (v6->sin6_scope_id) {
            char zone[IFNAMSIZ];
            if (if_indextoname(v6->sin6_scope_id, zone))
                snprintf(out, outlen, "[%s%%%s]:%d", ip, zone,
                         ntohs(v6->sin6_port));
            else
                snprintf(out, outlen, "[%s%%%u]:%d", ip, v6->sin6_scope_id,
                         ntohs(v6->sin6_port));
        } else {
            snprintf(out, outlen, "[%s]:%d", ip, ntohs(v6->sin6_port));
        }
    } else {
        snprintf(out, outlen, "?");
    }
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

/* ---- usbfs DIAG source: outbound opcode allow-list (RIS-9260) ---
 * The Kapsch RIS-9260's MDM9150 exposes DIAG as a USB composite (05c6:90f0)
 * whose interface 4 is claimed over usbfs — the 4.9 kernel has no qcserial/
 * option, so there is NO DIAG chardev to point --source hdlc-chardev at. The
 * USB DIAG interface speaks full HDLC-with-CRC in both directions (like the
 * hdlc-chardev source, NOT the type-0x20 diagchar framing of the kernel
 * /dev/diag path), so arm_mask()/recv_frame()/hdlc_encap()/fan-out are reused
 * verbatim; --source usbfs is a pure transport shim (USBDEVFS_BULK ioctls in
 * place of read()/write()). Ported from v2xph diag_usb.py + v2x_diag_capture.py.
 *
 * SAFETY — load-bearing: this RSU carries the project's ONE healthy
 * MDM9150 and is read-only by construction. diagbarf only ever emits 0x73
 * (DIAG_LOG_CONFIG_F) and 0x7D (DIAG_EXT_MSG_CONFIG_F) — diagnostic
 * subscriptions that cannot touch NV/EFS/flash and clear on power-cycle. But
 * "only ever" is an invariant of the code ABOVE this transport, not a property
 * of the wire. We make it a property of the wire: every frame the usbfs OUT
 * direction is about to ship is decoded and its opcode checked here, so a
 * future edit that tries to send 0x27 (NV_WRITE) or 0x29 (CONTROL: mode change
 * / reset / LPM) is refused at the transport boundary — a slip cannot brick or
 * reboot the modem. This is the C mirror of v2x_diag_capture._assert_allowed.
 *
 * Kept OUTSIDE the DIAGBARF_FRAMING_TEST guard below so the host unit test can
 * exercise the gate with no USB hardware. Pure: no side effects.
 *
 * The ONE widening is opt-in: with --cmd-listen, the gate also admits
 * exactly the command-passthrough allow-list (cmd_request_allowed below — EFS2,
 * NV read/write, read-only identity/status). 0x29 CONTROL, FTM, and every other
 * opcode stay refused here whatever the flag, so the gate remains an independent
 * second check behind the passthrough's own policy, not a copy of it.
 *
 * Returns 1 = allowed ({0x73, 0x7D}, or the passthrough allow-list when it is
 * on); 0 = a decodable frame with a disallowed opcode; -1 = empty/undecodable.
 * Callers ship ONLY on 1. */

/* Set once in main() when --cmd-listen is given, BEFORE any source bridge
 * thread starts (pthread_create orders the write before the bridge's reads). */
static int g_cmd_passthrough = 0;

/* ---- configurable passthrough allow/block rules (--cmd-allow/--cmd-block) ----
 * The hardcoded allow-list below (cmd_request_allowed) is the SAFE DEFAULT. An
 * operator can EXTEND it (admit more request opcodes — e.g. the handshake
 * opcodes a vendor log tool like qlc sends) or RESTRICT it (block some default)
 * at launch, without rebuilding this binary. A rule matches a
 * decoded request frame by its leading opcode and, optionally, a 0x4B/0x80
 * subsystem byte and a u16-LE command code:
 *
 *     OP            — match p[0] == OP (any payload)
 *     OP/SUB        — match p[0]==OP && p[1]==SUB
 *     OP/SUB/CMD    — match p[0]==OP && p[1]==SUB && u16le(p[2..3])==CMD
 *
 * Specs are comma-separated; each OP/SUB is a byte and CMD a u16, hex (0x..) or
 * decimal. Evaluation order in cmd_request_allowed: a BLOCK match refuses
 * (block always wins); else the hardcoded default allows; else an ALLOW-extra
 * match allows; else refuse. Both lists default EMPTY, so the shipped policy is
 * byte-for-byte unchanged unless a flag is given.
 *
 * SAFETY: this is an operator control, deliberately WITHOUT an un-overridable
 * floor — allowing a state-changing opcode (e.g. 0x29 CONTROL reset/offline) is
 * the operator's explicit, logged choice. The effective extra rules are printed
 * at startup for the audit trail, and the mask-config opcodes the daemon itself
 * emits (0x73/0x7D) are allowed on the usbfs transport by a separate branch, so
 * a client BLOCK of them never starves the daemon's own arming. Pure data; set
 * in main() before any bridge thread starts, same ordering as g_cmd_passthrough. */
#define CMD_RULE_MAX 64
struct cmd_rule {
    uint8_t  op;
    int      has_sub;
    uint8_t  sub;
    int      has_cmd;
    uint16_t cmd;
};
static struct cmd_rule g_cmd_allow_extra[CMD_RULE_MAX];
static int g_n_cmd_allow_extra = 0;
static struct cmd_rule g_cmd_block[CMD_RULE_MAX];
static int g_n_cmd_block = 0;

/* Does decoded request (p,n) match rule r? A rule component that needs a byte
 * not present in the frame cannot match (size≠shape → no match, never a read
 * past the end). Pure. */
static int cmd_rule_match(const struct cmd_rule *r, const uint8_t *p, size_t n)
{
    if (n < 1 || p[0] != r->op)
        return 0;
    if (r->has_sub && (n < 2 || p[1] != r->sub))
        return 0;
    if (r->has_cmd && (n < 4 || (uint16_t)(p[2] | (p[3] << 8)) != r->cmd))
        return 0;
    return 1;
}

static int cmd_rules_match_any(const struct cmd_rule *rules, int n_rules,
                               const uint8_t *p, size_t n)
{
    for (int i = 0; i < n_rules; i++)
        if (cmd_rule_match(&rules[i], p, n))
            return 1;
    return 0;
}

/* Parse a "OP[/SUB[/CMD]][,OP…]" spec into rules[], appending to *n (capped at
 * CMD_RULE_MAX). Returns 0 on success, -1 on a malformed token or overflow.
 * Pure; the caller owns the storage. Accepts hex (0x..) or decimal components,
 * '/' or ':' as the component separator. */
static int cmd_rules_parse(const char *spec, struct cmd_rule *rules, int *n)
{
    if (!spec || !*spec)
        return -1;
    char tmp[512];
    if (strlen(spec) >= sizeof tmp)
        return -1;
    strcpy(tmp, spec);
    char *save = NULL;
    for (char *tok = strtok_r(tmp, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        while (*tok == ' ')
            tok++;
        if (!*tok)
            continue;
        if (*n >= CMD_RULE_MAX)
            return -1;
        struct cmd_rule r;
        memset(&r, 0, sizeof r);
        /* component 1: opcode (mandatory) */
        char *sep = tok;
        while (*sep && *sep != '/' && *sep != ':')
            sep++;
        char saved = *sep;
        *sep = '\0';
        char *end = NULL;
        long v = strtol(tok, &end, 0);
        if (end == tok || *end != '\0' || v < 0 || v > 0xFF)
            return -1;
        r.op = (uint8_t)v;
        if (saved) {                                  /* component 2: subsystem */
            char *s2 = sep + 1;
            char *sep2 = s2;
            while (*sep2 && *sep2 != '/' && *sep2 != ':')
                sep2++;
            char saved2 = *sep2;
            *sep2 = '\0';
            v = strtol(s2, &end, 0);
            if (end == s2 || *end != '\0' || v < 0 || v > 0xFF)
                return -1;
            r.has_sub = 1;
            r.sub = (uint8_t)v;
            if (saved2) {                             /* component 3: u16 cmd */
                char *s3 = sep2 + 1;
                v = strtol(s3, &end, 0);
                if (end == s3 || *end != '\0' || v < 0 || v > 0xFFFF)
                    return -1;
                r.has_cmd = 1;
                r.cmd = (uint16_t)v;
            }
        }
        rules[(*n)++] = r;
    }
    return 0;
}

/* The --cmd-listen request policy: may a command client send this
 * DECODED request (opcode at p[0]) to the modem? A default allow-list —
 * everything not named here is refused:
 *   - 0x4B with subsystem 0x13 / 0x3E (EFS2 std / alt), whole header present;
 *   - 0x26 / 0x27 NV read / write;
 *   - 0x00 VERNO, 0x0C STATUS, 0x7C EXT_BUILD_ID (read-only identity/status);
 *   - 0x1D TS (read the ts64 clock — the host time anchor);
 *   - 0x80 with subsystem 0x12 cmd 0x16, record_type FILE_LIST/OPEN/READ/CLOSE
 *     (the DIAG_SERV qdb pull), and 0x4B/0x12 cmd 0x0222 (the diag_id
 *     binding query) — read-only, and the only way to pull the decode oracle
 *     while diagbarf holds the single MD slot.
 * Refused by construction, and deliberately so: the mask-changing opcodes
 * (0x73 LOG_CONFIG, 0x7D EXT_MSG_CONFIG, 0x60/0x82 event config) — diagbarf is
 * the sole mask arbiter, or the firehose silently changes under every sink;
 * 0x29 CONTROL (offline/reset); and every other 0x4B subsystem, FTM (0x0B)
 * included — the C-V2X work is RX-only; nothing may key its transmitter. There is
 * intentionally no allow-all escape hatch. Pure. */
/* The hardcoded SAFE DEFAULT allow-list. Factored out
 * of cmd_request_allowed so the configurable overlay can wrap it. Pure. */
static int cmd_request_allowed_default(const uint8_t *p, size_t n)
{
    if (n < 1)
        return 0;
    switch (p[0]) {
    case DIAG_VERNO_F:
    case DIAG_STATUS_F:
    case DIAG_EXT_BUILD_ID_F:
    case DIAG_NV_READ_F:
    case DIAG_NV_WRITE_F:
    case DIAG_TS_F:
        return 1;
    case DIAG_SUBSYS_CMD_F:
        /* [0x4B][subsys u8][cmd u16 LE] — a truncated header is malformed */
        if (n < 4)
            return 0;
        if (p[1] == DIAG_SUBSYS_EFS2 || p[1] == DIAG_SUBSYS_EFS2_ALT)
            return 1;
        return p[1] == DIAG_SUBSYS_DIAG_SERV
            && (p[2] | (p[3] << 8)) == DIAG_SERV_BINDING_CMD;
    case DIAG_SUBSYS_CMD_VER_2_F:
        /* the whole 8-byte DIAG_SERV header, record_type a file READ verb */
        return n >= 8 && p[1] == DIAG_SUBSYS_DIAG_SERV && p[2] == DIAG_SERV_FILE_CMD
            && (p[6] | (p[7] << 8)) <= DIAG_SERV_RECORD_MAX;
    default:
        return 0;
    }
}

/* Effective policy = (default-allow OR --cmd-allow extra) AND NOT --cmd-block.
 * Block always wins (it can only tighten); the extra-allow list only widens.
 * Both lists are empty unless a flag/conf key was given, so this is identical
 * to cmd_request_allowed_default on a stock launch. Pure. */
static int cmd_request_allowed(const uint8_t *p, size_t n)
{
    if (n < 1)
        return 0;
    if (cmd_rules_match_any(g_cmd_block, g_n_cmd_block, p, n))
        return 0;
    if (cmd_request_allowed_default(p, n))
        return 1;
    if (cmd_rules_match_any(g_cmd_allow_extra, g_n_cmd_allow_extra, p, n))
        return 1;
    return 0;
}

static int usbfs_out_frame_allowed(const uint8_t *frame, size_t len)
{
    uint8_t dec[2048];
    int d = hdlc_decap(frame, len, dec, sizeof dec);
    if (d < 1)
        return -1;
    if (dec[0] == DIAG_LOG_CONFIG_F || dec[0] == DIAG_EXT_MSG_CONFIG_F)
        return 1;
    if (g_cmd_passthrough && cmd_request_allowed(dec, (size_t)d))
        return 1;
    return 0;
}

/* ---- Plane B mux: pure framing / line-split / spec-parse (RIS-9260) -
 * Kept OUTSIDE the DIAGBARF_FRAMING_TEST guard so the host unit tests exercise
 * them with no hardware. All three are pure (no fds, no side effects). */

/* Frame one Plane B record into out (>= BMX_HDR_LEN + min(len,BMX_MAX_PAYLOAD)).
 * Payload longer than BMX_MAX_PAYLOAD is truncated (a single over-long log line
 * is clamped, never split — the header carries no continuation flag). Returns
 * the encoded length, or 0 if outcap is too small for header+payload. */
static size_t bmx_frame_record(uint8_t tag, uint8_t flags, uint32_t seq,
                               const uint8_t *payload, size_t len,
                               uint8_t *out, size_t outcap)
{
    if (len > BMX_MAX_PAYLOAD)
        len = BMX_MAX_PAYLOAD;
    if (outcap < BMX_HDR_LEN + len)
        return 0;
    memcpy(out, BMX_MAGIC, 4);
    out[4] = BMX_VERSION;
    out[5] = tag;
    out[6] = flags;
    out[7] = 0;                              /* reserved */
    memcpy(out + 8, &seq, 4);                /* host LE (armv7/i686 LE) == wire */
    uint16_t l16 = (uint16_t)len;
    memcpy(out + 12, &l16, 2);
    if (len)
        memcpy(out + BMX_HDR_LEN, payload, len);
    return BMX_HDR_LEN + len;
}

/* Extract the next complete '\n'-terminated line from buf[*off .. len).
 * On success sets *line and *llen to the line body with the trailing '\n' AND any
 * one trailing '\r' stripped (CRLF-safe), advances *off past the '\n', and
 * returns 1. Returns 0 when no further complete line exists (a partial tail
 * with no '\n' is left for the caller to keep buffered). Mirrors the house
 * diagdev_next_frame() split idiom. Pure: no side effects. */
static int linebuf_next_line(const uint8_t *buf, size_t len, size_t *off,
                             const uint8_t **line, size_t *llen)
{
    const uint8_t *nl = memchr(buf + *off, '\n', len - *off);
    if (!nl)
        return 0;
    size_t body = (size_t)(nl - (buf + *off));
    if (body > 0 && buf[*off + body - 1] == '\r')   /* CRLF → strip the CR */
        body--;
    *line = buf + *off;
    *llen = body;
    *off = (size_t)(nl - buf) + 1;                   /* past the '\n' */
    return 1;
}

/* Parse a --plane-b-log spec "NAME=PATH" into name_out (bounded) and *path_out
 * (points into spec after '='). Returns 0 on success, -1 if there is no '=',
 * an empty NAME/PATH, or NAME does not fit. Pure: no side effects. */
static int parse_log_spec(const char *spec, char *name_out, size_t namecap,
                          const char **path_out)
{
    const char *eq = strchr(spec, '=');
    if (!eq || eq == spec || eq[1] == '\0')
        return -1;
    size_t nlen = (size_t)(eq - spec);
    if (nlen >= namecap)
        return -1;
    memcpy(name_out, spec, nlen);
    name_out[nlen] = '\0';
    *path_out = eq + 1;
    return 0;
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

/* ---- host-side serial-like DIAG chardev source ------------------
 * On a jump box, the modem's DIAG stream is exposed at a serial-like HDLC
 * chardev: /dev/mhi_DIAG (PCIe/MHI Quectel) or /dev/ttyUSB2 (USB modems).
 * Unlike the modem-kernel /dev/diag (diag-dev mode, which uses CRC-less
 * type-0x20 diagchar framing and needs the MEMORY_DEVICE ioctl + a bridge
 * thread), this chardev IS the transport: it already speaks full HDLC with a
 * CRC-16 FCS in both directions. So there is no captive OEM binary, no ioctl,
 * and no bridge thread — we open the device and hand the raw fd straight to
 * arm_mask()/recv_frame() as `src`. hdlc_encap() already appends the CRC the
 * MHI/USB config path requires (this is the CRC-HDLC transport lesson:
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

/* ---- usbfs DIAG source (RIS-9260 MDM9150) -----------------------
 * Constants from the vendor's own diag-efs.conf, already tuned for this exact
 * modem and proven non-disruptive on this donor by the EFS backup
 * and NV sweep: 05c6:90f0, DIAG on interface 4, IN 0x85 / OUT 0x03.
 *
 * Grounded against the modem's OWN gadget config, the definitive
 * source: /sbin/usb/compositions/90F0 sets functions
 * "rndis,rmnet_gsi,ipc,diag,serial,ffs" — RNDIS eats interfaces 0-1, rmnet=2,
 * ipc=3, so diag lands on interface 4, and once DIAG sits fifth the kernel
 * hands it endpoints 0x85/0x03. Two independent confirmations of 0x85/0x03:
 * this empirical unit match AND diag-efs.conf. The sibling diag-relay.conf
 * lists 0x81/0x01 for the same 90f0/iface-4, but that is a stale template
 * default copied from the iface-0 layout (diag-relay/cli on 0x901d and
 * diag-rsrp on 0x9025 all put DIAG first => iface 0, IN 0x81/OUT 0x01) — NOT
 * this composition's real endpoints. Do not "fix" the constants to 0x81/0x01.
 *
 * Caveat: usbfs_find_device() matches 0x90f0 ONLY. If a unit ever boots in the
 * 0x901d (diag+adb) or 0x9025 (diag+adb+serial+rmnet+ms) composition, DIAG
 * moves to interface 0 with endpoints IN 0x81/OUT 0x01 and this matcher will
 * not find it — the fielded RSUs run 90f0, so that is correct today.
 *
 * A bridge thread owns the usbfs fd and translates between USBDEVFS_BULK
 * transfers and a socketpair carrying the raw-HDLC byte stream, so the caller
 * side of the socketpair becomes diagbarf's `src` and everything above is
 * unchanged — the same adapter shape as the diag-dev bridge, minus the
 * type-word wrapping (usbfs already carries full HDLC, /dev/diag does not). */
#define USBFS_VID        0x05C6
#define USBFS_PID        0x90F0
#define USBFS_INTERFACE  4
#define USBFS_EP_IN      0x85
#define USBFS_EP_OUT     0x03

/* struct usbdevfs_bulktransfer + ioctl numbers, defined locally (not via
 * <linux/usbdevice_fs.h>) so this file keeps compiling on the non-Linux test
 * hosts the Makefile targets. The BULK ioctl number is DERIVED from sizeof:
 * the trailing data pointer makes the struct size differ between 32- and
 * 64-bit, and diagbarf's i686 RSU target is 32-bit while its build/test hosts
 * are 64-bit — exactly why diag_usb.py computes it rather than hardcoding. */
struct usbfs_bulktransfer {
    unsigned int ep;
    unsigned int len;
    unsigned int timeout;      /* ms; 0 == unbounded */
    void *data;
};
/* _IOC layout: dir<<30 | size<<16 | type<<8 | nr  (mirrors diag_usb._IOC). */
#define USBFS_IOC(dir, nr, sz) \
    (((unsigned)(dir) << 30) | (((unsigned)'U') << 8) | \
     ((unsigned)(nr)) | ((unsigned)(sz) << 16))
#define USBFS_BULK             USBFS_IOC(3, 2, sizeof(struct usbfs_bulktransfer)) /* _IOWR */
#define USBFS_CLAIMINTERFACE   USBFS_IOC(2, 15, 4)                                /* _IOR */
#define USBFS_RELEASEINTERFACE USBFS_IOC(2, 16, 4)

/* Read a small sysfs attribute into an integer (base 10 or 16). Returns 0/-1. */
static int read_sysfs_int(const char *dir, const char *attr, int base, long *out)
{
    char path[512], buf[64];
    snprintf(path, sizeof path, "%s/%s", dir, attr);
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';
    errno = 0;
    char *end = NULL;
    long v = strtol(buf, &end, base);
    if (errno || end == buf)
        return -1;
    *out = v;
    return 0;
}

/* Locate /dev/bus/usb/BBB/DDD for VID:PID via sysfs (port of diag_usb
 * find_device). sysfs rather than parsing lsusb: busnum/devnum are the very
 * attributes the usbfs path is built from, so nothing can disagree with the
 * kernel. Returns 0 and fills out on success, -1 if not found. */
static int usbfs_find_device(char *out, size_t outcap)
{
    const char *root = "/sys/bus/usb/devices";
    DIR *d = opendir(root);
    if (!d)
        return -1;
    int found = -1;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.')
            continue;
        char dir[512];
        snprintf(dir, sizeof dir, "%s/%s", root, e->d_name);
        long vid, pid, bus, dev;
        if (read_sysfs_int(dir, "idVendor", 16, &vid) < 0 || vid != USBFS_VID)
            continue;
        if (read_sysfs_int(dir, "idProduct", 16, &pid) < 0 || pid != USBFS_PID)
            continue;
        if (read_sysfs_int(dir, "busnum", 10, &bus) < 0)
            continue;
        if (read_sysfs_int(dir, "devnum", 10, &dev) < 0)
            continue;
        snprintf(out, outcap, "/dev/bus/usb/%03ld/%03ld", bus, dev);
        found = 0;
        break;
    }
    closedir(d);
    return found;
}

struct usbfs_ctx { int usb_fd; int sp_fd; };

/* Best-effort release of the claimed interface (mirrors diag_usb.close). */
static void usbfs_release(int usb_fd)
{
    unsigned iface = USBFS_INTERFACE;
    (void)ioctl(usb_fd, USBFS_RELEASEINTERFACE, &iface);
}

/* Bridge: usbfs bulk endpoints <-> socketpair byte stream.
 *  IN  (modem -> src): USBDEVFS_BULK on EP 0x85 with a short timeout so g_stop
 *                      is observed promptly, forwarded verbatim to the src side.
 *  OUT (src -> modem): pending socketpair bytes are split into 0x7E-delimited
 *                      HDLC frames; EACH is opcode-gated (usbfs_out_frame_allowed)
 *                      before a single USBDEVFS_BULK on EP 0x03 — a disallowed
 *                      opcode is DROPPED, never shipped (the safety gate).
 * Wakeups match the diag-dev bridge: g_stop each tick, and EOF on the src side
 * (main's close(src) teardown) breaks the loop. */
static void *usbfs_bridge(void *arg)
{
    struct usbfs_ctx *c = arg;
    uint8_t inbuf[16384];      /* modem -> src */
    uint8_t wr[8192];          /* accumulate command frames from the src side */
    size_t wlen = 0;
    struct pollfd pfd = { .fd = c->sp_fd, .events = POLLIN, .revents = 0 };

    for (;;) {
        if (g_stop)
            break;

        /* src -> modem first, so a just-written command ships with minimal
         * latency instead of waiting out an IN bulk timeout. Non-blocking. */
        int pr = poll(&pfd, 1, 0);
        if (pr > 0 && (pfd.revents & (POLLIN | POLLHUP | POLLERR))) {
            if (wlen >= sizeof wr) wlen = 0;          /* runaway guard */
            ssize_t r = read(c->sp_fd, wr + wlen, sizeof wr - wlen);
            if (r <= 0)
                break;                                /* EOF: main closed src */
            wlen += (size_t)r;
            size_t off = 0, flen;
            int err = 0;
            while (diagdev_next_frame(wr, wlen, &off, &flen)) {
                /* flen includes the trailing 0x7E; the modem wants the full
                 * delimited frame on the wire, but the allow-check decodes the
                 * frame WITHOUT the delimiter (hdlc_decap strips none itself). */
                uint8_t *fr = wr + off - flen;
                size_t body = flen ? flen - 1 : 0;
                int ok = usbfs_out_frame_allowed(fr, body);
                if (ok != 1) {
                    if (ok == 0)
                        logmsg("usbfs: REFUSED outbound frame (opcode 0x%02x not "
                               "0x73/0x7D%s) — dropping", fr[0],
                               g_cmd_passthrough ? " or the --cmd-listen allow-list" : "");
                    continue;                          /* NEVER ship it */
                }
                struct usbfs_bulktransfer out = {
                    .ep = USBFS_EP_OUT, .len = (unsigned)flen,
                    .timeout = 3000, .data = fr,
                };
                if (ioctl(c->usb_fd, USBFS_BULK, &out) < 0) {
                    logmsg("usbfs: bulk OUT error: %s", strerror(errno));
                    err = 1;
                    break;
                }
            }
            memmove(wr, wr + off, wlen - off);
            wlen -= off;
            if (err)
                break;
        }

        /* modem -> src: a bounded bulk IN read. ETIMEDOUT with no data is the
         * normal idle case — just loop and re-check g_stop. */
        struct usbfs_bulktransfer in = {
            .ep = USBFS_EP_IN, .len = sizeof inbuf,
            .timeout = 500, .data = inbuf,
        };
        int n = ioctl(c->usb_fd, USBFS_BULK, &in);
        if (n > 0) {
            if (write_all(c->sp_fd, inbuf, (size_t)n) < 0)
                break;
        } else if (n < 0 && errno != ETIMEDOUT && errno != EAGAIN &&
                   errno != EINTR) {
            logmsg("usbfs: bulk IN error: %s", strerror(errno));
            break;
        }
    }

    usbfs_release(c->usb_fd);
    close(c->usb_fd);
    close(c->sp_fd);
    free(c);
    return NULL;
}

/* Find the modem, open + claim interface 4, spawn the bridge. Returns the
 * caller-side socketpair fd to use as `src`, or -1. */
static int start_usbfs_source(pthread_t *tid_out)
{
    char path[64];
    if (usbfs_find_device(path, sizeof path) < 0) {
        logmsg("usbfs: modem %04x:%04x not found on the USB bus "
               "(this runs ON THE RSU)", USBFS_VID, USBFS_PID);
        return -1;
    }
    int ufd = open(path, O_RDWR);
    if (ufd < 0) {
        logmsg("usbfs: open %s: %s", path, strerror(errno));
        return -1;
    }
    unsigned iface = USBFS_INTERFACE;
    if (ioctl(ufd, USBFS_CLAIMINTERFACE, &iface) < 0) {
        logmsg("usbfs: claim interface %d on %s failed: %s "
               "(is diag-efs or another DIAG client still running?)",
               USBFS_INTERFACE, path, strerror(errno));
        close(ufd);
        return -1;
    }
    logmsg("usbfs: claimed interface %d on %s (%04x:%04x)",
           USBFS_INTERFACE, path, USBFS_VID, USBFS_PID);

    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) {
        logmsg("usbfs: socketpair: %s", strerror(errno));
        usbfs_release(ufd); close(ufd);
        return -1;
    }
    struct usbfs_ctx *c = malloc(sizeof *c);
    if (!c) {
        logmsg("usbfs: OOM");
        usbfs_release(ufd); close(ufd); close(sp[0]); close(sp[1]);
        return -1;
    }
    c->usb_fd = ufd;
    c->sp_fd = sp[1];
    if (pthread_create(tid_out, NULL, usbfs_bridge, c) != 0) {
        logmsg("usbfs: pthread_create bridge failed");
        usbfs_release(ufd); close(ufd); close(sp[0]); close(sp[1]); free(c);
        return -1;
    }
    return sp[0];   /* diagbarf's `src` */
}

/* ---- Plane B: RSU daemon-log multiplexer (RIS-9260) --------------
 * Plane A (above) is the modem DIAG/F3 firehose. Plane B is the RSU's OWN
 * daemon logs (acme/kapschrsu, cv2x-daemon, cv2x_rx_app SDU deliveries, gpsd,
 * ntpd, startup.d) — the second data type to flow off the box.
 *
 * A self-contained thread TAILS a set of AP-side log files and ships each
 * appended line as a BMX1 tagged record over a DEDICATED UDP sink (default
 * :12400). It is deliberately independent of the DIAG fan-out:
 *   • It owns its own fds + UDP socket and never touches the usbfs OUT path, so
 *     Plane A's byte stream — the acceptance gate — is not perturbed by a
 *     single byte.
 *   • It only ever READS AP-side files and SENDS UDP; it has no handle to the
 *     modem, so "zero bytes written to the 9260" is structural, not a promise.
 *   • A single host pcap on eth1 still captures BOTH planes (different ports),
 *     which is the whole "one capture gets everything" goal.
 *
 * Why a thread with a sleep-poll tail and NOT the main poll() set: the sources
 * are REGULAR FILES, and poll() reports a regular file readable unconditionally
 * — folding them into the fan-out poll() would spin it at 100% CPU. A dedicated
 * low-rate tail loop (log lines, not the firehose) is the right tool and
 * mirrors the existing diagdev/usbfs bridge-thread pattern. */

struct logsrc {
    char        name[32];
    const char *path;
    uint8_t     tag;
    int         fd;             /* -1 when not currently open */
    ino_t       ino;            /* inode at open, for rotation detection */
    off_t       pos;            /* bytes consumed so far (truncation detection) */
    uint32_t    seq;            /* per-source record counter */
    uint8_t     lb[8192];       /* partial-line reassembly buffer */
    size_t      lblen;
    int         restart;        /* set BMX_FLAG_RESTART on the next record */
};

struct planeb_ctx {
    int                     udp_fd;
    struct sockaddr_storage dest;
    socklen_t               destlen;
    struct logsrc           src[MAX_LOG_SRC];
    int                     nsrc;
};

/* (Re)open a log source at its current END — tail -F semantics: we only want
 * lines appended AFTER diagbarf starts, not the file's backlog. Returns 0 if
 * open, -1 if the path can't be opened yet (retried next cycle — a daemon may
 * not have created its log yet). */
static int logsrc_open(struct logsrc *s) {
    int fd = open(s->path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return -1; }
    lseek(fd, 0, SEEK_END);
    s->fd = fd;
    s->ino = st.st_ino;
    s->pos = st.st_size;
    s->lblen = 0;
    s->restart = 1;
    return 0;
}

/* Frame + send one record over the Plane B UDP sink (best-effort; UDP loss is
 * acceptable for advisory logs and the manifest is re-announced periodically).
 * s == NULL is the manifest pseudo-source (seq 0, no RESTART bookkeeping). */
static void planeb_emit(struct planeb_ctx *c, struct logsrc *s, uint8_t tag,
                        const uint8_t *payload, size_t len) {
    uint8_t rec[BMX_HDR_LEN + BMX_MAX_PAYLOAD];
    uint8_t flags = 0;
    uint32_t seq = 0;
    if (s) {
        if (s->restart) { flags |= BMX_FLAG_RESTART; s->restart = 0; }
        seq = s->seq++;
    }
    size_t n = bmx_frame_record(tag, flags, seq, payload, len, rec, sizeof rec);
    if (n)
        (void)!sendto(c->udp_fd, rec, n, 0,
                      (struct sockaddr *)&c->dest, c->destlen);
}

/* Emit the tag→name/path manifest so the host can LABEL every stream without
 * out-of-band knowledge. One BMX1 record, tag = BMX_SRC_MANIFEST, payload =
 * "tag\tname\tpath\n" per source. Advisory — clamped to one datagram. */
static void planeb_emit_manifest(struct planeb_ctx *c) {
    uint8_t blob[BMX_MAX_PAYLOAD];
    size_t o = 0;
    for (int i = 0; i < c->nsrc; i++) {
        int w = snprintf((char *)blob + o, sizeof blob - o, "%u\t%s\t%s\n",
                         c->src[i].tag, c->src[i].name, c->src[i].path);
        if (w < 0 || (size_t)w >= sizeof blob - o)
            break;                              /* clamp — manifest is advisory */
        o += (size_t)w;
    }
    planeb_emit(c, NULL, BMX_SRC_MANIFEST, blob, o);
}

/* Drain all appended bytes from one source, emitting a record per complete
 * line, and handle log rotation / truncation (reopen from the new file's
 * start so a rotated file's first lines are not lost). */
static void logsrc_pump(struct planeb_ctx *c, struct logsrc *s) {
    if (s->fd < 0 && logsrc_open(s) < 0)
        return;
    for (;;) {
        if (s->lblen >= sizeof s->lb) {
            /* A line longer than the whole buffer: flush it as one (clamped)
             * record rather than grow unbounded — matches the diagdev runaway
             * guard. Rare for log lines; keeps memory bounded regardless. */
            planeb_emit(c, s, s->tag, s->lb, s->lblen);
            s->lblen = 0;
        }
        ssize_t n = read(s->fd, s->lb + s->lblen, sizeof s->lb - s->lblen);
        if (n <= 0)
            break;                              /* EAGAIN / EOF / error */
        s->pos += n;
        s->lblen += (size_t)n;
        size_t off = 0; const uint8_t *ln; size_t ll;
        while (linebuf_next_line(s->lb, s->lblen, &off, &ln, &ll))
            planeb_emit(c, s, s->tag, ln, ll);
        if (off) {                              /* keep the partial tail */
            memmove(s->lb, s->lb + off, s->lblen - off);
            s->lblen -= off;
        }
    }
    /* Rotation / truncation: inode changed or the file shrank below what we
     * have already read. Reopen from the START of the current file. */
    struct stat st;
    if (stat(s->path, &st) == 0 &&
        (st.st_ino != s->ino || st.st_size < s->pos)) {
        close(s->fd);
        int fd = open(s->path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd >= 0) {
            s->fd = fd; s->ino = st.st_ino; s->pos = 0;
            s->lblen = 0; s->restart = 1;
        } else {
            s->fd = -1;                         /* retry open next cycle */
        }
    }
}

static void *planeb_thread(void *arg) {
    struct planeb_ctx *c = arg;
    long last_manifest = -1000000;              /* force an immediate first emit */
    while (!g_stop) {
        long now = now_ms();
        if (now - last_manifest >= 30000) {     /* re-announce (UDP is lossy) */
            planeb_emit_manifest(c);
            last_manifest = now;
        }
        for (int i = 0; i < c->nsrc; i++)
            logsrc_pump(c, &c->src[i]);
        /* Low-rate tail: 200 ms is plenty for daemon logs and keeps the i686 AP
         * idle. The DIAG firehose (Plane A), not this, is the throughput case. */
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 200L * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    for (int i = 0; i < c->nsrc; i++)
        if (c->src[i].fd >= 0) close(c->src[i].fd);
    close(c->udp_fd);
    free(c);
    return NULL;
}

/* Build the Plane B context from config and start its thread. Returns 0 on
 * success (*tid_out set + *ctx_out kept for join), -1 on setup failure — in
 * which case Plane A still runs; Plane B is strictly additive. */
static int start_planeb(const struct sockaddr_storage *dest, socklen_t destlen,
                        const char *const *logs, int nlogs,
                        pthread_t *tid_out, struct planeb_ctx **ctx_out) {
    if (nlogs <= 0) {
        logmsg("plane-b: --plane-b-udp given but no --plane-b-log sources; "
               "nothing to tail");
        return -1;
    }
    if (nlogs > MAX_LOG_SRC) {
        logmsg("plane-b: too many --plane-b-log sources (%d > %d)",
               nlogs, MAX_LOG_SRC);
        return -1;
    }
    struct planeb_ctx *c = calloc(1, sizeof *c);
    if (!c) { logmsg("plane-b: OOM"); return -1; }
    c->udp_fd = socket(dest->ss_family, SOCK_DGRAM, 0);
    if (c->udp_fd < 0) {
        logmsg("plane-b: udp socket: %s", strerror(errno));
        free(c);
        return -1;
    }
    if (dest->ss_family == AF_INET) {
        int on = 1;  /* v4 dest may be a broadcast address; no-op for unicast */
        setsockopt(c->udp_fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof on);
    }
    c->dest = *dest;
    c->destlen = destlen;
    c->nsrc = nlogs;
    for (int i = 0; i < nlogs; i++) {
        struct logsrc *s = &c->src[i];
        const char *path;
        if (parse_log_spec(logs[i], s->name, sizeof s->name, &path) < 0) {
            logmsg("plane-b: bad --plane-b-log spec '%s' (want NAME=PATH)",
                   logs[i]);
            close(c->udp_fd); free(c); return -1;
        }
        s->path = path;
        s->tag  = (uint8_t)(BMX_SRC_FIRST + i);
        s->fd   = -1;                           /* opened lazily by logsrc_pump */
    }
    if (pthread_create(tid_out, NULL, planeb_thread, c) != 0) {
        logmsg("plane-b: pthread_create failed");
        close(c->udp_fd); free(c); return -1;
    }
    char ip[80];
    sa_ntop(dest, ip, sizeof ip);
    logmsg("plane-b: tailing %d log source(s) -> BMX1 UDP %s",
           nlogs, ip);
    *ctx_out = c;
    return 0;
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

/* ----------------------------------------------------------------------- */
/* OPT-IN DIAG command passthrough (--cmd-listen)                          */
/* ----------------------------------------------------------------------- */
/* The TCP sinks stay passive (their input is drained and dropped — diagbarf is
 * the sole mask arbiter). --cmd-listen adds ONE separate listener whose single
 * client may send whole HDLC request frames; each is reassembled, CRC-checked,
 * policy-checked (cmd_request_allowed), RE-ENCODED canonically and written to
 * the source as one unit. Replies come back through cmd_router: only reply-class
 * frames reach the command client, never the firehose. Every other sink keeps
 * receiving the raw stream byte-for-byte, replies included.
 *
 * Serialization with diagbarf's own send_recv(): send_recv() only runs inside
 * arm_mask(), which completes before the fan-out pump starts, and the pump is
 * the only place command frames are written — both on the main thread. A
 * client frame is written only once complete, so its bytes can never splice
 * into an in-flight diagbarf frame (pinned by tests/test_cmd_passthrough.c). */

#define CMD_MAX_REQ    2046    /* decoded request bytes: hdlc_encap()'s 2048-byte
                                * work buffer minus the 2-byte FCS */
#define CMD_RX_CAP     8192    /* escaped bytes buffered for one client frame */
#define CMD_ROUTE_CAP  16384   /* escaped bytes buffered for one routed reply */

#define CMD_E_BADCRC    (-1)
#define CMD_E_MALFORMED (-2)
#define CMD_E_TOOBIG    (-3)

struct cmd_stats {
    unsigned long forwarded, refused, bad_crc, malformed, oversize, routed, dropped;
};

/* Client -> modem request reassembly. `discard` = inside a runaway frame that
 * overflowed buf; drop everything through the next 0x7E. */
struct cmd_rx {
    uint8_t buf[CMD_RX_CAP];
    size_t len;
    int discard;
};

static void cmd_rx_reset(struct cmd_rx *c)
{
    c->len = 0;
    c->discard = 0;
}

/* Strict decap for untrusted client frames (delimiter already removed):
 * unescape, then VERIFY the CRC-16 FCS — unlike hdlc_decap(), which strips the
 * trailer unchecked. Writes payload+FCS into out (cap = max payload + 2).
 * Returns the payload length (>= 1, FCS excluded) or CMD_E_*. Pure. */
static int cmd_hdlc_decap_crc(const uint8_t *frame, size_t len,
                              uint8_t *out, size_t outcap)
{
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t b = frame[i];
        if (b == 0x7D) {
            if (i + 1 >= len)
                return CMD_E_MALFORMED;      /* dangling escape */
            b = (uint8_t)(frame[++i] ^ 0x20);
        }
        if (o >= outcap)
            return CMD_E_TOOBIG;
        out[o++] = b;
    }
    if (o < 3)
        return CMD_E_MALFORMED;              /* opcode + 2-byte FCS minimum */
    uint16_t want = (uint16_t)(out[o - 2] | (out[o - 1] << 8));
    if (crc16(out, o - 2) != want)
        return CMD_E_BADCRC;
    return (int)(o - 2);
}

/* One-line audit description of a decoded request, for the syslog record. */
static void cmd_describe(const uint8_t *p, size_t n, char *out, size_t cap)
{
    if (n >= 4 && p[0] == DIAG_SUBSYS_CMD_F)
        snprintf(out, cap, "op=0x4B subsys=0x%02X cmd=0x%04X len=%zu",
                 p[1], (unsigned)(p[2] | (p[3] << 8)), n);
    else if (n >= 8 && p[0] == DIAG_SUBSYS_CMD_VER_2_F)
        snprintf(out, cap, "op=0x80 subsys=0x%02X cmd=0x%02X record=%u len=%zu",
                 p[1], p[2], (unsigned)(p[6] | (p[7] << 8)), n);
    else if (n >= 3 && (p[0] == DIAG_NV_READ_F || p[0] == DIAG_NV_WRITE_F))
        snprintf(out, cap, "op=0x%02X nv_item=%u len=%zu",
                 p[0], (unsigned)(p[1] | (p[2] << 8)), n);
    else if (n >= 1)
        snprintf(out, cap, "op=0x%02X len=%zu", p[0], n);
    else
        snprintf(out, cap, "empty");
}

/* Validate one complete client frame and, if allowed, ship it to src. Logs one
 * line per request either way (the audit trail for NV/EFS writes). Returns 0,
 * or -1 if writing to src failed (the source is gone; caller re-spawns). */
static int cmd_forward_frame(int src, const uint8_t *frame, size_t len,
                             struct cmd_stats *st)
{
    uint8_t pkt[CMD_MAX_REQ + 2];
    int d = cmd_hdlc_decap_crc(frame, len, pkt, sizeof pkt);
    if (d == CMD_E_TOOBIG) {
        st->oversize++;
        logmsg("cmd: REFUSED request (decoded length > %d bytes)", CMD_MAX_REQ);
        return 0;
    }
    if (d == CMD_E_MALFORMED) {
        st->malformed++;
        logmsg("cmd: REFUSED request (malformed HDLC frame, %zu bytes)", len);
        return 0;
    }
    if (d == CMD_E_BADCRC) {
        st->bad_crc++;
        logmsg("cmd: REFUSED request (bad CRC, %zu bytes)", len);
        return 0;
    }
    char desc[96];
    cmd_describe(pkt, (size_t)d, desc, sizeof desc);
    if (!cmd_request_allowed(pkt, (size_t)d)) {
        st->refused++;
        logmsg("cmd: REFUSED %s (not on the passthrough allow-list)", desc);
        return 0;
    }
    /* Ship the canonical encoding of the bytes just checked — never the
     * client's own spelling — so no decoder differential between diagbarf and
     * the modem can carry a command other than the one the policy saw. */
    uint8_t enc[2 * (CMD_MAX_REQ + 2) + 1];
    size_t en = hdlc_encap(pkt, (size_t)d, enc, sizeof enc);
    if (en == 0) {
        st->oversize++;
        logmsg("cmd: REFUSED %s (re-encode failed)", desc);
        return 0;
    }
    if (write_all(src, enc, en) < 0) {
        logmsg("cmd: write to the DIAG source failed: %s", strerror(errno));
        return -1;
    }
    st->forwarded++;
    logmsg("cmd: FORWARDED %s", desc);
    return 0;
}

/* Feed bytes read from the command client. Complete 0x7E-terminated frames are
 * validated + forwarded as they close; a partial frame waits in c->buf. Empty
 * frames (idle/open 0x7E flags) are skipped. Returns 0, or -1 on src failure. */
static int cmd_rx_feed(struct cmd_rx *c, int src, const uint8_t *data, size_t n,
                       struct cmd_stats *st)
{
    size_t i = 0;
    while (i < n) {
        const uint8_t *d = memchr(data + i, 0x7E, n - i);
        size_t take = d ? (size_t)(d - (data + i)) : n - i;
        if (!c->discard) {
            if (c->len + take > sizeof c->buf) {
                c->discard = 1;
                c->len = 0;
                st->oversize++;
                logmsg("cmd: REFUSED request (no frame delimiter within %d "
                       "bytes) — discarding to the next 0x7E", CMD_RX_CAP);
            } else {
                memcpy(c->buf + c->len, data + i, take);
                c->len += take;
            }
        }
        i += take;
        if (!d)
            break;
        i++;                                    /* consume the delimiter */
        if (c->discard) {
            c->discard = 0;
            c->len = 0;
            continue;
        }
        if (c->len == 0)
            continue;                           /* empty frame */
        int r = cmd_forward_frame(src, c->buf, c->len, st);
        c->len = 0;
        if (r < 0)
            return -1;
    }
    return 0;
}

/* Modem -> command client reply routing: a streaming classifier over the raw
 * source bytes. A frame is routed iff its (unescaped) first byte is a reply to
 * an allowed request (replies echo the request opcode) or a DIAG error reply;
 * async LOG/F3/EVENT/QSR/QSH frames are skipped with one memchr per frame. */
enum { CMD_RT_SKIP = 0, CMD_RT_START, CMD_RT_START_ESC, CMD_RT_ROUTE };

struct cmd_router {
    int state;
    size_t len;
    uint8_t buf[CMD_ROUTE_CAP];                 /* raw (escaped) routed frame */
};

/* Start resynchronized: the first bytes seen may be mid-frame (a new source,
 * or a client connecting mid-stream), so drop through the first 0x7E. */
static void cmd_router_reset(struct cmd_router *r)
{
    r->state = CMD_RT_SKIP;
    r->len = 0;
}

static int cmd_response_routable(uint8_t op)
{
    /* Block wins first — same precedence as the request gate. An opcode-level
     * block (no subsystem/cmd qualifier) suppresses the reply too, so a blocked
     * family is silent in both directions. (A reply carries no subsystem/cmd
     * tail to match a qualified rule against, so only opcode-level blocks apply
     * here; the request gate already refused the qualified cases outbound.) */
    for (int i = 0; i < g_n_cmd_block; i++)
        if (g_cmd_block[i].op == op && !g_cmd_block[i].has_sub)
            return 0;
    switch (op) {
    case DIAG_VERNO_F:
    case DIAG_STATUS_F:
    case DIAG_EXT_BUILD_ID_F:
    case DIAG_NV_READ_F:
    case DIAG_NV_WRITE_F:
    case DIAG_TS_F:
    case DIAG_SUBSYS_CMD_F:
    case DIAG_SUBSYS_CMD_VER_2_F:
    case DIAG_BAD_CMD_F:
    case DIAG_BAD_PARM_F:
    case DIAG_BAD_LEN_F:
    case DIAG_BAD_MODE_F:
        return 1;
    default:
        break;
    }
    /* A reply echoes its request's opcode, so a reply to an EXTRA-allowed
     * request must route back too — else --cmd-allow lets the request out but
     * the answer is silently dropped. Matched on opcode alone for the reason
     * noted above. */
    for (int i = 0; i < g_n_cmd_allow_extra; i++)
        if (g_cmd_allow_extra[i].op == op)
            return 1;
    return 0;
}

/* Write one routed frame to the (non-blocking) client. A client that is not
 * draining must never stall the firehose and must never see a torn frame: a
 * full socket buffer drops the WHOLE reply (logged); a partial write or a hard
 * error returns -1 and the caller closes the client. */
static int cmd_router_emit(struct cmd_router *r, int client, struct cmd_stats *st)
{
    ssize_t w = write(client, r->buf, r->len);
    if (w == (ssize_t)r->len) {
        st->routed++;
        return 0;
    }
    if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        st->dropped++;
        logmsg("cmd: command client not draining — dropped a %zu-byte reply",
               r->len);
        return 0;
    }
    return -1;
}

/* Feed a chunk of the raw source stream. Returns 0, or -1 if the client broke. */
static int cmd_router_feed(struct cmd_router *r, const uint8_t *data, size_t n,
                           int client, struct cmd_stats *st)
{
    size_t i = 0;
    while (i < n) {
        switch (r->state) {
        case CMD_RT_SKIP: {
            const uint8_t *d = memchr(data + i, 0x7E, n - i);
            if (!d)
                return 0;
            i = (size_t)(d - data) + 1;
            r->state = CMD_RT_START;
            r->len = 0;
            break;
        }
        case CMD_RT_START: {
            uint8_t b = data[i++];
            if (b == 0x7E)
                break;                          /* empty frame */
            r->buf[0] = b;
            r->len = 1;
            if (b == 0x7D)
                r->state = CMD_RT_START_ESC;    /* opcode is the next byte ^ 0x20 */
            else
                r->state = cmd_response_routable(b) ? CMD_RT_ROUTE : CMD_RT_SKIP;
            break;
        }
        case CMD_RT_START_ESC: {
            uint8_t b = data[i++];
            if (b == 0x7E) {                    /* "7D 7E": malformed, frame over */
                r->state = CMD_RT_START;
                r->len = 0;
                break;
            }
            r->buf[r->len++] = b;
            r->state = cmd_response_routable((uint8_t)(b ^ 0x20)) ? CMD_RT_ROUTE
                                                                 : CMD_RT_SKIP;
            break;
        }
        case CMD_RT_ROUTE: {
            const uint8_t *d = memchr(data + i, 0x7E, n - i);
            size_t take = d ? (size_t)(d - (data + i)) + 1 : n - i; /* incl. 0x7E */
            if (r->len + take > sizeof r->buf) {
                st->dropped++;
                logmsg("cmd: reply frame larger than %d bytes — not routed",
                       CMD_ROUTE_CAP);
                r->state = CMD_RT_SKIP;         /* SKIP finds this frame's 0x7E */
                r->len = 0;
                break;
            }
            memcpy(r->buf + r->len, data + i, take);
            r->len += take;
            i += take;
            if (d) {
                int rc = cmd_router_emit(r, client, st);
                r->state = CMD_RT_START;
                r->len = 0;
                if (rc < 0)
                    return -1;
            }
            break;
        }
        }
    }
    return 0;
}

/* --cmd-listen [ADDR:]PORT. A bare PORT binds 127.0.0.1 — NOT the wildcard the
 * data sinks use — so the command channel is reachable only on-box (or over
 * ssh -L) unless an address is given explicitly. */
static int parse_cmd_listen(const char *spec, struct sockaddr_storage *ss,
                            socklen_t *slen)
{
    if (parse_hostport(spec, ss, slen, AF_INET) < 0)
        return -1;
    if (!strchr(spec, ':'))
        ((struct sockaddr_in *)ss)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return 0;
}

/* Arm the global log mask to "everything" (port of
 * diaggulp._build_all_logs_mask). Returns 0 on success, -1 on failure
 * (caller treats failure as non-fatal and pumps anyway). */
/* QSH-trace maskset SET (DIAG_SUBSYS_CMD_F, subsys 0x44, cmd 0x9001) — the
 * on-device primitive that turns on the 0x9D DIAG_QSH_TRACE_PAYLOAD_F stream.
 * These 40 (ssid, level) pairs are frame 73 of the golden cfw3212
 * /data/diag.cfg (USC_1.1.99.0, md5 381bd429), which diag_mdlog replays to bank
 * ~200k-330k 0x9D. Host-side replay of the identical maskset was verified to
 * arm 0x9D on SDX55 (Telit FN980m) and is the SDX62 family the cfw3212 ships
 *. Mirror of diagmunge's GOLDEN_QSH_TRACE_PAIRS — kept
 * byte-identical and pinned by tests/test_qsh_arm.c against the 180-byte frame.
 *
 * ⛔ ssids MUST stay strictly ascending: the modem rejects any inversion with
 * status 1 (an ordering fault, NOT a per-subsystem rejection). Judge
 * arming by whether 0x9D frames actually arrive, never by the SET status alone. */
static const uint16_t qsh_trace_golden_pairs[][2] = {
    {0x06,0x0F},{0x09,0x3E},{0x0B,0x03},{0x0D,0x03},{0x12,0x01},
    {0x2A,0x03},{0x2D,0x03},{0x2F,0x07},{0x34,0x0F},{0x35,0x1F},
    {0x36,0x03},{0x3D,0x03},{0x40,0x03},{0x49,0x0B},{0x4C,0x087F},
    {0x4E,0x02},{0x50,0x03},{0x53,0x3F},{0x54,0x0F},{0x55,0x0F},
    {0x56,0x03},{0x57,0x03},{0x58,0x01},{0x59,0x0F},{0x5E,0x01},
    {0x60,0x07},{0x61,0x03},{0x62,0x0F},{0x63,0x03},{0x64,0x3F},
    {0x65,0x03},{0x68,0x03},{0x69,0x0F},{0x6B,0x03},{0x6C,0x03},
    {0x6D,0x03},{0x6E,0x03},{0x6F,0x01},{0x70,0x01},{0x71,0x03},
};
#define QSH_TRACE_NPAIRS       (sizeof qsh_trace_golden_pairs / sizeof qsh_trace_golden_pairs[0])
#define QSH_TRACE_SUBSYS_ID    0x44
#define QSH_TRACE_MASKSET_SET  0x9001
#define QSH_TRACE_SET_MIN_ARGS 3       /* word_a + word_b + count precede the pairs */

/* Build the DIAG_SUBSYS_CMD_F payload (everything AFTER the 0x4B opcode byte,
 * which send_recv() prepends) for the golden QSH-trace maskset SET. Layout:
 *   u8(subsys_id) u16le(cmd) u32le(arg_count) u32le(1) u32le(1) u32le(count)
 *   count*(u16le ssid, u16le level)
 * with arg_count = QSH_TRACE_SET_MIN_ARGS + count. Returns the payload length,
 * or 0 if `out` is too small. Pure/host-testable. */
static size_t qsh_trace_arm_payload(uint8_t *out, size_t cap)
{
    size_t n = QSH_TRACE_NPAIRS;
    size_t need = 3 + 16 + n * 4;      /* subsys+cmd, 4 header u32, pairs */
    if (cap < need)
        return 0;
    size_t o = 0;
    out[o++] = QSH_TRACE_SUBSYS_ID;
    out[o++] = (uint8_t)(QSH_TRACE_MASKSET_SET & 0xFF);
    out[o++] = (uint8_t)((QSH_TRACE_MASKSET_SET >> 8) & 0xFF);
    uint32_t hdr[4] = {
        (uint32_t)(QSH_TRACE_SET_MIN_ARGS + n),   /* arg_count */
        1u, 1u,                                    /* word_a, word_b */
        (uint32_t)n,                               /* count */
    };
    memcpy(out + o, hdr, sizeof hdr); o += sizeof hdr;
    for (size_t i = 0; i < n; i++) {
        uint16_t ssid = qsh_trace_golden_pairs[i][0];
        uint16_t lvl  = qsh_trace_golden_pairs[i][1];
        memcpy(out + o, &ssid, 2); o += 2;
        memcpy(out + o, &lvl, 2);  o += 2;
    }
    return o;
}

/* Order the log types to arm. Writes ordered log-type indices into out[] (cap
 * NUM_LOG_TYPES) and returns the count. Pure — no I/O — so the host tests pin it.
 *
 * Order is load-bearing: SET_MASK is a request/response exchange, but arming a
 * busy type starts its flood immediately and that flood buries the SET_MASK
 * responses for everything armed after it (measured on the MDM9250: ascending
 * order armed 0-6 then timed out on 7/10/11/13 under 2.06 MB/s of type-1 LTE).
 * Type 11 is the C-V2X sidelink plane (0xB2xx), so `priority` types are armed
 * first, in the given order, deduped, empties (bitsize 0) dropped. With `only`,
 * nothing outside `priority` is armed. With no priority and !only, the order is
 * all non-empty types ascending (the historical default). Mirrors
 * st_diag_collect.plan_log_types byte-for-byte. */
static int plan_log_types(const uint32_t *bitsizes, const int *priority,
                          int npriority, int only, int *out)
{
    int n = 0;
    char seen[NUM_LOG_TYPES] = { 0 };
    for (int i = 0; i < npriority; i++) {
        int lt = priority[i];
        if (lt < 0 || lt >= NUM_LOG_TYPES)
            continue;                     /* caller validates; skip defensively */
        if (seen[lt] || !bitsizes[lt])    /* dedupe; empties skipped-not-faked */
            continue;
        seen[lt] = 1;
        out[n++] = lt;
    }
    if (!only) {
        for (int lt = 0; lt < NUM_LOG_TYPES; lt++) {
            if (seen[lt] || !bitsizes[lt])
                continue;
            seen[lt] = 1;
            out[n++] = lt;
        }
    }
    return n;
}

/* Build a 0x7D mask-table READ request body (the bytes AFTER the 0x7D opcode,
 * which send_recv prepends). Wire: u8 sub_cmd, u16le first, u16le last → 5 bytes.
 * `sub` is GET_BUILD_MASK (2, capability) or GET_RT_MASK (3, runtime). Returns
 * the byte count written, or 0 on bad args / short buffer. */
static size_t build_ext_msg_get_mask_request(uint8_t sub, uint16_t first,
                                             uint16_t last, uint8_t *out,
                                             size_t outcap)
{
    if (sub != EXT_MSG_GET_BUILD_MASK && sub != EXT_MSG_GET_RT_MASK)
        return 0;
    if (last < first || outcap < 5)
        return 0;
    out[0] = sub;
    memcpy(out + 1, &first, 2);
    memcpy(out + 3, &last, 2);
    return 5;
}

/* Build a 0x7D SET_RT_MASK (sub-command 4) body (AFTER the opcode). One u32
 * runtime level per ss_id in the inclusive range [first .. first+n-1]. Wire:
 * u8(4) u16le(first) u16le(last) u16le(reserved=0) u32le(level)*n. The reserved
 * u16 between `last` and the mask array is 0 in every golden frame; omitting it
 * shifts every mask by two bytes, so it is explicit. Returns bytes written, or
 * 0 on bad args / short buffer. This is a DIAG *write* that enables F3 message
 * output (RX telemetry); it does not touch RF/TX or persistent NV. */
static size_t build_ext_msg_set_rt_mask(uint16_t first, const uint32_t *levels,
                                        int n, uint8_t *out, size_t outcap)
{
    if (n <= 0 || (size_t)first + (size_t)n - 1 > 0xFFFF)
        return 0;
    size_t need = 7 + (size_t)n * 4;
    if (outcap < need)
        return 0;
    uint16_t last = (uint16_t)(first + n - 1);
    uint16_t reserved = 0;
    out[0] = EXT_MSG_SET_RT_MASK;
    memcpy(out + 1, &first, 2);
    memcpy(out + 3, &last, 2);
    memcpy(out + 5, &reserved, 2);
    for (int i = 0; i < n; i++)
        memcpy(out + 7 + (size_t)i * 4, &levels[i], 4);
    return need;
}

/* Parse an --ext-msg-f3-mute spec: comma-separated SSIDs or inclusive
 * ranges, e.g. "47" or "47,85-86". Each ss_id is 0..65535, first <= last, and a
 * range spans at most F3_MUTE_SPAN ss_ids (one SET_RT_MASK frame). Writes up to
 * cap ranges; returns the count, or -1 on any malformed entry or overflow. */
static int parse_ssid_ranges(const char *spec, uint16_t *first, uint16_t *last,
                             int cap)
{
    if (!spec || !*spec)
        return -1;
    int n = 0;
    const char *s = spec;
    for (;;) {
        char *end = NULL;
        if (*s < '0' || *s > '9')
            return -1;
        unsigned long a = strtoul(s, &end, 10);
        unsigned long b = a;
        if (*end == '-') {
            s = end + 1;
            if (*s < '0' || *s > '9')
                return -1;
            b = strtoul(s, &end, 10);
        }
        if (a > 0xFFFF || b > 0xFFFF || b < a || b - a + 1 > F3_MUTE_SPAN)
            return -1;
        if (n >= cap)
            return -1;
        first[n] = (uint16_t)a;
        last[n] = (uint16_t)b;
        n++;
        if (*end == '\0')
            return n;
        if (*end != ',')
            return -1;
        s = end + 1;
    }
}

/* Build the SET_RT_MASK body that mutes ss_ids [first..last] (every level 0).
 * Returns bytes written, or 0 on bad args / short buffer. */
static size_t build_ext_msg_mute_range(uint16_t first, uint16_t last,
                                       uint8_t *out, size_t outcap)
{
    uint32_t zeros[F3_MUTE_SPAN];
    if (last < first || last - first + 1 > F3_MUTE_SPAN)
        return 0;
    memset(zeros, 0, sizeof zeros);
    return build_ext_msg_set_rt_mask(first, zeros, last - first + 1, out, outcap);
}

/* Parse a 0x7D GET_BUILD_MASK/GET_RT_MASK reply body (the frame minus the
 * opcode, as send_recv returns). Layout: [0] u8 sub echo, [1:3] u16 first,
 * [3:5] u16 last, [5:7] u16 status, [7:] u32[] one mask per ss_id. Writes the
 * parsed fields + up to maskcap masks, returns the mask count, or -1 if the body
 * is too short, not a mask-table read, or not a whole number of u32 entries (so
 * a truncated reply is never misread as "mask is 0"). Mirrors
 * st_diag_collect.parse_ext_msg_mask_table_reply — the array is at offset 7. */
static int parse_ext_msg_mask_table_reply(const uint8_t *body, int len,
                                          uint8_t *sub, uint16_t *first,
                                          uint16_t *last, uint16_t *status,
                                          uint32_t *masks, int maskcap)
{
    if (!body || len < EXT_MSG_MASK_TABLE_HDR_LEN)
        return -1;
    if (body[0] != EXT_MSG_GET_BUILD_MASK && body[0] != EXT_MSG_GET_RT_MASK)
        return -1;
    int payload = len - EXT_MSG_MASK_TABLE_HDR_LEN;
    if (payload <= 0 || payload % 4)
        return -1;
    int nmask = payload / 4;
    if (sub)    *sub = body[0];
    if (first)  memcpy(first, body + 1, 2);
    if (last)   memcpy(last, body + 3, 2);
    if (status) memcpy(status, body + 5, 2);
    int nout = nmask < maskcap ? nmask : maskcap;
    for (int i = 0; i < nout; i++)
        memcpy(&masks[i], body + EXT_MSG_MASK_TABLE_HDR_LEN + (size_t)i * 4, 4);
    return nmask;
}

/* Is `s` a --source mode this build accepts? Pure; pins the CLI validation and
 * the `--source stdin` no-arm passthrough in one table. */
static int source_is_valid(const char *s)
{
    return s && (strcmp(s, "socket-log") == 0 ||
                 strcmp(s, "diag-dev") == 0 ||
                 strcmp(s, "hdlc-chardev") == 0 ||
                 strcmp(s, "usbfs") == 0 ||
                 strcmp(s, "stdin") == 0);
}

/* Should diagbarf drive the DIAG_LOG_CONFIG_F / F3 / QSH arming handshake for
 * this source? Yes for every channel that reaches the modem; NO for `stdin`,
 * whose stream is already armed upstream (diaggulp on the ST) and is fed in
 * one-way over a pipe — arming writes would have nowhere to go. Pure. */
static int source_should_arm(const char *s)
{
    return s && strcmp(s, "stdin") != 0;
}

/* Can --cmd-listen forward requests over this source? Not stdin: it is a
 * one-way pipe from the upstream arming tool, with no path back to the modem.
 * Pure; kept separate from source_should_arm() because "we arm" and "a client
 * may command" are different questions that happen to agree today. */
static int source_accepts_commands(const char *s)
{
    return s && strcmp(s, "stdin") != 0;
}

/* Arm the global log mask (port of diaggulp._build_all_logs_mask +
 * st_diag_collect.arm_masks). `priority`/`npriority`/`only` choose and order the
 * log types (see plan_log_types); `ext_msg_f3` also arms the F3 debug-message
 * stream, with the per-SSID SET_RT_MASK fallback; `qsh_trace` arms the 0x9D
 * QSH-trace plane. Returns 0 on success, -1 on failure (caller treats failure as
 * non-fatal and pumps anyway). */
enum { MASK_MAX = 0, MASK_GNSS = 1, MASK_NONE = 2 };

/* --mask value -> MASK_*; -1 for anything else. */
static int parse_mask_mode(const char *s)
{
    if (!strcmp(s, "max"))  return MASK_MAX;
    if (!strcmp(s, "gnss")) return MASK_GNSS;
    if (!strcmp(s, "none")) return MASK_NONE;
    return -1;
}

/* SET_MASK bitmap for one log type holding only `codes`. Same layout
 * as diagmunge DiagClient.subscribe_logs: item i -> byte i/8, bit i%8. Codes in
 * another type, or past this type's bitsize, are skipped. Returns how many
 * codes landed in this type; the bitmap is all-zero when that is 0, which
 * still goes out so a previous owner's bits in this type are cleared. */
static int fill_code_mask(uint32_t lt, uint32_t bitsize, const uint16_t *codes,
                          int ncodes, uint8_t *mask, size_t mbytes)
{
    memset(mask, 0, mbytes);
    int n = 0;
    for (int i = 0; i < ncodes; i++) {
        uint32_t c = codes[i];
        uint32_t item = c & 0xFFFu;
        if ((c >> 12) != lt || item >= bitsize || item / 8 >= mbytes)
            continue;
        mask[item / 8] |= (uint8_t)(1u << (item % 8));
        n++;
    }
    return n;
}

static int arm_mask(int src, struct rxbuf *rx, int ext_msg_f3, int qsh_trace,
                    const int *priority, int npriority, int only,
                    const uint16_t *mute_first, const uint16_t *mute_last,
                    int nmute, const uint16_t *codes, int ncodes)
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

    /* Order the types to arm (priority-first so a busy type's flood does not
     * bury the SET_MASK response of the plane we actually want). A
     * single SET_MASK timeout is NON-fatal: log it and keep going, so a buried
     * later type never costs us the ones that did arm. */
    int order[NUM_LOG_TYPES];
    int norder = plan_log_types(bitsizes, priority, npriority, only, order);
    int groups = 0;
    long total_codes = 0;
    for (int oi = 0; oi < norder; oi++) {
        uint32_t lt = (uint32_t)order[oi];
        uint32_t bs = bitsizes[lt];
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
        int ncodes_here = (int)bs;
        if (codes) {                      /* --mask gnss: only the preset's bits */
            ncodes_here = fill_code_mask(lt, bs, codes, ncodes, p + 15, mbytes);
        } else {
            memset(p + 15, 0xFF, mbytes);
            if (bs % 8) {                 /* trim extra bits in the last byte */
                int extra = 8 - (int)(bs % 8);
                p[15 + mbytes - 1] = (uint8_t)(0xFF >> extra);
            }
        }
        int sr = send_recv(src, rx, DIAG_LOG_CONFIG_F, p, plen, 10000,
                           resp, sizeof resp);
        free(p);
        if (sr < 0) {
            logmsg("mask: SET_MASK log_type=%u failed/timeout (non-fatal)", lt);
            continue;
        }
        groups++;
        total_codes += ncodes_here;
    }
    logmsg("mask: subscribed to %ld log codes across %d/%d groups%s",
           total_codes, groups, norder, only ? " (only)" : "");

    if (ext_msg_f3) {
        /* DIAG_EXT_MSG_CONFIG_F / SET_ALL_RT_MASKS: byte(5) + 2 pad + uint32(0xFFFFFFFF) */
        uint8_t e[7];
        e[0] = EXT_MSG_SET_ALL_RT_MASKS;
        e[1] = 0; e[2] = 0;
        uint32_t all = EXT_MSG_ALL_LEVELS;
        memcpy(e + 3, &all, 4);
        int er = send_recv(src, rx, DIAG_EXT_MSG_CONFIG_F, e, sizeof e, 10000,
                           resp, sizeof resp);
        if (er >= 0) {
            logmsg("mask: enabled all F3 ext-msg runtime levels");
        } else {
            /* SET_ALL_RT_MASKS is a silent no-op on the MDM9250 MPSS (no
             * reply, no F3). Fall back to per-SSID SET_RT_MASK, arming only the
             * ss_ids the build-capability mask reports, at their own levels (0
             * entries are harmless no-ops). F3 arming stays NON-fatal. */
            uint8_t req[8];
            size_t reqn = build_ext_msg_get_mask_request(
                EXT_MSG_GET_BUILD_MASK, 0, EXT_MSG_SS_RANGE0_LAST, req, sizeof req);
            int blen = send_recv(src, rx, DIAG_EXT_MSG_CONFIG_F, req, reqn, 10000,
                                 resp, sizeof resp);
            uint32_t levels[EXT_MSG_SS_RANGE0_LAST + 1];
            int nm = parse_ext_msg_mask_table_reply(resp, blen, NULL, NULL, NULL,
                                                    NULL, levels,
                                                    EXT_MSG_SS_RANGE0_LAST + 1);
            /* parse reports the reply's TRUE mask count (modem-supplied length),
             * but only maskcap entries were written into levels[]. A reply that
             * spans more ss_ids than we requested ([0..120]) would otherwise make
             * the loop/SET below index past the buffer — clamp to what we hold
             *. On the conformant MDM9250 reply nm == maskcap already. */
            if (nm > EXT_MSG_SS_RANGE0_LAST + 1)
                nm = EXT_MSG_SS_RANGE0_LAST + 1;
            int capable = 0;
            for (int i = 0; i < nm; i++)
                if (levels[i]) capable++;
            if (nm > 0 && capable > 0) {
                uint8_t set[8 + (EXT_MSG_SS_RANGE0_LAST + 1) * 4];
                size_t setn = build_ext_msg_set_rt_mask(0, levels, nm, set,
                                                        sizeof set);
                /* The 0x7D reply is usually buried by the F3 flood this SET
                 * starts, so a timeout here is expected — do not treat it as
                 * failure; the capture itself shows whether F3 is flowing. */
                send_recv(src, rx, DIAG_EXT_MSG_CONFIG_F, set, setn, 10000,
                          resp, sizeof resp);
                logmsg("mask: F3 SET_RT_MASK fallback armed %d capable ss_ids",
                       capable);
            } else {
                logmsg("mask: F3 not reachable on this build — build mask "
                       "unreadable/empty (non-fatal)");
            }
        }

        /* --ext-msg-f3-mute: drop chosen SSIDs back to level 0. This
         * must come AFTER the arm above, which would otherwise re-enable them.
         * On the RIS-9260 (MDM9150) ss_id 47 carries the GNSS correlator
         * prints (cc_slicer.c & co): 52% of all DIAG bytes on the bench. Like
         * the fallback SET, the reply is usually buried in the flood, so no
         * reply is not a failure; the capture shows whether the SSID is gone. */
        for (int i = 0; i < nmute; i++) {
            uint8_t set[8 + F3_MUTE_SPAN * 4];
            size_t setn = build_ext_msg_mute_range(mute_first[i], mute_last[i],
                                                   set, sizeof set);
            if (!setn)
                continue;
            send_recv(src, rx, DIAG_EXT_MSG_CONFIG_F, set, setn, 3000,
                      resp, sizeof resp);
            logmsg("mask: F3 muted ss_id %u-%u",
                   (unsigned)mute_first[i], (unsigned)mute_last[i]);
        }
    }

    if (qsh_trace) {
        /* Arm the QSH-trace 0x9D stream via the golden 0x9001 maskset SET. The
         * response echoes subsys 0x44 / cmd 0x9001 with a u32 status at body+3:
         * 0 = armed, 1 = maskset ordering fault, 2 = QSH absent on this
         * generation (e.g. SDX24). Non-fatal — like F3, we fan out whatever the
         * firmware then emits. */
        uint8_t q[256];
        size_t qn = qsh_trace_arm_payload(q, sizeof q);
        if (qn == 0) {
            logmsg("mask: QSH-trace payload build failed (buffer too small)");
        } else {
            int qr = send_recv(src, rx, DIAG_SUBSYS_CMD_F, q, qn, 10000,
                               resp, sizeof resp);
            if (qr < 0) {
                logmsg("mask: QSH-trace 0x9001 arm failed/timeout (non-fatal)");
            } else if (qr >= 7) {
                uint32_t qstatus;
                memcpy(&qstatus, resp + 3, 4);
                logmsg("mask: QSH-trace 0x9001 maskset SET status=%u (%zu pairs)",
                       qstatus, (size_t)QSH_TRACE_NPAIRS);
            } else {
                logmsg("mask: QSH-trace 0x9001 armed (short resp %d bytes)", qr);
            }
        }
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* Sinks                                                                   */
/* ----------------------------------------------------------------------- */

struct udp_sink {
    int enabled;
    int fd;
    struct sockaddr_storage dest;
    socklen_t destlen;
    uint32_t seq;
};

struct tcp_out {                  /* tcp-dial back-compat sink */
    int enabled;
    int fd;                       /* -1 when disconnected */
    struct sockaddr_storage dest;
    socklen_t destlen;
    long next_retry_ms;
};

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
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
                           (struct sockaddr *)&s->dest, s->destlen);
        (void)w;     /* UDP best-effort: ignore transient send errors */
        off += take;
        first = 0;
    }
}

/* ----------------------------------------------------------------------- */
/* Per-client subscriptions (--client-filters / --keep-*)                  */
/* ----------------------------------------------------------------------- */
/* OPT-IN delivery filtering, Part D of the DIAG consumer-filtering design
 *. Masks are untouched — diagbarf stays the sole mask arbiter; this
 * only decides which frames each sink receives.
 *
 * The peek is the C twin of diagmunge.framefilter.peek(): unescape at most the
 * first 32 escaped bytes, read the outer opcode, the 0x98 multi-radio
 * wrapper's inner opcode at offset 8, and the (inner) 0x10 LOG code at bytes
 * 6-8. Both implementations run the SAME vectors (tests/diag_peek_vectors.json,
 * pinned byte-equal to diagmunge's own copy of the vectors).
 *
 * A filtered sink receives each matching frame as 0x7E + original escaped
 * bytes + 0x7E (byte-exact, CRC-verified; bad-CRC frames are dropped) — the
 * same output diag_peek_filter (Part B) writes for the same filter. Sinks
 * without a filter receive the raw read() chunks exactly as before. */

#define SUB_LINE_MAX         4096    /* SUB line incl. the "SUB " prefix */
#define SUB_MAX_CODES        256
#define SUB_MAX_OPCODES      32
#define SUB_GRACE_MS_DEFAULT 500
#define PEEK_WINDOW          32      /* escaped bytes examined by dpeek_frame */
#define PEEK_LOG_OP          0x10    /* DIAG_LOG_F */
#define PEEK_EVENT_OP        0x60    /* DIAG_EVENT_REPORT_F */
#define PEEK_MULTI_RADIO_OP  0x98    /* DIAG_MULTI_RADIO wrapper */
#define PEEK_MULTI_RADIO_OFF 8       /* offset of the wrapped frame */
#define PEEK_LOG_CODE_OFF    6       /* [0]=op [1]=more [2:4]=len [4:6]=len2 [6:8]=code */
#define SPLIT_CARRY_CAP      65536   /* longest frame carried across reads */
#define SPLIT_MAX_FRAMES     (READ_CHUNK / 2 + 2)
#define FILT_OUT_CAP         (SPLIT_CARRY_CAP + 2 * READ_CHUNK + 16)

struct dpeek {
    int opcode;        /* outer opcode (byte 0) */
    int inner;         /* 0x98 wrapper: wrapped opcode; else -1 */
    int log_code;      /* (inner) 0x10 LOG frame: log code; else -1 */
};

/* Classify an escaped frame (no 0x7E delimiters) from its head. Returns 0, or
 * -1 when the frame is too short to classify (an (inner) 0x10 frame without
 * room for a log code is -1 too: it cannot be a valid LOG frame). */
static int dpeek_frame(const uint8_t *esc, size_t n, struct dpeek *p)
{
    uint8_t head[PEEK_WINDOW];
    size_t win = n < PEEK_WINDOW ? n : PEEK_WINDOW, h = 0;
    if (n == 0)
        return -1;
    /* Same result as framefilter.unescape's two-replace form: only 7D 5E and
     * 7D 5D are escapes; any other 7D xx is left verbatim (and fails CRC). */
    for (size_t i = 0; i < win; i++) {
        if (esc[i] == 0x7D && i + 1 < win &&
            (esc[i + 1] == 0x5E || esc[i + 1] == 0x5D)) {
            head[h++] = (uint8_t)(esc[i + 1] ^ 0x20);
            i++;
        } else {
            head[h++] = esc[i];
        }
    }
    p->opcode = head[0];
    p->inner = -1;
    p->log_code = -1;
    size_t base = 0;
    int eff = head[0];
    if (head[0] == PEEK_MULTI_RADIO_OP) {
        if (h <= PEEK_MULTI_RADIO_OFF)
            return -1;
        p->inner = head[PEEK_MULTI_RADIO_OFF];
        base = PEEK_MULTI_RADIO_OFF;
        eff = p->inner;
    }
    if (eff == PEEK_LOG_OP) {
        size_t o = base + PEEK_LOG_CODE_OFF;
        if (h < o + 2)
            return -1;
        p->log_code = head[o] | (head[o + 1] << 8);
    }
    return 0;
}

/* CRC-16/X.25 check of an ESCAPED frame (FCS = last two unescaped bytes, LE),
 * unescaping on the fly through a two-byte delay line — no frame copy. */
static int dframe_crc_ok(const uint8_t *esc, size_t n)
{
    uint16_t crc = 0xFFFF;
    uint8_t d0 = 0, d1 = 0;   /* the two most recent unescaped bytes */
    size_t got = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t b = esc[i];
        if (b == 0x7D && i + 1 < n && (esc[i + 1] == 0x5E || esc[i + 1] == 0x5D))
            b = (uint8_t)(esc[++i] ^ 0x20);
        if (got >= 2)
            crc = (uint16_t)((crc >> 8) ^ crc16_table[(crc ^ d0) & 0xFF]);
        d0 = d1;
        d1 = b;
        got++;
    }
    if (got < 3)
        return 0;
    return (uint16_t)(crc ^ 0xFFFF) == (uint16_t)(d0 | (d1 << 8));
}

struct dfilter {
    int active;                       /* 0 = no filter: full stream */
    int ncodes;
    uint16_t codes[SUB_MAX_CODES];    /* sorted, deduplicated */
    int nopcodes;
    uint8_t opcodes[SUB_MAX_OPCODES]; /* as declared */
    int f3, events;
    /* derived by dfilter_finalize(): */
    int all_logs;                     /* 0x10 declared as an opcode */
    uint8_t outer_bits[32];           /* declared opcodes, matched as outer op */
    uint8_t eff_bits[32];             /* declared - 0x10, + F3 set, + 0x60 */
};

#define BIT_SET(b, i) ((b)[(i) >> 3] |= (uint8_t)(1u << ((i) & 7)))
#define BIT_GET(b, i) (((b)[(i) >> 3] >> ((i) & 7)) & 1u)

static int cmp_u16(const void *a, const void *b)
{
    return (int)*(const uint16_t *)a - (int)*(const uint16_t *)b;
}

/* Sort + dedupe the code list and build the opcode bitsets. Same match rules
 * as framefilter.FrameFilter: f3 = {0x79, 0x99, 0x92}, events = 0x60, all
 * bare or 0x98-wrapped; an opcode matches as the outer OR the wrapped one. */
static void dfilter_finalize(struct dfilter *f)
{
    qsort(f->codes, (size_t)f->ncodes, sizeof f->codes[0], cmp_u16);
    int w = 0;
    for (int r = 0; r < f->ncodes; r++)
        if (w == 0 || f->codes[w - 1] != f->codes[r])
            f->codes[w++] = f->codes[r];
    f->ncodes = w;
    memset(f->outer_bits, 0, sizeof f->outer_bits);
    memset(f->eff_bits, 0, sizeof f->eff_bits);
    f->all_logs = 0;
    for (int i = 0; i < f->nopcodes; i++) {
        BIT_SET(f->outer_bits, f->opcodes[i]);
        if (f->opcodes[i] == PEEK_LOG_OP)
            f->all_logs = 1;
        else
            BIT_SET(f->eff_bits, f->opcodes[i]);
    }
    if (f->f3) {
        BIT_SET(f->eff_bits, 0x79);
        BIT_SET(f->eff_bits, 0x99);
        BIT_SET(f->eff_bits, 0x92);
    }
    if (f->events)
        BIT_SET(f->eff_bits, PEEK_EVENT_OP);
    f->active = 1;
}

static int dfilter_matches(const struct dfilter *f, const struct dpeek *p)
{
    if (!f->active)
        return 1;
    if (BIT_GET(f->outer_bits, p->opcode))
        return 1;
    int eff = p->inner >= 0 ? p->inner : p->opcode;
    if (eff == PEEK_LOG_OP) {
        if (f->all_logs)
            return 1;
        int lo = 0, hi = f->ncodes - 1;
        while (lo <= hi) {
            int mid = (lo + hi) / 2;
            if (f->codes[mid] == p->log_code) return 1;
            if (f->codes[mid] < p->log_code) lo = mid + 1; else hi = mid - 1;
        }
        return 0;
    }
    return (int)BIT_GET(f->eff_bits, eff);
}

/* --- SUB {json} parser ------------------------------------------------- */
/* Deliberately tiny: one object; keys "log_codes" / "opcodes" (arrays of JSON
 * integers — no hex strings) and "f3" / "events" (true/false). Unknown keys,
 * strings with escapes, floats, negatives and out-of-range values are errors:
 * a misspelt key must not silently widen or narrow what a client receives. */
struct jcur { const char *p, *end; };

static void j_ws(struct jcur *c)
{
    while (c->p < c->end && (*c->p == ' ' || *c->p == '\t' || *c->p == '\r' || *c->p == '\n'))
        c->p++;
}

static int j_lit(struct jcur *c, const char *lit)
{
    size_t n = strlen(lit);
    if ((size_t)(c->end - c->p) < n || memcmp(c->p, lit, n) != 0)
        return 0;
    c->p += n;
    return 1;
}

static int j_uint(struct jcur *c, unsigned long max, unsigned long *out)
{
    if (c->p >= c->end || *c->p < '0' || *c->p > '9')
        return -1;
    if (*c->p == '0' && c->p + 1 < c->end && c->p[1] >= '0' && c->p[1] <= '9')
        return -1;                        /* JSON forbids leading zeros */
    unsigned long v = 0;
    while (c->p < c->end && *c->p >= '0' && *c->p <= '9') {
        v = v * 10 + (unsigned long)(*c->p - '0');
        if (v > max)
            return -1;
        c->p++;
    }
    if (c->p < c->end && (*c->p == '.' || *c->p == 'e' || *c->p == 'E'))
        return -1;
    *out = v;
    return 0;
}

/* Parse "[int, ...]" into out (as uint16), at most cap entries. */
static int j_uint_array(struct jcur *c, unsigned long max, uint16_t *out, int cap,
                        int *n, const char **err)
{
    *n = 0;
    if (!j_lit(c, "[")) { *err = "expected array"; return -1; }
    j_ws(c);
    if (j_lit(c, "]")) return 0;
    for (;;) {
        unsigned long v;
        j_ws(c);
        if (j_uint(c, max, &v) < 0) { *err = "bad integer"; return -1; }
        if (*n >= cap) { *err = "too many entries"; return -1; }
        out[(*n)++] = (uint16_t)v;
        j_ws(c);
        if (j_lit(c, "]")) return 0;
        if (!j_lit(c, ",")) { *err = "expected , or ]"; return -1; }
    }
}

static int j_bool(struct jcur *c, int *out, const char **err)
{
    if (j_lit(c, "true")) { *out = 1; return 0; }
    if (j_lit(c, "false")) { *out = 0; return 0; }
    *err = "expected true/false";
    return -1;
}

/* Parse the JSON object of a SUB line into *f (finalized on success). On
 * failure returns -1, sets *err to a short reason and leaves *f untouched. */
static int parse_sub_json(const char *s, size_t n, struct dfilter *f, const char **err)
{
    struct dfilter t;
    memset(&t, 0, sizeof t);
    struct jcur c = { s, s + n };
    j_ws(&c);
    if (!j_lit(&c, "{")) { *err = "expected {"; return -1; }
    j_ws(&c);
    if (!j_lit(&c, "}")) {
        for (;;) {
            j_ws(&c);
            if (!j_lit(&c, "\"")) { *err = "expected key"; return -1; }
            const char *k = c.p;
            while (c.p < c.end && *c.p != '"' && *c.p != '\\') c.p++;
            if (c.p >= c.end || *c.p != '"') { *err = "bad key"; return -1; }
            size_t klen = (size_t)(c.p - k);
            c.p++;
            j_ws(&c);
            if (!j_lit(&c, ":")) { *err = "expected :"; return -1; }
            j_ws(&c);
            if (klen == 9 && !memcmp(k, "log_codes", 9)) {
                if (j_uint_array(&c, 0xFFFF, t.codes, SUB_MAX_CODES, &t.ncodes, err) < 0)
                    return -1;
            } else if (klen == 7 && !memcmp(k, "opcodes", 7)) {
                uint16_t ops[SUB_MAX_OPCODES];
                if (j_uint_array(&c, 0xFF, ops, SUB_MAX_OPCODES, &t.nopcodes, err) < 0)
                    return -1;
                for (int i = 0; i < t.nopcodes; i++) t.opcodes[i] = (uint8_t)ops[i];
            } else if (klen == 2 && !memcmp(k, "f3", 2)) {
                if (j_bool(&c, &t.f3, err) < 0) return -1;
            } else if (klen == 6 && !memcmp(k, "events", 6)) {
                if (j_bool(&c, &t.events, err) < 0) return -1;
            } else {
                *err = "unknown key";
                return -1;
            }
            j_ws(&c);
            if (j_lit(&c, "}")) break;
            if (!j_lit(&c, ",")) { *err = "expected , or }"; return -1; }
        }
    }
    j_ws(&c);
    if (c.p != c.end) { *err = "trailing data"; return -1; }
    dfilter_finalize(&t);
    *f = t;
    return 0;
}

/* Comma list of codes for --keep-log-code / --keep-opcode: decimal or 0x hex. */
static int parse_keep_list(const char *spec, unsigned long max, uint16_t *out,
                           int cap, int *n)
{
    const char *p = spec;
    if (!*p) return -1;
    while (*p) {
        char *endp;
        errno = 0;
        unsigned long v = strtoul(p, &endp, 0);
        if (endp == p || errno || v > max || *p == '-' || *p == '+') return -1;
        if (*n >= cap) return -1;
        out[(*n)++] = (uint16_t)v;
        p = endp;
        if (*p == ',') { p++; if (!*p) return -1; }
        else if (*p) return -1;
    }
    return 0;
}

/* --- per-TCP-client subscription state machine ------------------------- */
enum { CSUB_PENDING = 0, CSUB_FULL = 1, CSUB_FILTERED = 2 };

struct client_sub {
    int state;            /* PENDING: in the grace window, receives nothing */
    long accepted_ms;
    struct dfilter f;     /* valid in FILTERED */
    unsigned nsub;        /* SUB lines accepted (log on change) */
    size_t linelen;
    char line[SUB_LINE_MAX];
};

static void client_sub_init(struct client_sub *cs, int client_filters, long now)
{
    memset(cs, 0, sizeof *cs);
    cs->state = client_filters ? CSUB_PENDING : CSUB_FULL;
    cs->accepted_ms = now;
}

/* Grace window expired with no complete SUB line -> full stream (the
 * backwards-compatible path for diaggulp / kp / every existing receiver). */
static void client_sub_tick(struct client_sub *cs, long now, int grace_ms)
{
    if (cs->state == CSUB_PENDING && now - cs->accepted_ms >= grace_ms) {
        cs->state = CSUB_FULL;
        cs->linelen = 0;
    }
}

/* Feed bytes a TCP-listen client sent. Returns 0, or -1 with *err set when the
 * client must get "ERR <reason>\n" and be dropped. A SUB line is recognised as
 * the FIRST line (moving PENDING -> FILTERED); once FILTERED, a later SUB line
 * replaces the declaration. A first line that is not a SUB line selects the
 * full stream. FULL clients' input is ignored, exactly as before. */
static int client_sub_input(struct client_sub *cs, const uint8_t *data, size_t n,
                            const char **err)
{
    for (size_t i = 0; i < n; i++) {
        if (cs->state == CSUB_FULL)
            return 0;
        if (data[i] != '\n') {
            if (cs->linelen >= SUB_LINE_MAX) { *err = "line too long"; return -1; }
            cs->line[cs->linelen++] = (char)data[i];
            continue;
        }
        size_t len = cs->linelen;
        cs->linelen = 0;
        if (len > 0 && cs->line[len - 1] == '\r') len--;
        if (len >= 4 && !memcmp(cs->line, "SUB ", 4)) {
            if (parse_sub_json(cs->line + 4, len - 4, &cs->f, err) < 0)
                return -1;
            cs->state = CSUB_FILTERED;
            cs->nsub++;
        } else if (cs->state == CSUB_PENDING) {
            cs->state = CSUB_FULL;
        }
        /* FILTERED + a non-SUB line: ignored. */
    }
    return 0;
}

/* --- frame splitter over the pump's read chunks ------------------------ */
struct dsplit {
    size_t len;              /* carried partial frame */
    int discarding;          /* carry overflowed: skip to the next 0x7E */
    unsigned long overflows;
    uint8_t carry[SPLIT_CARRY_CAP];
};

struct dframe {
    const uint8_t *p;        /* into the chunk, or into dsplit.carry */
    uint32_t n;
    int8_t peeked;           /* 0 = not yet, 1 = ok, -1 = unclassifiable */
    int8_t crc;              /* 0 = not yet, 1 = good, -1 = bad */
    struct dpeek pk;
};

/* Split one read chunk into the complete escaped frames it ends (no 0x7E;
 * empty elements dropped, like FrameSplitter). The first frame may live in
 * s->carry, so call dsplit_commit() only AFTER the frames are consumed. */
static size_t dsplit_feed(struct dsplit *s, const uint8_t *chunk, size_t n,
                          struct dframe *out, size_t cap, size_t *tail_off,
                          int *had_delim)
{
    size_t nf = 0, off = 0;
    *had_delim = 0;
    const uint8_t *d = memchr(chunk, 0x7E, n);
    if (!d) { *tail_off = 0; return 0; }
    *had_delim = 1;
    /* first segment completes the carried frame */
    size_t seg = (size_t)(d - chunk);
    if (s->discarding) {
        s->discarding = 0;
        s->len = 0;
    } else if (s->len + seg > SPLIT_CARRY_CAP) {
        s->overflows++;
        s->len = 0;
    } else {
        memcpy(s->carry + s->len, chunk, seg);
        s->len += seg;
        if (s->len > 0 && nf < cap) {
            memset(&out[nf], 0, sizeof out[nf]);
            out[nf].p = s->carry;
            out[nf].n = (uint32_t)s->len;
            nf++;
        }
    }
    off = seg + 1;
    while (off < n) {
        d = memchr(chunk + off, 0x7E, n - off);
        if (!d) break;
        seg = (size_t)(d - (chunk + off));
        if (seg > 0 && nf < cap) {
            memset(&out[nf], 0, sizeof out[nf]);
            out[nf].p = chunk + off;
            out[nf].n = (uint32_t)seg;
            nf++;
        }
        off += seg + 1;
    }
    *tail_off = off;
    return nf;
}

static void dsplit_commit(struct dsplit *s, const uint8_t *chunk, size_t n,
                          size_t tail_off, int had_delim)
{
    if (had_delim)
        s->len = 0;
    size_t tail = n - tail_off;
    if (s->discarding)
        return;
    if (s->len + tail > SPLIT_CARRY_CAP) {
        s->overflows++;
        s->len = 0;
        s->discarding = 1;
        return;
    }
    memcpy(s->carry + s->len, chunk + tail_off, tail);
    s->len += tail;
}

static void dsplit_reset(struct dsplit *s)
{
    s->len = 0;
    s->discarding = 0;
}

/* Render the frames a filter wants as 0x7E + escaped + 0x7E units into out
 * (capacity FILT_OUT_CAP). Peek and CRC are computed at most once per frame
 * and cached in the dframe, however many sinks look at it. */
static size_t dfilter_render(const struct dfilter *f, struct dframe *fr, size_t nf,
                             uint8_t *out)
{
    size_t o = 0;
    for (size_t i = 0; i < nf; i++) {
        struct dframe *x = &fr[i];
        if (!x->peeked)
            x->peeked = dpeek_frame(x->p, x->n, &x->pk) == 0 ? 1 : -1;
        if (x->peeked < 0 || !dfilter_matches(f, &x->pk))
            continue;
        if (!x->crc)
            x->crc = dframe_crc_ok(x->p, x->n) ? 1 : -1;
        if (x->crc < 0)
            continue;
        out[o++] = 0x7E;
        memcpy(out + o, x->p, x->n);
        o += x->n;
        out[o++] = 0x7E;
    }
    return o;
}

/* DGE1-send a buffer of 0x7E-delimited units with datagrams cut only between
 * units (frame-aligned), except a single unit longer than one datagram, which
 * is split. Unit boundaries are exactly the "7E 7E" pairs (an escaped frame
 * never contains 0x7E). */
static void udp_send_frames(struct udp_sink *s, const uint8_t *buf, size_t len,
                            int restart)
{
    size_t off = 0;
    while (off < len) {
        size_t lim = len - off <= DGE_MAX_PAYLOAD ? len : off + DGE_MAX_PAYLOAD;
        size_t cut = lim;
        if (lim < len) {
            cut = 0;
            for (size_t i = lim; i > off + 1; i--)
                if (buf[i - 1] == 0x7E && buf[i] == 0x7E) { cut = i; break; }
            if (!cut) cut = lim;     /* one oversized unit: split it */
        }
        udp_send_chunk(s, buf + off, cut - off, restart);
        restart = 0;
        off = cut;
    }
}


/* Remove closed (-1) slots from clients[0..n), preserving the survivors'
 * order, and clear the freed tail. Returns the survivor count. Used by the
 * fan-out loop so client removal is a tombstone-then-compact pass rather than
 * a swap-during-iterate (which desynced the poll-slot map — the live-USB
 * crash: a client accepted mid-cycle was drained against an uninitialized
 * pfds index). subs[] (nullable) is the parallel per-client subscription
 * state and moves with its client. Pure/testable: no fd side effects. */
static int compact_clients(int *clients, struct client_sub *subs, int n)
{
    int w = 0;
    for (int r = 0; r < n; r++) {
        if (clients[r] < 0)
            continue;
        if (w != r) {
            clients[w] = clients[r];
            if (subs)
                subs[w] = subs[r];
        }
        w++;
    }
    for (int i = w; i < n; i++)
        clients[i] = -1;
    return w;
}

/* Everything one source read is fanned out to. */
struct fanout {
    int *clients;
    struct client_sub *subs;
    int nclients;                       /* entries of clients[] to visit */
    struct tcp_out *dial;
    struct udp_sink *bcast, *unicast;
    const struct dfilter *keep_bcast, *keep_unicast, *keep_dial;
    int splitting;                      /* any filter configured: run the splitter */
    struct dsplit *split;
    struct dframe *frames;              /* SPLIT_MAX_FRAMES entries */
    uint8_t *out;                       /* FILT_OUT_CAP bytes */
    int restart_pending[2];             /* filtered bcast / unicast owe a RESTART */
};

static void fanout_udp(struct fanout *fo, struct udp_sink *s, const struct dfilter *k,
                       int slot, struct dframe *fr, size_t nf, const uint8_t *chunk,
                       size_t n, int restart)
{
    if (!s->enabled)
        return;
    if (!k->active) {
        udp_send_chunk(s, chunk, n, restart);
        return;
    }
    size_t len = dfilter_render(k, fr, nf, fo->out);
    if (!len) {
        fo->restart_pending[slot] |= restart;
        return;
    }
    udp_send_frames(s, fo->out, len, restart | fo->restart_pending[slot]);
    fo->restart_pending[slot] = 0;
}

/* Fan one source read out to every sink. Unfiltered sinks get the raw chunk,
 * byte-identical to the unfiltered pump; filtered sinks get their rendered
 * frames; PENDING clients (inside the SUB grace window) get nothing. A client
 * whose write fails hard is closed and tombstoned (-1) — the caller compacts. */
static void fanout_chunk(struct fanout *fo, const uint8_t *chunk, size_t n, int restart)
{
    size_t nf = 0, tail_off = 0;
    int had_delim = 0;
    if (fo->splitting)
        nf = dsplit_feed(fo->split, chunk, n, fo->frames, SPLIT_MAX_FRAMES,
                         &tail_off, &had_delim);
    for (int i = 0; i < fo->nclients; i++) {
        int c = fo->clients[i];
        struct client_sub *cs = &fo->subs[i];
        if (c < 0 || cs->state == CSUB_PENDING)
            continue;
        const uint8_t *p = chunk;
        size_t len = n;
        if (cs->state == CSUB_FILTERED) {
            len = dfilter_render(&cs->f, fo->frames, nf, fo->out);
            p = fo->out;
            if (!len)
                continue;
        }
        ssize_t w = write(c, p, len);
        if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            close(c);
            fo->clients[i] = -1;
        }
    }
    if (fo->dial && fo->dial->fd >= 0) {
        const uint8_t *p = chunk;
        size_t len = n;
        if (fo->keep_dial->active) {
            len = dfilter_render(fo->keep_dial, fo->frames, nf, fo->out);
            p = fo->out;
        }
        if (len) {
            ssize_t w = write(fo->dial->fd, p, len);
            if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                close(fo->dial->fd);
                fo->dial->fd = -1;
                fo->dial->next_retry_ms = now_ms() + 5000;
                logmsg("tcp-dial dropped");
            }
        }
    }
    fanout_udp(fo, fo->bcast, fo->keep_bcast, 0, fo->frames, nf, chunk, n, restart);
    fanout_udp(fo, fo->unicast, fo->keep_unicast, 1, fo->frames, nf, chunk, n, restart);
    if (fo->splitting)
        dsplit_commit(fo->split, chunk, n, tail_off, had_delim);
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
 * unrelated and were once conflated (the only embedded "version" was
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
"Usage: %s [options]   (multi-protocol on-device DIAG egress)\n"
"\n"
"  --tcp-listen [ADDR:]PORT   TCP listener (host dials in, raw HDLC).\n"
"                             Default 0.0.0.0:%d (ON).\n"
"  --no-tcp-listen            Disable the TCP listener.\n"
"  --udp-broadcast SPEC       UDP broadcast. SPEC = IFACE | IFACE:PORT |\n"
"                             BCAST:PORT. Default %s:%d (ON).\n"
"  --no-udp-broadcast         Disable UDP broadcast.\n"
"  --udp-unicast HOST:PORT    Directed UDP datagrams (off by default).\n"
"  --tcp-dial HOST:PORT       Back-compat dial-out, raw HDLC (off by default).\n"
"  --mask max|gnss|none       Log mask mode. max = every log code\n"
"                             (default). gnss = only the GNSS preset codes\n"
"                             (presets_gnss.h), F3/events/QSH left disarmed.\n"
"                             none = arm nothing; another owner set the mask.\n"
"  --ext-msg-f3               Also enable the F3 ext-msg debug stream.\n"
"  --ext-msg-f3-mute SS[-SS][,...]\n"
"                             With --ext-msg-f3: force these F3 ss_ids back to\n"
"                             level 0 after arming (e.g. 47 = MDM9150 GNSS\n"
"                             correlator prints, ~half the firehose).\n"
"  --qsh-trace                Also arm the QSH-trace 0x9D stream (0x9001 maskset).\n"
"  --log-types L[,L...]       Arm these log types FIRST (e.g. 11 = C-V2X sidelink\n"
"                             0xB2xx), so a busy type's flood can't bury their\n"
"                             SET_MASK response. Default: all ascending.\n"
"  --only                     With --log-types: arm ONLY those types, nothing else.\n"
"  --internal-port PORT       Loopback port for the captive diag_socket_log\n"
"                             (default %d).\n"
"  --retry N                  diag_socket_log connect retries (default %d).\n"
"  --diag-socket-log PATH     Path/name of the OEM binary (default in PATH).\n"
"  --source MODE              DIAG source: socket-log (default, captive OEM\n"
"                             diag_socket_log) | diag-dev (native kernel /dev/diag,\n"
"                             zero-dependency; SDX55 M2000) | hdlc-chardev (host-side\n"
"                             jump box: serial-like CRC-HDLC DIAG chardev) |\n"
"                             usbfs (RIS-9260 MDM9150: claims DIAG interface 4 over\n"
"                             usbfs 05c6:90f0, no chardev needed; auto-finds device) |\n"
"                             stdin (read an ALREADY-ARMED raw-HDLC stream from fd 0\n"
"                             and fan out only — do NOT arm; e.g. CARCOM-G1:\n"
"                             diaggulp ... -o - | diagbarf --source stdin --udp-unicast H:P).\n"
"  --diag-dev PATH            Device node for --source diag-dev (kernel diag node,\n"
"                             default /dev/diag) OR --source hdlc-chardev (the DIAG\n"
"                             chardev, e.g. /dev/mhi_DIAG or /dev/ttyUSB2).\n"
"  --cmd-listen [ADDR:]PORT   OPT-IN DIAG command passthrough (OFF by\n"
"                             default). ONE client sends HDLC request frames that\n"
"                             are forwarded to the modem, and receives ONLY the\n"
"                             replies (not the firehose). A bare PORT binds\n"
"                             127.0.0.1 (reach it over ssh -L). Allow-list: EFS2\n"
"                             0x4B/0x13 + 0x4B/0x3E, NV read/write 0x26/0x27, and\n"
"                             0x00/0x0C/0x7C; everything else (mask config 0x73/\n"
"                             0x7D/0x60/0x82, CONTROL 0x29, FTM, ...) is refused.\n"
"                             One log line per request. Not with --source stdin.\n"
"  --cmd-allow OP[/SUB[/CMD]][,...]\n"
"                             With --cmd-listen: EXTEND the allow-list with these\n"
"                             request opcodes (e.g. a vendor log tool's handshake:\n"
"                             --cmd-allow 0x9f,0x01,0x4b/0x12/0x218,0x4b/0x12/0x833).\n"
"                             OP/SUB match p[0]/p[1]; CMD a u16-LE cmd code. Hex or\n"
"                             decimal. Replies to these opcodes also route back.\n"
"                             SAFETY: no un-overridable floor — allowing a state-\n"
"                             changing opcode (e.g. 0x29) is your explicit choice,\n"
"                             and every rule is logged at startup.\n"
"  --cmd-block OP[/SUB[/CMD]][,...]\n"
"                             With --cmd-listen: REFUSE these (block wins over both\n"
"                             the default allow-list and --cmd-allow). Tighten-only.\n"
"  --client-filters           OPT-IN per-client subscriptions (OFF by\n"
"                             default). A TCP-listen client's first line, sent\n"
"                             within the grace window, may be\n"
"                             SUB {\"log_codes\":[5238],\"opcodes\":[],\"f3\":false,\"events\":false}\n"
"                             -> it receives only those frames (bare + 0x98-\n"
"                             wrapped), byte-exact. No SUB -> full stream. Bad SUB\n"
"                             -> ERR <reason> and the client is dropped. Delivery\n"
"                             only: the modem mask is unchanged.\n"
"  --sub-grace-ms MS          SUB grace window (default %d). A client receives\n"
"                             nothing while its window is open.\n"
"  --keep-log-code LIST       Per-destination filter for the IMMEDIATELY preceding\n"
"  --keep-opcode LIST         --udp-unicast / --udp-broadcast / --tcp-dial (no\n"
"  --keep-f3                  back-channel for a SUB line). LIST = comma-separated\n"
"  --keep-events              decimal or 0x hex. Filtered DGE1 is frame-aligned.\n"
"  --plane-b-udp [ADDR:]PORT  Plane B: stream RSU daemon logs as BMX1 tagged\n"
"                             records over UDP (RIS-9260). Conventional\n"
"                             port %d. Independent of the DIAG sinks; a single\n"
"                             eth1 pcap captures both planes.\n"
"  --plane-b-log NAME=PATH    Register a daemon-log file to tail for Plane B\n"
"                             (repeatable, max %d). e.g. cv2x=/var/log/cv2x.log.\n"
"  -V, --version              Print version (build version + date + DGE proto).\n"
"  -h, --help                 This help.\n"
"\n"
"Address syntax (all sinks except --udp-broadcast, which is IPv4-only):\n"
"  IPv4     A.B.C.D:PORT           e.g. 192.168.7.2:12400\n"
"  IPv6     [ADDR]:PORT            e.g. [2001:db8::5]:12400  (brackets required)\n"
"  IPv6 LL  [ADDR%%ZONE]:PORT       e.g. [fe80::1%%eth1]:12400 (RIS-9260 eth1 is\n"
"                                  link-local; the %%ZONE scope is mandatory).\n"
"  Numeric only (no DNS): the binary is -static and carries no resolver.\n"
"\n"
"UDP sinks are DGE1 seq-framed (host side: diaggulp --transport udp-listen).\n"
"TCP sinks are raw HDLC (host side: diaggulp --transport tcp-connect --no-mask).\n",
        argv0, DEFAULT_PUBLIC_PORT, DEFAULT_BCAST_IFACE, DEFAULT_PUBLIC_PORT,
        DEFAULT_INTERNAL_PORT, DEFAULT_RETRY, SUB_GRACE_MS_DEFAULT,
        DEFAULT_MUX_PORT, MAX_LOG_SRC);
}

/* ----------------------------------------------------------------------- */
/* main                                                                    */
/* ----------------------------------------------------------------------- */

/* DIAGBARF_BRIDGE_TEST keeps the diag-dev bridge thread (above) compiled but
 * swaps out main() so tests/test_diagdev_teardown.c can drive diagdev_bridge
 * directly (the SIGTERM-wedge regression test). */
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
    {
        char pbuf[16];
        snprintf(pbuf, sizeof pbuf, "%d", DEFAULT_PUBLIC_PORT);
        parse_hostport(pbuf, &cfg.tcp_listen_addr, &cfg.tcp_listen_len, AF_INET);
    }
    cfg.udp_bcast_enabled = 1;
    snprintf(cfg.bcast_iface, IFNAMSIZ, "%s", DEFAULT_BCAST_IFACE);
    cfg.bcast_iface_resolve = 1;
    cfg.bcast_port = DEFAULT_PUBLIC_PORT;
    cfg.internal_port = DEFAULT_INTERNAL_PORT;
    cfg.retry = DEFAULT_RETRY;
    cfg.mask_mode = MASK_MAX;
    cfg.sub_grace_ms = SUB_GRACE_MS_DEFAULT;
    cfg.diag_socket_log = "diag_socket_log";
    cfg.source = "socket-log";
    cfg.diag_dev = "/dev/diag";

    /* --keep-*: per-destination filters for the sinks with no
     * back-channel. They bind to the IMMEDIATELY preceding destination flag
     * (or keep-flag chain); keep_dest is reset by every other flag. */
    static struct dfilter keep_bcast, keep_unicast, keep_dial;
    struct dfilter *keep_dest = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        struct dfilter *keep_prev = keep_dest;
        keep_dest = NULL;
        if (!strncmp(a, "--keep-", 7) && !keep_prev) {
            logmsg("%s must follow --udp-unicast, --udp-broadcast or --tcp-dial "
                   "(TCP-listen clients declare a SUB line instead)", a);
            return 2;
        }
        if (!strcmp(a, "--keep-log-code") && i + 1 < argc) {
            if (parse_keep_list(argv[++i], 0xFFFF, keep_prev->codes, SUB_MAX_CODES,
                                &keep_prev->ncodes) < 0) {
                logmsg("bad --keep-log-code %s", argv[i]); return 2;
            }
            keep_prev->active = 1;
            keep_dest = keep_prev;
        } else if (!strcmp(a, "--keep-opcode") && i + 1 < argc) {
            uint16_t ops[SUB_MAX_OPCODES];
            int nops = 0;
            if (parse_keep_list(argv[++i], 0xFF, ops, SUB_MAX_OPCODES - keep_prev->nopcodes,
                                &nops) < 0) {
                logmsg("bad --keep-opcode %s", argv[i]); return 2;
            }
            for (int k = 0; k < nops; k++)
                keep_prev->opcodes[keep_prev->nopcodes++] = (uint8_t)ops[k];
            keep_prev->active = 1;
            keep_dest = keep_prev;
        } else if (!strcmp(a, "--keep-f3")) {
            keep_prev->f3 = 1;
            keep_prev->active = 1;
            keep_dest = keep_prev;
        } else if (!strcmp(a, "--keep-events")) {
            keep_prev->events = 1;
            keep_prev->active = 1;
            keep_dest = keep_prev;
        } else if (!strcmp(a, "--client-filters")) {
            cfg.client_filters = 1;
        } else if (!strcmp(a, "--sub-grace-ms") && i + 1 < argc) {
            char *endp;
            long g = strtol(argv[++i], &endp, 10);
            if (*endp || g < 0 || g > 60000) {
                logmsg("bad --sub-grace-ms %s (0..60000)", argv[i]); return 2;
            }
            cfg.sub_grace_ms = (int)g;
        } else if (!strcmp(a, "--no-tcp-listen")) {
            cfg.tcp_listen_enabled = 0;
        } else if (!strcmp(a, "--tcp-listen") && i + 1 < argc) {
            cfg.tcp_listen_enabled = 1;
            if (parse_hostport(argv[++i], &cfg.tcp_listen_addr,
                               &cfg.tcp_listen_len, AF_INET) < 0) {
                logmsg("bad --tcp-listen %s", argv[i]); return 2;
            }
        } else if (!strcmp(a, "--no-udp-broadcast")) {
            cfg.udp_bcast_enabled = 0;
        } else if (!strcmp(a, "--udp-broadcast") && i + 1 < argc) {
            cfg.udp_bcast_enabled = 1;
            keep_dest = &keep_bcast;
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
            keep_dest = &keep_unicast;
            if (parse_hostport(argv[++i], &cfg.udp_unicast_addr,
                               &cfg.udp_unicast_len, AF_INET) < 0) {
                logmsg("bad --udp-unicast %s", argv[i]); return 2;
            }
        } else if (!strcmp(a, "--tcp-dial") && i + 1 < argc) {
            cfg.tcp_dial_enabled = 1;
            keep_dest = &keep_dial;
            if (parse_hostport(argv[++i], &cfg.tcp_dial_addr,
                               &cfg.tcp_dial_len, AF_INET) < 0) {
                logmsg("bad --tcp-dial %s", argv[i]); return 2;
            }
        } else if (!strcmp(a, "--cmd-listen") && i + 1 < argc) {
            cfg.cmd_listen_enabled = 1;
            if (parse_cmd_listen(argv[++i], &cfg.cmd_listen_addr,
                                 &cfg.cmd_listen_len) < 0) {
                logmsg("bad --cmd-listen %s", argv[i]); return 2;
            }
        } else if (!strcmp(a, "--cmd-allow") && i + 1 < argc) {
            if (cmd_rules_parse(argv[++i], g_cmd_allow_extra,
                                &g_n_cmd_allow_extra) < 0) {
                logmsg("bad --cmd-allow %s (expected OP[/SUB[/CMD]][,…], "
                       "max %d rules)", argv[i], CMD_RULE_MAX); return 2;
            }
        } else if (!strcmp(a, "--cmd-block") && i + 1 < argc) {
            if (cmd_rules_parse(argv[++i], g_cmd_block, &g_n_cmd_block) < 0) {
                logmsg("bad --cmd-block %s (expected OP[/SUB[/CMD]][,…], "
                       "max %d rules)", argv[i], CMD_RULE_MAX); return 2;
            }
        } else if (!strcmp(a, "--mask") && i + 1 < argc) {
            i++;
            cfg.mask_mode = parse_mask_mode(argv[i]);
            if (cfg.mask_mode < 0) {
                logmsg("bad --mask %s (expected max | gnss | none)", argv[i]);
                return 2;
            }
        } else if (!strcmp(a, "--ext-msg-f3")) {
            cfg.ext_msg_f3 = 1;
        } else if (!strcmp(a, "--ext-msg-f3-mute") && i + 1 < argc) {
            int n = parse_ssid_ranges(argv[++i], cfg.f3_mute_first,
                                      cfg.f3_mute_last, MAX_F3_MUTE);
            if (n < 0) {
                logmsg("bad --ext-msg-f3-mute '%s' (SS[-SS][,...], ss_id 0..65535, "
                       "<= %d ranges of <= %d)", argv[i], MAX_F3_MUTE, F3_MUTE_SPAN);
                usage(argv[0]); return 2;
            }
            cfg.nf3_mute = n;
        } else if (!strcmp(a, "--qsh-trace")) {
            cfg.qsh_trace = 1;
        } else if (!strcmp(a, "--log-types") && i + 1 < argc) {
            /* comma list of log types armed FIRST, e.g. 11 = C-V2X SL */
            char *list = argv[++i];
            cfg.nlog_types = 0;
            for (char *tok = strtok(list, ","); tok; tok = strtok(NULL, ",")) {
                char *end = NULL;
                long lt = strtol(tok, &end, 0);
                if (end == tok || *end || lt < 0 || lt >= NUM_LOG_TYPES) {
                    logmsg("bad --log-types entry '%s' (expected 0..%d)",
                           tok, NUM_LOG_TYPES - 1);
                    usage(argv[0]); return 2;
                }
                if (cfg.nlog_types < NUM_LOG_TYPES)
                    cfg.log_types[cfg.nlog_types++] = (int)lt;
            }
        } else if (!strcmp(a, "--only")) {
            cfg.only = 1;
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
        } else if (!strcmp(a, "--plane-b-udp") && i + 1 < argc) {
            cfg.planeb_enabled = 1;
            if (parse_hostport(argv[++i], &cfg.planeb_dest,
                               &cfg.planeb_destlen, AF_INET) < 0) {
                logmsg("bad --plane-b-udp %s", argv[i]); return 2;
            }
        } else if (!strcmp(a, "--plane-b-log") && i + 1 < argc) {
            if (cfg.planeb_nlogs >= MAX_LOG_SRC) {
                logmsg("too many --plane-b-log (max %d)", MAX_LOG_SRC); return 2;
            }
            cfg.planeb_logs[cfg.planeb_nlogs++] = argv[++i];
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            print_version(); return 0;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(argv[0]); return 0;
        } else {
            logmsg("unknown/incomplete argument: %s", a);
            usage(argv[0]); return 2;
        }
    }

    if (!source_is_valid(cfg.source)) {
        logmsg("unknown --source '%s' (expected socket-log | diag-dev | "
               "hdlc-chardev | usbfs | stdin)", cfg.source);
        return 2;
    }

    if (cfg.cmd_listen_enabled && !source_accepts_commands(cfg.source)) {
        logmsg("--cmd-listen needs a source with a path back to the modem; "
               "--source %s has none", cfg.source);
        return 2;
    }

    if (cfg.only && cfg.nlog_types == 0) {
        logmsg("--only needs --log-types");
        usage(argv[0]); return 2;
    }
    if (cfg.nf3_mute > 0 && !cfg.ext_msg_f3) {
        logmsg("--ext-msg-f3-mute needs --ext-msg-f3");
        usage(argv[0]); return 2;
    }
    /* --mask gnss / none hand the rest of the mask to someone else: gnss keeps
     * F3/events/QSH disarmed by design, none arms nothing. A flag that arms
     * more would silently contradict that, so refuse it. */
    if (cfg.mask_mode != MASK_MAX &&
        (cfg.ext_msg_f3 || cfg.qsh_trace || cfg.nlog_types)) {
        logmsg("--mask %s cannot be combined with --ext-msg-f3, --qsh-trace "
               "or --log-types", cfg.mask_mode == MASK_GNSS ? "gnss" : "none");
        usage(argv[0]); return 2;
    }

    if (keep_bcast.active) dfilter_finalize(&keep_bcast);
    if (keep_unicast.active) dfilter_finalize(&keep_unicast);
    if (keep_dial.active) dfilter_finalize(&keep_dial);
    if (cfg.client_filters && !cfg.tcp_listen_enabled)
        logmsg("warning: --client-filters has no effect without --tcp-listen");

    if (!cfg.tcp_listen_enabled && !cfg.udp_bcast_enabled &&
        !cfg.udp_unicast_enabled && !cfg.tcp_dial_enabled) {
        logmsg("no sinks enabled — nothing to do");
        return 2;
    }

    /* Emit the build version once at startup so journald answers "what's
     * running?" without a flag or an on-device binary hash. */
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
        /* broadcast stays v4: copy the sockaddr_in into the storage dest. */
        memcpy(&bcast.dest, &cfg.udp_bcast_addr, sizeof cfg.udp_bcast_addr);
        bcast.destlen = sizeof(struct sockaddr_in);
        bcast.enabled = 1;
        char ip[80];
        sa_ntop(&bcast.dest, ip, sizeof ip);
        logmsg("sink: UDP broadcast -> %s", ip);
    }
    if (cfg.udp_unicast_enabled) {
        unicast.fd = socket(cfg.udp_unicast_addr.ss_family, SOCK_DGRAM, 0);
        if (unicast.fd < 0) { logmsg("udp unicast socket: %s", strerror(errno)); return 1; }
        unicast.dest = cfg.udp_unicast_addr;
        unicast.destlen = cfg.udp_unicast_len;
        unicast.enabled = 1;
        char ip[80];
        sa_ntop(&unicast.dest, ip, sizeof ip);
        logmsg("sink: UDP unicast -> %s", ip);
    }

    /* --- Set up the TCP listener --- */
    int listen_fd = -1;
    if (cfg.tcp_listen_enabled) {
        listen_fd = socket(cfg.tcp_listen_addr.ss_family, SOCK_STREAM, 0);
        if (listen_fd < 0) { logmsg("tcp listen socket: %s", strerror(errno)); return 1; }
        int on = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
        if (bind(listen_fd, (struct sockaddr *)&cfg.tcp_listen_addr,
                 cfg.tcp_listen_len) < 0) {
            logmsg("tcp listen bind: %s", strerror(errno)); return 1;
        }
        if (listen(listen_fd, 8) < 0) { logmsg("listen: %s", strerror(errno)); return 1; }
        set_nonblock(listen_fd);
        char ip[80];
        sa_ntop(&cfg.tcp_listen_addr, ip, sizeof ip);
        logmsg("sink: TCP listener on %s", ip);
    }

    /* --- TCP dial-out (back-compat) --- */
    struct tcp_out dial = {0};
    dial.fd = -1;                  /* -1 even when disabled: write gates check fd>=0 */
    if (cfg.tcp_dial_enabled) {
        dial.enabled = 1;
        dial.fd = -1;
        dial.dest = cfg.tcp_dial_addr;
        dial.destlen = cfg.tcp_dial_len;
        dial.next_retry_ms = 0;     /* connect on first loop pass */
        char ip[80];
        sa_ntop(&dial.dest, ip, sizeof ip);
        logmsg("sink: TCP dial-out -> %s (back-compat)", ip);
    }

    int clients[MAX_CLIENTS];
    int nclients = 0;
    for (int i = 0; i < MAX_CLIENTS; i++) clients[i] = -1;

    /* --- Per-client subscriptions / per-destination filters --- */
    /* Off unless --client-filters or a --keep-* flag is given; then every
     * read is also split into frames (peek + CRC only for filtered sinks). */
    static struct client_sub subs[MAX_CLIENTS];
    static struct dsplit split;
    static struct dframe frames[SPLIT_MAX_FRAMES];
    static uint8_t filt_out[FILT_OUT_CAP];
    struct fanout fo;
    memset(&fo, 0, sizeof fo);
    fo.clients = clients;
    fo.subs = subs;
    fo.keep_bcast = &keep_bcast;
    fo.keep_unicast = &keep_unicast;
    fo.keep_dial = &keep_dial;
    fo.splitting = cfg.client_filters || keep_bcast.active ||
                   keep_unicast.active || keep_dial.active;
    fo.split = &split;
    fo.frames = frames;
    fo.out = filt_out;
    if (cfg.client_filters)
        logmsg("client-filters: ON (a TCP client's first line may be SUB {json} "
               "within %d ms; otherwise full stream)", cfg.sub_grace_ms);
    {
        const struct dfilter *ks[3] = { &keep_bcast, &keep_unicast, &keep_dial };
        const char *kn[3] = { "udp-broadcast", "udp-unicast", "tcp-dial" };
        for (int k = 0; k < 3; k++)
            if (ks[k]->active)
                logmsg("filter: %s keeps %d log code(s), %d opcode(s), f3=%d events=%d",
                       kn[k], ks[k]->ncodes, ks[k]->nopcodes, ks[k]->f3, ks[k]->events);
    }

    /* --- OPT-IN DIAG command passthrough --- */
    /* One listener, one client at a time. Set up BEFORE any source starts so
     * g_cmd_passthrough is visible to the usbfs bridge thread's wire gate. */
    int cmd_listen_fd = -1;
    int cmd_client = -1;
    static struct cmd_rx cmd_rx;
    static struct cmd_router cmd_rt;
    struct cmd_stats cmd_st;
    memset(&cmd_st, 0, sizeof cmd_st);
    cmd_rx_reset(&cmd_rx);
    cmd_router_reset(&cmd_rt);
    if (cfg.cmd_listen_enabled) {
        cmd_listen_fd = socket(cfg.cmd_listen_addr.ss_family, SOCK_STREAM, 0);
        if (cmd_listen_fd < 0) { logmsg("cmd listen socket: %s", strerror(errno)); return 1; }
        int on = 1;
        setsockopt(cmd_listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
        if (bind(cmd_listen_fd, (struct sockaddr *)&cfg.cmd_listen_addr,
                 cfg.cmd_listen_len) < 0) {
            logmsg("cmd listen bind: %s", strerror(errno)); return 1;
        }
        if (listen(cmd_listen_fd, 1) < 0) { logmsg("cmd listen: %s", strerror(errno)); return 1; }
        set_nonblock(cmd_listen_fd);
        g_cmd_passthrough = 1;
        char ip[80];
        sa_ntop(&cfg.cmd_listen_addr, ip, sizeof ip);
        logmsg("cmd-listen: DIAG command passthrough ON at %s (one client; "
               "allow-list: EFS2 0x4B/0x13+0x3E, NV 0x26/0x27, 0x00/0x0C/0x7C; "
               "all else refused)", ip);
        /* Audit trail: print every operator-supplied extra rule so the widened
         * (or narrowed) policy is visible in the journal, not just in argv. */
        for (int r = 0; r < g_n_cmd_allow_extra; r++) {
            const struct cmd_rule *cr = &g_cmd_allow_extra[r];
            if (cr->has_cmd)
                logmsg("cmd-listen: --cmd-allow 0x%02x/0x%02x/0x%04x", cr->op, cr->sub, cr->cmd);
            else if (cr->has_sub)
                logmsg("cmd-listen: --cmd-allow 0x%02x/0x%02x", cr->op, cr->sub);
            else
                logmsg("cmd-listen: --cmd-allow 0x%02x (ALL payloads)", cr->op);
        }
        for (int r = 0; r < g_n_cmd_block; r++) {
            const struct cmd_rule *cr = &g_cmd_block[r];
            if (cr->has_cmd)
                logmsg("cmd-listen: --cmd-block 0x%02x/0x%02x/0x%04x", cr->op, cr->sub, cr->cmd);
            else if (cr->has_sub)
                logmsg("cmd-listen: --cmd-block 0x%02x/0x%02x", cr->op, cr->sub);
            else
                logmsg("cmd-listen: --cmd-block 0x%02x (ALL payloads)", cr->op);
        }
    } else if (g_n_cmd_allow_extra || g_n_cmd_block) {
        logmsg("--cmd-allow/--cmd-block need --cmd-listen (the passthrough gate "
               "they tune is off without it)");
        return 2;
    }

    /* --- Plane B: RSU daemon-log multiplexer --- */
    /* Started once, runs alongside the DIAG fan-out for the whole session and
     * survives DIAG source re-spawns. Strictly additive: a Plane B setup
     * failure logs and leaves Plane A running. */
    pthread_t planeb_tid = 0;
    struct planeb_ctx *planeb = NULL;
    if (cfg.planeb_enabled) {
        if (start_planeb(&cfg.planeb_dest, cfg.planeb_destlen,
                         cfg.planeb_logs, cfg.planeb_nlogs,
                         &planeb_tid, &planeb) < 0) {
            planeb_tid = 0;
            logmsg("plane-b: disabled (setup failed) — Plane A continues");
        }
    }

    /* ===================================================================== */
    /* Outer loop: (re)spawn the captive diag_socket_log, arm the mask, pump */
    /* ===================================================================== */
    while (!g_stop) {
        int src = -1;
        pid_t child = -1;
        pthread_t bridge_tid = 0;
        int using_diag_dev = (strcmp(cfg.source, "diag-dev") == 0);
        int using_chardev  = (strcmp(cfg.source, "hdlc-chardev") == 0);
        int using_usbfs    = (strcmp(cfg.source, "usbfs") == 0);
        int using_stdin    = (strcmp(cfg.source, "stdin") == 0);

        if (using_stdin) {
            /* Read an ALREADY-ARMED raw-HDLC stream from fd 0 (diaggulp on
             * the ST pipes it in) and fan it out to the sinks. No captive
             * diag_socket_log, no chardev, no arming — diaggulp owns the modem
             * link and the mask handshake. EOF on stdin = diaggulp exited, so
             * the pump stops and the outer loop breaks (no re-spawn). */
            src = STDIN_FILENO;
            logmsg("stdin source ready: fanning out pre-armed HDLC from fd 0");
        } else if (using_chardev) {
            src = start_hdlc_chardev_source(cfg.diag_dev);
            if (src < 0) { if (g_stop) break; sleep(5); continue; }
            logmsg("hdlc-chardev source ready: %s (src fd %d)", cfg.diag_dev, src);
        } else if (using_usbfs) {
            src = start_usbfs_source(&bridge_tid);
            if (src < 0) { if (g_stop) break; sleep(5); continue; }
            logmsg("usbfs source ready (src fd %d)", src);
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

        /* Arm the global log mask (non-fatal on failure) — unless the source is
         * a pre-armed passthrough (stdin), where diaggulp already armed and the
         * one-way pipe has no back-channel to arm over. */
        struct rxbuf rx;
        rx.len = 0;
        if (source_should_arm(cfg.source) && cfg.mask_mode == MASK_NONE) {
            logmsg("--mask none: not arming; fanning out whatever the mask owner armed");
        } else if (source_should_arm(cfg.source)) {
            int gnss = (cfg.mask_mode == MASK_GNSS);
            if (arm_mask(src, &rx, cfg.ext_msg_f3, cfg.qsh_trace,
                         cfg.log_types, cfg.nlog_types, cfg.only,
                         cfg.f3_mute_first, cfg.f3_mute_last, cfg.nf3_mute,
                         gnss ? DIAGBARF_PRESET_GNSS : NULL,
                         gnss ? DIAGBARF_PRESET_GNSS_N : 0) < 0)
                logmsg("warning: mask handshake failed — fanning out whatever flows");
        } else {
            logmsg("source=stdin: passthrough — not arming (pre-armed upstream)");
        }

        /* Flush any bytes left in the handshake buffer to the sinks, then
         * switch to the raw byte pump for the rest of the stream. */
        int restart = 1;
        dsplit_reset(&split);           /* a new source may begin mid-frame */
        fo.dial = &dial;
        fo.bcast = &bcast;
        fo.unicast = &unicast;
        if (rx.len > 0) {
            fo.nclients = nclients;
            fanout_chunk(&fo, rx.buf, rx.len, restart);
            nclients = compact_clients(clients, subs, nclients);
            restart = 0;
            rx.len = 0;
        }

        /* ---------------- Fan-out pump ---------------- */
        uint8_t chunk[READ_CHUNK];
        int src_alive = 1;
        cmd_router_reset(&cmd_rt);      /* a new source may begin mid-frame */
        while (src_alive && !g_stop) {
            struct pollfd pfds[4 + MAX_CLIENTS];
            int np = 0;
            int idx_src = np;
            pfds[np].fd = src; pfds[np].events = POLLIN; np++;
            int idx_listen = -1;
            if (listen_fd >= 0) { idx_listen = np; pfds[np].fd = listen_fd; pfds[np].events = POLLIN; np++; }
            int idx_cmd_listen = -1, idx_cmd_client = -1;
            if (cmd_listen_fd >= 0) { idx_cmd_listen = np; pfds[np].fd = cmd_listen_fd; pfds[np].events = POLLIN; np++; }
            if (cmd_client >= 0) { idx_cmd_client = np; pfds[np].fd = cmd_client; pfds[np].events = POLLIN; np++; }
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
                int df = socket(dial.dest.ss_family, SOCK_STREAM, 0);
                if (df >= 0) {
                    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
                    setsockopt(df, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
                    if (connect(df, (struct sockaddr *)&dial.dest, dial.destlen) == 0) {
                        dial.fd = df;
                        set_nonblock(df);
                        logmsg("tcp-dial connected");
                    } else {
                        close(df);
                        dial.next_retry_ms = now_ms() + 5000;
                    }
                }
            }

            /* SUB grace window: expired PENDING clients get the full
             * stream; wake in time for the earliest pending deadline. */
            int ptimeout = 1000;
            if (cfg.client_filters) {
                long now = now_ms();
                for (int i = 0; i < nclients; i++) {
                    if (subs[i].state != CSUB_PENDING) continue;
                    client_sub_tick(&subs[i], now, cfg.sub_grace_ms);
                    if (subs[i].state == CSUB_FULL) {
                        logmsg("tcp-listen client: no SUB within %d ms — full stream",
                               cfg.sub_grace_ms);
                        continue;
                    }
                    long rem = cfg.sub_grace_ms - (now - subs[i].accepted_ms);
                    if (rem < ptimeout) ptimeout = rem < 1 ? 1 : (int)rem;
                }
            }

            int pr = poll(pfds, np, ptimeout);
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
                    } else if (cfg.client_filters) {
                        /* A SUB line selects delivery only — never a
                         * mask: we stay the sole mask arbiter. */
                        const char *err = "bad request";
                        unsigned before = subs[i].nsub;
                        if (client_sub_input(&subs[i], junk, (size_t)r, &err) < 0) {
                            char msg[96];
                            int m = snprintf(msg, sizeof msg, "ERR %s\n", err);
                            (void)!write(clients[i], msg, (size_t)m);
                            logmsg("tcp-listen client dropped: bad SUB (%s)", err);
                            close(clients[i]);
                            clients[i] = -1;
                        } else if (subs[i].nsub != before) {
                            logmsg("tcp-listen client subscribed: %d log code(s), "
                                   "%d opcode(s), f3=%d events=%d", subs[i].f.ncodes,
                                   subs[i].f.nopcodes, subs[i].f.f3, subs[i].f.events);
                        }
                    }
                    /* else: ignore client input (we are the sole mask
                     * arbiter; commands go ONLY via the opt-in --cmd-listen) */
                }
            }

            /* Command client input -> validated, policy-checked requests to
             * the modem. Whole frames only; see cmd_rx_feed. */
            if (idx_cmd_client >= 0 &&
                (pfds[idx_cmd_client].revents & (POLLIN | POLLHUP | POLLERR))) {
                uint8_t cbuf[4096];
                ssize_t r = read(cmd_client, cbuf, sizeof cbuf);
                if (r == 0 || (r < 0 && errno != EINTR && errno != EAGAIN &&
                               errno != EWOULDBLOCK)) {
                    close(cmd_client);
                    cmd_client = -1;
                    logmsg("cmd-listen: command client closed (forwarded=%lu "
                           "refused=%lu bad_crc=%lu malformed=%lu oversize=%lu "
                           "routed=%lu dropped=%lu)", cmd_st.forwarded,
                           cmd_st.refused, cmd_st.bad_crc, cmd_st.malformed,
                           cmd_st.oversize, cmd_st.routed, cmd_st.dropped);
                } else if (r > 0 &&
                           cmd_rx_feed(&cmd_rx, src, cbuf, (size_t)r, &cmd_st) < 0) {
                    logmsg("cmd: DIAG source write failed — re-spawning source");
                    src_alive = 0;
                }
            }
            if (idx_cmd_listen >= 0 && (pfds[idx_cmd_listen].revents & POLLIN)) {
                int c = accept(cmd_listen_fd, NULL, NULL);
                if (c >= 0) {
                    if (cmd_client >= 0) {
                        close(c);
                        logmsg("cmd-listen: refused a second command client "
                               "(one at a time)");
                    } else {
                        set_nonblock(c);
                        int one = 1;
                        setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
                        cmd_client = c;
                        cmd_rx_reset(&cmd_rx);
                        cmd_router_reset(&cmd_rt);
                        memset(&cmd_st, 0, sizeof cmd_st);
                        logmsg("cmd-listen: command client connected");
                    }
                }
            }
            {
                int before = nclients;
                nclients = compact_clients(clients, subs, nclients);
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
                        client_sub_init(&subs[nclients], cfg.client_filters, now_ms());
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
                    /* TCP sinks: raw bytes (or a client's subscribed
                     * frames), best-effort, drop on hard error; tcp-dial; UDP
                     * sinks DGE1-framed. All via fanout_chunk. */
                    fo.nclients = nclients;
                    fanout_chunk(&fo, chunk, (size_t)n, 0);
                    nclients = compact_clients(clients, subs, nclients);
                    /* Command client: reply-class frames only. The
                     * sinks above got the same bytes, replies included. */
                    if (cmd_client >= 0 &&
                        cmd_router_feed(&cmd_rt, chunk, (size_t)n, cmd_client,
                                        &cmd_st) < 0) {
                        close(cmd_client);
                        cmd_client = -1;
                        logmsg("cmd-listen: command client dropped (write failed)");
                    }
                }
            }
        }

        /* src loop ended — tear down the source before respawn. */
        if (using_stdin) {
            /* EOF on stdin = diaggulp (the upstream) exited. There is nothing
             * to re-spawn and reading fd 0 again just returns EOF, so stop. Do
             * not close fd 0 (harmless, but leave the std descriptor intact for
             * the shutdown logging below). */
            logmsg("stdin closed (upstream exited) — shutting down");
            break;
        } else if (using_chardev) {
            if (src >= 0) close(src);   /* no captive process / bridge; the
                                         * chardev IS the transport */
        } else if (using_diag_dev || using_usbfs) {
            if (src >= 0) close(src);   /* closing src ends the bridge thread;
                                         * it releases the usbfs interface /
                                         * reverts the /dev/diag MD session on
                                         * its side before exiting */
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
    if (fo.splitting && split.overflows)
        logmsg("client-filters: %lu oversized frame(s) dropped by the splitter",
               split.overflows);
    if (planeb_tid) {
        /* g_stop is already set; the thread exits its tail loop, releases its
         * fds + UDP socket, and frees its ctx. Join so teardown is clean. */
        pthread_join(planeb_tid, NULL);
        planeb = NULL;   /* freed by the thread */
    }
    (void)planeb;
    for (int i = 0; i < nclients; i++) if (clients[i] >= 0) close(clients[i]);
    if (dial.fd >= 0) close(dial.fd);
    if (bcast.enabled) close(bcast.fd);
    if (unicast.enabled) close(unicast.fd);
    if (listen_fd >= 0) close(listen_fd);
    if (cmd_client >= 0) close(cmd_client);
    if (cmd_listen_fd >= 0) close(cmd_listen_fd);
    return 0;
}
#endif /* !DIAGBARF_FRAMING_TEST && !DIAGBARF_BRIDGE_TEST */
