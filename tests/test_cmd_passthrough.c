/* SPDX-License-Identifier: Apache-2.0 */
/* Host unit tests for the OPT-IN DIAG command passthrough (`--cmd-listen`).
 * Build+run: make -C apps/diagbarf test   (or: make -C apps/diagbarf test-cmd)
 *
 * diagbarf's TCP sinks are passive by design: a collector must not arm masks,
 * because diagbarf is the sole mask arbiter. `--cmd-listen` is the one opt-in
 * exception: a SEPARATE listener (loopback by default) whose single client may
 * send whole HDLC request frames that diagbarf forwards to the modem, and which
 * receives ONLY the matching responses (not the firehose). It exists because the
 * RIS-9260's MDM9150 has no other DIAG command path while diagbarf holds its
 * USB DIAG interface, and a C-V2X bench study needs one EFS2 item-file write.
 *
 * What these pin (all hardware-free: pure functions + socketpairs):
 *   - the request policy: EFS2 (0x4B/0x13, 0x4B/0x3E), NV read/write, and
 *     read-only identity/status are allowed; mask-changing opcodes, CONTROL,
 *     FTM and every other subsystem are refused;
 *   - client-frame reassembly across split reads, CRC reject, oversize reject,
 *     and canonical re-encode (the modem gets exactly the bytes we checked);
 *   - response routing: only reply-class frames reach the command client;
 *   - no interleaving: a half-received client frame never reaches the wire
 *     while diagbarf's own send_recv() exchange is in flight;
 *   - the usbfs wire gate is UNCHANGED with the flag off and widened only to
 *     the passthrough allow-list with it on (0x29 / FTM still refused);
 *   - `--cmd-listen PORT` defaults to 127.0.0.1, and stdin (no back-channel)
 *     cannot take commands. */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>

#define DIAGBARF_FRAMING_TEST 1
#include "../diagbarf.c"

/* ---- helpers ------------------------------------------------------------ */

/* HDLC-encode a request exactly as a client (qrtr_diag_efs2_walk.py) does:
 * payload || CRC-16 LE, escaped, 0x7E-terminated. hdlc_encap IS that. */
static size_t enc(const uint8_t *pkt, size_t n, uint8_t *out, size_t cap)
{
    size_t m = hdlc_encap(pkt, n, out, cap);
    assert(m > 0);
    return m;
}

/* Read everything currently queued on fd (non-blocking after a short wait). */
static size_t drain(int fd, uint8_t *buf, size_t cap)
{
    size_t got = 0;
    for (;;) {
        struct pollfd p = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&p, 1, 50) <= 0)
            break;
        ssize_t r = read(fd, buf + got, cap - got);
        if (r <= 0)
            break;
        got += (size_t)r;
        if (got == cap)
            break;
    }
    return got;
}

static void pair(int sv[2])
{
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
}

static const uint8_t EFS_HELLO[] = { 0x4B, 0x13, 0x00, 0x00, 1, 2, 3, 4 };

/* ---- request policy ----------------------------------------------------- */

static void test_policy_allows_efs2_std_and_alt(void)
{
    const uint8_t std[] = { 0x4B, 0x13, 0x00, 0x00 };
    const uint8_t alt[] = { 0x4B, 0x3E, 0x02, 0x00 };
    assert(cmd_request_allowed(std, sizeof std) == 1);
    assert(cmd_request_allowed(alt, sizeof alt) == 1);
    printf("ok policy_allows_efs2_std_and_alt\n");
}

static void test_policy_allows_nv_and_readonly_identity(void)
{
    const uint8_t ops[] = { 0x26, 0x27, 0x00, 0x0C, 0x7C };
    for (size_t i = 0; i < sizeof ops; i++) {
        uint8_t p[4] = { ops[i], 0, 0, 0 };
        assert(cmd_request_allowed(p, sizeof p) == 1);
    }
    printf("ok policy_allows_nv_and_readonly_identity\n");
}

static void test_policy_refuses_mask_changing_opcodes(void)
{
    /* diagbarf must stay the sole mask arbiter, or the firehose silently changes. */
    const uint8_t ops[] = { 0x73, 0x7D, 0x60, 0x82 };
    for (size_t i = 0; i < sizeof ops; i++) {
        uint8_t p[8] = { ops[i], 0, 0, 0, 0, 0, 0, 0 };
        assert(cmd_request_allowed(p, sizeof p) == 0);
    }
    printf("ok policy_refuses_mask_changing_opcodes\n");
}

static void test_policy_refuses_control_ftm_and_other_subsystems(void)
{
    const uint8_t ctrl[] = { 0x29, 0x02, 0x00 };             /* CONTROL: reset/offline */
    const uint8_t ftm[]  = { 0x4B, 0x0B, 0x00, 0x00 };       /* FTM: can key a TX */
    const uint8_t qsh[]  = { 0x4B, 0x44, 0x01, 0x90 };       /* some other subsystem */
    const uint8_t v2[]   = { 0x80, 0x13, 0x00, 0x00 };       /* SUBSYS_CMD_VER_2 */
    const uint8_t short4b[] = { 0x4B, 0x13 };                /* no cmd code: malformed */
    assert(cmd_request_allowed(ctrl, sizeof ctrl) == 0);
    assert(cmd_request_allowed(ftm, sizeof ftm) == 0);
    assert(cmd_request_allowed(qsh, sizeof qsh) == 0);
    assert(cmd_request_allowed(v2, sizeof v2) == 0);
    assert(cmd_request_allowed(short4b, sizeof short4b) == 0);
    assert(cmd_request_allowed(ctrl, 0) == 0);
    printf("ok policy_refuses_control_ftm_and_other_subsystems\n");
}

/* The read-only time + qdb-pull families: DIAG_TS_F, the
 * DIAG_SERV file-transfer records, and the diag_id-binding query. Bytes are
 * exactly what the host-side time-anchor and DIAG_SERV clients build. */
static void test_policy_allows_ts_and_diag_serv_reads(void)
{
    const uint8_t ts[]    = { 0x1D };
    const uint8_t flist[] = { 0x80, 0x12, 0x16, 0x08, 0x01, 0x00, 0x00, 0x00 };
    const uint8_t open_[] = { 0x80, 0x12, 0x16, 0x08, 0x01, 0x00, 0x01, 0x00,
                              0x9f, 0x15, 0x32, 0xab, 0xb5, 0x7a, 0x58, 0x05,
                              0x46, 0x10, 0xc1, 0xb9, 0x17, 0x51, 0xbb, 0x34 };
    const uint8_t read_[] = { 0x80, 0x12, 0x16, 0x08, 0x01, 0x00, 0x02, 0x00,
                              0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0, 0, 0, 0 };
    const uint8_t close_[] = { 0x80, 0x12, 0x16, 0x08, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00 };
    const uint8_t bind[]  = { 0x4B, 0x12, 0x22, 0x02, 0x01 };
    assert(cmd_request_allowed(ts, sizeof ts) == 1);
    assert(cmd_request_allowed(flist, sizeof flist) == 1);
    assert(cmd_request_allowed(open_, sizeof open_) == 1);
    assert(cmd_request_allowed(read_, sizeof read_) == 1);
    assert(cmd_request_allowed(close_, sizeof close_) == 1);
    assert(cmd_request_allowed(bind, sizeof bind) == 1);
    printf("ok policy_allows_ts_and_diag_serv_reads\n");
}

static void test_policy_scopes_diag_serv_to_the_file_reads(void)
{
    /* the widening is the four file-transfer records on 0x80/0x12/0x16 and the
     * one binding query on 0x4B/0x12 — nothing else on either subsystem */
    const uint8_t rec4[]   = { 0x80, 0x12, 0x16, 0x08, 0x01, 0x00, 0x04, 0x00 };
    const uint8_t othcmd[] = { 0x80, 0x12, 0x17, 0x08, 0x01, 0x00, 0x00, 0x00 };
    const uint8_t othsub[] = { 0x80, 0x13, 0x16, 0x08, 0x01, 0x00, 0x00, 0x00 };
    const uint8_t hdr7[]   = { 0x80, 0x12, 0x16, 0x08, 0x01, 0x00, 0x00 };
    const uint8_t dsub[]   = { 0x4B, 0x12, 0x0C, 0x02 };   /* other 0x4B/0x12 cmd */
    assert(cmd_request_allowed(rec4, sizeof rec4) == 0);
    assert(cmd_request_allowed(othcmd, sizeof othcmd) == 0);
    assert(cmd_request_allowed(othsub, sizeof othsub) == 0);
    assert(cmd_request_allowed(hdr7, sizeof hdr7) == 0);
    assert(cmd_request_allowed(dsub, sizeof dsub) == 0);
    printf("ok policy_scopes_diag_serv_to_the_file_reads\n");
}

/* ---- client request reassembly + forwarding ----------------------------- */

static void test_rx_forwards_frame_split_across_reads(void)
{
    crc16_init();
    int sv[2]; pair(sv);                 /* sv[0] = diagbarf src, sv[1] = modem */
    static struct cmd_rx rx; cmd_rx_reset(&rx);
    struct cmd_stats st; memset(&st, 0, sizeof st);
    uint8_t f[64]; size_t n = enc(EFS_HELLO, sizeof EFS_HELLO, f, sizeof f);

    assert(cmd_rx_feed(&rx, sv[0], f, 3, &st) == 0);
    uint8_t got[256];
    assert(drain(sv[1], got, sizeof got) == 0);        /* nothing until 0x7E */
    assert(cmd_rx_feed(&rx, sv[0], f + 3, n - 3, &st) == 0);
    size_t g = drain(sv[1], got, sizeof got);
    assert(g == n && memcmp(got, f, n) == 0);         /* exactly one whole frame */
    assert(st.forwarded == 1 && st.refused == 0 && st.bad_crc == 0);
    close(sv[0]); close(sv[1]);
    printf("ok rx_forwards_frame_split_across_reads\n");
}

static void test_rx_forwards_byte_at_a_time_and_skips_flags(void)
{
    crc16_init();
    int sv[2]; pair(sv);
    static struct cmd_rx rx; cmd_rx_reset(&rx);
    struct cmd_stats st; memset(&st, 0, sizeof st);
    uint8_t f[64]; size_t n = enc(EFS_HELLO, sizeof EFS_HELLO, f, sizeof f);
    const uint8_t flag = 0x7E;                        /* idle/open flags are empty frames */
    assert(cmd_rx_feed(&rx, sv[0], &flag, 1, &st) == 0);
    for (size_t i = 0; i < n; i++)
        assert(cmd_rx_feed(&rx, sv[0], f + i, 1, &st) == 0);
    uint8_t got[256];
    size_t g = drain(sv[1], got, sizeof got);
    assert(g == n && memcmp(got, f, n) == 0);
    assert(st.forwarded == 1 && st.malformed == 0);
    close(sv[0]); close(sv[1]);
    printf("ok rx_forwards_byte_at_a_time_and_skips_flags\n");
}

static void test_rx_rejects_bad_crc(void)
{
    crc16_init();
    int sv[2]; pair(sv);
    static struct cmd_rx rx; cmd_rx_reset(&rx);
    struct cmd_stats st; memset(&st, 0, sizeof st);
    uint8_t f[64]; size_t n = enc(EFS_HELLO, sizeof EFS_HELLO, f, sizeof f);
    f[n - 2] ^= 0x01;                                 /* corrupt the FCS */
    assert(cmd_rx_feed(&rx, sv[0], f, n, &st) == 0);
    uint8_t got[256];
    assert(drain(sv[1], got, sizeof got) == 0);       /* never shipped */
    assert(st.bad_crc == 1 && st.forwarded == 0);
    close(sv[0]); close(sv[1]);
    printf("ok rx_rejects_bad_crc\n");
}

static void test_rx_refuses_policy_and_resyncs(void)
{
    crc16_init();
    int sv[2]; pair(sv);
    static struct cmd_rx rx; cmd_rx_reset(&rx);
    struct cmd_stats st; memset(&st, 0, sizeof st);
    const uint8_t mask[] = { 0x73, 0, 0, 0, 3, 0, 0, 0 };
    const uint8_t f3[]   = { 0x7D, 5, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF };
    const uint8_t ctrl[] = { 0x29, 0x02, 0x00 };
    const uint8_t ftm[]  = { 0x4B, 0x0B, 0x00, 0x00 };
    uint8_t stream[512]; size_t s = 0;
    s += enc(mask, sizeof mask, stream + s, sizeof stream - s);
    s += enc(f3,   sizeof f3,   stream + s, sizeof stream - s);
    s += enc(ctrl, sizeof ctrl, stream + s, sizeof stream - s);
    s += enc(ftm,  sizeof ftm,  stream + s, sizeof stream - s);
    size_t good_off = s;
    s += enc(EFS_HELLO, sizeof EFS_HELLO, stream + s, sizeof stream - s);
    assert(cmd_rx_feed(&rx, sv[0], stream, s, &st) == 0);   /* one read, 5 frames */
    uint8_t got[512];
    size_t g = drain(sv[1], got, sizeof got);
    assert(g == s - good_off);                        /* ONLY the EFS2 frame */
    assert(memcmp(got, stream + good_off, g) == 0);
    assert(st.refused == 4 && st.forwarded == 1);
    close(sv[0]); close(sv[1]);
    printf("ok rx_refuses_policy_and_resyncs\n");
}

static void test_rx_reencodes_canonically(void)
{
    /* A client that escapes a byte that needs no escaping (0x11 -> 7D 31) must
     * not get its spelling onto the wire: diagbarf ships the canonical encoding
     * of the DECODED bytes it policy-checked, so no decoder differential between
     * diagbarf and the modem can smuggle a different command through. */
    crc16_init();
    int sv[2]; pair(sv);
    static struct cmd_rx rx; cmd_rx_reset(&rx);
    struct cmd_stats st; memset(&st, 0, sizeof st);
    const uint8_t pkt[] = { 0x4B, 0x13, 0x11, 0x00 };
    uint8_t canon[64]; size_t cn = enc(pkt, sizeof pkt, canon, sizeof canon);
    assert(canon[2] == 0x11);                         /* canonical: 0x11 literal */
    uint8_t odd[64]; size_t on = 0;
    odd[on++] = canon[0]; odd[on++] = canon[1];
    odd[on++] = 0x7D; odd[on++] = 0x11 ^ 0x20;        /* needless escape */
    memcpy(odd + on, canon + 3, cn - 3); on += cn - 3;
    assert(cmd_rx_feed(&rx, sv[0], odd, on, &st) == 0);
    uint8_t got[64];
    size_t g = drain(sv[1], got, sizeof got);
    assert(g == cn && memcmp(got, canon, cn) == 0);
    assert(st.forwarded == 1);
    close(sv[0]); close(sv[1]);
    printf("ok rx_reencodes_canonically\n");
}

static void test_rx_rejects_oversize_and_recovers(void)
{
    crc16_init();
    int sv[2]; pair(sv);
    static struct cmd_rx rx; cmd_rx_reset(&rx);
    struct cmd_stats st; memset(&st, 0, sizeof st);
    /* (a) a whole, CRC-valid frame whose payload exceeds CMD_MAX_REQ */
    static uint8_t big[CMD_MAX_REQ + 1];
    memset(big, 0x41, sizeof big);
    big[0] = 0x4B; big[1] = 0x13; big[2] = 0x05; big[3] = 0x00;
    static uint8_t bigenc[2 * (CMD_MAX_REQ + 4) + 8];
    /* hdlc_encap caps at 2046 payload bytes, so build this one by hand */
    uint16_t c = crc16(big, sizeof big);
    size_t o = 0;
    for (size_t i = 0; i < sizeof big + 2; i++) {
        uint8_t b = i < sizeof big ? big[i]
                  : (uint8_t)(i == sizeof big ? (c & 0xFF) : (c >> 8));
        if (b == 0x7D || b == 0x7E) { bigenc[o++] = 0x7D; bigenc[o++] = b ^ 0x20; }
        else bigenc[o++] = b;
    }
    bigenc[o++] = 0x7E;
    assert(cmd_rx_feed(&rx, sv[0], bigenc, o, &st) == 0);
    assert(st.oversize == 1 && st.forwarded == 0);
    /* (b) a runaway with NO delimiter overflows the buffer: discard to next 0x7E */
    static uint8_t junk[CMD_RX_CAP + 100];
    memset(junk, 0x42, sizeof junk);
    assert(cmd_rx_feed(&rx, sv[0], junk, sizeof junk, &st) == 0);
    const uint8_t flag = 0x7E;
    assert(cmd_rx_feed(&rx, sv[0], &flag, 1, &st) == 0);   /* ends the runaway */
    assert(st.oversize == 2);
    /* (c) the stream is usable again */
    uint8_t f[64]; size_t n = enc(EFS_HELLO, sizeof EFS_HELLO, f, sizeof f);
    assert(cmd_rx_feed(&rx, sv[0], f, n, &st) == 0);
    uint8_t got[128];
    size_t g = drain(sv[1], got, sizeof got);
    assert(g == n && memcmp(got, f, n) == 0);
    assert(st.forwarded == 1);
    close(sv[0]); close(sv[1]);
    printf("ok rx_rejects_oversize_and_recovers\n");
}

static void test_rx_reports_src_write_failure(void)
{
    crc16_init();
    int sv[2]; pair(sv);
    close(sv[1]);                                     /* modem side gone */
    static struct cmd_rx rx; cmd_rx_reset(&rx);
    struct cmd_stats st; memset(&st, 0, sizeof st);
    uint8_t f[64]; size_t n = enc(EFS_HELLO, sizeof EFS_HELLO, f, sizeof f);
    signal(SIGPIPE, SIG_IGN);
    assert(cmd_rx_feed(&rx, sv[0], f, n, &st) == -1);  /* caller re-spawns src */
    close(sv[0]);
    printf("ok rx_reports_src_write_failure\n");
}

/* ---- no interleaving with diagbarf's own send_recv() --------------------- */

static void test_no_interleave_with_in_flight_send_recv(void)
{
    /* Half a client frame arrives; then diagbarf runs its own send_recv()
     * exchange on the SAME src; then the rest of the client frame arrives. The
     * wire must carry diagbarf's command whole, then the client's frame whole —
     * never client bytes spliced into the middle of diagbarf's frame. */
    crc16_init();
    int sv[2]; pair(sv);
    static struct cmd_rx rx; cmd_rx_reset(&rx);
    struct cmd_stats st; memset(&st, 0, sizeof st);
    uint8_t cf[64]; size_t cn = enc(EFS_HELLO, sizeof EFS_HELLO, cf, sizeof cf);
    assert(cmd_rx_feed(&rx, sv[0], cf, cn / 2, &st) == 0);

    /* the modem's reply to diagbarf's 0x73 is already queued, so send_recv()
     * writes its command, then reads the reply without blocking */
    const uint8_t reply[] = { 0x73, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 };
    uint8_t renc[64]; size_t rn = enc(reply, sizeof reply, renc, sizeof renc);
    assert(write(sv[1], renc, rn) == (ssize_t)rn);
    static struct rxbuf hrx; hrx.len = 0;
    const uint8_t rr[7] = { 0, 0, 0, 1, 0, 0, 0 };
    uint8_t resp[64];
    assert(send_recv(sv[0], &hrx, DIAG_LOG_CONFIG_F, rr, sizeof rr, 1000,
                     resp, sizeof resp) >= 0);

    assert(cmd_rx_feed(&rx, sv[0], cf + cn / 2, cn - cn / 2, &st) == 0);

    uint8_t own_pkt[8] = { DIAG_LOG_CONFIG_F };
    memcpy(own_pkt + 1, rr, sizeof rr);
    uint8_t own[64]; size_t on = enc(own_pkt, sizeof own_pkt, own, sizeof own);
    uint8_t got[256];
    size_t g = drain(sv[1], got, sizeof got);
    assert(g == on + cn);
    assert(memcmp(got, own, on) == 0);               /* diagbarf's frame, whole */
    assert(memcmp(got + on, cf, cn) == 0);           /* then the client's, whole */
    close(sv[0]); close(sv[1]);
    printf("ok no_interleave_with_in_flight_send_recv\n");
}

/* ---- response routing to the command client ---------------------------- */

static void test_router_routes_only_responses(void)
{
    crc16_init();
    int sv[2]; pair(sv);                 /* sv[0] = cmd client (diagbarf side) */
    static struct cmd_router rt; cmd_router_reset(&rt);
    struct cmd_stats st; memset(&st, 0, sizeof st);
    const uint8_t logf[] = { 0x10, 0x00, 0x12, 0x00, 0x12, 0x00, 0xD9, 0xB2 };
    const uint8_t f3[]   = { 0x79, 0x00, 0x01, 0x02 };
    const uint8_t efs[]  = { 0x4B, 0x13, 0x00, 0x00, 1, 0, 0, 0 };
    const uint8_t qsr4[] = { 0x99, 0x01, 0x02 };
    const uint8_t nv[]   = { 0x26, 0x0A, 0x00, 0x11 };
    const uint8_t bad[]  = { 0x13, 0x4B, 0x0B, 0x00, 0x00 };
    const uint8_t evt[]  = { 0x60, 0x05, 0x00 };
    uint8_t stream[512], want[512];
    size_t s = 0, w = 0, k;
    /* a leading partial frame: the router starts resynced and must drop it */
    const uint8_t tail[] = { 0x4B, 0x13, 0x00, 0x7E };
    memcpy(stream, tail, sizeof tail); s += sizeof tail;
    s += enc(logf, sizeof logf, stream + s, sizeof stream - s);
    s += enc(f3,   sizeof f3,   stream + s, sizeof stream - s);
    k = enc(efs,   sizeof efs,  stream + s, sizeof stream - s);
    memcpy(want + w, stream + s, k); w += k; s += k;
    s += enc(qsr4, sizeof qsr4, stream + s, sizeof stream - s);
    k = enc(nv,    sizeof nv,   stream + s, sizeof stream - s);
    memcpy(want + w, stream + s, k); w += k; s += k;
    k = enc(bad,   sizeof bad,  stream + s, sizeof stream - s);
    memcpy(want + w, stream + s, k); w += k; s += k;
    s += enc(evt,  sizeof evt,  stream + s, sizeof stream - s);

    assert(cmd_router_feed(&rt, stream, s, sv[0], &st) == 0);
    uint8_t got[512];
    size_t g = drain(sv[1], got, sizeof got);
    assert(g == w && memcmp(got, want, w) == 0);
    assert(st.routed == 3);
    close(sv[0]); close(sv[1]);
    printf("ok router_routes_only_responses\n");
}

static void test_router_routes_ts_and_diag_serv_replies(void)
{
    crc16_init();
    int sv[2]; pair(sv);
    static struct cmd_router rt; cmd_router_reset(&rt);
    struct cmd_stats st; memset(&st, 0, sizeof st);
    const uint8_t logf[] = { 0x10, 0x00, 0x12, 0x00, 0x12, 0x00, 0xD9, 0xB2 };
    const uint8_t ts[]   = { 0x1D, 1, 2, 3, 4, 5, 6, 7, 8 };
    const uint8_t serv[] = { 0x80, 0x12, 0x16, 0x08, 0x01, 0x00, 0x00, 0x00, 0xAA };
    uint8_t stream[256], want[256];
    size_t s = 0, w = 0, k;
    s += enc(logf, sizeof logf, stream + s, sizeof stream - s);
    k = enc(ts, sizeof ts, stream + s, sizeof stream - s);
    memcpy(want + w, stream + s, k); w += k; s += k;
    s += enc(logf, sizeof logf, stream + s, sizeof stream - s);
    k = enc(serv, sizeof serv, stream + s, sizeof stream - s);
    memcpy(want + w, stream + s, k); w += k; s += k;
    assert(cmd_router_feed(&rt, stream, s, sv[0], &st) == 0);
    uint8_t got[256];
    size_t g = drain(sv[1], got, sizeof got);
    assert(g == w && memcmp(got, want, w) == 0);
    assert(st.routed == 2);
    close(sv[0]); close(sv[1]);
    printf("ok router_routes_ts_and_diag_serv_replies\n");
}

static void test_router_reassembles_at_every_split(void)
{
    crc16_init();
    const uint8_t logf[] = { 0x10, 0x7E, 0x7D, 0x01 };   /* escapes inside */
    const uint8_t efs[]  = { 0x4B, 0x13, 0x7E, 0x00, 0x7D, 0 };
    const uint8_t cfg[]  = { 0x7D, 0x05, 0x00 };         /* escaped opcode: not routable */
    uint8_t stream[256], want[128];
    size_t s = 0, w;
    s += enc(logf, sizeof logf, stream + s, sizeof stream - s);
    s += enc(cfg,  sizeof cfg,  stream + s, sizeof stream - s);
    w = enc(efs,   sizeof efs,  want, sizeof want);
    memcpy(stream + s, want, w); s += w;
    for (size_t cut = 1; cut < s; cut++) {
        int sv[2]; pair(sv);
        static struct cmd_router rt; cmd_router_reset(&rt);
        rt.state = CMD_RT_START;          /* stream begins on a frame boundary */
        struct cmd_stats st; memset(&st, 0, sizeof st);
        assert(cmd_router_feed(&rt, stream, cut, sv[0], &st) == 0);
        assert(cmd_router_feed(&rt, stream + cut, s - cut, sv[0], &st) == 0);
        uint8_t got[256];
        size_t g = drain(sv[1], got, sizeof got);
        assert(g == w && memcmp(got, want, w) == 0);
        close(sv[0]); close(sv[1]);
    }
    printf("ok router_reassembles_at_every_split\n");
}

static void test_router_drops_whole_frame_when_client_not_draining(void)
{
    /* A client that is not reading must never stall the firehose pump, and must
     * never receive a torn frame: a full socket buffer drops the WHOLE response. */
    crc16_init();
    int sv[2]; pair(sv);
    set_nonblock(sv[0]);
    static uint8_t fill[4096];
    memset(fill, 0x7E, sizeof fill);                  /* pure flags: harmless */
    while (write(sv[0], fill, sizeof fill) > 0) ;
    while (write(sv[0], fill, 1) > 0) ;                /* top up: truly full */
    assert(errno == EAGAIN || errno == EWOULDBLOCK);
    static struct cmd_router rt; cmd_router_reset(&rt);
    rt.state = CMD_RT_START;
    struct cmd_stats st; memset(&st, 0, sizeof st);
    const uint8_t efs[] = { 0x4B, 0x13, 0x00, 0x00, 1, 0, 0, 0 };
    uint8_t f[64]; size_t n = enc(efs, sizeof efs, f, sizeof f);
    assert(cmd_router_feed(&rt, f, n, sv[0], &st) == 0);   /* not fatal */
    assert(st.dropped == 1 && st.routed == 0);
    /* drain the filler; the next response arrives whole */
    static uint8_t sink[1 << 20];
    while (drain(sv[1], sink, sizeof sink) > 0) ;
    assert(cmd_router_feed(&rt, f, n, sv[0], &st) == 0);
    uint8_t got[64];
    size_t g = drain(sv[1], got, sizeof got);
    assert(g == n && memcmp(got, f, n) == 0);
    assert(st.routed == 1);
    close(sv[0]); close(sv[1]);
    printf("ok router_drops_whole_frame_when_client_not_draining\n");
}

/* ---- usbfs wire gate interplay ------------------------------------------ */

static void test_usbfs_gate_unchanged_without_passthrough(void)
{
    crc16_init();
    g_cmd_passthrough = 0;
    uint8_t f[64]; size_t n;
    n = enc(EFS_HELLO, sizeof EFS_HELLO, f, sizeof f);
    assert(usbfs_out_frame_allowed(f, n - 1) == 0);   /* EFS2 refused by default */
    const uint8_t nvw[] = { 0x27, 0x0A, 0x00 };
    n = enc(nvw, sizeof nvw, f, sizeof f);
    assert(usbfs_out_frame_allowed(f, n - 1) == 0);
    const uint8_t mask[] = { 0x73, 0, 0, 0, 1 };
    n = enc(mask, sizeof mask, f, sizeof f);
    assert(usbfs_out_frame_allowed(f, n - 1) == 1);   /* own arming still ok */
    printf("ok usbfs_gate_unchanged_without_passthrough\n");
}

static void test_usbfs_gate_widened_only_to_allow_list(void)
{
    crc16_init();
    g_cmd_passthrough = 1;
    uint8_t f[64]; size_t n;
    n = enc(EFS_HELLO, sizeof EFS_HELLO, f, sizeof f);
    assert(usbfs_out_frame_allowed(f, n - 1) == 1);
    const uint8_t nvw[] = { 0x27, 0x0A, 0x00 };
    n = enc(nvw, sizeof nvw, f, sizeof f);
    assert(usbfs_out_frame_allowed(f, n - 1) == 1);
    const uint8_t ctrl[] = { 0x29, 0x02, 0x00 };
    n = enc(ctrl, sizeof ctrl, f, sizeof f);
    assert(usbfs_out_frame_allowed(f, n - 1) == 0);   /* reset: still never */
    const uint8_t ftm[] = { 0x4B, 0x0B, 0x00, 0x00 };
    n = enc(ftm, sizeof ftm, f, sizeof f);
    assert(usbfs_out_frame_allowed(f, n - 1) == 0);   /* FTM: still never */
    const uint8_t mask[] = { 0x73, 0, 0, 0, 1 };
    n = enc(mask, sizeof mask, f, sizeof f);
    assert(usbfs_out_frame_allowed(f, n - 1) == 1);
    g_cmd_passthrough = 0;
    printf("ok usbfs_gate_widened_only_to_allow_list\n");
}

/* ---- CLI seams ----------------------------------------------------------- */

static void test_cmd_listen_bare_port_is_loopback(void)
{
    struct sockaddr_storage ss; socklen_t sl;
    assert(parse_cmd_listen("43555", &ss, &sl) == 0);
    const struct sockaddr_in *v4 = (const struct sockaddr_in *)&ss;
    assert(v4->sin_family == AF_INET);
    assert(ntohs(v4->sin_port) == 43555);
    assert(ntohl(v4->sin_addr.s_addr) == INADDR_LOOPBACK);
    assert(parse_cmd_listen("0.0.0.0:7", &ss, &sl) == 0);   /* explicit ADDR wins */
    assert(v4->sin_addr.s_addr == htonl(INADDR_ANY));
    assert(parse_cmd_listen("[::1]:7", &ss, &sl) == 0);
    assert(ss.ss_family == AF_INET6);
    assert(parse_cmd_listen("nope", &ss, &sl) < 0);
    printf("ok cmd_listen_bare_port_is_loopback\n");
}

static void test_stdin_source_cannot_take_commands(void)
{
    assert(source_accepts_commands("stdin") == 0);
    assert(source_accepts_commands("usbfs") == 1);
    assert(source_accepts_commands("socket-log") == 1);
    assert(source_accepts_commands("diag-dev") == 1);
    assert(source_accepts_commands("hdlc-chardev") == 1);
    printf("ok stdin_source_cannot_take_commands\n");
}

static void test_describe_names_the_audited_fields(void)
{
    char d[96];
    const uint8_t efs[] = { 0x4B, 0x13, 0x05, 0x00, 9 };
    cmd_describe(efs, sizeof efs, d, sizeof d);
    assert(strstr(d, "op=0x4B") && strstr(d, "subsys=0x13") && strstr(d, "cmd=0x0005"));
    const uint8_t nvw[] = { 0x27, 0x26, 0x02, 0 };
    cmd_describe(nvw, sizeof nvw, d, sizeof d);
    assert(strstr(d, "op=0x27") && strstr(d, "nv_item=550"));
    printf("ok describe_names_the_audited_fields\n");
}

/* ---- configurable allow/block rules (--cmd-allow/--cmd-block) -- */

static void reset_cmd_rules(void)
{
    g_n_cmd_allow_extra = 0;
    g_n_cmd_block = 0;
}

static void test_rules_parse_all_three_shapes(void)
{
    struct cmd_rule r[8];
    int n = 0;
    /* OP, OP/SUB, OP/SUB/CMD — hex and decimal, '/' and ':' separators */
    assert(cmd_rules_parse("0x9f,0x4b/0x12/0x218,1,0x80:0x12:0x16", r, &n) == 0);
    assert(n == 4);
    assert(r[0].op == 0x9f && !r[0].has_sub && !r[0].has_cmd);
    assert(r[1].op == 0x4b && r[1].has_sub && r[1].sub == 0x12 && r[1].has_cmd && r[1].cmd == 0x0218);
    assert(r[2].op == 1 && !r[2].has_sub);
    assert(r[3].op == 0x80 && r[3].has_sub && r[3].sub == 0x12 && r[3].has_cmd && r[3].cmd == 0x16);
    printf("ok rules_parse_all_three_shapes\n");
}

static void test_rules_parse_rejects_garbage(void)
{
    struct cmd_rule r[8];
    int n = 0;
    assert(cmd_rules_parse("", r, &n) < 0);
    assert(cmd_rules_parse("0x1ff", r, &n) < 0);          /* opcode > 0xFF */
    assert(cmd_rules_parse("0x4b/0x12/0x1ffff", r, &n) < 0); /* cmd > 0xFFFF */
    assert(cmd_rules_parse("nope", r, &n) < 0);
    assert(cmd_rules_parse("0x9f/", r, &n) < 0);          /* trailing sep, empty sub */
    printf("ok rules_parse_rejects_garbage\n");
}

static void test_cmd_allow_widens_the_policy(void)
{
    reset_cmd_rules();
    /* qlc's handshake opcodes the default refuses */
    const uint8_t op9f[]  = { 0x9f, 0x06, 0x9c };
    const uint8_t op01[]  = { 0x01, 0xf1, 0xe1 };
    const uint8_t serv1[] = { 0x4b, 0x12, 0x18, 0x02, 0x01 };    /* 0x4b/0x12/0x0218 */
    const uint8_t serv2[] = { 0x4b, 0x12, 0x33, 0x08, 0x01 };    /* 0x4b/0x12/0x0833 */
    /* refused before the widening */
    assert(cmd_request_allowed(op9f, sizeof op9f) == 0);
    assert(cmd_request_allowed(serv1, sizeof serv1) == 0);
    assert(cmd_rules_parse("0x9f,0x01,0x4b/0x12/0x218,0x4b/0x12/0x833",
                           g_cmd_allow_extra, &g_n_cmd_allow_extra) == 0);
    /* admitted after it */
    assert(cmd_request_allowed(op9f, sizeof op9f) == 1);
    assert(cmd_request_allowed(op01, sizeof op01) == 1);
    assert(cmd_request_allowed(serv1, sizeof serv1) == 1);
    assert(cmd_request_allowed(serv2, sizeof serv2) == 1);
    /* a DIFFERENT 0x4b/0x12 cmd stays refused — the rule is cmd-scoped */
    const uint8_t serv3[] = { 0x4b, 0x12, 0x99, 0x00, 0x01 };
    assert(cmd_request_allowed(serv3, sizeof serv3) == 0);
    /* and the replies to the widened opcodes now route back */
    assert(cmd_response_routable(0x9f) == 1);
    assert(cmd_response_routable(0x01) == 1);
    reset_cmd_rules();
    printf("ok cmd_allow_widens_the_policy\n");
}

static void test_cmd_block_wins_over_default_and_extra(void)
{
    reset_cmd_rules();
    const uint8_t verno[] = { 0x00, 0, 0, 0 };
    assert(cmd_request_allowed(verno, sizeof verno) == 1);       /* default-allowed */
    assert(cmd_rules_parse("0x00", g_cmd_block, &g_n_cmd_block) == 0);
    assert(cmd_request_allowed(verno, sizeof verno) == 0);       /* now blocked */
    assert(cmd_response_routable(0x00) == 0);                    /* reply also dropped */
    /* block beats an explicit allow of the same opcode */
    assert(cmd_rules_parse("0x00", g_cmd_allow_extra, &g_n_cmd_allow_extra) == 0);
    assert(cmd_request_allowed(verno, sizeof verno) == 0);
    reset_cmd_rules();
    printf("ok cmd_block_wins_over_default_and_extra\n");
}

static void test_empty_rules_are_identical_to_default(void)
{
    reset_cmd_rules();
    /* the shipped policy must be byte-for-byte unchanged with no flags */
    const uint8_t ctrl[] = { 0x29, 0x02, 0x00 };
    const uint8_t ftm[]  = { 0x4B, 0x0B, 0x00, 0x00 };
    const uint8_t verno[] = { 0x00 };
    assert(cmd_request_allowed(ctrl, sizeof ctrl) == 0);
    assert(cmd_request_allowed(ftm, sizeof ftm) == 0);
    assert(cmd_request_allowed(verno, sizeof verno) == 1);
    assert(cmd_request_allowed(verno, sizeof verno) == cmd_request_allowed_default(verno, sizeof verno));
    printf("ok empty_rules_are_identical_to_default\n");
}

int main(void)
{
    test_policy_allows_efs2_std_and_alt();
    test_policy_allows_nv_and_readonly_identity();
    test_policy_refuses_mask_changing_opcodes();
    test_policy_refuses_control_ftm_and_other_subsystems();
    test_policy_allows_ts_and_diag_serv_reads();
    test_policy_scopes_diag_serv_to_the_file_reads();
    test_rx_forwards_frame_split_across_reads();
    test_rx_forwards_byte_at_a_time_and_skips_flags();
    test_rx_rejects_bad_crc();
    test_rx_refuses_policy_and_resyncs();
    test_rx_reencodes_canonically();
    test_rx_rejects_oversize_and_recovers();
    test_rx_reports_src_write_failure();
    test_no_interleave_with_in_flight_send_recv();
    test_router_routes_only_responses();
    test_router_reassembles_at_every_split();
    test_router_routes_ts_and_diag_serv_replies();
    test_router_drops_whole_frame_when_client_not_draining();
    test_usbfs_gate_unchanged_without_passthrough();
    test_usbfs_gate_widened_only_to_allow_list();
    test_cmd_listen_bare_port_is_loopback();
    test_stdin_source_cannot_take_commands();
    test_describe_names_the_audited_fields();
    test_rules_parse_all_three_shapes();
    test_rules_parse_rejects_garbage();
    test_cmd_allow_widens_the_policy();
    test_cmd_block_wins_over_default_and_extra();
    test_empty_rules_are_identical_to_default();
    printf("all cmd-passthrough tests passed\n");
    return 0;
}
