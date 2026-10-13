/* SPDX-License-Identifier: Apache-2.0 */
/* Host unit tests for the diagchar /dev/diag type-framing helpers.
 * Build+run: make -C apps/diagbarf test
 * Framing pinned empirically on the M2000 (SDX55); see the design session note. */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* Pull in only the framing helpers from diagbarf.c (guarded region). */
#define DIAGBARF_FRAMING_TEST 1
#include "../diagbarf.c"

static void test_wrap_prepends_type_header(void) {
    /* An HDLC command frame in; expect [USER_SPACE_DATA_TYPE u32 LE][frame]. */
    const uint8_t frame[] = { 0x73, 0x00, 0x7E };
    uint8_t out[64];
    size_t n = diagdev_wrap_cmd(frame, sizeof frame, out, sizeof out);
    assert(n == 4 + sizeof frame);
    uint32_t t; memcpy(&t, out, 4);
    assert(t == USER_SPACE_DATA_TYPE);          /* == 0x20 */
    assert(memcmp(out + 4, frame, sizeof frame) == 0);
    printf("ok wrap_prepends_type_header\n");
}

static void test_user_msgs_parses_count(void) {
    /* [type=0x20][num_data=2][len][frame][len][frame] */
    uint8_t buf[64] = {0};
    buf[0] = USER_SPACE_DATA_TYPE;              /* type word, LE */
    buf[4] = 2;                                 /* num_data = 2 */
    const uint8_t *msgs = NULL;
    int num = diagdev_user_msgs(buf, sizeof buf, &msgs);
    assert(num == 2);
    assert(msgs == buf + 8);
    printf("ok user_msgs_parses_count\n");
}

static void test_user_msgs_skips_non_user_types(void) {
    uint8_t buf[16] = {0}; buf[0] = DCI_DATA_TYPE;   /* 0x04 — not log traffic */
    const uint8_t *msgs;
    assert(diagdev_user_msgs(buf, sizeof buf, &msgs) == -1);
    uint8_t runt[4] = {0};
    assert(diagdev_user_msgs(runt, sizeof runt, &msgs) == -1);  /* n<8 */
    printf("ok user_msgs_skips_non_user_types\n");
}

static void test_next_msg_iterates_length_prefixed(void) {
    /* two length-prefixed HDLC frames: [3]{AB AB 7E} [2]{CD 7E} */
    uint8_t m[32] = {0};
    m[0]=3;  m[4]=0xAB; m[5]=0xAB; m[6]=0x7E;          /* len=3 frame */
    m[7]=2;  m[11]=0xCD; m[12]=0x7E;                    /* len=2 frame */
    size_t off = 0, fl; const uint8_t *fp;
    assert(diagdev_next_msg(m, 13, &off, &fp, &fl) == 1);
    assert(fl == 3 && fp[0] == 0xAB && fp[2] == 0x7E);
    assert(diagdev_next_msg(m, 13, &off, &fp, &fl) == 1);
    assert(fl == 2 && fp[0] == 0xCD && fp[1] == 0x7E);
    assert(diagdev_next_msg(m, 13, &off, &fp, &fl) == 0);   /* exhausted */
    printf("ok next_msg_iterates_length_prefixed\n");
}

static void test_next_msg_rejects_truncated(void) {
    /* claims len=10 but only 4 bytes follow -> no complete record */
    uint8_t m[8] = {0}; m[0] = 10;
    size_t off = 0, fl; const uint8_t *fp;
    assert(diagdev_next_msg(m, sizeof m, &off, &fp, &fl) == 0);
    printf("ok next_msg_rejects_truncated\n");
}

static void test_next_frame_splits_on_7e(void) {
    /* two frames back-to-back: "AB7E" "CD7E" plus a partial "EE" */
    uint8_t buf[] = { 0xAB, 0x7E, 0xCD, 0x7E, 0xEE };
    size_t off = 0, flen;
    assert(diagdev_next_frame(buf, sizeof buf, &off, &flen) == 1);
    assert(flen == 2 && buf[off-flen] == 0xAB);          /* includes 0x7E */
    assert(diagdev_next_frame(buf, sizeof buf, &off, &flen) == 1);
    assert(flen == 2);
    assert(diagdev_next_frame(buf, sizeof buf, &off, &flen) == 0); /* partial */
    assert(off == 4);                                    /* 1 byte left buffered */
    printf("ok next_frame_splits_on_7e\n");
}

/* ---- usbfs OUT opcode allow-list gate --------------------------
 * usbfs_out_frame_allowed() is the wire-boundary safety gate for --source
 * usbfs: only 0x73 (log config) and 0x7D (ext-msg/F3 config) may reach the
 * RIS-9260's one healthy MDM9150. A frame is passed WITHOUT its trailing 0x7E
 * (hdlc_decap unescapes + strips the 2-byte FCS trailer, unverified), so these
 * frames carry a 2-byte dummy trailer and no delimiter. */
static void test_usbfs_gate_allows_log_config(void) {
    /* opcode 0x73 + 2 dummy trailer bytes -> decodes to {0x73} -> allowed */
    const uint8_t f[] = { 0x73, 0xAA, 0xBB };
    assert(usbfs_out_frame_allowed(f, sizeof f) == 1);
    printf("ok usbfs_gate_allows_log_config\n");
}

static void test_usbfs_gate_allows_ext_msg_config_escaped(void) {
    /* 0x7D is the HDLC escape byte, so a real 0x7D opcode is on the wire as
     * 7D 5D; the gate must UNESCAPE it back to 0x7D before checking. */
    const uint8_t f[] = { 0x7D, 0x5D, 0xAA, 0xBB };
    assert(usbfs_out_frame_allowed(f, sizeof f) == 1);
    printf("ok usbfs_gate_allows_ext_msg_config_escaped\n");
}

static void test_usbfs_gate_refuses_nv_write_and_control(void) {
    /* 0x27 NV_WRITE and 0x29 CONTROL (mode change / reset / LPM) — the exact
     * opcodes that must NEVER hit this modem. */
    const uint8_t nv[]   = { 0x27, 0xAA, 0xBB };
    const uint8_t ctrl[] = { 0x29, 0xAA, 0xBB };
    assert(usbfs_out_frame_allowed(nv,   sizeof nv)   == 0);
    assert(usbfs_out_frame_allowed(ctrl, sizeof ctrl) == 0);
    printf("ok usbfs_gate_refuses_nv_write_and_control\n");
}

static void test_usbfs_gate_refuses_undecodable(void) {
    /* too short to hold even the 2-byte trailer -> -1 (caller drops it too) */
    const uint8_t one[] = { 0xAA };
    assert(usbfs_out_frame_allowed(one, sizeof one) == -1);
    assert(usbfs_out_frame_allowed(one, 0)          == -1);
    printf("ok usbfs_gate_refuses_undecodable\n");
}

static void test_usbfs_gate_matches_real_encoder(void) {
    /* Tie the gate to the real send path: hdlc_encap() a 0x73 command exactly
     * as arm_mask() does, strip the trailing 0x7E delimiter, and confirm the
     * gate accepts it. Proves the gate agrees with what diagbarf actually
     * ships — CRC bytes and all. */
    crc16_init();
    const uint8_t cmd[] = { DIAG_LOG_CONFIG_F, 0x00, 0x00, 0x00, 0x01 };
    uint8_t enc[64];
    size_t n = hdlc_encap(cmd, sizeof cmd, enc, sizeof enc);
    assert(n > 1 && enc[n - 1] == 0x7E);       /* encoder appends the delimiter */
    assert(usbfs_out_frame_allowed(enc, n - 1) == 1);  /* gate sees 0x73 */

    /* And the same encoder path for a forbidden opcode is refused. */
    const uint8_t bad[] = { 0x27, 0x00, 0x00, 0x00, 0x01 };
    size_t m = hdlc_encap(bad, sizeof bad, enc, sizeof enc);
    assert(usbfs_out_frame_allowed(enc, m - 1) == 0);
    printf("ok usbfs_gate_matches_real_encoder\n");
}

/* ---- Plane B mux framing / line-split / spec-parse --------------
 * BMX1 tagged records carry the RSU daemon logs (Plane B) on a separate UDP
 * port so a single eth1 pcap holds both planes without the two ever sharing a
 * byte stream. These pure helpers are the testable core. */
static void test_bmx_frame_header_is_byte_exact(void) {
    const uint8_t body[] = { 'h','i' };
    uint8_t out[64];
    size_t n = bmx_frame_record(BMX_SRC_FIRST, BMX_FLAG_RESTART, 0x04030201u,
                                body, sizeof body, out, sizeof out);
    assert(n == BMX_HDR_LEN + sizeof body);          /* 14 + 2 */
    assert(memcmp(out, "BMX1", 4) == 0);
    assert(out[4] == BMX_VERSION);
    assert(out[5] == BMX_SRC_FIRST);
    assert(out[6] == BMX_FLAG_RESTART);
    assert(out[7] == 0);                              /* reserved */
    /* seq is LE on the wire */
    assert(out[8]==0x01 && out[9]==0x02 && out[10]==0x03 && out[11]==0x04);
    /* length is LE u16 */
    assert(out[12]==2 && out[13]==0);
    assert(memcmp(out + BMX_HDR_LEN, body, sizeof body) == 0);
    printf("ok bmx_frame_header_is_byte_exact\n");
}

static void test_bmx_frame_truncates_overlong_payload(void) {
    uint8_t big[BMX_MAX_PAYLOAD + 100];
    memset(big, 'x', sizeof big);
    uint8_t out[BMX_HDR_LEN + BMX_MAX_PAYLOAD + 8];
    size_t n = bmx_frame_record(BMX_SRC_FIRST, 0, 0, big, sizeof big,
                                out, sizeof out);
    assert(n == BMX_HDR_LEN + BMX_MAX_PAYLOAD);       /* clamped, not split */
    uint16_t l16; memcpy(&l16, out + 12, 2);
    assert(l16 == BMX_MAX_PAYLOAD);
    printf("ok bmx_frame_truncates_overlong_payload\n");
}

static void test_bmx_frame_rejects_small_outcap(void) {
    const uint8_t body[] = { 'a','b','c' };
    uint8_t out[BMX_HDR_LEN + 2];                     /* one byte short */
    assert(bmx_frame_record(BMX_SRC_FIRST, 0, 0, body, sizeof body,
                            out, sizeof out) == 0);
    printf("ok bmx_frame_rejects_small_outcap\n");
}

static void test_linebuf_splits_and_strips_crlf(void) {
    /* "one\n" "two\r\n" then a partial "thr" with no newline */
    const uint8_t buf[] = "one\ntwo\r\nthr";
    size_t len = sizeof buf - 1;                       /* drop the NUL */
    size_t off = 0; const uint8_t *ln; size_t ll;

    assert(linebuf_next_line(buf, len, &off, &ln, &ll) == 1);
    assert(ll == 3 && memcmp(ln, "one", 3) == 0);

    assert(linebuf_next_line(buf, len, &off, &ln, &ll) == 1);
    assert(ll == 3 && memcmp(ln, "two", 3) == 0);      /* CR stripped */

    /* the partial "thr" has no '\n' -> no complete line, off left at its start */
    size_t off_before = off;
    assert(linebuf_next_line(buf, len, &off, &ln, &ll) == 0);
    assert(off == off_before);
    assert(len - off == 3);                            /* "thr" kept buffered */
    printf("ok linebuf_splits_and_strips_crlf\n");
}

static void test_linebuf_handles_empty_line(void) {
    const uint8_t buf[] = "\nx\n";                     /* blank line then "x" */
    size_t len = sizeof buf - 1;
    size_t off = 0; const uint8_t *ln; size_t ll;
    assert(linebuf_next_line(buf, len, &off, &ln, &ll) == 1);
    assert(ll == 0);                                   /* empty line preserved */
    assert(linebuf_next_line(buf, len, &off, &ln, &ll) == 1);
    assert(ll == 1 && ln[0] == 'x');
    assert(linebuf_next_line(buf, len, &off, &ln, &ll) == 0);
    printf("ok linebuf_handles_empty_line\n");
}

static void test_parse_log_spec(void) {
    char name[32]; const char *path;
    assert(parse_log_spec("cv2x=/var/log/cv2x-daemon.log", name, sizeof name, &path) == 0);
    assert(strcmp(name, "cv2x") == 0);
    assert(strcmp(path, "/var/log/cv2x-daemon.log") == 0);

    assert(parse_log_spec("noeq", name, sizeof name, &path) == -1);          /* no '=' */
    assert(parse_log_spec("=/var/log/x", name, sizeof name, &path) == -1);   /* empty NAME */
    assert(parse_log_spec("x=", name, sizeof name, &path) == -1);            /* empty PATH */
    char tiny[4];
    assert(parse_log_spec("toolong=/p", tiny, sizeof tiny, &path) == -1);    /* NAME overflow */
    printf("ok parse_log_spec\n");
}

int main(void) {
    test_wrap_prepends_type_header();
    test_user_msgs_parses_count();
    test_user_msgs_skips_non_user_types();
    test_next_msg_iterates_length_prefixed();
    test_next_msg_rejects_truncated();
    test_next_frame_splits_on_7e();
    test_usbfs_gate_allows_log_config();
    test_usbfs_gate_allows_ext_msg_config_escaped();
    test_usbfs_gate_refuses_nv_write_and_control();
    test_usbfs_gate_refuses_undecodable();
    test_usbfs_gate_matches_real_encoder();
    test_bmx_frame_header_is_byte_exact();
    test_bmx_frame_truncates_overlong_payload();
    test_bmx_frame_rejects_small_outcap();
    test_linebuf_splits_and_strips_crlf();
    test_linebuf_handles_empty_line();
    test_parse_log_spec();
    printf("ALL PASS\n");
    return 0;
}
