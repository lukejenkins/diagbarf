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

int main(void) {
    test_wrap_prepends_type_header();
    test_user_msgs_parses_count();
    test_user_msgs_skips_non_user_types();
    test_next_msg_iterates_length_prefixed();
    test_next_msg_rejects_truncated();
    test_next_frame_splits_on_7e();
    printf("ALL PASS\n");
    return 0;
}
