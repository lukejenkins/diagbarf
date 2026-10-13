/* SPDX-License-Identifier: Apache-2.0 */
/* Host unit tests for diagbarf's log-mask arming order and the per-SSID
 * F3 fallback payload/parse helpers.
 * Build+run: make -C apps/diagbarf test-mask
 *
 * Two MDM9250-specific behaviours are pinned here (ported from the C-V2X bench
 * collector st_diag_collect.py, which discovered them on the live modem):
 *
 *   1. plan_log_types() ordering. SET_MASK is a request/response exchange, but
 *      arming a busy type (type 1 = LTE ML1, 2.06 MB/s) starts its flood at once
 *      and buries the SET_MASK *responses* for everything armed after it. Type
 *      11 is the C-V2X sidelink plane (0xB2xx), so it must be armable FIRST.
 *
 *   2. The 0x7D mask-table helpers for the F3 fallback. SET_ALL_RT_MASKS is a
 *      silent no-op on this MPSS, so arm_mask() reads the build-capability mask
 *      (GET_BUILD_MASK) and writes a per-SSID SET_RT_MASK. The wire layout of
 *      those frames is fixed (array at offset 7, explicit reserved u16) — a byte
 *      diff here is the cheap place to catch drift, not the live unit.
 *
 * Uses the DIAGBARF_FRAMING_TEST guard (like test_qsh_arm.c): the helpers under
 * test are pure and live in the always-compiled region next to arm_mask(), so
 * this skips the pthread daemon body and main() and needs no -pthread. */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define DIAGBARF_FRAMING_TEST 1
#include "../diagbarf.c"

/* 16-entry bitsize array, non-empty at exactly the given types (distinct values
 * so a mis-paired size would be visible). */
static void sizes_with(uint32_t *s, const int *types, int n) {
    memset(s, 0, NUM_LOG_TYPES * sizeof *s);
    for (int i = 0; i < n; i++)
        s[types[i]] = 100 + types[i];
}

/* --- plan_log_types ----------------------------------------------------- */

static void test_default_is_ascending_nonempty(void) {
    uint32_t s[NUM_LOG_TYPES];
    int present[] = { 0, 1, 5, 11, 13 };
    sizes_with(s, present, 5);
    int out[NUM_LOG_TYPES];
    int n = plan_log_types(s, NULL, 0, 0, out);
    assert(n == 5);
    int want[] = { 0, 1, 5, 11, 13 };
    assert(memcmp(out, want, sizeof want) == 0);
    printf("ok default ascending, empties dropped\n");
}

static void test_empty_types_dropped(void) {
    uint32_t s[NUM_LOG_TYPES];
    int present[] = { 2 };
    sizes_with(s, present, 1);
    int out[NUM_LOG_TYPES];
    int n = plan_log_types(s, NULL, 0, 0, out);
    assert(n == 1 && out[0] == 2);
    printf("ok empty log types dropped\n");
}

static void test_priority_armed_first(void) {
    uint32_t s[NUM_LOG_TYPES];
    int present[] = { 0, 1, 5, 11, 13 };
    sizes_with(s, present, 5);
    int prio[] = { 11 };
    int out[NUM_LOG_TYPES];
    int n = plan_log_types(s, prio, 1, 0, out);
    assert(n == 5 && out[0] == 11);          /* sidelink first, then the rest */
    int want[] = { 11, 0, 1, 5, 13 };
    assert(memcmp(out, want, sizeof want) == 0);
    printf("ok type 11 armed first, remainder ascending\n");
}

static void test_priority_keeps_caller_order(void) {
    uint32_t s[NUM_LOG_TYPES];
    int present[] = { 0, 1, 5, 11, 13 };
    sizes_with(s, present, 5);
    int prio[] = { 13, 11 };
    int out[NUM_LOG_TYPES];
    int n = plan_log_types(s, prio, 2, 0, out);
    int want[] = { 13, 11, 0, 1, 5 };
    assert(n == 5 && memcmp(out, want, sizeof want) == 0);
    printf("ok caller order kept, remainder follows\n");
}

static void test_priority_deduped(void) {
    uint32_t s[NUM_LOG_TYPES];
    int present[] = { 1, 11 };
    sizes_with(s, present, 2);
    int prio[] = { 11, 11, 1 };
    int out[NUM_LOG_TYPES];
    int n = plan_log_types(s, prio, 3, 1, out);      /* only=1 */
    int want[] = { 11, 1 };
    assert(n == 2 && memcmp(out, want, sizeof want) == 0);
    printf("ok repeated priority entry deduped, order kept\n");
}

static void test_empty_priority_skipped_not_faked(void) {
    uint32_t s[NUM_LOG_TYPES];
    int present[] = { 0, 1 };
    sizes_with(s, present, 2);                        /* type 11 is empty */
    int prio[] = { 11 };
    int out[NUM_LOG_TYPES];
    int n = plan_log_types(s, prio, 1, 0, out);
    int want[] = { 0, 1 };
    assert(n == 2 && memcmp(out, want, sizeof want) == 0);
    printf("ok empty priority type skipped, remainder still armed\n");
}

static void test_only_arms_just_the_plane(void) {
    uint32_t s[NUM_LOG_TYPES];
    int present[] = { 0, 1, 5, 11, 13 };
    sizes_with(s, present, 5);
    int prio[] = { 11 };
    int out[NUM_LOG_TYPES];
    int n = plan_log_types(s, prio, 1, 1, out);       /* only=1 */
    assert(n == 1 && out[0] == 11);
    printf("ok --only arms just the requested plane\n");
}

static void test_only_empty_type_arms_nothing(void) {
    uint32_t s[NUM_LOG_TYPES];
    int present[] = { 0, 1 };
    sizes_with(s, present, 2);                        /* type 11 empty */
    int prio[] = { 11 };
    int out[NUM_LOG_TYPES];
    int n = plan_log_types(s, prio, 1, 1, out);
    assert(n == 0);                     /* nothing, not a silent firehose fallback */
    printf("ok --only on an undefined type arms nothing\n");
}

/* --- 0x7D mask-table build / parse (the F3 fallback) ----------- */

static void test_get_mask_request_layout(void) {
    uint8_t out[8];
    size_t n = build_ext_msg_get_mask_request(EXT_MSG_GET_BUILD_MASK, 0, 120,
                                              out, sizeof out);
    assert(n == 5);
    assert(out[0] == EXT_MSG_GET_BUILD_MASK);
    uint16_t first, last;
    memcpy(&first, out + 1, 2); memcpy(&last, out + 3, 2);
    assert(first == 0 && last == 120);
    /* runtime read form */
    assert(build_ext_msg_get_mask_request(EXT_MSG_GET_RT_MASK, 0, 1, out,
                                          sizeof out) == 5);
    printf("ok GET_MASK request layout (sub, first, last)\n");
}

static void test_get_mask_request_rejects_bad(void) {
    uint8_t out[8];
    assert(build_ext_msg_get_mask_request(EXT_MSG_SET_RT_MASK, 0, 1, out,
                                          sizeof out) == 0);   /* not a read */
    assert(build_ext_msg_get_mask_request(EXT_MSG_GET_BUILD_MASK, 5, 1, out,
                                          sizeof out) == 0);   /* last < first */
    assert(build_ext_msg_get_mask_request(EXT_MSG_GET_BUILD_MASK, 0, 1, out,
                                          4) == 0);            /* short buffer */
    printf("ok GET_MASK request rejects bad sub/range/buffer\n");
}

static void test_set_rt_mask_layout_and_derived_last(void) {
    uint32_t levels[] = { 0x1F, 0x00, 0x03 };
    uint8_t out[64];
    size_t n = build_ext_msg_set_rt_mask(0, levels, 3, out, sizeof out);
    assert(n == 7 + 3 * 4);
    assert(out[0] == EXT_MSG_SET_RT_MASK);
    uint16_t first, last, reserved;
    memcpy(&first, out + 1, 2);
    memcpy(&last, out + 3, 2);
    memcpy(&reserved, out + 5, 2);
    assert(first == 0 && last == 2 && reserved == 0);   /* last = first + n - 1 */
    uint32_t m0, m1, m2;
    memcpy(&m0, out + 7, 4); memcpy(&m1, out + 11, 4); memcpy(&m2, out + 15, 4);
    assert(m0 == 0x1F && m1 == 0x00 && m2 == 0x03);
    printf("ok SET_RT_MASK layout, reserved u16, derived last\n");
}

static void test_set_rt_mask_rejects_bad(void) {
    uint32_t levels[] = { 1 };
    uint8_t out[64];
    assert(build_ext_msg_set_rt_mask(0, levels, 0, out, sizeof out) == 0);   /* n<=0 */
    assert(build_ext_msg_set_rt_mask(0, levels, 1, out, 6) == 0);            /* short */
    printf("ok SET_RT_MASK rejects empty levels / short buffer\n");
}

static void test_mask_table_reply_roundtrip(void) {
    /* A GET_BUILD_MASK reply: sub=2, first=0, last=1, status=0, masks[2]. */
    uint8_t body[7 + 2 * 4];
    body[0] = EXT_MSG_GET_BUILD_MASK;
    uint16_t first = 0, last = 1, status = 0;
    memcpy(body + 1, &first, 2);
    memcpy(body + 3, &last, 2);
    memcpy(body + 5, &status, 2);
    uint32_t in0 = 0x1F, in1 = 0x00;
    memcpy(body + 7, &in0, 4);
    memcpy(body + 11, &in1, 4);
    uint8_t sub; uint16_t pf, pl, ps; uint32_t masks[8];
    int nm = parse_ext_msg_mask_table_reply(body, sizeof body, &sub, &pf, &pl,
                                            &ps, masks, 8);
    assert(nm == 2);
    assert(sub == EXT_MSG_GET_BUILD_MASK && pf == 0 && pl == 1 && ps == 0);
    assert(masks[0] == 0x1F && masks[1] == 0x00);
    printf("ok mask-table reply round-trips at offset 7\n");
}

static void test_mask_table_reply_rejects(void) {
    uint8_t masks_buf[8 * 4];
    uint32_t masks[8];
    assert(parse_ext_msg_mask_table_reply(NULL, 0, NULL, NULL, NULL, NULL,
                                          masks, 8) == -1);          /* null */
    uint8_t tooshort[] = { 0x02, 0x00 };
    assert(parse_ext_msg_mask_table_reply(tooshort, sizeof tooshort, NULL, NULL,
                                          NULL, NULL, masks, 8) == -1);
    /* header present but no array -> not a valid table read (never "mask is 0") */
    uint8_t hdr_only[] = { 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };
    assert(parse_ext_msg_mask_table_reply(hdr_only, sizeof hdr_only, NULL, NULL,
                                          NULL, NULL, masks, 8) == -1);
    /* not a whole number of u32 entries */
    uint8_t partial[] = { 0x02, 0,0, 0,0, 0,0, 0x01, 0x02, 0x03 };
    assert(parse_ext_msg_mask_table_reply(partial, sizeof partial, NULL, NULL,
                                          NULL, NULL, masks, 8) == -1);
    /* a SET_ALL echo (sub 5) is not a mask-table read */
    uint8_t setall[] = { 0x05, 0,0, 0,0, 0,0, 0,0,0,0 };
    assert(parse_ext_msg_mask_table_reply(setall, sizeof setall, NULL, NULL,
                                          NULL, NULL, masks, 8) == -1);
    (void)masks_buf;
    printf("ok mask-table parse rejects truncated / partial-u32 / non-table\n");
}

static void test_mask_table_reply_reports_total_but_caps_writes(void) {
    /* A reply carrying MORE masks than the caller's buffer: parse must report the
     * reply's TRUE count (so the caller can tell it was truncated) yet write only
     * maskcap entries. arm_mask() requests [0..120] and sizes levels[] to 121; a
     * non-conformant reply with a wider range must NOT make the caller index past
     * that buffer, which is why arm_mask() clamps the return to maskcap. */
    uint8_t body[7 + 5 * 4];
    body[0] = EXT_MSG_GET_BUILD_MASK;
    uint16_t first = 0, last = 4, status = 0;
    memcpy(body + 1, &first, 2);
    memcpy(body + 3, &last, 2);
    memcpy(body + 5, &status, 2);
    for (int i = 0; i < 5; i++) {
        uint32_t v = 0xA0u + (uint32_t)i;
        memcpy(body + 7 + i * 4, &v, 4);
    }
    uint32_t masks[3] = { 0xDEAD, 0xDEAD, 0xDEAD };
    int nm = parse_ext_msg_mask_table_reply(body, sizeof body, NULL, NULL, NULL,
                                            NULL, masks, 3);      /* maskcap = 3 */
    assert(nm == 5);                               /* true count, not the cap */
    assert(masks[0] == 0xA0 && masks[1] == 0xA1 && masks[2] == 0xA2);
    /* nothing written past masks[2]; the caller must clamp nm before iterating */
    printf("ok mask-table parse reports total but writes only maskcap\n");
}

static void test_build_then_parse_capability_roundtrip(void) {
    /* Model the fallback path: a build-capability reply carries per-ssid levels;
     * feed those straight into SET_RT_MASK, as arm_mask() does. */
    uint8_t reply[7 + 3 * 4];
    reply[0] = EXT_MSG_GET_BUILD_MASK;
    uint16_t f = 0, l = 2, st = 0;
    memcpy(reply + 1, &f, 2); memcpy(reply + 3, &l, 2); memcpy(reply + 5, &st, 2);
    uint32_t caps[] = { 0xFFFFFFFF, 0, 0x0F };
    memcpy(reply + 7, caps, sizeof caps);
    uint32_t got[8];
    int nm = parse_ext_msg_mask_table_reply(reply, sizeof reply, NULL, NULL,
                                            NULL, NULL, got, 8);
    assert(nm == 3);
    uint8_t set[64];
    size_t sn = build_ext_msg_set_rt_mask(0, got, nm, set, sizeof set);
    assert(sn == 7 + 3 * 4);
    uint32_t back0, back2;
    memcpy(&back0, set + 7, 4); memcpy(&back2, set + 15, 4);
    assert(back0 == 0xFFFFFFFF && back2 == 0x0F);   /* build levels reused verbatim */
    printf("ok GET_BUILD_MASK levels feed SET_RT_MASK verbatim\n");
}

/* --ext-msg-f3-mute ------------------------------------------------ */
static void test_mute_spec_single_list_and_range(void) {
    uint16_t f[MAX_F3_MUTE], l[MAX_F3_MUTE];
    assert(parse_ssid_ranges("47", f, l, MAX_F3_MUTE) == 1);
    assert(f[0] == 47 && l[0] == 47);
    assert(parse_ssid_ranges("47,85-86,9509", f, l, MAX_F3_MUTE) == 3);
    assert(f[0] == 47 && l[0] == 47);
    assert(f[1] == 85 && l[1] == 86);
    assert(f[2] == 9509 && l[2] == 9509);
    assert(parse_ssid_ranges("0-255", f, l, MAX_F3_MUTE) == 1);   /* max span */
    printf("ok mute spec: single, list, range, max span\n");
}

static void test_mute_spec_rejects(void) {
    uint16_t f[2], l[2];
    const char *bad[] = { "", "x", "47,", ",47", "47-", "-47", "50-47",
                          "65536", "0-256", "47;48", "47 ", "1,2,3", NULL };
    for (int i = 0; bad[i]; i++) {
        int r = parse_ssid_ranges(bad[i], f, l, 2);   /* cap 2: "1,2,3" overflows */
        if (r != -1) { printf("FAIL accepted '%s' -> %d\n", bad[i], r); assert(0); }
    }
    assert(parse_ssid_ranges(NULL, f, l, 2) == -1);
    printf("ok mute spec: malformed / reversed / oversize / overflow rejected\n");
}

static void test_mute_range_is_set_rt_mask_of_zeros(void) {
    uint8_t out[8 + F3_MUTE_SPAN * 4];
    size_t n = build_ext_msg_mute_range(47, 47, out, sizeof out);
    /* u8(4) u16le(47) u16le(47) u16le(0) u32le(0) */
    const uint8_t want[] = { 0x04, 0x2F, 0x00, 0x2F, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00 };
    assert(n == sizeof want);
    assert(memcmp(out, want, sizeof want) == 0);
    n = build_ext_msg_mute_range(85, 86, out, sizeof out);
    assert(n == 7 + 2 * 4);
    for (size_t i = 7; i < n; i++) assert(out[i] == 0);
    assert(build_ext_msg_mute_range(50, 47, out, sizeof out) == 0);
    assert(build_ext_msg_mute_range(47, 47, out, 10) == 0);        /* short buf */
    printf("ok mute range = SET_RT_MASK with every level 0\n");
}

/* --- --mask presets -------------------------------------------- */

static void test_parse_mask_mode(void) {
    assert(parse_mask_mode("max") == MASK_MAX);
    assert(parse_mask_mode("gnss") == MASK_GNSS);
    assert(parse_mask_mode("none") == MASK_NONE);
    assert(parse_mask_mode("MAX") == -1 && parse_mask_mode("") == -1 &&
           parse_mask_mode("gnss-basic") == -1);
    printf("ok --mask max|gnss|none parsed, others rejected\n");
}

static void test_fill_code_mask_sets_only_preset_bits(void) {
    /* type 1 holds 0x1476 -> item 0x476 = byte 0x8E bit 6 */
    uint8_t m[0x120];                             /* 0x900 bits */
    const uint16_t codes[] = { 0x1476, 0x1886, 0xB0C0 };
    int n = fill_code_mask(1, 0x900, codes, 3, m, sizeof m);
    assert(n == 2);                               /* 0x1476 and 0x1886 */
    assert(m[0x476 / 8] == (1u << (0x476 % 8)));
    assert(m[0x886 / 8] == (1u << (0x886 % 8)));
    int set = 0;
    for (size_t i = 0; i < sizeof m; i++) set += __builtin_popcount(m[i]);
    assert(set == 2);
    printf("ok gnss mask sets exactly the preset bits of its type\n");
}

static void test_fill_code_mask_other_type_is_all_zero(void) {
    uint8_t m[64];
    memset(m, 0xAA, sizeof m);
    const uint16_t codes[] = { 0x1476 };
    assert(fill_code_mask(0xB, 400, codes, 1, m, sizeof m) == 0);
    for (size_t i = 0; i < sizeof m; i++) assert(m[i] == 0);
    printf("ok type with no preset code gets a clearing all-zero mask\n");
}

static void test_fill_code_mask_skips_past_bitsize(void) {
    uint8_t m[0x100];
    const uint16_t codes[] = { 0x1476 };
    /* firmware advertises type 1 shorter than item 0x476; the buffer is big
     * enough to hold the bit, so only the bitsize check can refuse it */
    assert(fill_code_mask(1, 0x400, codes, 1, m, sizeof m) == 0);
    for (size_t i = 0; i < sizeof m; i++) assert(m[i] == 0);
    printf("ok preset code past the advertised bitsize is skipped\n");
}

static void test_generated_preset_carries_position_report(void) {
    int found = 0;
    for (int i = 0; i < DIAGBARF_PRESET_GNSS_N; i++)
        if (DIAGBARF_PRESET_GNSS[i] == 0x1476) found = 1;
    assert(found);
    printf("ok presets_gnss.h carries 0x1476\n");
}

int main(void) {
    test_parse_mask_mode();
    test_fill_code_mask_sets_only_preset_bits();
    test_fill_code_mask_other_type_is_all_zero();
    test_fill_code_mask_skips_past_bitsize();
    test_generated_preset_carries_position_report();
    test_mute_spec_single_list_and_range();
    test_mute_spec_rejects();
    test_mute_range_is_set_rt_mask_of_zeros();
    test_default_is_ascending_nonempty();
    test_empty_types_dropped();
    test_priority_armed_first();
    test_priority_keeps_caller_order();
    test_priority_deduped();
    test_empty_priority_skipped_not_faked();
    test_only_arms_just_the_plane();
    test_only_empty_type_arms_nothing();
    test_get_mask_request_layout();
    test_get_mask_request_rejects_bad();
    test_set_rt_mask_layout_and_derived_last();
    test_set_rt_mask_rejects_bad();
    test_mask_table_reply_roundtrip();
    test_mask_table_reply_rejects();
    test_mask_table_reply_reports_total_but_caps_writes();
    test_build_then_parse_capability_roundtrip();
    printf("\nall mask-arming tests passed\n");
    return 0;
}
