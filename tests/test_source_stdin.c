/* SPDX-License-Identifier: Apache-2.0 */
/* Host unit tests for the `--source stdin` no-arm passthrough.
 * Build+run: make -C apps/diagbarf test   (or: make -C apps/diagbarf test-stdin)
 *
 * On the CARCOM-G1 the DIAG-owning modem (MDM9250) has no LAN egress, so
 * diagbarf cannot run there and fire UDP at the WiFi. Instead diaggulp runs on
 * the ST (it arms the log+F3 masks and writes raw HDLC to stdout) and pipes
 * into `diagbarf --source stdin`, which fans that ALREADY-ARMED stream out to
 * its sinks WITHOUT arming:  diaggulp ... -o - | diagbarf --source stdin \
 *   --udp-unicast 192.168.43.2:PORT
 *
 * These pin the two pure seams the stdin source turns on — source_is_valid()
 * accepts "stdin", source_should_arm() gates arming OFF for it (and ON for
 * every other source) — plus that a raw chunk handed to the UDP sink (exactly
 * what the fan-out pump does with each read from stdin) reaches the wire
 * DGE1-framed with its payload bytes intact. Pure funcs + a socketpair; no
 * hardware, no daemon body. */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>

#define DIAGBARF_FRAMING_TEST 1
#include "../diagbarf.c"

static void test_source_validation_accepts_stdin(void) {
    assert(source_is_valid("stdin"));
    assert(source_is_valid("socket-log"));
    assert(source_is_valid("diag-dev"));
    assert(source_is_valid("hdlc-chardev"));
    assert(source_is_valid("usbfs"));
    assert(!source_is_valid("bogus"));
    assert(!source_is_valid(""));
    printf("ok source_validation_accepts_stdin\n");
}

static void test_stdin_source_skips_arming(void) {
    /* The whole point: a pre-armed stream must NOT be re-armed. */
    assert(source_should_arm("stdin") == 0);
    /* Every channel that reaches the modem still arms. */
    assert(source_should_arm("socket-log") == 1);
    assert(source_should_arm("diag-dev") == 1);
    assert(source_should_arm("hdlc-chardev") == 1);
    assert(source_should_arm("usbfs") == 1);
    printf("ok stdin_source_skips_arming\n");
}

static void test_udp_passthrough_bytes_intact(void) {
    /* The fan-out pump hands each raw read() straight to udp_send_chunk; prove
     * the bytes land DGE1-framed with the payload verbatim (a single frame). */
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    struct udp_sink s;
    memset(&s, 0, sizeof s);
    s.enabled = 1;
    s.fd = sv[0];
    s.destlen = 0;                 /* connected pair: dest ignored */

    const uint8_t raw[] = { 0x10, 0xB2, 0xD9, 0x00, 0x01, 0x02, 0x7E };
    udp_send_chunk(&s, raw, sizeof raw, 1 /*restart*/);

    uint8_t buf[DGE_HDR_LEN + 64];
    ssize_t n = recv(sv[1], buf, sizeof buf, 0);
    assert(n == (ssize_t)(DGE_HDR_LEN + sizeof raw));
    assert(memcmp(buf, DGE_MAGIC, 4) == 0);
    assert(buf[4] == DGE_VERSION);
    assert(buf[5] == DGE_FLAG_RESTART);        /* restart flag honored */
    uint32_t seq; memcpy(&seq, buf + 6, 4);
    assert(seq == 0);                          /* first datagram */
    uint16_t l16; memcpy(&l16, buf + 10, 2);
    assert(l16 == sizeof raw);
    assert(memcmp(buf + DGE_HDR_LEN, raw, sizeof raw) == 0);  /* bytes intact */
    close(sv[0]); close(sv[1]);
    printf("ok udp_passthrough_bytes_intact\n");
}

static void test_udp_passthrough_splits_oversized_with_seq(void) {
    /* A chunk larger than one datagram splits into MTU-bounded datagrams with
     * monotonic seq — the pump never relies on chunk==datagram. */
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    struct udp_sink s;
    memset(&s, 0, sizeof s);
    s.enabled = 1; s.fd = sv[0]; s.destlen = 0;

    size_t total = DGE_MAX_PAYLOAD + 100;      /* -> 2 datagrams */
    uint8_t *big = malloc(total);
    for (size_t i = 0; i < total; i++) big[i] = (uint8_t)(i & 0xFF);
    udp_send_chunk(&s, big, total, 0 /*not restart*/);

    uint8_t buf[DGE_HDR_LEN + DGE_MAX_PAYLOAD];
    ssize_t n0 = recv(sv[1], buf, sizeof buf, 0);
    assert(n0 == (ssize_t)(DGE_HDR_LEN + DGE_MAX_PAYLOAD));
    uint32_t seq0; memcpy(&seq0, buf + 6, 4);
    assert(seq0 == 0);
    assert(memcmp(buf + DGE_HDR_LEN, big, DGE_MAX_PAYLOAD) == 0);

    ssize_t n1 = recv(sv[1], buf, sizeof buf, 0);
    assert(n1 == (ssize_t)(DGE_HDR_LEN + 100));
    uint32_t seq1; memcpy(&seq1, buf + 6, 4);
    assert(seq1 == 1);                         /* seq advanced */
    assert(memcmp(buf + DGE_HDR_LEN, big + DGE_MAX_PAYLOAD, 100) == 0);

    free(big);
    close(sv[0]); close(sv[1]);
    printf("ok udp_passthrough_splits_oversized_with_seq\n");
}

int main(void) {
    test_source_validation_accepts_stdin();
    test_stdin_source_skips_arming();
    test_udp_passthrough_bytes_intact();
    test_udp_passthrough_splits_oversized_with_seq();
    printf("all source-stdin tests passed\n");
    return 0;
}
