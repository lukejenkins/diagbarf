/* SPDX-License-Identifier: Apache-2.0 */
/* Host unit tests for the dual-stack numeric host/port parser.
 * Build+run: make -C apps/diagbarf test  (or: make -C apps/diagbarf test-addr)
 *
 * Why this exists: the RIS-9260's eth1 is IPv6 link-local (fe80::/10, zone
 * %eth1), but every diagbarf sink was IPv4-only (struct sockaddr_in +
 * strrchr(":") port split). Neither Plane A (modem DIAG) nor Plane B (daemon
 * logs) could actually egress over the real interface until the address layer
 * spoke IPv6 with a scope id. These tests pin the numeric parser (no
 * getaddrinfo/NSS — the binary is static) and the family-aware pretty-printer.
 */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <net/if.h>

/* Pull in the always-compiled helpers (parse_hostport / sa_ntop live before
 * the framing-guarded region, so this guard drops main() + the threads). */
#define DIAGBARF_FRAMING_TEST 1
#include "../diagbarf.c"

static void test_bare_port_is_ipv4_wildcard(void) {
    struct sockaddr_storage ss;
    socklen_t slen = 0;
    assert(parse_hostport("12399", &ss, &slen, AF_INET) == 0);
    assert(ss.ss_family == AF_INET);
    assert(slen == sizeof(struct sockaddr_in));
    const struct sockaddr_in *v4 = (const struct sockaddr_in *)&ss;
    assert(v4->sin_addr.s_addr == htonl(INADDR_ANY));
    assert(ntohs(v4->sin_port) == 12399);
    printf("ok bare_port_is_ipv4_wildcard\n");
}

static void test_bare_port_honors_default_family_v6(void) {
    /* A bare port with an IPv6 default family binds the v6 wildcard [::]. */
    struct sockaddr_storage ss;
    socklen_t slen = 0;
    assert(parse_hostport("12400", &ss, &slen, AF_INET6) == 0);
    assert(ss.ss_family == AF_INET6);
    assert(slen == sizeof(struct sockaddr_in6));
    const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)&ss;
    assert(memcmp(&v6->sin6_addr, &in6addr_any, sizeof in6addr_any) == 0);
    assert(ntohs(v6->sin6_port) == 12400);
    printf("ok bare_port_honors_default_family_v6\n");
}

static void test_ipv4_addr_port(void) {
    struct sockaddr_storage ss;
    socklen_t slen = 0;
    assert(parse_hostport("192.168.7.2:12400", &ss, &slen, AF_INET) == 0);
    assert(ss.ss_family == AF_INET);
    const struct sockaddr_in *v4 = (const struct sockaddr_in *)&ss;
    struct in_addr want;
    assert(inet_pton(AF_INET, "192.168.7.2", &want) == 1);
    assert(v4->sin_addr.s_addr == want.s_addr);
    assert(ntohs(v4->sin_port) == 12400);
    printf("ok ipv4_addr_port\n");
}

static void test_ipv6_bracketed_no_zone(void) {
    struct sockaddr_storage ss;
    socklen_t slen = 0;
    assert(parse_hostport("[::1]:80", &ss, &slen, AF_INET) == 0);
    assert(ss.ss_family == AF_INET6);
    assert(slen == sizeof(struct sockaddr_in6));
    const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)&ss;
    struct in6_addr want;
    assert(inet_pton(AF_INET6, "::1", &want) == 1);
    assert(memcmp(&v6->sin6_addr, &want, sizeof want) == 0);
    assert(ntohs(v6->sin6_port) == 80);
    assert(v6->sin6_scope_id == 0);         /* no zone given */
    printf("ok ipv6_bracketed_no_zone\n");
}

static void test_ipv6_link_local_with_zone(void) {
    /* The RIS-9260 case: fe80::.../eth1. Use "lo" as a zone that always exists
     * on the test host so the if_nametoindex() path is exercised for real. */
    unsigned lo = if_nametoindex("lo");
    assert(lo != 0);                        /* sanity: the test host has "lo" */
    struct sockaddr_storage ss;
    socklen_t slen = 0;
    assert(parse_hostport("[fe80::1%lo]:12400", &ss, &slen, AF_INET) == 0);
    assert(ss.ss_family == AF_INET6);
    const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)&ss;
    struct in6_addr want;
    assert(inet_pton(AF_INET6, "fe80::1", &want) == 1);
    assert(memcmp(&v6->sin6_addr, &want, sizeof want) == 0);
    assert(ntohs(v6->sin6_port) == 12400);
    assert(v6->sin6_scope_id == lo);        /* zone resolved to lo's ifindex */
    printf("ok ipv6_link_local_with_zone\n");
}

static void test_rejects_unbracketed_ipv6(void) {
    /* Bare multi-colon token is ambiguous with addr:port — must be rejected,
     * NOT mis-parsed as host "fe80::1" port "1". */
    struct sockaddr_storage ss;
    socklen_t slen = 0;
    assert(parse_hostport("fe80::1:12400", &ss, &slen, AF_INET) == -1);
    printf("ok rejects_unbracketed_ipv6\n");
}

static void test_rejects_bad_and_oob(void) {
    struct sockaddr_storage ss;
    socklen_t slen = 0;
    assert(parse_hostport("1.2.3.4:0", &ss, &slen, AF_INET) == -1);       /* port 0 */
    assert(parse_hostport("1.2.3.4:99999", &ss, &slen, AF_INET) == -1);   /* > 65535 */
    assert(parse_hostport("[not:a:v6]:80", &ss, &slen, AF_INET) == -1);   /* bad v6 */
    assert(parse_hostport("[::1]:notaport", &ss, &slen, AF_INET) == -1);  /* bad port */
    assert(parse_hostport("[::1]", &ss, &slen, AF_INET) == -1);           /* no port */
    assert(parse_hostport("[fe80::1%nosuchif0]:80", &ss, &slen, AF_INET) == -1); /* bad zone */
    assert(parse_hostport("999.1.1.1:80", &ss, &slen, AF_INET) == -1);    /* bad v4 */
    printf("ok rejects_bad_and_oob\n");
}

static void test_sa_ntop_roundtrips(void) {
    struct sockaddr_storage ss;
    socklen_t slen = 0;
    char out[80];

    assert(parse_hostport("10.0.0.5:12399", &ss, &slen, AF_INET) == 0);
    sa_ntop(&ss, out, sizeof out);
    assert(strcmp(out, "10.0.0.5:12399") == 0);

    assert(parse_hostport("[::1]:80", &ss, &slen, AF_INET) == 0);
    sa_ntop(&ss, out, sizeof out);
    assert(strcmp(out, "[::1]:80") == 0);

    /* v6 with a zone prints the bracketed [addr%zone]:port form. */
    assert(parse_hostport("[fe80::1%lo]:12400", &ss, &slen, AF_INET) == 0);
    sa_ntop(&ss, out, sizeof out);
    /* zone renders as the interface NAME, not its index. */
    assert(strcmp(out, "[fe80::1%lo]:12400") == 0);
    printf("ok sa_ntop_roundtrips\n");
}

int main(void) {
    test_bare_port_is_ipv4_wildcard();
    test_bare_port_honors_default_family_v6();
    test_ipv4_addr_port();
    test_ipv6_bracketed_no_zone();
    test_ipv6_link_local_with_zone();
    test_rejects_unbracketed_ipv6();
    test_rejects_bad_and_oob();
    test_sa_ntop_roundtrips();
    printf("ALL addr-parse tests passed\n");
    return 0;
}
