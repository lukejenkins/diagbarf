/* SPDX-License-Identifier: Apache-2.0 */
/* Host unit tests for per-client subscriptions (--client-filters / --keep-*),
 * part of the DIAG consumer-filtering design.
 * Build+run: make -C apps/diagbarf test   (or: make -C apps/diagbarf test-filters)
 *
 * Pins:
 *  - dpeek_frame + dfilter_matches + dframe_crc_ok against the SHARED peek
 *    vectors (tests/diag_peek_vectors.json — the same cases the Python
 *    diagmunge.framefilter runs; a -side test pins the two files equal);
 *  - the SUB {json} parser: accepted shapes, every limit, malformed input;
 *  - the per-client state machine: grace window, first-line-only SUB, later
 *    SUB replaces, oversize line;
 *  - the frame splitter: the same stream fed in every chunking yields the same
 *    filtered output (carry across reads, oversize-frame resync);
 *  - fanout_chunk over socketpairs: a full-stream client gets the input
 *    byte-identical, a filtered client exactly its frames as 7E+esc+7E, a
 *    PENDING client nothing; filtered UDP datagrams are frame-aligned. */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#define DIAGBARF_FRAMING_TEST 1
#include "../diagbarf.c"

#ifndef PEEK_VECTORS
#define PEEK_VECTORS "tests/diag_peek_vectors.json"
#endif

/* ---- tiny helpers ---- */
static char *slurp(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "FAIL cannot open %s\n", path); exit(1); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = malloc((size_t)sz + 1);
    assert(fread(b, 1, (size_t)sz, f) == (size_t)sz);
    b[sz] = 0;
    fclose(f);
    *n = (size_t)sz;
    return b;
}

static size_t unhex(const char *h, uint8_t *out)
{
    size_t n = 0;
    while (h[0] && h[0] != '"') {
        unsigned v;
        assert(sscanf(h, "%2x", &v) == 1);
        out[n++] = (uint8_t)v;
        h += 2;
    }
    return n;
}

/* Value of "key": within [p, end) as int; -1 for null; -2 when absent. */
static long json_int_field(const char *p, const char *end, const char *key)
{
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\":", key);
    const char *k = strstr(p, pat);
    if (!k || k >= end) return -2;
    k += strlen(pat);
    while (*k == ' ') k++;
    if (!strncmp(k, "null", 4)) return -1;
    if (!strncmp(k, "true", 4)) return 1;
    if (!strncmp(k, "false", 5)) return 0;
    return strtol(k, NULL, 10);
}

static int frame_yields(const struct dfilter *f, const uint8_t *esc, size_t n)
{
    struct dpeek p;
    return dpeek_frame(esc, n, &p) == 0 && dfilter_matches(f, &p) && dframe_crc_ok(esc, n);
}

/* ---- shared vectors ---- */
static void test_shared_peek_vectors(void)
{
    size_t n;
    char *js = slurp(PEEK_VECTORS, &n);
    char *end = js + n;

    /* The vectors' fixed filter, parsed by the SUB parser itself. */
    char *fo = strstr(js, "\"filter\":");
    assert(fo);
    char *ob = strchr(fo, '{'), *cb = strchr(ob, '}');
    struct dfilter f;
    const char *err = NULL;
    assert(parse_sub_json(ob, (size_t)(cb - ob + 1), &f, &err) == 0);

    int count = 0;
    char *v = strstr(js, "\"vectors\":");
    assert(v);
    for (char *nm = strstr(v, "\"name\":"); nm; ) {
        char *next = strstr(nm + 1, "\"name\":");
        char *vend = next ? next : end;
        char name[64];
        assert(sscanf(nm, "\"name\": \"%63[^\"]\"", name) == 1);
        char *eh = strstr(nm, "\"escaped\": \"");
        assert(eh && eh < vend);
        uint8_t esc[512];
        size_t elen = unhex(eh + 12, esc);

        char *pk = strstr(nm, "\"peek\":");
        assert(pk && pk < vend);
        pk += 7;
        while (*pk == ' ') pk++;
        struct dpeek got;
        int rc = dpeek_frame(esc, elen, &got);
        if (!strncmp(pk, "null", 4)) {
            if (rc != -1) { fprintf(stderr, "FAIL %s: peek should be null\n", name); exit(1); }
        } else {
            char *pend = strchr(pk, '}');
            long op = json_int_field(pk, pend, "opcode");
            long inner = json_int_field(pk, pend, "inner_opcode");
            long code = json_int_field(pk, pend, "log_code");
            if (rc != 0 || got.opcode != op || got.inner != inner || got.log_code != code) {
                fprintf(stderr, "FAIL %s: peek rc=%d op=%d inner=%d code=%d "
                        "want op=%ld inner=%ld code=%ld\n", name, rc, got.opcode,
                        got.inner, got.log_code, op, inner, code);
                exit(1);
            }
        }
        long want_m = json_int_field(nm, vend, "matches");
        long want_y = json_int_field(nm, vend, "yields");
        int m = rc == 0 && dfilter_matches(&f, &got);
        int y = frame_yields(&f, esc, elen);
        if (m != want_m || y != want_y) {
            fprintf(stderr, "FAIL %s: matches=%d yields=%d want %ld/%ld\n",
                    name, m, y, want_m, want_y);
            exit(1);
        }
        count++;
        nm = next;
    }
    assert(count >= 18);    /* the original vectors file had 18 cases */
    free(js);
    printf("ok shared_peek_vectors (%d cases)\n", count);
}

/* ---- SUB parser ---- */
static int sub(const char *s, struct dfilter *f, const char **err)
{
    return parse_sub_json(s, strlen(s), f, err);
}

static void test_sub_parser_accepts(void)
{
    struct dfilter f;
    const char *err = NULL;
    assert(sub("{\"log_codes\":[5239,5238,5238],\"opcodes\":[],\"f3\":false,\"events\":false}", &f, &err) == 0);
    assert(f.active && f.ncodes == 2 && f.codes[0] == 5238 && f.codes[1] == 5239);
    assert(!f.f3 && !f.events && f.nopcodes == 0);
    assert(sub("  { }  ", &f, &err) == 0);       /* empty object: matches nothing */
    struct dpeek p = { 0x10, -1, 0x1476 };
    assert(!dfilter_matches(&f, &p));
    assert(sub("{\"opcodes\":[16, 152],\"f3\":true}", &f, &err) == 0);
    assert(f.all_logs);
    struct dpeek ev = { 0x60, -1, -1 }, f3w = { 0x98, 0x79, -1 };
    assert(dfilter_matches(&f, &p));             /* 0x10 as opcode = every LOG */
    assert(!dfilter_matches(&f, &ev));
    assert(dfilter_matches(&f, &f3w));
    assert(sub("{\"log_codes\":[65535,0]}", &f, &err) == 0);
    assert(f.ncodes == 2 && f.codes[0] == 0 && f.codes[1] == 65535);
    printf("ok sub_parser_accepts\n");
}

static void test_sub_parser_rejects(void)
{
    struct dfilter f;
    memset(&f, 0x5A, sizeof f);
    struct dfilter before = f;
    const char *err = NULL;
    const char *bad[] = {
        "", "[]", "{", "{\"log_codes\":[1,]}", "{\"log_codes\":[\"0x1476\"]}",
        "{\"log_codes\":[-1]}", "{\"log_codes\":[65536]}", "{\"log_codes\":[1.5]}",
        "{\"log_codes\":[1e3]}", "{\"log_codes\":[01]}", "{\"opcodes\":[256]}",
        "{\"f3\":1}", "{\"f3\":\"true\"}", "{\"logcodes\":[1]}", "{\"log_codes\":[1]} x",
        "{\"log_codes\":[1]", "{\"lo\\\"g\":[1]}", "{\"f3\":true,}", "{\"f3\" true}",
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        err = NULL;
        if (sub(bad[i], &f, &err) != -1 || !err) {
            fprintf(stderr, "FAIL accepted malformed SUB: %s\n", bad[i]);
            exit(1);
        }
        assert(!memcmp(&f, &before, sizeof f));   /* untouched on failure */
    }
    /* limits: 256 codes ok, 257 rejected; 32 opcodes ok, 33 rejected */
    char buf[8192];
    for (int lim = 256; lim <= 257; lim++) {
        size_t o = (size_t)snprintf(buf, sizeof buf, "{\"log_codes\":[");
        for (int i = 0; i < lim; i++)
            o += (size_t)snprintf(buf + o, sizeof buf - o, "%s%d", i ? "," : "", i);
        snprintf(buf + o, sizeof buf - o, "]}");
        assert(sub(buf, &f, &err) == (lim == 256 ? 0 : -1));
    }
    assert(f.ncodes == 256);
    for (int lim = 32; lim <= 33; lim++) {
        size_t o = (size_t)snprintf(buf, sizeof buf, "{\"opcodes\":[");
        for (int i = 0; i < lim; i++)
            o += (size_t)snprintf(buf + o, sizeof buf - o, "%s%d", i ? "," : "", i);
        snprintf(buf + o, sizeof buf - o, "]}");
        assert(sub(buf, &f, &err) == (lim == 32 ? 0 : -1));
    }
    printf("ok sub_parser_rejects\n");
}

static void test_keep_list(void)
{
    uint16_t v[4];
    int n = 0;
    assert(parse_keep_list("0x1476,5239", 0xFFFF, v, 4, &n) == 0 && n == 2);
    assert(v[0] == 0x1476 && v[1] == 5239);
    n = 0;
    assert(parse_keep_list("0x100", 0xFF, v, 4, &n) == -1);
    n = 0;
    assert(parse_keep_list("1,", 0xFFFF, v, 4, &n) == -1);
    n = 0;
    assert(parse_keep_list("-1", 0xFFFF, v, 4, &n) == -1);
    n = 0;
    assert(parse_keep_list("1,2,3,4,5", 0xFFFF, v, 4, &n) == -1);
    n = 0;
    assert(parse_keep_list("", 0xFFFF, v, 4, &n) == -1);
    printf("ok keep_list\n");
}

/* ---- client state machine ---- */
static int feed_str(struct client_sub *cs, const char *s, const char **err)
{
    return client_sub_input(cs, (const uint8_t *)s, strlen(s), err);
}

static void test_client_state_machine(void)
{
    static struct client_sub cs;
    const char *err;

    /* flag off: full stream from accept, input ignored */
    client_sub_init(&cs, 0, 1000);
    assert(cs.state == CSUB_FULL);
    assert(feed_str(&cs, "SUB {\"f3\":true}\n", &err) == 0 && cs.state == CSUB_FULL);

    /* no SUB within the grace window -> full stream */
    client_sub_init(&cs, 1, 1000);
    assert(cs.state == CSUB_PENDING);
    client_sub_tick(&cs, 1499, 500);
    assert(cs.state == CSUB_PENDING);
    client_sub_tick(&cs, 1500, 500);
    assert(cs.state == CSUB_FULL);
    assert(feed_str(&cs, "SUB {\"f3\":true}\n", &err) == 0 && cs.state == CSUB_FULL);

    /* SUB split across reads, CRLF tolerated; later SUB replaces */
    client_sub_init(&cs, 1, 0);
    assert(feed_str(&cs, "SUB {\"log_co", &err) == 0 && cs.state == CSUB_PENDING);
    assert(feed_str(&cs, "des\":[5238]}\r\n", &err) == 0 && cs.state == CSUB_FILTERED);
    assert(cs.f.ncodes == 1 && cs.f.codes[0] == 5238 && cs.nsub == 1);
    client_sub_tick(&cs, 100000, 500);            /* FILTERED is not timed out */
    assert(cs.state == CSUB_FILTERED);
    assert(feed_str(&cs, "hello\n", &err) == 0 && cs.state == CSUB_FILTERED);
    assert(feed_str(&cs, "SUB {\"events\":true}\n", &err) == 0);
    assert(cs.f.ncodes == 0 && cs.f.events && cs.nsub == 2);

    /* first line not a SUB -> full stream */
    client_sub_init(&cs, 1, 0);
    assert(feed_str(&cs, "HELLO\nSUB {\"f3\":true}\n", &err) == 0 && cs.state == CSUB_FULL);

    /* malformed SUB -> error (caller sends ERR and drops) */
    client_sub_init(&cs, 1, 0);
    err = NULL;
    assert(feed_str(&cs, "SUB {\"log_codes\":[\"0x1476\"]}\n", &err) == -1 && err);

    /* line > 4 KiB -> error, never an overflow */
    client_sub_init(&cs, 1, 0);
    char big[SUB_LINE_MAX + 8];
    memset(big, 'x', sizeof big);
    err = NULL;
    assert(client_sub_input(&cs, (const uint8_t *)big, sizeof big, &err) == -1);
    assert(!strcmp(err, "line too long"));
    printf("ok client_state_machine\n");
}

/* ---- synthetic stream ---- */
static size_t make_frame(uint8_t *out, uint8_t op, uint16_t code, int wrap, int bad_crc,
                         int pad)
{
    uint8_t raw[600];
    size_t n = 0;
    if (wrap) {
        uint8_t w[8] = { 0x98, 1, 0, 0, 1, 0, 0, 0 };
        memcpy(raw, w, 8);
        n = 8;
    }
    raw[n++] = op;
    if (op == 0x10) {
        raw[n++] = 0;
        raw[n++] = 0x18; raw[n++] = 0;
        raw[n++] = 0x18; raw[n++] = 0;
        raw[n++] = (uint8_t)code; raw[n++] = (uint8_t)(code >> 8);
    }
    for (int i = 0; i < pad; i++)
        raw[n++] = (uint8_t)(i * 37 + code);   /* includes 7E/7D bytes */
    uint16_t c = crc16(raw, n);
    if (bad_crc) c ^= 0x5555;
    raw[n++] = (uint8_t)c;
    raw[n++] = (uint8_t)(c >> 8);
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        if (raw[i] == 0x7E || raw[i] == 0x7D) {
            out[o++] = 0x7D;
            out[o++] = raw[i] ^ 0x20;
        } else {
            out[o++] = raw[i];
        }
    }
    return o;
}

/* Stream of frames (each followed by 7E), plus the expected filtered output
 * for filter {log_codes:[0x1476], f3:true}. */
static size_t build_stream(uint8_t *s, uint8_t *want, size_t *wantn)
{
    size_t n = 0, w = 0;
    s[n++] = 0x7E;
    for (int i = 0; i < 400; i++) {
        uint8_t fr[1400];
        int kind = i % 7;
        size_t fl;
        int keep;
        switch (kind) {
        case 0: fl = make_frame(fr, 0x10, 0x1476, 0, 0, i % 50); keep = 1; break;
        case 1: fl = make_frame(fr, 0x10, 0xB0C0, 0, 0, i % 90); keep = 0; break;
        case 2: fl = make_frame(fr, 0x10, 0x1476, 1, 0, i % 60); keep = 1; break;
        case 3: fl = make_frame(fr, 0x79, 0, 0, 0, i % 200); keep = 1; break;
        case 4: fl = make_frame(fr, 0x60, 0, 0, 0, i % 20); keep = 0; break;
        case 5: fl = make_frame(fr, 0x10, 0x1476, 0, 1, 10); keep = 0; break;  /* bad CRC */
        default: fl = make_frame(fr, 0x98, 0, 0, 0, 3 + i % 500); keep = 0; break;
        }
        memcpy(s + n, fr, fl);
        n += fl;
        s[n++] = 0x7E;
        if (i % 11 == 0) s[n++] = 0x7E;   /* empty elements are dropped */
        if (keep) {
            want[w++] = 0x7E;
            memcpy(want + w, fr, fl);
            w += fl;
            want[w++] = 0x7E;
        }
    }
    *wantn = w;
    return n;
}

static struct dsplit g_split;
static struct dframe g_frames[SPLIT_MAX_FRAMES];
static uint8_t g_out[FILT_OUT_CAP];

static void test_splitter_any_chunking(void)
{
    static uint8_t s[400 * 1400], want[400 * 1400], got[400 * 1400];
    size_t wantn, n = build_stream(s, want, &wantn);
    struct dfilter f;
    const char *err;
    assert(sub("{\"log_codes\":[5238],\"f3\":true}", &f, &err) == 0);
    size_t sizes[] = { 1, 2, 3, 7, 31, 32, 33, 1399, 4096, 65536, 0 /* random */ };
    srand(5532);
    for (size_t k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
        dsplit_reset(&g_split);
        size_t gn = 0, off = 0;
        while (off < n) {
            size_t c = sizes[k] ? sizes[k] : (size_t)(1 + rand() % 9000);
            if (c > n - off) c = n - off;
            size_t tail, nf;
            int had;
            nf = dsplit_feed(&g_split, s + off, c, g_frames, SPLIT_MAX_FRAMES, &tail, &had);
            size_t len = dfilter_render(&f, g_frames, nf, g_out);
            memcpy(got + gn, g_out, len);
            gn += len;
            dsplit_commit(&g_split, s + off, c, tail, had);
            off += c;
        }
        if (gn != wantn || memcmp(got, want, wantn)) {
            fprintf(stderr, "FAIL splitter chunk=%zu: got %zu bytes want %zu\n",
                    sizes[k], gn, wantn);
            exit(1);
        }
    }
    printf("ok splitter_any_chunking (%zu bytes kept of %zu)\n", wantn, n);
}

static void test_splitter_oversize_resync(void)
{
    /* A >64 KiB run with no 0x7E is dropped whole, then the next frame is
     * delivered — never an overflow, never a half-frame. */
    static uint8_t s[SPLIT_CARRY_CAP + 4096];
    struct dfilter f;
    const char *err;
    assert(sub("{\"log_codes\":[5238]}", &f, &err) == 0);
    dsplit_reset(&g_split);
    g_split.overflows = 0;
    uint8_t fr[64];
    size_t fl = make_frame(fr, 0x10, 0x1476, 0, 0, 4);
    size_t gn = 0;
    memset(s, 0x10, sizeof s);
    for (int pass = 0; pass < 3; pass++) {      /* 3 x ~68 KiB of junk */
        size_t tail, nf;
        int had;
        nf = dsplit_feed(&g_split, s, sizeof s, g_frames, SPLIT_MAX_FRAMES, &tail, &had);
        assert(nf == 0);
        dsplit_commit(&g_split, s, sizeof s, tail, had);
    }
    assert(g_split.overflows >= 1 && g_split.discarding);
    uint8_t tailb[80];
    size_t tn = 0;
    tailb[tn++] = 0x10;                 /* end of the junk frame */
    tailb[tn++] = 0x7E;
    memcpy(tailb + tn, fr, fl);
    tn += fl;
    tailb[tn++] = 0x7E;
    size_t tail, nf;
    int had;
    nf = dsplit_feed(&g_split, tailb, tn, g_frames, SPLIT_MAX_FRAMES, &tail, &had);
    gn = dfilter_render(&f, g_frames, nf, g_out);
    dsplit_commit(&g_split, tailb, tn, tail, had);
    assert(gn == fl + 2 && !memcmp(g_out + 1, fr, fl));
    printf("ok splitter_oversize_resync\n");
}

/* ---- fanout over socketpairs ---- */
static size_t drain(int fd, uint8_t *buf, size_t cap)
{
    size_t n = 0;
    for (;;) {
        ssize_t r = recv(fd, buf + n, cap - n, MSG_DONTWAIT);
        if (r <= 0) break;
        n += (size_t)r;
    }
    return n;
}

static void test_fanout_full_filtered_pending(void)
{
    static uint8_t s[400 * 1400], want[400 * 1400], got[400 * 1400];
    size_t wantn, n = build_stream(s, want, &wantn);
    int full[2], filt[2], pend[2], udp[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, full) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, filt) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pend) == 0);
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, udp) == 0);
    int big = 8 << 20;
    for (int i = 0; i < 2; i++) {
        setsockopt(full[i], SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
        setsockopt(full[i], SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
        setsockopt(filt[i], SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
        setsockopt(filt[i], SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
        setsockopt(udp[i], SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
        setsockopt(udp[i], SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    }
    static struct client_sub subs[3];
    int clients[3] = { full[0], filt[0], pend[0] };
    client_sub_init(&subs[0], 1, 0);
    client_sub_init(&subs[1], 1, 0);
    client_sub_init(&subs[2], 1, 0);
    const char *err;
    assert(feed_str(&subs[0], "not a sub\n", &err) == 0 && subs[0].state == CSUB_FULL);
    assert(feed_str(&subs[1], "SUB {\"log_codes\":[5238],\"f3\":true}\n", &err) == 0);

    struct udp_sink us;
    memset(&us, 0, sizeof us);
    us.enabled = 1;
    us.fd = udp[0];
    struct udp_sink off;
    memset(&off, 0, sizeof off);
    struct dfilter keep_u, none;
    memset(&none, 0, sizeof none);
    assert(sub("{\"log_codes\":[5238],\"f3\":true}", &keep_u, &err) == 0);
    struct tcp_out dial;
    memset(&dial, 0, sizeof dial);
    dial.fd = -1;

    struct fanout fo;
    memset(&fo, 0, sizeof fo);
    fo.clients = clients;
    fo.subs = subs;
    fo.nclients = 3;
    fo.dial = &dial;
    fo.bcast = &off;
    fo.unicast = &us;
    fo.keep_bcast = &none;
    fo.keep_unicast = &keep_u;
    fo.keep_dial = &none;
    fo.splitting = 1;
    dsplit_reset(&g_split);
    fo.split = &g_split;
    fo.frames = g_frames;
    fo.out = g_out;
    size_t o = 0;
    int first = 1;
    while (o < n) {
        size_t c = n - o < 3000 ? n - o : 3000;
        fanout_chunk(&fo, s + o, c, first);
        first = 0;
        o += c;
    }
    size_t gn = drain(full[1], got, sizeof got);
    assert(gn == n && !memcmp(got, s, n));               /* byte-identical */
    gn = drain(filt[1], got, sizeof got);
    assert(gn == wantn && !memcmp(got, want, wantn));     /* exactly its frames */
    assert(drain(pend[1], got, sizeof got) == 0);         /* nothing while PENDING */

    /* filtered UDP: DGE1 datagrams, each payload ends on a frame boundary
     * unless one unit alone exceeds a datagram; concatenation == want. */
    size_t un = 0;
    int ndg = 0, restart_seen = 0;
    for (;;) {
        uint8_t dg[DGE_HDR_LEN + DGE_MAX_PAYLOAD];
        ssize_t r = recv(udp[1], dg, sizeof dg, MSG_DONTWAIT);
        if (r <= 0) break;
        assert(!memcmp(dg, DGE_MAGIC, 4));
        uint16_t l16;
        memcpy(&l16, dg + 10, 2);
        assert((size_t)r == (size_t)DGE_HDR_LEN + l16 && l16 <= DGE_MAX_PAYLOAD);
        if (ndg == 0) restart_seen = dg[5] & DGE_FLAG_RESTART;
        else assert(!(dg[5] & DGE_FLAG_RESTART));
        if (l16 < DGE_MAX_PAYLOAD)
            assert(dg[DGE_HDR_LEN] == 0x7E && dg[DGE_HDR_LEN + l16 - 1] == 0x7E);
        memcpy(got + un, dg + DGE_HDR_LEN, l16);
        un += l16;
        ndg++;
    }
    assert(restart_seen);
    assert(un == wantn && !memcmp(got, want, wantn));
    printf("ok fanout_full_filtered_pending (%d filtered datagrams)\n", ndg);
}

static void test_compact_moves_subs(void)
{
    static struct client_sub subs[4];
    int c[4] = { 10, -1, 12, 13 };
    for (int i = 0; i < 4; i++) client_sub_init(&subs[i], 1, i);
    subs[2].state = CSUB_FILTERED;
    subs[3].state = CSUB_FULL;
    assert(compact_clients(c, subs, 4) == 3);
    assert(c[0] == 10 && c[1] == 12 && c[2] == 13 && c[3] == -1);
    assert(subs[1].state == CSUB_FILTERED && subs[1].accepted_ms == 2);
    assert(subs[2].state == CSUB_FULL && subs[2].accepted_ms == 3);
    printf("ok compact_moves_subs\n");
}

int main(void)
{
    crc16_init();
    test_shared_peek_vectors();
    test_sub_parser_accepts();
    test_sub_parser_rejects();
    test_keep_list();
    test_client_state_machine();
    test_splitter_any_chunking();
    test_splitter_oversize_resync();
    test_fanout_full_filtered_pending();
    test_compact_moves_subs();
    printf("all client-filter tests passed\n");
    return 0;
}
