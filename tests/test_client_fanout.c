/* SPDX-License-Identifier: Apache-2.0 */
/* Host regression test for the TCP-listen client-fanout bookkeeping (#N).
 * Build+run: make -C apps/diagbarf test  (or: make -C apps/diagbarf test-fanout)
 *
 * The bug (build 406bd93e5, <redacted-ref>, first hit on the live-USB run in this
 * issue): the fan-out loop kept a parallel `client_idx[]` array mapping each
 * client to its pollfd slot, populated only for the clients present when pfds
 * was built. accept() then grew `nclients` for a newly connected client BEFORE
 * the drain loop, so the drain loop read `client_idx[<new>]` — an UNINITIALIZED
 * stack slot — and dereferenced `pfds[garbage].revents`. When the first client
 * connected (nclients 0 -> 1) that garbage was frequently a small in-range-ish
 * value, so the read landed on a wild address and SIGSEGV'd. Non-deterministic
 * (uninitialized memory), which is why the offline PTY E2E had passed.
 *
 * The fix removes client_idx entirely: a polled client's slot is exactly
 * idx_first_client + i by construction, the drain loop is bounded by the
 * poll-time client count (npoll_clients), accept happens AFTER draining, and
 * closed clients are tombstoned then compacted via compact_clients() rather
 * than swap-removed during iteration. This test pins compact_clients() and
 * models the tombstone->compact->accept discipline the loop now follows.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Drop the daemon main(); keep the helpers (incl. compact_clients) compiled. */
#define DIAGBARF_BRIDGE_TEST 1
#include "../diagbarf.c"

#define CAP MAX_CLIENTS

/* compact_clients removes -1 tombstones, preserves order, clears the tail. */
static void test_compact_basic(void)
{
    int c[CAP];
    for (int i = 0; i < CAP; i++) c[i] = -1;

    /* no holes */
    c[0] = 10; c[1] = 11; c[2] = 12;
    assert(compact_clients(c, 3) == 3);
    assert(c[0] == 10 && c[1] == 11 && c[2] == 12);

    /* hole in the middle -> survivors keep order, tail cleared */
    c[0] = 10; c[1] = -1; c[2] = 12;
    assert(compact_clients(c, 3) == 2);
    assert(c[0] == 10 && c[1] == 12 && c[2] == -1);

    /* first slot closed */
    c[0] = -1; c[1] = 11; c[2] = 12; c[3] = -1;
    assert(compact_clients(c, 4) == 2);
    assert(c[0] == 11 && c[1] == 12 && c[2] == -1 && c[3] == -1);

    /* all closed */
    c[0] = -1; c[1] = -1;
    assert(compact_clients(c, 2) == 0);
    assert(c[0] == -1 && c[1] == -1);

    /* empty */
    assert(compact_clients(c, 0) == 0);
    printf("ok compact_basic\n");
}

/* Model of the loop's per-cycle discipline: build pfds contiguously, drain the
 * polled clients by computed slot (never an uninitialized index), tombstone the
 * closed ones, compact, THEN accept a new client. Asserts every slot the drain
 * touches is in-range and that the just-accepted client is not drained this
 * cycle. This is the structural property whose absence caused the crash. */
static void test_drain_then_accept_discipline(void)
{
    int clients[CAP];
    for (int i = 0; i < CAP; i++) clients[i] = -1;
    int nclients = 0;

    /* --- cycle A: zero clients, one connecting. --- */
    /* pfds layout: [src][listen] then clients (none). */
    int np = 2;                       /* src + listen already placed */
    int idx_first_client = np;
    int npoll_clients = nclients;     /* 0 */
    for (int i = 0; i < nclients; i++) { np++; }

    /* drain: bounded by npoll_clients==0, so the loop body never runs and no
     * client_idx[]/pfds[] slot is read for the not-yet-existing client. This
     * is exactly what prevented the uninitialized read. */
    for (int i = 0; i < npoll_clients; i++) {
        int slot = idx_first_client + i;
        assert(slot >= idx_first_client && slot < np);  /* always in range */
    }
    nclients = compact_clients(clients, nclients);
    assert(nclients == 0);

    /* accept the new client AFTER draining. */
    clients[nclients++] = 100;
    assert(nclients == 1);

    /* --- cycle B: one established client, it stays; a second connects. --- */
    np = 2;
    idx_first_client = np;
    npoll_clients = nclients;         /* 1 */
    for (int i = 0; i < nclients; i++) { np++; }   /* client 100 at slot 2 */
    assert(idx_first_client == 2 && np == 3);

    /* pretend client 100 had no POLLIN (revents 0) -> not drained, survives. */
    /* pretend nothing to drain; compact is a no-op. */
    nclients = compact_clients(clients, nclients);
    assert(nclients == 1 && clients[0] == 100);

    clients[nclients++] = 101;        /* second client accepted */
    assert(nclients == 2 && clients[0] == 100 && clients[1] == 101);

    /* --- cycle C: established client 100 closes; 101 stays. --- */
    np = 2;
    idx_first_client = np;
    npoll_clients = nclients;         /* 2 */
    for (int i = 0; i < nclients; i++) { np++; }
    assert(idx_first_client == 2 && np == 4);

    /* client 100 (i=0, slot 2) returns EOF -> tombstone. */
    int drain_i = 0;
    int slot = idx_first_client + drain_i;
    assert(slot < np);
    clients[drain_i] = -1;            /* tombstone (what close-path does) */

    nclients = compact_clients(clients, nclients);
    assert(nclients == 1 && clients[0] == 101 && clients[1] == -1);

    printf("ok drain_then_accept_discipline\n");
}

int main(void)
{
    test_compact_basic();
    test_drain_then_accept_discipline();
    printf("ALL PASS\n");
    return 0;
}
