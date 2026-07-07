/* SPDX-License-Identifier: Apache-2.0 */
/* Host regression test for the diag-dev bridge SIGTERM-teardown wedge (#N).
 * Build+run: make -C apps/diagbarf test   (or: make -C apps/diagbarf test-bridge)
 *
 * The bug (build 475bbfc94-dirty, <redacted-ref>): the diag-dev bridge thread
 * blocked in a bare read() on /dev/diag with no wakeup path, so a SIGTERM-set
 * g_stop was never observed and the main thread's pthread_join() hung forever
 * (required kill -9, which risks leaving /dev/diag in MEMORY_DEVICE mode).
 *
 * The committed native-bridge fix gives the thread an interruptible wait: it
 * poll()s diag_fd + the caller socketpair with a 1s timeout and checks g_stop
 * each iteration (g_stop wakeup), AND treats EOF on the caller-closed
 * socketpair as a stop (close(src) wakeup — main's teardown path).
 *
 * These tests pin BOTH wakeup paths using plain socketpairs in place of
 * /dev/diag — no hardware, no kernel diagchar. A SIGALRM watchdog converts a
 * regressed (wedging) bridge into a loud test failure instead of a hung run.
 */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <signal.h>

/* Keep diagdev_bridge compiled but drop the daemon main(). */
#define DIAGBARF_BRIDGE_TEST 1
#include "../diagbarf.c"

/* If a join wedges, the bridge has regressed — fail loudly rather than hang
 * the whole test run forever. alarm()/SIGALRM is portable (macOS + Linux). */
static void on_alarm(int s) {
    (void)s;
    static const char m[] =
        "TIMEOUT: diagdev_bridge wedged — SIGTERM teardown regression (#N)\n";
    (void)!write(2, m, sizeof m - 1);
    _exit(1);
}

/* Spawn the bridge over two socketpairs standing in for /dev/diag and the
 * caller `src` side. The bridge owns + closes its own ends (dp[1]/sp[1]); the
 * test owns dp[0] (diag peer) and sp[0] (caller src). */
static pthread_t spawn_bridge(int *caller_src, int *diag_peer) {
    int sp[2], dp[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);   /* sp[0]=caller, sp[1]=bridge */
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, dp) == 0);   /* dp[1]=bridge diag_fd */
    struct diagdev_ctx *c = malloc(sizeof *c);
    assert(c != NULL);
    c->diag_fd = dp[1];   /* bridge owns + closes this */
    c->sp_fd   = sp[1];   /* bridge owns + closes this */
    pthread_t t;
    assert(pthread_create(&t, NULL, diagdev_bridge, c) == 0);
    *caller_src = sp[0];
    *diag_peer  = dp[0];
    return t;
}

/* Wakeup path 1: the SIGTERM handler sets g_stop while both fds are idle.
 * The 1s poll tick must observe it and exit (line 491). */
static void test_bridge_exits_on_gstop(void) {
    g_stop = 0;
    int caller_src, diag_peer;
    pthread_t t = spawn_bridge(&caller_src, &diag_peer);
    usleep(150 * 1000);   /* let it settle into poll() with both fds idle */
    g_stop = 1;           /* what on_signal() does on SIGTERM/SIGINT */
    signal(SIGALRM, on_alarm);
    alarm(3);             /* generous vs the 1s poll timeout */
    pthread_join(t, NULL);
    alarm(0);
    close(caller_src);
    close(diag_peer);
    printf("ok bridge_exits_on_gstop\n");
}

/* Wakeup path 2: main's teardown close(src) (g_stop NOT yet set on this tick).
 * EOF on the bridge's socketpair end must break the loop immediately. */
static void test_bridge_exits_on_src_close(void) {
    g_stop = 0;
    int caller_src, diag_peer;
    pthread_t t = spawn_bridge(&caller_src, &diag_peer);
    usleep(150 * 1000);
    close(caller_src);    /* main: close(src) — bridge sp_fd read() returns 0 */
    signal(SIGALRM, on_alarm);
    alarm(3);
    pthread_join(t, NULL);
    alarm(0);
    close(diag_peer);
    printf("ok bridge_exits_on_src_close\n");
}

int main(void) {
    test_bridge_exits_on_gstop();
    test_bridge_exits_on_src_close();
    printf("ALL PASS\n");
    return 0;
}
