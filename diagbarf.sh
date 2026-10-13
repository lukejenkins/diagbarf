#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# diagbarf.sh — launcher for the DIAG egress daemon.
#
# Sources /data/diagbarf/diagbarf.conf (shell KEY=VALUE, like at_tcp.sh) and
# exec's the static C daemon with derived flags. Launch flags override config;
# with no config the daemon's built-in defaults apply (TCP listener :12399 +
# UDP broadcast bridge0:12399).
#
# The daemon is the SINGLE MD-mode /dev/diag reader: it spawns the OEM
# diag_socket_log as a captive child dialing 127.0.0.1, arms the global log
# mask itself, and fans the firehose out to TCP-listen + UDP sinks. It REPLACES
# diag_collector.sh for capture (do not run both — one MD reader only).

CONF=/data/diagbarf/diagbarf.conf
[ -r "$CONF" ] && . "$CONF"

BIN="${DIAGBARF_BIN:-/data/diagbarf/services/diagbarf}"

set --

# TCP listener
if [ "${DIAG_TCP_LISTEN_ENABLE:-1}" = "0" ]; then
    set -- "$@" --no-tcp-listen
elif [ -n "$DIAG_TCP_LISTEN" ]; then
    set -- "$@" --tcp-listen "$DIAG_TCP_LISTEN"
fi

# UDP broadcast
if [ "${DIAG_UDP_BROADCAST_ENABLE:-1}" = "0" ]; then
    set -- "$@" --no-udp-broadcast
elif [ -n "$DIAG_UDP_BROADCAST" ]; then
    set -- "$@" --udp-broadcast "$DIAG_UDP_BROADCAST"
fi

# Optional sinks
[ -n "$DIAG_UDP_UNICAST" ] && set -- "$@" --udp-unicast "$DIAG_UDP_UNICAST"
[ -n "$DIAG_TCP_DIAL" ]    && set -- "$@" --tcp-dial "$DIAG_TCP_DIAL"

# Knobs
[ -n "$DIAG_MASK" ]          && set -- "$@" --mask "$DIAG_MASK"
[ "${DIAG_EXT_MSG_F3:-0}" = "1" ] && set -- "$@" --ext-msg-f3
[ "${DIAG_QSH_TRACE:-0}" = "1" ] && set -- "$@" --qsh-trace
[ -n "$DIAG_INTERNAL_PORT" ] && set -- "$@" --internal-port "$DIAG_INTERNAL_PORT"
[ -n "$DIAG_RETRY" ]         && set -- "$@" --retry "$DIAG_RETRY"
[ -n "$DIAG_SOCKET_LOG" ]    && set -- "$@" --diag-socket-log "$DIAG_SOCKET_LOG"
# Opt-in DIAG command passthrough. A bare PORT binds 127.0.0.1.
[ -n "$DIAG_CMD_LISTEN" ]    && set -- "$@" --cmd-listen "$DIAG_CMD_LISTEN"

# DIAG source: socket-log (default, captive OEM diag_socket_log), diag-dev
# (native kernel /dev/diag, zero-dependency — SDX55 M2000, no diag_socket_log), or
# hdlc-chardev (host-side jump box: serial-like CRC-HDLC DIAG chardev).
[ -n "$DIAG_SOURCE" ]        && set -- "$@" --source "$DIAG_SOURCE"
[ -n "$DIAG_DEV" ]           && set -- "$@" --diag-dev "$DIAG_DEV"

exec "$BIN" "$@"
