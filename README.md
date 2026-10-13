# diagbarf

**An on-device Qualcomm DIAG egress daemon.** `diagbarf` gets the raw cellular
diagnostic firehose *off* your modem and onto the network. It runs on the modem's
own application processor, arms the global DIAG log mask itself, and fans the
resulting raw HDLC stream out to as many network sinks as you want, at once.

It's a small (~1400 lines), static, self-contained C daemon meant for hackers,
researchers, and cellular enthusiasts who want their modem's DIAG stream
somewhere they can actually work with it. In its `diag-dev` mode it runs as a
single static binary with no external dependencies.

```
 modem AP ── diagbarf ─┬─▶ TCP listener  (a collector dials in)   raw HDLC
                       ├─▶ UDP broadcast (whole LAN)              DGE1 datagrams
                       ├─▶ UDP unicast   (one host)              DGE1 datagrams
                       └─▶ TCP dial-out  (push to a collector)   raw HDLC
```

| Sink | Framing | Direction | Default |
|------|---------|-----------|---------|
| TCP listener `:12399` | raw HDLC, multi-client | collector **dials in** | **ON** |
| UDP broadcast → LAN iface `:12399` | DGE1 seq-framed | device → LAN | **ON** |
| UDP unicast → `host:port` | DGE1 seq-framed | device → host | opt |
| TCP dial-out → `host:port` | raw HDLC | device → collector | opt |

The output is **open and documented** (see [Wire formats](#wire-formats) below),
so you can point your own consumer at it — a capture script, a live decoder, a
`tshark` capture, or whatever you build.

## Why one reader that fans out

The Qualcomm DIAG transport exposes exactly **one** memory-device (MD) consumer
slot. Two MD streamers collide on the shared global `DIAG_LOG_CONFIG_F` mask and
steal each other's buffer bytes — broken HDLC for both. So there must be exactly
**one** MD reader; `diagbarf` is it, and it fans out internally to every sink.
(DCI recorders like `qdiagd` are unaffected — they get private filtered copies.)

That single-reader constraint is *the* reason a fan-out daemon exists instead of
just running several capture tools side by side: you can't. diagbarf owns the one
slot and shares the firehose.

## Source modes — how it gets the DIAG stream

Pick with `--source` (or `DIAG_SOURCE=` in `diagbarf.conf`):

| `--source` | How it reads DIAG | Good for | Deps |
|------------|-------------------|----------|------|
| `socket-log` (default) | spawns the OEM `diag_socket_log` as a captive child on `127.0.0.1`, arms the mask over that socket | devices that ship `diag_socket_log` | the OEM binary + its libs |
| `diag-dev` | opens the kernel `/dev/diag` itself (`DIAG_IOCTL_SWITCH_LOGGING` → `MEMORY_DEVICE`) via an in-process bridge that presents a raw-HDLC `socketpair` to the fan-out core | devices with `/dev/diag` and **no** vendor tooling | **none** (one static binary) |
| `hdlc-chardev` | opens a serial-like **CRC-HDLC DIAG chardev** directly (`/dev/mhi_DIAG` on PCIe/MHI, `/dev/ttyUSBx` on USB) and uses the fd as the transport | a **host/jump-box** with an attached modem exposing DIAG at a chardev | **none** (one static host binary) |
| `usbfs` | claims the modem's DIAG **USB interface over usbfs** (`USBDEVFS_CLAIMINTERFACE` + `USBDEVFS_BULK` on `/dev/bus/usb/BBB/DDD`) via an in-process bridge presenting a raw-HDLC `socketpair` to the fan-out core; auto-finds the device by VID:PID through sysfs | a device whose DIAG is a **USB composite with no chardev** (kernel lacks `qcserial`/`option`), e.g. the Kapsch **RIS-9260** RSU's MDM9150 | **none** (one static binary) |
| `stdin` | reads an **ALREADY-ARMED** raw-HDLC stream from fd 0 and only fans out — opens no DIAG transport and does **not** arm; EOF = upstream exited → clean shutdown | a box where the DIAG owner can't egress, so another tool arms + pipes in, e.g. CARCOM-G1: `diaggulp … -o - \| diagbarf --source stdin --udp-unicast H:P` | **none** (arming is upstream) |

**`diag-dev` is the zero-dependency path.** It bundles the diagchar transport
(type-`0x20` framing; all-or-nothing `write()`; MD reads are `[type][num_data]`
plus per-message `[len][HDLC]`) directly in the daemon, so a device that ships no
vendor DIAG binary still works with nothing but this one static executable.

**`hdlc-chardev` runs diagbarf on a jump box, not on the modem.** The modem
exposes the same DIAG firehose at a serial-like chardev that already speaks full
HDLC with a CRC-16 FCS in both directions — so it *is* the transport. diagbarf
opens it (raw termios for a real tty; a bare raw fd for MHI chardevs, which
aren't ttys) and drives mask-arm + fan-out over it. This replaces a three-process
`socat`/PTY + external-bridge setup with one self-versioned binary. The key
detail: config commands (mask + F3 enable) **must** carry the HDLC CRC, so the
handshake that some CRC-less bridges silently drop works here because diagbarf's
framer always appends the FCS.

**`usbfs` runs on a host whose kernel gives the modem no DIAG chardev at all.**
On the Kapsch RIS-9260 RSU (i686 Debian 9, kernel 4.9, no `qcserial`/`option`),
the MDM9150 is a USB composite (`05c6:90f0`) whose DIAG endpoint is reachable
only by claiming **interface 4** over usbfs and issuing `USBDEVFS_BULK` transfers
(IN `0x85` / OUT `0x03`). Like `hdlc-chardev`, the USB DIAG interface already
speaks full CRC-HDLC in both directions, so a bridge thread just relays raw bytes
between the bulk endpoints and a `socketpair` — mask-arm + fan-out are unchanged.
Two details are load-bearing: the `USBDEVFS_BULK` ioctl number is **derived from
`sizeof`** so the 32-bit RSU and a 64-bit build host each get the right magic
(the struct's trailing pointer changes its size, hence the ioctl number, per
arch); and every outbound frame is **opcode-gated to `0x73`/`0x7D` only** at the
usbfs boundary, so a slip to `0x27` (NV write) or `0x29` (control/reset) can
never reach this modem — the project's one healthy MDM9150. The one exception is
the loopback [`--cmd-listen`](#standard-diag-command-passthrough---cmd-listen-loopback)
channel: the gate also admits exactly the passthrough allow-list (EFS2, NV
read/write, read-only identity); `0x29` and FTM stay refused either way. Ported from the
v2xph `diag_usb.py` + `v2x_diag_capture.py` reference tools.

## Supported devices (validated)

diagbarf is intentionally transport-shaped, not device-specific — if a device
gives you DIAG through one of the source modes, it should work. These are
the platforms it's been exercised on:

| Module | Chipset | `/dev/diag`? | DIAG backing | Mode |
|--------|---------|--------------|--------------|------|
| Wistron **LV55** | SDX55 | yes | kernel `diagchar` | `socket-log` |
| Casa Systems **CFW-3212** | SDX62 | **no** | userspace `diag-router` IPC | `socket-log` |
| Fibocom **FM101-GL** (Dell-packed) | SDX12 | **no** | userspace `diag-router` over QRTR `(0,15)` | `socket-log` |
| Inseego **M2000** | SDX55 | yes | kernel `diagchar` | `diag-dev` (native, no vendor binary) |
| Inseego **M3100** | SDX65 | **no** | userspace `diag-router` (OEM `diag_socket_log`) | `socket-log` *(on-device power-and-barf, 72k rec / 0.00% loss validated)* |
| Quectel **RM520N-GL** | SDX62 | n/a (host-side) | `/dev/mhi_DIAG` on a jump box | `hdlc-chardev` |
| Quectel **RM500Q** | SDX55 | n/a (host-side) | `/dev/ttyUSBx` on a jump box | `hdlc-chardev` |
| Kapsch **RIS-9260** (MDM9150) | MDM9150 | **no** | USB composite `05c6:90f0`, DIAG on interface 4 via usbfs | `usbfs` *(built + unit-tested; live byte-parity bench pending)* |

The `hdlc-chardev` path has been run to **0.000% bad CRC** across hundreds of
thousands of frames with **100% F3 ext-msg resolution**, over both MHI (`/dev/mhi_DIAG`)
and USB (`/dev/ttyUSBx`) — the same result as a `socat`/PTY bridge, with no
`socat`, no PTY, and no external process reading the device.

The `usbfs` path is code-complete and unit-tested (framing + the `0x73`/`0x7D`
opcode gate), and its transport constants are verified byte-exact against the
kernel's `<linux/usbdevice_fs.h>` on i686. The RSU daemon-log **Plane B** egress
(`--plane-b-udp` / `--plane-b-log`, BMX1 tagged records — see
[Wire formats](#wire-formats)) is also code-complete, unit-tested, and validated
end-to-end on a host (thread + tail-follow + framing + UDP egress). The one item
that **remains to be done on hardware** is the end-to-end **byte-parity bench
run** against a live RIS-9260, the Plane A acceptance gate: USB enumeration +
line-rate throughput are all that is unproven off the RSU.

The **Casa CFW-3212** result is worth calling out: that platform has **no
`/dev/diag`** and DIAG runs entirely in userspace via `diag-router`. diagbarf
works there unchanged because `diag_socket_log` bridges `diag-router`
bidirectionally in diagbarf's localhost + self-armed-mask configuration — which
is what enables DIAG-over-Ethernet on a device that otherwise won't give it up.

On the CFW-3212, diagbarf also **cannot coexist with the stock Casa
DIAG-over-Ethernet service** (an RDB-configured `diag_socket_log` dialing out
to a host `:2500`). Both the stock template and
diagbarf open with `killall diag_socket_log`, so enabling the stock path kills
diagbarf's captive child; diagbarf respawns it in-process (no systemd restart)
and wins the single MD slot, while the stock reader gets 0 bytes. This is
mutual exclusion, not stream corruption — but it means the two are an
either/or on this device. Teardown (`enable=0`) is a plain killall and does
**not** clear the global mask (the mask clear is gated behind
`diag_socket_log -m`, which the stock template never passes) — though every
graceful `diag_socket_log` exit, `-m` or not, switches `diag-router` back to
USB logging mode. Verified on the device and by binary analysis of
`diag_socket_log`.

The **Fibocom FM101-GL** (in Dell `_A45`/`_A63` carrier packs) is the same
shape — **no `/dev/diag`**, DIAG behind userspace `diag-router` reached over
QRTR service `(0,15)` — and is a pointed demonstration of the `socket-log`
value: on these units the **USB DIAG endpoint is dead** (the host-side
`LOG_CONFIG_F` mask handshake, and even `DIAG_VERNO_F`, time out), so every
host-driven capture tool gets zero bytes and the module was long written off as
"DIAG-disarmed." Running diagbarf **on the module** instead arms the mask over
the live on-device QRTR transport (12093 codes / 7 groups) and fans the stream
out over the TCP sink — turning a module that gives up nothing over USB into a
working DIAG source. Reach the TCP-listener sink over `adb forward tcp:12399`
when the module exposes no LAN interface.

## Build

diagbarf is one C file and a `Makefile`. No autotools, no build system to learn.

```sh
# DEVICE build — static armv7l hard-float (VFP). Both SDX55 and SDX62 app
# processors are armv7l, so one binary serves both. Auto-runs `make verify`.
make

make verify      # assert the ELF is really armv7 + VFP hard-float

# HOST builds — for running diagbarf ON a jump box (--source hdlc-chardev):
make host            # both host binaries, each auto-verified
make host-x86_64     # -> diagbarf-x86_64   (x86-64 hosts)
make host-aarch64    # -> diagbarf-aarch64  (aarch64 jump boxes)
# On a non-Debian host whose readelf lacks the binutils triple (e.g. Arch, where
# it's plain `readelf`), override the verify tool — the compile already works:
make host-x86_64 X86_64_READELF=readelf      # or AARCH64_READELF=readelf

# RIS-9260 RSU build — static i686 (--source usbfs):
make i686                            # -> diagbarf-i686  (needs the i686 cross-gcc)
make i686 I686_CC='gcc -m32' I686_READELF=readelf   # on a 32-bit-multilib host
```

**Toolchains.** The device build needs `gcc-arm-linux-gnueabihf`
(`arm-linux-gnueabihf-gcc` + `-readelf`). The host builds need
`x86_64-linux-gnu-gcc` (usually native) and, for aarch64,
`gcc-aarch64-linux-gnu` + `binutils-aarch64-linux-gnu`. The i686 RSU build needs
either `gcc-i686-linux-gnu` or a 32-bit-multilib gcc (`gcc -m32`) with the 32-bit
static libc (Debian: `libc6-dev-i386`; Arch: `lib32-glibc`). On Debian/Ubuntu:

```sh
sudo apt install gcc-arm-linux-gnueabihf gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu gcc-i686-linux-gnu
```

Everything is built **static**, so a binary doesn't couple to the target's glibc
version — copy it over and run it. The build stamps a version string in at
compile time (`git describe` + build date); query it with `diagbarf --version`
(or `-V`), and it's also printed to stderr once at startup so your logs answer
"what's running?" without a flag or a hash.

## Install (on the device)

diagbarf is one static binary plus a launcher and a sample config. A typical
systemd install:

```sh
# 1. Copy the binary and helpers to a writable partition on the device.
#    (On devices whose sshd has no sftp subsystem, stage with:  ssh DEV 'cat > dest' < file )
adb push diagbarf      /data/diagbarf/diagbarf      &&  chmod 755 /data/diagbarf/diagbarf
adb push diagbarf.sh   /data/diagbarf/diagbarf.sh
adb push diagbarf.conf /data/diagbarf/diagbarf.conf

# 2. Install a systemd unit that runs diagbarf.sh (a minimal example ships as
#    diagbarf.sh's header comment). Then:
systemctl daemon-reload
systemctl enable --now diagbarf.service
```

Edit `diagbarf.conf` to choose the source mode and which sinks are on. Paths in
`diagbarf.sh`/`diagbarf.conf` are examples — point them wherever your device's
writable filesystem lives. diagbarf stores **nothing** on the device itself; your
captures land on the collector host.

## Use — capture the stream

diagbarf just emits the firehose; a **collector** on the other side records or
decodes it. Any consumer that speaks raw HDLC (the TCP sinks) or reassembles the
DGE1 datagrams (the UDP sinks) works. Two easy options:

**Roll your own** — the wire formats are documented below, so a dozen lines of
Python or a `socat`/`nc` one-liner will capture the TCP-listener stream to a file.

**Capture it as network frames (`tshark` / Wireshark)** — because every sink is
plain TCP/UDP on the wire, you can just packet-capture it. You get each datagram
or segment **timestamped**, and — since it's an ordinary capture — the DIAG
firehose lands **interleaved in the same file with everything else on the link**
(other protocols, GNSS/NMEA sidecar streams, your own tooling's traffic), so you
can line the DIAG stream up against other data types on one timeline.

```sh
# UDP firehose (broadcast/unicast) → timestamped pcapng:
tshark -i <iface> -f 'udp port 12399' -w diagbarf.pcapng
# or the TCP listener/dial-out sink:
tshark -i <iface> -f 'tcp port 12399' -w diagbarf.pcapng
```

The payloads are raw HDLC (TCP) or DGE1 datagrams (UDP) per [Wire
formats](#wire-formats) — carve them out of the capture later, or just keep the
pcap as a timestamped archive of the session alongside your other traffic.

**Use the companion tools** — this project has sibling open-source tools for the
host side:

- [**diaggulp**](https://github.com/lukejenkins/diaggulp) — a DIAG capture client.
  Point it at diagbarf's TCP listener (it consumes the stream passively, since
  diagbarf already armed the mask):

  ```sh
  # TCP listener sink — the collector dials IN to the device:
  diaggulp --transport tcp-connect --host <device-ip> --port 12399 --no-mask -o capture.dlf

  # UDP broadcast/unicast sink — passive DGE1 reassembly (+ a gap sidecar):
  diaggulp --transport udp-listen --host 0.0.0.0 --port 12399 -o capture.dlf
  ```

- [**diaggrok**](https://github.com/lukejenkins/diaggrok) — a clean-room DIAG log
  decoder library, if you want to turn the captured records into structured data.

> **Passive means passive.** On the TCP/UDP sinks the collector must **not** try
> to arm the mask — diagbarf already owns all mask state. With `diaggulp` that's
> `--no-mask`. The daemon owns the wire; consumers just read it. Anything a
> client sends on a data sink is read and discarded. The **only** way to send the
> modem a command is the separate `--cmd-listen` channel below (standard, but
> loopback-only), and even that refuses every mask-changing opcode.

## Standard: DIAG command passthrough (`--cmd-listen`, loopback)

**Standard install mode (loopback-only).** A standing diagbarf node sets
`DIAG_CMD_LISTEN` so the command channel is available on every deployment —
bound to `127.0.0.1`, reachable only through an on-device shell (`ssh -L`),
never on the wire. Without the flag diagbarf behaves as a pure firehose
(described above); the standard config turns the channel on.

While diagbarf holds the DIAG interface it is otherwise the *only* thing that
can — some devices have no other DIAG command path at all (the Kapsch RIS-9260:
no `option`/`qcserial`, diagbarf owns USB interface 4). `--cmd-listen
[ADDR:]PORT` opens a **separate** listener so one external client can reach the
modem's EFS2 / NV command handlers **while the firehose keeps streaming** to
every sink.

```sh
# on the device (a bare PORT binds 127.0.0.1 — never the wildcard):
diagbarf --source usbfs ... --cmd-listen 43556
# from the host, over ssh — then point any HDLC-over-TCP EFS2/NV client
# at 127.0.0.1:43555 (it should match replies by their echoed header):
ssh -L 43555:127.0.0.1:43556 <device>
```

How it behaves:

| | |
|---|---|
| **Clients** | One at a time. A second connection is accepted and closed at once (logged). |
| **Requests** | Whole HDLC frames (`payload ‖ CRC-16 LE`, escaped, `0x7E`-terminated). Each is reassembled across reads, **CRC-verified**, policy-checked, then **re-encoded** and written to the modem as one unit. The modem receives the canonical encoding of the exact bytes the policy saw, never the client's own spelling. Requests larger than 2046 decoded bytes are refused. |
| **Replies** | The command client receives **only** reply-class frames: replies to the allowed opcodes (DIAG replies echo the request opcode) and the DIAG error replies `0x13`/`0x14`/`0x15`/`0x18`. It does **not** receive the firehose. The normal sinks are unchanged and still carry every byte, replies included. |
| **Slow client** | Never stalls the firehose. If its socket buffer is full, a whole reply is dropped (logged). A torn write closes the client. |
| **Serialization** | diagbarf's own mask arming finishes before the pump starts, and client frames are written only from the pump, whole. The two can never interleave on the wire. |
| **Audit** | One log line per request: `cmd: FORWARDED op=0x4B subsys=0x13 cmd=0x0002 len=…` or `cmd: REFUSED …` (NV requests log the item number). On the RIS-9260, stderr goes to syslog. |

**Allow-list (everything else is refused and logged):**

| Opcode | What |
|---|---|
| `0x4B` subsystem `0x13` / `0x3E` | EFS2 (standard / alternate): read, write, mkdir, stat, … |
| `0x26` / `0x27` | NV item read / write |
| `0x00` / `0x0C` / `0x7C` | VERNO / STATUS / EXT_BUILD_ID (read-only identity) |
| `0x1D` | DIAG_TS_F: read the modem ts64 clock (the host time anchor) |
| `0x80` subsystem `0x12` cmd `0x16`, record 0–3 | DIAG_SERV qdb pull: FILE_LIST / OPEN / READ / CLOSE. Read-only |
| `0x4B` subsystem `0x12` cmd `0x0222` | DIAG_SERV diag_id-binding query. Read-only |

The `0x1D` and DIAG_SERV rows exist so a host time anchor
and qdb pull run through a node that already holds the single MD slot. Nothing
else on subsystem `0x12` is admitted.

**Always refused:** the mask-changing opcodes `0x73` / `0x7D` / `0x60` / `0x82`
(diagbarf must stay the sole mask arbiter, or the stream every sink records would
change under it); `0x29` CONTROL (offline / reset); and every other `0x4B`
subsystem, including FTM (`0x0B`), which can key a transmitter. There is no
allow-all escape hatch.

`--cmd-listen` needs a source with a path back to the modem, so it is rejected
with `--source stdin`.

⚠️ **The allow-list admits EFS2 and NV *writes*, which change the device
persistently.** That is the deliberate cost of a standing channel. It is
acceptable as the standard mode *because the listener is loopback-only*: reaching
it already requires an on-device root shell, and such a shell can mutate EFS2/NV
by other means regardless. The channel adds no exposure a device's existing
shell does not already have — it does not widen the attack surface, it just makes
the one MD-slot holder reachable for a time anchor / qdb pull without evicting it.
Do not bind it to a non-loopback address.

## Optional: per-client subscriptions (`--client-filters`, `--keep-*`)

Off by default. Different consumers of one diagbarf can each receive only a
subset of the stream — log codes, opcodes, F3, events — filtered in C where
diagbarf runs. **What the modem emits is unchanged:** diagbarf stays the sole
mask arbiter, and a subscription decides delivery only.

**TCP-listen clients** (with `--client-filters`): a client's first line, if sent
within the grace window (`--sub-grace-ms`, default 500), may be

```
SUB {"log_codes":[5238,5239],"opcodes":[],"f3":false,"events":false}\n
```

- Codes are JSON integers (no hex strings). `f3` = opcodes `0x79`/`0x99`/`0x92`,
  `events` = `0x60`; log codes and opcodes match bare **and** `0x98`-wrapped
  frames. An `opcodes` entry of `16` (`0x10`) takes every LOG frame.
- No complete line within the grace window, or a first line that is not a `SUB`
  line → the **full stream** (diaggulp, kp/celldiag and existing receivers work
  untouched; they miss at most the grace window's bytes after connecting).
- A later `SUB` line replaces the declaration.
- A client gets **nothing** while its grace window is open.
- Limits: line ≤ 4 KiB, ≤ 256 codes, ≤ 32 opcodes. A violation, malformed JSON
  or an unknown key → `ERR <reason>\n` and that client is dropped (other
  clients are unaffected).

**UDP / dial-out destinations** have no back-channel, so their filter is on the
command line, bound to the **immediately preceding** destination flag:

```sh
diagbarf --source hdlc-chardev --diag-dev /dev/ttyUSB2 \
    --udp-unicast 192.168.7.2:12399 --keep-log-code 0x1476,0x1477 --keep-f3 \
    --tcp-dial 192.168.7.2:2600 --keep-events
```

`--keep-log-code LIST`, `--keep-opcode LIST` (decimal or `0x` hex, comma lists),
`--keep-f3`, `--keep-events`.

**Output.** A filtered sink receives each matching frame as `0x7E` + the
original escaped bytes + `0x7E` (byte-exact, CRC-verified; bad-CRC frames are
dropped). That is exactly the output `diag_peek_filter` writes for the same filter. A
filtered UDP destination's DGE1 datagrams are cut on frame boundaries (only a
single frame longer than one datagram is split). Unfiltered sinks receive the raw
stream exactly as without the flag. The classifier reads only the first 32
escaped bytes of each frame, and it is tested against the same vectors as the
Python `diagmunge.framefilter` (`tests/diag_peek_vectors.json`).

## F3 ext-msg debug stream (plaintext + QSR4)

diagbarf can *also* arm the firmware's **F3 ext-msg debug stream**
(`DIAG_EXT_MSG_CONFIG_F` / `SET_ALL_RT_MASKS`, all subsystems, all levels) on top
of the log-code mask. It's **OFF by default** — enable it with `--ext-msg-f3`
(or `DIAG_EXT_MSG_F3=1` in `diagbarf.conf`) and restart.

Arm F3 **at the daemon**, not at the collector: because the collector reads
passively, it can't arm anything. A capture against a default-config diagbarf
gives you every log code but **zero F3**.

Three F3 families land in the stream:

| pkt | family | needs a firmware QDB? |
|---|---|---|
| `0x79` | `EXT_MSG_F` free-text | **no** — readable `file:line` strings |
| `0x99` | `QSR4_EXT_MSG_TERSE_F` (hash-keyed) | **yes** — needs the matching firmware QDB |
| `0x98` | multi-radio ext-msg | — |

So the **plaintext** `0x79` logs are decodable with no QDB at all; only the
hash-keyed `0x99` QSR4-terse messages need the firmware's QDB to resolve.

`--ext-msg-f3-mute SS[-SS][,...]` (with `--ext-msg-f3`) sends one `SET_RT_MASK` of
all-zero levels per range **after** arming, so those ss_ids stay silent.
On the RIS-9260 (MDM9150), ss_id 47 is the GNSS correlator and makes up about half
of the whole firehose. Muting it also stops log `0x1376`, which the firmware gates
on the same SSID.

Heads-up: F3 is **chatty** — on an SDX6x a couple of minutes of all-F3 capture is
dominated by the `0x99` stream and can run to tens of megabytes. Arm it when you
need it.

## Wire formats

diagbarf's output is deliberately simple so anything can consume it.

**TCP sinks (listener + dial-out): raw HDLC.** Exactly the modem's DIAG framing —
each packet is byte-stuffed (`0x7D`/`0x7E`) and delimited with `0x7E`, with a
CRC-16 FCS. This is the same shape QCSuper/SCAT and friends already understand,
so a raw HDLC capture is portable.

**UDP sinks (broadcast + unicast): DGE1 datagrams.** Each datagram carries a
12-byte header, then a chunk of the raw HDLC stream:

```
 offset  size  field
   0      4    magic  "DGE1"
   4      1    version (currently 0x01)
   5      1    flags   (0x01 = first datagram after a source re-spawn)
   6      4    seq     (little-endian u32, monotonic)
  10      2    length  (little-endian u16, payload bytes that follow)
  12      …    payload (raw HDLC bytes)
```

A consumer reassembles by `seq` order; a gap in `seq` is datagram loss (UDP is
lossy by nature — use the TCP sinks if you can't tolerate any loss).

**Plane B mux (RSU daemon logs): BMX1 tagged records.** The DIAG stream above is
*Plane A* (the modem firehose). On the RIS-9260 the RSU also has its own
daemon logs — `acme`/`kapschrsu`, `cv2x-daemon`, `cv2x_rx_app` SDU deliveries,
`gpsd`, `ntpd` — which are *Plane B*. Plane B rides a **separate UDP port** (so a
single `tcpdump -i eth1` grabs both planes, yet the raw-HDLC Plane A stream stays
byte-identical) and each record is self-delimiting and source-**tagged**:

```
 offset  size  field
   0      4    magic  "BMX1"
   4      1    version (currently 0x01)
   5      1    source tag (0x00 = manifest | 0x01.. = a registered log source)
   6      1    flags   (0x01 = first record after a (re)start / rotation)
   7      1    reserved (0)
   8      4    seq     (little-endian u32, per-source)
  12      2    length  (little-endian u16, payload bytes that follow)
  14      …    payload (one log line, newline stripped; or the manifest blob)
```

The **manifest** record (tag `0x00`, re-announced every 30 s since UDP is lossy)
carries `tag<TAB>name<TAB>path\n` per source, so the host labels every stream
with no out-of-band config. The tag byte is deliberately open-ended: an unused
value is **room for a future third tagged source** (e.g. a J2735 payload plane),
which is why Plane B does not hard-code a two-plane assumption.

Enable it with `--plane-b-udp [ADDR:]PORT` (conventional port `12400`) plus one
or more `--plane-b-log NAME=PATH` (repeatable). Plane B is **strictly additive**:
it runs in its own thread, only ever *reads* AP-side log files and *sends* UDP,
and never touches the modem — so "zero bytes written to the 9260" is structural,
and a Plane B setup failure leaves Plane A running.

**Address syntax — IPv4 and IPv6 link-local.** Every dest/listen sink
(`--tcp-listen`, `--udp-unicast`, `--tcp-dial`, `--plane-b-udp`) accepts both
families numerically (the binary is `-static`, so there is **no DNS resolver** —
addresses must be literals):

| Form | Example | Notes |
|------|---------|-------|
| IPv4 | `192.168.7.2:12400` | dotted-quad, as before |
| IPv6 | `[2001:db8::5]:12400` | **brackets required** — a bare `a::b:port` is ambiguous and is rejected |
| IPv6 link-local | `[fe80::1%eth1]:12400` | the RIS-9260 case — eth1 is IPv6 link-local, so the `%ZONE` scope is **mandatory** for the kernel to pick the egress interface |

`--udp-broadcast` stays IPv4-only by design: broadcast is a v4 concept (IPv6 uses
multicast) and `SIOCGIFBRDADDR` returns a v4 address. The RIS-9260's eth1 has no
IPv4, so on that box you reach the host with `--udp-unicast [fe80::HOST%eth1]:PORT`
(and, for Plane B, `--plane-b-udp [fe80::HOST%eth1]:PORT`), not broadcast.

## Safety

diagbarf is **read-only with respect to the device** by default: it sets the
global DIAG log mask (required to get an MD capture at all) but writes no NV,
triggers no reboot, and stores nothing on the device. Your captures live on the
collector host(s). The single exception is the loopback `--cmd-listen` channel
(standard, bound to `127.0.0.1`), which lets **one** client you connect from an
on-device shell send EFS2 / NV requests, including writes. It adds no exposure
beyond that shell; never bind it to a non-loopback address.

That said — DIAG is a deeply privileged interface. The stream contains everything
your modem sees on the radio, which can include identifiers and message contents.
Capture responsibly, on hardware and subscriptions you own or are authorized to
test.

## Acknowledgements & inspiration

diagbarf exists because other people did great work in the open first. In
particular:

- **[Rayhunter](https://github.com/EFForg/rayhunter)** (EFF) was a direct trigger
  for writing diagbarf. Rayhunter is an open-source IMSI-catcher / cell-site-simulator
  detector that runs on an inexpensive hotspot and analyzes the Qualcomm DIAG/QMDL
  stream on-device to surface surveillance. Watching a small Rust daemon read
  `/dev/diag` right on the modem is what pushed us to build a clean, dependency-free
  way to get that same raw DIAG firehose off the device and to wherever you want to
  analyze it. We hope diagbarf turns out to be useful to the Rayhunter project and
  its community in some way.

- **[atcli_rust](https://github.com/1alessandro1/atcli_rust)** (by
  [@1alessandro1](https://github.com/1alessandro1)) was the inspiration for
  diagbarf's *posture*. It's a memory-safe Rust rewrite of the OEM `atcli`/`atcmd`
  utilities for Qualcomm SDX55/X65/X75 modems, reverse-engineered into a single
  static binary with zero shared-library dependencies for embedded use. diagbarf
  aims to be the DIAG-egress companion to what atcli_rust does for AT commands — a
  standalone, statically-linked, on-device tool in the same spirit.

- **QCSuper, SCAT (Signals Collecting And Tracing), and osmo-qcdiag** blazed the
  trail. They documented Qualcomm's DIAG protocol in the open and are the reason a
  tool like this can exist at all. diagbarf isn't a replacement for them — it makes
  a different set of tradeoffs (a tiny, on-device egress daemon rather than a full
  host-side analysis suite), and it's built to **compose** with that ecosystem, not
  compete with it. If you want a full-featured host-side DIAG toolkit, go use them —
  they're excellent, and diagbarf's raw-HDLC output feeds straight into them.

## License

Apache-2.0. See [LICENSE](LICENSE).
