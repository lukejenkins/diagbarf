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

## Supported devices (validated)

diagbarf is intentionally transport-shaped, not device-specific — if a device
gives you DIAG through one of the three source modes, it should work. These are
the platforms it's been exercised on:

| Module | Chipset | `/dev/diag`? | DIAG backing | Mode |
|--------|---------|--------------|--------------|------|
| Wistron **LV55** | SDX55 | yes | kernel `diagchar` | `socket-log` |
| Casa Systems **CFW-3212** | SDX62 | **no** | userspace `diag-router` IPC | `socket-log` |
| Inseego **M2000** | SDX55 | yes | kernel `diagchar` | `diag-dev` (native, no vendor binary) |
| Quectel **RM520N-GL** | SDX62 | n/a (host-side) | `/dev/mhi_DIAG` on a jump box | `hdlc-chardev` |
| Quectel **RM500Q** | SDX55 | n/a (host-side) | `/dev/ttyUSBx` on a jump box | `hdlc-chardev` |

The `hdlc-chardev` path has been run to **0.000% bad CRC** across hundreds of
thousands of frames with **100% F3 ext-msg resolution**, over both MHI (`/dev/mhi_DIAG`)
and USB (`/dev/ttyUSBx`) — the same result as a `socat`/PTY bridge, with no
`socat`, no PTY, and no external process reading the device.

The **Casa CFW-3212** result is worth calling out: that platform has **no
`/dev/diag`** and DIAG runs entirely in userspace via `diag-router`. diagbarf
works there unchanged because `diag_socket_log` bridges `diag-router`
bidirectionally in diagbarf's localhost + self-armed-mask configuration — which
is what enables DIAG-over-Ethernet on a device that otherwise won't give it up.

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
```

**Toolchains.** The device build needs `gcc-arm-linux-gnueabihf`
(`arm-linux-gnueabihf-gcc` + `-readelf`). The host builds need
`x86_64-linux-gnu-gcc` (usually native) and, for aarch64,
`gcc-aarch64-linux-gnu` + `binutils-aarch64-linux-gnu`. On Debian/Ubuntu:

```sh
sudo apt install gcc-arm-linux-gnueabihf gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu
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
> `--no-mask`. The daemon owns the wire; consumers just read it.

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

## Safety

diagbarf is **read-only with respect to the device**: it sets the global DIAG log
mask (required to get an MD capture at all) but writes no NV, triggers no reboot,
and stores nothing on the device. Your captures live on the collector host(s).

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
