# SPDX-License-Identifier: Apache-2.0
# diagbarf — native multi-protocol on-device DIAG egress daemon
#
# On-device target is armv7l hard-float (VFP) for BOTH supported modems:
#   - Wistron LV55     (SDX55)
#   - Casa CFW-3212    (SDX62)
# Built static with glibc-based arm-linux-gnueabihf-gcc (the toolchain the
# original LV55 binary was built with; the resulting static binary runs on both
# SDX55 and SDX62 app processors, both armv7l).
#
# Host targets run diagbarf ON a jump box against an attached modem's
# serial-like CRC-HDLC DIAG chardev (--source hdlc-chardev): an aarch64
# (cortex-a53) jump box, or a NUC/Pi host (x86-64/aarch64). Built static so they don't
# couple to the host's glibc version (diagbarf uses numeric-only host parsing,
# no getaddrinfo/NSS — safe under -static).
#
# The i686 target runs diagbarf ON the Kapsch RIS-9260 RSU (i686 Debian
# 9, kernel 4.9, NO compiler on-device) against its MDM9150 via --source usbfs.
# Cross-built static off-device and scp'd over (scp -O — legacy protocol on the
# capture host). Same -static rationale: the RSU's glibc 2.24 is not this build
# host's, and usbfs uses only ancient syscalls (socket/poll/ioctl/pthread).
#
# Build targets:
#   make               — build the device binary (static armv7l hard-float)
#   make verify        — assert the ABI tags (Tag_CPU_arch v7 + VFP registers)
#   make host          — build BOTH host binaries (x86-64 + aarch64)
#   make host-x86_64   — static x86-64 host binary  -> diagbarf-x86_64
#   make host-aarch64  — static aarch64 host binary -> diagbarf-aarch64
#   make i686          — static i686 binary          -> diagbarf-i686 (RIS-9260 RSU)
#   make clean         — remove all built binaries
#
# Requirements:
#   device : arm-linux-gnueabihf-gcc + binutils (apt install gcc-arm-linux-gnueabihf)
#   host   : x86_64-linux-gnu-gcc (native), aarch64-linux-gnu-gcc + binutils
#            (apt install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu)
#   i686   : an i686 static toolchain — either the i686-linux-gnu cross-gcc
#            (apt install gcc-i686-linux-gnu) or, where 32-bit multilib + static
#            libs are installed, `make i686 I686_CC='gcc -m32'`. Needs the 32-bit
#            static libc (Debian: libc6-dev-i386; Arch: lib32-glibc). NOTE: a bare
#            x86-64 workstation without multilib CANNOT link this — build it on a
#            multilib/CI host. The C source itself is arch-neutral and is fully
#            exercised by `make test` on any host.

CC      = arm-linux-gnueabihf-gcc
READELF = arm-linux-gnueabihf-readelf

# Build-time version stamp. git describe gives the source version; the
# `|| echo unknown` keeps a build outside a git tree honest rather than failing.
# These are the *software* version — distinct from DGE_VERSION (the on-wire DGE1
# framing byte) which is compiled in as a constant.
VERSION    := $(shell git describe --always --dirty 2>/dev/null || echo unknown)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)

CFLAGS  = -static -O2 -Wall -Wextra \
          -DDIAGBARF_VERSION='"$(VERSION)"' \
          -DDIAGBARF_BUILD_DATE='"$(BUILD_DATE)"'
BIN     = diagbarf
SRC     = diagbarf.c
LDLIBS  = -lpthread

.PHONY: all verify clean host host-x86_64 host-aarch64 i686 \
        verify-host-x86_64 verify-host-aarch64 verify-i686

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)
	@ls -lh $@
	@file $@
	@$(MAKE) --no-print-directory verify

# Hard fail if the binary is not armv7 + VFP (would silently mis-run on the modem).
verify: $(BIN)
	@$(READELF) -A $(BIN) | grep -q 'Tag_CPU_arch: v7' \
	  && $(READELF) -A $(BIN) | grep -q 'Tag_ABI_VFP_args: VFP registers' \
	  && echo "verify: OK (armv7 + VFP hard-float)" \
	  || (echo "verify: FAIL — wrong ABI tags" >&2; exit 1)

clean:
	rm -f $(BIN) diagbarf-x86_64 diagbarf-aarch64 diagbarf-i686

# --- host builds: diagbarf ON a jump box, --source hdlc-chardev ------
# Same source, same version stamp, static per-arch, verified by ELF
# machine type (readelf -A ARM attributes don't apply to host arches, so verify
# checks `readelf -h` Machine instead of the armv7/VFP tags).
HOST_CFLAGS = -static -O2 -Wall -Wextra \
              -DDIAGBARF_VERSION='"$(VERSION)"' \
              -DDIAGBARF_BUILD_DATE='"$(BUILD_DATE)"'

# READELF vars are ?= so a non-Debian host (e.g. Arch, where the native
# readelf is plain `readelf`) can override the hardcoded binutils triple:
#   make host-x86_64 X86_64_READELF=readelf   (compile already works; only the
#   verify wrapper hardcoded the Debian triple). Matches the i686 target.
X86_64_CC        = x86_64-linux-gnu-gcc
X86_64_READELF  ?= x86_64-linux-gnu-readelf
AARCH64_CC       = aarch64-linux-gnu-gcc
AARCH64_READELF ?= aarch64-linux-gnu-readelf

host: host-x86_64 host-aarch64

host-x86_64: diagbarf-x86_64
diagbarf-x86_64: $(SRC)
	$(X86_64_CC) $(HOST_CFLAGS) -o $@ $< $(LDLIBS)
	@ls -lh $@
	@file $@
	@$(MAKE) --no-print-directory verify-host-x86_64

verify-host-x86_64: diagbarf-x86_64
	@$(X86_64_READELF) -h diagbarf-x86_64 | grep -q 'Machine:.*X86-64' \
	  && echo "verify: OK (x86-64 host)" \
	  || (echo "verify: FAIL — not an x86-64 ELF" >&2; exit 1)

host-aarch64: diagbarf-aarch64
diagbarf-aarch64: $(SRC)
	$(AARCH64_CC) $(HOST_CFLAGS) -o $@ $< $(LDLIBS)
	@ls -lh $@
	@file $@
	@$(MAKE) --no-print-directory verify-host-aarch64

verify-host-aarch64: diagbarf-aarch64
	@$(AARCH64_READELF) -h diagbarf-aarch64 | grep -q 'Machine:.*AArch64' \
	  && echo "verify: OK (aarch64 host)" \
	  || (echo "verify: FAIL — not an aarch64 ELF" >&2; exit 1)

# --- RIS-9260 RSU build: diagbarf ON the i686 RSU, --source usbfs -----
# Override the compiler on hosts without the i686-linux-gnu cross-gcc, e.g.
#   make i686 I686_CC='gcc -m32' I686_READELF=readelf   (needs 32-bit static libc)
I686_CC      ?= i686-linux-gnu-gcc
I686_READELF ?= i686-linux-gnu-readelf

i686: diagbarf-i686
diagbarf-i686: $(SRC)
	$(I686_CC) $(HOST_CFLAGS) -o $@ $< $(LDLIBS)
	@ls -lh $@
	@file $@
	@$(MAKE) --no-print-directory verify-i686

verify-i686: diagbarf-i686
	@$(I686_READELF) -h diagbarf-i686 | grep -qE 'Machine:.*(Intel 80386|80386)' \
	  && echo "verify: OK (i686 RSU)" \
	  || (echo "verify: FAIL — not an i686/80386 ELF" >&2; exit 1)

# --- host unit tests (system gcc, x86_64; also runs on macOS clang) ------
HOSTCC ?= gcc
.PHONY: test test-framing test-bridge test-fanout test-addr test-qsh test-mask test-stdin test-cmd test-filters
test: test-framing test-bridge test-fanout test-addr test-qsh test-mask test-stdin test-cmd test-filters

# Per-client subscriptions (--client-filters / --keep-*): the C peek runs
# the SHARED peek vectors (tests/diag_peek_vectors.json, pinned equal to the
# Python framefilter's copy), the SUB parser + limits, the grace-window state
# machine, any-chunking splitter equivalence, and a socketpair fan-out (full
# client byte-identical, filtered client exactly its frames, frame-aligned DGE1).
test-filters:
	$(HOSTCC) -O0 -g -Wall -Wextra -fsanitize=address,undefined -I. -o tests/test_client_filters tests/test_client_filters.c
	./tests/test_client_filters

test-framing:
	$(HOSTCC) -O0 -g -Wall -Wextra -I. -o /tmp/diagbarf_test tests/test_diagchar_framing.c
	/tmp/diagbarf_test

# Log-mask arming order (type-11-first) + the per-SSID SET_RT_MASK F3
# fallback payload/parse helpers. Pure functions (DIAGBARF_FRAMING_TEST guard,
# like test-qsh); no -pthread needed.
test-mask:
	$(HOSTCC) -O0 -g -Wall -Wextra -I. -o /tmp/diagbarf_mask_test tests/test_mask_arming.c
	/tmp/diagbarf_mask_test

# Pure seams for the --source stdin no-arm passthrough: source_is_valid,
# source_should_arm, and udp_send_chunk byte-integrity (FRAMING_TEST guard).
test-stdin:
	$(HOSTCC) -O0 -g -Wall -Wextra -I. -o /tmp/diagbarf_stdin_test tests/test_source_stdin.c
	/tmp/diagbarf_stdin_test

# Opt-in DIAG command passthrough (--cmd-listen): request policy, client
# frame reassembly + CRC/oversize reject + canonical re-encode, response-only
# routing, no interleave with send_recv(), and the usbfs gate staying closed
# unless the flag is on. Pure funcs + socketpairs (FRAMING_TEST guard). The
# binary lands in tests/ (gitignored; the carve treats it as a build artifact).
test-cmd:
	$(HOSTCC) -O0 -g -Wall -Wextra -fsanitize=address,undefined -I. -o tests/test_cmd_passthrough tests/test_cmd_passthrough.c
	./tests/test_cmd_passthrough

# Dual-stack numeric host/port parser + family-aware pretty-printer.
# Pins the IPv6 link-local (%zone) path that lets both planes egress over the
# RIS-9260's eth1 (fe80::/10). Pure functions; no -pthread needed.
test-addr:
	$(HOSTCC) -O0 -g -Wall -Wextra -I. -o /tmp/diagbarf_addr_test tests/test_addr_parse.c
	/tmp/diagbarf_addr_test

# QSH-trace 0x9001 maskset arming payload. Pins the on-wire
# bytes to the hardware-proven golden frame 73 (diag_cmd.py builder). Pure
# function; no -pthread needed.
test-qsh:
	$(HOSTCC) -O0 -g -Wall -Wextra -I. -o /tmp/diagbarf_qsh_test tests/test_qsh_arm.c
	/tmp/diagbarf_qsh_test

# Regression test for the diag-dev bridge SIGTERM-teardown wedge.
# Needs -pthread (drives diagdev_bridge on a real thread).
test-bridge:
	$(HOSTCC) -O0 -g -Wall -Wextra -I. -pthread -o /tmp/diagbarf_bridge_test tests/test_diagdev_teardown.c
	/tmp/diagbarf_bridge_test

# Regression test for the TCP-listen client-fanout bookkeeping crash.
# Pins compact_clients() + the tombstone->compact->accept slot discipline.
# Needs -pthread (pulls in the compiled diagdev_bridge symbol).
test-fanout:
	$(HOSTCC) -O0 -g -Wall -Wextra -fsanitize=address -I. -pthread -o /tmp/diagbarf_fanout_test tests/test_client_fanout.c
	/tmp/diagbarf_fanout_test
