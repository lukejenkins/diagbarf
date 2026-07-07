# SPDX-License-Identifier: Apache-2.0
# diagbarf — native multi-protocol on-device DIAG egress daemon (#N, #N)
#
# On-device target is armv7l hard-float (VFP) for BOTH supported modems:
#   - Wistron LV55     (SDX55, #N)
#   - Casa CFW-3212    (SDX62, #N)
# Built static with glibc-based arm-linux-gnueabihf-gcc (the toolchain the
# original LV55 binary was built with; the resulting static binary runs on both
# SDX55 and SDX62 app processors, both armv7l).
#
# Host targets (#N) run diagbarf ON a jump box against an attached modem's
# serial-like CRC-HDLC DIAG chardev (--source hdlc-chardev): <redacted-host> is aarch64
# (cortex-a53); NUC/Pi hosts are x86-64/aarch64. Built static so they don't
# couple to the host's glibc version (diagbarf uses numeric-only host parsing,
# no getaddrinfo/NSS — safe under -static).
#
# Build targets:
#   make               — build the device binary (static armv7l hard-float)
#   make verify        — assert the ABI tags (Tag_CPU_arch v7 + VFP registers)
#   make host          — build BOTH host binaries (x86-64 + aarch64)
#   make host-x86_64   — static x86-64 host binary  -> diagbarf-x86_64
#   make host-aarch64  — static aarch64 host binary -> diagbarf-aarch64 (<redacted-host>)
#   make clean         — remove all built binaries
#
# Requirements:
#   device : arm-linux-gnueabihf-gcc + binutils (apt install gcc-arm-linux-gnueabihf)
#   host   : x86_64-linux-gnu-gcc (native), aarch64-linux-gnu-gcc + binutils
#            (apt install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu)

CC      = arm-linux-gnueabihf-gcc
READELF = arm-linux-gnueabihf-readelf

# Build-time version stamp (#N). git describe gives the source version; the
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

.PHONY: all verify clean host host-x86_64 host-aarch64 \
        verify-host-x86_64 verify-host-aarch64

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
	rm -f $(BIN) diagbarf-x86_64 diagbarf-aarch64

# --- host builds (#N): diagbarf ON a jump box, --source hdlc-chardev ------
# Same source, same #N version stamp, static per-arch, verified by ELF
# machine type (readelf -A ARM attributes don't apply to host arches, so verify
# checks `readelf -h` Machine instead of the armv7/VFP tags).
HOST_CFLAGS = -static -O2 -Wall -Wextra \
              -DDIAGBARF_VERSION='"$(VERSION)"' \
              -DDIAGBARF_BUILD_DATE='"$(BUILD_DATE)"'

X86_64_CC       = x86_64-linux-gnu-gcc
X86_64_READELF  = x86_64-linux-gnu-readelf
AARCH64_CC      = aarch64-linux-gnu-gcc
AARCH64_READELF = aarch64-linux-gnu-readelf

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

# --- host unit tests (system gcc, x86_64; also runs on macOS clang) ------
HOSTCC ?= gcc
.PHONY: test test-framing test-bridge test-fanout
test: test-framing test-bridge test-fanout

test-framing:
	$(HOSTCC) -O0 -g -Wall -Wextra -I. -o /tmp/diagbarf_test tests/test_diagchar_framing.c
	/tmp/diagbarf_test

# Regression test for the diag-dev bridge SIGTERM-teardown wedge (#N).
# Needs -pthread (drives diagdev_bridge on a real thread).
test-bridge:
	$(HOSTCC) -O0 -g -Wall -Wextra -I. -pthread -o /tmp/diagbarf_bridge_test tests/test_diagdev_teardown.c
	/tmp/diagbarf_bridge_test

# Regression test for the TCP-listen client-fanout bookkeeping crash (#N).
# Pins compact_clients() + the tombstone->compact->accept slot discipline.
# Needs -pthread (pulls in the compiled diagdev_bridge symbol).
test-fanout:
	$(HOSTCC) -O0 -g -Wall -Wextra -fsanitize=address -I. -pthread -o /tmp/diagbarf_fanout_test tests/test_client_fanout.c
	/tmp/diagbarf_fanout_test
