# SPDX-License-Identifier: MIT
# uringscope build
#
#   make            build ./uringscope (dynamic)
#   make STATIC=1   build a fully static binary (needs libbpf.a, libelf.a, libz.a)
#   make V=1        verbose
#   make clean
#
# Requirements: clang >= 12, bpftool, libbpf >= 1.0 (headers + lib), libelf, zlib.
# On Debian/Ubuntu: apt install clang libbpf-dev linux-tools-common linux-tools-$(uname -r)
# On Fedora:        dnf install clang libbpf-devel bpftool
# On Arch:          pacman -S clang libbpf bpf

OUT      := build
CLANG    ?= clang
CC       ?= cc
BPFTOOL  ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/ppc64le/powerpc/;s/riscv64/riscv/;s/loongarch64/loongarch/')

VMLINUX  := bpf/vmlinux.h

VERSION  := 0.2.0
GITREV   := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

CFLAGS   ?= -g -O2 -Wall -Wextra -Wno-unused-parameter
DEFS     := -DUS_VERSION=\"$(VERSION)\" -DUS_GITREV=\"$(GITREV)\"
BPFCFLAGS := -g -O2 -Wall -target bpf -D__TARGET_ARCH_$(ARCH) -Ibpf -Isrc
INCLUDES := -I$(OUT) -Isrc
LDLIBS   := -lbpf -lelf -lz -lpthread

ifeq ($(STATIC),1)
  LDFLAGS += -static
  LDLIBS  += -lzstd
endif

APP  := uringscope
SRCS := src/uringscope.c src/probe.c src/doctor.c src/perfetto.c src/jsonout.c src/metrics.c src/uprobes.c
OBJS := $(patsubst src/%.c,$(OUT)/%.o,$(SRCS))

ifeq ($(V),1)
  Q =
else
  Q = @
  MAKEFLAGS += --no-print-directory
endif

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
MANDIR  ?= $(PREFIX)/share/man/man8

.PHONY: all clean opnames check-vmlinux test test-offline install uninstall

all: $(APP)

$(OUT):
	$(Q)mkdir -p $@

# Regenerate vmlinux.h from the running kernel when available; otherwise the
# vendored bpf/vmlinux.h is used (CO-RE makes either fine -- field offsets are
# relocated against the *running* kernel's BTF at load time).
check-vmlinux:
	@test -s $(VMLINUX) || { echo "bpf/vmlinux.h missing -- run tools/gen_vmlinux.sh"; exit 1; }

$(OUT)/$(APP).bpf.o: bpf/$(APP).bpf.c bpf/io_uring_shims.bpf.h src/uringscope.h | $(OUT) check-vmlinux
	@echo "  CLANG-BPF $@"
	$(Q)$(CLANG) $(BPFCFLAGS) -c $< -o $@

$(OUT)/$(APP).skel.h: $(OUT)/$(APP).bpf.o
	@echo "  GEN-SKEL  $@"
	$(Q)$(BPFTOOL) gen skeleton $< name uringscope_bpf > $@

$(OUT)/%.o: src/%.c $(OUT)/$(APP).skel.h src/uringscope.h src/opnames.h
	@echo "  CC        $@"
	$(Q)$(CC) $(CFLAGS) $(DEFS) $(INCLUDES) -c $< -o $@

$(APP): $(OBJS)
	@echo "  LINK      $@"
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@

opnames:
	$(Q)./tools/gen_opnames.sh $(VMLINUX) src/opnames.h

install: $(APP)
	$(Q)install -D -m 0755 $(APP) $(DESTDIR)$(BINDIR)/$(APP)
	$(Q)install -D -m 0644 docs/$(APP).8 $(DESTDIR)$(MANDIR)/$(APP).8
	@echo "installed $(DESTDIR)$(BINDIR)/$(APP) + man page"

uninstall:
	$(Q)rm -f $(DESTDIR)$(BINDIR)/$(APP) $(DESTDIR)$(MANDIR)/$(APP).8

clean:
	$(Q)rm -rf $(OUT) $(APP)

# Offline doctor unit tests: link the real doctor.c with synthetic inputs.
# No kernel/BTF needed -- runs anywhere, good for CI pre-checks.
test-offline:
	$(Q)$(CC) $(CFLAGS) -Isrc -o $(OUT)/doctor_offline test/doctor_offline.c src/doctor.c
	$(Q)$(OUT)/doctor_offline

# Full pathology suite needs root + a BTF kernel (loads BPF).
test: all test-offline
	@echo "run sudo test/pathology/run.sh for the live injection suite"
