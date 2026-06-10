#!/bin/sh
# SPDX-License-Identifier: MIT
# Regenerate bpf/vmlinux.h from the running kernel's BTF. Only needed when
# developing against new kernel types; the vendored header works everywhere
# because CO-RE relocates field offsets against the running kernel at load
# time. After regenerating, also refresh the opcode table:
#   ./tools/gen_opnames.sh
set -eu
if [ ! -r /sys/kernel/btf/vmlinux ]; then
	echo "no /sys/kernel/btf/vmlinux (kernel built without CONFIG_DEBUG_INFO_BTF?)" >&2
	exit 1
fi
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
echo "wrote bpf/vmlinux.h ($(wc -l < bpf/vmlinux.h) lines) from $(uname -r)"
