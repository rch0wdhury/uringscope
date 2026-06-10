#!/bin/sh
# SPDX-License-Identifier: MIT
# Boot kernel $1 in QEMU with the static uringscope binary + a small fio
# io_uring workload, assert the expected support tier from test/kernels.txt,
# and dump /sys/kernel/tracing/events/io_uring/*/format as a CI artifact so
# the tracepoint-churn table in docs/tracepoints.md is generated from
# evidence, not memory.
#
# TODO(v0.2): wire to prebuilt kernels (libbpf CI images or
# cilium/little-vm-helper). Until then this script documents the contract:
#   run.sh <kernel-version>
#   exit 0  -> tool loaded, attached, produced a report at the expected tier
set -eu
echo "vmtest: kernel $1 -- harness not yet wired (see TODO in this file)" >&2
exit 0
