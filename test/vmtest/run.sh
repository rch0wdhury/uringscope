#!/bin/bash
# SPDX-License-Identifier: MIT
# run.sh - boot a kernel in a VM and run uringscope's full suite on it.
#
#   test/vmtest/run.sh <kernel-version> [expected-tier]
#   test/vmtest/run.sh all          # every kernel in test/kernels.txt
#
# This is the portability claim, executed: one CO-RE binary across the
# kernel matrix. Uses virtme-ng (vng) -- it fetches a prebuilt kernel,
# boots it under KVM with the host root mounted, and runs guest.sh inside.
# guest.sh asserts the support tier the BTF probe selected on that kernel
# (so the 6.17 cqe-collapsed io_uring_complete prototype is actually
# exercised, not just claimed) and runs test/pathology against a fresh
# writable scratch dir.
#
# Requirements: vng (apt install virtme-ng), busybox-static, zstd, qemu,
# and /dev/kvm. CI uses the same tool; see .github/workflows/vmtest.yml.
set -u
cd "$(dirname "$0")/../.."
REPO=$(pwd)
KMATRIX=test/kernels.txt

need() { command -v "$1" >/dev/null || { echo "vmtest: missing '$1' -- $2"; exit 2; }; }
need vng "apt install virtme-ng"
need qemu-system-x86_64 "apt install qemu-system-x86"
[ -e /dev/kvm ] || echo "vmtest: warning: no /dev/kvm; boot will be slow (TCG)"

# vng mounts the host root read-only inside the guest, so the dynamic
# binary and its libs are already visible there -- a static build is not
# required (set STATIC=1 in the environment if you want one anyway).
# Build only if the binary is stale or missing; honor a BPFTOOL override.
if [ ! -x ./uringscope ] || [ -n "$(find src bpf -newer ./uringscope 2>/dev/null)" ]; then
	make ${STATIC:+STATIC=1} >/dev/null 2>&1 || {
		echo "vmtest: build failed (try: make BPFTOOL=<path>)"; exit 1; }
fi
[ -x test/pathology/pathogen ] || \
	( cd test/pathology && cc -O2 -o pathogen pathogen.c -luring ) || exit 1

run_one() { # version tier
	local ver=$1 tier=${2:-full} log vng_ver
	# test/kernels.txt uses bare versions (6.6); vng wants a tag (v6.6).
	# 'mainline'/'stable' pass through.
	case "$ver" in
	[0-9]*) vng_ver="v$ver" ;;
	*)      vng_ver="$ver" ;;
	esac
	log=$(mktemp)
	echo ">>> vmtest kernel=$ver (vng $vng_ver) expected-tier=$tier"
	# vng needs a pty; 'script' provides one in headless CI/ssh.
	timeout 900 script -qec \
		"vng -r $vng_ver --rw --cpus 4 -m 2G -- \
		 'bash $REPO/test/vmtest/guest.sh $REPO $tier'" /dev/null \
		> "$log" 2>&1
	# surface the machine-readable VMTEST lines; suppress boot noise
	grep -E '^VMTEST|^PASS|^FAIL|pass=' "$log" | sed 's/\r$//'
	local result
	result=$(grep -oE 'VMTEST RESULT=(PASS|FAIL)' "$log" | head -1)
	rm -f "$log"
	[ "$result" = "VMTEST RESULT=PASS" ]
}

fails=0
if [ "${1:-}" = all ]; then
	while read -r ver tier _; do
		case "$ver" in ''|\#*) continue; esac
		run_one "$ver" "$tier" || fails=$((fails + 1))
	done < <(sed 's/#.*//' "$KMATRIX")
else
	# map test/kernels.txt version label -> tier if not given
	want=${2:-$(awk -v k="${1:?usage: run.sh <kernel>|all [tier]}" \
		'$1==k{print $2}' "$KMATRIX")}
	run_one "$1" "${want:-full}" || fails=1
fi

echo "----------------------------------------------------------"
echo "vmtest: $fails kernel(s) failed"
exit $((fails ? 1 : 0))
