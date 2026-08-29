#!/bin/bash
# SPDX-License-Identifier: MIT
# guest.sh - runs INSIDE the vmtest VM (invoked by run.sh via vng).
#
# The repo is mounted read-only under virtme, so all writes go to a tmpfs
# scratch dir -- critically, NOT the repo's test/pathology/out, which on a
# dev box still holds logs from a host run and would let stale results
# masquerade as a fresh kernel's. Asserts the expected support tier and
# runs the full pathology suite, then prints machine-readable VMTEST lines
# the host harness greps.
set -u
REPO=${1:-/home/$USER/uringscope}
WANT_TIER=${2:-full}
US="$REPO/uringscope"
SCRATCH=$(mktemp -d /tmp/vmtest.XXXXXX)

echo "VMTEST kernel=$(uname -r)"
[ -x "$US" ] || { echo "VMTEST FAIL reason=no-binary at $US"; exit 1; }
[ -r /sys/kernel/btf/vmlinux ] || { echo "VMTEST FAIL reason=no-BTF"; exit 1; }

# --- support tier: which variants did the BTF probe select? -------------
"$US" --version > "$SCRATCH/ver.txt" 2>&1
comp=$(grep -E '^  completion ' "$SCRATCH/ver.txt")
submit=$(grep -E '^  submission ' "$SCRATCH/ver.txt")
echo "VMTEST tier-submission=[$submit]"
echo "VMTEST tier-completion=[$comp]"
# ...and every other feature line. Without this, a kernel where some
# detector is off shows up only as a pile of failing scenarios with no way
# to tell which capability was missing.
grep -E '^  [a-z][a-z0-9-]* +(active|off|degraded)' "$SCRATCH/ver.txt" \
	| sed 's/  */ /g; s/^ //; s/^/VMTEST feat: /'

# --- what does this kernel's io_uring tracepoint ABI actually look like? -
# Printed inline, NOT written to the repo: vng --rw gives the guest an
# overlay, so anything written under $REPO is discarded when the VM exits
# (which is why the old tracepoint-formats.txt artifact was always empty).
# This is the evidence for adding a prototype variant to src/probe.c.
TR=/sys/kernel/tracing/events/io_uring
[ -d "$TR" ] || TR=/sys/kernel/debug/tracing/events/io_uring
if [ -d "$TR" ]; then
	echo "VMTEST tracepoints=[$(ls "$TR" 2>/dev/null | tr '\n' ' ')]"
	for ev in io_uring_submit_req io_uring_submit_sqe io_uring_complete \
		  io_uring_queue_async_work; do
		f="$TR/$ev/format"
		if [ -r "$f" ]; then
			flds=$(sed -n 's/^\tfield:\([^;]*\);.*/\1/p' "$f" \
				| grep -v '^__' | tr '\n' '|')
			echo "VMTEST proto $ev fields=[$flds]"
		else
			echo "VMTEST proto $ev=ABSENT"
		fi
	done
else
	echo "VMTEST note=no-tracefs-mounted"
fi

tier_ok=1
case "$WANT_TIER" in
full)
	echo "$submit" | grep -q "active"   || tier_ok=0
	echo "$comp"   | grep -q "active"   || tier_ok=0 ;;
counts)
	# legacy: submission active (via legacy variant), per-op latency may
	# be degraded -- just require submission attaches at all
	echo "$submit" | grep -q "active"   || tier_ok=0 ;;
esac
[ "$tier_ok" = 1 ] && echo "VMTEST tier=PASS want=$WANT_TIER" \
		   || echo "VMTEST tier=FAIL want=$WANT_TIER"

# --- pathology suite against a fresh, writable OUT ----------------------
cp "$REPO/test/pathology/pathogen" "$SCRATCH/" 2>/dev/null
sed "s,^OUT=.*,OUT=$SCRATCH/out; mkdir -p \"\$OUT\"," \
	"$REPO/test/pathology/run.sh" > "$SCRATCH/run.sh"
# Pass the tier through: on a counts kernel the suite must not assert
# detectors that tier documentedly cannot provide.
( cd "$SCRATCH" && bash run.sh "$US" "$WANT_TIER" )
suite_rc=$?

[ "$suite_rc" = 0 ] && [ "$tier_ok" = 1 ] \
	&& echo "VMTEST RESULT=PASS kernel=$(uname -r)" \
	|| echo "VMTEST RESULT=FAIL kernel=$(uname -r)"
rm -rf "$SCRATCH"
exit $([ "$suite_rc" = 0 ] && [ "$tier_ok" = 1 ] && echo 0 || echo 1)
