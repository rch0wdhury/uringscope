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

# --- support tier: which completion variant did the BTF probe select? ---
"$US" --version > "$SCRATCH/ver.txt" 2>&1
comp=$(grep -E '^  completion ' "$SCRATCH/ver.txt")
submit=$(grep -E '^  submission ' "$SCRATCH/ver.txt")
echo "VMTEST tier-submission=[$submit]"
echo "VMTEST tier-completion=[$comp]"

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
( cd "$SCRATCH" && bash run.sh "$US" )
suite_rc=$?

# --- tracepoint format dump: evidence for docs/tracepoints.md -----------
for ev in io_uring_complete io_uring_submit_req io_uring_queue_async_work; do
	d=/sys/kernel/tracing/events/io_uring/$ev/format
	[ -r "$d" ] && { echo "=== $ev ==="; cat "$d"; } \
		    >> "$SCRATCH/tracepoint-formats.txt" 2>/dev/null
done
cp "$SCRATCH/tracepoint-formats.txt" "$REPO/test/vmtest/" 2>/dev/null || \
	echo "VMTEST note=tracepoint-dump-not-copied(ro-mount)"

[ "$suite_rc" = 0 ] && [ "$tier_ok" = 1 ] \
	&& echo "VMTEST RESULT=PASS kernel=$(uname -r)" \
	|| echo "VMTEST RESULT=FAIL kernel=$(uname -r)"
rm -rf "$SCRATCH"
exit $([ "$suite_rc" = 0 ] && [ "$tier_ok" = 1 ] && echo 0 || echo 1)
