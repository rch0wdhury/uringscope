#!/bin/bash
# SPDX-License-Identifier: MIT
# run.sh - attach-path regression test.
#
#   sudo ./run.sh [path-to-uringscope]
#
# bench/collect.sh starts a workload and THEN attaches uringscope to its pid
# with -p. On that path the target's io_uring rings were created before the
# scope attached, so io_uring_create never fires for them. This test mirrors
# that usage and asserts the scope still sees the pre-existing ring AND counts
# its ongoing submissions/completions. The pathology suite can't catch this:
# it always launches the target *under* the scope, so creation is observed.
set -u
cd "$(dirname "$0")/../.."
US=${1:-./uringscope}
PATHOGEN=test/pathology/pathogen

[ -x "$US" ] || { echo "uringscope not found at $US (make first)"; exit 1; }
[ -x "$PATHOGEN" ] || cc -O2 -o "$PATHOGEN" test/pathology/pathogen.c -luring || exit 1

# Long-running submitter: creates its ring up front, then submits forever.
"$PATHOGEN" punt 100000000 >/tmp/attach-workload.out 2>&1 &
PP=$!
trap 'kill "$PP" 2>/dev/null' EXIT
sleep 1   # ring created + submitting BEFORE we attach

log=$(mktemp)
"$US" -p "$PP" -d 3 >"$log" 2>&1
kill "$PP" 2>/dev/null; wait "$PP" 2>/dev/null

rings=$(grep -oE 'rings created: [0-9]+' "$log" | grep -oE '[0-9]+' | head -1)
subs=$(grep -oE 'submissions: [0-9]+' "$log" | grep -oE '[0-9]+' | head -1)
comps=$(grep -oE 'completions: [0-9]+' "$log" | grep -oE '[0-9]+' | head -1)

echo "attach to running pid: rings=${rings:-0} submissions=${subs:-0} completions=${comps:-0}"
grep -E 'rings created:|ring fd=|submissions:' "$log" | head -3
rm -f "$log"

fail=0
[ "${subs:-0}"  -gt 0 ] || { echo "FAIL: zero submissions on attach path"; fail=1; }
[ "${comps:-0}" -gt 0 ] || { echo "FAIL: zero completions on attach path"; fail=1; }
[ "${rings:-0}" -gt 0 ] || { echo "FAIL: pre-existing ring not discovered"; fail=1; }
[ "$fail" = 0 ] && echo "PASS: attach-to-running sees ring + submissions + completions"
exit $fail
