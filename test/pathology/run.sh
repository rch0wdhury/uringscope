#!/bin/bash
# SPDX-License-Identifier: MIT
# run.sh - score uringscope's doctor against injected pathologies.
#
#   sudo ./run.sh [path-to-uringscope] [kernel-tier]
#
# For each pathogen scenario: run it under the scope, grep the doctor's
# output for the finding that the injected ground truth demands, and emit
# PASS/FAIL. Scenarios tagged FUTURE target detectors that are designed
# but not shipped; they assert only that the injection itself reproduced
# (ground truth present), and flip to full assertions when the detector
# lands. (All current rows are real PASS/FAIL: the buffer-hazard and
# reap-lag detectors shipped.)
#
# kernel-tier (default full) is the support tier from test/kernels.txt for
# the kernel under test. On a `counts` kernel (5.15: legacy submit_sqe, no
# punt attribution) most detectors CANNOT fire by design, so asserting them
# would be asserting a documented non-capability. Those rows are SKIPped and
# do not fail the run -- see the min-tier column below.
#
# Output doubles as the detection-effectiveness table:
#   injected anomaly -> detected? -> evidence matches ground truth?
set -u
cd "$(dirname "$0")"
US=${1:-../../uringscope}
TIER=${2:-full}
OUT=out; mkdir -p "$OUT"
PASS=0; FAIL=0; FUT=0; SKIP=0

[ -x "$US" ] || { echo "uringscope binary not found at $US (make first)"; exit 1; }
[ -x ./pathogen ] || cc -O2 -o pathogen pathogen.c -luring || exit 1

# scenario | args | scope-duration | grep pattern | tier | uringscope flags | min-tier
#
# min-tier: the lowest kernel support tier on which this detection is
# expected to work. `counts` rows must pass everywhere; `full` rows are
# skipped on a counts kernel. The split is empirical, from the 5.15 vmtest
# leg: nobatch/leak/sqpoll-stall/worker-storm pass there because they are
# driven by submit counting and sched_switch, which the legacy path still
# provides. The rest need punt attribution, per-request completion detail,
# the hazard syscall hooks, or the liburing uprobes -- none of which a
# counts-tier kernel offers.
CASES='
punt|2000|8|fell back to the io-wq|now||full
nobatch|3000|10|averaging only|now||counts
overflow|1000|6|CQ overflowed|now||full
errors|500|6|completions returned res < 0|now||full
leak|16 30|8|submitted but never completed|now||counts
sqpoll-stall|6|8|SQPOLL thread|now||counts
worker-storm|64|8|distinct worker threads|now||counts
uaf-unmap||6|munmap of|now|--check|full
uaf-reg||6|overlapping in-flight buffer range|now|--check|full
uaf-reg-lifetime||6|unregistered buffer index|now|--check|full
reap-lag|800|6|CQEs sat ready|now||full
'

# Is this scenario's minimum tier satisfied by the tier we were told to
# assume? Only `full` satisfies `full`; everything satisfies `counts`.
tier_satisfied() { # min-tier
	[ "$1" = counts ] || [ "$TIER" = full ]
}

run_case() { # name args dur pattern tier usflags min-tier
	local name=$1 args=$2 dur=$3 pat=$4 tier=$5 usflags=${6:-} mintier=${7:-full}
	local log="$OUT/$name.log"
	if ! tier_satisfied "$mintier"; then
		echo "SKIP    $name (needs '$mintier' tier; kernel is '$TIER')"
		SKIP=$((SKIP + 1))
		return
	fi
	# shellcheck disable=SC2086
	timeout $((dur + 25)) "$US" $usflags -d "$dur" -- ./pathogen "$name" $args \
		> "$log" 2>&1
	if [ "$tier" = future ]; then
		# detector not shipped: assert the injection reproduced
		if grep -q "$pat" "$log"; then
			echo "FUTURE  $name (injection reproduced; detector pending)"
			FUT=$((FUT + 1))
		else
			echo "FAIL    $name (injection itself did not reproduce!)"
			FAIL=$((FAIL + 1))
		fi
		return
	fi
	if grep -q "$pat" "$log"; then
		echo "PASS    $name -> '$pat'"
		PASS=$((PASS + 1))
	else
		echo "FAIL    $name -> wanted '$pat'; see $log"
		FAIL=$((FAIL + 1))
	fi
}

echo "scoring doctor against injected pathologies ($(uname -r), tier=$TIER)"
echo "----------------------------------------------------------"
# <<< not |: a pipe would run the loop in a subshell and lose the tallies
while IFS='|' read -r name args dur pat tier usflags mintier; do
	[ -z "$name" ] && continue
	run_case "$name" "$args" "$dur" "$pat" "$tier" "$usflags" "$mintier"
done <<< "$CASES"

# leak needs the scope window to end while the requests are still held:
# pathogen leak holds 30s, scope runs 8s -- handled by the table above.

echo "----------------------------------------------------------"
echo "pass=$PASS fail=$FAIL future=$FUT skip=$SKIP  (logs in $OUT/)"
# A skipped row is a documented non-capability of the kernel, not a defect,
# so it does not fail the run. A genuine regression on a counts kernel still
# does: the four counts-tier rows are asserted everywhere.
[ "$FAIL" -eq 0 ]
