#!/bin/bash
# SPDX-License-Identifier: MIT
# run.sh - score uringscope's doctor against injected pathologies.
#
#   sudo ./run.sh [path-to-uringscope]
#
# For each pathogen scenario: run it under the scope, grep the doctor's
# output for the finding that the injected ground truth demands, and emit
# PASS/FAIL. Scenarios tagged FUTURE target detectors that are designed
# but not shipped (buffer-hazard mode, reaping-lag uprobes); they assert
# only that the injection itself reproduced (ground truth present), and
# flip to full assertions when the detector lands.
#
# Output doubles as the paper's detection-effectiveness table:
#   injected anomaly -> detected? -> evidence matches ground truth?
set -u
cd "$(dirname "$0")"
US=${1:-../../uringscope}
OUT=out; mkdir -p "$OUT"
PASS=0; FAIL=0; FUT=0

[ -x "$US" ] || { echo "uringscope binary not found at $US (make first)"; exit 1; }
[ -x ./pathogen ] || cc -O2 -o pathogen pathogen.c -luring || exit 1

# scenario | args | scope-duration | grep pattern in uringscope output | tier
CASES='
punt|2000|8|fell back to the io-wq|now
nobatch|3000|10|averaging only|now
overflow|1000|6|CQ overflowed|now
errors|500|6|completions returned res < 0|now
leak|16 30|8|submitted but never completed|now
sqpoll-stall|6|8|SQPOLL thread|now
worker-storm|64|8|distinct worker threads|now
uaf-unmap||6|observed_res=-14|future
uaf-reg||6|HAZARD-CONFIRMED silent-corruption|future
reap-lag|800|6|cqe_ready_unreaped|future
'

run_case() { # name args dur pattern tier
	local name=$1 args=$2 dur=$3 pat=$4 tier=$5
	local log="$OUT/$name.log"
	# shellcheck disable=SC2086
	timeout $((dur + 25)) "$US" -d "$dur" -- ./pathogen "$name" $args \
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

echo "scoring doctor against injected pathologies ($(uname -r))"
echo "----------------------------------------------------------"
# <<< not |: a pipe would run the loop in a subshell and lose the tallies
while IFS='|' read -r name args dur pat tier; do
	[ -z "$name" ] && continue
	run_case "$name" "$args" "$dur" "$pat" "$tier"
done <<< "$CASES"

# leak needs the scope window to end while the requests are still held:
# pathogen leak holds 30s, scope runs 8s -- handled by the table above.

echo "----------------------------------------------------------"
echo "pass=$PASS fail=$FAIL future=$FUT  (logs in $OUT/)"
[ "$FAIL" -eq 0 ]
