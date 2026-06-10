#!/bin/bash
# SPDX-License-Identifier: MIT
# collect.sh - run the workload x observer grid and drop one JSON per cell
# into results/. See bench/README.md for the protocol this implements.
#
#   sudo TARGET_DEV=/dev/nvme0n1p3 ./collect.sh randread-direct
#   sudo TARGET_DEV=/dev/nvme0n1p3 TARGET_FILE=/data/fio.dat ./collect.sh all
#
# TARGET_DEV  - raw block device/partition you can clobber (O_DIRECT jobs)
# TARGET_FILE - file path on a real filesystem (buffered jobs)
# RUNS        - repetitions per cell (default 5)
set -eu
cd "$(dirname "$0")"

: "${TARGET_DEV:?set TARGET_DEV to a block device you can clobber}"
: "${TARGET_FILE:=/tmp/uringscope-bench.dat}"
: "${RUNS:=5}"
URINGSCOPE=${URINGSCOPE:-../uringscope}
RESULTS=results
mkdir -p "$RESULTS"
export TARGET_DEV TARGET_FILE

OBSERVERS="baseline uscope-agg uscope-trace perf bpftrace strace"
WORKLOADS="randread-direct randread-buffered-cold seqwrite-fsync sqpoll smallbatch"

machine_info() {
	{
		uname -a
		grep "model name" /proc/cpuinfo | head -1
		cat /sys/devices/system/cpu/vulnerabilities/* 2>/dev/null | sort -u
		fio --version
		lsblk -d -o NAME,MODEL,ROTA "$TARGET_DEV" 2>/dev/null || true
		cat "/sys/block/$(basename "$TARGET_DEV" | sed 's/p[0-9]*$//')/queue/scheduler" 2>/dev/null || true
	} > "$RESULTS/machine.txt"
}

cpu_jiffies() { awk '/^cpu /{print $2+$3+$4+$6+$7+$8}' /proc/stat; }

start_observer() { # $1 observer  $2 fio_pid  $3 tag
	case "$1" in
	baseline)     OBS_PID="" ;;
	uscope-agg)   "$URINGSCOPE" --no-doctor -p "$2" \
	                  > "$RESULTS/$3.uscope.txt" 2>&1 & OBS_PID=$! ;;
	uscope-trace) "$URINGSCOPE" --no-doctor --trace "$RESULTS/$3.perfetto.json" \
	                  -p "$2" > "$RESULTS/$3.uscope.txt" 2>&1 & OBS_PID=$! ;;
	perf)         perf record -e 'io_uring:*' -o "$RESULTS/$3.perf.data" \
	                  -p "$2" > /dev/null 2>&1 & OBS_PID=$! ;;
	bpftrace)     bpftrace -e 'tracepoint:io_uring:io_uring_complete { @c = count(); }' \
	                  > "$RESULTS/$3.bpftrace.txt" 2>&1 & OBS_PID=$! ;;
	strace)       strace -c -f -o "$RESULTS/$3.strace.txt" -p "$2" \
	                  > /dev/null 2>&1 & OBS_PID=$! ;;
	esac
}

run_cell() { # $1 workload  $2 observer  $3 run-index
	local tag="$1.$2.r$3" job="workloads/$1.fio"
	echo ">>> $tag"
	sync; echo 3 > /proc/sys/vm/drop_caches
	local j0 j1
	j0=$(cpu_jiffies)

	# fio pinned to cpus 0-3; observers land elsewhere so their cost is
	# visible as system CPU, not stolen fio cycles.
	taskset -c 0-3 fio "$job" --output "$RESULTS/$tag.fio.json" &
	local FIO_PID=$!
	sleep 2   # let fio open files / create rings before attaching
	start_observer "$2" "$FIO_PID" "$tag"

	wait "$FIO_PID"
	[ -n "${OBS_PID}" ] && { kill -INT "$OBS_PID" 2>/dev/null || true; wait "$OBS_PID" 2>/dev/null || true; }
	j1=$(cpu_jiffies)
	echo "{\"cell\":\"$tag\",\"cpu_jiffies\":$((j1-j0))}" > "$RESULTS/$tag.sys.json"
}

main() {
	machine_info
	local wls="$WORKLOADS"
	[ "${1:-all}" != all ] && wls="$1"
	for wl in $wls; do
		for obs in $OBSERVERS; do
			for r in $(seq 1 "$RUNS"); do
				run_cell "$wl" "$obs" "$r"
			done
		done
	done
	echo "done -> $RESULTS/ ($(ls "$RESULTS" | wc -l) files)"
	echo "next: bench/plot.py (TODO) or hand the directory to pandas"
}
main "$@"
