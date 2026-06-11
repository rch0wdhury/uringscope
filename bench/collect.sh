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
# SETTLE      - seconds to wait after launching fio before attaching observers,
#               so the worker has created its io_uring ring (default 3)
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

# Find the fio PID that actually holds an open io_uring ring, i.e. has an
# anon_inode:[io_uring] fd. With thread=1 that's the launched pid itself
# (threads share the fd table, so the tgid shows the ring fd even when a
# worker thread created it). It also rescues fio builds/configs that still
# fork a worker *process* -- there the launched pid is an idle supervisor and
# the ring lives in a child. Retries briefly while the ring is being created;
# falls back to the launched pid if none is found.
ring_owner_pid() { # $1 launched fio pid
	local launched=$1 t p
	for t in 1 2 3 4 5 6 7 8; do
		for p in "$launched" $(pgrep -x fio 2>/dev/null); do
			[ -d "/proc/$p/fd" ] || continue
			if readlink "/proc/$p/fd/"* 2>/dev/null | grep -q '\[io_uring\]'; then
				echo "$p"; return 0
			fi
		done
		sleep 0.5
	done
	echo "$launched"
}

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
	# visible as system CPU, not stolen fio cycles. The workloads set
	# thread=1 so fio runs single-process, but we don't rely on that: we
	# attach to whichever fio pid actually owns the io_uring ring (see
	# ring_owner_pid). Without this, attaching to the launched pid when fio
	# forks a worker yields zero submissions -- the bug this harness had.
	taskset -c 0-3 fio "$job" --output-format=json \
		--output "$RESULTS/$tag.fio.json" &
	local FIO_PID=$!
	sleep "${SETTLE:-3}"   # let the worker create its ring before we attach
	local RING_PID; RING_PID=$(ring_owner_pid "$FIO_PID")
	if [ "$RING_PID" = "$FIO_PID" ]; then
		echo "    ring owner pid=$RING_PID"
	else
		echo "    ring owner pid=$RING_PID (launcher $FIO_PID is the supervisor)"
	fi
	start_observer "$2" "$RING_PID" "$tag"

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
