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
# KEEP_RAW    - 1 to keep raw perf.data / perfetto traces (GBs per cell at
#               NVMe rates); default summarizes byte counts + stats and deletes
# MIN_FREE_GB - refuse to start a cell below this much free space (default 12)
set -eu
cd "$(dirname "$0")"

: "${TARGET_DEV:?set TARGET_DEV to a block device you can clobber}"
: "${TARGET_FILE:=/tmp/uringscope-bench.dat}"
: "${RUNS:=5}"
: "${KEEP_RAW:=0}"
: "${MIN_FREE_GB:=12}"
URINGSCOPE=${URINGSCOPE:-../uringscope}
RESULTS=results
mkdir -p "$RESULTS"
export TARGET_DEV TARGET_FILE

# At saturation, perf record -e 'io_uring:*' can write >10G in one 70s cell.
# Rotate so on-disk size stays bounded while perf keeps doing its full work
# (the overhead being measured includes writing the data out).
PERF_ROTATE=""
if perf record -h 2>&1 | grep -q -- --switch-max-files; then
	PERF_ROTATE="--switch-output=1G --switch-max-files=2"
fi

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
	perf)         perf record -e 'io_uring:*' $PERF_ROTATE \
	                  -o "$RESULTS/$3.perf.data" \
	                  -p "$2" > "$RESULTS/$3.perf.log" 2>&1 & OBS_PID=$! ;;
	bpftrace)     bpftrace -e 'tracepoint:io_uring:io_uring_complete { @c = count(); }' \
	                  > "$RESULTS/$3.bpftrace.txt" 2>&1 & OBS_PID=$! ;;
	strace)       strace -c -f -o "$RESULTS/$3.strace.txt" -p "$2" \
	                  > /dev/null 2>&1 & OBS_PID=$! ;;
	esac
}

# The per-event artifacts (perfetto JSON, perf.data) are the only unbounded
# outputs of the grid -- everything the protocol needs from them is their
# byte rate (README: "trace output bytes/sec") and perf's lost-sample stats.
# Extract those, then delete the raw files unless KEEP_RAW=1. Echoes the
# artifact size in bytes. Note: when perf rotated (PERF_ROTATE), on-disk
# size undercounts total bytes written; the .perf.log keeps perf's own
# numbers.
finish_observer() { # $1 observer  $2 tag
	local f bytes=0
	case "$1" in
	uscope-trace)
		f="$RESULTS/$2.perfetto.json"
		bytes=$(stat -c %s "$f" 2>/dev/null || echo 0)
		[ "$KEEP_RAW" = 1 ] || rm -f "$f"
		;;
	perf)
		# rotation leaves perf.data plus timestamped chunks
		bytes=$(du -cb "$RESULTS/$2.perf.data"* 2>/dev/null | awk 'END{print $1}')
		perf report --stats -i "$RESULTS/$2.perf.data" \
			> "$RESULTS/$2.perfstats.txt" 2>&1 || true
		[ "$KEEP_RAW" = 1 ] || rm -f "$RESULTS/$2.perf.data"*
		;;
	esac
	echo "${bytes:-0}"
}

free_gb() { df -BG --output=avail "$RESULTS" | tail -1 | tr -dc '0-9'; }

run_cell() { # $1 workload  $2 observer  $3 run-index
	local tag="$1.$2.r$3" job="workloads/$1.fio"
	echo ">>> $tag"
	if [ "$(free_gb)" -lt "$MIN_FREE_GB" ]; then
		echo "abort before $tag: <${MIN_FREE_GB}G free -- a trace/perf cell" \
		     "could ENOSPC mid-run (override with MIN_FREE_GB)" >&2
		exit 1
	fi
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
	local obs_bytes; obs_bytes=$(finish_observer "$2" "$tag")
	echo "{\"cell\":\"$tag\",\"cpu_jiffies\":$((j1-j0)),\"obs_bytes\":$obs_bytes}" > "$RESULTS/$tag.sys.json"
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
