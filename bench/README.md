# uringscope evaluation harness

Everything under here exists to produce uringscope's evaluation numbers.
The headline question:

> What does observing io_uring cost, at what fidelity, compared to the tools
> people actually reach for today?

## The grid

We measure **workloads x observers x kernels**, recording application-side
throughput/latency and system-side overhead for each cell.

### Workloads (`workloads/*.fio` + `workloads/*.c`)

| name | what it stresses | why it's in the set |
|---|---|---|
| `randread-direct.fio` | O_DIRECT 4k randread, iodepth 64, fixed buffers | the fast path; max IOPS; observer overhead is most visible here |
| `randread-buffered-cold.fio` | buffered 4k randread, cold page cache | forces io-wq punts -> exercises punt attribution (doctor's flagship rule) |
| `seqwrite-fsync.fio` | sequential write + periodic fsync | bounded io-wq pool, short writes |
| `sqpoll.fio` | randread with `sqthread_poll=1` | SQPOLL stall accounting; the "you paid a core for nothing" rule |
| `smallbatch.fio` | iodepth 1, sync-style submission | batching-efficiency rule (avg SQEs/enter ~ 1) |
| `netecho.c` | TCP echo server, multishot recv | multishot semantics, poll-retry path, non-storage io_uring |

Run each at three intensities: light (rate-limited 10% of max), moderate
(50%), saturation (uncapped). Overhead hides at light load and explodes at
saturation; the evaluation needs the whole curve.

### Observers (the comparison set)

| observer | command | role |
|---|---|---|
| baseline | (nothing) | reference |
| uringscope aggregate | `uringscope -p $(pidof fio)` | our default mode |
| uringscope trace | `uringscope --trace t.json -p ...` | our high-fidelity mode |
| perf | `perf record -e 'io_uring:*' -p ...` | the "obvious" alternative |
| bpftrace | `bpftrace -e 'tracepoint:io_uring:io_uring_complete { @c = count(); }' ` | the one-liner alternative |
| strace | `strace -c -f` | the syscall-level baseline (high overhead on io_uring) |

### Kernels

The matrix in `../test/kernels.txt` (5.15, 6.1, 6.6, 6.8, 6.12, mainline).
Full grid on 6.12; spot-check the overhead numbers on the others; the
*coverage* table (which features light up on which kernel) comes from CI.

## What to record per cell

Application side (fio json output / netecho stats):
- IOPS or req/s
- p50 / p99 / p99.9 / p99.99 completion latency
- run-to-run variance: >= 5 runs, report median + IQR; 60s runs after 10s warmup

System side:
- whole-system CPU% attributable to the observer
  (`pidstat -p <observer>` + delta of `/proc/stat` vs baseline)
- observer-induced events/sec (uringscope prints this; perf: `perf report --stats`)
- fidelity losses: uringscope `untracked` + ringbuf-drop counters; perf's
  "lost samples"; these are first-class results, not footnotes
- trace output bytes/sec (trace modes only)

Machine metadata (script captures automatically): kernel, CPU model, turbo
state, storage device + scheduler, fio version, mitigations.

## Running it

```sh
cd bench
sudo ./collect.sh randread-direct          # one workload, all observers
sudo ./collect.sh netecho                  # the network cell (needs nc)
sudo ./collect.sh all                      # the whole grid (hours)
ls results/                                # one JSON per cell + machine.txt
```

The netecho cell builds `workloads/netecho` on first use (needs liburing
dev headers) and drives it with `NET_CLIENTS` (64) concurrent `nc` echo
streams for `NET_DURATION` (60) seconds on `NET_PORT` (7777); the
app-side stats are the counters netecho prints on SIGINT, captured in
`$tag.netecho.txt`.

Disk: the per-event artifacts (perfetto JSON, perf.data) run to GBs per cell
at saturation -- the full grid would write >100G raw. `collect.sh` therefore
records their byte count into each cell's `.sys.json` (`obs_bytes`, the
bytes/sec input above), keeps perf's lost-sample stats (`.perfstats.txt`,
`.perf.log`), and deletes the raw files. Set `KEEP_RAW=1` to keep them
(rerun just the cell you want to inspect); `MIN_FREE_GB` (default 12) aborts
cleanly before a cell that could ENOSPC mid-run.

Pin everything: `collect.sh` uses taskset to keep fio, the observer, and
io-wq interference visible and repeatable. Do not run on a laptop on
battery; do not run in Docker (io_uring is seccomp-blocked there by default).

## The plots the evaluation needs

1. **Overhead vs load** — x: offered load (% of max IOPS), y: throughput loss
   % vs baseline, one line per observer, per workload. (The money plot.)
2. **Fidelity vs overhead** — scatter: x: CPU overhead, y: % of requests fully
   reconstructed (latency attributable). uringscope-aggregate should sit
   top-left; perf/trace modes drift right; strace sits far to the right.
3. **Tail-latency perturbation** — p99.9 with each observer attached vs
   baseline (observers that *change* the tail are lying to you about it).
4. **Coverage matrix** — features x kernels, colored by tier, generated from
   CI artifacts (`test/vmtest/out/`).
5. **Case study** — before/after fixing a doctor finding (e.g. the buffered
   punt storm in `randread-buffered-cold`): doctor report, the one-line fix,
   the p99 delta.
