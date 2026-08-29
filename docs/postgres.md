# Profiling PostgreSQL 18's io_uring with uringscope

PostgreSQL 18 added asynchronous I/O, and with `io_method = io_uring` it
submits reads through io_uring rather than blocking in `pread`. That moves
a real part of query latency below the line `EXPLAIN (ANALYZE, BUFFERS)`
can see. `EXPLAIN` tells you a scan read 324,991 blocks, not that 94% of
those reads detoured through kernel worker threads on the way back.

This guide shows what uringscope sees on a stock PostgreSQL 18, which knobs
move it, and the several ordinary situations where the report is
legitimately empty.

Every number below was measured on the setup in [Caveats](#caveats). Treat
them as illustrative shapes, not benchmarks.

## Setup

```sh
# PostgreSQL 18 from PGDG
sudo apt install -y postgresql-common
sudo /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y
sudo apt install -y postgresql-18 postgresql-client-18

# this build must actually have io_uring support
ldd /usr/lib/postgresql/18/bin/postgres | grep uring
#   liburing.so.2 => /lib/x86_64-linux-gnu/liburing.so.2
```

`io_method` **defaults to `worker`, not `io_uring`**. That is asynchronous
too, but through a pool of helper processes rather than the kernel. Switch
it explicitly. It is postmaster-context, so the cluster must restart:

```sh
sudo -u postgres psql -c "ALTER SYSTEM SET io_method = 'io_uring'"
sudo pg_ctlcluster 18 main restart
sudo -u postgres psql -tAc 'SHOW io_method'   # must print io_uring
```

Install uringscope (the static binary needs no toolchain):

```sh
curl -LO https://github.com/rch0wdhury/uringscope/releases/latest/download/uringscope-$(uname -m)
chmod +x uringscope-$(uname -m) && sudo mv uringscope-$(uname -m) /usr/local/bin/uringscope
```

A note on containers: Docker's default seccomp profile blocks the io_uring
syscalls, so a PostgreSQL running under stock Docker is not using io_uring
at all, whatever `io_method` says. Bare metal and VMs are the interesting
targets.

## What PostgreSQL 18 actually sends through io_uring

This decides whether uringscope has anything to tell you, so it comes
first. Measured, not inferred:

| workload | goes through io_uring? |
|---|---|
| sequential scan (heap) | **yes** |
| bitmap heap scan | **yes** |
| single-block random reads (index → heap fetch) | no |
| heap writes, checkpointer, WAL, fsync | no |

PostgreSQL 18 wired AIO into its **read-stream** paths, the ones that know
what they will need next and can queue it. A 46,680-transaction `pgbench`
run doing random single-row `UPDATE`s produced **zero** io_uring
submissions, while `pg_stat_io` recorded 325,817 relation writes and 24,375
WAL fsyncs for the same period. All of that I/O was synchronous.

So uringscope will look idle on an OLTP point-lookup workload even with
`io_method = io_uring` set correctly. That is not a failed attach. The tool
is most useful on analytical and bulk-read work.

## Attaching

Three patterns:

```sh
sudo uringscope -a -d 20                 # everything on the box (simplest)
sudo uringscope -p $(pgrep -f 'postgres.*checkpointer' ) -f -d 20
sudo uringscope -p <backend-pid> -d 20   # one backend
```

For the last one, get the pid from the session you want to watch:

```sql
SELECT pg_backend_pid();
```

Two things about PostgreSQL's rings that will otherwise confuse you:

- A backend holds roughly **140 io_uring file descriptors**. They are
  created by the postmaster at startup and inherited across `fork()`, not
  created per backend or per query. Ring fd numbers are therefore not
  identifiers you can map back to a session.
- The report's ring listing shows the owning pid (since v0.3.0), which you
  can join against `pg_stat_activity`. For clean per-backend numbers,
  attach with `-p` instead of `-a`.

### The trap: `count(*)` does no I/O

The obvious smoke-test query is misleading:

```sql
SELECT count(*) FROM pgbench_accounts;   -- reads nothing
```

The planner serves it as an index-only scan out of `shared_buffers`. On a
3GB table this issued **one** `pread64` and 507 syscalls in total, and
uringscope correctly reported zero submissions. Force a real heap scan by
filtering on an unindexed column:

```sql
SELECT count(*) FROM pgbench_accounts WHERE abalance = -12345;
-- Seq Scan ... Buffers: shared hit=2878 read=324991
```

Check the plan before concluding the tool is broken.

### The control: prove the tool works

When a report is empty, this settles whether the problem is the tool or the
workload in about ten seconds:

```sh
sudo uringscope -d 8 -- ./test/pathology/pathogen punt 2000
#  submissions: 2000   punted to io-wq: 2000 (100.0%)
#  [PUNT] 100.0% of requests fell back to the io-wq async worker pool
```

If that works and PostgreSQL's report is empty, the empty report is real.

## Experiment 1: the cold-cache punt storm

```sh
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches
sudo uringscope -a -d 20 --json=cold.json &
psql bench -tAc 'SET max_parallel_workers_per_gather=0;
                 SELECT count(*) FROM pgbench_accounts WHERE abalance = -12345'
```

A stock, untuned PostgreSQL 18 trips three findings on an ordinary scan:

```
[PUNT]    94.2% of requests fell back to the io-wq async worker pool (35249 of 37410).
[WORKERS] io-wq spawned 64 distinct worker threads (24 CPUs).
[BATCH]   averaging only 0.90 SQEs per io_uring_enter() across 40954 calls.
```

Run it again warm (no `drop_caches`) and compare:

| | cold | warm |
|---|---|---|
| submissions | 37410 | 37358 |
| punted | 94.2% | 74.1% |
| READ avg latency | 256.4us | **14.2us** |
| READ p99 | 1048.6us | **131.1us** |
| io-wq worker threads | 64 | 64 |

**Read the latency, not the punt rate.** You might expect a warm cache to
eliminate punting. It does not: the rate falls only 20 points and the
worker count does not move at all. What changes is what a punt costs,
about 18x on average here. A high punt rate on buffered reads is normal.
A high punt rate on a cold cache is where the p99 comes from.

`untracked_completions` was 0 in both runs, so these numbers cover every
request, not a sample.

## Experiment 2: the knobs that move it

`io_combine_limit` is measured in 8kB blocks, so a bare integer works. Same
cold scan each time:

| `io_combine_limit` | submissions | `io_uring_enter` calls | punt % | READ avg |
|---|---|---|---|---|
| **128kB (default)** | 37264 | 41430 | 94.8 | 243.3us |
| 32kB | 77094 | 83539 | 97.3 | 185.6us |
| 8kB | 252436 | 252290 | 77.7 | 64.8us |

Shrinking it 16x multiplies submissions by 6.8 and syscalls by 6.1 for
identical bytes. Watch the trap here: punt rate falls and per-request
latency improves, because each request is now a sixteenth the size.
uringscope's `--diff` reports this as `IOPS +578%`, `punt rate fell`,
`READ p50 -87.5%`. Every line reads like a win for what is plainly a
pessimization. Compare submissions and syscalls alongside latency. A rate
that improves because the unit of work shrank is not an improvement.
(Since v0.3.0 the diff table includes a submissions row and warns when the
request count moves sharply.)

`effective_io_concurrency` is blunter. On a bitmap heap scan:

| `effective_io_concurrency` | submissions |
|---|---|
| **16 (default)** | 3957 |
| 1 | **0** |

At 1, PostgreSQL stops using io_uring for the scan and falls back to
synchronous reads. The query still runs and returns the same rows. If
uringscope shows nothing on a bulk-read query, check this before anything
else.

## Experiment 3: `io_method`, and why an empty report is a diagnosis

Same cold scan under each method (each needs a restart):

| `io_method` | wall | uringscope submissions | PG io worker procs |
|---|---|---|---|
| **io_uring** | **1.60s** | 20543 | 0 |
| worker | 1.88s | 0 | 3 |
| sync | 2.65s | 0 | 0 |

On this setup io_uring was the fastest of the three even while punting 97%
of its requests. A high punt rate is a reason to look at why the fast path
is missed, not a reason to abandon io_uring.

Under `worker` and `sync`, uringscope observes nothing, and since v0.3.0 it
says exactly that instead of implying health:

```
  [NODATA] no io_uring activity observed in this 20.0s window: 0 submissions,
           0 completions (0 rings created). Nothing was measured -- this is
           not a clean bill of health.
```

The empty report is itself the diagnosis. Seeing `NODATA` while you
believed `io_method=io_uring` was live means checking `SHOW io_method` and
`effective_io_concurrency` next. (`NODATA` is severity INFO and excluded
from `--fail-on`, so it never fails a CI gate on its own.)

On uringscope **v0.2.1 and earlier** the same situation printed "no
pathologies detected". That reads as confirmation that your tuning took
effect when in fact nothing was measured. If your binary says that on a
zero-submission run, upgrade, or gate on a non-zero submission count
yourself.

## Experiment 4: taking the doctor's advice

The `PUNT` finding points at O_DIRECT. PostgreSQL has a developer GUC for
that. **`debug_io_direct` is not a production setting.** It exists for
PostgreSQL developers, and this experiment is here to make a point, not as
a recommendation.

| | buffered | `debug_io_direct='data'` |
|---|---|---|
| submissions | 20543 | 20553 |
| punted | 97.2% | **0.0%** |
| io-wq workers | 64 | **0** |
| READ avg | 256.4us | 682.5us |
| READ p99 | 1048.6us | 2097.2us |
| wall | 1.60s | 1.54s |

The punts vanish completely and the `PUNT` and `WORKERS` findings disappear
from the report. The query is no faster. Per-request latency is 2.7x worse,
and identical wall time at higher per-request latency means the effective
queue depth went up.

It cannot help PostgreSQL here for two structural reasons. O_DIRECT gives
up the page cache and readahead at the same rate it removes punts, and the
other half of the advice, registered buffers, is not something PostgreSQL
exposes.

**A finding disappearing is not the same as the workload improving.**
uringscope tells you the mechanism changed. Only the clock tells you
whether that was worth doing.

## Findings → PostgreSQL knobs

| finding | on PostgreSQL 18 it means | what to actually do |
|---|---|---|
| `PUNT` on READ/READV | buffered reads missing the page cache | Get more of the working set in memory: `shared_buffers`, more RAM, a smaller hot set. O_DIRECT is not available to you in production. |
| `WORKERS` | io-wq fan-out from those punts | Root-cause the punts. PostgreSQL does not expose `io_uring_register_iowq_max_workers()`. |
| `BATCH` ~1 SQE/enter | PG submits roughly one read per syscall | Largely structural in 18. Raising `io_combine_limit` gets more bytes per submission even though SQEs/enter stays near 1. |
| `NODATA` (empty report) | not using io_uring on this path | Check `SHOW io_method`, `effective_io_concurrency`, and whether the workload is a read-stream path at all. |
| `OVERFLOW`, `LEAK`, `HAZARD-*` | not observed on stock PG18 | If you see these on PostgreSQL, that is worth reporting upstream. |

## Cross-checking against PostgreSQL's own view

`pg_aios` shows in-flight AIOs and is useful for confirming what is being
submitted:

```
 pid   | state            | operation | length | target_desc
 21178 | COMPLETED_SHARED | readv     |  16384 | blocks 1..2 in file "base/16388/16404"
```

It is a poor throughput instrument, though. Individual IOs complete faster
than you can sample the view. 25 samples at 80ms intervals during a cold
scan mostly returned zero rows. Use `pg_aios` to catch a stalled AIO,
`pg_stat_io` for volume, and uringscope for rate, latency, and where
requests actually went.

## In CI

The JSON report is a versioned machine API ([json.md](json.md)). Findings
live under `doctor[]`, not `findings[]`:

```sh
sudo uringscope -a -d 20 --json=report.json --fail-on=warn -p "$PID" || alert
jq -r '.doctor[] | "\(.severity) \(.tag): \(.message)"' report.json
```

Per-op `PUNT` entries carry `evidence.op` and the summary entry does not,
which is how to tell them apart when scripting. Given everything above,
gate on a regression against a `--baseline` rather than on absolute punt
rate. On buffered PostgreSQL reads a high punt rate is the normal
condition.

## Caveats

Measured on PostgreSQL 18.6 (PGDG) on kernel 6.6.87 under WSL2, 24 CPUs,
7GB RAM, ext4 on a virtual disk, `shared_buffers = 1GB`, `pgbench -i -s 200`
(`pgbench_accounts` = 2991 MB). Absolute latencies on a VM disk are not
representative of bare-metal NVMe. The shapes are what this guide is about:
punt ratios, warm/cold ratios, and which paths use io_uring at all.
