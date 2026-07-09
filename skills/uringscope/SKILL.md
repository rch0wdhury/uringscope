---
name: uringscope
description: Diagnose io_uring performance and correctness problems with uringscope — an eBPF flight recorder and doctor. Use when a Linux process that uses io_uring shows tail latency, unexplained iou-wrk-* thread explosions, suspiciously syscall-heavy behavior, silent buffer corruption, or completions that never arrive; or when strace shows only opaque io_uring_enter calls. Works on any language/runtime (liburing, tokio-uring, glommio, netty, fio, TigerBeetle-class engines).
---

# uringscope: diagnosing io_uring with a flight recorder

uringscope attaches eBPF to the kernel's io_uring tracepoints,
reconstructs each request's lifecycle (submit → inline/poll-retry/io-wq
punt → complete → reap), and reports **named findings with evidence and a
suggested fix**. strace cannot see io_uring request flow at all — do not
bother with it here.

## When to reach for it

- p99/p999 latency regressions in an io_uring app (databases, storage
  engines, tokio-uring/glommio/eio runtimes, netty's io_uring transport)
- hundreds of `iou-wrk-*` kernel threads in `ps -eLf`
- io_uring app doing a syscall per operation (defeats the point)
- suspected buffer races / silent data corruption around submission
- completions that never arrive (app hangs waiting)

## Requirements (check before running)

- root (BPF) and a BTF kernel (`/sys/kernel/btf/vmlinux` exists; stock on
  5.15+ distro kernels). Kernels 5.15 → 6.17+ supported; on 5.15 the tool
  degrades to counters+batching (no punt attribution) and says so.
- **io_uring is blocked by Docker's default seccomp profile** — if the
  workload runs in a container without a custom profile, io_uring isn't
  in play at all; look elsewhere.
- Install if needed: https://github.com/rch0wdhury/uringscope —
  `make && sudo make install` (clang, libbpf ≥1.0, bpftool), or the
  static binary from the GitHub releases. `uringscope --version` prints
  the per-feature support tier for the running kernel.

## How to run it

Always prefer JSON + the exit-code gate; never parse the ASCII tables.

```sh
# attach to a running process, bounded 10s window
sudo uringscope --json --fail-on=warn -p <PID> -d 10

# spawn a workload under the scope (its stdout interleaves on stdout,
# so send JSON to a file)
sudo uringscope --json=report.json --fail-on=warn -- ./myapp args...

# buffer-hazard mode (ASan-style; higher overhead, use on tests not prod)
sudo uringscope --check --json=report.json -- ./my-test-suite

# before/after a fix
sudo uringscope --baseline before.json -p <PID> -d 30
# ...apply fix...
sudo uringscope --diff before.json -p <PID> -d 30
```

Exit codes: `0` clean · `1` uringscope/setup error · spawned command's
own nonzero status propagates · `3` = doctor found something at/above
`--fail-on`. So `if ! uringscope --fail-on=warn ...; then` is a valid CI
gate with no parsing.

Read findings from `.doctor[]` in the JSON: each has a stable `tag`,
`severity`, human `message`, machine `evidence`, and a `suggestion`.
Schema reference: `docs/json.md` in the uringscope repo. `jq` one-liner:

```sh
jq -r '.doctor[] | "\(.severity) \(.tag): \(.message)"' report.json
```

## Finding tags → what to change in the code

### `PUNT` — requests detour through the io-wq thread pool
The classic hidden tail-latency source. The per-op detail rows name the
opcode. Fixes by cause:
- **Buffered reads punting** (cold page cache): switch to `O_DIRECT` +
  registered buffers. liburing: `io_uring_prep_read_fixed` after
  `io_uring_register_buffers`. tokio-uring/glommio: open with
  `O_DIRECT`/DMA file APIs (glommio `DmaFile`).
- **Writes/fsync punting**: expected — these opcodes always execute on
  io-wq. The fix is bounding impact, not eliminating: cap the pool with
  `io_uring_register_iowq_max_workers()`, separate WAL/fsync onto its own
  ring, batch fsyncs.
- **Socket ops punting**: unusual (they should poll-retry) — look for
  `MSG_WAITALL` or exotic socket types.

### `WORKERS` — io-wq worker explosion
Each blocking op pins a worker thread. Cap with
`io_uring_register_iowq_max_workers()` (liburing ≥2.2; netty
`IoUring` transport exposes maxBoundedWorker options). Root-cause the
punts first (`PUNT`).

### `BATCH` — syscall-per-operation
~1 SQE per `io_uring_enter` means epoll-priced io_uring. Queue several
SQEs, then one `io_uring_submit()`. In liburing, stop calling
`io_uring_submit` after every prep; in event loops, submit once per loop
tick. Or set `IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SINGLE_ISSUER`
(6.1+), or SQPOLL if a core is budgeted for it.

### `OVERFLOW` — completion queue overflowed (CRIT)
Overflowed CQEs take a slow allocating path. Grow the CQ
(`IORING_SETUP_CQSIZE`, cq_entries ≥ max in-flight), or reap more often.
Multishot ops make CQ pressure worse — budget for many CQEs per SQE.

### `SQPOLL` — submission poller misbehaving
- WARN (off-CPU a lot): each burst pays a wakeup; raise
  `sq_thread_idle` or drop SQPOLL for this duty cycle.
- INFO (never switched): it's burning a full core by design — verify
  that's intended.

### `DEFER-TW` — DEFER_TASKRUN but task work never runs
Completions sit unprocessed. With `IORING_SETUP_DEFER_TASKRUN` the
submitting thread must reap via `io_uring_get_events()` /
`io_uring_enter(GETEVENTS)`.

### `LEAK` — submitted, never completed
The evidence names opcodes and `user_data` tokens — grep the codebase
for those tokens. Usual causes: lost `user_data` bookkeeping, a wait
loop that miscounts, poll requests on an fd that never becomes ready
(the finding says if most are poll-parked). Buffers referenced by leaked
requests must outlive them — this is how buffer UAFs start.

### `HAZARD` / `HAZARD-BUFREG` / `HAZARD-UAF` (--check mode, CRIT)
Submission-boundary memory bugs, all with `user_data` tokens and address
ranges in evidence:
- `HAZARD`: two in-flight ops overlap the same buffer — silent
  corruption, no error is ever returned. Serialize: reap the first
  completion before submitting the second.
- `HAZARD-BUFREG`: buffer index unregistered/re-registered with live
  fixed-op references. Quiesce in-flight fixed ops first.
- `HAZARD-UAF`: munmap while an op targets the range. Keep mappings
  alive until the completion is reaped. (Allocator `free()`/stack reuse
  is NOT detectable from the kernel — absence of findings ≠ absence of
  UAF.)

### `REAP-LAG` — completions ready but not collected
The kernel finished; the event loop is slow to come back. Poll the CQ
more often or block in a waiting `io_uring_enter`. (Needs liburing
uprobes; inlined reap paths make this unmeasurable — the tool says so
rather than guessing.)

### `ERRORS` / `SHORT-WRITE`
High `res < 0` rate makes latency look deceptively good (errors complete
fast). Break down per opcode before trusting latency numbers.

### `TOOL`
Self-report that uringscope's own fidelity degraded (map pressure, trace
drops). Not a workload problem; never trips `--fail-on`.

## Interpreting cleanly

- No findings ≠ no problem — it means none of the named pathologies
  fired. Check `.ops[]` latency percentiles yourself for raw numbers.
- Percentiles are log2-bucket upper bounds (powers of two), not exact.
- A saturated SQPOLL ring with zero syscalls and 0% idle is *healthy*;
  the doctor staying silent there is correct.
- Overhead: aggregate mode is production-safe (single-digit % on
  device-bound work); `--trace` and `--check` are diagnosis tiers.
