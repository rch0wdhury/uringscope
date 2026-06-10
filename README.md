# uringscope

**A flight recorder and doctor for io_uring — the `strace` that io_uring never had.**

```
$ sudo uringscope ./myapp
... myapp runs ...

uringscope report (12.4s, 8 cpus)
=================================

ring #0 fd=5  sq=256 cq=512  flags: (none)        myapp pid 31337

submission
  io_uring_enter() calls          1,204,332
  SQEs submitted                  1,209,544     avg batch 1.0/enter   <-- !
  completions                     1,209,540

per-op latency (submit -> complete)
  READ      1,102,238 reqs   p50 14us   p99 1.2ms   punted 63.1%      <-- !
  WRITE        91,002 reqs   p50 22us   p99 410us   punted  2.0%
  ...

doctor
  [BATCH]  You average 1.0 SQEs per io_uring_enter(). You are paying a
           syscall per request -- the thing io_uring exists to avoid.
           Queue more SQEs before calling submit.
  [PUNT]   63% of READ requests fell off the fast path into io-wq worker
           threads (likely buffered reads missing the page cache). This
           is where your p99 lives. Consider O_DIRECT + registered
           buffers, or provoke readahead.
```

io_uring keeps its request flow in shared memory rings, so `strace` shows you
almost nothing — a problem noted on the strace mailing list in 2020 and never
fixed since. The kernel *does* ship ~18 static tracepoints for io_uring, but
their prototypes are not ABI and have churned every few releases, which is why
the one prior tool in this space pinned itself to kernels 6.1–6.7.

uringscope is a single binary that attaches to any process using io_uring (any
language, any runtime) and tells you what the ring actually did:

- **per-opcode latency histograms** (submit → complete), aggregated *inside the
  kernel* — per-event data never crosses to userspace in the default mode
- **async-punt detection**: which requests silently fell off the
  submit-path fast path into the io-wq worker pool (the classic hidden
  tail-latency source), per opcode
- **SQPOLL stall accounting**: how long your `iou-sqp` thread spent off-CPU
- **io-wq worker fan-out**: how many `iou-wrk` threads the kernel spawned
- **batching efficiency**: SQEs per `io_uring_enter()` syscall
- **CQ overflow / short write / poll-retry / task-work counters**
- **`doctor`**: named pathologies with evidence and a suggested fix
- **`--trace`**: a per-request timeline you can open in
  [Perfetto](https://ui.perfetto.dev)

## Install / build

```sh
# Debian/Ubuntu
sudo apt install clang libbpf-dev linux-tools-common linux-tools-$(uname -r)
# Fedora
sudo dnf install clang libbpf-devel bpftool

make            # ./uringscope
make STATIC=1   # fully static binary you can scp anywhere
```

Requirements at *runtime*: a kernel with `CONFIG_DEBUG_INFO_BTF=y` (every
mainstream distro since ~5.15) and CAP_BPF + CAP_PERFMON or root.

## Usage

```sh
sudo uringscope ./myapp --my-args        # run a command under the scope
sudo uringscope -p 31337 -d 30           # watch a running pid for 30s
sudo uringscope -a -d 10                 # everything on the box, 10s
sudo uringscope --trace t.json -- ./myapp # + Perfetto timeline
sudo uringscope --no-doctor -p 31337     # numbers only, no verdicts
```

Containers: note that Docker's default seccomp profile blocks io_uring
syscalls entirely, so the interesting targets are bare-metal and VM workloads
(databases, storage engines, io_uring-native runtimes).

## What the report means

| Section | Source | What to look for |
|---|---|---|
| avg batch / enter | `syscalls:sys_enter_io_uring_enter` | < 2 means you're paying syscall overhead per request |
| punted % | `io_uring:io_uring_queue_async_work` | high % on READ/WRITE = fast path missed; this is usually the p99 story |
| sqpoll off-cpu | `sched:sched_switch` on `iou-sqp-*` | the poller you paid a core for is asleep; raise `sq_thread_idle` or drop SQPOLL |
| workers seen | `sched:sched_switch` on `iou-wrk-*` | unbounded fan-out = blocking ops (buffered I/O, fsync) flooding io-wq |
| CQ overflow | `io_uring:io_uring_cqe_overflow` | CQ ring too small or reaping too slow; completions took the slow path |
| poll-retry | `io_uring:io_uring_poll_arm` | sockets/pipes not ready at submit; normal for network, news for disk |
| untracked completions | (tool fidelity) | requests submitted before attach, or map pressure; latency stats cover tracked reqs only |

## Kernel support

| Kernel | Tier | Notes |
|---|---|---|
| 6.1+ (incl. 6.6, 6.8, 6.12 LTS) | full | modern tracepoint prototypes |
| 5.15 LTS | counters + batching | legacy `submit_sqe`/`complete` prototypes; no punt attribution |
| < 5.15 | unsupported | |

uringscope probes the running kernel's BTF at startup and enables only the
program variants whose tracepoints (by name and prototype) exist — so a
missing tracepoint degrades one feature instead of failing the load. See
`docs/tracepoints.md` for the churn table this design is responding to, and
`test/kernels.txt` for the CI matrix.

## How it works (short version)

- CO-RE eBPF, `tp_btf` attachments to the kernel's io_uring tracepoints.
- Request state is read from the `io_kiocb` pointer through minimal,
  relocatable shadow structs (`bpf/io_uring_shims.bpf.h`) rather than trusting
  positional tracepoint arguments, because the *struct fields* have been far
  more stable than the *tracepoint prototypes*.
- Known layout changes (e.g. `io_kiocb.user_data` moving into `io_kiocb.cqe`
  in 5.19) are handled with CO-RE flavors + `bpf_core_field_exists()`.
- Renamed/resignatured tracepoints are handled with multiple compiled program
  variants; `src/probe.c` inspects kernel BTF and flips autoload per variant
  before load.
- Default mode aggregates everything in kernel maps (per-opcode log2 latency
  histograms, counters); userspace reads maps once at exit. `--trace` streams
  per-request records over a ring buffer instead.

Longer version: `docs/lifecycle.md` (the io_uring request lifecycle state
machine the tool reconstructs) and the paper draft under `paper/`.

## Benchmarks / evaluation

`bench/` contains the fio workloads, baseline commands, and collection script
used for the overhead-vs-fidelity evaluation. See `bench/README.md`.

## Status

Early. The aggregate mode, doctor rules, and Perfetto export work on modern
kernels; the 5.15 legacy tier and the liburing uprobe enrichment
(completion-reaping lag) are roadmap. Issues with `uname -r` + 
`bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep io_uring_`
output gratefully accepted — tracepoint churn reports are this project's
lifeblood.

## License

BPF programs: GPL-2.0-only OR BSD-3-Clause. Userspace: MIT. See `LICENSE`.
