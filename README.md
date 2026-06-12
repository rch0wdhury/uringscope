# uringscope

[![build](https://github.com/rch0wdhury/uringscope/actions/workflows/build.yml/badge.svg)](https://github.com/rch0wdhury/uringscope/actions/workflows/build.yml) [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20672340.svg)](https://doi.org/10.5281/zenodo.20672340)

**Complete kernel + userspace tracing for io_uring.** A single-binary flight
recorder and doctor that attaches to any process using io_uring — any language,
any runtime — and reconstructs what each request actually did: per-opcode
latency, hidden async-worker punts, batching efficiency, stalls, and a `doctor`
that names the problem and points at a fix.

## Quick start

```sh
# build + install (Debian/Ubuntu — see Install for Fedora and static builds)
sudo apt install clang libbpf-dev linux-tools-common linux-tools-$(uname -r)
make && sudo make install

# the three commands you'll reach for most:
sudo uringscope ./myapp           # run a program under the scope
sudo uringscope -p 31337 -d 30    # watch a running pid for 30 seconds
sudo uringscope -a -d 10          # everything on the box for 10 seconds
```

Each run prints a per-ring report that ends in a `doctor` verdict — here's what
that looks like:

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

Because io_uring carries its request flow through shared-memory rings rather
than a system call per request, syscall-level tracing alone sees only ring
setup, not the requests inside. uringscope covers both sides: it reads the
kernel's io_uring tracepoints — plus optional liburing uprobes for the
userspace boundary — and stitches them back into per-request flows. The kernel
ships ~18 static tracepoints for this, but their prototypes are not ABI and have
churned every few releases (the one prior tool in this space pinned itself to
kernels 6.1–6.7); uringscope probes kernel BTF at startup and adapts.

What it surfaces:

- **per-opcode latency histograms** (submit → complete), aggregated *inside the
  kernel* — per-event data never crosses to userspace in the default mode
- **async-punt detection**: which requests silently fell off the
  submit-path fast path into the io-wq worker pool (the classic hidden
  tail-latency source), per opcode
- **SQPOLL stall accounting**: how long your `iou-sqp` thread spent off-CPU
- **io-wq worker fan-out**: how many `iou-wrk` threads the kernel spawned
- **batching efficiency**: SQEs per `io_uring_enter()` syscall
- **CQ overflow / short write / poll-retry / task-work counters**
- **dropped-operation (leak) detection**: requests submitted but never
  completed — the buffer is pinned and the app may be waiting on a
  completion it will never reap
- **`--check` correctness mode** ("ASan for the io_uring boundary"):
  overlapping in-flight buffer ranges, registered-buffer lifetime
  violations (`HAZARD-BUFREG`), and the unmap variant of buffer
  use-after-free (`HAZARD-UAF`) — with an explicit account of which
  hazards are and aren't detectable from the kernel side
- **end-to-end boundary timing** via best-effort liburing uprobes:
  submit batching and CQE-ready→reap lag, the two segments kernel
  tracepoints can't see
- **`doctor`**: named pathologies with evidence and a suggested fix
- **live mode** (`-i 2`, iostat-style) and a zero-dependency
  **OpenMetrics endpoint** (`--metrics :9090`) for Prometheus scraping
- **`--json`** machine-readable reports, plus `--baseline`/`--diff` for
  before/after comparisons with doctor commentary on what changed
- **`--trace`**: a per-request timeline you can open in
  [Perfetto](https://ui.perfetto.dev)

## Install / build

```sh
# Debian/Ubuntu
sudo apt install clang libbpf-dev linux-tools-common linux-tools-$(uname -r)
# Fedora
sudo dnf install clang libbpf-devel bpftool

make             # ./uringscope
make STATIC=1    # fully static binary you can scp anywhere
sudo make install  # -> /usr/local/bin (PREFIX= to relocate)
```

Requirements at *runtime*: a kernel with `CONFIG_DEBUG_INFO_BTF=y` (every
mainstream distro since ~5.15) and CAP_BPF + CAP_PERFMON or root. The tool
itself links only libbpf/libelf/zlib — liburing is **not** a dependency of
uringscope; it is needed only to build the test injector
(`test/pathology/pathogen.c`) and by the fio benchmark workloads
(`apt install liburing-dev fio` for those). The static binary
(`make STATIC=1`, attached to GitHub releases) is the portable artifact.

## Usage

```sh
sudo uringscope ./myapp --my-args        # run a command under the scope
sudo uringscope -p 31337 -d 30           # watch a running pid for 30s
sudo uringscope -a -d 10                 # everything on the box, 10s
sudo uringscope -c -p 31337              # compact: per-op table + doctor,
                                         #   like strace -c
sudo uringscope -e op=READ,WRITE -p 31337 # display only these opcodes
sudo uringscope -e punt -p 31337         #   ...or only punted / -e error
sudo uringscope -f -p 31337              # follow children/threads too
sudo uringscope -i 2 -p 31337            # live per-op deltas every 2s
sudo uringscope --metrics :9090 -p 31337 # OpenMetrics at :9090/metrics
sudo uringscope --json report.json -- ./myapp  # machine-readable report
sudo uringscope --baseline b.json -- ./myapp   # save for later --diff
sudo uringscope --diff b.json -- ./myapp # delta table vs the baseline
sudo uringscope --trace t.json -- ./myapp # + Perfetto timeline
sudo uringscope --check -- ./myapp       # hazard mode: buffer races,
                                         #   reg-buffer lifetime, unmap-UAF
sudo uringscope --no-doctor -p 31337     # numbers only, no verdicts
uringscope --version                     # version + kernel support tiers
uringscope --list-ops                    # the opcode table
```

(`-c` was the short form of `--check` before 0.2; it now means the
strace-style compact summary, and `--check` is long-form only.)

`--check` is a higher-overhead debugging/CI mode (run your io_uring test
suite under it like ASan); it detects two concurrently in-flight requests
that target overlapping memory — silent data corruption that returns no
error.

Containers: note that Docker's default seccomp profile blocks io_uring
syscalls entirely, so the interesting targets are bare-metal and VM workloads
(databases, storage engines, io_uring-native runtimes).

PID namespaces (WSL2 distros, containers): the kernel reports root-namespace
tgids while you filter on namespaced pids. uringscope detects that it is in a
child pid namespace and translates in the BPF programs automatically, so
`uringscope ./myapp` works unchanged under WSL2.

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
`test/kernels.txt` for the CI matrix. `test/vmtest/run.sh <kernel>` boots a
kernel under virtme-ng/KVM and runs the full suite on it, asserting the BTF
probe selected the right variant (e.g. 6.17's cqe-collapsed
`io_uring_complete`) and that every injected pathology is still detected —
the portability claim, executed rather than asserted.

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

## Testing / validating effectiveness

`test/pathology/` deliberately injects pathologies and scores the doctor
against ground truth:

```sh
make                          # build uringscope
cd test/pathology && sudo ./run.sh
```

`pathogen.c` induces one anomaly per scenario (punt storm, no batching, CQ
overflow, error floods, dropped/leaked requests, SQPOLL stalls, worker
storms, buffer use-after-unmap, registered-buffer races and lifetime
violations, and reaping lag) and prints machine-readable `GROUND-TRUTH`
lines; `run.sh` runs each under the scope and checks the doctor reported
it. The same harness produces the detection-effectiveness table.

## Benchmarks / evaluation

`bench/` contains the fio workloads, baseline commands, and collection script
used for the overhead-vs-fidelity evaluation. See `bench/README.md`.

## Status

Early. The aggregate mode, doctor rules, hazard (`--check`) detectors,
live/metrics/JSON output, liburing-uprobe boundary timing, and Perfetto
export work on modern kernels; the 5.15 legacy tier remains best-effort
(counters + batching only). Issues with `uname -r` + 
`bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep io_uring_`
output gratefully accepted — tracepoint churn reports are this project's
lifeblood.

## Contributing & support

Bug reports, tracepoint-churn reports, and doctor-verdict disputes are all
welcome on the [issue tracker](https://github.com/rch0wdhury/uringscope/issues);
see [CONTRIBUTING.md](CONTRIBUTING.md) for how to run the test suites and
what a good report looks like.

## Citing

If you use uringscope in your research, please cite it (see
[CITATION.cff](CITATION.cff)). The archived release is on Zenodo:
[10.5281/zenodo.20672340](https://doi.org/10.5281/zenodo.20672340).

## License

BPF programs: GPL-2.0-only OR BSD-3-Clause. Userspace: MIT. See `LICENSE`.
