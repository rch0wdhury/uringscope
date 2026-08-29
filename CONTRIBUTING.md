# Contributing to uringscope

Thanks for your interest! This page covers how to report problems, get
help, and land changes.

## Reporting issues / getting support

Open a [GitHub issue](https://github.com/rch0wdhury/uringscope/issues).
Two reports are especially valuable:

- **Tracepoint churn** (the reports this project most depends on): if
  uringscope's startup tier summary shows `DEGRADED` or `off` rows on your
  kernel, include `uname -r` and the output of
  `bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep io_uring_`.
  That is usually enough to add a prototype variant (`src/probe.c` explains
  the three-step recipe).
- **Findings you disagree with**: a finding that fired on a healthy
  workload (false positive) or stayed silent on a sick one. Attach the
  report output and, if you can, a small reproducer.
  `test/faults/inject.c` shows the shape of a good one.

## Development workflow

```sh
make                          # build (needs clang, libbpf-dev, bpftool)
make test-offline             # findings unit tests, no kernel/root needed
sudo test/faults/run.sh       # full injection suite (root + BTF kernel)
sudo test/attach/run.sh       # attach-to-running-pid regression
```

A change is expected to keep all three green. New findings rules need an
offline unit test **including a false-positive guard** (see
`test/findings_offline.c`). New detectors need an injection scenario with
machine-readable `GROUND-TRUTH` lines and a `run.sh` row.

Ground rules the codebase tries to hold:

- **Degrade, never abort.** A missing tracepoint/symbol disables one
  feature and is reported in the tier summary. Only a missing submission
  tracepoint is fatal.
- **Honest bounds.** If something is not observable (allocator-freelist
  reuse, inlined liburing reap paths), the docs and the report say so.
  We do not fabricate numbers.
- **Conservative findings.** An analyzer that cries wolf gets ignored.
  Rules should fire on real problems with evidence, and the offline tests
  enforce the negative cases.
- Kernel-side reads go through CO-RE shims (`bpf/io_uring_shims.bpf.h`),
  not positional tracepoint args. BPF programs must pass the verifier on
  the kernels in `test/kernels.txt`.

Code style is kernel-ish C (tabs, 80-ish columns, comments explain *why*).
Userspace is MIT and BPF programs are GPL-2.0-only OR BSD-3-Clause. New
files need an SPDX header.

## Submitting changes

Fork, branch, and open a pull request against `main`. CI builds with gcc
and clang and runs the offline tests. Please run the root test suites
locally, since CI runners can't exercise every kernel path.
