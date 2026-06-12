# Contributing to uringscope

Thanks for your interest! This page covers how to report problems, get
help, and land changes.

## Reporting issues / getting support

Open a [GitHub issue](https://github.com/rch0wdhury/uringscope/issues).
Two reports are especially valuable:

- **Tracepoint churn** (this project's lifeblood): if uringscope's startup
  tier summary shows `DEGRADED` or `off` rows on your kernel, include
  `uname -r` and the output of
  `bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep io_uring_`.
  That is usually enough to add a prototype variant (`src/probe.c` explains
  the three-step recipe).
- **Doctor verdicts you disagree with**: a finding that fired on a healthy
  workload (false positive) or stayed silent on a sick one. Attach the
  report output and, if you can, a small reproducer — `test/pathology/
  pathogen.c` shows the shape of a good one.

## Development workflow

```sh
make                          # build (needs clang, libbpf-dev, bpftool)
make test-offline             # doctor unit tests; no kernel/root needed
sudo test/pathology/run.sh    # full injection suite (root + BTF kernel)
sudo test/attach/run.sh       # attach-to-running-pid regression
```

A change is expected to keep all three green. New doctor rules need an
offline unit test **including a false-positive guard** (see
`test/doctor_offline.c`); new detectors need a pathogen scenario with
machine-readable `GROUND-TRUTH` lines and a `run.sh` row.

Ground rules the codebase tries to hold:

- **Degrade, never abort.** A missing tracepoint/symbol disables one
  feature and is reported in the tier summary. Only a missing submission
  tracepoint is fatal.
- **Honest bounds.** If something is not observable (allocator-freelist
  reuse, inlined liburing reap paths), the docs and the report say so;
  we do not fabricate numbers.
- **Conservative doctor.** A doctor that cries wolf gets ignored — rules
  should fire on real pathologies with evidence, and the offline tests
  enforce the negative cases.
- Kernel-side reads go through CO-RE shims (`bpf/io_uring_shims.bpf.h`),
  not positional tracepoint args; BPF programs must pass the verifier on
  the kernels in `test/kernels.txt`.

Code style is kernel-ish C (tabs, 80-ish columns, comments explain *why*).
Userspace is MIT; BPF programs are GPL-2.0-only OR BSD-3-Clause — new files
need an SPDX header.

## Submitting changes

Fork, branch, and open a pull request against `main`. CI builds with gcc
and clang and runs the offline tests; please run the root test suites
locally since CI runners can't exercise every kernel path.
