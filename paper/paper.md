---
title: 'uringscope: an eBPF flight recorder and doctor for Linux io_uring applications'
tags:
  - Linux
  - io_uring
  - eBPF
  - performance analysis
  - observability
  - systems software
  - C
authors:
  - name: Rajarshi Chowdhury
    orcid: 0009-0007-7032-2450
    affiliation: 1
affiliations:
  - name: Independent Researcher
    index: 1
date: 12 June 2026
bibliography: paper.bib
---

# Summary

`io_uring` is the Linux kernel's asynchronous I/O interface [@axboe2019]:
applications place requests in a submission ring shared with the kernel and
collect results from a completion ring, often with no system call per
operation. That design is why it is fast — and it also moves the request flow
out of system calls and into shared memory, so syscall-level tracing sees only
ring setup, not the requests inside. The kernel's ~18 static `io_uring`
tracepoints expose that flow, but their prototypes are not ABI and have been
renamed and re-typed repeatedly across kernel releases, which is why prior
tooling in this space pinned itself to narrow kernel ranges.

`uringscope` is a single-binary flight recorder and "doctor" for io_uring.
It attaches CO-RE (Compile Once — Run Everywhere) eBPF programs
[@nakryiko2020] to the kernel's io_uring tracepoints, reconstructs the
per-request lifecycle (submit → punt/poll-retry → complete → reap), and
aggregates everything inside the kernel, so per-event data never crosses to
userspace in the default mode and the tool stays usable at millions of
operations per second. On top of the recorder sits a rule engine that reports
*named* pathologies with evidence and a suggested fix: io-wq punt storms (the
classic hidden tail-latency source), completion-queue overflows,
syscall-per-operation batching failures, SQPOLL stalls, io-wq worker fan-out,
completion leaks, and reaping lag. Reports are available as live terminal
deltas (`-i`, like `iostat`), compact summaries (`-c`), JSON with
baseline/diff comparison, an embedded OpenMetrics endpoint for Prometheus
scraping, and per-request Perfetto timelines [@perfetto].

# Statement of need

io_uring adoption is growing across databases, storage engines, language
runtimes, and proxies, and recent systematic studies of modern storage APIs
show both its performance potential and the subtlety of its behavior
[@didona2022]. Yet the asynchronous boundary it introduces is genuinely hard
to observe: ownership of a buffer transfers to the kernel at submit and
returns only at completion; requests silently fall off the fast path into
worker threads; completions sit unreaped without any error. Researchers
benchmarking storage stacks, engineers chasing p99 latencies, and developers
debugging buffer-lifetime races all need an io_uring-literate observer that
works on whatever kernel they have, rather than a generic event firehose they
must interpret by hand. uringscope targets that audience with an opinionated,
validated instrument that reconstructs application-meaningful request flows
instead of emitting raw tracepoint events.

# State of the field

General-purpose tracers can read the same tracepoints uringscope does.
`perf record -e 'io_uring:*'` and one-line bpftrace [@bpftrace] scripts count
events well, but they emit per-event streams with no request-level
correlation, defer all semantics to offline processing, require the user to
know which of the unstable tracepoints to hook and how to join them, and break
when a prototype changes between kernels. Purpose-built io_uring tools have
appeared but froze against a single kernel window — the most directly
comparable prior tool supports only kernels 6.1–6.7. Other work combines
io_uring with eBPF for a different goal, enforcing security policy, rather than
observability or correctness checking. uringscope differs in being
io_uring-specific and semantics-aware, packaged as a single static binary, and
engineered to survive the tracepoint instability that limited earlier tools.

# Software design

uringscope offers two modes that trade fidelity for cost. The default
*aggregate* mode folds per-opcode log2 latency histograms and pathology
counters into BPF maps in the kernel; userspace reads the maps once at exit
(or periodically for metrics export), so nothing per-event crosses to
userspace. The *trace* mode streams one per-request record over a ring buffer
for Perfetto timeline reconstruction and reports any ring-buffer drops as a
first-class counter rather than losing them silently. Requests are correlated
by the `io_kiocb` pointer, which is stable from submit to completion, with
multishot, linked, and SQPOLL-submitted requests handled explicitly.

Portability is treated as an explicit contract rather than a hope. At startup
uringscope interrogates the running kernel's BTF, selects among compiled
program variants per tracepoint prototype, and prints a support-tier table; an
unrecognized prototype degrades one feature — with a fail-soft fallback where
possible — instead of failing the load. Kernel-side reads go through minimal
CO-RE "shadow" structs and trust the `io_kiocb` pointer rather than positional
tracepoint arguments, because the struct fields have been far more stable than
the tracepoint prototypes.

A correctness mode (`--check`) reuses the lifecycle tracking as an
AddressSanitizer-style [@serebryany2012] checker for the io_uring submission
boundary: it detects overlapping in-flight buffer ranges (silent data
corruption that returns no error), registered-buffer lifetime violations, and
the `munmap` variant of buffer use-after-free, each reported with the offending
`user_data` tokens so developers can grep their code. Because the BPF verifier
forbids unbounded loops, the overlap test compares against a bounded per-ring
window of recent in-flight ranges — a documented approximation rather than an
exhaustive guarantee. End-to-end boundary timing via best-effort liburing
uprobes closes the two lifecycle segments tracepoints cannot see (submit-side
batching and CQE-ready→reap lag); the documentation is explicit that uprobes
lack CO-RE's portability and that fully inlined reap paths are unobservable,
and the tool reports "no samples" rather than fabricating numbers.

# Research impact statement

uringscope is newly released open-source software intended as practical
infrastructure for systems and storage research and for production performance
engineering on io_uring. Its value to the community is twofold. First, it
lowers the cost of attributing io_uring tail latency to concrete kernel-side
causes — async-worker punts, batching failures, SQPOLL stalls — which is
otherwise a manual, kernel-source-reading exercise, and so supports
reproducible measurement of storage and networking stacks. Second, its
detection and portability claims are validated rather than asserted: the
repository ships a pathology harness (`test/pathology`) that injects eleven
ground-truth anomalies — punt storms, batching failures, CQ overflows, error
floods, completion leaks, SQPOLL stalls, worker storms, use-after-unmap,
registered-buffer races and lifetime violations, and reaping lag — and asserts
that the doctor reports each, alongside negative tests that guard against false
positives. A virtme-ng harness (`test/vmtest`) boots a kernel matrix
(`test/kernels.txt`) under KVM and checks that the BTF probe selects the
correct tracepoint variant for each kernel (for example, the collapsed
`io_uring_complete` prototype introduced in 6.17) and that every detector still
fires. The documentation states honestly which hazards are *not* detectable
from the kernel side (for example, allocator-freelist reuse fires no syscall),
a boundary we believe is itself useful to practitioners.

# AI usage disclosure

Generative AI tools were used as a development aid. Their
most substantive contributions were in identifying bugs and in writing the
pathology test harness (`test/pathology`); they were also used for
documentation and for editing assistance on this paper. The author conceived
and designed the tool, made all architectural and implementation decisions,
and reviewed and validated every AI-assisted contribution. The experimental
design and its execution, and the substantive technical content of this paper,
are the author's own work.

# Acknowledgements

uringscope builds on libbpf and the kernel BPF community's CO-RE
infrastructure, and on liburing by Jens Axboe.

# References
