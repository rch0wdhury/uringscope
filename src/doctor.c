/* SPDX-License-Identifier: MIT */
/*
 * doctor.c - turn counters into verdicts.
 *
 * Each rule names a known io_uring pathology, shows the evidence, and
 * says what to do about it. This is the part of the tool that should
 * grow over time; keep rules conservative (low false-positive) -- a
 * doctor that cries wolf gets ignored.
 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "doctor.h"
#include "opnames.h"

/* Findings are printed as they fire AND kept here so --json (and --diff's
 * commentary) can emit them as structured {tag, severity, message} records. */
__u64 us_hist_percentile(const __u64 *hist, int n, double p)
{
	__u64 total = 0, acc = 0, need;
	for (int i = 0; i < n; i++)
		total += hist[i];
	if (!total)
		return 0;
	/* round up: with small totals a truncated p*total of 0 would let
	 * the first (empty) bucket satisfy the percentile */
	need = (__u64)(p * total);
	if (need < 1)
		need = 1;
	for (int i = 0; i < n; i++) {
		acc += hist[i];
		if (acc >= need)
			return 1ULL << (i + 1); /* bucket upper bound */
	}
	return 1ULL << n;
}

static struct doc_finding finding_buf[DOC_MAX_FINDINGS];
static int findings;
static int quiet; /* --json to stdout: collect findings, print nothing */

void doctor_set_quiet(int q) { quiet = q; }

int doctor_nfindings(void) { return findings; }

const struct doc_finding *doctor_finding(int i)
{
	return (i >= 0 && i < findings && i < DOC_MAX_FINDINGS)
		? &finding_buf[i] : NULL;
}

__attribute__((format(printf, 3, 4)))
static void finding(const char *tag, const char *sev, const char *fmt, ...)
{
	va_list ap;

	if (!findings && !quiet)
		printf("\n---------------------------- doctor ----------------------------\n");
	if (findings < DOC_MAX_FINDINGS) {
		struct doc_finding *f = &finding_buf[findings];
		f->tag = tag;
		f->sev = sev;
		f->suggestion = NULL;  /* buffer is reused across doctor_run */
		f->nkv = 0;            /* calls: clear the previous tenant   */
		va_start(ap, fmt);
		vsnprintf(f->msg, sizeof(f->msg), fmt, ap);
		va_end(ap);
	}
	findings++;
	if (quiet)
		return;
	printf("  [%s] ", tag);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

/* Machine-readable evidence and the suggested action attach to the finding
 * just recorded (no-ops when the finding buffer overflowed). The terminal
 * message is unchanged -- these feed --json and --fail-on only. */
static struct doc_finding *last_finding(void)
{
	return (findings > 0 && findings <= DOC_MAX_FINDINGS)
		? &finding_buf[findings - 1] : NULL;
}

static struct doc_kv *ev_slot(const char *key)
{
	struct doc_finding *f = last_finding();

	if (!f || f->nkv >= DOC_MAX_EVIDENCE)
		return NULL;
	f->kv[f->nkv].key = key;
	return &f->kv[f->nkv++];
}

static void ev_u(const char *key, __u64 v)
{
	struct doc_kv *kv = ev_slot(key);
	if (kv) { kv->type = DOC_EV_U64; kv->u = v; }
}

static void ev_d(const char *key, double v)
{
	struct doc_kv *kv = ev_slot(key);
	if (kv) { kv->type = DOC_EV_DBL; kv->d = v; }
}

static void ev_s(const char *key, const char *v)
{
	struct doc_kv *kv = ev_slot(key);
	if (kv) { kv->type = DOC_EV_STR; kv->s = v; }
}

static void suggest(const char *s)
{
	struct doc_finding *f = last_finding();
	if (f)
		f->suggestion = s;
}

int doctor_worst_severity(void)
{
	int worst = DOC_SEV_NONE;

	for (int i = 0; i < findings && i < DOC_MAX_FINDINGS; i++) {
		const struct doc_finding *f = &finding_buf[i];
		int s;

		if (!strcmp(f->tag, "TOOL"))
			continue;
		s = !strcmp(f->sev, "CRIT") ? DOC_SEV_CRIT :
		    !strcmp(f->sev, "WARN") ? DOC_SEV_WARN : DOC_SEV_INFO;
		if (s > worst)
			worst = s;
	}
	return worst;
}

/* Why does this opcode punt? Opcode-specific hints. */
static const char *punt_hint(int op)
{
	switch (op) {
	case 22: case 1: /* READ, READV */
		return "buffered reads punt on page-cache misses; consider "
		       "O_DIRECT + registered buffers, or expect this on "
		       "cold caches";
	case 23: case 2: /* WRITE, WRITEV */
		return "writes punt when they can't complete nowait "
		       "(e.g. fs without FMODE_NOWAIT, file extension)";
	case 18: case 28: case 17: case 3: case 36: case 35:
		/* OPENAT, OPENAT2, FALLOCATE, FSYNC, UNLINKAT, RENAMEAT */
		return "this opcode class always executes on io-wq; each "
		       "one occupies a worker thread for its full duration";
	case 26: case 27: case 9: case 10: /* SEND, RECV, SENDMSG, RECVMSG */
		return "socket ops normally use the poll-retry path, not "
		       "io-wq; punting here is unusual -- check for "
		       "MSG_WAITALL or exotic socket types";
	default:
		return "see io_uring's NOWAIT issue rules for this opcode";
	}
}

void doctor_run(const __u64 *c, const struct opstat *ops,
		const struct ring_info *rings, int nrings,
		const struct leak_report *lr,
		const struct hazard_report *hr,
		const struct e2e_report *er,
		__u64 wall_ns, int ncpu)
{
	int sqpoll = 0, defer_tw = 0;
	__u32 min_cq = 0;

	findings = 0;

	for (int i = 0; i < nrings; i++) {
		if (rings[i].flags & US_SETUP_SQPOLL)
			sqpoll = 1;
		if (rings[i].flags & US_SETUP_DEFER_TASKRUN)
			defer_tw = 1;
		if (!min_cq || rings[i].cq_entries < min_cq)
			min_cq = rings[i].cq_entries;
	}

	/* 1. CQ overflow: the silent killer. */
	if (c[C_OVERFLOW]) {
		finding("OVERFLOW", "CRIT", "CQ overflowed %llu times. Overflowed CQEs "
			"take a slow, allocating, lock-taking path and stall "
			"the ring. Your CQ (%u entries) is too small for your "
			"inflight depth, or completions aren't reaped fast "
			"enough.",
			(unsigned long long)c[C_OVERFLOW], min_cq);
		ev_u("overflows", c[C_OVERFLOW]);
		ev_u("cq_entries", min_cq);
		suggest("Grow the CQ (IORING_SETUP_CQSIZE) or reap "
			"completions more often.");
	}

	/* 2. io-wq punts: the tail-latency killer. */
	if (c[C_SUBMIT] >= 100) {
		double pr = 100.0 * c[C_PUNT] / c[C_SUBMIT];
		if (pr >= 5.0) {
			finding("PUNT", "WARN", "%.1f%% of requests fell back to the "
				"io-wq async worker pool (%llu of %llu). "
				"These take a thread-pool detour measured in "
				"tens of microseconds+, not the fast path.",
				pr, (unsigned long long)c[C_PUNT],
				(unsigned long long)c[C_SUBMIT]);
			ev_d("punt_pct", pr);
			ev_u("punted", c[C_PUNT]);
			ev_u("submitted", c[C_SUBMIT]);
			suggest("Identify the punting opcode (per-op findings "
				"follow); prefer fast-path-capable I/O "
				"(O_DIRECT + registered buffers for reads) and "
				"cap the pool with "
				"io_uring_register_iowq_max_workers().");
			for (int i = 0; i < MAX_OPS; i++) {
				if (ops[i].submitted >= 50 &&
				    ops[i].punted * 100 >= ops[i].submitted * 20) {
					finding("PUNT", "WARN", "  -> %s punts %.0f%% "
						"of the time: %s.",
						op_name(i),
						100.0 * ops[i].punted /
							ops[i].submitted,
						punt_hint(i));
					ev_s("op", op_name(i));
					ev_d("punt_pct", 100.0 * ops[i].punted /
							 ops[i].submitted);
					ev_u("punted", ops[i].punted);
					ev_u("submitted", ops[i].submitted);
					suggest(punt_hint(i));
				}
			}
		}
	}

	/* 3. Worker fan-out. A storm is many *distinct* workers -- each blocking
	 * op pins one. Scale the trip point with cores, but CAP it: on a
	 * many-core box a bare 2*ncpu exceeds a real 64-worker storm and would
	 * silently miss it. Capping at 32 keeps the bar well above routine io-wq
	 * use (a handful of workers) yet below any genuine fan-out, on machines
	 * of any size. */
	{
		int worker_thresh = 2 * ncpu;

		if (worker_thresh > 32)
			worker_thresh = 32;
		if ((int)c[C_WORKERS_SEEN] > worker_thresh) {
			finding("WORKERS", "WARN", "io-wq spawned %llu distinct worker "
				"threads (%d CPUs). Unbounded workers thrash; "
				"cap them with "
				"io_uring_register_iowq_max_workers().",
				(unsigned long long)c[C_WORKERS_SEEN], ncpu);
			ev_u("workers", c[C_WORKERS_SEEN]);
			ev_u("cpus", ncpu);
			suggest("Cap the pool with "
				"io_uring_register_iowq_max_workers().");
		}
	}

	/* 4. Batching efficiency. */
	if (c[C_ENTER] >= 1000) {
		double per = (double)c[C_RET_SUBMITTED] / c[C_ENTER];
		if (per < 1.5 && c[C_RET_SUBMITTED] > 0) {
			finding("BATCH", "INFO", "averaging only %.2f SQEs per "
				"io_uring_enter() across %llu calls -- "
				"you're paying syscall-per-op like epoll. "
				"Batch submissions, or consider "
				"DEFER_TASKRUN/SQPOLL.",
				per, (unsigned long long)c[C_ENTER]);
			ev_d("sqes_per_enter", per);
			ev_u("enter_calls", c[C_ENTER]);
			suggest("Queue several SQEs before each "
				"io_uring_submit()/io_uring_enter(), or "
				"consider DEFER_TASKRUN or SQPOLL.");
		}
	}

	/* 5. SQPOLL behavior. */
	if (sqpoll && c[C_SQPOLL_SWITCHES] && wall_ns) {
		double frac = 100.0 * c[C_SQPOLL_OFFCPU_NS] / wall_ns;
		if (frac > 25.0) {
			finding("SQPOLL", "WARN", "SQPOLL thread was off-CPU %.0f%% of "
				"the window. Idle-sleeping sqpoll means each "
				"submission burst pays a wakeup "
				"(io_uring_enter + IORING_SQ_NEED_WAKEUP). "
				"Raise sq_thread_idle or reconsider SQPOLL "
				"for this duty cycle.", frac);
			ev_d("offcpu_pct", frac);
			suggest("Raise sq_thread_idle or reconsider SQPOLL "
				"for this duty cycle.");
		}
	}
	if (sqpoll && !c[C_SQPOLL_SWITCHES] && wall_ns > 2000000000ULL) {
		finding("SQPOLL", "INFO", "SQPOLL thread never context-switched: it is "
			"burning a full core busy-polling. Intended for "
			"latency, but verify the core is budgeted for it.");
		suggest("Verify a core is budgeted for the busy-polling "
			"sqpoll thread.");
	}

	/* 6. DEFER_TASKRUN misuse. */
	if (defer_tw && !c[C_LOCAL_TW_RUN] && c[C_COMPLETE] > 100) {
		finding("DEFER-TW", "WARN", "ring has DEFER_TASKRUN but local task work "
			"never ran -- completions may be sitting unprocessed. "
			"With DEFER_TASKRUN you must reap via "
			"io_uring_get_events()/enter(GETEVENTS) on the "
			"submitting thread.");
		ev_u("completions", c[C_COMPLETE]);
		suggest("Reap via io_uring_get_events()/io_uring_enter"
			"(GETEVENTS) on the submitting thread.");
	}

	/* 7. Short writes. */
	if (c[C_SHORT_WRITE]) {
		finding("SHORT-WRITE", "INFO", "%llu short writes detected (kernel had to "
			"truncate-and-retry); check fs/quota/signals.",
			(unsigned long long)c[C_SHORT_WRITE]);
		ev_u("short_writes", c[C_SHORT_WRITE]);
		suggest("Check filesystem free space, quotas, and signal "
			"delivery to the writing threads.");
	}

	/* 8. Error rate. */
	if (c[C_COMPLETE] >= 100 && c[C_ERRORS] * 100 > c[C_COMPLETE]) {
		finding("ERRORS", "WARN", "%.1f%% of completions returned res < 0 "
			"(excluding EAGAIN). Errors complete fast and make "
			"latency look deceptively good.",
			100.0 * c[C_ERRORS] / c[C_COMPLETE]);
		ev_d("error_pct", 100.0 * c[C_ERRORS] / c[C_COMPLETE]);
		ev_u("errors", c[C_ERRORS]);
		ev_u("completions", c[C_COMPLETE]);
		suggest("Break errors down per opcode (-e error) before "
			"trusting the latency numbers.");
	}

	/* 9. Dropped in-flight operations: submitted, never completed.
	 * The app has likely lost track of these (forgotten user_data,
	 * miscounted completions => a wait that never returns). The kernel
	 * still holds their resources -- including any buffers they
	 * reference, which is how buffer-lifetime bugs start. */
	if (lr && lr->n) {
		finding("LEAK", "WARN", "%llu request%s submitted but never completed "
			"after %llus (oldest: %llus)%s.",
			(unsigned long long)lr->n, lr->n == 1 ? " was" : "s were",
			(unsigned long long)(lr->thresh_ns / 1000000000ULL),
			(unsigned long long)(lr->oldest_ns / 1000000000ULL),
			lr->n_polled ?
			" -- most are parked on poll-retry: the fd never became ready"
			: "");
		ev_u("leaked", lr->n);
		ev_u("polled", lr->n_polled);
		ev_u("pending", lr->pending);
		ev_u("oldest_s", lr->oldest_ns / 1000000000ULL);
		ev_u("threshold_s", lr->thresh_ns / 1000000000ULL);
		suggest("Match every submission with a completion; if these "
			"are intentional long-lived requests, ignore.");
		for (int i = 0; i < MAX_OPS; i++)
			if (lr->per_op[i]) {
				finding("LEAK", "WARN", "  -> %llu x %s still in "
					"flight", (unsigned long long)
					lr->per_op[i], op_name(i));
				ev_s("op", op_name(i));
				ev_u("count", lr->per_op[i]);
			}
		for (int i = 0; i < lr->nsample; i++) {
			finding("LEAK", "WARN", "  -> e.g. %s user_data=0x%llx -- "
				"grep your code for this token",
				op_name(lr->sample_op[i]),
				(unsigned long long)lr->sample_ud[i]);
			ev_s("op", op_name(lr->sample_op[i]));
			ev_u("user_data", lr->sample_ud[i]);
		}
		finding("LEAK", "WARN", "  if these are intentional long-lived "
			"requests, ignore; otherwise you have a completion "
			"leak (and any buffers they reference must stay "
			"alive until the kernel lets go).");
	}

	/* 9b. Overlapping in-flight buffer ranges (--check mode). Two requests
	 * targeted the same memory while both were in flight: the later
	 * completion silently overwrites the earlier one's result and the
	 * kernel returns no error. High-confidence -- it only fires on a real
	 * range overlap of two concurrently live read/write requests. */
	if (hr && hr->n) {
		finding("HAZARD", "CRIT", "%llu overlapping in-flight buffer range%s "
			"detected: two requests targeted the same memory while "
			"both were in flight. No error is returned -- the "
			"second completion silently clobbers the first "
			"request's data.",
			(unsigned long long)hr->n,
			hr->n == 1 ? " was" : "s were");
		ev_u("overlaps", hr->n);
		suggest("Wait for the first request's completion before "
			"submitting another operation on overlapping memory.");
		for (int i = 0; i < hr->nsample; i++) {
			const struct hazard_sample *h = &hr->samples[i];
			if (h->kind == TGT_BUFIDX)
				finding("HAZARD", "CRIT", "  -> %s(user_data=0x%llx) and "
					"%s(user_data=0x%llx) overlap in "
					"registered buffer #%u at [0x%llx,+%u) "
					"-- grep your code for these tokens",
					op_name(h->opcode_a),
					(unsigned long long)h->user_data_a,
					op_name(h->opcode_b),
					(unsigned long long)h->user_data_b,
					h->bufidx,
					(unsigned long long)h->base, h->len);
			else
				finding("HAZARD", "CRIT", "  -> %s(user_data=0x%llx) and "
					"%s(user_data=0x%llx) overlap at "
					"[0x%llx,+%u) -- grep your code for "
					"these tokens",
					op_name(h->opcode_a),
					(unsigned long long)h->user_data_a,
					op_name(h->opcode_b),
					(unsigned long long)h->user_data_b,
					(unsigned long long)h->base, h->len);
			ev_s("op_a", op_name(h->opcode_a));
			ev_u("user_data_a", h->user_data_a);
			ev_s("op_b", op_name(h->opcode_b));
			ev_u("user_data_b", h->user_data_b);
			ev_u("base", h->base);
			ev_u("len", h->len);
			if (h->kind == TGT_BUFIDX)
				ev_u("bufidx", h->bufidx);
		}
		finding("HAZARD", "CRIT", "  if intentional (you reap one before the "
			"other writes), ignore; otherwise this is a "
			"data-corruption race at the submission boundary.");
	}

	/* 9c. Registered-buffer lifetime (--check, hazard 3): the app called
	 * (un|re)register_buffers while *_FIXED requests referencing those
	 * indexes were still in flight. The kernel refcounts the buffer node
	 * so memory stays valid, but the *index* changes meaning for every
	 * request submitted next -- and on quiesce kernels the unregister
	 * stalls the ring until the stragglers drain. */
	if (hr && hr->n_bufreg) {
		for (int i = 0; i < hr->nbufreg; i++) {
			finding("HAZARD-BUFREG", "CRIT", "unregistered buffer "
				"index %u while %u in-flight op%s reference%s "
				"it -- a new registration at that index will "
				"write into the wrong memory.",
				hr->bufreg[i].bufidx, hr->bufreg[i].refs,
				hr->bufreg[i].refs == 1 ? "" : "s",
				hr->bufreg[i].refs == 1 ? "s" : "");
			ev_u("bufidx", hr->bufreg[i].bufidx);
			ev_u("live_refs", hr->bufreg[i].refs);
			suggest("Wait for (or cancel) those in-flight "
				"fixed-buffer completions before "
				"unregistering or re-registering.");
		}
		if (hr->n_bufreg > (__u64)hr->nbufreg)
			finding("HAZARD-BUFREG", "CRIT", "  (+%llu more live "
				"indexes beyond the first %d sampled)",
				(unsigned long long)(hr->n_bufreg - hr->nbufreg),
				hr->nbufreg);
		finding("HAZARD-BUFREG", "CRIT", "  wait for those "
			"completions (or cancel them) before unregistering "
			"or re-registering.");
	}

	/* 9d. munmap under in-flight I/O (--check, hazard 1, unmap variant).
	 * Honest bound: only the munmap path is kernel-visible; free() to
	 * the allocator freelist or stack-frame reuse fires no syscall and
	 * cannot be caught here (docs/buffer-hazards.md). */
	if (hr && hr->n_unmap) {
		for (int i = 0; i < hr->nunmap; i++) {
			finding("HAZARD-UAF", "CRIT", "munmap of [0x%llx,+%u) "
				"while %s into that range is in flight "
				"(user_data=0x%llx) -- kernel will fault or "
				"write into freed memory.",
				(unsigned long long)hr->unmap[i].base,
				hr->unmap[i].len,
				op_name(hr->unmap[i].opcode),
				(unsigned long long)hr->unmap[i].user_data);
			ev_u("base", hr->unmap[i].base);
			ev_u("len", hr->unmap[i].len);
			ev_s("op", op_name(hr->unmap[i].opcode));
			ev_u("user_data", hr->unmap[i].user_data);
			suggest("Keep the mapping alive until the matching "
				"completion is reaped.");
		}
		if (hr->n_unmap > (__u64)hr->nunmap)
			finding("HAZARD-UAF", "CRIT", "  (+%llu more overlaps "
				"beyond the first %d sampled)",
				(unsigned long long)(hr->n_unmap - hr->nunmap),
				hr->nunmap);
		finding("HAZARD-UAF", "CRIT", "  note: only the munmap "
			"variant is detectable from the kernel; free() to "
			"the allocator and stack reuse fire no syscall.");
	}

	/* 9e. Reap lag (end-to-end boundary, liburing uprobes): CQEs were
	 * ready in the ring well before the app came back for them.
	 * Conservative: p99 over 500us is far beyond scheduling noise. */
	if (er && er->available && er->reap_n) {
		__u64 avg = er->reap_sum_ns / er->reap_n;
		__u64 p99 = us_hist_percentile(er->reap_hist, NLAT_SLOTS,
					       0.99);
		if (p99 > 500000) {
			finding("REAP-LAG", "WARN", "CQEs sat ready avg "
				"%lluus / p99 %lluus before your app reaped "
				"them (n=%llu) -- event loop may be polling "
				"too slowly.",
				(unsigned long long)(avg / 1000),
				(unsigned long long)(p99 / 1000),
				(unsigned long long)er->reap_n);
			ev_u("avg_ns", avg);
			ev_u("p99_ns", p99);
			ev_u("samples", er->reap_n);
			suggest("Poll the completion queue more often, or "
				"block in a waiting io_uring_enter() instead "
				"of a slow event loop.");
		}
	}

	/* 10. Tool health: be honest when our own data is degraded. */
	if (c[C_INFLIGHT_DROP]) {
		finding("TOOL", "INFO", "%llu submits weren't tracked (inflight map "
			"full at 256k). Latency stats undercount; raise the "
			"map size for this workload.",
			(unsigned long long)c[C_INFLIGHT_DROP]);
		ev_u("inflight_map_drops", c[C_INFLIGHT_DROP]);
	}
	if (c[C_UNTRACKED] > c[C_COMPLETE] / 10 && c[C_COMPLETE] > 100) {
		finding("TOOL", "INFO", "%llu completions had no matching submit "
			"(pre-attach requests or untracked multishot); "
			"per-op latency covers tracked requests only.",
			(unsigned long long)c[C_UNTRACKED]);
		ev_u("untracked_completions", c[C_UNTRACKED]);
	}
	if (c[C_RB_DROP]) {
		finding("TOOL", "INFO", "%llu trace events were dropped (--trace "
			"ring buffer full); the timeline has gaps. Aggregate "
			"stats and the doctor are unaffected.",
			(unsigned long long)c[C_RB_DROP]);
		ev_u("trace_rb_drops", c[C_RB_DROP]);
	}

	if (!findings && !quiet)
		printf("\ndoctor: no pathologies detected -- ring config and "
		       "fast-path behavior look healthy.\n");
}
