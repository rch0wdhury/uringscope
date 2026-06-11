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
#include "doctor.h"
#include "opnames.h"

static int findings;

__attribute__((format(printf, 2, 3)))
static void finding(const char *sev, const char *fmt, ...)
{
	va_list ap;

	if (!findings++)
		printf("\n---------------------------- doctor ----------------------------\n");
	printf("  [%s] ", sev);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
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
	if (c[C_OVERFLOW])
		finding("CRIT", "CQ overflowed %llu times. Overflowed CQEs "
			"take a slow, allocating, lock-taking path and stall "
			"the ring. Your CQ (%u entries) is too small for your "
			"inflight depth, or completions aren't reaped fast "
			"enough.",
			(unsigned long long)c[C_OVERFLOW], min_cq);

	/* 2. io-wq punts: the tail-latency killer. */
	if (c[C_SUBMIT] >= 100) {
		double pr = 100.0 * c[C_PUNT] / c[C_SUBMIT];
		if (pr >= 5.0) {
			finding("WARN", "%.1f%% of requests fell back to the "
				"io-wq async worker pool (%llu of %llu). "
				"These take a thread-pool detour measured in "
				"tens of microseconds+, not the fast path.",
				pr, (unsigned long long)c[C_PUNT],
				(unsigned long long)c[C_SUBMIT]);
			for (int i = 0; i < MAX_OPS; i++) {
				if (ops[i].submitted >= 50 &&
				    ops[i].punted * 100 >= ops[i].submitted * 20)
					finding("WARN", "  -> %s punts %.0f%% "
						"of the time: %s.",
						op_name(i),
						100.0 * ops[i].punted /
							ops[i].submitted,
						punt_hint(i));
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
		if ((int)c[C_WORKERS_SEEN] > worker_thresh)
			finding("WARN", "io-wq spawned %llu distinct worker "
				"threads (%d CPUs). Unbounded workers thrash; "
				"cap them with "
				"io_uring_register_iowq_max_workers().",
				(unsigned long long)c[C_WORKERS_SEEN], ncpu);
	}

	/* 4. Batching efficiency. */
	if (c[C_ENTER] >= 1000) {
		double per = (double)c[C_RET_SUBMITTED] / c[C_ENTER];
		if (per < 1.5 && c[C_RET_SUBMITTED] > 0)
			finding("INFO", "averaging only %.2f SQEs per "
				"io_uring_enter() across %llu calls -- "
				"you're paying syscall-per-op like epoll. "
				"Batch submissions, or consider "
				"DEFER_TASKRUN/SQPOLL.",
				per, (unsigned long long)c[C_ENTER]);
	}

	/* 5. SQPOLL behavior. */
	if (sqpoll && c[C_SQPOLL_SWITCHES] && wall_ns) {
		double frac = 100.0 * c[C_SQPOLL_OFFCPU_NS] / wall_ns;
		if (frac > 25.0)
			finding("WARN", "SQPOLL thread was off-CPU %.0f%% of "
				"the window. Idle-sleeping sqpoll means each "
				"submission burst pays a wakeup "
				"(io_uring_enter + IORING_SQ_NEED_WAKEUP). "
				"Raise sq_thread_idle or reconsider SQPOLL "
				"for this duty cycle.", frac);
	}
	if (sqpoll && !c[C_SQPOLL_SWITCHES] && wall_ns > 2000000000ULL)
		finding("INFO", "SQPOLL thread never context-switched: it is "
			"burning a full core busy-polling. Intended for "
			"latency, but verify the core is budgeted for it.");

	/* 6. DEFER_TASKRUN misuse. */
	if (defer_tw && !c[C_LOCAL_TW_RUN] && c[C_COMPLETE] > 100)
		finding("WARN", "ring has DEFER_TASKRUN but local task work "
			"never ran -- completions may be sitting unprocessed. "
			"With DEFER_TASKRUN you must reap via "
			"io_uring_get_events()/enter(GETEVENTS) on the "
			"submitting thread.");

	/* 7. Short writes. */
	if (c[C_SHORT_WRITE])
		finding("INFO", "%llu short writes detected (kernel had to "
			"truncate-and-retry); check fs/quota/signals.",
			(unsigned long long)c[C_SHORT_WRITE]);

	/* 8. Error rate. */
	if (c[C_COMPLETE] >= 100 && c[C_ERRORS] * 100 > c[C_COMPLETE])
		finding("WARN", "%.1f%% of completions returned res < 0 "
			"(excluding EAGAIN). Errors complete fast and make "
			"latency look deceptively good.",
			100.0 * c[C_ERRORS] / c[C_COMPLETE]);

	/* 9. Dropped in-flight operations: submitted, never completed.
	 * The app has likely lost track of these (forgotten user_data,
	 * miscounted completions => a wait that never returns). The kernel
	 * still holds their resources -- including any buffers they
	 * reference, which is how buffer-lifetime bugs start. */
	if (lr && lr->n) {
		finding("LEAK", "%llu request%s submitted but never completed "
			"after %llus (oldest: %llus)%s.",
			(unsigned long long)lr->n, lr->n == 1 ? " was" : "s were",
			(unsigned long long)(lr->thresh_ns / 1000000000ULL),
			(unsigned long long)(lr->oldest_ns / 1000000000ULL),
			lr->n_polled ?
			" -- most are parked on poll-retry: the fd never became ready"
			: "");
		for (int i = 0; i < MAX_OPS; i++)
			if (lr->per_op[i])
				finding("LEAK", "  -> %llu x %s still in "
					"flight", (unsigned long long)
					lr->per_op[i], op_name(i));
		for (int i = 0; i < lr->nsample; i++)
			finding("LEAK", "  -> e.g. %s user_data=0x%llx -- "
				"grep your code for this token",
				op_name(lr->sample_op[i]),
				(unsigned long long)lr->sample_ud[i]);
		finding("LEAK", "  if these are intentional long-lived "
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
		finding("HAZARD", "%llu overlapping in-flight buffer range%s "
			"detected: two requests targeted the same memory while "
			"both were in flight. No error is returned -- the "
			"second completion silently clobbers the first "
			"request's data.",
			(unsigned long long)hr->n,
			hr->n == 1 ? " was" : "s were");
		for (int i = 0; i < hr->nsample; i++) {
			const struct hazard_sample *h = &hr->samples[i];
			if (h->kind == TGT_BUFIDX)
				finding("HAZARD", "  -> %s(user_data=0x%llx) and "
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
				finding("HAZARD", "  -> %s(user_data=0x%llx) and "
					"%s(user_data=0x%llx) overlap at "
					"[0x%llx,+%u) -- grep your code for "
					"these tokens",
					op_name(h->opcode_a),
					(unsigned long long)h->user_data_a,
					op_name(h->opcode_b),
					(unsigned long long)h->user_data_b,
					(unsigned long long)h->base, h->len);
		}
		finding("HAZARD", "  if intentional (you reap one before the "
			"other writes), ignore; otherwise this is a "
			"data-corruption race at the submission boundary.");
	}

	/* 10. Tool health: be honest when our own data is degraded. */
	if (c[C_INFLIGHT_DROP])
		finding("TOOL", "%llu submits weren't tracked (inflight map "
			"full at 256k). Latency stats undercount; raise the "
			"map size for this workload.",
			(unsigned long long)c[C_INFLIGHT_DROP]);
	if (c[C_UNTRACKED] > c[C_COMPLETE] / 10 && c[C_COMPLETE] > 100)
		finding("TOOL", "%llu completions had no matching submit "
			"(pre-attach requests or untracked multishot); "
			"per-op latency covers tracked requests only.",
			(unsigned long long)c[C_UNTRACKED]);

	if (!findings)
		printf("\ndoctor: no pathologies detected -- ring config and "
		       "fast-path behavior look healthy.\n");
}
