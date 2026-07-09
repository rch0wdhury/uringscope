/* SPDX-License-Identifier: MIT */
/*
 * uringscope - flight recorder & doctor for io_uring applications.
 *
 *   uringscope ./myapp           # run app under the scope, print report
 *   uringscope -p 1234 -d 10     # observe a running pid for 10 seconds
 *   uringscope --trace t.json -- ./myapp   # also emit a Perfetto timeline
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "uringscope.h"
#include "uringscope.skel.h"
#include "opnames.h"
#include "probe.h"
#include "perfetto.h"
#include "doctor.h"
#include "jsonout.h"
#include "metrics.h"
#include "uprobes.h"

#ifndef US_VERSION
#define US_VERSION "0.2.0"
#endif
#ifndef US_GITREV
#define US_GITREV "unknown"
#endif

static volatile sig_atomic_t exiting;
static int verbose;
/* Diagnostics level, set once at startup from URINGSCOPE_DEBUG (0..2) and
 * never read on any per-event path -- it gates startup/exit-time stderr
 * reporting only, so it has ZERO effect on the in-kernel data path or the
 * map-aggregation hot path. 1 = stage timing + a one-line load-failure
 * hint; 2 = also stream libbpf/verifier debug (implies -v). */
static int debug_level;

__attribute__((format(printf, 2, 3)))
static void dbg(int lvl, const char *fmt, ...)
{
	va_list ap;

	if (debug_level < lvl)
		return;
	fputs("uringscope[dbg]: ", stderr);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

/* Display-only options: what of the collected data we *show*. The BPF side
 * always collects everything (strace -e style: filtering the view, not the
 * instrumentation). */
static struct {
	int summary_only;            /* -c: per-op table + doctor only      */
	int op_filter;               /* -e op=...: op_ok[] is authoritative */
	int punt_only;               /* -e punt: rows with punted > 0       */
	int err_only;                /* -e error: rows with errors > 0      */
	unsigned char op_ok[MAX_OPS];
} disp;

static int opcode_by_name(const char *name)
{
	for (unsigned i = 0; i < NUM_OP_NAMES; i++)
		if (!strcasecmp(name, op_names[i]))
			return (int)i;
	return -1;
}

/* -e TOKENS: comma-separated. op=NAME starts an opcode list (further bare
 * names extend it, so 'op=READ,WRITE' works); punt / error / all are modes. */
static int parse_filter(char *spec)
{
	char *tok, *save = NULL;

	for (tok = strtok_r(spec, ",", &save); tok;
	     tok = strtok_r(NULL, ",", &save)) {
		int op;

		if (!strcmp(tok, "all")) {
			disp.op_filter = disp.punt_only = disp.err_only = 0;
			continue;
		}
		if (!strcmp(tok, "punt")) {
			disp.punt_only = 1;
			continue;
		}
		if (!strcmp(tok, "error") || !strcmp(tok, "err")) {
			disp.err_only = 1;
			continue;
		}
		if (!strncmp(tok, "op=", 3))
			tok += 3;
		op = opcode_by_name(tok);
		if (op < 0) {
			fprintf(stderr, "uringscope: -e: unknown token '%s' "
				"(see --list-ops; tokens: op=NAME, punt, "
				"error, all)\n", tok);
			return -1;
		}
		disp.op_filter = 1;
		disp.op_ok[op] = 1;
	}
	return 0;
}

static int row_visible(int op, const struct opstat *o)
{
	if (disp.op_filter && !disp.op_ok[op])
		return 0;
	if (disp.punt_only && !o->punted)
		return 0;
	if (disp.err_only && !o->errors)
		return 0;
	return 1;
}

static void list_ops(void)
{
	printf("%-4s %s\n", "code", "opcode");
	for (unsigned i = 0; i < NUM_OP_NAMES; i++)
		printf("%4u %s\n", i, op_names[i]);
}

static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print(enum libbpf_print_level lvl, const char *fmt,
			va_list args)
{
	/* DEBUG (incl. the verifier log) shows under -v or URINGSCOPE_DEBUG=2;
	 * WARN/INFO (load-failure reasons like "BPF program is too large")
	 * always pass through, so the *cause* of a failure is never hidden. */
	if (lvl == LIBBPF_DEBUG && !verbose && debug_level < 2)
		return 0;
	return vfprintf(stderr, fmt, args);
}

static __u64 now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* ---------- pretty printing ------------------------------------------- */

static const char *fmt_ns(__u64 ns, char *buf, size_t len)
{
	if (ns < 1000)
		snprintf(buf, len, "%lluns", ns);
	else if (ns < 1000000)
		snprintf(buf, len, "%.1fus", ns / 1e3);
	else if (ns < 1000000000)
		snprintf(buf, len, "%.1fms", ns / 1e6);
	else
		snprintf(buf, len, "%.2fs", ns / 1e9);
	return buf;
}

static void print_hist(const __u64 *hist, int n, const char *title)
{
	__u64 max = 0, total = 0;
	char lo[32], hi[32];
	int first = -1, last = 0;

	for (int i = 0; i < n; i++) {
		total += hist[i];
		if (hist[i] > max)
			max = hist[i];
		if (hist[i] && first < 0)
			first = i;
		if (hist[i])
			last = i;
	}
	if (!total)
		return;
	printf("\n  %s (n=%llu)\n", title, (unsigned long long)total);
	for (int i = first; i <= last; i++) {
		int w = max ? (int)(40ULL * hist[i] / max) : 0;
		fmt_ns(i ? 1ULL << i : 0, lo, sizeof(lo));
		fmt_ns(1ULL << (i + 1), hi, sizeof(hi));
		printf("  %9s - %-9s |%-40.*s| %llu\n", lo, hi, w,
		       "****************************************",
		       (unsigned long long)hist[i]);
	}
}

/* ---------- map readers ------------------------------------------------ */

static void read_counters(struct uringscope_bpf *skel, __u64 *out)
{
	for (__u32 i = 0; i < C_MAX; i++) {
		__u64 v = 0;
		bpf_map__lookup_elem(skel->maps.counters, &i, sizeof(i), &v,
				     sizeof(v), 0);
		out[i] = v;
	}
}

static void read_opstats(struct uringscope_bpf *skel, struct opstat *out)
{
	for (__u32 i = 0; i < MAX_OPS; i++) {
		memset(&out[i], 0, sizeof(out[i]));
		bpf_map__lookup_elem(skel->maps.opstats, &i, sizeof(i),
				     &out[i], sizeof(out[i]), 0);
	}
}

static int read_rings(struct uringscope_bpf *skel, struct ring_info *out)
{
	int n = 0;
	for (__u32 i = 0; i < MAX_RINGS; i++) {
		struct ring_info ri = {};
		if (bpf_map__lookup_elem(skel->maps.rings, &i, sizeof(i),
					 &ri, sizeof(ri), 0))
			continue;
		if (ri.ctx)
			out[n++] = ri;
	}
	return n;
}

/* --check mode: pull the hazard counts and captured samples (overlap,
 * registered-buffer lifetime, munmap-under-I/O). */
static void read_hazards(struct uringscope_bpf *skel, struct hazard_report *hr)
{
	__u32 k, filled;
	__u64 n;

	memset(hr, 0, sizeof(*hr));

	k = C_HAZARD; n = 0;
	bpf_map__lookup_elem(skel->maps.counters, &k, sizeof(k), &n,
			     sizeof(n), 0);
	hr->n = n;
	filled = n < HAZARD_SAMPLES ? (__u32)n : HAZARD_SAMPLES;
	for (__u32 i = 0; i < filled; i++) {
		struct hazard_sample s = {};
		if (bpf_map__lookup_elem(skel->maps.haz_samples, &i, sizeof(i),
					 &s, sizeof(s), 0))
			continue;
		hr->samples[hr->nsample++] = s;
	}

	/* hazard 3: the count comes from the kernel; the live indexes are
	 * recovered by scanning the per-ring snapshot the register hook took
	 * (the kernel only copies the refcounts -- see us_uring_register).
	 * Snapshots are keyed by the real io_ring_ctx pointer, which the
	 * spawned-command --check path has in rings[].ctx. */
	k = C_HAZARD_BUFREG; n = 0;
	bpf_map__lookup_elem(skel->maps.counters, &k, sizeof(k), &n,
			     sizeof(n), 0);
	hr->n_bufreg = n;
	if (n) {
		static struct buf_refcounts snap; /* 8K: keep off the stack */
		struct ring_info rings[MAX_RINGS];
		int nr = read_rings(skel, rings);

		for (int ri = 0; ri < nr && hr->nbufreg < HAZARD_SAMPLES; ri++) {
			if (bpf_map__lookup_elem(skel->maps.bufreg_snap,
						 &rings[ri].ctx,
						 sizeof(rings[ri].ctx),
						 &snap, sizeof(snap), 0))
				continue;
			for (__u32 i = 0; i < MAX_REG_BUFS &&
			     hr->nbufreg < HAZARD_SAMPLES; i++) {
				if (!snap.refs[i])
					continue;
				hr->bufreg[hr->nbufreg].bufidx = i;
				hr->bufreg[hr->nbufreg].refs =
					snap.refs[i] > 0xFFFFFFFFu ?
					0xFFFFFFFFu : (__u32)snap.refs[i];
				hr->nbufreg++;
			}
		}
	}

	k = C_HAZARD_UNMAP; n = 0;
	bpf_map__lookup_elem(skel->maps.counters, &k, sizeof(k), &n,
			     sizeof(n), 0);
	hr->n_unmap = n;
	filled = n < HAZARD_SAMPLES ? (__u32)n : HAZARD_SAMPLES;
	for (__u32 i = 0; i < filled; i++) {
		struct unmap_sample s = {};
		if (bpf_map__lookup_elem(skel->maps.haz_unmap_samples, &i,
					 sizeof(i), &s, sizeof(s), 0))
			continue;
		hr->unmap[hr->nunmap++] = s;
	}
}

/* ---------- seed rings that existed before we attached ----------------- *
 *
 * On the -p/-a attach path the target's rings were created before us, so
 * io_uring_create (us_create) never fired for them: ctx_owner has no entry
 * and the report would show "rings created: 0". Submit/complete are still
 * counted -- do_submit falls back to the submitting task's tgid (cur_tgid)
 * when the ring is unknown -- but the ring list, sizes, and SQPOLL state are
 * missing. The kernel io_ring_ctx pointer (the map key us_create uses) is not
 * exposed to userspace, so we can't seed ctx_owner; instead we read what
 * /proc does expose -- the anon_inode:[io_uring] fd links under
 * /proc/<pid>/fd, plus best-effort geometry from /proc/<pid>/fdinfo/<fd> --
 * and seed the rings report map directly. The ring is counted on the fd
 * match alone; sizes/flags are filled only when fdinfo exposes them, which a
 * busy ring (and any ring on >= 6.17, where the io_uring fdinfo dump drops the
 * SqMask/CqMask lines under load) may not. DEFER_TASKRUN/SINGLE_ISSUER are
 * never exposed and stay unknown on this path. */

/* Fill ring geometry from fdinfo, best-effort: a busy ring (or >= 6.17) may
 * print only the generic fd fields, in which case sizes stay 0 (unknown) and
 * SQPOLL can't be inferred. The caller counts the ring regardless. */
static void parse_ring_fdinfo(const char *path, struct ring_info *ri)
{
	char line[160];
	long sqmask = -1, cqmask = -1, sqthread = -1;
	FILE *f = fopen(path, "r");

	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		sscanf(line, "SqMask: %li", &sqmask);
		sscanf(line, "CqMask: %li", &cqmask);
		sscanf(line, "SqThread: %li", &sqthread);
	}
	fclose(f);
	if (sqmask >= 0)
		ri->sq_entries = (__u32)(sqmask + 1);
	if (cqmask >= 0)
		ri->cq_entries = (__u32)(cqmask + 1);
	if (sqthread >= 0)
		ri->flags |= US_SETUP_SQPOLL;
}

/* Seed every io_uring ring open in @pid into the rings map, starting at
 * *slot. The synthetic ctx id only has to be non-zero (read_rings treats a
 * zero ctx as an empty slot); attribution flows through cur_tgid, not this. */
static void seed_pid_rings(struct uringscope_bpf *skel, int pid, __u32 *slot,
			   int verbose)
{
	char dpath[64], fdpath[96], fipath[96], cpath[64], comm[TASK_COMM_SZ] = {};
	struct dirent *e;
	DIR *d;
	FILE *cf;

	snprintf(dpath, sizeof(dpath), "/proc/%d/fd", pid);
	d = opendir(dpath);
	if (!d)
		return;

	snprintf(cpath, sizeof(cpath), "/proc/%d/comm", pid);
	cf = fopen(cpath, "r");
	if (cf) {
		if (fgets(comm, sizeof(comm), cf))
			comm[strcspn(comm, "\n")] = 0;
		fclose(cf);
	}

	while ((e = readdir(d)) && *slot < MAX_RINGS) {
		char link[64];
		struct ring_info ri = {};
		ssize_t n;
		int fd;

		if (e->d_name[0] < '0' || e->d_name[0] > '9')
			continue;
		fd = atoi(e->d_name);
		snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd/%d", pid, fd);
		n = readlink(fdpath, link, sizeof(link) - 1);
		if (n < 0)
			continue;
		link[n] = 0;
		if (!strstr(link, "[io_uring]"))
			continue;
		/* It's a ring -- count it on the fd match. fdinfo only fills in
		 * sizes/SQPOLL when the kernel exposes them (idle ring, < 6.17). */
		snprintf(fipath, sizeof(fipath), "/proc/%d/fdinfo/%d", pid, fd);
		parse_ring_fdinfo(fipath, &ri);

		ri.ctx = ((__u64)pid << 20) | (__u32)(fd + 1); /* non-zero marker */
		ri.fd = fd;
		ri.tgid = pid;
		memcpy(ri.comm, comm, sizeof(ri.comm));
		bpf_map__update_elem(skel->maps.rings, slot, sizeof(*slot),
				     &ri, sizeof(ri), 0);
		(*slot)++;
		if (verbose)
			fprintf(stderr, "uringscope: seeded existing ring "
				"pid=%d fd=%d sq=%u cq=%u%s\n", pid, fd,
				ri.sq_entries, ri.cq_entries,
				(ri.flags & US_SETUP_SQPOLL) ? " SQPOLL" : "");
	}
	closedir(d);
}

static int pid_ppid(int pid)
{
	char path[64], line[64];
	int ppid = -1;
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	f = fopen(path, "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f))
		if (sscanf(line, "PPid:\t%d", &ppid) == 1)
			break;
	fclose(f);
	return ppid;
}

static int pid_descends_from(int pid, int ancestor)
{
	for (int i = 0; i < 16 && pid > 1; i++) {
		pid = pid_ppid(pid);
		if (pid == ancestor)
			return 1;
	}
	return 0;
}

/* Discover rings open before attach: the target pid (-p) or every pid (-a).
 * With -f, the target's pre-existing descendants are seeded too (their new
 * activity is matched in-kernel by the ancestry walk; this fills in the
 * ring list for rings they created before we attached). */
static void seed_existing_rings(struct uringscope_bpf *skel, pid_t target,
				int all, int follow, int verbose)
{
	__u32 slot = 0, k = C_RINGS;
	__u64 n;

	if (all || follow) {
		struct dirent *e;
		DIR *proc = opendir("/proc");

		if (!proc)
			return;
		while ((e = readdir(proc)) && slot < MAX_RINGS) {
			int pid;

			if (e->d_name[0] < '0' || e->d_name[0] > '9')
				continue;
			pid = atoi(e->d_name);
			if (!all && pid != (int)target &&
			    !pid_descends_from(pid, (int)target))
				continue;
			seed_pid_rings(skel, pid, &slot, verbose);
		}
		closedir(proc);
	} else {
		seed_pid_rings(skel, (int)target, &slot, verbose);
	}

	if (slot) {
		/* Match us_create's bookkeeping so new rings append after these. */
		n = slot;
		bpf_map__update_elem(skel->maps.counters, &k, sizeof(k),
				     &n, sizeof(n), 0);
	}
}

/* ---------- summary report --------------------------------------------- */

/* Scan the in-flight map for requests that were submitted but never
 * completed. Multishot requests are skipped: they hold an in-flight slot
 * forever by design. Everything else older than the threshold is a
 * suspected completion leak. */
static void scan_inflight(struct uringscope_bpf *skel, __u64 wall_ns,
			  struct leak_report *lr)
{
	__u64 key, next, now = now_ns();
	void *prev = NULL;
	struct inflight v;

	memset(lr, 0, sizeof(*lr));
	/* aged = older than 2s, but never more than half the window so
	 * short runs can still detect. */
	lr->thresh_ns = 2000000000ULL;
	if (wall_ns / 2 < lr->thresh_ns)
		lr->thresh_ns = wall_ns / 2;

	while (!bpf_map__get_next_key(skel->maps.inflight, prev, &next,
				      sizeof(next))) {
		key = next;
		prev = &key;
		if (bpf_map__lookup_elem(skel->maps.inflight, &key,
					 sizeof(key), &v, sizeof(v), 0))
			continue;
		if (v.fl & IF_MULTISHOT)
			continue;
		if (now - v.ts_submit < lr->thresh_ns) {
			lr->pending++;
			continue;
		}
		lr->n++;
		if (v.fl & IF_POLLED)
			lr->n_polled++;
		if (now - v.ts_submit > lr->oldest_ns)
			lr->oldest_ns = now - v.ts_submit;
		if (v.opcode < MAX_OPS)
			lr->per_op[v.opcode]++;
		if (lr->nsample < LEAK_SAMPLES) {
			lr->sample_ud[lr->nsample] = v.user_data;
			lr->sample_op[lr->nsample] = v.opcode;
			lr->nsample++;
		}
	}
}

/* ---------- live (-i) mode --------------------------------------------- */

/* Counters and per-op stats only -- the cheap snapshot a live tick needs.
 * Leak scan and hazard samples wait for the final report: they need the
 * full window to avoid false positives. */
static void collect_live(struct uringscope_bpf *skel, __u64 wall_ns,
			 struct us_report *r)
{
	r->wall_ns = wall_ns;
	read_counters(skel, r->c);
	read_opstats(skel, r->ops);
	r->nrings = read_rings(skel, r->rings);
}

/* Snapshot-and-delta, iostat-style: the kernel maps keep accumulating (the
 * final report and the doctor need the whole window); we print only what
 * moved since the previous tick. */
static void print_live(const struct us_report *cur)
{
	static struct us_report prev;
	static int first = 1;
	const __u64 *c = cur->c, *p = prev.c;
	char b1[32], b2[32], b3[32];
	__u64 dsub = c[C_SUBMIT] - p[C_SUBMIT];
	__u64 dpunt = c[C_PUNT] - p[C_PUNT];

	if (isatty(1))
		printf("\033[H\033[2J");
	else if (!first)
		printf("\n");

	fmt_ns(cur->wall_ns, b1, sizeof(b1));
	printf("uringscope live -- %s elapsed (deltas since last tick)\n", b1);
	printf("submissions +%-9llu completions +%-9llu punted +%llu (%.1f%%)\n",
	       (unsigned long long)dsub,
	       (unsigned long long)(c[C_COMPLETE] - p[C_COMPLETE]),
	       (unsigned long long)dpunt,
	       dsub ? 100.0 * dpunt / dsub : 0.0);
	printf("overflows +%llu  errors +%llu  enter() +%llu  poll-armed +%llu  workers total %llu\n",
	       (unsigned long long)(c[C_OVERFLOW] - p[C_OVERFLOW]),
	       (unsigned long long)(c[C_ERRORS] - p[C_ERRORS]),
	       (unsigned long long)(c[C_ENTER] - p[C_ENTER]),
	       (unsigned long long)(c[C_POLL_ARM] - p[C_POLL_ARM]),
	       (unsigned long long)c[C_WORKERS_SEEN]);

	printf("\n%-16s %10s %10s %7s %7s %9s %9s %9s\n", "op", "submitted",
	       "completed", "punt%", "err", "avg", "p50", "p99");
	for (int i = 0; i < MAX_OPS; i++) {
		const struct opstat *o = &cur->ops[i], *q = &prev.ops[i];
		struct opstat d;

		d.submitted = o->submitted - q->submitted;
		d.completed = o->completed - q->completed;
		d.punted = o->punted - q->punted;
		d.errors = o->errors - q->errors;
		d.lat_sum_ns = o->lat_sum_ns - q->lat_sum_ns;
		for (int s = 0; s < NLAT_SLOTS; s++)
			d.hist[s] = o->hist[s] - q->hist[s];
		if (!d.submitted && !d.completed)
			continue;
		if (!row_visible(i, &d))
			continue;
		fmt_ns(d.completed ? d.lat_sum_ns / d.completed : 0,
		       b1, sizeof(b1));
		fmt_ns(us_hist_percentile(d.hist, NLAT_SLOTS, 0.50),
		       b2, sizeof(b2));
		fmt_ns(us_hist_percentile(d.hist, NLAT_SLOTS, 0.99),
		       b3, sizeof(b3));
		printf("%-16s %+10lld %+10lld %6.1f%% %7llu %9s %9s %9s\n",
		       op_name(i),
		       (long long)d.submitted, (long long)d.completed,
		       d.submitted ? 100.0 * d.punted / d.submitted : 0.0,
		       (unsigned long long)d.errors, b1, b2, b3);
	}
	fflush(stdout);
	prev = *cur;
	first = 0;
}

/* When completion ran on the fail-soft (an unrecognized io_uring_complete
 * prototype on this kernel), we have a global completion count but no
 * per-request correlation: the inflight map never drains, so the leak
 * scan would flag everything as leaked. Suppress it rather than emit
 * that wrong data -- the support-tier summary already explained why. */
static void collect_report(struct uringscope_bpf *skel, __u64 wall_ns,
			   struct us_report *r)
{
	struct e2e_report er = r->er; /* filled by the uprobe layer, keep */

	memset(r, 0, sizeof(*r));
	r->er = er;
	r->wall_ns = wall_ns;
	r->coarse_complete =
		bpf_program__autoload(skel->progs.us_complete_count);
	read_counters(skel, r->c);
	read_opstats(skel, r->ops);
	r->nrings = read_rings(skel, r->rings);
	if (!r->coarse_complete)
		scan_inflight(skel, wall_ns, &r->lr);
	read_hazards(skel, &r->hr);
}

static void print_summary(const struct us_report *r, int run_doctor)
{
	const __u64 *c = r->c;
	char b1[32], b2[32], b3[32];

	printf("\n========================= uringscope report =========================\n");
	fmt_ns(r->wall_ns, b1, sizeof(b1));
	printf("observed: %s   rings created: %llu\n", b1,
	       (unsigned long long)c[C_RINGS]);

	if (!disp.summary_only) {
		for (int i = 0; i < r->nrings; i++) {
			const struct ring_info *ri = &r->rings[i];
			printf("  ring fd=%u  comm=%-15s sq=%u cq=%u  flags=0x%x%s%s%s%s\n",
			       ri->fd, ri->comm, ri->sq_entries, ri->cq_entries,
			       ri->flags,
			       (ri->flags & US_SETUP_SQPOLL) ? " SQPOLL" : "",
			       (ri->flags & US_SETUP_IOPOLL) ? " IOPOLL" : "",
			       (ri->flags & US_SETUP_DEFER_TASKRUN) ? " DEFER_TASKRUN" : "",
			       (ri->flags & US_SETUP_SINGLE_ISSUER) ? " SINGLE_ISSUER" : "");
		}
	}

	if (r->coarse_complete)
		printf("\nNOTE: this kernel's io_uring_complete prototype is "
		       "unrecognized; completions are a coarse count only "
		       "(no per-op latency, no leak detection). See the "
		       "support-tier summary above.\n");

	if (!disp.summary_only) {
		printf("\nsubmissions: %-10llu completions: %-10llu inflight at exit: %lld\n",
		       (unsigned long long)c[C_SUBMIT],
		       (unsigned long long)c[C_COMPLETE],
		       (long long)(c[C_SUBMIT] - c[C_COMPLETE]));
		printf("punted to io-wq: %llu (%.1f%%)   poll-armed: %llu   multishot CQEs: %llu\n",
		       (unsigned long long)c[C_PUNT],
		       c[C_SUBMIT] ? 100.0 * c[C_PUNT] / c[C_SUBMIT] : 0.0,
		       (unsigned long long)c[C_POLL_ARM],
		       (unsigned long long)c[C_MULTISHOT]);
		printf("CQ overflows: %llu   short writes: %llu   errors (res<0): %llu\n",
		       (unsigned long long)c[C_OVERFLOW],
		       (unsigned long long)c[C_SHORT_WRITE],
		       (unsigned long long)c[C_ERRORS]);

		if (c[C_ENTER]) {
			printf("\nbatching: %llu io_uring_enter() calls, avg %.2f SQEs submitted per call\n",
			       (unsigned long long)c[C_ENTER],
			       (double)c[C_RET_SUBMITTED] / c[C_ENTER]);
		} else if (c[C_SUBMIT]) {
			printf("\nbatching: 0 io_uring_enter() calls seen (SQPOLL fast path)\n");
		}
		if (c[C_CQ_DEPTH_SAMPLES]) {
			printf("CQ depth: avg %.1f, max %llu (sampled at completion, %llu samples)\n",
			       (double)c[C_CQ_DEPTH_SUM] / c[C_CQ_DEPTH_SAMPLES],
			       (unsigned long long)c[C_CQ_DEPTH_MAX],
			       (unsigned long long)c[C_CQ_DEPTH_SAMPLES]);
		}
		if (c[C_SQPOLL_SWITCHES]) {
			fmt_ns(c[C_SQPOLL_OFFCPU_NS], b1, sizeof(b1));
			printf("SQPOLL thread: off-CPU %s total (%.1f%% of observed window)\n",
			       b1, r->wall_ns ?
			       100.0 * c[C_SQPOLL_OFFCPU_NS] / r->wall_ns : 0.0);
		}
		if (c[C_WORKERS_SEEN])
			printf("io-wq workers observed: %llu distinct threads\n",
			       (unsigned long long)c[C_WORKERS_SEEN]);

		/* end-to-end boundary: submit-side | kernel | reap-side */
		if (r->er.available) {
			const struct e2e_report *er = &r->er;

			printf("\nend-to-end boundary (liburing uprobes)\n");
			if (er->submit_calls) {
				fmt_ns(er->submit_calls > 1 ?
				       er->submit_interval_sum_ns /
					       (er->submit_calls - 1) : 0,
				       b1, sizeof(b1));
				printf("  submit-side: %llu io_uring_submit() calls, "
				       "avg %.1f SQEs pending/call, avg %s between calls\n",
				       (unsigned long long)er->submit_calls,
				       (double)er->submit_batch_sum /
					       er->submit_calls, b1);
			} else {
				printf("  submit-side: no io_uring_submit() calls "
				       "observed (inlined submission or SQPOLL)\n");
			}
			printf("  kernel:      submit -> complete latency in the "
			       "per-op table below\n");
			if (er->reap_n) {
				fmt_ns(er->reap_sum_ns / er->reap_n, b1, sizeof(b1));
				fmt_ns(us_hist_percentile(er->reap_hist,
							  NLAT_SLOTS, 0.99),
				       b2, sizeof(b2));
				printf("  reap-side:   reap lag: avg %s p99 %s "
				       "(n=%llu, age of the oldest ready CQE at "
				       "reap entry)\n", b1, b2,
				       (unsigned long long)er->reap_n);
			} else {
				printf("  reap-side:   no samples (app may reap "
				       "via liburing's inlined peek path -- "
				       "invisible to uprobes)\n");
			}
		} else {
			printf("\nend-to-end boundary: kernel-side only "
			       "(liburing uprobes unavailable; see "
			       "docs/end-to-end.md)\n");
		}
	}

	/* per-opcode table */
	printf("\n%-16s %10s %10s %7s %7s %9s %9s %9s\n", "op", "submitted",
	       "completed", "punt%", "err", "avg", "p50", "p99");
	for (int i = 0; i < MAX_OPS; i++) {
		const struct opstat *o = &r->ops[i];
		if (!o->submitted && !o->completed)
			continue;
		if (!row_visible(i, o))
			continue;
		fmt_ns(o->completed ? o->lat_sum_ns / o->completed : 0, b1, sizeof(b1));
		fmt_ns(us_hist_percentile(o->hist, NLAT_SLOTS, 0.50), b2, sizeof(b2));
		fmt_ns(us_hist_percentile(o->hist, NLAT_SLOTS, 0.99), b3, sizeof(b3));
		printf("%-16s %10llu %10llu %6.1f%% %7llu %9s %9s %9s\n",
		       op_name(i),
		       (unsigned long long)o->submitted,
		       (unsigned long long)o->completed,
		       o->submitted ? 100.0 * o->punted / o->submitted : 0.0,
		       (unsigned long long)o->errors, b1, b2, b3);
	}

	/* latency histograms for the 3 busiest (visible) opcodes */
	if (!disp.summary_only) {
		int top[3] = { -1, -1, -1 };
		for (int i = 0; i < MAX_OPS; i++) {
			if (!row_visible(i, &r->ops[i]))
				continue;
			for (int t = 0; t < 3; t++) {
				if (top[t] < 0 ||
				    r->ops[i].completed > r->ops[top[t]].completed) {
					for (int s = 2; s > t; s--)
						top[s] = top[s - 1];
					top[t] = i;
					break;
				}
			}
		}
		for (int t = 0; t < 3; t++) {
			char title[64];
			if (top[t] < 0 || !r->ops[top[t]].completed)
				continue;
			snprintf(title, sizeof(title),
				 "%s latency (submit -> complete)",
				 op_name(top[t]));
			print_hist(r->ops[top[t]].hist, NLAT_SLOTS, title);
		}
	}

	if (run_doctor)
		doctor_run(c, r->ops, r->rings, r->nrings, &r->lr, &r->hr,
			   &r->er, r->wall_ns, get_nprocs());

	printf("======================================================================\n");
}

/* ---------- child spawning --------------------------------------------- */

static pid_t spawn_paused(char **argv, int *go_pipe)
{
	int p[2];
	pid_t pid;

	if (pipe(p))
		return -1;
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		char c;
		close(p[1]);
		/* wait for the parent to finish attaching */
		while (read(p[0], &c, 1) < 0 && errno == EINTR)
			;
		close(p[0]);
		execvp(argv[0], argv);
		fprintf(stderr, "uringscope: exec %s: %s\n", argv[0],
			strerror(errno));
		_exit(127);
	}
	close(p[0]);
	*go_pipe = p[1];
	return pid;
}

/* ---------- main -------------------------------------------------------- */

static void usage(const char *me)
{
	fprintf(stderr,
"uringscope - flight recorder & doctor for io_uring\n\n"
"usage: %s [options] [--] <command> [args...]\n"
"       %s [options] -p <pid>\n\n"
"  -p, --pid PID        observe an already-running process\n"
"  -a, --all            observe every io_uring user on the system\n"
"  -f, --follow         with -p: also observe children/threads forked by\n"
"                       the target (events match by ring ownership and\n"
"                       fork ancestry instead of one tgid; costs a bounded\n"
"                       parent-chain walk on filtered events)\n"
"  -d, --duration SEC   stop after SEC seconds\n"
"  -c, --summary        compact report: per-op table + doctor only,\n"
"                       like strace -c\n"
"  -e, --filter TOKENS  display filter, comma-separated (collection is\n"
"                       unaffected): op=NAME[,NAME..] | punt | error | all\n"
"  -i, --interval SEC   live mode: reprint the per-op delta table every\n"
"                       SEC seconds while the target runs (iostat -x 1\n"
"                       style; doctor still runs on the full window at\n"
"                       exit only)\n"
"      --metrics [H:]P  serve OpenMetrics text at http://H:P/metrics\n"
"                       (default host 0.0.0.0; snapshots refresh on the\n"
"                       -i interval, default 5s)\n"
"      --baseline FILE  save the JSON report to FILE at exit\n"
"      --diff FILE      after the report, print a delta table (IOPS,\n"
"                       percentiles, punt%%) vs a saved baseline\n"
"  -t, --trace FILE     also record a per-request timeline\n"
"                       (Perfetto/Chrome JSON; open at ui.perfetto.dev)\n"
"      --check          hazard mode: flag overlapping in-flight buffer\n"
"                       ranges, registered-buffer lifetime violations and\n"
"                       munmap-under-I/O (silent data corruption). Higher\n"
"                       overhead; use it like ASan for your io_uring test\n"
"                       suite. (-c meant this before 0.2; it is now the\n"
"                       strace-style summary flag.)\n"
"      --json[=PATH]    emit the full report as one JSON object. With no\n"
"                       PATH it goes to stdout and replaces the human\n"
"                       report. '--json PATH' is accepted when PATH ends\n"
"                       in .json\n"
"      --fail-on LEVEL  exit 3 when the doctor reports a finding at or\n"
"                       above LEVEL (info|warn|crit), so scripts and CI\n"
"                       can gate on the verdict without parsing output.\n"
"                       TOOL self-reports never trip the gate. Precedence:\n"
"                       uringscope errors exit 1; a spawned command's\n"
"                       nonzero exit status propagates; then this gate\n"
"      --list-ops       print the opcode table and exit\n"
"      --version        print version + kernel support tiers and exit\n"
"      --no-doctor      skip the diagnosis section of the report\n"
"  -v, --verbose        libbpf debug output (incl. the kernel verifier log)\n"
"  -h, --help           this text\n"
"\n"
"environment:\n"
"  URINGSCOPE_DEBUG=1   startup/exit-time diagnostics (stage timing, map\n"
"                       fill levels, a hint on load failure). =2 also\n"
"                       streams the verifier log. Userspace-only: no effect\n"
"                       on the in-kernel data path.\n", me, me);
}

enum { OPT_NO_DOCTOR = 1, OPT_CHECK, OPT_JSON, OPT_LIST_OPS, OPT_VERSION,
       OPT_METRICS, OPT_BASELINE, OPT_DIFF, OPT_FAIL_ON };

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "pid",       required_argument, NULL, 'p' },
		{ "all",       no_argument,       NULL, 'a' },
		{ "follow",    no_argument,       NULL, 'f' },
		{ "duration",  required_argument, NULL, 'd' },
		{ "summary",   no_argument,       NULL, 'c' },
		{ "filter",    required_argument, NULL, 'e' },
		{ "interval",  required_argument, NULL, 'i' },
		{ "trace",     required_argument, NULL, 't' },
		{ "check",     no_argument,       NULL, OPT_CHECK },
		{ "json",      optional_argument, NULL, OPT_JSON },
		{ "metrics",   required_argument, NULL, OPT_METRICS },
		{ "baseline",  required_argument, NULL, OPT_BASELINE },
		{ "diff",      required_argument, NULL, OPT_DIFF },
		{ "fail-on",   required_argument, NULL, OPT_FAIL_ON },
		{ "list-ops",  no_argument,       NULL, OPT_LIST_OPS },
		{ "version",   no_argument,       NULL, OPT_VERSION },
		{ "no-doctor", no_argument,       NULL, OPT_NO_DOCTOR },
		{ "verbose",   no_argument,       NULL, 'v' },
		{ "help",      no_argument,       NULL, 'h' },
		{},
	};
	struct uringscope_bpf *skel;
	struct ring_buffer *rb = NULL;
	struct perfetto_writer pw = {};
	static struct us_report rep; /* ~50K of maps snapshot: not stack */
	const char *trace_path = NULL, *json_path = NULL;
	const char *metrics_spec = NULL, *baseline_path = NULL;
	const char *diff_path = NULL;
	__u64 t_start, duration_ns = 0, interval_ns = 0;
	pid_t target = 0, child = 0;
	int run_doctor = 1, all = 0, go_pipe = -1, check = 0, follow = 0;
	int json_out = 0, want_version = 0, fail_on = DOC_SEV_NONE;
	int err, c, child_status = 0;

	while ((c = getopt_long(argc, argv, "+p:afd:ce:i:t:vh", opts, NULL)) != -1) {
		switch (c) {
		case 'p': target = atoi(optarg); break;
		case 'a': all = 1; break;
		case 'f': follow = 1; break;
		case 'd': duration_ns = strtoull(optarg, NULL, 10) * 1000000000ULL; break;
		case 'c': disp.summary_only = 1; break;
		case 'e':
			if (parse_filter(optarg))
				return 1;
			break;
		case 'i':
			interval_ns = (__u64)(strtod(optarg, NULL) * 1e9);
			if (!interval_ns) {
				fprintf(stderr, "uringscope: -i needs a "
					"positive interval in seconds\n");
				return 1;
			}
			break;
		case 't': trace_path = optarg; break;
		case OPT_CHECK: check = 1; break;
		case OPT_METRICS: metrics_spec = optarg; break;
		case OPT_BASELINE: baseline_path = optarg; break;
		case OPT_DIFF: diff_path = optarg; break;
		case OPT_JSON:
			json_out = 1;
			json_path = optarg; /* --json=PATH form */
			/* '--json PATH': getopt won't bind a separate token
			 * to an optional argument, so peek -- but only claim
			 * it when it is unmistakably a json path, never the
			 * command we're about to exec. */
			if (!json_path && optind < argc) {
				size_t n = strlen(argv[optind]);
				if (n > 5 && !strcmp(argv[optind] + n - 5,
						     ".json"))
					json_path = argv[optind++];
			}
			break;
		case OPT_FAIL_ON:
			if (!strcmp(optarg, "info"))
				fail_on = DOC_SEV_INFO;
			else if (!strcmp(optarg, "warn"))
				fail_on = DOC_SEV_WARN;
			else if (!strcmp(optarg, "crit"))
				fail_on = DOC_SEV_CRIT;
			else {
				fprintf(stderr, "uringscope: --fail-on takes "
					"info, warn or crit\n");
				return 1;
			}
			break;
		case OPT_LIST_OPS: list_ops(); return 0;
		case OPT_VERSION: want_version = 1; break;
		case OPT_NO_DOCTOR: run_doctor = 0; break;
		case 'v': verbose = 1; break;
		case 'h': usage(argv[0]); return 0;
		default: usage(argv[0]); return 1;
		}
	}

	/* Debug level (startup/exit-time diagnostics only; never on a
	 * per-event path -- see dbg()). URINGSCOPE_DEBUG=2 also implies -v. */
	{
		const char *d = getenv("URINGSCOPE_DEBUG");
		if (d && *d)
			debug_level = atoi(d);
		if (debug_level >= 2)
			verbose = 1;
	}

	if (want_version) {
		printf("uringscope %s (%s)\n", US_VERSION, US_GITREV);
		/* the support-tier table for *this* kernel: open the
		 * skeleton (no load, no privileges) and run the BTF probe */
		libbpf_set_print(libbpf_print);
		skel = uringscope_bpf__open();
		if (skel) {
			probe_set_tier_stream(stdout);
			probe_setup(skel, 0);
			uringscope_bpf__destroy(skel);
		}
		return 0;
	}
	if (!target && !all && optind >= argc) {
		usage(argv[0]);
		return 1;
	}
	if (follow && all) {
		fprintf(stderr, "uringscope: -f is a no-op with -a "
			"(everything is already observed)\n");
		follow = 0;
	}
	if (fail_on && !run_doctor) {
		fprintf(stderr, "uringscope: --fail-on gates on the doctor's "
			"findings; it cannot be combined with --no-doctor\n");
		return 1;
	}
	if (json_out && !json_path && !target && !all)
		fprintf(stderr, "uringscope: note: with a spawned command, "
			"its stdout interleaves with the JSON object -- "
			"use --json=PATH for a clean file\n");
	if (interval_ns && json_out && !json_path) {
		fprintf(stderr, "uringscope: -i disabled: stdout is "
			"reserved for the JSON object (use --json=PATH)\n");
		interval_ns = 0;
	}

	libbpf_set_print(libbpf_print);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
	setrlimit(RLIMIT_MEMLOCK, &rl); /* pre-5.11 kernels */

	if (!target && !all)
		child = target = spawn_paused(&argv[optind], &go_pipe);
	if (target < 0) {
		fprintf(stderr, "uringscope: failed to spawn child\n");
		return 1;
	}

	skel = uringscope_bpf__open();
	if (!skel) {
		fprintf(stderr, "uringscope: failed to open BPF skeleton\n");
		return 1;
	}
	skel->rodata->cfg_tgid = all ? 0 : (__u32)target;
	skel->rodata->cfg_trace_mode = trace_path ? 1 : 0;
	skel->rodata->cfg_check_mode = check ? 1 : 0;
	skel->rodata->cfg_follow = follow ? 1 : 0;

	/* If we run inside a child pid namespace (every WSL2 distro does,
	 * and so does any container), the pids we filter on are namespaced
	 * while the kernel reports root-namespace ids. Hand the BPF side
	 * our namespace's nsfs inode so it can translate. */
	{
		struct stat pidns;
		if (!stat("/proc/self/ns/pid", &pidns) &&
		    pidns.st_ino != 0xEFFFFFFCu /* PROC_PID_INIT_INO */) {
			skel->rodata->cfg_pidns_ino = (__u32)pidns.st_ino;
			if (verbose)
				fprintf(stderr,
					"uringscope: child pid namespace (inode %lu); translating tgids\n",
					(unsigned long)pidns.st_ino);
		}
	}

	/* Probe the running kernel's BTF; enable the right tracepoint
	 * program variants for this kernel generation. */
	err = probe_setup(skel, verbose);
	if (err) {
		fprintf(stderr,
			"uringscope: kernel probe failed (%d). Is this kernel"
			" built with CONFIG_DEBUG_INFO_BTF and io_uring?\n",
			err);
		goto out;
	}

	/* End-to-end boundary (best-effort liburing uprobes): locate the
	 * target's liburing now so cfg_e2e bakes into rodata before load.
	 * -p reads the live process's maps; the spawned-command and -a
	 * paths resolve the system liburing from the ld cache. */
	{
		int e2e_ok = uprobes_prepare(
				(!child && !all && target) ? target : 0);
		skel->rodata->cfg_e2e = e2e_ok ? 1 : 0;
	}

	/* The hazard hooks only do work under --check; skip loading and
	 * attaching them entirely outside it (munmap is a hot-ish path). */
	if (!check) {
		bpf_program__set_autoload(skel->progs.us_uring_register, false);
		bpf_program__set_autoload(skel->progs.us_munmap, false);
	}

	{
		__u64 t0 = now_ns();

		err = uringscope_bpf__load(skel);
		if (err) {
			fprintf(stderr, "uringscope: BPF load failed: %d (%s)\n",
				err, strerror(err < 0 ? -err : err));
			/* The verifier's verdict (e.g. "BPF program is too
			 * large") is libbpf WARN output above; if the user
			 * didn't ask for it, point them at the full log. */
			if (!verbose && debug_level < 2)
				fprintf(stderr, "uringscope: re-run with -v "
					"(or URINGSCOPE_DEBUG=2) to see the "
					"kernel verifier log for the rejected "
					"program.\n");
			goto out;
		}
		dbg(1, "BPF objects loaded in %.1fms",
		    (now_ns() - t0) / 1e6);

		t0 = now_ns();
		err = uringscope_bpf__attach(skel);
		if (err) {
			fprintf(stderr, "uringscope: BPF attach failed: %d "
				"(%s)\n", err, strerror(err < 0 ? -err : err));
			goto out;
		}
		dbg(1, "programs attached in %.1fms", (now_ns() - t0) / 1e6);
	}

	/* uprobes attach by library path; the perf pid filter narrows them
	 * to the target where we have a single one (-f and -a need every
	 * process -- the BPF side still tgid-filters the data). Any failure
	 * here logged one line and the kernel-side tool runs unaffected. */
	if (skel->rodata->cfg_e2e)
		uprobes_attach(skel,
			       (follow || all) ? -1 : (child ? child : target),
			       verbose);

	/* Attaching to already-running process(es): their rings predate us, so
	 * seed them from /proc. The -- cmd path (child) creates its rings after
	 * we attach, so us_create observes them -- don't seed there. */
	if (!child)
		seed_existing_rings(skel, target, all, follow, verbose);

	if (trace_path) {
		err = perfetto_open(&pw, trace_path);
		if (err)
			goto out;
		rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
				      perfetto_handle_event, &pw, NULL);
		if (!rb) {
			err = -1;
			goto out;
		}
	}

	if (metrics_spec && metrics_start(metrics_spec)) {
		err = -1;
		goto out;
	}

	t_start = now_ns();
	if (go_pipe >= 0) { /* release the child */
		if (write(go_pipe, "g", 1) != 1)
			fprintf(stderr, "uringscope: child release failed\n");
		close(go_pipe);
	}
	if (verbose)
		fprintf(stderr, "uringscope: attached, observing %s%d\n",
			all ? "system-wide (all=" : "tgid ", all ? 1 : target);

	{
		/* live refresh: -i drives both the screen and /metrics; with
		 * --metrics alone, refresh the snapshot every 5s (default) */
		__u64 tick_ns = interval_ns ? interval_ns : 5000000000ULL;
		__u64 last_tick = t_start;
		int live = interval_ns || metrics_spec;

		while (!exiting) {
			__u64 now;

			if (rb)
				ring_buffer__poll(rb, 100 /* ms */);
			else
				usleep(100 * 1000);
			now = now_ns();
			if (live && now - last_tick >= tick_ns) {
				collect_live(skel, now - t_start, &rep);
				if (interval_ns)
					print_live(&rep);
				if (metrics_spec)
					metrics_update(&rep);
				last_tick = now;
			}
			if (duration_ns && now - t_start >= duration_ns)
				break;
			if (child) {
				pid_t r = waitpid(child, &child_status,
						  WNOHANG);
				if (r == child)
					break;
			} else if (target && kill(target, 0) &&
				   errno == ESRCH) {
				break; /* observed pid went away */
			}
		}
	}
	if (rb) /* drain */
		ring_buffer__poll(rb, 0);

	metrics_stop();
	uprobes_collect(skel, &rep.er);
	collect_report(skel, now_ns() - t_start, &rep);

	/* Tool-health diagnostics (exit-time only, never per-event): map
	 * pressure is the usual cause of undercounted stats, so surface it
	 * under debug. The doctor already raises TOOL findings for the same
	 * conditions in the human report; this adds the raw fill signal. */
	if (debug_level >= 1) {
		dbg(1, "counters: submit=%llu complete=%llu untracked=%llu "
		    "inflight_map_drops=%llu",
		    (unsigned long long)rep.c[C_SUBMIT],
		    (unsigned long long)rep.c[C_COMPLETE],
		    (unsigned long long)rep.c[C_UNTRACKED],
		    (unsigned long long)rep.c[C_INFLIGHT_DROP]);
		if (rep.c[C_INFLIGHT_DROP])
			dbg(1, "inflight hash hit its 256k cap -- latency "
			    "stats undercount; this is a tool limit, not a "
			    "workload bug");
		dbg(1, "leak scan: %llu suspected, %llu still pending at exit",
		    (unsigned long long)rep.lr.n,
		    (unsigned long long)rep.lr.pending);
	}
	if (json_out && !json_path) {
		/* machine mode: stdout carries exactly one JSON object */
		if (run_doctor) {
			doctor_set_quiet(1);
			doctor_run(rep.c, rep.ops, rep.rings, rep.nrings,
				   &rep.lr, &rep.hr, &rep.er, rep.wall_ns,
				   get_nprocs());
		}
		json_write_report(NULL, &rep);
		if (diff_path)
			fprintf(stderr, "uringscope: --diff skipped: stdout "
				"is reserved for the JSON object\n");
	} else {
		print_summary(&rep, run_doctor);
		if (json_out)
			json_write_report(json_path, &rep);
		if (diff_path) {
			static struct baseline base;
			if (!baseline_load(diff_path, &base))
				diff_print(&base, &rep);
		}
	}
	if (baseline_path && !json_write_report(baseline_path, &rep))
		fprintf(stderr, "uringscope: baseline saved to %s\n",
			baseline_path);
	if (trace_path) {
		perfetto_close(&pw);
		fprintf(stderr,
			"timeline written to %s (open at https://ui.perfetto.dev)\n",
			trace_path);
		if (rep.c[C_RB_DROP])
			fprintf(stderr, "uringscope: %llu trace events dropped "
				"(ring buffer full) -- the timeline has gaps\n",
				(unsigned long long)rep.c[C_RB_DROP]);
	}

out:
	uprobes_detach();
	ring_buffer__free(rb);
	uringscope_bpf__destroy(skel);
	/* Exit-status contract (docs/json.md): 1 = uringscope error; a
	 * spawned command's own nonzero exit outranks the doctor gate (CI
	 * should see the workload's failure); 3 = --fail-on tripped; 0 ok. */
	if (err)
		return 1;
	if (child && WIFEXITED(child_status) && WEXITSTATUS(child_status))
		return WEXITSTATUS(child_status);
	if (fail_on && doctor_worst_severity() >= fail_on)
		return 3;
	return 0;
}
