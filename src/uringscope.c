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
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "uringscope.h"
#include "uringscope.skel.h"
#include "opnames.h"
#include "probe.h"
#include "perfetto.h"
#include "doctor.h"

static volatile sig_atomic_t exiting;
static int verbose;

static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print(enum libbpf_print_level lvl, const char *fmt,
			va_list args)
{
	if (lvl == LIBBPF_DEBUG && !verbose)
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

static __u64 hist_percentile(const __u64 *hist, int n, double p)
{
	__u64 total = 0, acc = 0;
	for (int i = 0; i < n; i++)
		total += hist[i];
	if (!total)
		return 0;
	for (int i = 0; i < n; i++) {
		acc += hist[i];
		if (acc >= (__u64)(p * total))
			return 1ULL << (i + 1); /* bucket upper bound */
	}
	return 1ULL << n;
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

/* ---------- summary report --------------------------------------------- */

static void print_summary(struct uringscope_bpf *skel, __u64 wall_ns,
			  int run_doctor)
{
	__u64 c[C_MAX];
	static struct opstat ops[MAX_OPS];
	struct ring_info rings[MAX_RINGS];
	char b1[32], b2[32], b3[32];
	int nrings;

	read_counters(skel, c);
	read_opstats(skel, ops);
	nrings = read_rings(skel, rings);

	printf("\n========================= uringscope report =========================\n");
	fmt_ns(wall_ns, b1, sizeof(b1));
	printf("observed: %s   rings created: %llu\n", b1,
	       (unsigned long long)c[C_RINGS]);

	for (int i = 0; i < nrings; i++) {
		struct ring_info *r = &rings[i];
		printf("  ring fd=%u  comm=%-15s sq=%u cq=%u  flags=0x%x%s%s%s%s\n",
		       r->fd, r->comm, r->sq_entries, r->cq_entries, r->flags,
		       (r->flags & US_SETUP_SQPOLL) ? " SQPOLL" : "",
		       (r->flags & US_SETUP_IOPOLL) ? " IOPOLL" : "",
		       (r->flags & US_SETUP_DEFER_TASKRUN) ? " DEFER_TASKRUN" : "",
		       (r->flags & US_SETUP_SINGLE_ISSUER) ? " SINGLE_ISSUER" : "");
	}

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
		       b1, wall_ns ? 100.0 * c[C_SQPOLL_OFFCPU_NS] / wall_ns : 0.0);
	}
	if (c[C_WORKERS_SEEN])
		printf("io-wq workers observed: %llu distinct threads\n",
		       (unsigned long long)c[C_WORKERS_SEEN]);

	/* per-opcode table */
	printf("\n%-16s %10s %10s %7s %7s %9s %9s %9s\n", "op", "submitted",
	       "completed", "punt%", "err", "avg", "p50", "p99");
	for (int i = 0; i < MAX_OPS; i++) {
		struct opstat *o = &ops[i];
		if (!o->submitted && !o->completed)
			continue;
		fmt_ns(o->completed ? o->lat_sum_ns / o->completed : 0, b1, sizeof(b1));
		fmt_ns(hist_percentile(o->hist, NLAT_SLOTS, 0.50), b2, sizeof(b2));
		fmt_ns(hist_percentile(o->hist, NLAT_SLOTS, 0.99), b3, sizeof(b3));
		printf("%-16s %10llu %10llu %6.1f%% %7llu %9s %9s %9s\n",
		       op_name(i),
		       (unsigned long long)o->submitted,
		       (unsigned long long)o->completed,
		       o->submitted ? 100.0 * o->punted / o->submitted : 0.0,
		       (unsigned long long)o->errors, b1, b2, b3);
	}

	/* latency histograms for the 3 busiest opcodes */
	{
		int top[3] = { -1, -1, -1 };
		for (int i = 0; i < MAX_OPS; i++) {
			for (int t = 0; t < 3; t++) {
				if (top[t] < 0 ||
				    ops[i].completed > ops[top[t]].completed) {
					for (int s = 2; s > t; s--)
						top[s] = top[s - 1];
					top[t] = i;
					break;
				}
			}
		}
		for (int t = 0; t < 3; t++) {
			char title[64];
			if (top[t] < 0 || !ops[top[t]].completed)
				continue;
			snprintf(title, sizeof(title),
				 "%s latency (submit -> complete)",
				 op_name(top[t]));
			print_hist(ops[top[t]].hist, NLAT_SLOTS, title);
		}
	}

	if (run_doctor)
		doctor_run(c, ops, rings, nrings, wall_ns,
			   get_nprocs());

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
"  -d, --duration SEC   stop after SEC seconds\n"
"  -t, --trace FILE     also record a per-request timeline\n"
"                       (Perfetto/Chrome JSON; open at ui.perfetto.dev)\n"
"      --no-doctor      skip the diagnosis section of the report\n"
"  -v, --verbose        libbpf debug output\n"
"  -h, --help           this text\n", me, me);
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "pid",       required_argument, NULL, 'p' },
		{ "all",       no_argument,       NULL, 'a' },
		{ "duration",  required_argument, NULL, 'd' },
		{ "trace",     required_argument, NULL, 't' },
		{ "no-doctor", no_argument,       NULL,  1  },
		{ "verbose",   no_argument,       NULL, 'v' },
		{ "help",      no_argument,       NULL, 'h' },
		{},
	};
	struct uringscope_bpf *skel;
	struct ring_buffer *rb = NULL;
	struct perfetto_writer pw = {};
	const char *trace_path = NULL;
	__u64 t_start, duration_ns = 0;
	pid_t target = 0, child = 0;
	int run_doctor = 1, all = 0, go_pipe = -1;
	int err, c, child_status = 0;

	while ((c = getopt_long(argc, argv, "+p:ad:t:vh", opts, NULL)) != -1) {
		switch (c) {
		case 'p': target = atoi(optarg); break;
		case 'a': all = 1; break;
		case 'd': duration_ns = strtoull(optarg, NULL, 10) * 1000000000ULL; break;
		case 't': trace_path = optarg; break;
		case  1 : run_doctor = 0; break;
		case 'v': verbose = 1; break;
		case 'h': usage(argv[0]); return 0;
		default: usage(argv[0]); return 1;
		}
	}
	if (!target && !all && optind >= argc) {
		usage(argv[0]);
		return 1;
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

	err = uringscope_bpf__load(skel);
	if (err) {
		fprintf(stderr, "uringscope: BPF load failed: %d\n", err);
		goto out;
	}
	err = uringscope_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "uringscope: BPF attach failed: %d\n", err);
		goto out;
	}

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

	t_start = now_ns();
	if (go_pipe >= 0) { /* release the child */
		if (write(go_pipe, "g", 1) != 1)
			fprintf(stderr, "uringscope: child release failed\n");
		close(go_pipe);
	}
	if (verbose)
		fprintf(stderr, "uringscope: attached, observing %s%d\n",
			all ? "system-wide (all=" : "tgid ", all ? 1 : target);

	while (!exiting) {
		if (rb)
			ring_buffer__poll(rb, 100 /* ms */);
		else
			usleep(100 * 1000);
		if (duration_ns && now_ns() - t_start >= duration_ns)
			break;
		if (child) {
			pid_t r = waitpid(child, &child_status, WNOHANG);
			if (r == child)
				break;
		} else if (target && kill(target, 0) && errno == ESRCH) {
			break; /* observed pid went away */
		}
	}
	if (rb) /* drain */
		ring_buffer__poll(rb, 0);

	print_summary(skel, now_ns() - t_start, run_doctor);
	if (trace_path) {
		perfetto_close(&pw);
		printf("timeline written to %s (open at https://ui.perfetto.dev)\n",
		       trace_path);
	}

out:
	ring_buffer__free(rb);
	uringscope_bpf__destroy(skel);
	if (child && !WIFEXITED(child_status))
		return err ? 1 : 0;
	return err ? 1 : (child ? WEXITSTATUS(child_status) : 0);
}
