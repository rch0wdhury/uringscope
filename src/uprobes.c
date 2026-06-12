/* SPDX-License-Identifier: MIT */
/*
 * uprobes.c - best-effort liburing uprobes for the end-to-end boundary.
 *
 * The portability contract here is the opposite of the kernel side and the
 * code is structured around that asymmetry: CO-RE gives the BPF programs
 * one-binary-every-kernel portability, but uprobes bind to one specific
 * liburing build's exported symbols. Static linking, stripped symbols,
 * inlining, LTO, or version skew all break attachment. So every step --
 * locate, resolve, attach -- is allowed to fail, logs one clear line, and
 * leaves the kernel-side tool untouched. Nothing here may degrade the
 * kernel-side functionality.
 *
 * Which symbols we anchor on (and why not the obvious ones) is documented
 * at the uprobe programs in bpf/uringscope.bpf.c and in docs/end-to-end.md:
 * io_uring_cqe_seen/io_uring_cq_advance are static inline -- they do not
 * exist in liburing.so and cannot be uprobed by anyone.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>

#include "uringscope.skel.h"
#include "uprobes.h"
#include "jsonout.h"

#define MAX_UPLINKS 16

static struct bpf_link *links[MAX_UPLINKS];
static int nlinks;
static int submit_attached, reap_attached;
static char lib_path[512];

/* /proc/<pid>/maps: the path of the first mapped file containing
 * "liburing". Authoritative for an already-running target. */
static int liburing_from_maps(pid_t pid)
{
	char mpath[64], line[1024];
	FILE *f;
	int found = 0;

	snprintf(mpath, sizeof(mpath), "/proc/%d/maps", pid);
	f = fopen(mpath, "r");
	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		char *path = strchr(line, '/');

		if (!path || !strstr(path, "liburing"))
			continue;
		path[strcspn(path, "\n")] = 0;
		snprintf(lib_path, sizeof(lib_path), "%s", path);
		found = 1;
		break;
	}
	fclose(f);
	return found;
}

/* ld.so cache via ldconfig: where a spawned command will get liburing
 * from. (The child is paused pre-exec when we need this, so its maps
 * don't exist yet.) */
static int liburing_from_ldcache(void)
{
	FILE *p = popen("ldconfig -p 2>/dev/null", "r");
	char line[1024];
	int found = 0;

	if (!p)
		return 0;
	while (fgets(line, sizeof(line), p)) {
		char *arrow, *path;

		if (!strstr(line, "liburing.so.2") &&
		    !strstr(line, "liburing.so "))
			continue;
		if (strstr(line, "liburing-ffi"))
			continue;
		arrow = strstr(line, "=> ");
		if (!arrow)
			continue;
		path = arrow + 3;
		path[strcspn(path, "\n")] = 0;
		snprintf(lib_path, sizeof(lib_path), "%s", path);
		found = 1;
		break;
	}
	pclose(p);
	return found;
}

int uprobes_prepare(pid_t maps_pid)
{
	int found = maps_pid > 0 ? liburing_from_maps(maps_pid)
				 : liburing_from_ldcache();

	if (!found) {
		fprintf(stderr, "  %-16s %s  %s\n", "e2e-boundary", "off     ",
			"no dynamic liburing located");
		fprintf(stderr, "uringscope: note: liburing not dynamically "
			"linked; end-to-end boundary timing unavailable "
			"(kernel-side metrics unaffected)\n");
		return 0;
	}
	fprintf(stderr, "  %-16s %s  liburing uprobes (%s)\n", "e2e-boundary",
		"active  ", lib_path);
	return 1;
}

static void attach_one(struct bpf_program *prog, pid_t pid, const char *sym,
		       int *ok_flag, int verbose)
{
	LIBBPF_OPTS(bpf_uprobe_opts, uopts, .func_name = sym);
	struct bpf_link *l;

	if (nlinks >= MAX_UPLINKS)
		return;
	l = bpf_program__attach_uprobe_opts(prog, pid, lib_path, 0, &uopts);
	if (!l) {
		/* per-symbol absence is expected across liburing versions;
		 * only narrate it when asked */
		if (verbose)
			fprintf(stderr, "uringscope: uprobe %s not attached "
				"(symbol absent in %s?)\n", sym, lib_path);
		return;
	}
	links[nlinks++] = l;
	*ok_flag = 1;
}

int uprobes_attach(struct uringscope_bpf *skel, pid_t filter_pid, int verbose)
{
	static const char *submit_syms[] = {
		"io_uring_submit",
		"io_uring_submit_and_wait",
		"io_uring_submit_and_wait_timeout",
	};
	/* the exported reap-side family; cqe_seen/cq_advance are inline and
	 * have no symbol -- see the header comment */
	static const char *reap_syms[] = {
		"__io_uring_get_cqe",
		"io_uring_wait_cqe_timeout",
		"io_uring_wait_cqes",
		"io_uring_peek_batch_cqe",
		"io_uring_get_events",
		"io_uring_submit_and_get_events",
	};

	if (!lib_path[0])
		return 0;
	for (unsigned i = 0; i < sizeof(submit_syms) / sizeof(*submit_syms); i++)
		attach_one(skel->progs.ur_submit, filter_pid, submit_syms[i],
			   &submit_attached, verbose);
	for (unsigned i = 0; i < sizeof(reap_syms) / sizeof(*reap_syms); i++)
		attach_one(skel->progs.ur_reap, filter_pid, reap_syms[i],
			   &reap_attached, verbose);

	if (!submit_attached && !reap_attached) {
		fprintf(stderr, "uringscope: note: no liburing symbols "
			"attachable in %s (stripped or incompatible); "
			"end-to-end boundary timing unavailable "
			"(kernel-side metrics unaffected)\n", lib_path);
		return 0;
	}
	if (verbose)
		fprintf(stderr, "uringscope: e2e boundary: %d uprobes on %s\n",
			nlinks, lib_path);
	return 1;
}

void uprobes_collect(struct uringscope_bpf *skel, struct e2e_report *er)
{
	struct e2e_stats st = {};
	__u32 z = 0;

	memset(er, 0, sizeof(*er));
	if (!submit_attached && !reap_attached)
		return;
	er->available = 1;
	if (bpf_map__lookup_elem(skel->maps.e2e_stats, &z, sizeof(z), &st,
				 sizeof(st), 0))
		return;
	er->submit_calls = st.submit_calls;
	er->submit_interval_sum_ns = st.submit_interval_sum_ns;
	er->submit_batch_sum = st.submit_batch_sum;
	er->reap_n = st.reap_n;
	er->reap_sum_ns = st.reap_sum_ns;
	memcpy(er->reap_hist, st.reap_hist, sizeof(er->reap_hist));
}

void uprobes_detach(void)
{
	for (int i = 0; i < nlinks; i++)
		bpf_link__destroy(links[i]);
	nlinks = 0;
}
