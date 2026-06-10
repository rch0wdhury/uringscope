/* SPDX-License-Identifier: MIT */
/*
 * probe.c - interrogate the running kernel's BTF and decide which
 * tracepoint program variants to load.
 *
 * Every static tracepoint TP_PROTO(...) shows up in vmlinux BTF as a
 * typedef named btf_trace_<name> pointing at a FUNC_PROTO whose first
 * parameter is the internal `void *__data` followed by the TP_PROTO args.
 * That gives us, at runtime and with zero version tables:
 *
 *   - existence:   does this kernel have io_uring_submit_req at all,
 *                  or the pre-6.0 io_uring_submit_sqe?
 *   - shape:       how many args does io_uring_complete take? does
 *                  queue_async_work pass the request as its first arg?
 *
 * This is what lets one binary cover a span of kernels that renamed and
 * re-prototyped these tracepoints repeatedly.
 */
#include <stdio.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>

#include "uringscope.skel.h"
#include "probe.h"

/* Return nr of TP_PROTO params (excluding the leading void *__data),
 * or -1 if the tracepoint doesn't exist on this kernel. */
static int tp_nr_params(const struct btf *btf, const char *tp)
{
	char name[128];
	int id;
	const struct btf_type *t;

	snprintf(name, sizeof(name), "btf_trace_%s", tp);
	id = btf__find_by_name_kind(btf, name, BTF_KIND_TYPEDEF);
	if (id < 0)
		return -1;
	t = btf__type_by_id(btf, id);
	t = btf__type_by_id(btf, t->type);          /* typedef -> PTR   */
	if (!btf_is_ptr(t))
		return -1;
	t = btf__type_by_id(btf, t->type);          /* PTR -> FUNC_PROTO */
	if (!btf_is_func_proto(t))
		return -1;
	return (int)btf_vlen(t) - 1;
}

/* Does the first TP_PROTO param of `tp` point at struct `sname`? */
static int tp_first_param_is_struct_ptr(const struct btf *btf, const char *tp,
					 const char *sname)
{
	char name[128];
	int id;
	const struct btf_type *t;
	const struct btf_param *p;

	snprintf(name, sizeof(name), "btf_trace_%s", tp);
	id = btf__find_by_name_kind(btf, name, BTF_KIND_TYPEDEF);
	if (id < 0)
		return 0;
	t = btf__type_by_id(btf, id);
	t = btf__type_by_id(btf, t->type);
	if (!btf_is_ptr(t))
		return 0;
	t = btf__type_by_id(btf, t->type);
	if (!btf_is_func_proto(t) || btf_vlen(t) < 2)
		return 0;
	p = btf_params(t) + 1;                      /* skip void *__data */
	t = btf__type_by_id(btf, p->type);
	if (!btf_is_ptr(t))
		return 0;
	t = btf__type_by_id(btf, t->type);
	while (btf_is_mod(t) || btf_is_typedef(t))
		t = btf__type_by_id(btf, t->type);
	if (!btf_is_struct(t))
		return 0;
	return strcmp(btf__name_by_offset(btf, t->name_off), sname) == 0;
}

static void off(struct bpf_program *p, int verbose, const char *why)
{
	bpf_program__set_autoload(p, false);
	if (verbose)
		fprintf(stderr, "uringscope: disabled %s (%s)\n",
			bpf_program__name(p), why);
}

int probe_setup(struct uringscope_bpf *skel, int verbose)
{
	struct btf *btf;
	int n, modern_submit, legacy_submit;

	btf = btf__load_vmlinux_btf();
	if (!btf) {
		fprintf(stderr, "uringscope: cannot load vmlinux BTF "
			"(/sys/kernel/btf/vmlinux missing?)\n");
		return -1;
	}

	/* --- submission family: renamed submit_sqe -> submit_req in v6.0 */
	modern_submit = tp_nr_params(btf, "io_uring_submit_req") >= 1;
	legacy_submit = tp_nr_params(btf, "io_uring_submit_sqe") >= 4;
	if (modern_submit) {
		off(skel->progs.us_submit_sqe_legacy, verbose, "modern kernel");
	} else if (legacy_submit) {
		off(skel->progs.us_submit_req, verbose, "pre-6.0 kernel");
		fprintf(stderr, "uringscope: pre-6.0 kernel detected; "
			"legacy mode (no punt/poll detection, "
			"user_data-keyed attribution)\n");
	} else {
		fprintf(stderr, "uringscope: no io_uring submission "
			"tracepoint in kernel BTF -- kernel too old or "
			"io_uring disabled\n");
		btf__free(btf);
		return -2;
	}

	/* --- completion: distinguish by arity.
	 *     >=6 params: (ctx, req, user_data, res, cflags[, extra1, extra2])
	 *     ==4 params: (ctx, user_data, res, cflags)            (pre-5.19)
	 */
	n = tp_nr_params(btf, "io_uring_complete");
	if (n >= 5) {
		off(skel->progs.us_complete_legacy, verbose, "modern complete");
	} else if (n >= 4) {
		off(skel->progs.us_complete, verbose, "legacy complete");
	} else {
		fprintf(stderr, "uringscope: io_uring_complete tracepoint "
			"missing/unrecognized (params=%d)\n", n);
		btf__free(btf);
		return -3;
	}

	/* --- req-first tracepoints: only safe if the request really is
	 *     the first TP_PROTO argument (true from ~v6.0 onward).      */
	if (!tp_first_param_is_struct_ptr(btf, "io_uring_queue_async_work",
					  "io_kiocb"))
		off(skel->progs.us_queue_async_work, verbose,
		    "old queue_async_work prototype");
	if (!tp_first_param_is_struct_ptr(btf, "io_uring_poll_arm",
					  "io_kiocb"))
		off(skel->progs.us_poll_arm, verbose, "old poll_arm prototype");

	/* --- optional tracepoints that simply may not exist ------------ */
	if (tp_nr_params(btf, "io_uring_local_work_run") < 0)
		off(skel->progs.us_local_work_run, verbose, "not in kernel");
	if (tp_nr_params(btf, "io_uring_short_write") < 0)
		off(skel->progs.us_short_write, verbose, "not in kernel");
	if (tp_nr_params(btf, "io_uring_cqe_overflow") < 0)
		off(skel->progs.us_cqe_overflow, verbose, "not in kernel");
	if (tp_nr_params(btf, "io_uring_task_work_run") < 0)
		off(skel->progs.us_task_work_run, verbose, "not in kernel");
	if (tp_nr_params(btf, "io_uring_create") < 0)
		off(skel->progs.us_create, verbose, "not in kernel");

	btf__free(btf);
	return 0;
}
