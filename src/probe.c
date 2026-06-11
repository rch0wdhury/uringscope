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
 *
 * Portability contract (kernel-agnostic within honest bounds)
 * -----------------------------------------------------------
 * Tracepoints are NOT ABI: a future kernel can give io_uring_complete (or any
 * hooked tracepoint) a prototype that no compiled variant matches -- exactly
 * what 6.17 did (it collapsed complete's scalar user_data/res/cflags into a
 * single struct io_uring_cqe *). The contract is "degrade and warn, never
 * crash or emit wrong data" -- NOT "attach to a variant we never wrote." So:
 *
 *   - A single tracepoint mismatch never aborts the load. Only an absent
 *     *submission* tracepoint (kernel too old / io_uring off) or missing BTF
 *     is fatal -- without submit there is nothing to correlate against.
 *   - An unrecognized prototype disables just that feature. Where a
 *     positional-arg-free fail-soft program exists (completion), we attach it
 *     instead to keep a coarse count. Either way it is reported in the
 *     startup support-tier summary so the user knows what they're getting.
 *
 * Extending for a new kernel
 * --------------------------
 * The prototype->program mapping lives in ONE place: the feature/variant
 * tables built at the top of probe_setup(). Adding support for a new
 * prototype is a localized change:
 *   1. write the BPF program (a new SEC("tp_btf/<tp>") in uringscope.bpf.c);
 *   2. add a struct tp_variant row naming it, its param-count range, and any
 *      positional struct check;
 *   3. order it among the existing rows (first match wins).
 * No other edits to this file are needed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>

#include "uringscope.skel.h"
#include "probe.h"

#define ANY_PARAMS 99   /* upper bound for "this many params or more" */

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

/* Does TP_PROTO arg `idx` (0-based, after the leading void *__data) point at
 * struct `sname`? Used to disambiguate same-arity prototypes (e.g. the 6.17
 * complete's 3rd arg is io_uring_cqe *) and to confirm req-first tracepoints. */
static int tp_param_is_struct_ptr(const struct btf *btf, const char *tp,
				  int idx, const char *sname)
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
	if (!btf_is_func_proto(t) || (int)btf_vlen(t) < idx + 2)
		return 0;
	p = btf_params(t) + 1 + idx;                /* skip void *__data, then idx */
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

/* One candidate program for a feature: the prototype it expects and the BPF
 * program that reads that prototype. First matching variant wins. */
struct tp_variant {
	struct bpf_program *prog;
	const char *tp;          /* tracepoint name this variant attaches to   */
	int min_params;
	int max_params;
	int struct_param;        /* TP_PROTO arg index to type-check, or -1     */
	const char *struct_name; /* required struct for that arg, or NULL       */
	const char *label;       /* shown in the support-tier summary           */
};

/* A capability backed by one-or-more variants. If none match: attach the
 * fail-soft (if any) for coarse data, else disable; `required` makes an
 * unmatched feature fatal (only submission is required). */
struct tp_feature {
	const char *name;
	const struct tp_variant *variants;
	int nvariants;
	struct bpf_program *failsoft;  /* positional-arg-free, or NULL          */
	const char *failsoft_tp;       /* tracepoint the fail-soft attaches to   */
	const char *failsoft_label;
	int required;
};

enum feat_state { FEAT_ACTIVE, FEAT_DEGRADED, FEAT_OFF };

struct feat_status {
	const char *name;
	const char *detail;
	enum feat_state state;
	int observed;            /* observed param count of the primary tp     */
};

/* Pick the variant whose expected prototype matches this kernel, autoloading
 * it and disabling the rest. Returns -1 only if the feature is required and
 * nothing (variant or fail-soft) could be selected. */
static int select_feature(const struct btf *btf, const struct tp_feature *f,
			  struct feat_status *st)
{
	const struct tp_variant *chosen = NULL;
	int i, n, primary_n = -1;

	/* Disable every candidate first; we enable exactly one below. */
	for (i = 0; i < f->nvariants; i++)
		bpf_program__set_autoload(f->variants[i].prog, false);
	if (f->failsoft)
		bpf_program__set_autoload(f->failsoft, false);

	for (i = 0; i < f->nvariants; i++) {
		const struct tp_variant *v = &f->variants[i];

		n = tp_nr_params(btf, v->tp);
		if (i == 0)
			primary_n = n;
		if (n < 0 || n < v->min_params || n > v->max_params)
			continue;
		if (v->struct_name &&
		    !tp_param_is_struct_ptr(btf, v->tp, v->struct_param,
					    v->struct_name))
			continue;
		chosen = v;
		break;
	}

	st->name = f->name;
	st->observed = primary_n;
	if (chosen) {
		bpf_program__set_autoload(chosen->prog, true);
		st->state = FEAT_ACTIVE;
		st->detail = chosen->label;
		return 0;
	}
	if (f->failsoft && tp_nr_params(btf, f->failsoft_tp) >= 0) {
		bpf_program__set_autoload(f->failsoft, true);
		st->state = FEAT_DEGRADED;
		st->detail = f->failsoft_label;
		return 0;
	}
	st->state = FEAT_OFF;
	st->detail = (primary_n < 0) ? "tracepoint absent on this kernel"
				     : "prototype unrecognized";
	return f->required ? -1 : 0;
}

/* Map a forced-variant key to its program, or NULL. */
static struct bpf_program *complete_forced_prog(struct uringscope_bpf *skel,
						const char *key,
						const char **label)
{
	if (!strcmp(key, "cqe"))    { *label = "(forced) v6.17 cqe (3-arg)"; return skel->progs.us_complete_cqe; }
	if (!strcmp(key, "modern")) { *label = "(forced) modern (5-arg)";    return skel->progs.us_complete; }
	if (!strcmp(key, "legacy")) { *label = "(forced) legacy (4-arg)";    return skel->progs.us_complete_legacy; }
	if (!strcmp(key, "count"))  { *label = "(forced) fail-soft counter"; return skel->progs.us_complete_count; }
	return NULL;
}

static void print_tier(const struct feat_status *st, int n)
{
	struct utsname uts;

	if (uname(&uts))
		strcpy(uts.release, "?");
	fprintf(stderr, "uringscope: io_uring tracepoint support (kernel %s):\n",
		uts.release);
	for (int i = 0; i < n; i++) {
		const char *tag = st[i].state == FEAT_ACTIVE   ? "active  "
				: st[i].state == FEAT_DEGRADED ? "DEGRADED"
				:                                "off     ";
		if (st[i].state == FEAT_DEGRADED)
			fprintf(stderr,
				"  %-16s %s  %s (observed params=%d matched no "
				"variant; coarse count only)\n",
				st[i].name, tag, st[i].detail, st[i].observed);
		else
			fprintf(stderr, "  %-16s %s  %s\n",
				st[i].name, tag, st[i].detail);
	}
}

int probe_setup(struct uringscope_bpf *skel, int verbose)
{
	struct btf *btf;
	struct feat_status st[16];
	int nst = 0, fatal = 0;

	btf = btf__load_vmlinux_btf();
	if (!btf) {
		fprintf(stderr, "uringscope: cannot load vmlinux BTF "
			"(/sys/kernel/btf/vmlinux missing?)\n");
		return -1;
	}

	/* ---- the prototype->program map: one row per known variant -------- *
	 * Order within a feature is match priority (first match wins).        */
	const struct tp_variant submit_v[] = {
		{ skel->progs.us_submit_req, "io_uring_submit_req",
		  1, ANY_PARAMS, -1, NULL, "modern submit_req" },
		{ skel->progs.us_submit_sqe_legacy, "io_uring_submit_sqe",
		  4, ANY_PARAMS, -1, NULL, "pre-6.0 submit_sqe (legacy)" },
	};
	const struct tp_variant complete_v[] = {
		{ skel->progs.us_complete_cqe, "io_uring_complete",
		  3, 3, 2, "io_uring_cqe", "v6.17 cqe-collapsed (3-arg)" },
		{ skel->progs.us_complete_legacy, "io_uring_complete",
		  4, 4, -1, NULL, "pre-5.19 legacy (4-arg)" },
		{ skel->progs.us_complete, "io_uring_complete",
		  5, 7, -1, NULL, "modern (5-arg)" },
	};
	const struct tp_variant queue_v[] = {
		{ skel->progs.us_queue_async_work, "io_uring_queue_async_work",
		  1, ANY_PARAMS, 0, "io_kiocb", "queue_async_work" },
	};
	const struct tp_variant poll_v[] = {
		{ skel->progs.us_poll_arm, "io_uring_poll_arm",
		  1, ANY_PARAMS, 0, "io_kiocb", "poll_arm" },
	};
	const struct tp_variant create_v[] = {
		{ skel->progs.us_create, "io_uring_create",
		  1, ANY_PARAMS, -1, NULL, "create" },
	};
	const struct tp_variant overflow_v[] = {
		{ skel->progs.us_cqe_overflow, "io_uring_cqe_overflow",
		  1, ANY_PARAMS, -1, NULL, "cqe_overflow" },
	};
	const struct tp_variant taskwork_v[] = {
		{ skel->progs.us_task_work_run, "io_uring_task_work_run",
		  1, ANY_PARAMS, -1, NULL, "task_work_run" },
	};
	const struct tp_variant localtw_v[] = {
		{ skel->progs.us_local_work_run, "io_uring_local_work_run",
		  1, ANY_PARAMS, -1, NULL, "local_work_run" },
	};
	const struct tp_variant shortwr_v[] = {
		{ skel->progs.us_short_write, "io_uring_short_write",
		  1, ANY_PARAMS, -1, NULL, "short_write" },
	};

	const struct tp_feature feats[] = {
		{ "submission", submit_v, 2, NULL, NULL, NULL, 1 },
		{ "completion", complete_v, 3,
		  skel->progs.us_complete_count, "io_uring_complete",
		  "fail-soft counter-only", 0 },
		{ "punt-to-iowq", queue_v, 1, NULL, NULL, NULL, 0 },
		{ "poll-retry", poll_v, 1, NULL, NULL, NULL, 0 },
		{ "ring-create", create_v, 1, NULL, NULL, NULL, 0 },
		{ "cqe-overflow", overflow_v, 1, NULL, NULL, NULL, 0 },
		{ "task-work", taskwork_v, 1, NULL, NULL, NULL, 0 },
		{ "local-task-work", localtw_v, 1, NULL, NULL, NULL, 0 },
		{ "short-write", shortwr_v, 1, NULL, NULL, NULL, 0 },
	};

	/* Testing/debug override for io_uring_complete selection:
	 *   URINGSCOPE_FORCE_COMPLETE = cqe|modern|legacy|count  force a variant
	 *                             = unknown   simulate a prototype no variant
	 *                                         matches (exercises the fail-soft
	 *                                         / degraded path on any kernel)
	 * Lets you reach the 6.17 cqe program and the degradation path without
	 * booting the kernel that would naturally select them. */
	const char *fc = getenv("URINGSCOPE_FORCE_COMPLETE");

	for (unsigned i = 0; i < sizeof(feats) / sizeof(feats[0]); i++) {
		const struct tp_feature *f = &feats[i];

		if (fc && f->variants == complete_v) {
			const char *label = NULL;
			struct bpf_program *forced = complete_forced_prog(skel,
								fc, &label);
			int cn = tp_nr_params(btf, "io_uring_complete");

			for (int v = 0; v < f->nvariants; v++)
				bpf_program__set_autoload(f->variants[v].prog, false);
			bpf_program__set_autoload(f->failsoft, false);

			if (forced) {                       /* pin a variant */
				bpf_program__set_autoload(forced, true);
				st[nst] = (struct feat_status){ f->name, label,
					FEAT_ACTIVE, cn };
			} else if (cn >= 0) {               /* simulate unknown */
				bpf_program__set_autoload(f->failsoft, true);
				st[nst] = (struct feat_status){ f->name,
					f->failsoft_label, FEAT_DEGRADED, cn };
			} else {
				st[nst] = (struct feat_status){ f->name,
					"prototype unrecognized", FEAT_OFF, cn };
			}
		} else if (select_feature(btf, f, &st[nst]) < 0) {
			fatal = 1;
		}
		nst++;
	}

	print_tier(st, nst);

	if (fatal) {
		fprintf(stderr, "uringscope: no usable io_uring submission "
			"tracepoint -- kernel too old (< 5.15) or io_uring "
			"disabled. Cannot proceed.\n");
		btf__free(btf);
		return -2;
	}

	/* Heads-up when running the best-effort legacy submission path. */
	if (bpf_program__autoload(skel->progs.us_submit_sqe_legacy))
		fprintf(stderr, "uringscope: pre-6.0 kernel -- legacy mode "
			"(no punt/poll detection, user_data-keyed "
			"attribution)\n");

	(void)verbose;
	btf__free(btf);
	return 0;
}
