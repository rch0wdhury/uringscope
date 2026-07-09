/* SPDX-License-Identifier: MIT */
/*
 * jsonout.c - machine-readable output: --json report writer, plus the
 * --baseline/--diff reader for comparing two runs.
 *
 * The reader is NOT a general JSON parser: it understands exactly the
 * format json_write_report() emits (flat keys, one ops[] array), which is
 * all --diff ever feeds it. Hand-written so the tool keeps zero deps.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "jsonout.h"
#include "opnames.h"

/* Counter names, indexed by enum gcounter. Keep in sync with uringscope.h. */
static const char *counter_names[C_MAX] = {
	[C_ENTER]            = "enter_calls",
	[C_TOSUBMIT]         = "to_submit_sum",
	[C_RET_SUBMITTED]    = "ret_submitted_sum",
	[C_SUBMIT]           = "submissions",
	[C_COMPLETE]         = "completions",
	[C_PUNT]             = "punted",
	[C_OVERFLOW]         = "cq_overflows",
	[C_POLL_ARM]         = "poll_armed",
	[C_TW_RUN]           = "task_work_runs",
	[C_TW_ITEMS]         = "task_work_items",
	[C_LOCAL_TW_RUN]     = "local_task_work_runs",
	[C_MULTISHOT]        = "multishot_cqes",
	[C_UNTRACKED]        = "untracked_completions",
	[C_INFLIGHT_DROP]    = "inflight_map_drops",
	[C_SHORT_WRITE]      = "short_writes",
	[C_SQPOLL_OFFCPU_NS] = "sqpoll_offcpu_ns",
	[C_SQPOLL_SWITCHES]  = "sqpoll_switches",
	[C_WORKERS_SEEN]     = "workers_distinct",
	[C_RINGS]            = "rings_created",
	[C_CQ_DEPTH_SAMPLES] = "cq_depth_samples",
	[C_CQ_DEPTH_SUM]     = "cq_depth_sum",
	[C_CQ_DEPTH_MAX]     = "cq_depth_max",
	[C_ERRORS]           = "errors",
	[C_HAZARD]           = "hazard_overlaps",
	[C_HAZARD_BUFREG]    = "hazard_bufreg",
	[C_HAZARD_UNMAP]     = "hazard_unmap",
	[C_RB_DROP]          = "trace_rb_drops",
};

static void json_escape(FILE *f, const char *s)
{
	for (; *s; s++) {
		switch (*s) {
		case '"':  fputs("\\\"", f); break;
		case '\\': fputs("\\\\", f); break;
		case '\n': fputs("\\n", f); break;
		case '\t': fputs("\\t", f); break;
		default:
			if ((unsigned char)*s < 0x20)
				fprintf(f, "\\u%04x", *s);
			else
				fputc(*s, f);
		}
	}
}

int json_write_report(const char *path, const struct us_report *r)
{
	FILE *f = stdout;
	int first;

	if (path && strcmp(path, "-")) {
		f = fopen(path, "w");
		if (!f) {
			fprintf(stderr, "uringscope: cannot write %s\n", path);
			return -1;
		}
	}

	fprintf(f, "{\n  \"tool\": \"uringscope\",\n");
	/* Schema contract (docs/json.md): additive changes only within a
	 * schema number; renames/removals bump it. Consumers should accept
	 * unknown keys. */
	fprintf(f, "  \"schema\": 1,\n");
	fprintf(f, "  \"tool_version\": \"%s\",\n", US_VERSION);
	fprintf(f, "  \"wall_ns\": %llu,\n", (unsigned long long)r->wall_ns);
	fprintf(f, "  \"completion_coarse\": %s,\n",
		r->coarse_complete ? "true" : "false");

	fprintf(f, "  \"counters\": {");
	for (int i = 0; i < C_MAX; i++)
		fprintf(f, "%s\n    \"%s\": %llu", i ? "," : "",
			counter_names[i] ? counter_names[i] : "unknown",
			(unsigned long long)r->c[i]);
	fprintf(f, "\n  },\n");

	fprintf(f, "  \"rings\": [");
	for (int i = 0; i < r->nrings; i++) {
		const struct ring_info *ri = &r->rings[i];
		fprintf(f, "%s\n    {\"fd\": %u, \"comm\": \"", i ? "," : "",
			ri->fd);
		json_escape(f, ri->comm);
		fprintf(f, "\", \"sq_entries\": %u, \"cq_entries\": %u, "
			"\"flags\": %u, \"sqpoll\": %s}",
			ri->sq_entries, ri->cq_entries, ri->flags,
			(ri->flags & US_SETUP_SQPOLL) ? "true" : "false");
	}
	fprintf(f, "\n  ],\n");

	fprintf(f, "  \"ops\": [");
	first = 1;
	for (int i = 0; i < MAX_OPS; i++) {
		const struct opstat *o = &r->ops[i];
		if (!o->submitted && !o->completed)
			continue;
		fprintf(f, "%s\n    {\"op\": \"%s\", \"opcode\": %d, "
			"\"submitted\": %llu, \"completed\": %llu, "
			"\"punted\": %llu, \"errors\": %llu, "
			"\"avg_ns\": %llu, \"p50_ns\": %llu, \"p99_ns\": %llu}",
			first ? "" : ",", op_name(i), i,
			(unsigned long long)o->submitted,
			(unsigned long long)o->completed,
			(unsigned long long)o->punted,
			(unsigned long long)o->errors,
			(unsigned long long)(o->completed ?
					     o->lat_sum_ns / o->completed : 0),
			(unsigned long long)us_hist_percentile(o->hist,
							NLAT_SLOTS, 0.50),
			(unsigned long long)us_hist_percentile(o->hist,
							NLAT_SLOTS, 0.99));
		first = 0;
	}
	fprintf(f, "\n  ],\n");

	fprintf(f, "  \"leak\": {\"suspected\": %llu, \"pending\": %llu, "
		"\"oldest_ns\": %llu},\n",
		(unsigned long long)r->lr.n,
		(unsigned long long)r->lr.pending,
		(unsigned long long)r->lr.oldest_ns);

	fprintf(f, "  \"hazards\": {\"overlap\": %llu, \"bufreg\": %llu, "
		"\"unmap\": %llu},\n",
		(unsigned long long)r->hr.n,
		(unsigned long long)r->hr.n_bufreg,
		(unsigned long long)r->hr.n_unmap);

	/* End-to-end boundary (liburing uprobes); kernel submit->complete
	 * latency lives in ops[] above, this adds the two userspace sides. */
	fprintf(f, "  \"end_to_end\": {\"available\": %s",
		r->er.available ? "true" : "false");
	if (r->er.available) {
		fprintf(f, ", \"submit_calls\": %llu, "
			"\"avg_sqes_per_submit\": %.2f, "
			"\"avg_inter_submit_ns\": %llu, "
			"\"reap_lag\": {\"n\": %llu, \"avg_ns\": %llu, "
			"\"p99_ns\": %llu}",
			(unsigned long long)r->er.submit_calls,
			r->er.submit_calls ?
				(double)r->er.submit_batch_sum /
					r->er.submit_calls : 0.0,
			(unsigned long long)(r->er.submit_calls > 1 ?
				r->er.submit_interval_sum_ns /
					(r->er.submit_calls - 1) : 0),
			(unsigned long long)r->er.reap_n,
			(unsigned long long)(r->er.reap_n ?
				r->er.reap_sum_ns / r->er.reap_n : 0),
			(unsigned long long)us_hist_percentile(r->er.reap_hist,
							NLAT_SLOTS, 0.99));
	}
	fprintf(f, "},\n");

	fprintf(f, "  \"doctor\": [");
	for (int i = 0; i < doctor_nfindings(); i++) {
		const struct doc_finding *d = doctor_finding(i);
		if (!d)
			break;
		fprintf(f, "%s\n    {\"tag\": \"%s\", \"severity\": \"%s\", "
			"\"message\": \"", i ? "," : "", d->tag, d->sev);
		json_escape(f, d->msg);
		fprintf(f, "\"");
		if (d->suggestion) {
			fprintf(f, ", \"suggestion\": \"");
			json_escape(f, d->suggestion);
			fprintf(f, "\"");
		}
		if (d->nkv) {
			fprintf(f, ", \"evidence\": {");
			for (int k = 0; k < d->nkv; k++) {
				const struct doc_kv *kv = &d->kv[k];

				fprintf(f, "%s\"%s\": ", k ? ", " : "",
					kv->key);
				switch (kv->type) {
				case DOC_EV_U64:
					fprintf(f, "%llu",
						(unsigned long long)kv->u);
					break;
				case DOC_EV_DBL:
					fprintf(f, "%.3f", kv->d);
					break;
				case DOC_EV_STR:
					fputc('"', f);
					json_escape(f, kv->s);
					fputc('"', f);
					break;
				}
			}
			fprintf(f, "}");
		}
		fprintf(f, "}");
	}
	fprintf(f, "\n  ]\n}\n");

	if (f != stdout)
		fclose(f);
	return 0;
}

/* ---------- --baseline / --diff ---------------------------------------- */

/* Pull `"key": <u64>` out of a JSON object chunk we emitted ourselves. */
static int chunk_u64(const char *chunk, const char *key, __u64 *out)
{
	char pat[48];
	const char *p;

	snprintf(pat, sizeof(pat), "\"%s\":", key);
	p = strstr(chunk, pat);
	if (!p)
		return -1;
	*out = strtoull(p + strlen(pat), NULL, 10);
	return 0;
}

int baseline_load(const char *path, struct baseline *b)
{
	FILE *f = fopen(path, "r");
	char *buf;
	long sz;
	const char *p, *end;

	memset(b, 0, sizeof(*b));
	if (!f) {
		fprintf(stderr, "uringscope: cannot read baseline %s\n", path);
		return -1;
	}
	fseek(f, 0, SEEK_END);
	sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (sz <= 0 || sz > 16 * 1024 * 1024) {
		fclose(f);
		return -1;
	}
	buf = malloc(sz + 1);
	if (!buf || fread(buf, 1, sz, f) != (size_t)sz) {
		free(buf);
		fclose(f);
		return -1;
	}
	buf[sz] = 0;
	fclose(f);

	if (!strstr(buf, "\"tool\": \"uringscope\"")) {
		fprintf(stderr, "uringscope: %s is not a uringscope JSON "
			"report\n", path);
		free(buf);
		return -1;
	}
	chunk_u64(buf, "wall_ns", &b->wall_ns);
	chunk_u64(buf, "submissions", &b->submissions);
	chunk_u64(buf, "completions", &b->completions);
	chunk_u64(buf, "punted", &b->punted);

	/* walk the ops[] array, one {...} object per opcode */
	p = strstr(buf, "\"ops\": [");
	end = p ? strstr(p, "]") : NULL;
	while (p && end && b->nops < MAX_OPS) {
		const char *obj = strchr(p, '{');
		const char *close;
		char chunk[512];
		size_t len;

		if (!obj || obj > end)
			break;
		close = strchr(obj, '}');
		if (!close || close > end)
			break;
		len = close - obj + 1;
		if (len >= sizeof(chunk))
			len = sizeof(chunk) - 1;
		memcpy(chunk, obj, len);
		chunk[len] = 0;

		struct baseline_op *bo = &b->ops[b->nops];
		const char *nm = strstr(chunk, "\"op\": \"");
		if (nm) {
			nm += 7;
			size_t i = 0;
			while (*nm && *nm != '"' && i < sizeof(bo->name) - 1)
				bo->name[i++] = *nm++;
			bo->name[i] = 0;
			chunk_u64(chunk, "submitted", &bo->submitted);
			chunk_u64(chunk, "completed", &bo->completed);
			chunk_u64(chunk, "punted", &bo->punted);
			chunk_u64(chunk, "errors", &bo->errors);
			chunk_u64(chunk, "avg_ns", &bo->avg_ns);
			chunk_u64(chunk, "p50_ns", &bo->p50_ns);
			chunk_u64(chunk, "p99_ns", &bo->p99_ns);
			b->nops++;
		}
		p = close + 1;
	}
	free(buf);
	return 0;
}

static const struct baseline_op *baseline_find(const struct baseline *b,
					       const char *name)
{
	for (int i = 0; i < b->nops; i++)
		if (!strcmp(b->ops[i].name, name))
			return &b->ops[i];
	return NULL;
}

static const char *fmt_ns_s(__u64 ns, char *buf, size_t len)
{
	if (ns < 1000)
		snprintf(buf, len, "%lluns", (unsigned long long)ns);
	else if (ns < 1000000)
		snprintf(buf, len, "%.1fus", ns / 1e3);
	else if (ns < 1000000000)
		snprintf(buf, len, "%.1fms", ns / 1e6);
	else
		snprintf(buf, len, "%.2fs", ns / 1e9);
	return buf;
}

static double pct_change(double base, double now)
{
	if (base == 0.0)
		return now == 0.0 ? 0.0 : 100.0;
	return 100.0 * (now - base) / base;
}

void diff_print(const struct baseline *b, const struct us_report *r)
{
	char b1[32], b2[32];
	double iops_b = b->wall_ns ? b->completions * 1e9 / b->wall_ns : 0;
	double iops_n = r->wall_ns ? r->c[C_COMPLETE] * 1e9 / r->wall_ns : 0;
	double punt_b = b->submissions ?
			100.0 * b->punted / b->submissions : 0;
	double punt_n = r->c[C_SUBMIT] ?
			100.0 * r->c[C_PUNT] / r->c[C_SUBMIT] : 0;

	printf("\n------------------------- diff vs baseline -------------------------\n");
	printf("%-22s %12s %12s %10s\n", "", "baseline", "now", "change");
	printf("%-22s %12.0f %12.0f %+9.1f%%\n", "IOPS (completions/s)",
	       iops_b, iops_n, pct_change(iops_b, iops_n));
	printf("%-22s %11.1f%% %11.1f%% %+9.1fpt\n", "punted to io-wq",
	       punt_b, punt_n, punt_n - punt_b);

	for (int i = 0; i < MAX_OPS; i++) {
		const struct opstat *o = &r->ops[i];
		const struct baseline_op *bo;
		char row[32];

		if (!o->submitted && !o->completed)
			continue;
		bo = baseline_find(b, op_name(i));
		if (!bo)
			continue;

		__u64 p50 = us_hist_percentile(o->hist, NLAT_SLOTS, 0.50);
		__u64 p99 = us_hist_percentile(o->hist, NLAT_SLOTS, 0.99);
		double op_pb = bo->submitted ?
				100.0 * bo->punted / bo->submitted : 0;
		double op_pn = o->submitted ?
				100.0 * o->punted / o->submitted : 0;

		snprintf(row, sizeof(row), "%s p50", op_name(i));
		printf("%-22s %12s %12s %+9.1f%%\n", row,
		       fmt_ns_s(bo->p50_ns, b1, sizeof(b1)),
		       fmt_ns_s(p50, b2, sizeof(b2)),
		       pct_change(bo->p50_ns, p50));
		snprintf(row, sizeof(row), "%s p99", op_name(i));
		printf("%-22s %12s %12s %+9.1f%%\n", row,
		       fmt_ns_s(bo->p99_ns, b1, sizeof(b1)),
		       fmt_ns_s(p99, b2, sizeof(b2)),
		       pct_change(bo->p99_ns, p99));
		snprintf(row, sizeof(row), "%s punt%%", op_name(i));
		printf("%-22s %11.1f%% %11.1f%% %+9.1fpt\n", row,
		       op_pb, op_pn, op_pn - op_pb);
	}

	/* the doctor's read on what moved, same conservative spirit as the
	 * live rules: comment only on changes big enough to mean something */
	if (punt_n - punt_b >= 5.0)
		printf("  [DIFF] punt rate rose %.1f -> %.1f%%: more requests "
		       "are taking the io-wq detour than in the baseline -- "
		       "this is usually where a p99 regression comes from.\n",
		       punt_b, punt_n);
	else if (punt_b - punt_n >= 5.0)
		printf("  [DIFF] punt rate fell %.1f -> %.1f%%: more requests "
		       "complete on the fast path than in the baseline.\n",
		       punt_b, punt_n);
	if (iops_b > 0 && pct_change(iops_b, iops_n) <= -10.0)
		printf("  [DIFF] IOPS dropped %.1f%% vs baseline.\n",
		       -pct_change(iops_b, iops_n));
	for (int i = 0; i < MAX_OPS; i++) {
		const struct opstat *o = &r->ops[i];
		const struct baseline_op *bo;

		if (o->completed < 50)
			continue;
		bo = baseline_find(b, op_name(i));
		if (!bo || bo->completed < 50 || !bo->p99_ns)
			continue;
		__u64 p99 = us_hist_percentile(o->hist, NLAT_SLOTS, 0.99);
		if (p99 >= 2 * bo->p99_ns)
			printf("  [DIFF] %s p99 regressed %s -> %s (%.1fx).\n",
			       op_name(i),
			       fmt_ns_s(bo->p99_ns, b1, sizeof(b1)),
			       fmt_ns_s(p99, b2, sizeof(b2)),
			       (double)p99 / bo->p99_ns);
	}
	printf("---------------------------------------------------------------------\n");
}
