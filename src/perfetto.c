/* SPDX-License-Identifier: MIT */
/*
 * perfetto.c - stream per-request lifecycle events into Chrome Trace
 * Event JSON, loadable at https://ui.perfetto.dev (no custom GUI; we emit
 * a standard format and let Perfetto do the rendering).
 *
 * Layout: one "process" per traced tgid, one "thread" lane per opcode.
 * Each request is an async span (ph "b"/"e") keyed by its kernel identity,
 * so multishot and out-of-order completions pair up correctly. Punts to
 * io-wq show up as instant markers on the span's lane.
 */
#include <stdio.h>
#include <string.h>
#include "perfetto.h"
#include "opnames.h"

int perfetto_open(struct perfetto_writer *pw, const char *path)
{
	memset(pw, 0, sizeof(*pw));
	pw->f = fopen(path, "w");
	if (!pw->f) {
		perror("uringscope: trace file");
		return -1;
	}
	fputs("{\"traceEvents\":[\n", pw->f);
	pw->first = 1;
	return 0;
}

static void sep(struct perfetto_writer *pw)
{
	if (!pw->first)
		fputs(",\n", pw->f);
	pw->first = 0;
}

static void name_lane(struct perfetto_writer *pw, __u32 tgid, __u8 op)
{
	if (op < MAX_OPS && pw->lane_named[op])
		return;
	if (op < MAX_OPS)
		pw->lane_named[op] = 1;
	sep(pw);
	fprintf(pw->f,
		"{\"ph\":\"M\",\"name\":\"thread_name\",\"pid\":%u,"
		"\"tid\":%u,\"args\":{\"name\":\"%s\"}}",
		tgid, op, op_name(op));
}

int perfetto_handle_event(void *ctx, void *data, size_t len)
{
	struct perfetto_writer *pw = ctx;
	const struct us_event *e = data;
	double ts_us;

	if (len < sizeof(*e))
		return 0;
	ts_us = e->ts_ns / 1000.0;
	pw->n_events++;

	switch (e->type) {
	case EV_SUBMIT:
		name_lane(pw, e->tgid, e->opcode);
		sep(pw);
		fprintf(pw->f,
			"{\"ph\":\"b\",\"cat\":\"io_uring\",\"id\":\"0x%llx\","
			"\"name\":\"%s\",\"pid\":%u,\"tid\":%u,\"ts\":%.3f,"
			"\"args\":{\"user_data\":\"0x%llx\"}}",
			(unsigned long long)e->id, op_name(e->opcode),
			e->tgid, e->opcode, ts_us,
			(unsigned long long)e->user_data);
		break;
	case EV_PUNT:
		sep(pw);
		fprintf(pw->f,
			"{\"ph\":\"i\",\"cat\":\"io_uring\",\"s\":\"t\","
			"\"name\":\"punt->io-wq %s\",\"pid\":%u,\"tid\":%u,"
			"\"ts\":%.3f}",
			op_name(e->opcode), e->tgid, e->opcode, ts_us);
		break;
	case EV_COMPLETE:
		name_lane(pw, e->tgid, e->opcode);
		sep(pw);
		fprintf(pw->f,
			"{\"ph\":\"e\",\"cat\":\"io_uring\",\"id\":\"0x%llx\","
			"\"name\":\"%s\",\"pid\":%u,\"tid\":%u,\"ts\":%.3f,"
			"\"args\":{\"res\":%d,\"lat_ns\":%llu,\"punted\":%s,"
			"\"multishot\":%s}}",
			(unsigned long long)e->id, op_name(e->opcode),
			e->tgid, e->opcode, ts_us, e->res,
			(unsigned long long)e->lat_ns,
			(e->fl & IF_PUNTED) ? "true" : "false",
			(e->fl & IF_MULTISHOT) ? "true" : "false");
		break;
	case EV_OVERFLOW:
		sep(pw);
		fprintf(pw->f,
			"{\"ph\":\"i\",\"cat\":\"io_uring\",\"s\":\"g\","
			"\"name\":\"CQ OVERFLOW\",\"pid\":%u,\"tid\":0,"
			"\"ts\":%.3f}",
			e->tgid, ts_us);
		break;
	}
	return 0;
}

void perfetto_close(struct perfetto_writer *pw)
{
	if (!pw->f)
		return;
	fputs("\n]}\n", pw->f);
	fclose(pw->f);
	pw->f = NULL;
}
