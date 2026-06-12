/* SPDX-License-Identifier: MIT */
#ifndef US_JSONOUT_H
#define US_JSONOUT_H
#include <stdio.h>
#include "uringscope.h"
#include "doctor.h"

/* Everything one report needs, collected from the maps in a single pass so
 * the human printer, the JSON writer, the metrics endpoint and the doctor
 * all see the same numbers. */
struct us_report {
	__u64 c[C_MAX];
	struct opstat ops[MAX_OPS];
	struct ring_info rings[MAX_RINGS];
	int nrings;
	int coarse_complete;   /* fail-soft completion counter active: no
	                          per-op latency, leak scan suppressed     */
	struct leak_report lr;
	struct hazard_report hr;
	struct e2e_report er;
	__u64 wall_ns;
};

/* Write the full report as one JSON object. path NULL or "-" = stdout.
 * Doctor findings are read back via doctor_nfindings()/doctor_finding(),
 * so doctor_run() must have run first (quiet or not). */
int json_write_report(const char *path, const struct us_report *r);

/* --diff support: the slice of a baseline JSON report we compare against. */
struct baseline_op {
	char name[24];
	__u64 submitted, completed, punted, errors;
	__u64 p50_ns, p99_ns, avg_ns;
};
struct baseline {
	__u64 wall_ns;
	__u64 submissions, completions, punted;
	int nops;
	struct baseline_op ops[MAX_OPS];
};
int baseline_load(const char *path, struct baseline *b);
void diff_print(const struct baseline *b, const struct us_report *r);

#endif
