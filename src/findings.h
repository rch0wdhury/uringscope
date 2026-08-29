/* SPDX-License-Identifier: MIT */
#ifndef US_FINDINGS_H
#define US_FINDINGS_H
#include "uringscope.h"

/* Result of scanning the in-flight map at report time: requests that were
 * submitted but never completed. Multishot requests are excluded (they
 * live forever by design); poll-armed ones are counted separately as
 * evidence ("the fd never became ready"). */
#define LEAK_SAMPLES 5
struct leak_report {
	__u64 n;                     /* aged past threshold: suspected leaks */
	__u64 n_polled;              /* of those, parked on poll-retry       */
	__u64 pending;               /* younger than threshold: in progress  */
	__u64 oldest_ns;             /* age of the oldest suspected leak     */
	__u64 thresh_ns;             /* the threshold used                   */
	__u64 per_op[MAX_OPS];
	__u64 sample_ud[LEAK_SAMPLES];
	__u8  sample_op[LEAK_SAMPLES];
	int   nsample;
};

/* --check mode: kernel-side buffer hazards, read at report time.
 * n/samples: hazard 2 (overlapping in-flight ranges).
 * n_bufreg/bufreg: hazard 3 (unregister/re-register with live refs).
 * n_unmap/unmap: hazard 1, unmap variant (munmap over a live target). */
struct hazard_report {
	__u64 n;
	__u64 n_bufreg;
	__u64 n_unmap;
	int   nsample;
	int   nbufreg;
	int   nunmap;
	struct hazard_sample samples[HAZARD_SAMPLES];
	struct bufreg_sample bufreg[HAZARD_SAMPLES];
	struct unmap_sample  unmap[HAZARD_SAMPLES];
};

/* End-to-end boundary aggregates from the best-effort liburing uprobes
 * (see docs/end-to-end.md). available==0 means uprobes never attached or
 * their data failed validation; the findings and report skip the section. */
struct e2e_report {
	int   available;
	__u64 submit_calls;          /* io_uring_submit() entries observed   */
	__u64 submit_interval_sum_ns;/* sum of gaps between consecutive calls*/
	__u64 submit_batch_sum;      /* SQEs pending in SQ, summed per call  */
	__u64 reap_n;                /* CQE-ready -> reap-entry samples      */
	__u64 reap_sum_ns;
	__u64 reap_hist[NLAT_SLOTS];
};

/* A structured copy of every finding printed, for --json.
 * `msg` stays the complete human text (the fault injection harness greps it);
 * `evidence` repeats the numbers machine-readably and `suggestion` carries
 * the action, so JSON consumers never parse prose. Schema: docs/json.md. */
#define US_MAX_FINDINGS 64
#define US_MAX_EVIDENCE 8

enum us_ev_type { US_EV_U64 = 0, US_EV_DBL, US_EV_STR };
struct us_kv {
	const char *key;             /* static string                        */
	enum us_ev_type type;
	__u64 u;                     /* US_EV_U64                           */
	double d;                    /* US_EV_DBL                           */
	const char *s;               /* US_EV_STR (static string)           */
};

struct us_finding {
	const char *tag;             /* e.g. "PUNT", "HAZARD-BUFREG"         */
	const char *sev;             /* CRIT | WARN | INFO                   */
	char msg[512];
	const char *suggestion;      /* static action text, or NULL          */
	struct us_kv kv[US_MAX_EVIDENCE];
	int nkv;
};
int findings_count(void);
const struct us_finding *findings_get(int i);
void findings_set_quiet(int q); /* collect findings without printing */

/* Worst severity across recorded findings, for --fail-on. TOOL
 * self-reports are excluded: degraded tool fidelity is not a workload
 * problem and must not fail a CI gate. */
enum us_sev { US_SEV_NONE = 0, US_SEV_INFO, US_SEV_WARN, US_SEV_CRIT };
int findings_worst_severity(void);

/* log2-histogram percentile (bucket upper bound). Lives in findings.c so the
 * offline tests (which link only findings.c) get it too; the report printer
 * and JSON writer share it. */
__u64 us_hist_percentile(const __u64 *hist, int n, double p);

void findings_run(const __u64 *c, const struct opstat *ops,
		const struct ring_info *rings, int nrings,
		const struct leak_report *lr,
		const struct hazard_report *hr,
		const struct e2e_report *er,
		__u64 wall_ns, int ncpu);
#endif
