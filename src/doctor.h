/* SPDX-License-Identifier: MIT */
#ifndef US_DOCTOR_H
#define US_DOCTOR_H
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

void doctor_run(const __u64 *c, const struct opstat *ops,
		const struct ring_info *rings, int nrings,
		const struct leak_report *lr,
		__u64 wall_ns, int ncpu);
#endif
