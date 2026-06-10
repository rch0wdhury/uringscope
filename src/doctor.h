/* SPDX-License-Identifier: MIT */
#ifndef US_DOCTOR_H
#define US_DOCTOR_H
#include "uringscope.h"
void doctor_run(const __u64 *c, const struct opstat *ops,
		const struct ring_info *rings, int nrings,
		__u64 wall_ns, int ncpu);
#endif
