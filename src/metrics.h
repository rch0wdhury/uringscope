/* SPDX-License-Identifier: MIT */
#ifndef US_METRICS_H
#define US_METRICS_H
#include "jsonout.h"

/* --metrics [HOST:]PORT: serve OpenMetrics text at /metrics from a
 * background thread. The thread never touches BPF maps; the main loop
 * pushes snapshots via metrics_update() on its refresh tick. */
int metrics_start(const char *spec);
void metrics_update(const struct us_report *r);
void metrics_stop(void);

#endif
