/* SPDX-License-Identifier: MIT */
#ifndef US_PROBE_H
#define US_PROBE_H
#include <stdio.h>
struct uringscope_bpf;
int probe_setup(struct uringscope_bpf *skel, int verbose);
/* Where the support-tier table goes: stderr by default (keeps the report
 * stream clean); --version points it at stdout. */
void probe_set_tier_stream(FILE *f);
#endif
