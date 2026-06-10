/* SPDX-License-Identifier: MIT */
#ifndef US_PROBE_H
#define US_PROBE_H
struct uringscope_bpf;
int probe_setup(struct uringscope_bpf *skel, int verbose);
#endif
