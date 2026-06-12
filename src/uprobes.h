/* SPDX-License-Identifier: MIT */
#ifndef US_UPROBES_H
#define US_UPROBES_H
#include <sys/types.h>
#include "doctor.h"
struct uringscope_bpf;

/* Best-effort liburing uprobes for the end-to-end boundary (see
 * docs/end-to-end.md). Failure at any step logs one line and leaves the
 * kernel-side tool fully functional.
 *
 * uprobes_prepare: locate the target's dynamic liburing BEFORE the BPF
 * skeleton loads (so cfg_e2e can be baked into rodata). maps_pid > 0 scans
 * that process's /proc maps (authoritative for -p); maps_pid == 0 resolves
 * the system liburing via ldconfig (spawned-command and -a paths, where
 * the target hasn't mapped anything yet). Returns 1 if a path was found. */
int uprobes_prepare(pid_t maps_pid);
/* Attach after skeleton load+attach. filter_pid > 0 restricts the perf
 * uprobes to that process; -1 traces every user of the located liburing
 * (the BPF side still tgid-filters the data). */
int uprobes_attach(struct uringscope_bpf *skel, pid_t filter_pid,
		   int verbose);
void uprobes_collect(struct uringscope_bpf *skel, struct e2e_report *er);
void uprobes_detach(void);

#endif
