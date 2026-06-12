/* SPDX-License-Identifier: MIT */
/*
 * uringscope - shared definitions between the BPF programs and userspace.
 * This header must be includable from both vmlinux.h-world (BPF) and libc-world.
 */
#ifndef URINGSCOPE_H
#define URINGSCOPE_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define NLAT_SLOTS    36   /* log2(ns) buckets: covers 1ns .. ~68s          */
#define NSUBMIT_SLOTS 16   /* log2 buckets for to_submit per io_uring_enter */
#define MAX_OPS       96   /* opcode table size (IORING_OP_* headroom)      */
#define MAX_RINGS     8    /* ring setups we record per traced process     */
#define MAX_REG_BUFS  1024 /* registered-buffer indexes refcounted per ring */
#define TASK_COMM_SZ  16

/* Global counters (single BPF array map, indexed by these). */
enum gcounter {
	C_ENTER = 0,          /* io_uring_enter() syscalls                     */
	C_TOSUBMIT,           /* sum of to_submit across enters                */
	C_RET_SUBMITTED,      /* sum of successful enter() return values       */
	C_SUBMIT,             /* SQEs seen at io_uring_submit_req              */
	C_COMPLETE,           /* CQEs seen at io_uring_complete                */
	C_PUNT,               /* requests punted to io-wq async workers        */
	C_OVERFLOW,           /* io_uring_cqe_overflow events                  */
	C_POLL_ARM,           /* requests parked on the poll-retry path        */
	C_TW_RUN,             /* io_uring_task_work_run invocations            */
	C_TW_ITEMS,           /* total task-work items processed               */
	C_LOCAL_TW_RUN,       /* io_uring_local_work_run (DEFER_TASKRUN)       */
	C_MULTISHOT,          /* completions with IORING_CQE_F_MORE            */
	C_UNTRACKED,          /* completions with no matching submit record    */
	C_INFLIGHT_DROP,      /* submits dropped because inflight map was full */
	C_SHORT_WRITE,        /* io_uring_short_write events                   */
	C_SQPOLL_OFFCPU_NS,   /* total ns the iou-sqp thread spent off-CPU     */
	C_SQPOLL_SWITCHES,    /* sched switches involving the sqpoll thread    */
	C_WORKERS_SEEN,       /* distinct iou-wrk worker threads observed      */
	C_RINGS,              /* rings created while tracing                   */
	C_CQ_DEPTH_SAMPLES,   /* number of CQ depth samples taken              */
	C_CQ_DEPTH_SUM,       /* sum of sampled CQ depth (tail - head)         */
	C_CQ_DEPTH_MAX,       /* max sampled CQ depth                          */
	C_ERRORS,             /* completions with res < 0 (excl. -EAGAIN)      */
	C_HAZARD,             /* --check: overlapping in-flight ranges seen    */
	C_HAZARD_BUFREG,      /* --check: unregister/re-register w/ live refs  */
	C_HAZARD_UNMAP,       /* --check: munmap overlapping an in-flight tgt  */
	C_MAX,
};

/* Per-opcode statistics (BPF array map, indexed by opcode). */
struct opstat {
	__u64 submitted;
	__u64 completed;
	__u64 punted;
	__u64 errors;              /* res < 0 */
	__u64 lat_sum_ns;          /* submit -> complete */
	__u64 punt_lat_sum_ns;     /* punt   -> complete (io-wq queue + exec) */
	__u64 hist[NLAT_SLOTS];    /* submit -> complete latency, log2(ns)    */
};

/* --check mode: kind of buffer target a request points at, captured at
 * submit so concurrently in-flight requests can be tested for overlap. */
enum tgt_kind {
	TGT_NONE = 0,              /* opcode has no addr/len buffer target     */
	TGT_ADDR,                  /* plain read/write: (addr, len) in tgid AS */
	TGT_BUFIDX,                /* *_fixed: (buf_index, addr, len)          */
};

/* In-flight request record, keyed by request identity (see bpf code). */
struct inflight {
	__u64 ts_submit;
	__u64 ts_punt;             /* 0 if never punted */
	__u64 user_data;
	__u64 tgt_addr;            /* --check: target buffer addr (or in-buffer
	                              addr for BUFIDX); 0 when TGT_NONE         */
	__u32 tgid;
	__u32 tgt_len;             /* --check: target range length in bytes    */
	__u16 tgt_bufidx;          /* --check: registered buffer index (BUFIDX)*/
	__u8  opcode;
	__u8  fl;
	__u8  tgt_kind;            /* --check: enum tgt_kind                   */
};
#define IF_PUNTED    (1 << 0)
#define IF_MULTISHOT (1 << 1)
#define IF_POLLED    (1 << 2)

/* --check mode: first few overlapping-in-flight hazards, captured in the
 * haz_samples map so the doctor can echo the offending user_data tokens.
 * '_a' is the request already in flight; '_b' is the new submit that
 * overlapped it. */
#define HAZARD_SAMPLES 8
struct hazard_sample {
	__u64 user_data_a;
	__u64 user_data_b;
	__u64 base;                /* overlap range start                     */
	__u32 len;                 /* overlap range length                    */
	__u16 bufidx;              /* registered buffer index (BUFIDX kind)   */
	__u8  kind;                /* enum tgt_kind                           */
	__u8  opcode_a;
	__u8  opcode_b;
	__u8  pad[3];
};

/* --check hazard 3: per-ring refcount of in-flight *_FIXED requests by
 * registered-buffer index. Shared so userspace can scan a snapshot of it
 * (the kernel hook only branchlessly copies it -- finding which indexes are
 * live is done in userspace, where there is no verifier instruction budget
 * to blow; see the 6.17 complexity trap noted at us_uring_register). */
struct buf_refcounts {
	__u64 live;                /* sum of refs[]: O(1) "any live?" check  */
	__u64 refs[MAX_REG_BUFS];
};

/* A registered-buffer index that was unregistered (or re-registered over)
 * while in-flight *_FIXED requests still referenced it. */
struct bufreg_sample {
	__u32 bufidx;
	__u32 refs;                /* in-flight references at unregister time */
};

/* --check hazard 1, unmap variant: an munmap() range that overlapped the
 * buffer target of a request that was still in flight. */
struct unmap_sample {
	__u64 user_data;
	__u64 base;                /* overlap range start                     */
	__u32 len;                 /* overlap range length                    */
	__u8  opcode;
	__u8  pad[3];
};

/* End-to-end boundary aggregates (liburing uprobes; see docs/end-to-end.md).
 * One global BPF array entry: Tier 1 reports per-process aggregates, not
 * per-request correlation. */
struct e2e_stats {
	__u64 submit_calls;          /* io_uring_submit*() entries           */
	__u64 submit_last_ns;
	__u64 submit_interval_sum_ns;
	__u64 submit_batch_sum;      /* SQEs pending in the SQ per call      */
	__u64 reap_n;                /* CQE-ready -> reap-entry samples      */
	__u64 reap_sum_ns;
	__u64 reap_hist[NLAT_SLOTS];
};

/* Per-ring CQE-position -> completion-timestamp window for reap-lag
 * matching. Positions are the free-running CQ tail/head counters, masked.
 * An app lagging more than POS_TS_SLOTS CQEs behind sees underestimated
 * lag (old stamps overwritten) -- documented bound. */
#define POS_TS_SLOTS 4096        /* power of two */
struct pos_ts {
	__u64 ts[POS_TS_SLOTS];
	__u64 last_pos;              /* last head position measured (dedup) */
	__u32 init;
	__u32 pad;
};

/* Ring configuration captured at io_uring_create. */
struct ring_info {
	__u64 ctx;                 /* kernel io_ring_ctx pointer (opaque id) */
	__u32 fd;
	__u32 sq_entries;
	__u32 cq_entries;
	__u32 flags;               /* IORING_SETUP_* */
	__u32 tgid;
	char  comm[TASK_COMM_SZ];
};

/* Per-event records streamed over the ring buffer in --trace mode. */
enum ev_type {
	EV_SUBMIT = 1,
	EV_PUNT,
	EV_COMPLETE,
	EV_OVERFLOW,
};

struct us_event {
	__u64 ts_ns;               /* bpf_ktime_get_ns at the event           */
	__u64 id;                  /* request identity key                    */
	__u64 user_data;
	__s32 res;                 /* EV_COMPLETE only                        */
	__u32 tgid;
	__u64 lat_ns;              /* EV_COMPLETE: submit->complete           */
	__u8  type;                /* enum ev_type                            */
	__u8  opcode;
	__u8  fl;                  /* IF_* flags                              */
	__u8  pad;
};

/* IORING_SETUP_* flags we interpret in userspace (kept in sync w/ uapi). */
#define US_SETUP_IOPOLL        (1U << 0)
#define US_SETUP_SQPOLL        (1U << 1)
#define US_SETUP_COOP_TASKRUN  (1U << 8)
#define US_SETUP_TASKRUN_FLAG  (1U << 9)
#define US_SETUP_SINGLE_ISSUER (1U << 12)
#define US_SETUP_DEFER_TASKRUN (1U << 13)

/* IORING_CQE_F_MORE from uapi: further completions will follow (multishot) */
#define US_CQE_F_MORE          (1U << 1)

#endif /* URINGSCOPE_H */
