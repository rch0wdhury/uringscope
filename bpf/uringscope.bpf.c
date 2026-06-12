/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * uringscope.bpf.c - in-kernel side of uringscope.
 *
 * Attach strategy
 * ---------------
 * We hook the kernel's static io_uring tracepoints via tp_btf (typed raw
 * tracepoints). Tracepoint *prototypes* have churned across kernel
 * releases, so:
 *
 *   1. We read request state from the io_kiocb pointer wherever possible
 *      (CO-RE relocated, see io_uring_shims.bpf.h) instead of trusting
 *      positional args.
 *   2. For renamed/resignatured tracepoints we ship multiple program
 *      variants; userspace probes the running kernel's BTF and flips
 *      autoload per variant before load (src/probe.c).
 *
 * Two output modes:
 *   - aggregate (default): everything is folded into per-opcode latency
 *     histograms + global counters inside the kernel; userspace reads the
 *     maps once at exit. This is the low-overhead production mode.
 *   - trace (--trace): per-request lifecycle events are streamed over a
 *     ring buffer for timeline (Perfetto) reconstruction. Higher overhead.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "io_uring_shims.bpf.h"
#include "../src/uringscope.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* ---------------- configuration (set by userspace before load) -------- */

const volatile __u32 cfg_tgid = 0;        /* 0 = system-wide               */
const volatile __u8  cfg_trace_mode = 0;  /* 1 = stream per-event records  */
const volatile __u8  cfg_check_mode = 0;  /* 1 = hazard (--check) mode     */
const volatile __u8  cfg_follow = 0;      /* 1 = -f: also match descendant
					     tgids of cfg_tgid (and accept
					     any registered ring's events
					     by ownership)                  */
const volatile __u32 cfg_pidns_ino = 0;   /* nonzero: userspace runs in a
					     child pid namespace (WSL2
					     distro, container) with this
					     nsfs inode; translate tgids   */
const volatile __u8  cfg_e2e = 0;         /* 1 = liburing located; stamp CQE
					     positions for reap-lag        */

/* liburing struct io_uring field offsets (the liburing.so.2 ABI; verified
 * against liburing 2.x headers -- the struct is allocated by applications,
 * so the project keeps it ABI-stable within .so.2). These are USERSPACE
 * offsets read with bpf_probe_read_user; there is no BTF/CO-RE for
 * userspace, which is exactly the uprobe-vs-CO-RE portability asymmetry
 * documented in docs/end-to-end.md. Self-validating: ur_* programs match
 * the ring_fd they read against the rings table and record nothing on
 * mismatch -- wrong offsets mean missing data, never wrong data. */
const volatile __u32 cfg_ur_sq_khead_off = 0;    /* struct io_uring.sq.khead (ptr) */
const volatile __u32 cfg_ur_sqe_tail_off = 68;   /* .sq.sqe_tail (u32)             */
const volatile __u32 cfg_ur_cq_khead_off = 104;  /* .cq.khead (ptr)                */
const volatile __u32 cfg_ur_cq_ktail_off = 112;  /* .cq.ktail (ptr)                */
const volatile __u32 cfg_ur_ring_fd_off  = 196;  /* .ring_fd (int)                 */

/* ---------------- maps ------------------------------------------------ */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 262144);
	__type(key, __u64);                 /* request identity              */
	__type(value, struct inflight);
} inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, C_MAX);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_OPS);
	__type(key, __u32);
	__type(value, struct opstat);
} opstats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NSUBMIT_SLOTS);
	__type(key, __u32);
	__type(value, __u64);
} tosubmit_hist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_RINGS);
	__type(key, __u32);
	__type(value, struct ring_info);
} rings SEC(".maps");

/* ctx pointer -> owning tgid; lets us attribute SQPOLL-driven submits
 * (which execute on the iou-sqp kernel thread) back to the application. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u32);
} ctx_owner SEC(".maps");

/* sqpoll thread pid -> timestamp it last went off-CPU */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u64);
} sqpoll_offcpu SEC(".maps");

/* distinct io-wq worker pids observed */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u8);
} workers SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22); /* 4 MiB */
} events SEC(".maps");

/* ---------------- hazard (--check) mode state ------------------------- */
/*
 * Per-ring window of the last HAZ_K in-flight buffer targets. On each submit
 * we scan this window (bounded, #pragma unroll -- a hash map can't be
 * unroll-iterated and the verifier rejects unbounded loops) for a target
 * range that overlaps the new request: two live requests on the same memory
 * is silent data corruption. The authoritative per-request descriptor lives
 * in struct inflight; this window is the scannable interval set. Misses
 * overlaps older than HAZ_K in flight -- acceptable, the LEAK rule covers
 * the very-old ones (see docs/buffer-hazards.md, "Verifier reality check").
 */
#define HAZ_K 64                   /* must stay a power of two (masked) */

struct haz_slot {
	__u64 key;                 /* io_kiocb identity; 0 = empty slot  */
	__u64 user_data;
	__u64 addr;
	__u32 len;
	__u16 bufidx;
	__u8  kind;                /* enum tgt_kind                      */
	__u8  opcode;
};

struct haz_window {
	struct haz_slot slot[HAZ_K];
	__u32 head;                /* next circular insert position      */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RINGS);
	__type(key, __u64);                 /* io_ring_ctx pointer       */
	__type(value, struct haz_window);
} haz_windows SEC(".maps");

/* Zeroed template used to initialise a new per-ring window without putting
 * the (large) struct on the BPF stack. Never written, so it stays zero. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct haz_window);
} haz_zero SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, HAZARD_SAMPLES);
	__type(key, __u32);
	__type(value, struct hazard_sample);
} haz_samples SEC(".maps");

/* ---------------- hazard 3: registered-buffer lifetime ----------------- */
/*
 * Per-ring refcount of in-flight *_FIXED requests per registered-buffer
 * index: ++ at submit, -- at completion. The sys_enter_io_uring_register
 * hook reads it at the moment the app *requests* (un|re)registration.
 *
 * Why sys_enter and not the native io_uring_register tracepoint: that
 * tracepoint fires when the syscall *returns*, and on the rsrc-quiesce
 * kernels (~5.13..6.12) unregister_buffers blocks until every in-flight
 * reference drains -- by which time these refcounts are zero again and
 * the hazard is unobservable. The syscall entry is also the semantically
 * right instant: the bug is the app unregistering while ops are live.
 */
/* struct buf_refcounts lives in uringscope.h (shared with userspace).
 * __u64 per index: BPF's only portable atomic is the 64-bit XADD (a 32-bit
 * __sync_fetch_and_sub fails instruction selection), and 8K per ring is
 * nothing for a --check-only map. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);                 /* io_ring_ctx pointer       */
	__type(value, struct buf_refcounts);
} buf_refs SEC(".maps");

/* Snapshot of a ring's refcounts taken at a *violating* (un)register -- by
 * report time the in-flight reads have completed and decremented the live
 * counts back down, so the live indexes must be captured at the event.
 * The kernel hook only branchlessly *copies* the array here; userspace
 * scans it for the nonzero indexes (no instruction budget there). Present
 * == a violation happened on that ctx. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);                 /* io_ring_ctx pointer       */
	__type(value, struct buf_refcounts);
} bufreg_snap SEC(".maps");

/* Zero template, same trick as haz_zero: 8K won't fit on the BPF stack. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct buf_refcounts);
} bufref_zero SEC(".maps");

/* hazard 1 (unmap variant) samples */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, HAZARD_SAMPLES);
	__type(key, __u32);
	__type(value, struct unmap_sample);
} haz_unmap_samples SEC(".maps");

/* ---------------- end-to-end boundary (liburing uprobes) --------------- */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct e2e_stats);
} e2e_stats SEC(".maps");

/* per-ring CQE position -> completion timestamp */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);                 /* io_ring_ctx pointer       */
	__type(value, struct pos_ts);
} cqe_pos_ts SEC(".maps");

/* zero template (32K: too big for the BPF stack AND for a percpu map's
 * per-element limit -- a plain array is fine, it is only ever read) */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct pos_ts);
} pos_ts_zero SEC(".maps");

/* ---------------- small helpers --------------------------------------- */

static __always_inline __u64 log2l(__u64 v)
{
	__u32 shift, r;
	__u32 hi = v >> 32;
	__u32 lo = (__u32)v;
	__u32 x = hi ? hi : lo;

	r = (hi != 0) << 5;
	shift = (x > 0xFFFF) << 4; x >>= shift; r |= shift;
	shift = (x > 0xFF)   << 3; x >>= shift; r |= shift;
	shift = (x > 0xF)    << 2; x >>= shift; r |= shift;
	shift = (x > 0x3)    << 1; x >>= shift; r |= shift;
	r |= (x >> 1);
	return r;
}

static __always_inline void cadd(__u32 idx, __u64 n)
{
	__u64 *v = bpf_map_lookup_elem(&counters, &idx);
	if (v)
		__sync_fetch_and_add(v, n);
}

static __always_inline void cmax(__u32 idx, __u64 n)
{
	__u64 *v = bpf_map_lookup_elem(&counters, &idx);
	if (v && n > *v)
		*v = n; /* racy max: acceptable for a gauge */
}

static __always_inline struct opstat *opstat_of(__u8 opcode)
{
	__u32 k = opcode < MAX_OPS ? opcode : MAX_OPS - 1;
	return bpf_map_lookup_elem(&opstats, &k);
}

static __always_inline bool tgid_wanted(__u32 tgid)
{
	return cfg_tgid == 0 || tgid == cfg_tgid;
}

/* Deepest pid-ns nesting we walk (kernel MAX_PID_NS_LEVEL is 32; real
 * deployments nest 2-3 levels). */
#define PIDNS_WALK_MAX 8

/* tgid of @t as seen from uringscope's own pid namespace.
 *
 * task->tgid and bpf_get_current_pid_tgid() report *root*-namespace ids.
 * When uringscope itself runs in a child pid namespace (every WSL2 distro
 * does, and so do containers), cfg_tgid is a namespaced id that no root
 * id will ever equal, so walk the task's upid stack and pick the id
 * belonging to our namespace. Returns 0 if @t is not visible in it. */
static __always_inline __u32 task_tgid_view(struct task_struct *t)
{
	struct upid up, *base;
	struct pid *p;
	__u32 lvl, i;

	if (!cfg_pidns_ino)
		return BPF_CORE_READ(t, tgid);

	p = BPF_CORE_READ(t, group_leader, thread_pid);
	if (!p)
		return 0;
	lvl = BPF_CORE_READ(p, level);
	base = &p->numbers[0];	/* CO-RE: offset on the running kernel */
	for (i = 0; i < PIDNS_WALK_MAX; i++) {
		if (i > lvl)
			break;
		/* struct upid layout (int nr; struct pid_namespace *ns)
		 * has been stable forever; a raw copy is safe. */
		if (bpf_probe_read_kernel(&up, sizeof(up), base + i) || !up.ns)
			break;
		if (BPF_CORE_READ(up.ns, ns.inum) == cfg_pidns_ino)
			return up.nr;
	}
	return 0;
}

static __always_inline __u32 cur_tgid(void)
{
	if (!cfg_pidns_ino)
		return bpf_get_current_pid_tgid() >> 32;
	return task_tgid_view((struct task_struct *)bpf_get_current_task());
}

/* -f: how many fork levels we walk looking for the target ancestor. */
#define FOLLOW_WALK_MAX 8

/* Is @t the target -- or, with -f, a descendant of it? The walk is over
 * real_parent so it follows fork ancestry, not session/pgrp. Bounded at
 * FOLLOW_WALK_MAX levels; a deeper process tree falls out of scope, which
 * is the documented -f tradeoff (alongside its per-event walk cost). */
static __always_inline bool task_wanted(struct task_struct *t)
{
	struct task_struct *p = t;

	if (cfg_tgid == 0)
		return true;
	if (task_tgid_view(t) == cfg_tgid)
		return true;
	if (!cfg_follow)
		return false;
	for (int i = 0; i < FOLLOW_WALK_MAX; i++) {
		p = BPF_CORE_READ(p, real_parent);
		if (!p)
			break;
		if (task_tgid_view(p) == cfg_tgid)
			return true;
	}
	return false;
}

static __always_inline bool wanted_cur(void)
{
	if (cfg_tgid == 0)
		return true;
	return task_wanted((struct task_struct *)bpf_get_current_task());
}

/* Identity for pre-5.19 kernels whose tracepoints don't expose the req
 * pointer at completion: hash of (ctx, user_data). Collides if the app
 * reuses user_data concurrently on one ring -- documented limitation. */
static __always_inline __u64 legacy_key(__u64 ctx, __u64 user_data)
{
	return (ctx ^ user_data) * 0x9E3779B97F4A7C15ULL;
}

static __always_inline void emit_event(__u8 type, __u64 id, __u64 user_data,
				       __u8 opcode, __u8 fl, __s32 res,
				       __u64 lat_ns, __u32 tgid)
{
	struct us_event *e;

	if (!cfg_trace_mode)
		return;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	e->ts_ns = bpf_ktime_get_ns();
	e->id = id;
	e->user_data = user_data;
	e->res = res;
	e->tgid = tgid;
	e->lat_ns = lat_ns;
	e->type = type;
	e->opcode = opcode;
	e->fl = fl;
	e->pad = 0;
	bpf_ringbuf_submit(e, 0);
}

/* ---------------- hazard (--check) helpers ---------------------------- */
/* IORING_OP_* values whose buffer target we capture for overlap testing. */
#define US_OP_READV       1
#define US_OP_WRITEV      2
#define US_OP_READ_FIXED  4
#define US_OP_WRITE_FIXED 5
#define US_OP_READ        22
#define US_OP_WRITE       23

/* Read a request's buffer target descriptor. Plain rw -> (addr, len);
 * *_fixed -> additionally the registered (buf_index). Other opcodes carry no
 * addr/len buffer target and are left TGT_NONE (never overlap-tested). */
static __always_inline void req_target(struct io_kiocb *req, __u8 opcode,
				       __u8 *kind, __u16 *bufidx,
				       __u64 *addr, __u32 *len)
{
	bool fixed = (opcode == US_OP_READ_FIXED || opcode == US_OP_WRITE_FIXED);
	bool plain = (opcode == US_OP_READ  || opcode == US_OP_WRITE ||
		      opcode == US_OP_READV || opcode == US_OP_WRITEV);
	struct io_rw *rw;

	*kind = TGT_NONE;
	*bufidx = 0;
	*addr = 0;
	*len = 0;
	if (!fixed && !plain)
		return;
	*kind = fixed ? TGT_BUFIDX : TGT_ADDR;
	if (fixed)
		*bufidx = BPF_CORE_READ(req, buf_index);
	rw = (struct io_rw *)req;            /* overlaid on the io_kiocb cmd area */
	*addr = BPF_CORE_READ(rw, addr);
	*len = BPF_CORE_READ(rw, len);
}

/* Per-ring window for this ctx, creating a zeroed one on first use. */
static __always_inline struct haz_window *haz_get(__u64 ctx_ptr, bool create)
{
	struct haz_window *w = bpf_map_lookup_elem(&haz_windows, &ctx_ptr);
	struct haz_window *tpl;
	__u32 z = 0;

	if (w || !create)
		return w;
	tpl = bpf_map_lookup_elem(&haz_zero, &z);
	if (!tpl)
		return NULL;
	bpf_map_update_elem(&haz_windows, &ctx_ptr, tpl, BPF_NOEXIST);
	return bpf_map_lookup_elem(&haz_windows, &ctx_ptr);
}

/* On submit: test the new target against the in-flight window for a range
 * overlap on the same ring, record a hazard if found, then add this request
 * to the window. Caller guarantees cfg_check_mode and kind != TGT_NONE. */
static __always_inline void hazard_on_submit(__u64 ctx_ptr, __u64 key,
		__u64 user_data, __u8 opcode, __u8 kind, __u16 bufidx,
		__u64 addr, __u32 len)
{
	struct haz_window *w = haz_get(ctx_ptr, true);
	__u64 ud_a = 0, base = 0;
	__u32 olen = 0, h;
	__u8  op_a = 0;
	int found = 0;

	if (!w)
		return;

	#pragma unroll
	for (int i = 0; i < HAZ_K; i++) {
		struct haz_slot *s = &w->slot[i];
		__u64 a0, a1, b0, b1, hi;

		if (!s->key || s->kind != kind)
			continue;
		if (kind == TGT_BUFIDX && s->bufidx != bufidx)
			continue;
		a0 = s->addr; a1 = s->addr + s->len;
		b0 = addr;    b1 = addr + len;
		if (a0 < b1 && b0 < a1) {              /* ranges overlap */
			found = 1;
			ud_a = s->user_data;
			op_a = s->opcode;
			base = a0 > b0 ? a0 : b0;
			hi   = a1 < b1 ? a1 : b1;
			olen = (__u32)(hi - base);
			break;
		}
	}

	if (found) {
		__u32 ck = C_HAZARD, si;
		__u64 *cv = bpf_map_lookup_elem(&counters, &ck);
		__u64 idx = cv ? __sync_fetch_and_add(cv, 1) : 0;

		if (idx < HAZARD_SAMPLES) {
			struct hazard_sample *hs;
			si = (__u32)idx;
			hs = bpf_map_lookup_elem(&haz_samples, &si);
			if (hs) {
				hs->user_data_a = ud_a;
				hs->user_data_b = user_data;
				hs->base = base;
				hs->len = olen;
				hs->bufidx = bufidx;
				hs->kind = kind;
				hs->opcode_a = op_a;
				hs->opcode_b = opcode;
			}
		}
	}

	/* circular insert of this request's descriptor */
	h = w->head & (HAZ_K - 1);
	w->slot[h].key = key;
	w->slot[h].user_data = user_data;
	w->slot[h].addr = addr;
	w->slot[h].len = len;
	w->slot[h].bufidx = bufidx;
	w->slot[h].kind = kind;
	w->slot[h].opcode = opcode;
	w->head = h + 1;
}

/* Per-ring refcount array for this ctx, zero-created on first use. */
static __always_inline struct buf_refcounts *bufref_get(__u64 ctx_ptr,
							bool create)
{
	struct buf_refcounts *r = bpf_map_lookup_elem(&buf_refs, &ctx_ptr);
	struct buf_refcounts *tpl;
	__u32 z = 0;

	if (r || !create)
		return r;
	tpl = bpf_map_lookup_elem(&bufref_zero, &z);
	if (!tpl)
		return NULL;
	bpf_map_update_elem(&buf_refs, &ctx_ptr, tpl, BPF_NOEXIST);
	return bpf_map_lookup_elem(&buf_refs, &ctx_ptr);
}

static __always_inline void bufref_inc(__u64 ctx_ptr, __u16 idx)
{
	struct buf_refcounts *r = bufref_get(ctx_ptr, true);

	if (!r || idx >= MAX_REG_BUFS)
		return;
	__sync_fetch_and_add(&r->refs[idx], 1);
	__sync_fetch_and_add(&r->live, 1);   /* O(1) live total */
}

static __always_inline void bufref_dec(__u64 ctx_ptr, __u16 idx)
{
	struct buf_refcounts *r = bufref_get(ctx_ptr, false);

	if (!r || idx >= MAX_REG_BUFS)
		return;
	if (r->refs[idx] > 0) {
		__sync_fetch_and_add(&r->refs[idx], (__u64)-1);
		__sync_fetch_and_add(&r->live, (__u64)-1);
	}
}

/* Stamp this completion's CQ-ring position so a later reap-side uprobe can
 * compute "how long did the CQE at position P sit ready". The position is
 * the kernel's free-running cached_cq_tail at fill time. */
static __always_inline struct pos_ts *pos_ts_get(__u64 ctx_ptr)
{
	struct pos_ts *pt = bpf_map_lookup_elem(&cqe_pos_ts, &ctx_ptr);
	struct pos_ts *tpl;
	__u32 z = 0;

	if (pt)
		return pt;
	tpl = bpf_map_lookup_elem(&pos_ts_zero, &z);
	if (!tpl)
		return NULL;
	bpf_map_update_elem(&cqe_pos_ts, &ctx_ptr, tpl, BPF_NOEXIST);
	return bpf_map_lookup_elem(&cqe_pos_ts, &ctx_ptr);
}

static __always_inline void pos_stamp(struct io_ring_ctx *ctx, __u64 now)
{
	struct pos_ts *pt;
	__u32 tail;

	if (!bpf_core_field_exists(ctx->cached_cq_tail))
		return; /* ancient layout: reap lag silently unavailable */
	pt = pos_ts_get((__u64)ctx);
	if (!pt)
		return;
	/* io_get_cqe bumps cached_cq_tail before the CQE is filled and the
	 * tracepoint fires (verified on 6.6 with pathogen reap-lag: the
	 * single CQE lands at position tail-1, not tail), so the CQE being
	 * completed sits at the previous position. */
	tail = BPF_CORE_READ(ctx, cached_cq_tail);
	pt->ts[(tail - 1) & (POS_TS_SLOTS - 1)] = now;
}

/* On completion: drop this request's slot from the window so its range
 * stops being tested against future submits. */
static __always_inline void hazard_on_complete(__u64 ctx_ptr, __u64 key)
{
	struct haz_window *w;

	if (!ctx_ptr)
		return;
	w = bpf_map_lookup_elem(&haz_windows, &ctx_ptr);
	if (!w)
		return;
	#pragma unroll
	for (int i = 0; i < HAZ_K; i++) {
		if (w->slot[i].key == key) {
			w->slot[i].key = 0;
			w->slot[i].kind = TGT_NONE;
		}
	}
}

/* ---------------- core handlers (shared by tracepoint variants) ------- */

static __always_inline int do_submit(__u64 key, __u64 ctx_ptr,
				     __u64 user_data, __u8 opcode,
				     __u8 tgt_kind, __u16 tgt_bufidx,
				     __u64 tgt_addr, __u32 tgt_len)
{
	struct inflight val = {};
	struct opstat *os;
	__u32 tgid, *owner;

	/* Attribution: prefer the ring's registered owner (correct under
	 * SQPOLL, where current is the iou-sqp kthread), else current.
	 * With -f a registered owner is accepted outright: us_create only
	 * registers rings that passed the (follow-aware) filter, so ring
	 * ownership -- not the submitting task's tgid -- decides. */
	owner = bpf_map_lookup_elem(&ctx_owner, &ctx_ptr);
	if (owner) {
		tgid = *owner;
		if (!cfg_follow && !tgid_wanted(tgid))
			return 0;
	} else {
		tgid = cur_tgid();
		if (!wanted_cur())
			return 0;
	}

	val.ts_submit = bpf_ktime_get_ns();
	val.user_data = user_data;
	val.tgid = tgid;
	val.opcode = opcode;
	val.tgt_kind = tgt_kind;
	val.tgt_bufidx = tgt_bufidx;
	val.tgt_addr = tgt_addr;
	val.tgt_len = tgt_len;

	if (bpf_map_update_elem(&inflight, &key, &val, BPF_ANY)) {
		cadd(C_INFLIGHT_DROP, 1);
		return 0;
	}

	cadd(C_SUBMIT, 1);
	os = opstat_of(opcode);
	if (os)
		__sync_fetch_and_add(&os->submitted, 1);

	if (cfg_check_mode && tgt_kind != TGT_NONE) {
		hazard_on_submit(ctx_ptr, key, user_data, opcode, tgt_kind,
				 tgt_bufidx, tgt_addr, tgt_len);
		if (tgt_kind == TGT_BUFIDX)
			bufref_inc(ctx_ptr, tgt_bufidx);
	}

	emit_event(EV_SUBMIT, key, user_data, opcode, 0, 0, 0, tgid);
	return 0;
}

static __always_inline int do_complete(__u64 key, __s32 res, __u32 cflags,
				       struct io_ring_ctx *ctx)
{
	struct inflight *val;
	struct opstat *os;
	__u64 now = bpf_ktime_get_ns(), lat;
	bool more = cflags & US_CQE_F_MORE;
	__u32 slot;

	val = bpf_map_lookup_elem(&inflight, &key);
	if (!val) {
		/* Completion for a request submitted before we attached,
		 * filtered out, or a multishot CQE we chose not to track. */
		cadd(C_UNTRACKED, 1);
		return 0;
	}

	lat = now - val->ts_submit;
	cadd(C_COMPLETE, 1);
	if (res < 0 && res != -11 /* -EAGAIN */)
		cadd(C_ERRORS, 1);
	if (more) {
		cadd(C_MULTISHOT, 1);
		val->fl |= IF_MULTISHOT;
	}

	os = opstat_of(val->opcode);
	if (os) {
		__sync_fetch_and_add(&os->completed, 1);
		__sync_fetch_and_add(&os->lat_sum_ns, lat);
		if (res < 0 && res != -11)
			__sync_fetch_and_add(&os->errors, 1);
		if (val->fl & IF_PUNTED && val->ts_punt)
			__sync_fetch_and_add(&os->punt_lat_sum_ns,
					     now - val->ts_punt);
		slot = log2l(lat);
		if (slot >= NLAT_SLOTS)
			slot = NLAT_SLOTS - 1;
		__sync_fetch_and_add(&os->hist[slot], 1);
	}

	/* Opportunistic CQ-depth sample while we hold the ctx pointer. */
	if (ctx) {
		__u32 d = ctx_cq_depth(ctx);
		cadd(C_CQ_DEPTH_SAMPLES, 1);
		cadd(C_CQ_DEPTH_SUM, d);
		cmax(C_CQ_DEPTH_MAX, d);
		if (cfg_e2e)
			pos_stamp(ctx, now);
	}

	emit_event(EV_COMPLETE, key, val->user_data, val->opcode, val->fl,
		   res, lat, val->tgid);

	/* Multishot requests stay armed: keep the record, reset the clock
	 * so each CQE measures time-since-previous-CQE. */
	if (more) {
		val->ts_submit = now;
	} else {
		__u8  t_kind = val->tgt_kind;   /* before delete: val points */
		__u16 t_idx  = val->tgt_bufidx; /* into the map entry        */

		bpf_map_delete_elem(&inflight, &key);
		if (cfg_check_mode) {
			hazard_on_complete((__u64)ctx, key);
			if (t_kind == TGT_BUFIDX && ctx)
				bufref_dec((__u64)ctx, t_idx);
		}
	}
	return 0;
}

/* ---------------- modern tracepoints (>= ~v5.19/6.0 prototypes) ------- */

SEC("tp_btf/io_uring_create")
int BPF_PROG(us_create, int fd, void *ring, u32 sq_entries, u32 cq_entries,
	     u32 flags)
{
	__u64 ctx_ptr = (__u64)ring;
	__u32 tgid = cur_tgid();
	struct ring_info ri = {};
	__u32 slot;
	__u64 *n;
	__u32 ckey = C_RINGS;

	if (!wanted_cur())
		return 0;

	bpf_map_update_elem(&ctx_owner, &ctx_ptr, &tgid, BPF_ANY);

	n = bpf_map_lookup_elem(&counters, &ckey);
	if (!n)
		return 0;
	slot = __sync_fetch_and_add(n, 1);
	if (slot >= MAX_RINGS)
		return 0;

	ri.ctx = ctx_ptr;
	ri.fd = fd;
	ri.sq_entries = sq_entries;
	ri.cq_entries = cq_entries;
	ri.flags = flags;
	ri.tgid = tgid;
	bpf_get_current_comm(&ri.comm, sizeof(ri.comm));
	bpf_map_update_elem(&rings, &slot, &ri, BPF_ANY);
	return 0;
}

/* v6.0+ name; TP_PROTO(struct io_kiocb *req) */
SEC("tp_btf/io_uring_submit_req")
int BPF_PROG(us_submit_req, struct io_kiocb *req)
{
	__u8 opcode = BPF_CORE_READ(req, opcode), kind;
	__u16 bufidx;
	__u64 addr;
	__u32 len;

	req_target(req, opcode, &kind, &bufidx, &addr, &len);
	return do_submit((__u64)req, (__u64)BPF_CORE_READ(req, ctx),
			 req_user_data(req), opcode, kind, bufidx, addr, len);
}

/* Punt to the io-wq async worker pool: the tail-latency killer.
 * TP_PROTO(struct io_kiocb *req, int rw) on >= v6.0. */
SEC("tp_btf/io_uring_queue_async_work")
int BPF_PROG(us_queue_async_work, struct io_kiocb *req)
{
	__u64 key = (__u64)req;
	struct inflight *val = bpf_map_lookup_elem(&inflight, &key);
	struct opstat *os;

	if (!val)
		return 0;
	/* A request can be queued to io-wq more than once (requeue after a
	 * poll wakeup, quiesce paths). Count the *request* as punted once --
	 * the report says "X% of requests fell back", and a ratio over 100%
	 * is nonsense -- but keep updating ts_punt so punt->complete latency
	 * measures the punt that actually ran. */
	val->ts_punt = bpf_ktime_get_ns();
	if (val->fl & IF_PUNTED)
		return 0;
	val->fl |= IF_PUNTED;
	cadd(C_PUNT, 1);
	os = opstat_of(val->opcode);
	if (os)
		__sync_fetch_and_add(&os->punted, 1);
	emit_event(EV_PUNT, key, val->user_data, val->opcode, val->fl, 0, 0,
		   val->tgid);
	return 0;
}

/* Poll-retry path (fd not ready, parked on a wait queue).
 * TP_PROTO(struct io_kiocb *req, int mask, int events) on >= v6.0. */
SEC("tp_btf/io_uring_poll_arm")
int BPF_PROG(us_poll_arm, struct io_kiocb *req)
{
	__u64 key = (__u64)req;
	struct inflight *val = bpf_map_lookup_elem(&inflight, &key);

	if (!val)
		return 0;
	val->fl |= IF_POLLED;
	cadd(C_POLL_ARM, 1);
	return 0;
}

/* TP_PROTO(void *ctx, void *req, u64 user_data, int res, unsigned cflags
 *          [, u64 extra1, u64 extra2])   -- 5.19 / 6.0+ shapes */
SEC("tp_btf/io_uring_complete")
int BPF_PROG(us_complete, void *ring, struct io_kiocb *req, u64 user_data,
	     int res, unsigned int cflags)
{
	if (!req) /* overflow-flush paths may pass NULL */
		return 0;
	return do_complete((__u64)req, res, cflags,
			   (struct io_ring_ctx *)ring);
}

/* v6.17+: TP_PROTO(struct io_ring_ctx *ctx, void *req, struct io_uring_cqe *cqe)
 * -- the scalar user_data/res/cflags collapsed into the ring CQE pointer.
 * Identical to us_complete otherwise; res/flags come from the CQE via CO-RE. */
SEC("tp_btf/io_uring_complete")
int BPF_PROG(us_complete_cqe, void *ring, void *req, struct io_uring_cqe *cqe)
{
	if (!req)
		return 0;
	return do_complete((__u64)req, BPF_CORE_READ(cqe, res),
			   BPF_CORE_READ(cqe, flags),
			   (struct io_ring_ctx *)ring);
}

/* Fail-soft: an io_uring_complete prototype that no known variant matches.
 * Reads no positional args, so it attaches on any shape -- we lose latency
 * and per-op stats but keep an honest completion count instead of going
 * blind. src/probe.c autoloads this only when the tracepoint exists but its
 * prototype is unrecognized. */
SEC("tp_btf/io_uring_complete")
int BPF_PROG(us_complete_count)
{
	cadd(C_COMPLETE, 1);
	return 0;
}

SEC("tp_btf/io_uring_cqe_overflow")
int BPF_PROG(us_cqe_overflow, void *ring)
{
	cadd(C_OVERFLOW, 1);
	emit_event(EV_OVERFLOW, (__u64)ring, 0, 0, 0, 0, 0, cur_tgid());
	return 0;
}

/* TP_PROTO(void *tctx, unsigned int count, unsigned int loops) */
SEC("tp_btf/io_uring_task_work_run")
int BPF_PROG(us_task_work_run, void *tctx, unsigned int count)
{
	if (!wanted_cur())
		return 0;
	cadd(C_TW_RUN, 1);
	cadd(C_TW_ITEMS, count);
	return 0;
}

/* DEFER_TASKRUN local work (>= v6.1).
 * TP_PROTO(void *ctx, ...) -- arity changed in v6.x; we only count. */
SEC("tp_btf/io_uring_local_work_run")
int BPF_PROG(us_local_work_run, void *ring)
{
	cadd(C_LOCAL_TW_RUN, 1);
	return 0;
}

SEC("tp_btf/io_uring_short_write")
int BPF_PROG(us_short_write, void *ring)
{
	cadd(C_SHORT_WRITE, 1);
	return 0;
}

/* ---------------- legacy tracepoints (pre-v6.0 prototypes) ------------ */
/* Disabled by default; src/probe.c flips autoload after BTF inspection.
 * Supported as best-effort: 5.15 LTS class kernels. Punt/poll detection
 * is unavailable there (prototypes too unstable across 5.x to chase). */

/* v5.15: TP_PROTO(void *ctx, void *req, unsigned long long user_data,
 *                 u8 opcode, u32 flags, bool force_nonblock, bool sq_thread) */
SEC("tp_btf/io_uring_submit_sqe")
int BPF_PROG(us_submit_sqe_legacy, void *ring, void *req, u64 user_data,
	     u32 opcode)
{
	/* Legacy path has no relocatable io_kiocb view for addr/len; hazard
	 * mode is modern-kernel only, so carry no target descriptor. */
	return do_submit(legacy_key((__u64)ring, user_data), (__u64)ring,
			 user_data, (__u8)opcode, TGT_NONE, 0, 0, 0);
}

/* v5.15: TP_PROTO(void *ctx, u64 user_data, int res, unsigned cflags) */
SEC("tp_btf/io_uring_complete")
int BPF_PROG(us_complete_legacy, void *ring, u64 user_data, int res,
	     unsigned int cflags)
{
	return do_complete(legacy_key((__u64)ring, user_data), res, cflags,
			   NULL);
}

/* ---------------- syscall batching + scheduler signals ---------------- */

SEC("tracepoint/syscalls/sys_enter_io_uring_enter")
int us_sys_enter(struct trace_event_raw_sys_enter *args)
{
	__u64 to_submit;
	__u32 slot;

	if (!wanted_cur())
		return 0;
	to_submit = (__u64)args->args[1];
	cadd(C_ENTER, 1);
	cadd(C_TOSUBMIT, to_submit);
	slot = to_submit ? log2l(to_submit) + 1 : 0;
	if (slot >= NSUBMIT_SLOTS)
		slot = NSUBMIT_SLOTS - 1;
	{
		__u64 *v = bpf_map_lookup_elem(&tosubmit_hist, &slot);
		if (v)
			__sync_fetch_and_add(v, 1);
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_io_uring_enter")
int us_sys_exit(struct trace_event_raw_sys_exit *args)
{
	if (!wanted_cur())
		return 0;
	if (args->ret > 0)
		cadd(C_RET_SUBMITTED, (__u64)args->ret);
	return 0;
}

/* ---------------- --check: hazard 3 + hazard 1 (unmap) hooks ----------- */

/* IORING_REGISTER_* opcodes we inspect (uapi values; stable ABI). Bit 31
 * (IORING_REGISTER_USE_REGISTERED_RING) flags that args[0] is a registered
 * ring *index*, not an fd -- those won't match our fd-keyed ring table and
 * are a documented miss. */
#define US_IORING_REGISTER_BUFFERS   0
#define US_IORING_UNREGISTER_BUFFERS 1
#define US_IORING_REGISTER_BUFFERS2  15
#define US_IORING_REG_RING_FLAG      (1U << 31)

/* Hazard 3: the app asked to unregister (or re-register over) buffers while
 * in-flight *_FIXED requests still hold references to those indexes. */
SEC("tracepoint/syscalls/sys_enter_io_uring_register")
int us_uring_register(struct trace_event_raw_sys_enter *args)
{
	struct buf_refcounts *r;
	__u64 ctx_ptr = 0;
	__u32 fd, opcode, tgid;

	if (!cfg_check_mode)
		return 0;
	opcode = (__u32)args->args[1] & ~US_IORING_REG_RING_FLAG;
	if (opcode != US_IORING_REGISTER_BUFFERS &&
	    opcode != US_IORING_UNREGISTER_BUFFERS &&
	    opcode != US_IORING_REGISTER_BUFFERS2)
		return 0;
	if ((__u32)args->args[1] & US_IORING_REG_RING_FLAG)
		return 0;
	if (!wanted_cur())
		return 0;
	fd = (__u32)args->args[0];
	tgid = cur_tgid();

	for (__u32 i = 0; i < MAX_RINGS; i++) {
		__u32 k = i;
		struct ring_info *ri = bpf_map_lookup_elem(&rings, &k);

		if (!ri || !ri->ctx)
			continue;
		if (ri->fd == fd && ri->tgid == tgid) {
			ctx_ptr = ri->ctx;
			break;
		}
	}
	if (!ctx_ptr)
		return 0;
	r = bufref_get(ctx_ptr, false);
	if (!r)
		return 0;

	/* No in-kernel scan. Scanning a 1024-wide array in the BPF program
	 * (even a branchless copy) makes the verifier track the loop index
	 * precisely across 1024 states and blows its 1M-instruction budget
	 * on strict verifiers -- 6.17 rejected it, 6.6 pruned just under (a
	 * real cross-kernel complexity trap the vmtest harness caught). So
	 * we keep an O(1) live total (maintained by bufref_inc/dec) and, on
	 * a *violating* (un)register, snapshot the whole refcount array with
	 * a SINGLE map-copy helper call -- no loop. Userspace finds which
	 * indexes are live by scanning the snapshot, where there is no
	 * instruction budget. */
	if (r->live) {
		__u32 ck = C_HAZARD_BUFREG;
		__u64 *cv = bpf_map_lookup_elem(&counters, &ck);

		/* one helper copies live + refs[] wholesale into the snapshot */
		bpf_map_update_elem(&bufreg_snap, &ctx_ptr, r, BPF_ANY);
		if (cv)
			__sync_fetch_and_add(cv, r->live);
	} else {
		/* clean (un)register: drop any stale snapshot so a later
		 * report doesn't resurrect an old violation */
		bpf_map_delete_elem(&bufreg_snap, &ctx_ptr);
	}
	return 0;
}

/* Hazard 1, unmap variant: munmap of a range that an in-flight request is
 * still reading from / writing into. Scans the same per-ring windows the
 * overlap detector maintains. The freelist variant (free() without munmap,
 * stack reuse) fires no syscall and is NOT catchable here -- documented in
 * docs/buffer-hazards.md, not silently claimed. */
SEC("tracepoint/syscalls/sys_enter_munmap")
int us_munmap(struct trace_event_raw_sys_enter *args)
{
	__u64 m0, m1;

	if (!cfg_check_mode)
		return 0;
	if (!wanted_cur())
		return 0;
	m0 = (__u64)args->args[0];
	m1 = m0 + (__u64)args->args[1];

	for (__u32 ri_i = 0; ri_i < MAX_RINGS; ri_i++) {
		__u32 k = ri_i;
		struct ring_info *ri = bpf_map_lookup_elem(&rings, &k);
		struct haz_window *w;

		if (!ri || !ri->ctx)
			continue;
		w = bpf_map_lookup_elem(&haz_windows, &ri->ctx);
		if (!w)
			continue;

		#pragma unroll
		for (int i = 0; i < HAZ_K; i++) {
			struct haz_slot *s = &w->slot[i];
			__u64 a0, a1, base, hi;
			__u32 ck = C_HAZARD_UNMAP;
			__u64 *cv;
			__u64 idx;

			if (!s->key || s->kind != TGT_ADDR)
				continue;
			a0 = s->addr;
			a1 = s->addr + s->len;
			if (!(a0 < m1 && m0 < a1))
				continue;
			base = a0 > m0 ? a0 : m0;
			hi   = a1 < m1 ? a1 : m1;
			cv = bpf_map_lookup_elem(&counters, &ck);
			idx = cv ? __sync_fetch_and_add(cv, 1) : 0;
			if (idx < HAZARD_SAMPLES) {
				__u32 si = (__u32)idx;
				struct unmap_sample *us =
					bpf_map_lookup_elem(&haz_unmap_samples,
							    &si);
				if (us) {
					us->user_data = s->user_data;
					us->base = base;
					us->len = (__u32)(hi - base);
					us->opcode = s->opcode;
				}
			}
		}
	}
	return 0;
}

static __always_inline bool comm_has_prefix(const char *comm,
					    const char *pfx, int n)
{
	for (int i = 0; i < n; i++)
		if (comm[i] != pfx[i])
			return false;
	return true;
}

/* ---------------- liburing uprobes (end-to-end boundary) --------------- */
/*
 * Strictly best-effort (src/uprobes.c): these attach only when a dynamic
 * liburing was located, and every record is gated on matching the ring_fd
 * read from the app's struct io_uring against our rings table -- an ABI
 * mismatch yields no data rather than wrong data.
 *
 * What is and is not implemented (per docs/end-to-end.md):
 *  - reap gap: io_uring_cqe_seen()/io_uring_cq_advance() are static inline
 *    in liburing.h -- they have NO symbol in liburing.so and cannot be
 *    uprobed. We anchor on the exported wait/peek entry points instead and
 *    measure the age of the oldest ready CQE (head position) at call
 *    entry, matched to the kernel-side completion stamp for that position.
 *    Apps that reap exclusively through the inlined peek path are
 *    invisible; the report says "no samples", not a fabricated number.
 *  - prep gap: per-SQE prep timestamps are NOT observable (prep helpers
 *    are inlined and write ring memory directly, no library call), so we
 *    measure the reliable coarser signal the spec falls back to:
 *    submit-batch size and inter-submit interval at io_uring_submit*().
 */

/* Resolve the app's struct io_uring* to our kernel ctx via (tgid, ring_fd).
 * Returns 0 and leaves *ctx_out alone on any mismatch. */
static __always_inline int ur_ring_ctx(const void *ring, __u32 tgid,
				       __u64 *ctx_out)
{
	int fd = -1;

	if (bpf_probe_read_user(&fd, sizeof(fd),
				(const char *)ring + cfg_ur_ring_fd_off))
		return 0;
	for (__u32 i = 0; i < MAX_RINGS; i++) {
		__u32 k = i;
		struct ring_info *ri = bpf_map_lookup_elem(&rings, &k);

		if (!ri || !ri->ctx)
			continue;
		if (ri->fd == (__u32)fd && ri->tgid == tgid) {
			*ctx_out = ri->ctx;
			return 1;
		}
	}
	return 0;
}

static __always_inline struct e2e_stats *e2e(void)
{
	__u32 z = 0;
	return bpf_map_lookup_elem(&e2e_stats, &z);
}

/* io_uring_submit / io_uring_submit_and_wait[_timeout] entry. */
SEC("uprobe")
int BPF_KPROBE(ur_submit, void *ring)
{
	struct e2e_stats *st;
	__u64 ctx_ptr = 0, now;
	__u32 tgid, head = 0, sqe_tail = 0;
	void *khead_p = NULL;

	if (!wanted_cur())
		return 0;
	tgid = cur_tgid();
	if (!ur_ring_ctx(ring, tgid, &ctx_ptr))
		return 0;
	st = e2e();
	if (!st)
		return 0;

	/* pending = sqe_tail - *sq.khead: what this call is about to flush */
	bpf_probe_read_user(&sqe_tail, sizeof(sqe_tail),
			    (const char *)ring + cfg_ur_sqe_tail_off);
	if (!bpf_probe_read_user(&khead_p, sizeof(khead_p),
				 (const char *)ring + cfg_ur_sq_khead_off) &&
	    khead_p)
		bpf_probe_read_user(&head, sizeof(head), khead_p);

	now = bpf_ktime_get_ns();
	__sync_fetch_and_add(&st->submit_calls, 1);
	__sync_fetch_and_add(&st->submit_batch_sum,
			     (__u64)(__u32)(sqe_tail - head));
	/* last_ns is read-modify-write without a lock: a racing pair of
	 * submitting threads can smear one interval sample; acceptable for
	 * an average over thousands. */
	if (st->submit_last_ns)
		__sync_fetch_and_add(&st->submit_interval_sum_ns,
				     now - st->submit_last_ns);
	st->submit_last_ns = now;
	return 0;
}

/* Entry of the exported reap-side family (__io_uring_get_cqe,
 * io_uring_wait_cqe_timeout, io_uring_wait_cqes, io_uring_peek_batch_cqe,
 * io_uring_get_events, io_uring_submit_and_get_events): if a CQE is
 * already ready, its age IS the reap lag for the head position. */
SEC("uprobe")
int BPF_KPROBE(ur_reap, void *ring)
{
	struct pos_ts *pt;
	struct e2e_stats *st;
	__u64 ctx_ptr = 0, ts, lag;
	__u32 tgid, head = 0, tail = 0, slot;
	void *khead_p = NULL, *ktail_p = NULL;

	if (!wanted_cur())
		return 0;
	tgid = cur_tgid();
	if (!ur_ring_ctx(ring, tgid, &ctx_ptr))
		return 0;

	if (bpf_probe_read_user(&khead_p, sizeof(khead_p),
				(const char *)ring + cfg_ur_cq_khead_off) ||
	    !khead_p)
		return 0;
	if (bpf_probe_read_user(&ktail_p, sizeof(ktail_p),
				(const char *)ring + cfg_ur_cq_ktail_off) ||
	    !ktail_p)
		return 0;
	if (bpf_probe_read_user(&head, sizeof(head), khead_p) ||
	    bpf_probe_read_user(&tail, sizeof(tail), ktail_p))
		return 0;
	if (head == tail)
		return 0; /* nothing ready: a wait, not a lagging reap */

	pt = bpf_map_lookup_elem(&cqe_pos_ts, &ctx_ptr);
	if (!pt)
		return 0;
	/* one measurement per position: nested exported calls (e.g.
	 * wait_cqe_timeout -> get_cqe) would otherwise double-count */
	if (pt->init && (__s32)(head - (__u32)pt->last_pos) <= 0)
		return 0;
	ts = pt->ts[head & (POS_TS_SLOTS - 1)];
	if (!ts)
		return 0;
	pt->last_pos = head;
	pt->init = 1;

	st = e2e();
	if (!st)
		return 0;
	lag = bpf_ktime_get_ns() - ts;
	__sync_fetch_and_add(&st->reap_n, 1);
	__sync_fetch_and_add(&st->reap_sum_ns, lag);
	slot = log2l(lag);
	if (slot >= NLAT_SLOTS)
		slot = NLAT_SLOTS - 1;
	__sync_fetch_and_add(&st->reap_hist[slot], 1);
	return 0;
}

/* Track SQPOLL-thread off-CPU time (stalls) and io-wq worker fan-out.
 * Both thread types live inside the traced process's thread group. */
SEC("tp_btf/sched_switch")
int BPF_PROG(us_sched_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	char comm[TASK_COMM_SZ];
	__u32 pid;
	__u64 now = bpf_ktime_get_ns();

	/* sqpoll thread going to sleep */
	BPF_CORE_READ_STR_INTO(&comm, prev, comm);
	if (comm_has_prefix(comm, "iou-sqp-", 8)) {
		if (task_wanted(prev)) {
			pid = BPF_CORE_READ(prev, pid);
			bpf_map_update_elem(&sqpoll_offcpu, &pid, &now,
					    BPF_ANY);
			cadd(C_SQPOLL_SWITCHES, 1);
		}
	}

	BPF_CORE_READ_STR_INTO(&comm, next, comm);
	/* sqpoll thread waking back up: account the stall */
	if (comm_has_prefix(comm, "iou-sqp-", 8)) {
		if (task_wanted(next)) {
			__u64 *ts;
			pid = BPF_CORE_READ(next, pid);
			ts = bpf_map_lookup_elem(&sqpoll_offcpu, &pid);
			if (ts) {
				cadd(C_SQPOLL_OFFCPU_NS, now - *ts);
				bpf_map_delete_elem(&sqpoll_offcpu, &pid);
			}
		}
	}
	/* distinct io-wq workers */
	else if (comm_has_prefix(comm, "iou-wrk-", 8)) {
		if (task_wanted(next)) {
			__u8 one = 1;
			pid = BPF_CORE_READ(next, pid);
			if (!bpf_map_lookup_elem(&workers, &pid)) {
				bpf_map_update_elem(&workers, &pid, &one,
						    BPF_NOEXIST);
				cadd(C_WORKERS_SEEN, 1);
			}
		}
	}
	return 0;
}
