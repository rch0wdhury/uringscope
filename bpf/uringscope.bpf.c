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
const volatile __u32 cfg_pidns_ino = 0;   /* nonzero: userspace runs in a
					     child pid namespace (WSL2
					     distro, container) with this
					     nsfs inode; translate tgids   */

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

/* ---------------- core handlers (shared by tracepoint variants) ------- */

static __always_inline int do_submit(__u64 key, __u64 ctx_ptr,
				     __u64 user_data, __u8 opcode)
{
	struct inflight val = {};
	struct opstat *os;
	__u32 tgid, *owner;

	/* Attribution: prefer the ring's registered owner (correct under
	 * SQPOLL, where current is the iou-sqp kthread), else current. */
	owner = bpf_map_lookup_elem(&ctx_owner, &ctx_ptr);
	tgid = owner ? *owner : cur_tgid();
	if (!tgid_wanted(tgid))
		return 0;

	val.ts_submit = bpf_ktime_get_ns();
	val.user_data = user_data;
	val.tgid = tgid;
	val.opcode = opcode;

	if (bpf_map_update_elem(&inflight, &key, &val, BPF_ANY)) {
		cadd(C_INFLIGHT_DROP, 1);
		return 0;
	}

	cadd(C_SUBMIT, 1);
	os = opstat_of(opcode);
	if (os)
		__sync_fetch_and_add(&os->submitted, 1);

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
	}

	emit_event(EV_COMPLETE, key, val->user_data, val->opcode, val->fl,
		   res, lat, val->tgid);

	/* Multishot requests stay armed: keep the record, reset the clock
	 * so each CQE measures time-since-previous-CQE. */
	if (more)
		val->ts_submit = now;
	else
		bpf_map_delete_elem(&inflight, &key);
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

	if (!tgid_wanted(tgid))
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
	return do_submit((__u64)req, (__u64)BPF_CORE_READ(req, ctx),
			 req_user_data(req), BPF_CORE_READ(req, opcode));
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
	val->fl |= IF_PUNTED;
	val->ts_punt = bpf_ktime_get_ns();
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
	if (!tgid_wanted(cur_tgid()))
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
	return do_submit(legacy_key((__u64)ring, user_data), (__u64)ring,
			 user_data, (__u8)opcode);
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

	if (!tgid_wanted(cur_tgid()))
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
	if (!tgid_wanted(cur_tgid()))
		return 0;
	if (args->ret > 0)
		cadd(C_RET_SUBMITTED, (__u64)args->ret);
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

/* Track SQPOLL-thread off-CPU time (stalls) and io-wq worker fan-out.
 * Both thread types live inside the traced process's thread group. */
SEC("tp_btf/sched_switch")
int BPF_PROG(us_sched_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	char comm[TASK_COMM_SZ];
	__u32 pid, tgid;
	__u64 now = bpf_ktime_get_ns();

	/* sqpoll thread going to sleep */
	BPF_CORE_READ_STR_INTO(&comm, prev, comm);
	if (comm_has_prefix(comm, "iou-sqp-", 8)) {
		tgid = task_tgid_view(prev);
		if (tgid_wanted(tgid)) {
			pid = BPF_CORE_READ(prev, pid);
			bpf_map_update_elem(&sqpoll_offcpu, &pid, &now,
					    BPF_ANY);
			cadd(C_SQPOLL_SWITCHES, 1);
		}
	}

	BPF_CORE_READ_STR_INTO(&comm, next, comm);
	/* sqpoll thread waking back up: account the stall */
	if (comm_has_prefix(comm, "iou-sqp-", 8)) {
		tgid = task_tgid_view(next);
		if (tgid_wanted(tgid)) {
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
		tgid = task_tgid_view(next);
		if (tgid_wanted(tgid)) {
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
