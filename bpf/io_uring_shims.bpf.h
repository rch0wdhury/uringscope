/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * io_uring_shims.bpf.h - minimal, relocatable views of io_uring kernel
 * internals.
 *
 * Design note (this is the heart of uringscope's portability story):
 *
 * io_uring's internal structs (io_kiocb, io_ring_ctx, io_rings) are NOT
 * exposed in any UAPI header, and their layout churns across kernel
 * releases. Instead of compiling against a full vmlinux.h generated from
 * one specific kernel, we declare *only the fields we read*, mark the
 * structs with preserve_access_index, and let libbpf's CO-RE relocation
 * match fields *by name* against the BTF of whatever kernel we load on.
 *
 * Fields that moved between versions get a "flavor" struct (suffix ___vXXX,
 * stripped by libbpf before matching) and a bpf_core_field_exists() guard.
 *
 * Known layout churn we handle:
 *   - io_kiocb.user_data / io_kiocb.result moved into io_kiocb.cqe
 *     (struct io_cqe { user_data; res; flags; }) in v5.19
 *     (kernel commit cef216fc32d7, "io_uring: explicitly keep a CQE in
 *     io_kiocb"). Guarded via io_kiocb___pre519.
 *   - tracepoint *prototypes* changed across 5.x/6.x; we cope by reading
 *     almost everything from the io_kiocb pointer rather than trusting
 *     positional tracepoint args, and by registering legacy program
 *     variants that userspace enables/disables after probing kernel BTF
 *     (see src/probe.c).
 */
#ifndef IO_URING_SHIMS_BPF_H
#define IO_URING_SHIMS_BPF_H

#include "vmlinux.h"

/* The CQE cached inside each request (>= v5.19). */
struct io_cqe {
	__u64 user_data;
	__s32 res;
	__u32 flags;
} __attribute__((preserve_access_index));

/* Ring head/tail pair as the kernel sees it. */
struct io_uring {
	__u32 head;
	__u32 tail;
} __attribute__((preserve_access_index));

/* Shared rings page. Field offsets relocated by name at load time. */
struct io_rings {
	struct io_uring sq;
	struct io_uring cq;
} __attribute__((preserve_access_index));

/* Per-ring context. We only ever read these two members. */
struct io_ring_ctx {
	unsigned int     flags;   /* IORING_SETUP_* */
	struct io_rings *rings;
} __attribute__((preserve_access_index));

/* One io_uring request. Modern (>= v5.19) layout view. */
struct io_kiocb {
	__u8                opcode;
	unsigned int        flags;  /* REQ_F_* */
	struct io_cqe       cqe;
	struct io_ring_ctx *ctx;
} __attribute__((preserve_access_index));

/* Flavor: pre-5.19 io_kiocb kept user_data/result directly. */
struct io_kiocb___pre519 {
	__u64 user_data;
	__s32 result;
} __attribute__((preserve_access_index));

/* Read user_data from a request on any supported kernel. */
static __always_inline __u64 req_user_data(struct io_kiocb *req)
{
	if (bpf_core_field_exists(req->cqe))
		return BPF_CORE_READ(req, cqe.user_data);
	return BPF_CORE_READ((struct io_kiocb___pre519 *)req, user_data);
}

/* Read the completion result from a request on any supported kernel. */
static __always_inline __s32 req_res(struct io_kiocb *req)
{
	if (bpf_core_field_exists(req->cqe))
		return BPF_CORE_READ(req, cqe.res);
	return BPF_CORE_READ((struct io_kiocb___pre519 *)req, result);
}

/* Read CQE flags (for IORING_CQE_F_MORE / multishot detection). */
static __always_inline __u32 req_cqe_flags(struct io_kiocb *req)
{
	if (bpf_core_field_exists(req->cqe))
		return BPF_CORE_READ(req, cqe.flags);
	return 0; /* multishot didn't exist before io_cqe did */
}

/* Sample CQ occupancy straight from the shared rings page. */
static __always_inline __u32 ctx_cq_depth(struct io_ring_ctx *ctx)
{
	struct io_rings *rings = BPF_CORE_READ(ctx, rings);
	__u32 head, tail;

	if (!rings)
		return 0;
	head = BPF_CORE_READ(rings, cq.head);
	tail = BPF_CORE_READ(rings, cq.tail);
	return tail - head;
}

#endif /* IO_URING_SHIMS_BPF_H */
