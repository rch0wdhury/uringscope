/* SPDX-License-Identifier: MIT */
/* Deterministic multishot CQE accounting regression for issue #10.
 * Build: cc -O2 -o repro repro.c -luring
 * Usage: repro recv|read|duplicate|two-rings|single|continuous [rounds]
 * Needs liburing >= 2.3; READ_MULTISHOT needs Linux >= 6.7. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <liburing.h>

enum { NBUF = 16, BSIZE = 4096 };
struct endpoint {
	struct io_uring_buf_ring *br;
	char *buffers;
	int fd[2], group;
};

static void require(int ok, const char *what)
{
	if (!ok) {
		fprintf(stderr, "multishot repro: %s\n", what);
		exit(1);
	}
}

static void init_ring(struct io_uring *ring)
{
	struct io_uring_params p = {
		.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN,
	};
	int ret = io_uring_queue_init_params(64, ring, &p);
	if (ret)
		fprintf(stderr, "queue_init: %s\n", strerror(-ret));
	require(!ret, "queue_init");
}

static void init_endpoint(struct endpoint *ep, struct io_uring *ring, int group)
{
	struct io_uring_buf_reg reg = { 0 };
	ep->group = group;
	require(!socketpair(AF_UNIX, SOCK_DGRAM, 0, ep->fd), "socketpair");
	require(!posix_memalign((void **)&ep->br, 4096, 4096), "buffer ring");
	require(!posix_memalign((void **)&ep->buffers, 4096, NBUF * BSIZE),
		"buffer allocation");
	memset(ep->br, 0, 4096);
	reg.ring_addr = (unsigned long)ep->br;
	reg.ring_entries = NBUF;
	reg.bgid = group;
	require(!io_uring_register_buf_ring(ring, &reg, 0), "register_buf_ring");
	io_uring_buf_ring_init(ep->br);
}

static void provide(struct endpoint *ep)
{
	for (int i = 0; i < NBUF; i++)
		io_uring_buf_ring_add(ep->br, ep->buffers + i * BSIZE,
				     BSIZE, i, NBUF - 1, i);
	io_uring_buf_ring_advance(ep->br, NBUF);
}

static void send_n(struct endpoint *ep, int n)
{
	char data[64] = { 0 };
	for (int i = 0; i < n; i++)
		require(send(ep->fd[1], data, sizeof(data), 0) == sizeof(data),
			"send");
}

static void submit(struct io_uring *ring, struct endpoint *ep,
		   int read_mshot, int single)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	require(sqe != NULL, "get_sqe");
	if (read_mshot) {
		/* Opcode 49 is READ_MULTISHOT (6.7+). Using prep_rw keeps the
		 * test buildable with 2.3 headers predating its named helper. */
		io_uring_prep_rw(49, sqe, ep->fd[0], NULL, 0, 0);
	} else if (single) {
		io_uring_prep_recv(sqe, ep->fd[0], NULL, BSIZE, 0);
	} else {
		io_uring_prep_recv_multishot(sqe, ep->fd[0], NULL, 0, 0);
	}
	sqe->flags |= IOSQE_BUFFER_SELECT;
	sqe->buf_group = ep->group;
	sqe->user_data = 0x10; /* deliberately reused after retirement */
}

static void reap(struct io_uring *ring, int n, struct endpoint *recycle)
{
	for (int i = 0; i < n; i++) {
		struct io_uring_cqe *cqe;
		require(!io_uring_wait_cqe(ring, &cqe), "wait_cqe");
		if (cqe->res >= 0) {
			require(cqe->flags & IORING_CQE_F_MORE, "MORE on data CQE");
			if (recycle) {
				unsigned bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
				require(bid < NBUF, "buffer id");
				io_uring_buf_ring_add(recycle->br,
					recycle->buffers + bid * BSIZE,
					BSIZE, bid, NBUF - 1, 0);
				io_uring_buf_ring_advance(recycle->br, 1);
			}
		} else {
			if (cqe->res != -ENOBUFS)
				fprintf(stderr, "CQE error: %s\n", strerror(-cqe->res));
			require(cqe->res == -ENOBUFS, "ENOBUFS termination");
			require(!(cqe->flags & IORING_CQE_F_MORE), "terminal CQE");
		}
		io_uring_cqe_seen(ring, cqe);
	}
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "recv";
	int rounds = argc > 2 ? atoi(argv[2]) : 3000;
	int dup = !strcmp(mode, "duplicate"), two = !strcmp(mode, "two-rings");
	int single = !strcmp(mode, "single"), live = !strcmp(mode, "continuous");
	int rd = !strcmp(mode, "read"), ne = (dup || two) ? 2 : 1;
	struct io_uring rings[2];
	struct endpoint ep[2];

	require(rounds > 0 && (dup || two || single || live || rd ||
			       !strcmp(mode, "recv")), "mode and rounds");
	setvbuf(stdout, NULL, _IOLBF, 0);
	init_ring(&rings[0]);
	if (two)
		init_ring(&rings[1]);
	for (int i = 0; i < ne; i++)
		init_endpoint(&ep[i], &rings[two ? i : 0], 7 + i);

	if (live) {
		provide(&ep[0]);
		submit(&rings[0], &ep[0], 0, 0);
		require(io_uring_submit(&rings[0]) == 1, "arm continuous");
		puts("READY continuous");
		for (int n = 0; n < rounds; n++) {
			send_n(&ep[0], 8);
			require(io_uring_submit_and_wait(&rings[0], 8) >= 0, "wait");
			reap(&rings[0], 8, &ep[0]);
		}
		send_n(&ep[0], NBUF + 1);
		require(io_uring_submit_and_wait(&rings[0], NBUF + 1) >= 0, "finish");
		reap(&rings[0], NBUF + 1, NULL);
	} else {
		for (int i = 0; i < ne; i++)
			send_n(&ep[i], single ? 1 : 0);
		for (int n = 0; n < rounds; n++) {
			for (int i = 0; i < ne; i++) {
				if (!single)
					provide(&ep[i]);
				submit(&rings[two ? i : 0], &ep[i], rd, single);
			}
			/* Arm while sockets are empty: both duplicate tokens must
			 * be live together before any multishot CQEs are produced. */
			require(io_uring_submit(&rings[0]) >= 0, "submit");
			if (two)
				require(io_uring_submit(&rings[1]) >= 0, "submit second ring");
			if (!single) {
				for (int i = 0; i < ne; i++)
					send_n(&ep[i], NBUF + 1);
			}
			for (int i = 0; i < (two ? 2 : 1); i++) {
				int count = single ? 1 : (NBUF + 1) * (dup ? 2 : 1);
				require(io_uring_submit_and_wait(&rings[i], count) >= 0, "wait");
				reap(&rings[i], count, NULL);
			}
			/* Discard the extra datagram that caused exhaustion, so
			 * the next requests are armed before either socket is ready. */
			if (!single) {
				char data[64];
				for (int i = 0; i < ne; i++)
					require(recv(ep[i].fd[0], data, sizeof(data), 0) > 0,
						"drain extra datagram");
			}
		}
	}
	unsigned long submitted = live ? 1 : (unsigned long)rounds * ne;
	unsigned long more = live ? (unsigned long)rounds * 8 + NBUF :
		(single ? 0 : submitted * NBUF);
	printf("GROUND-TRUTH {\"submitted\":%lu,\"more\":%lu,\"enobufs\":%lu,"
	       "\"completed\":%lu,\"op\":\"%s\"}\n",
	       submitted, more, submitted, submitted + more,
	       rd ? "READ_MULTISHOT" : "RECV");
	for (int i = 0; i < ne; i++) {
		require(!io_uring_unregister_buf_ring(&rings[two ? i : 0], 7 + i),
			"unregister_buf_ring");
		close(ep[i].fd[0]); close(ep[i].fd[1]);
		free(ep[i].br); free(ep[i].buffers);
	}
	io_uring_queue_exit(&rings[0]);
	if (two)
		io_uring_queue_exit(&rings[1]);
	return 0;
}
