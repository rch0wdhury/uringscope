/* SPDX-License-Identifier: MIT */
/*
 * netecho.c - liburing TCP echo server for the uringscope evaluation grid.
 *
 * Exercises the lifecycle paths storage workloads don't: multishot accept,
 * multishot recv (one submit -> many CQEs with IORING_CQE_F_MORE), the
 * poll-retry path (sockets are rarely ready at submit), and send.
 *
 * Build:  cc -O2 -o netecho netecho.c -luring     (liburing >= 2.3)
 * Run:    ./netecho 7777
 * Drive:  any TCP load generator; e.g.
 *         for i in $(seq 64); do nc localhost 7777 < bigfile > /dev/null & done
 * Stats:  prints accepted/echoed counters on SIGINT.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <liburing.h>

#define QD        256
#define BUFSZ     4096
#define MAXCONN   1024

enum { OP_ACCEPT = 1, OP_RECV, OP_SEND };

/* user_data layout: type in the top byte, fd below. */
static inline __u64 ud(int type, int fd) { return ((__u64)type << 56) | (__u32)fd; }
static inline int ud_type(__u64 u) { return u >> 56; }
static inline int ud_fd(__u64 u)   { return (int)(u & 0xffffffff); }

static volatile sig_atomic_t stop;
static void on_int(int s) { stop = 1; }

static unsigned long n_accept, n_recv_cqe, n_echo_bytes;
static char bufs[MAXCONN][BUFSZ];

static void arm_recv(struct io_uring *ring, int fd)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	if (!sqe)
		return;
	/* Multishot recv: one SQE, completions keep flowing with CQE_F_MORE
	 * until the socket closes or the kernel says re-arm. */
	io_uring_prep_recv_multishot(sqe, fd, bufs[fd % MAXCONN], BUFSZ, 0);
	io_uring_sqe_set_data64(sqe, ud(OP_RECV, fd));
}

static void send_back(struct io_uring *ring, int fd, int len)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	if (!sqe)
		return;
	io_uring_prep_send(sqe, fd, bufs[fd % MAXCONN], len, 0);
	io_uring_sqe_set_data64(sqe, ud(OP_SEND, fd));
}

int main(int argc, char **argv)
{
	int port = argc > 1 ? atoi(argv[1]) : 7777;
	struct io_uring ring;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr.s_addr = htonl(INADDR_ANY),
	};
	int lfd, one = 1;

	signal(SIGINT, on_int);
	signal(SIGPIPE, SIG_IGN);

	lfd = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) ||
	    listen(lfd, 512)) {
		perror("bind/listen");
		return 1;
	}

	if (io_uring_queue_init(QD, &ring, 0)) {
		perror("io_uring_queue_init");
		return 1;
	}

	/* Multishot accept: one SQE accepts forever. */
	{
		struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
		io_uring_prep_multishot_accept(sqe, lfd, NULL, NULL, 0);
		io_uring_sqe_set_data64(sqe, ud(OP_ACCEPT, lfd));
	}

	fprintf(stderr, "netecho: listening on :%d (qd=%d)\n", port, QD);

	while (!stop) {
		struct io_uring_cqe *cqe;
		unsigned head, seen = 0;

		io_uring_submit_and_wait(&ring, 1);
		io_uring_for_each_cqe(&ring, head, cqe) {
			__u64 u = io_uring_cqe_get_data64(cqe);
			int res = cqe->res;

			seen++;
			switch (ud_type(u)) {
			case OP_ACCEPT:
				if (res >= 0) {
					n_accept++;
					arm_recv(&ring, res);
				}
				break;
			case OP_RECV:
				n_recv_cqe++;
				if (res > 0) {
					send_back(&ring, ud_fd(u), res);
					/* kernel asks for re-arm when MORE
					 * flag is absent */
					if (!(cqe->flags & IORING_CQE_F_MORE))
						arm_recv(&ring, ud_fd(u));
				} else if (res <= 0) {
					close(ud_fd(u));
				}
				break;
			case OP_SEND:
				if (res > 0)
					n_echo_bytes += res;
				break;
			}
		}
		io_uring_cq_advance(&ring, seen);
	}

	fprintf(stderr, "netecho: accepted=%lu recv_cqes=%lu echoed=%lu bytes\n",
		n_accept, n_recv_cqe, n_echo_bytes);
	io_uring_queue_exit(&ring);
	close(lfd);
	return 0;
}
