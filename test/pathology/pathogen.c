/* SPDX-License-Identifier: MIT */
/*
 * pathogen.c - io_uring pathology injector.
 *
 * Each scenario deliberately induces one known io_uring pathology and
 * prints GROUND-TRUTH lines describing exactly what was injected. Run it
 * under uringscope and the doctor's findings can be scored against the
 * truth (test/pathology/run.sh automates this; the detection-effectiveness
 * table is generated from it).
 *
 * Build:  cc -O2 -o pathogen pathogen.c -luring
 * Usage:  pathogen <scenario> [args]
 *
 *   punt N            force N requests onto the io-wq pool (IOSQE_ASYNC)
 *   nobatch N         N reads at one SQE per io_uring_enter()
 *   overflow N        overflow the CQ ring ~N times (tiny CQ, no reaping)
 *   errors N          N completions with res < 0 (reads on a bad fd)
 *   leak K [SECS]     submit K reads that never complete; hold SECS (30)
 *   sqpoll-stall S    SQPOLL ring with a sparse duty cycle for S seconds
 *   worker-storm N    pin N distinct io-wq workers simultaneously
 *   uaf-unmap         munmap a buffer while a read into it is in flight
 *   uaf-reg           two concurrent kernel writers into one registered
 *                     buffer + unregister attempt while in flight
 *   reap-lag MS       let a ready CQE sit unreaped for MS milliseconds
 *
 * Scenarios marked FUTURE in run.sh exist as targets for detectors that
 * are designed but not yet shipped (buffer-hazard mode, reaping lag).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <liburing.h>

#define GT(fmt, ...) printf("GROUND-TRUTH " fmt "\n", ##__VA_ARGS__)

static void die(const char *what, int err)
{
	fprintf(stderr, "pathogen: %s: %s\n", what, strerror(err < 0 ? -err : err));
	exit(1);
}

static void reap_n(struct io_uring *ring, int n)
{
	struct io_uring_cqe *cqe;
	for (int i = 0; i < n; i++) {
		if (io_uring_wait_cqe(ring, &cqe))
			break;
		io_uring_cqe_seen(ring, cqe);
	}
}

/* ---- punt: force requests onto io-wq ---------------------------------- */
static int sc_punt(int n)
{
	struct io_uring ring;
	char tmpl[] = "/tmp/pathogen.XXXXXX", buf[4096];
	int fd, r;

	fd = mkstemp(tmpl);
	unlink(tmpl);
	memset(buf, 'x', sizeof(buf));
	for (int i = 0; i < 64; i++)
		if (write(fd, buf, sizeof(buf)) < 0)
			die("write", errno);

	if ((r = io_uring_queue_init(256, &ring, 0)))
		die("queue_init", r);

	int done = 0;
	while (done < n) {
		int batch = n - done > 128 ? 128 : n - done;
		for (int i = 0; i < batch; i++) {
			struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
			io_uring_prep_read(sqe, fd, buf, sizeof(buf),
					   (done + i) % 64 * 4096);
			sqe->flags |= IOSQE_ASYNC; /* the injection */
		}
		io_uring_submit_and_wait(&ring, batch);
		reap_n(&ring, batch);
		done += batch;
	}
	GT("scenario=punt injected_punts=%d opcode=READ mechanism=IOSQE_ASYNC", n);
	GT("expect=doctor tag=PUNT detail=punt-ratio~100%%");
	io_uring_queue_exit(&ring);
	close(fd);
	return 0;
}

/* ---- nobatch: one SQE per syscall -------------------------------------- */
static int sc_nobatch(int n)
{
	struct io_uring ring;
	char buf[512];
	int fd = open("/dev/zero", O_RDONLY), r;

	if ((r = io_uring_queue_init(8, &ring, 0)))
		die("queue_init", r);
	for (int i = 0; i < n; i++) {
		struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
		io_uring_prep_read(sqe, fd, buf, sizeof(buf), 0);
		io_uring_submit_and_wait(&ring, 1);   /* one enter per op */
		reap_n(&ring, 1);
	}
	GT("scenario=nobatch enters=%d sqes_per_enter=1.0", n);
	GT("expect=doctor tag=BATCH detail=avg~1.0");
	io_uring_queue_exit(&ring);
	close(fd);
	return 0;
}

/* ---- overflow: completions with nowhere to land ------------------------ */
static int sc_overflow(int n)
{
	struct io_uring ring;
	struct io_uring_params p = {};
	int r, submitted = 0;

	p.flags = IORING_SETUP_CQSIZE;
	p.cq_entries = 8;
	if ((r = io_uring_queue_init_params(8, &ring, &p)))
		die("queue_init_params", r);

	/* NOPs complete inline at submit; never reap until the end. */
	int target = n + (int)p.cq_entries;
	while (submitted < target) {
		int batch = target - submitted > 8 ? 8 : target - submitted;
		for (int i = 0; i < batch; i++)
			io_uring_prep_nop(io_uring_get_sqe(&ring));
		io_uring_submit(&ring);
		submitted += batch;
	}
	GT("scenario=overflow cq_entries=%u submitted_unreaped=%d expected_overflows>=%d",
	   p.cq_entries, submitted, n);
	GT("expect=doctor tag=OVERFLOW");
	reap_n(&ring, submitted);
	io_uring_queue_exit(&ring);
	return 0;
}

/* ---- errors: res < 0 completions --------------------------------------- */
static int sc_errors(int n)
{
	struct io_uring ring;
	char buf[64];
	int r;

	if ((r = io_uring_queue_init(256, &ring, 0)))
		die("queue_init", r);
	int done = 0;
	while (done < n) {
		int batch = n - done > 128 ? 128 : n - done;
		for (int i = 0; i < batch; i++) {
			struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
			io_uring_prep_read(sqe, -1, buf, sizeof(buf), 0);
		}
		io_uring_submit_and_wait(&ring, batch);
		reap_n(&ring, batch);
		done += batch;
	}
	GT("scenario=errors injected_errors=%d expected_errno=EBADF", n);
	GT("expect=doctor tag=ERRORS detail=error-rate~100%%");
	io_uring_queue_exit(&ring);
	return 0;
}

/* ---- leak: submitted, never completes ----------------------------------*/
static int sc_leak(int k, int hold)
{
	struct io_uring ring;
	static char bufs[64][256];
	int pfd[2], r;

	if (k > 64) k = 64;
	if (pipe(pfd))
		die("pipe", errno);
	if ((r = io_uring_queue_init(128, &ring, 0)))
		die("queue_init", r);

	for (int i = 0; i < k; i++) {
		struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
		io_uring_prep_read(sqe, pfd[0], bufs[i], sizeof(bufs[i]), 0);
		/* an app-meaningful token the doctor should echo back */
		io_uring_sqe_set_data64(sqe, 0xDEAD0000 + i);
	}
	io_uring_submit(&ring);
	GT("scenario=leak leaked=%d opcode=READ user_data_base=0xdead0000 hold_s=%d",
	   k, hold);
	GT("expect=doctor tag=LEAK detail=count=%d", k);
	/* hold them in flight; uringscope's window must end before we do */
	sleep(hold);
	io_uring_queue_exit(&ring);
	return 0;
}

/* ---- sqpoll-stall: a poller you paid a core for, asleep ----------------*/
static int sc_sqpoll(int secs)
{
	struct io_uring ring;
	struct io_uring_params p = {};
	int r;

	p.flags = IORING_SETUP_SQPOLL;
	p.sq_thread_idle = 100; /* ms: sleeps quickly between our sparse ops */
	if ((r = io_uring_queue_init_params(64, &ring, &p))) {
		if (r == -EPERM)
			die("SQPOLL needs a newer kernel or privileges", r);
		die("queue_init_params", r);
	}

	int iters = secs * 2;
	for (int i = 0; i < iters; i++) {
		io_uring_prep_nop(io_uring_get_sqe(&ring));
		io_uring_submit(&ring);   /* handles NEED_WAKEUP */
		reap_n(&ring, 1);
		usleep(500000);           /* 0.5s gap >> sq_thread_idle */
	}
	GT("scenario=sqpoll-stall duty_cycle=sparse idle_ms=%u window_s=%d "
	   "expected_offcpu_pct>=50", p.sq_thread_idle, secs);
	GT("expect=doctor tag=SQPOLL detail=off-CPU");
	io_uring_queue_exit(&ring);
	return 0;
}

/* ---- worker-storm: pin N distinct io-wq workers at once ----------------*/
static int sc_worker_storm(int n)
{
	struct io_uring ring;
	int (*pfds)[2], r, devnull;

	if (n > 256) n = 256;
	pfds = calloc(n, sizeof(*pfds));
	for (int i = 0; i < n; i++)
		if (pipe(pfds[i]))
			die("pipe (raise ulimit -n?)", errno);
	if ((devnull = open("/dev/null", O_WRONLY)) < 0)
		die("open /dev/null", errno);
	if ((r = io_uring_queue_init(512, &ring, 0)))
		die("queue_init", r);

	/* Pin each worker with a SPLICE out of an empty pipe. io_uring
	 * never issues splice nonblocking and splice cannot arm poll (two
	 * fds), so the worker truly blocks in do_splice until pipe data
	 * shows up. (Plain empty-pipe READs stopped pinning workers around
	 * v5.7: the worker poll-arms and goes free. The out-fd must not be
	 * a regular file, or io-wq hashes the work by inode and runs all of
	 * it on ONE worker.) */
	for (int i = 0; i < n; i++) {
		struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
		io_uring_prep_splice(sqe, pfds[i][0], -1, devnull, -1, 1, 0);
	}
	io_uring_submit(&ring);
	sleep(2); /* workers now exist and are blocked; let the scope see them */
	GT("scenario=worker-storm expected_distinct_workers~=%d pool=unbounded", n);
	GT("expect=doctor tag=WORKERS");
	for (int i = 0; i < n; i++)
		if (write(pfds[i][1], "x", 1) < 0)
			die("write", errno);
	reap_n(&ring, n);
	io_uring_queue_exit(&ring);
	close(devnull);
	free(pfds);
	return 0;
}

/* ---- uaf-unmap: free the buffer while the kernel still owes a write ----*/
static int sc_uaf_unmap(void)
{
	struct io_uring ring;
	struct io_uring_cqe *cqe;
	int pfd[2], r;
	char *buf;

	if (pipe(pfd))
		die("pipe", errno);
	buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED)
		die("mmap", errno);
	if ((r = io_uring_queue_init(8, &ring, 0)))
		die("queue_init", r);

	struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
	io_uring_prep_read(sqe, pfd[0], buf, 4096, 0);
	sqe->flags |= IOSQE_ASYNC;  /* ensure the copy happens later, on io-wq */
	io_uring_submit(&ring);
	usleep(200000);             /* worker is now blocked on the empty pipe */

	munmap(buf, 4096);          /* the bug: buffer dies, request lives */
	GT("scenario=uaf-unmap injected=munmap-while-in-flight buf=%p len=4096",
	   (void *)buf);

	if (write(pfd[1], "boom", 4) < 0)  /* kernel now writes into the hole */
		die("write", errno);
	io_uring_wait_cqe(&ring, &cqe);
	GT("scenario=uaf-unmap observed_res=%d expected=-EFAULT(-14)", cqe->res);
	GT("expect=hazard-mode tag=UAF detail=unmap-overlap (FUTURE detector); "
	   "today visible only as an error completion");
	io_uring_cqe_seen(&ring, cqe);
	io_uring_queue_exit(&ring);
	return 0;
}

/* ---- uaf-reg: racing writers into one registered buffer ----------------*/
/*
 * The hazard: two concurrent reads into the SAME range of one registered
 * buffer. Both complete with res>0 (both "succeed"), yet only one payload
 * survives in memory -- the other writer's bytes are silently overwritten
 * and no error is ever returned. A consumer who trusted the clobbered
 * read's success CQE now reads the wrong process's data.
 *
 * This injector doesn't just set the race up; it PROVES it fired, by
 * giving each read a distinguishable 4 KiB payload and checking afterward
 * that the shared range holds exactly one of them. The HAZARD-CONFIRMED
 * ground-truth line is what test/pathology/run.sh scores, so the reproduction
 * is trustworthy rather than hoped-for.
 */
static int sc_uaf_reg(void)
{
	struct io_uring ring;
	struct io_uring_cqe *cqe;
	static char regbuf[8192];
	struct iovec iov = { .iov_base = regbuf, .iov_len = sizeof(regbuf) };
	char a_pay[4096], b_pay[4096];
	int p1[2], p2[2], r, res_a = -1, res_b = -1, na = 0, nb = 0;
	char winner, loser;
	pid_t helper;

	memset(a_pay, 'A', sizeof(a_pay));
	memset(b_pay, 'B', sizeof(b_pay));
	memset(regbuf, 0, sizeof(regbuf));

	if (pipe(p1) || pipe(p2))
		die("pipe", errno);
	if ((r = io_uring_queue_init(8, &ring, 0)))
		die("queue_init", r);
	if ((r = io_uring_register_buffers(&ring, &iov, 1)))
		die("register_buffers", r);

	/* Two reads into the SAME registered range [0,4096), forced onto
	 * io-wq so they are genuinely concurrent in-flight writers. */
	struct io_uring_sqe *a = io_uring_get_sqe(&ring);
	io_uring_prep_read_fixed(a, p1[0], regbuf, sizeof(a_pay), 0, 0);
	a->flags |= IOSQE_ASYNC;
	io_uring_sqe_set_data64(a, 'A');
	struct io_uring_sqe *b = io_uring_get_sqe(&ring);
	io_uring_prep_read_fixed(b, p2[0], regbuf, sizeof(b_pay), 0, 0);
	b->flags |= IOSQE_ASYNC;
	io_uring_sqe_set_data64(b, 'B');
	io_uring_submit(&ring);
	usleep(200000);  /* both now parked in io-wq, genuinely in flight */
	GT("scenario=uaf-reg injected=overlapping-inflight buf_index=0 "
	   "range=[0,4096) writers=2");

	/* Second hazard: unregister while those reads are still in flight.
	 * A forked helper delivers each payload from another process, so the
	 * unregister overlaps in-flight reads whether the kernel returns
	 * immediately (refcount keeps the node alive) or blocks until they
	 * drain (the ~v5.13..v6.12 rsrc-quiesce path). Without this the
	 * unregister could wait forever for bytes the parent hasn't sent. */
	helper = fork();
	if (helper < 0)
		die("fork", errno);
	if (helper == 0) {
		usleep(300000);
		if (write(p1[1], a_pay, sizeof(a_pay)) != (ssize_t)sizeof(a_pay) ||
		    write(p2[1], b_pay, sizeof(b_pay)) != (ssize_t)sizeof(b_pay))
			_exit(1);
		_exit(0);
	}
	r = io_uring_unregister_buffers(&ring);
	GT("scenario=uaf-reg unregister_while_inflight ret=%d "
	   "(0=kernel kept node alive via refcount; -EBUSY on older kernels)", r);

	for (int i = 0; i < 2; i++) {
		if (io_uring_wait_cqe(&ring, &cqe))
			break;
		if (io_uring_cqe_get_data64(cqe) == 'A')
			res_a = cqe->res;
		else
			res_b = cqe->res;
		io_uring_cqe_seen(&ring, cqe);
	}
	waitpid(helper, NULL, 0);

	/* Both reads delivered a full 4 KiB; the surviving range can hold
	 * only one of them. That is the silent corruption, made visible. */
	for (size_t i = 0; i < sizeof(a_pay); i++) {
		if (regbuf[i] == 'A') na++;
		else if (regbuf[i] == 'B') nb++;
	}
	winner = (na == (int)sizeof(a_pay)) ? 'A'
	       : (nb == (int)sizeof(b_pay)) ? 'B' : '?';
	loser  = winner == 'A' ? 'B' : 'A';
	GT("scenario=uaf-reg res_a=%d res_b=%d buffer_winner=%c a_bytes=%d b_bytes=%d",
	   res_a, res_b, winner, na, nb);
	if (res_a == (int)sizeof(a_pay) && res_b == (int)sizeof(b_pay) &&
	    winner != '?')
		GT("scenario=uaf-reg HAZARD-CONFIRMED silent-corruption: both reads "
		   "succeeded (res=4096) yet writer '%c' was clobbered with no error",
		   loser);
	else
		GT("scenario=uaf-reg HAZARD-NOT-REPRODUCED res_a=%d res_b=%d winner=%c",
		   res_a, res_b, winner);
	GT("expect=hazard-mode tag=BUF-RACE (FUTURE detector); kernel-side "
	   "tracking of (buf_index,range) ownership through completion");

	io_uring_queue_exit(&ring);
	close(p1[0]); close(p1[1]); close(p2[0]); close(p2[1]);
	return 0;
}

/* ---- reap-lag: ready CQE, lazy application -----------------------------*/
static int sc_reap_lag(int ms)
{
	struct io_uring ring;
	char buf[64];
	int pfd[2], r;

	if (pipe(pfd))
		die("pipe", errno);
	if (write(pfd[1], "ready", 5) < 0)
		die("write", errno);
	if ((r = io_uring_queue_init(8, &ring, 0)))
		die("queue_init", r);

	struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
	io_uring_prep_read(sqe, pfd[0], buf, sizeof(buf), 0);
	io_uring_submit(&ring);          /* completes ~immediately */
	usleep(ms * 1000);               /* ...and sits in the CQ, ignored */
	reap_n(&ring, 1);
	GT("scenario=reap-lag cqe_ready_unreaped_ms~=%d", ms);
	GT("expect=uprobe-mode tag=REAP-LAG (FUTURE: liburing uprobe "
	   "enrichment measures CQE-ready -> reap)");
	io_uring_queue_exit(&ring);
	return 0;
}

int main(int argc, char **argv)
{
	const char *s = argc > 1 ? argv[1] : "";
	int a = argc > 2 ? atoi(argv[2]) : 0;
	int b = argc > 3 ? atoi(argv[3]) : 0;

	/* GROUND-TRUTH must reach the log even if a scenario wedges and
	 * gets killed; redirected stdout is fully buffered by default. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	if (!strcmp(s, "punt"))         return sc_punt(a ?: 5000);
	if (!strcmp(s, "nobatch"))      return sc_nobatch(a ?: 3000);
	if (!strcmp(s, "overflow"))     return sc_overflow(a ?: 1000);
	if (!strcmp(s, "errors"))       return sc_errors(a ?: 500);
	if (!strcmp(s, "leak"))         return sc_leak(a ?: 16, b ?: 30);
	if (!strcmp(s, "sqpoll-stall")) return sc_sqpoll(a ?: 6);
	if (!strcmp(s, "worker-storm")) return sc_worker_storm(a ?: 64);
	if (!strcmp(s, "uaf-unmap"))    return sc_uaf_unmap();
	if (!strcmp(s, "uaf-reg"))      return sc_uaf_reg();
	if (!strcmp(s, "reap-lag"))     return sc_reap_lag(a ?: 800);

	fprintf(stderr,
		"usage: pathogen punt|nobatch|overflow|errors|leak|sqpoll-stall|"
		"worker-storm|uaf-unmap|uaf-reg|reap-lag [N] [SECS]\n");
	return 2;
}
