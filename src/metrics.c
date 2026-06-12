/* SPDX-License-Identifier: MIT */
/*
 * metrics.c - a /metrics endpoint with no HTTP library.
 *
 * One background thread runs a single-threaded accept -> read request ->
 * write OpenMetrics text -> close loop. That is the whole server: no
 * keep-alive, no routing beyond "every GET gets /metrics", no TLS. A
 * scraper (or curl) gets a complete close-delimited HTTP/1.0 response.
 *
 * The thread reads only the snapshot the main loop pushes through
 * metrics_update() (mutex-guarded copy), never the BPF maps, so map
 * access stays single-threaded.
 *
 * Label honesty: per-opcode stats are aggregated across rings in the
 * kernel (a per-(ring,opcode) split would put a second map lookup on the
 * submit fast path for a label). ring_fd is therefore exact when the
 * report saw exactly one ring -- the common case -- and "all" otherwise.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "metrics.h"
#include "opnames.h"

static pthread_t srv_thread;
static pthread_mutex_t snap_lock = PTHREAD_MUTEX_INITIALIZER;
static struct us_report snap;
static int have_snap;
static int listen_fd = -1;
static volatile int running;

static void ring_label(const struct us_report *r, char *buf, size_t len)
{
	if (r->nrings == 1)
		snprintf(buf, len, "%u", r->rings[0].fd);
	else
		snprintf(buf, len, "all");
}

static void write_body(FILE *f, const struct us_report *r)
{
	char rfd[16];

	ring_label(r, rfd, sizeof(rfd));

	fprintf(f, "# TYPE uringscope_submissions counter\n");
	for (int i = 0; i < MAX_OPS; i++)
		if (r->ops[i].submitted)
			fprintf(f, "uringscope_submissions_total{opcode=\"%s\",ring_fd=\"%s\"} %llu\n",
				op_name(i), rfd,
				(unsigned long long)r->ops[i].submitted);

	fprintf(f, "# TYPE uringscope_completions counter\n");
	for (int i = 0; i < MAX_OPS; i++)
		if (r->ops[i].completed)
			fprintf(f, "uringscope_completions_total{opcode=\"%s\",ring_fd=\"%s\"} %llu\n",
				op_name(i), rfd,
				(unsigned long long)r->ops[i].completed);

	fprintf(f, "# TYPE uringscope_punts counter\n");
	for (int i = 0; i < MAX_OPS; i++)
		if (r->ops[i].punted)
			fprintf(f, "uringscope_punts_total{opcode=\"%s\",ring_fd=\"%s\"} %llu\n",
				op_name(i), rfd,
				(unsigned long long)r->ops[i].punted);

	/* submit->complete latency, one cumulative bucket per log2(ns) slot
	 * that the kernel histogram tracks; le is the bucket bound in
	 * seconds, prometheus-style, with the +Inf/_count/_sum trio */
	fprintf(f, "# TYPE uringscope_latency histogram\n");
	for (int i = 0; i < MAX_OPS; i++) {
		const struct opstat *o = &r->ops[i];
		__u64 acc = 0, total = 0;

		if (!o->completed)
			continue;
		for (int s = 0; s < NLAT_SLOTS; s++)
			total += o->hist[s];
		for (int s = 0; s < NLAT_SLOTS; s++) {
			if (!o->hist[s] && acc != total)
				continue; /* skip empty leading/inner slots */
			acc += o->hist[s];
			fprintf(f, "uringscope_latency_bucket{opcode=\"%s\",le=\"%.9g\"} %llu\n",
				op_name(i), (double)(1ULL << (s + 1)) / 1e9,
				(unsigned long long)acc);
			if (acc == total)
				break;
		}
		fprintf(f, "uringscope_latency_bucket{opcode=\"%s\",le=\"+Inf\"} %llu\n",
			op_name(i), (unsigned long long)total);
		fprintf(f, "uringscope_latency_count{opcode=\"%s\"} %llu\n",
			op_name(i), (unsigned long long)total);
		fprintf(f, "uringscope_latency_sum{opcode=\"%s\"} %.9f\n",
			op_name(i), o->lat_sum_ns / 1e9);
	}

	fprintf(f, "# TYPE uringscope_cq_depth gauge\n");
	fprintf(f, "uringscope_cq_depth %.3f\n",
		r->c[C_CQ_DEPTH_SAMPLES] ?
		(double)r->c[C_CQ_DEPTH_SUM] / r->c[C_CQ_DEPTH_SAMPLES] : 0.0);

	fprintf(f, "# TYPE uringscope_sqpoll_offcpu_seconds counter\n");
	fprintf(f, "uringscope_sqpoll_offcpu_seconds_total %.9f\n",
		r->c[C_SQPOLL_OFFCPU_NS] / 1e9);

	fprintf(f, "# TYPE uringscope_workers_distinct counter\n");
	fprintf(f, "uringscope_workers_distinct_total %llu\n",
		(unsigned long long)r->c[C_WORKERS_SEEN]);

	fprintf(f, "# EOF\n");
}

static void *serve(void *arg)
{
	while (running) {
		char req[1024];
		struct us_report local;
		int have;
		int cfd = accept(listen_fd, NULL, NULL);
		FILE *f;

		if (cfd < 0)
			break; /* listen fd closed by metrics_stop() */
		/* drain whatever request line arrived; every GET is /metrics */
		if (read(cfd, req, sizeof(req)) < 0) {
			close(cfd);
			continue;
		}
		pthread_mutex_lock(&snap_lock);
		local = snap;
		have = have_snap;
		pthread_mutex_unlock(&snap_lock);

		f = fdopen(cfd, "w");
		if (!f) {
			close(cfd);
			continue;
		}
		fprintf(f, "HTTP/1.0 200 OK\r\n"
			"Content-Type: application/openmetrics-text; "
			"version=1.0.0; charset=utf-8\r\n"
			"Connection: close\r\n\r\n");
		if (have)
			write_body(f, &local);
		else
			fprintf(f, "# EOF\n");
		fclose(f); /* closes cfd */
	}
	return NULL;
}

int metrics_start(const char *spec)
{
	char host[128] = "0.0.0.0";
	struct sockaddr_in addr = {};
	const char *colon = strrchr(spec, ':');
	int port, one = 1;

	if (colon) {
		size_t hlen = colon - spec;
		if (hlen >= sizeof(host))
			hlen = sizeof(host) - 1;
		if (hlen)
			memcpy(host, spec, hlen), host[hlen] = 0;
		port = atoi(colon + 1);
	} else {
		port = atoi(spec);
	}
	if (port <= 0 || port > 65535) {
		fprintf(stderr, "uringscope: --metrics: bad [HOST:]PORT '%s'\n",
			spec);
		return -1;
	}

	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd < 0)
		return -1;
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((unsigned short)port);
	if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
		fprintf(stderr, "uringscope: --metrics: bad host '%s'\n", host);
		close(listen_fd);
		return -1;
	}
	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) ||
	    listen(listen_fd, 8)) {
		fprintf(stderr, "uringscope: --metrics: cannot listen on "
			"%s:%d: %m\n", host, port);
		close(listen_fd);
		return -1;
	}
	running = 1;
	if (pthread_create(&srv_thread, NULL, serve, NULL)) {
		close(listen_fd);
		running = 0;
		return -1;
	}
	fprintf(stderr, "uringscope: serving OpenMetrics at "
		"http://%s:%d/metrics\n", host, port);
	return 0;
}

void metrics_update(const struct us_report *r)
{
	pthread_mutex_lock(&snap_lock);
	snap = *r;
	have_snap = 1;
	pthread_mutex_unlock(&snap_lock);
}

void metrics_stop(void)
{
	if (!running)
		return;
	running = 0;
	shutdown(listen_fd, SHUT_RDWR);
	close(listen_fd);
	pthread_join(srv_thread, NULL);
}
