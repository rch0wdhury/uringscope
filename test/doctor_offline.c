/* SPDX-License-Identifier: MIT */
/* Offline unit test for the doctor rules: feed synthetic counters/opstats
 * and a leak report, capture findings, assert the right tags fire. No
 * kernel needed -- this links the real src/doctor.c. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <stdlib.h>
#include "uringscope.h"
#include "doctor.h"

static int check(const char *name, const __u64 *c, const struct opstat *ops,
		 const struct ring_info *r, int nr,
		 const struct leak_report *lr, __u64 wall, int ncpu,
		 const char *must_contain)
{
	/* doctor_run writes to stdout; capture via a temp file. */
	char path[] = "/tmp/docXXXXXX";
	int fd = mkstemp(path);
	fflush(stdout);
	int saved = dup(1); dup2(fd, 1);
	doctor_run(c, ops, r, nr, lr, NULL, NULL, wall, ncpu);
	fflush(stdout); dup2(saved, 1); close(saved); close(fd);

	FILE *f = fopen(path, "r");
	char buf[8192]; size_t n = fread(buf, 1, sizeof(buf) - 1, f); buf[n] = 0;
	fclose(f); remove(path);

	int ok = must_contain ? (strstr(buf, must_contain) != NULL)
			      : (strstr(buf, "no pathologies detected") != NULL);
	printf("%-22s %s%s%s\n", name, ok ? "PASS" : "FAIL",
	       must_contain ? "  wants: " : "  wants: clean",
	       must_contain ? must_contain : "");
	return ok ? 0 : 1;
}

int main(void)
{
	int fails = 0;
	__u64 c[C_MAX]; struct opstat ops[MAX_OPS]; struct ring_info r[1];
	struct leak_report lr;

	/* clean baseline */
	memset(c, 0, sizeof(c)); memset(ops, 0, sizeof(ops));
	memset(&lr, 0, sizeof(lr));
	memset(r, 0, sizeof(r)); r[0].ctx = 0x1000; r[0].cq_entries = 256;
	c[C_SUBMIT] = 1000; c[C_COMPLETE] = 1000; c[C_RET_SUBMITTED] = 1000;
	c[C_ENTER] = 500;
	fails += check("clean", c, ops, r, 1, &lr, 5000000000ULL, 8, NULL);

	/* punt storm */
	c[C_PUNT] = 700; ops[22].submitted = 700; ops[22].punted = 700;
	fails += check("punt-storm", c, ops, r, 1, &lr, 5000000000ULL, 8,
		       "fell back to the io-wq");
	c[C_PUNT] = 0; memset(ops, 0, sizeof(ops));

	/* overflow */
	c[C_OVERFLOW] = 1204;
	fails += check("cq-overflow", c, ops, r, 1, &lr, 5000000000ULL, 8,
		       "CQ overflowed");
	c[C_OVERFLOW] = 0;

	/* batching: 1 sqe/enter */
	c[C_ENTER] = 100000; c[C_RET_SUBMITTED] = 100000;
	fails += check("nobatch", c, ops, r, 1, &lr, 5000000000ULL, 8,
		       "averaging only");
	c[C_ENTER] = 500; c[C_RET_SUBMITTED] = 1000;

	/* errors */
	c[C_ERRORS] = 600;
	fails += check("error-rate", c, ops, r, 1, &lr, 5000000000ULL, 8,
		       "returned res < 0");
	c[C_ERRORS] = 0;

	/* leak */
	lr.n = 4; lr.thresh_ns = 2000000000ULL; lr.oldest_ns = 9000000000ULL;
	lr.per_op[22] = 4; lr.nsample = 1; lr.sample_ud[0] = 0xdead0000;
	lr.sample_op[0] = 22;
	fails += check("leak", c, ops, r, 1, &lr, 20000000000ULL, 8, "submitted but never completed");

	/* leak finding must echo the user_data token for grep-ability */
	fails += check("leak-token", c, ops, r, 1, &lr, 20000000000ULL, 8,
		       "0xdead0000");
	memset(&lr, 0, sizeof(lr));

	/* negative: nobatch must NOT report PUNT */
	c[C_ENTER] = 100000; c[C_RET_SUBMITTED] = 100000;
	{
		char path[] = "/tmp/negXXXXXX"; int fd = mkstemp(path);
		fflush(stdout); int s = dup(1); dup2(fd, 1);
		doctor_run(c, ops, r, 1, &lr, NULL, NULL, 5000000000ULL, 8);
		fflush(stdout); dup2(s, 1); close(s); close(fd);
		FILE *f = fopen(path, "r"); char b[8192];
		size_t n = fread(b, 1, sizeof(b) - 1, f); b[n] = 0; fclose(f);
		remove(path);
		int ok = strstr(b, "fell back to the io-wq") == NULL;
		printf("%-22s %s  (no false PUNT)\n", "nobatch-no-punt",
		       ok ? "PASS" : "FAIL");
		fails += !ok;
	}

	/* hazard: overlapping in-flight buffer ranges, with grep-able tokens */
	{
		struct hazard_report hz; memset(&hz, 0, sizeof(hz));
		hz.n = 2; hz.nsample = 1;
		hz.samples[0].kind = TGT_BUFIDX;
		hz.samples[0].user_data_a = 0xaaaa;
		hz.samples[0].user_data_b = 0xbbbb;
		hz.samples[0].opcode_a = 4; hz.samples[0].opcode_b = 4;
		hz.samples[0].bufidx = 0;
		hz.samples[0].base = 0x1000; hz.samples[0].len = 4096;

		char path[] = "/tmp/hazXXXXXX"; int fd = mkstemp(path);
		fflush(stdout); int s = dup(1); dup2(fd, 1);
		doctor_run(c, ops, r, 1, &lr, &hz, NULL, 5000000000ULL, 8);
		fflush(stdout); dup2(s, 1); close(s); close(fd);
		FILE *f = fopen(path, "r"); char b[8192];
		size_t n = fread(b, 1, sizeof(b) - 1, f); b[n] = 0; fclose(f);
		remove(path);
		int ok = strstr(b, "overlapping in-flight buffer range") &&
			 strstr(b, "0xbbbb");
		printf("%-22s %s  wants: overlapping in-flight + token\n",
		       "hazard-overlap", ok ? "PASS" : "FAIL");
		fails += !ok;
	}

	/* hazard 3: registered-buffer lifetime violation echoes the index
	 * and the live-reference count */
	{
		struct hazard_report hz; memset(&hz, 0, sizeof(hz));
		hz.n_bufreg = 8; hz.nbufreg = 2;
		hz.bufreg[0].bufidx = 0; hz.bufreg[0].refs = 1;
		hz.bufreg[1].bufidx = 7; hz.bufreg[1].refs = 3;

		char path[] = "/tmp/brgXXXXXX"; int fd = mkstemp(path);
		fflush(stdout); int s = dup(1); dup2(fd, 1);
		doctor_run(c, ops, r, 1, &lr, &hz, NULL, 5000000000ULL, 8);
		fflush(stdout); dup2(s, 1); close(s); close(fd);
		FILE *f = fopen(path, "r"); char b[8192];
		size_t n = fread(b, 1, sizeof(b) - 1, f); b[n] = 0; fclose(f);
		remove(path);
		int ok = strstr(b, "unregistered buffer index 7") &&
			 strstr(b, "3 in-flight ops");
		printf("%-22s %s  wants: unregistered index + refcount\n",
		       "hazard-bufreg", ok ? "PASS" : "FAIL");
		fails += !ok;
	}

	/* hazard 1 (unmap variant): echoes range, opcode and user_data */
	{
		struct hazard_report hz; memset(&hz, 0, sizeof(hz));
		hz.n_unmap = 1; hz.nunmap = 1;
		hz.unmap[0].user_data = 0xfeed;
		hz.unmap[0].base = 0x7f0000000000ULL;
		hz.unmap[0].len = 4096;
		hz.unmap[0].opcode = 22; /* READ */

		char path[] = "/tmp/unmXXXXXX"; int fd = mkstemp(path);
		fflush(stdout); int s = dup(1); dup2(fd, 1);
		doctor_run(c, ops, r, 1, &lr, &hz, NULL, 5000000000ULL, 8);
		fflush(stdout); dup2(s, 1); close(s); close(fd);
		FILE *f = fopen(path, "r"); char b[8192];
		size_t n = fread(b, 1, sizeof(b) - 1, f); b[n] = 0; fclose(f);
		remove(path);
		int ok = strstr(b, "munmap of [0x7f0000000000,+4096)") &&
			 strstr(b, "READ") && strstr(b, "0xfeed");
		printf("%-22s %s  wants: munmap range + READ + token\n",
		       "hazard-unmap", ok ? "PASS" : "FAIL");
		fails += !ok;
	}

	/* false-positive guard: a --check run that saw NO hazards must not
	 * print any hazard finding */
	{
		struct hazard_report hz; memset(&hz, 0, sizeof(hz));

		char path[] = "/tmp/hz0XXXXXX"; int fd = mkstemp(path);
		fflush(stdout); int s = dup(1); dup2(fd, 1);
		doctor_run(c, ops, r, 1, &lr, &hz, NULL, 5000000000ULL, 8);
		fflush(stdout); dup2(s, 1); close(s); close(fd);
		FILE *f = fopen(path, "r"); char b[8192];
		size_t n = fread(b, 1, sizeof(b) - 1, f); b[n] = 0; fclose(f);
		remove(path);
		int ok = !strstr(b, "unregistered buffer index") &&
			 !strstr(b, "munmap of") &&
			 !strstr(b, "overlapping in-flight");
		printf("%-22s %s  (no false HAZARD-*)\n", "hazard-clean",
		       ok ? "PASS" : "FAIL");
		fails += !ok;
	}

	/* reap lag (uprobe e2e): one 800ms straggler must fire ... */
	{
		struct e2e_report er; memset(&er, 0, sizeof(er));
		er.available = 1;
		er.reap_n = 1;
		er.reap_sum_ns = 800000000ULL;
		er.reap_hist[29] = 1; /* 2^30ns ~ 1.07s bucket */

		char path[] = "/tmp/rlgXXXXXX"; int fd = mkstemp(path);
		fflush(stdout); int s = dup(1); dup2(fd, 1);
		doctor_run(c, ops, r, 1, &lr, NULL, &er, 5000000000ULL, 8);
		fflush(stdout); dup2(s, 1); close(s); close(fd);
		FILE *f = fopen(path, "r"); char b[8192];
		size_t n = fread(b, 1, sizeof(b) - 1, f); b[n] = 0; fclose(f);
		remove(path);
		int ok = strstr(b, "CQEs sat ready") != NULL;
		printf("%-22s %s  wants: CQEs sat ready\n", "reap-lag",
		       ok ? "PASS" : "FAIL");
		fails += !ok;
	}

	/* ... and healthy microsecond-scale reaping must NOT */
	{
		struct e2e_report er; memset(&er, 0, sizeof(er));
		er.available = 1;
		er.reap_n = 10000;
		er.reap_sum_ns = 10000 * 5000ULL;   /* avg 5us */
		er.reap_hist[12] = 9900;            /* ~8us bucket */
		er.reap_hist[16] = 100;             /* p99 ~ 131us < 500us */

		char path[] = "/tmp/rl0XXXXXX"; int fd = mkstemp(path);
		fflush(stdout); int s = dup(1); dup2(fd, 1);
		doctor_run(c, ops, r, 1, &lr, NULL, &er, 5000000000ULL, 8);
		fflush(stdout); dup2(s, 1); close(s); close(fd);
		FILE *f = fopen(path, "r"); char b[8192];
		size_t n = fread(b, 1, sizeof(b) - 1, f); b[n] = 0; fclose(f);
		remove(path);
		int ok = strstr(b, "CQEs sat ready") == NULL;
		printf("%-22s %s  (no false REAP-LAG)\n", "reap-fast",
		       ok ? "PASS" : "FAIL");
		fails += !ok;
	}

	/* worker storm: a 64-worker fan-out must fire even on a many-core box,
	 * where 2*ncpu would otherwise exceed 64 and miss it (the regression). */
	memset(c, 0, sizeof(c));
	c[C_WORKERS_SEEN] = 64;
	fails += check("worker-storm", c, ops, r, 1, &lr, 5000000000ULL,
		       64 /* ncpu: a high core count is where the old bar missed */,
		       "distinct worker threads");

	/* negative: a normal handful of workers must NOT report WORKERS */
	memset(c, 0, sizeof(c));
	c[C_WORKERS_SEEN] = 6;
	{
		char path[] = "/tmp/wrkXXXXXX"; int fd = mkstemp(path);
		fflush(stdout); int s = dup(1); dup2(fd, 1);
		doctor_run(c, ops, r, 1, &lr, NULL, NULL, 5000000000ULL, 8);
		fflush(stdout); dup2(s, 1); close(s); close(fd);
		FILE *f = fopen(path, "r"); char b[8192];
		size_t n = fread(b, 1, sizeof(b) - 1, f); b[n] = 0; fclose(f);
		remove(path);
		int ok = strstr(b, "distinct worker threads") == NULL;
		printf("%-22s %s  (no false WORKERS)\n", "worker-handful",
		       ok ? "PASS" : "FAIL");
		fails += !ok;
	}

	printf("\n%s (%d failures)\n", fails ? "FAILURES" : "all doctor unit tests passed",
	       fails);
	return fails ? 1 : 0;
}
