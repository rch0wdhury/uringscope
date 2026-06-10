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
	doctor_run(c, ops, r, nr, lr, wall, ncpu);
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
		doctor_run(c, ops, r, 1, &lr, 5000000000ULL, 8);
		fflush(stdout); dup2(s, 1); close(s); close(fd);
		FILE *f = fopen(path, "r"); char b[8192];
		size_t n = fread(b, 1, sizeof(b) - 1, f); b[n] = 0; fclose(f);
		remove(path);
		int ok = strstr(b, "fell back to the io-wq") == NULL;
		printf("%-22s %s  (no false PUNT)\n", "nobatch-no-punt",
		       ok ? "PASS" : "FAIL");
		fails += !ok;
	}

	printf("\n%s (%d failures)\n", fails ? "FAILURES" : "all doctor unit tests passed",
	       fails);
	return fails ? 1 : 0;
}
