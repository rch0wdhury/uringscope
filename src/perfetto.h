/* SPDX-License-Identifier: MIT */
#ifndef US_PERFETTO_H
#define US_PERFETTO_H
#include <stdio.h>
#include "uringscope.h"

struct perfetto_writer {
	FILE *f;
	int first;
	unsigned char lane_named[MAX_OPS];
	unsigned long long n_events;
};

int perfetto_open(struct perfetto_writer *pw, const char *path);
int perfetto_handle_event(void *ctx, void *data, size_t len); /* ringbuf cb */
void perfetto_close(struct perfetto_writer *pw);
#endif
