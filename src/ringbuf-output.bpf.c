// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Andrii Nakryiko */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include <stdint.h>

#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* BPF ringbuf map */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

struct switch_args {
    unsigned long long ignore;
    char prev_comm[16];
    int prev_pid;
    int prev_prio;
    long long prev_state;
    char next_comm[16];
    int next_pid;
    int next_prio;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct event);
} heap SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int tp_sched_switch(struct switch_args* args) {
	struct event e;

	e.pid = args->prev_pid;
	e.next_pid = args->next_pid;

	// if (bpf_get_prandom_u32() < 0xffffff)
      bpf_ringbuf_output(&rb, &e, sizeof(e), 0);
    return 0;
}
