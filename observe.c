//go:build ignore
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include "pid_iter.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// Ref Code: https://github.com/libbpf/bpftool/blob/64402b8ea43b2ef62ee8ba71d9b50a5e32603fd2/src/skeleton/pid_iter.bpf.c 
// BLOCKER!: https://github.com/cilium/ebpf/issues/1354

/* keep in sync with the definition in main.h */
enum bpf_obj_type {
	BPF_OBJ_UNKNOWN,
	BPF_OBJ_PROG,
	BPF_OBJ_MAP,
	BPF_OBJ_LINK,
	BPF_OBJ_BTF,
};

extern const void bpf_map_fops __ksym;
extern const void bpf_prog_fops __ksym;

const volatile enum bpf_obj_type obj_type = BPF_OBJ_UNKNOWN;

static __always_inline __u32 get_obj_id(void *ent, enum bpf_obj_type type)
{
	switch (type) {
	case BPF_OBJ_PROG:
		return BPF_CORE_READ((struct bpf_prog *)ent, aux, id);
	case BPF_OBJ_MAP:
		return BPF_CORE_READ((struct bpf_map *)ent, id);
	default:
		return 0;
	}
}

SEC("iter/task_file")
int iter(struct bpf_iter__task_file *ctx)
{
	struct file *file = ctx->file;
	struct task_struct *task = ctx->task;
	struct pid_iter_entry e;
	const void *fops;

	if (!file || !task)
		return 0;

	switch (obj_type) {
	case BPF_OBJ_PROG:
		fops = &bpf_prog_fops;
		break;
	case BPF_OBJ_MAP:
		fops = &bpf_map_fops;
		break;
	default:
		return 0;
	}

	if (file->f_op != fops)
		return 0;

	__builtin_memset(&e, 0, sizeof(e));
	e.pid = task->tgid;
	e.id = get_obj_id(file->private_data, obj_type);

	bpf_probe_read_kernel_str(&e.comm, sizeof(e.comm),
				  task->group_leader->comm);
	bpf_seq_write(ctx->meta->seq, &e, sizeof(e));

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
