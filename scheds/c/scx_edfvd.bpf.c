/* SPDX-License-Identifier: GPL-2.0 */
#include <scx/common.bpf.h>
#include "scx_edfvd.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TASKS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, s32);
	__type(value, struct task_ctx);
} task_ctx SEC(".maps");

s32 BPF_STRUCT_OPS(edfvd_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	pid_t pid = p->pid;
	bpf_printk("Initialzing task with pid %d\n", pid);
	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx, &pid);
	if (tctx) {
		bpf_printk(
			"Task ctx for pid %d: task_nr=%llu, criticality= %d, period=%llu, modified_period=%llu, wcet_lo=%llu, wcet_hi=%llu\n",
			p->pid, tctx->task_nr, tctx->criticality,
			tctx->period_ms, tctx->modified_period_ms,
			tctx->wcet_ms_lo, tctx->wcet_ms_hi);
	} else {
		bpf_printk("No task ctx found for pid %d\n", p->pid);
	}
	return 0;
}

void BPF_STRUCT_OPS(edfvd_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(edfvd_ops, .exit = (void *)edfvd_exit,
	       .init_task = (void *)edfvd_init_task,
	       .flags = SCX_OPS_SWITCH_PARTIAL, .name = "edfvd");
