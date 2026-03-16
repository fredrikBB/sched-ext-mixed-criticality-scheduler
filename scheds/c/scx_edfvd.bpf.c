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

s32 BPF_STRUCT_OPS(edfvd_enable, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	pid_t pid = p->pid;
	bpf_printk("Task with pid %d entered SCX\n", pid);
	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx, &pid);
	if (tctx) {
		bpf_printk(
			"Task ctx for pid %d: task_nr=%llu, criticality=%s, period=%llu, modified_period=%llu, wcet_lo=%llu, wcet_hi=%llu\n",
			p->pid, tctx->task_nr,
			tctx->criticality == LO ? "LO" : "HI", tctx->period_ms,
			tctx->modified_period_ms, tctx->wcet_ms_lo,
			tctx->wcet_ms_hi);
	} else {
		bpf_printk(
			"No task ctx found for pid %d. Have you provided task context through bpf_map_update_elem()?\n",
			p->pid);
	}
	return 0;
}

void BPF_STRUCT_OPS(edfvd_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/* clang-format off */
SCX_OPS_DEFINE(edfvd_ops,
	.exit =			(void *)edfvd_exit,
	.enable =		(void *)edfvd_enable,
	.flags =		SCX_OPS_SWITCH_PARTIAL,
	.name =			"edfvd");
/* clang-format on */
