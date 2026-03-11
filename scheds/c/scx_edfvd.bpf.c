/* SPDX-License-Identifier: GPL-2.0 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

void BPF_STRUCT_OPS(edfvd_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(edfvd_ops,
	       .exit			= (void *)edfvd_exit,
		   .flags			= SCX_OPS_SWITCH_PARTIAL,
	       .name			= "edfvd");
