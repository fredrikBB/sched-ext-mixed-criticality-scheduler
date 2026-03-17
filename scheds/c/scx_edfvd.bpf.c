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

struct edf_lo_node {
	struct bpf_rb_node rb_node;
	u64 deadline_ns;
	s32 pid;
};

struct edf_hi_node {
	struct bpf_rb_node rb_node;
	u64 deadline_ns;
	s32 pid;
};

private(EDFVD_LO_TREE) struct bpf_spin_lock lo_tree_lock;
private(EDFVD_LO_TREE) struct bpf_rb_root lo_tree
	__contains(edf_lo_node, rb_node);

private(EDFVD_HI_TREE) struct bpf_spin_lock hi_tree_lock;
private(EDFVD_HI_TREE) struct bpf_rb_root hi_tree
	__contains(edf_hi_node, rb_node);

struct edf_lo_node_stash {
	struct edf_lo_node __kptr *node;
};

struct edf_hi_node_stash {
	struct edf_hi_node __kptr *node;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TASKS);
	__type(key, s32);
	__type(value, struct edf_lo_node_stash);
} lo_node_stash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TASKS);
	__type(key, s32);
	__type(value, struct edf_hi_node_stash);
} hi_node_stash SEC(".maps");

static bool edf_tree_less_lo(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct edf_lo_node *node_a, *node_b;
	node_a = container_of(a, struct edf_lo_node, rb_node);
	node_b = container_of(b, struct edf_lo_node, rb_node);
	return node_a->deadline_ns < node_b->deadline_ns;
}

static bool edf_tree_less_hi(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct edf_hi_node *node_a, *node_b;
	node_a = container_of(a, struct edf_hi_node, rb_node);
	node_b = container_of(b, struct edf_hi_node, rb_node);
	return node_a->deadline_ns < node_b->deadline_ns;
}

static s32 edf_tree_insert_lo(struct task_ctx *tctx)
{
	struct edf_lo_node_stash empty = {}, *stash;
	struct edf_lo_node *node;
	pid_t pid;
	long ret;

	if (!tctx) {
		bpf_printk("Failed LO insert: NULL task context\n");
		return -1;
	}

	pid = tctx->pid;

	ret = bpf_map_update_elem(&lo_node_stash, &pid, &empty, BPF_NOEXIST);
	if (ret && ret != -EEXIST) {
		bpf_printk("Failed LO stash create for pid %d\n", pid);
		return -1;
	}

	stash = bpf_map_lookup_elem(&lo_node_stash, &pid);
	if (!stash) {
		bpf_printk("Failed LO stash lookup for pid %d\n", pid);
		return -1;
	}

	node = bpf_kptr_xchg(&stash->node, NULL);
	if (!node) {
		node = bpf_obj_new(struct edf_lo_node);
		if (!node) {
			bpf_printk("Failed LO node allocation for pid %d\n",
				   pid);
			return -1;
		}
	}

	node->deadline_ns = tctx->deadline_ns_lo;
	node->pid = pid;

	bpf_spin_lock(&lo_tree_lock);
	bpf_rbtree_add(&lo_tree, &node->rb_node, edf_tree_less_lo);
	bpf_spin_unlock(&lo_tree_lock);
	return 0;
}

static s32 edf_tree_insert_hi(struct task_ctx *tctx)
{
	struct edf_hi_node_stash empty = {}, *stash;
	struct edf_hi_node *node;
	pid_t pid;
	long ret;

	if (!tctx) {
		bpf_printk("Failed HI insert: NULL task context\n");
		return -1;
	}

	pid = tctx->pid;

	ret = bpf_map_update_elem(&hi_node_stash, &pid, &empty, BPF_NOEXIST);
	if (ret && ret != -EEXIST) {
		bpf_printk("Failed HI stash create for pid %d\n", pid);
		return -1;
	}

	stash = bpf_map_lookup_elem(&hi_node_stash, &pid);
	if (!stash) {
		bpf_printk("Failed HI stash lookup for pid %d\n", pid);
		return -1;
	}

	node = bpf_kptr_xchg(&stash->node, NULL);
	if (!node) {
		node = bpf_obj_new(struct edf_hi_node);
		if (!node) {
			bpf_printk("Failed HI node allocation for pid %d\n",
				   pid);
			return -1;
		}
	}

	node->deadline_ns = tctx->deadline_ns_hi;
	node->pid = pid;

	bpf_spin_lock(&hi_tree_lock);
	bpf_rbtree_add(&hi_tree, &node->rb_node, edf_tree_less_hi);
	bpf_spin_unlock(&hi_tree_lock);
	return 0;
}

static struct task_ctx *edf_tree_pop_lo(void)
{
	struct edf_lo_node *node;
	struct edf_lo_node_stash *stash;
	struct task_ctx *tctx;
	s32 pid;

	bpf_spin_lock(&lo_tree_lock);
	struct bpf_rb_node *rb_node = bpf_rbtree_first(&lo_tree);
	if (!rb_node) {
		bpf_spin_unlock(&lo_tree_lock);
		bpf_printk("LO tree is empty on pop\n");
		return NULL;
	}
	rb_node = bpf_rbtree_remove(&lo_tree, rb_node);
	bpf_spin_unlock(&lo_tree_lock);

	if (!rb_node)
		return NULL;

	node = container_of(rb_node, struct edf_lo_node, rb_node);
	pid = node->pid;

	tctx = bpf_map_lookup_elem(&task_ctx, &pid);

	stash = bpf_map_lookup_elem(&lo_node_stash, &pid);
	if (stash) {
		struct edf_lo_node *old = bpf_kptr_xchg(&stash->node, node);
		if (old)
			bpf_obj_drop(old);
	} else {
		bpf_obj_drop(node);
	}

	return tctx;
}

static struct task_ctx *edf_tree_pop_hi(void)
{
	struct edf_hi_node *node;
	struct edf_hi_node_stash *stash;
	struct task_ctx *tctx;
	s32 pid;

	bpf_spin_lock(&hi_tree_lock);
	struct bpf_rb_node *rb_node = bpf_rbtree_first(&hi_tree);
	if (!rb_node) {
		bpf_spin_unlock(&hi_tree_lock);
		bpf_printk("HI tree is empty on pop\n");
		return NULL;
	}
	rb_node = bpf_rbtree_remove(&hi_tree, rb_node);
	bpf_spin_unlock(&hi_tree_lock);

	if (!rb_node)
		return NULL;

	node = container_of(rb_node, struct edf_hi_node, rb_node);
	pid = node->pid;

	tctx = bpf_map_lookup_elem(&task_ctx, &pid);

	stash = bpf_map_lookup_elem(&hi_node_stash, &pid);
	if (stash) {
		struct edf_hi_node *old = bpf_kptr_xchg(&stash->node, node);
		if (old)
			bpf_obj_drop(old);
	} else {
		bpf_obj_drop(node);
	}

	return tctx;
}

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
