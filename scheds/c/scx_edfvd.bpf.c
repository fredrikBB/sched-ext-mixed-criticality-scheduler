/* SPDX-License-Identifier: GPL-2.0 */
#include <scx/common.bpf.h>
#include "scx_edfvd.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

static bool in_hi_crit_mode = false;

/* Map to store task contexts with pid as key */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TASKS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, s32);
	__type(value, struct task_ctx);
} task_ctx SEC(".maps");

/*
 * Map to store deadlines for running tasks.
 * Needed to enable the preemption logic of running tasks.
 * The run queues (lo_tree and hi_tree) does not store running tasks
 * (only runnable ones).
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32)); /* CPU ID */
	__uint(value_size, sizeof(u64)); /* Deadline (ns) */
	__uint(max_entries, NO_CPUS);
} cpu_deadlines SEC(".maps");

/*
 * EDF-VD run queues:
 * - lo_tree: Runnable tasks for LO-criticality mode, ordered by earliest deadline_ns.
 * - hi_tree: Runnable tasks for HI-criticality mode, ordered by earliest deadline_ns.
 *
 * The tree stores allocated edf_node_* objects internally.
 * Insert and pop operations are provided and operates on task_ctx objects.
 * Duplicate insertions updates the node, and does not create a new node.
 */

struct edf_node_lo {
	struct bpf_rb_node rb_node;
	u64 deadline_ns;
	pid_t pid;
	u8 queued; /* To avoid duplicate insertions */
};

struct edf_node_hi {
	struct bpf_rb_node rb_node;
	u64 deadline_ns;
	pid_t pid;
	u8 queued; /* To avoid duplicate insertions */
};

private(EDFVD_LO_TREE) struct bpf_spin_lock lo_tree_lock;
private(EDFVD_LO_TREE) struct bpf_rb_root lo_tree
	__contains(edf_node_lo, rb_node);

private(EDFVD_HI_TREE) struct bpf_spin_lock hi_tree_lock;
private(EDFVD_HI_TREE) struct bpf_rb_root hi_tree
	__contains(edf_node_hi, rb_node);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TASKS);
	__type(key, pid_t);
	__type(value, struct edf_node_lo);
} edf_map_lo SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TASKS);
	__type(key, pid_t);
	__type(value, struct edf_node_hi);
} edf_map_hi SEC(".maps");

static bool edf_tree_less_lo(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct edf_node_lo *node_a, *node_b;
	node_a = container_of(a, struct edf_node_lo, rb_node);
	node_b = container_of(b, struct edf_node_lo, rb_node);
	return node_a->deadline_ns < node_b->deadline_ns;
}

static bool edf_tree_less_hi(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct edf_node_hi *node_a, *node_b;
	node_a = container_of(a, struct edf_node_hi, rb_node);
	node_b = container_of(b, struct edf_node_hi, rb_node);
	return node_a->deadline_ns < node_b->deadline_ns;
}

/* Duplicate insertions updates node */
static s32 edf_tree_insert_lo(struct task_ctx *tctx)
{
	struct edf_node_lo node_val = {};
	struct edf_node_lo *cached;
	struct edf_node_lo *node;
	pid_t pid;
	long ret;

	if (!tctx) {
		bpf_printk("Failed LO insert: NULL task context\n");
		return -1;
	}

	pid = tctx->pid;

	cached = bpf_map_lookup_elem(&edf_map_lo, &pid);
	if (cached) {
		cached->deadline_ns = tctx->deadline_ns_lo;
		cached->pid = pid;
		if (cached->queued)
			return 0;
		cached->queued = 1;
	} else {
		node_val.deadline_ns = tctx->deadline_ns_lo;
		node_val.pid = pid;
		node_val.queued = 1;

		ret = bpf_map_update_elem(&edf_map_lo, &pid, &node_val,
					  BPF_NOEXIST);
		if (ret) {
			bpf_printk("Failed LO map update for pid %d\n", pid);
			return -1;
		}

		cached = bpf_map_lookup_elem(&edf_map_lo, &pid);
		if (!cached) {
			bpf_printk("Failed LO map lookup for pid %d\n", pid);
			return -1;
		}
	}

	node = bpf_obj_new(struct edf_node_lo);
	if (!node) {
		bpf_printk("Failed LO node allocation for pid %d\n", pid);
		return -1;
	}

	node->deadline_ns = cached->deadline_ns;
	node->pid = cached->pid;
	node->queued = 1;

	bpf_spin_lock(&lo_tree_lock);
	bpf_rbtree_add(&lo_tree, &node->rb_node, edf_tree_less_lo);
	bpf_spin_unlock(&lo_tree_lock);
	return 0;
}

/* Duplicate insertions updates node */
static s32 edf_tree_insert_hi(struct task_ctx *tctx)
{
	struct edf_node_hi node_val = {};
	struct edf_node_hi *cached;
	struct edf_node_hi *node;
	pid_t pid;
	long ret;

	if (!tctx) {
		bpf_printk("Failed HI insert: NULL task context\n");
		return -1;
	}

	pid = tctx->pid;

	cached = bpf_map_lookup_elem(&edf_map_hi, &pid);
	if (cached) {
		cached->deadline_ns = tctx->deadline_ns_hi;
		cached->pid = pid;
		if (cached->queued)
			return 0;
		cached->queued = 1;
	} else {
		node_val.deadline_ns = tctx->deadline_ns_hi;
		node_val.pid = pid;
		node_val.queued = 1;

		ret = bpf_map_update_elem(&edf_map_hi, &pid, &node_val,
					  BPF_NOEXIST);
		if (ret) {
			bpf_printk("Failed HI map update for pid %d\n", pid);
			return -1;
		}

		cached = bpf_map_lookup_elem(&edf_map_hi, &pid);
		if (!cached) {
			bpf_printk("Failed HI map lookup for pid %d\n", pid);
			return -1;
		}
	}

	node = bpf_obj_new(struct edf_node_hi);
	if (!node) {
		bpf_printk("Failed HI node allocation for pid %d\n", pid);
		return -1;
	}

	node->deadline_ns = cached->deadline_ns;
	node->pid = cached->pid;
	node->queued = 1;

	bpf_spin_lock(&hi_tree_lock);
	bpf_rbtree_add(&hi_tree, &node->rb_node, edf_tree_less_hi);
	bpf_spin_unlock(&hi_tree_lock);
	return 0;
}

static struct task_ctx *edf_tree_pop_lo(void)
{
	struct edf_node_lo *node;
	struct task_ctx *tctx;
	pid_t pid;

	bpf_spin_lock(&lo_tree_lock);
	struct bpf_rb_node *rb_node = bpf_rbtree_first(&lo_tree);
	if (!rb_node) {
		bpf_spin_unlock(&lo_tree_lock);
		/* Empty tree */
		return NULL;
	}
	rb_node = bpf_rbtree_remove(&lo_tree, rb_node);
	bpf_spin_unlock(&lo_tree_lock);

	if (!rb_node)
		return NULL;

	node = container_of(rb_node, struct edf_node_lo, rb_node);
	pid = node->pid;

	tctx = bpf_map_lookup_elem(&task_ctx, &pid);
	struct edf_node_lo *cached = bpf_map_lookup_elem(&edf_map_lo, &pid);
	if (cached)
		cached->queued = 0;
	bpf_obj_drop(node);

	return tctx;
}

static struct task_ctx *edf_tree_pop_hi(void)
{
	struct edf_node_hi *node;
	struct task_ctx *tctx;
	pid_t pid;

	bpf_spin_lock(&hi_tree_lock);
	struct bpf_rb_node *rb_node = bpf_rbtree_first(&hi_tree);
	if (!rb_node) {
		bpf_spin_unlock(&hi_tree_lock);
		/* Empty tree */
		return NULL;
	}
	rb_node = bpf_rbtree_remove(&hi_tree, rb_node);
	bpf_spin_unlock(&hi_tree_lock);

	if (!rb_node)
		return NULL;

	node = container_of(rb_node, struct edf_node_hi, rb_node);
	pid = node->pid;

	tctx = bpf_map_lookup_elem(&task_ctx, &pid);
	struct edf_node_hi *cached = bpf_map_lookup_elem(&edf_map_hi, &pid);
	if (cached)
		cached->queued = 0;
	bpf_obj_drop(node);

	return tctx;
}

/* Enqueue the task by inserting into the appropriate EDF tree(s) */
s32 BPF_STRUCT_OPS(edfvd_enqueue, struct task_struct *p, u64 enq_flags)
{
	pid_t pid = p->pid;
	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx, &pid);
	if (!tctx) {
		bpf_printk(
			"Failed to enqueue: No task context found for pid %d\n",
			pid);
		return -1;
	}

	/* Deadline is already calculated */
	if (!in_hi_crit_mode)
		edf_tree_insert_lo(tctx);

	if (tctx->criticality == HI)
		return edf_tree_insert_hi(tctx);

	return 0;
}

/*
 * Pop a task from the appropriate EDF tree and dispatch it into the 
 * local dispatch queue (DSQ) of the calling CPU.
 */
s32 BPF_STRUCT_OPS(edfvd_dispatch, s32 cpu, struct task_struct *prev)
{
	if (!in_hi_crit_mode) {
		struct task_ctx *tctx = edf_tree_pop_lo();
		if (!tctx)
			return 0;
		pid_t pid = tctx->pid;
		if (tctx->criticality == HI)
			edf_tree_pop_hi(); /* Remove HI-criticality duplicate */
		struct task_struct *next = bpf_task_from_pid(pid);
		if (!next)
			return -1;
		scx_bpf_dsq_insert(next, SCX_DSQ_LOCAL, SCX_SLICE_INF, 0);
		bpf_task_release(next);
	}
	if (in_hi_crit_mode) {
		struct task_ctx *tctx = edf_tree_pop_hi();
		if (!tctx)
			return 0;
		pid_t pid = tctx->pid;
		struct task_struct *next = bpf_task_from_pid(pid);
		if (!next)
			return -1;
		scx_bpf_dsq_insert(next, SCX_DSQ_LOCAL, SCX_SLICE_INF, 0);
		bpf_task_release(next);
	}
	return 0;
}

/*
 * If it is a new job, calculate and update new deadline, and kick CPU with
 * highest registered deadline if the new deadline is earlier.
 */
s32 BPF_STRUCT_OPS(edfvd_runnable, struct task_struct *p, u64 enq_flags)
{
	pid_t pid = p->pid;
	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx, &pid);
	if (!tctx)
		return -1;

	if (!(enq_flags & SCX_ENQ_WAKEUP))
		return 0;

	if (!tctx->new_job)
		return 0;

	/* Wakeup of new job! */
	tctx->new_job = false;

	/* Set new deadline */
	u64 modified_deadline;
	u64 unmodified_deadline;
	u64 now_ns = bpf_ktime_get_ns();
	/* For LO-criticality tasks modified period = period (see pre-processing) */
	modified_deadline = now_ns + tctx->modified_period_ms * 1000000;
	unmodified_deadline = now_ns + tctx->period_ms * 1000000;
	tctx->deadline_ns_lo = modified_deadline;
	if (tctx->criticality == HI) {
		tctx->deadline_ns_hi = unmodified_deadline;
	}

	/* Kick CPU with highest registered deadline if new deadline is earlier */
	u32 cpu_with_highest_deadline = 0;
	u64 highest_deadline = 0;
	for (u32 cpu = 0; cpu < NO_CPUS; cpu++) {
		u64 *cpu_deadline_ns =
			bpf_map_lookup_elem(&cpu_deadlines, &cpu);
		if (*cpu_deadline_ns > highest_deadline) {
			highest_deadline = *cpu_deadline_ns;
			cpu_with_highest_deadline = cpu;
		}
	}
	if (modified_deadline < highest_deadline) {
		scx_bpf_kick_cpu(cpu_with_highest_deadline, SCX_KICK_PREEMPT);
	}
	return 0;
}

/* Detect if job is completed. Necessary for deadline logic. */
s32 BPF_STRUCT_OPS(edfvd_quiescent, struct task_struct *p, u64 deq_flags)
{
	if (!(deq_flags & SCX_DEQ_SLEEP))
		return 0;

	/* Job completed, set flag for deadline logic */
	pid_t pid = p->pid;
	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx, &pid);
	if (!tctx)
		return -1;
	tctx->new_job = true;
	tctx->job_count++;
	return 0;
}

/*
 * Update CPU deadlines map with the deadline of the running task.
 * Necessary for preemption logic.
 */
s32 BPF_STRUCT_OPS(edfvd_running, struct task_struct *p)
{
	u32 cpu = bpf_get_smp_processor_id();
	pid_t pid = p->pid;
	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx, &pid);
	if (!tctx)
		return -1;
	u64 deadline_ns = in_hi_crit_mode ? tctx->deadline_ns_hi :
					    tctx->deadline_ns_lo;
	bpf_map_update_elem(&cpu_deadlines, &cpu, &deadline_ns, BPF_ANY);
	return 0;
}

/*
 * Update CPU deadlines map with a sentinel value when a task stops running.
 * Necessary for preemption logic.
 */
s32 BPF_STRUCT_OPS(edfvd_stopping, struct task_struct *p, bool runnable)
{
	u32 cpu = bpf_get_smp_processor_id();
	u64 sentinel = ~0ULL;
	bpf_map_update_elem(&cpu_deadlines, &cpu, &sentinel, BPF_ANY);
	return 0;
}

/* Initialize task context */
s32 BPF_STRUCT_OPS(edfvd_enable, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	pid_t pid = p->pid;
	bpf_printk("Task with pid %d entered SCX\n", pid);
	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx, &pid);
	if (!tctx) {
		bpf_printk(
			"No task ctx found for pid %d. Have you provided task context through bpf_map_update_elem()?\n",
			p->pid);
		return -1;
	}
	bpf_printk(
		"Task ctx provided for pid %d: task_nr=%llu, criticality=%s, period=%llu, modified_period=%llu, wcet_lo=%llu, wcet_hi=%llu\n",
		p->pid, tctx->task_nr, tctx->criticality == LO ? "LO" : "HI",
		tctx->period_ms, tctx->modified_period_ms, tctx->wcet_ms_lo,
		tctx->wcet_ms_hi);

	tctx->pid = pid;
	tctx->new_job = true;
	tctx->job_count = 0;
	return 0;
}

/* Initialize the EDF-VD scheduler */
s32 BPF_STRUCT_OPS(edfvd_init)
{
	bpf_printk("EDF-VD scheduler initialized with %d possible CPUs\n",
		   NO_CPUS);

	/* Initilize cpu deadlines with maximum values */
	u64 sentinel = ~0ULL;
	u32 cpu = 0;
	bpf_repeat(NO_CPUS)
	{
		bpf_map_update_elem(&cpu_deadlines, &cpu, &sentinel, BPF_ANY);
		cpu++;
	}
	return 0;
}

/* Shutdown the EDF-VD scheduler */
void BPF_STRUCT_OPS(edfvd_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/* clang-format off */
SCX_OPS_DEFINE(edfvd_ops,
	.enqueue =		(void *)edfvd_enqueue,
	.dispatch =		(void *)edfvd_dispatch,
	.runnable =		(void *)edfvd_runnable,
	.quiescent =	(void *)edfvd_quiescent,
	.running =		(void *)edfvd_running,
	.stopping =		(void *)edfvd_stopping,
	.enable =		(void *)edfvd_enable,
	.init =			(void *)edfvd_init,
	.exit =			(void *)edfvd_exit,
	.flags =		SCX_OPS_SWITCH_PARTIAL,
	.name =			"edfvd");
/* clang-format on */
