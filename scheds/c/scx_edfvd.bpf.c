/* SPDX-License-Identifier: GPL-2.0 */
#include <scx/common.bpf.h>
#include "scx_edfvd.h"

/* Defined in include/linux/sched.h */
#define TASK_INTERRUPTIBLE 0x00000001

#define NS_PER_MS 1000000
#define SENTINEL_DEADLINE 0xFFFFFFFFFFFFFFFF

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

static bool in_hi_crit_mode = false;

static bool pin_to_single_cpu = false;
static int target_cpu = -1;

/* 
 * Map to receive CPU pinning information from userspace.
 * If the tasks' affinity is not respected the BPF scheduler will
 * throw an runtime error and exit.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(value_size, sizeof(u8)); /* Pinned or not */
	__uint(key_size, sizeof(u32)); /* CPU ID */
	__uint(max_entries, NO_CPUS);
} cpu_pin SEC(".maps");

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
		bpf_printk("SCX: Failed LO insert: NULL task context\n");
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
			bpf_printk("SCX: Failed LO map update for pid %d\n",
				   pid);
			return -1;
		}

		cached = bpf_map_lookup_elem(&edf_map_lo, &pid);
		if (!cached) {
			bpf_printk("SCX: Failed LO map lookup for pid %d\n",
				   pid);
			return -1;
		}
	}

	node = bpf_obj_new(struct edf_node_lo);
	if (!node) {
		bpf_printk("SCX: Failed LO node allocation for pid %d\n", pid);
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
		bpf_printk("SCX: Failed HI insert: NULL task context\n");
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
			bpf_printk("SCX: Failed HI map update for pid %d\n",
				   pid);
			return -1;
		}

		cached = bpf_map_lookup_elem(&edf_map_hi, &pid);
		if (!cached) {
			bpf_printk("SCX: Failed HI map lookup for pid %d\n",
				   pid);
			return -1;
		}
	}

	node = bpf_obj_new(struct edf_node_hi);
	if (!node) {
		bpf_printk("SCX: Failed HI node allocation for pid %d\n", pid);
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

s32 transition_to_hi_crit_mode(void)
{
	in_hi_crit_mode = true;
	bpf_repeat(MAX_TASKS)
	{
		struct task_ctx *tctx = edf_tree_pop_lo();
		if (!tctx)
			break;
	}
	bpf_printk("SCX: Entered to HI-criticality mode\n");
	return 0;
}

static s32 edfvd_check_deadline_surpassal(struct task_struct *p,
					  struct task_ctx *tctx,
					  const char *where)
{
	u64 now_ns = bpf_ktime_get_ns();
	u64 current_deadline;
	if (tctx->criticality == LO) {
		current_deadline = tctx->deadline_ns_lo;
	}
	if (tctx->criticality == HI) {
		/*
		 * For HI-criticality tasks, we check against the unmodified deadline
		 * (stored in deadline_ns_hi), even in LO-criticality mode, as this is the
		 * deadline that matters for determining if a task has missed its deadline.
		 * Umodified deadline is start + period, and not start + modified period.
		*/
		current_deadline = tctx->deadline_ns_hi;
	}
	if (now_ns > current_deadline) {
		bpf_printk(
			"SCX: %s, Task %d job %d missed its deadline! Current time: %llu ns, (unmodified) Deadline: %llu ns\n",
			where, tctx->task_nr, tctx->job_count, now_ns,
			current_deadline);
		return 1;
	}
	return 0;
}

static s32 edfvd_check_wcet_overrun(struct task_struct *p,
				    struct task_ctx *tctx, const char *where)
{
	u64 now_exec_runtime_ns;
	u64 start_exec_runtime_ns;
	u64 consumed_exec_runtime_ns = 0;
	u64 wcet_ns;

	if (in_hi_crit_mode)
		return 0;

	now_exec_runtime_ns = p->se.sum_exec_runtime;
	start_exec_runtime_ns = tctx->job_start_exec_runtime_ns;
	if (now_exec_runtime_ns > start_exec_runtime_ns)
		consumed_exec_runtime_ns =
			now_exec_runtime_ns - start_exec_runtime_ns;

	wcet_ns = tctx->wcet_ms_lo * NS_PER_MS;
	if (consumed_exec_runtime_ns <= wcet_ns)
		return 0;

	bpf_printk("SCX: %s, Task %d exceeded LO-criticality WCET\n", where,
		   tctx->task_nr);
	bpf_printk(
		"SCX: %s, Task %d consumed CPU runtime: %llu ns, WCET: %llu ns\n",
		where, tctx->task_nr, consumed_exec_runtime_ns, wcet_ns);
	return 1;
}

static s32 edfvd_kick_if_needed(struct task_ctx *tctx, const char *where)
{
	if (!tctx)
		return -1;
	u64 current_deadline = in_hi_crit_mode ? tctx->deadline_ns_hi :
						 tctx->deadline_ns_lo;
	u32 cpu_with_highest_deadline = 0;
	u64 highest_deadline = 0;
	if (!pin_to_single_cpu) {
		u32 cpu = 0;
		bpf_repeat(NO_CPUS)
		{
			u64 *cpu_deadline_ns =
				bpf_map_lookup_elem(&cpu_deadlines, &cpu);
			if (cpu_deadline_ns &&
			    *cpu_deadline_ns > highest_deadline) {
				highest_deadline = *cpu_deadline_ns;
				cpu_with_highest_deadline = cpu;
			}
			cpu++;
		}
	}
	if (pin_to_single_cpu) {
		cpu_with_highest_deadline = target_cpu;
		u64 *cpu_deadline_ns =
			bpf_map_lookup_elem(&cpu_deadlines, &target_cpu);
		if (cpu_deadline_ns)
			highest_deadline = *cpu_deadline_ns;
	}
	if (pin_to_single_cpu && highest_deadline == SENTINEL_DEADLINE) {
		/*
		 * No task is running on the target CPU in pinned mode, so no need to kick
		 * as this can cause a preemption storm.
		 */
		return 0;
	}
	if (current_deadline < highest_deadline &&
	    !(tctx->criticality == LO && in_hi_crit_mode)) {
		scx_bpf_kick_cpu(cpu_with_highest_deadline, SCX_KICK_PREEMPT);
		bpf_printk(
			"SCX: %s, Kicked CPU %d due to earlier deadline of task %d job %d: %llu ns vs %llu ns\n",
			where, cpu_with_highest_deadline, tctx->task_nr,
			tctx->job_count, current_deadline, highest_deadline);
	}
	return 0;
}

static s32 edfvd_set_new_deadline(struct task_ctx *tctx)
{
	if (!tctx)
		return -1;
	/* Set new deadline */
	u64 modified_deadline;
	u64 unmodified_deadline;
	u64 now_ns = bpf_ktime_get_ns();
	/* For LO-criticality tasks modified period = period (see pre-processing) */
	modified_deadline = now_ns + tctx->modified_period_ms * NS_PER_MS;
	unmodified_deadline = now_ns + tctx->period_ms * NS_PER_MS;
	tctx->deadline_ns_lo = modified_deadline;
	if (tctx->criticality == HI) {
		tctx->deadline_ns_hi = unmodified_deadline;
	}
	return 0;
}

/*
 * Enqueue the task by inserting into the appropriate EDF tree(s),
 * and kick CPU with highest registered deadline if the new deadline is earlier
 */
s32 BPF_STRUCT_OPS(edfvd_enqueue, struct task_struct *p, u64 enq_flags)
{
	pid_t pid = p->pid;
	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx, &pid);
	if (!tctx) {
		bpf_printk(
			"SCX: ops.enqueue(), Failed to enqueue: No task context found for pid %d\n",
			pid);
		return -1;
	}

	/* Deadline is already calculated */
	if (!in_hi_crit_mode) {
		edf_tree_insert_lo(tctx);
		bpf_printk(
			"SCX: ops.enqueue(), Enqueued task %d job %d with deadline %llu ns to LO-criticality queue\n",
			tctx->task_nr, tctx->job_count, tctx->deadline_ns_lo);
	}

	if (tctx->criticality == HI) {
		edf_tree_insert_hi(tctx);
		bpf_printk(
			"SCX: ops.enqueue(), Enqueued task %d job %d with deadline %llu ns to HI-criticality queue\n",
			tctx->task_nr, tctx->job_count, tctx->deadline_ns_hi);
	}

	/* Kick CPU with highest registered deadline if new deadline is earlier */
	edfvd_kick_if_needed(tctx, "ops.enqueue()");

	return 0;
}

/*
 * Pop a task from the appropriate EDF tree and dispatch it into the 
 * local dispatch queue (DSQ) of the calling CPU.
 */
s32 BPF_STRUCT_OPS(edfvd_dispatch, s32 cpu, struct task_struct *prev)
{
	if (pin_to_single_cpu && cpu != target_cpu) {
		/* If pinning is enabled, only dispatch to the target CPU */
		return 0;
	}

	if (!in_hi_crit_mode) {
		struct task_ctx *tctx = edf_tree_pop_lo();
		if (!tctx)
			return 0;
		pid_t pid = tctx->pid;
		u64 wcet_ns = tctx->wcet_ms_lo * NS_PER_MS;
		if (tctx->criticality == HI)
			edf_tree_pop_hi(); /* Remove HI-criticality duplicate */
		struct task_struct *next = bpf_task_from_pid(pid);
		if (!next)
			return -1;
		scx_bpf_dsq_insert(next, SCX_DSQ_LOCAL, wcet_ns, 0);
		bpf_printk(
			"SCX: ops.dispatch(), Dispatched task %d job %d with deadline %llu ns to CPU %d in LO-criticality mode\n",
			tctx->task_nr, tctx->job_count, tctx->deadline_ns_lo,
			cpu);
		bpf_task_release(next);
	}
	if (in_hi_crit_mode) {
		struct task_ctx *tctx = edf_tree_pop_hi();
		if (!tctx)
			return 0;
		pid_t pid = tctx->pid;
		u64 wcet_ns = tctx->wcet_ms_hi * NS_PER_MS;
		struct task_struct *next = bpf_task_from_pid(pid);
		if (!next)
			return -1;
		scx_bpf_dsq_insert(next, SCX_DSQ_LOCAL, wcet_ns, 0);
		bpf_printk(
			"SCX: ops.dispatch(), Dispatched task %d job %d with deadline %llu ns to CPU %d in HI-criticality mode\n",
			tctx->task_nr, tctx->job_count, tctx->deadline_ns_hi,
			cpu);
		bpf_task_release(next);
	}
	return 0;
}

/*
 * If it is a new job, calculate and update new deadline and set CPU runtime baseline.
 * Kick CPU with highest registered deadline if the new deadline is earlier.
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
	bpf_printk(
		"SCX: ops.runnable(), Detected wakeup of job %d for task %d\n",
		tctx->job_count, tctx->task_nr);

	tctx->new_job = false;

	/*
	 * Set CPU runtime baseline for this new job.
	 * Used to monitor if LO-criticality WCET is exceeded.
	 */
	tctx->job_start_exec_runtime_ns = p->se.sum_exec_runtime;

	/* Set new deadline for the new job */
	edfvd_set_new_deadline(tctx);

	/* Kick CPU with highest registered deadline if new deadline is earlier */
	edfvd_kick_if_needed(tctx, "ops.runnable()");

	return 0;
}

/*
 * Detect if job is completed. Necessary for deadline logic.
 * Also set remaning slice to zero so new job enters enqueue() and gets
 * WCET slice right from the start.
 * Also added an additional check for LO-criticality WCET overrun here in case the task finishes,
 * but it is almost always detected by ops.tick() first.
 */
s32 BPF_STRUCT_OPS(edfvd_quiescent, struct task_struct *p, u64 deq_flags)
{
	if (!(deq_flags & SCX_DEQ_SLEEP))
		return 0;

	/*
	 * A task can also go into quiescent with SCX_DEQ_SLEEP flag if in uninterruptible (D) state,
	 * to make sure the job was completed check that we are in interruptible state (S).
	 */
	if (!(READ_ONCE(p->__state) & TASK_INTERRUPTIBLE)) {
		return 0;
	}

	/* Job completed! */
	pid_t pid = p->pid;
	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx, &pid);
	if (!tctx)
		return -1;

	bpf_printk(
		"SCX: ops.quiescent(), Detected completion of job %d for task %d\n",
		tctx->job_count, tctx->task_nr);

	/* Set flag for deadline logic */
	tctx->new_job = true;
	tctx->job_count++;

	/* Set remaining slice to zero */
	p->scx.slice = 0;
	bpf_printk(
		"SCX: ops.quiescent(), Set remaining slice for task %d job %d to %llu\n",
		tctx->task_nr, tctx->job_count, p->scx.slice);

	/* Check for LO-criticality WCET overrun */
	s32 overrun = edfvd_check_wcet_overrun(p, tctx, "ops.quiescent()");
	if (overrun)
		transition_to_hi_crit_mode();

	return 0;
}

/*
 * Update CPU deadlines map with the deadline of the running task.
 * Necessary for preemption logic.
 * Also update deadline and runtime baseline if it is the first job
 * since if that is the case ops.runnable() is not called.
 */
s32 BPF_STRUCT_OPS(edfvd_running, struct task_struct *p)
{
	u32 cpu = bpf_get_smp_processor_id();
	pid_t pid = p->pid;
	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx, &pid);
	if (!tctx)
		return -1;

	/* If it is the first job, update deadline and runtime baseline */
	if (tctx->new_job) {
		tctx->job_start_exec_runtime_ns = p->se.sum_exec_runtime;
		edfvd_set_new_deadline(tctx);
		tctx->new_job = false;
		bpf_printk(
			"SCX: ops.running(), First job detected for task %d. Set deadline to %llu ns\n",
			tctx->task_nr,
			in_hi_crit_mode ? tctx->deadline_ns_hi :
					  tctx->deadline_ns_lo);
	}

	/* Update CPU deadline map */
	u64 deadline_ns = in_hi_crit_mode ? tctx->deadline_ns_hi :
					    tctx->deadline_ns_lo;
	bpf_map_update_elem(&cpu_deadlines, &cpu, &deadline_ns, BPF_ANY);
	bpf_printk(
		"SCX: ops.running(), Updated CPU %d deadline to %llu ns for task %d job %d\n",
		cpu, deadline_ns, tctx->task_nr, tctx->job_count);

	return 0;
}

/*
 * Update CPU deadlines map with a sentinel value when a task stops running.
 * Necessary for preemption logic.
 */
s32 BPF_STRUCT_OPS(edfvd_stopping, struct task_struct *p, bool runnable)
{
	u32 cpu = bpf_get_smp_processor_id();
	u64 sentinel = SENTINEL_DEADLINE;
	bpf_map_update_elem(&cpu_deadlines, &cpu, &sentinel, BPF_ANY);
	bpf_printk(
		"SCX: ops.stopping(), Updated CPU %d deadline to sentinel value\n",
		cpu);
	return 0;
}

/*
 * Tick to monitor if running tasks break their LO-criticality WCET and
 * if the deadline is surpassed.
 */
s32 BPF_STRUCT_OPS(edfvd_tick, struct task_struct *p)
{
	s32 ret;
	pid_t pid = p->pid;
	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx, &pid);
	if (!tctx)
		return -1;

	/* Check for deadline surpassal */
	ret = edfvd_check_deadline_surpassal(p, tctx, "ops.tick()");
	if (ret) {
		scx_bpf_exit(SCX_EXIT_NONE, "Task %d missed its deadline!",
			     (int)tctx->task_nr);
	}

	/* Check for LO-criticality WCET overrun */
	ret = edfvd_check_wcet_overrun(p, tctx, "ops.tick()");
	if (!ret) {
		return 0;
	}
	transition_to_hi_crit_mode();
	if (tctx->criticality == LO) {
		u32 cpu = bpf_get_smp_processor_id();
		scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
		bpf_printk(
			"SCX: ops.tick(), Kicked CPU %d due to LO-criticality WCET overrun by task %d job %d\n",
			cpu, tctx->task_nr, tctx->job_count);
	}
	return 0;
}

/* Initialize task context */
s32 BPF_STRUCT_OPS(edfvd_enable, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	pid_t pid = p->pid;
	bpf_printk("SCX: ops.enable(), Task with pid %d entered SCX\n", pid);
	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx, &pid);
	if (!tctx) {
		bpf_printk(
			"SCX: ops.enable(), No task ctx found for pid %d. Have you provided task context through bpf_map_update_elem()?\n",
			p->pid);
		return -1;
	}
	bpf_printk(
		"SCX: ops.enable(), Task ctx provided for pid %d: task_nr=%llu, criticality=%s, period=%llu, modified_period=%llu, wcet_lo=%llu, wcet_hi=%llu\n",
		p->pid, tctx->task_nr, tctx->criticality == LO ? "LO" : "HI",
		tctx->period_ms, tctx->modified_period_ms, tctx->wcet_ms_lo,
		tctx->wcet_ms_hi);

	tctx->pid = pid;
	tctx->deadline_ns_lo = SENTINEL_DEADLINE;
	tctx->deadline_ns_hi = SENTINEL_DEADLINE;
	tctx->new_job = true;
	tctx->job_start_exec_runtime_ns = p->se.sum_exec_runtime;
	tctx->job_count = 0;
	return 0;
}

/* Initialize the EDF-VD scheduler */
s32 BPF_STRUCT_OPS(edfvd_init)
{
	/* Initilize cpu deadlines with maximum values */
	u64 sentinel = SENTINEL_DEADLINE;
	u32 cpu = 0;
	bpf_repeat(NO_CPUS)
	{
		bpf_map_update_elem(&cpu_deadlines, &cpu, &sentinel, BPF_ANY);
		cpu++;
	}

	/* Check CPU pinning information given by userspace */
	cpu = 0;
	bpf_repeat(NO_CPUS)
	{
		u8 *pinned = bpf_map_lookup_elem(&cpu_pin, &cpu);
		if (pinned && *pinned == 1) {
			pin_to_single_cpu = true;
			target_cpu = cpu;
		}
		cpu++;
	}
	if (pin_to_single_cpu) {
		bpf_printk(
			"SCX: ops.init(), EDF-VD scheduler initialized with CPU pinning to CPU %d\n",
			target_cpu);
	} else {
		bpf_printk(
			"SCX: ops.init(), EDF-VD scheduler initialized with %d possible CPUs\n",
			NO_CPUS);
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
	.tick = 		(void *)edfvd_tick,
	.enable =		(void *)edfvd_enable,
	.init =			(void *)edfvd_init,
	.exit =			(void *)edfvd_exit,
	.flags =		SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_LAST,
	.dispatch_max_batch = 1,
	.name =			"edfvd");
/* clang-format on */
