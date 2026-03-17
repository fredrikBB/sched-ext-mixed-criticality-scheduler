#ifndef __SCX_EDFVD_COMMON_H
#define __SCX_EDFVD_COMMON_H

#define MAX_TASKS 128
#define LO 0
#define HI 1

/* User-space task model */
/* Each individual release of a task is referred to as a "job" */
struct edfvd_task {
	u64 task_nr;
	u8 criticality; /* LO=0, HI=1 */
	u64 period_ms; /* Minimum time between two jobs */
	u64 modified_period_ms; /* <= period_ms for HI-criticality tasks */
	u64 wcet_ms_lo; /* WCET in LO-criticality mode */
	u64 wcet_ms_hi; /* WCET in HI-criticality mode */
};

struct edfvd_task_set {
	u64 num_tasks;
	struct edfvd_task tasks[MAX_TASKS];
};

/* 
 * Per-task context used for EDF-VD algorithm
 * Initially filled out be the task itelf
 */
struct task_ctx {
	/* From struct edfvd_task */
	u64 task_nr;
	u8 criticality; /* LO=0, HI=1 */
	u64 period_ms;
	u64 modified_period_ms;
	u64 wcet_ms_lo;
	u64 wcet_ms_hi;

	/* Additional fields for EDF-VD algorithm */
	pid_t pid;
	u64 deadline_ns_lo;
	u64 deadline_ns_hi;
};

#endif // __SCX_EDFVD_COMMON_H