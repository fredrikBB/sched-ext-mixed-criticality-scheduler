#ifndef __SCX_EDFVD_COMMON_H
#define __SCX_EDFVD_COMMON_H

#define MAX_TASKS 128

enum edfvd_criticality_level {
	LO = 0,
	HI = 1,
};

/* Each individual release of a task is reffered to as a "job" */
struct edfvd_task {
	int id;
	enum edfvd_criticality_level criticality;
	int period_ms; /* Minimum time between two jobs */
	int modified_period_ms; /* Used by HI-criticality tasks */
	int wcet_ms_lo; /* WCET in LO-criticality mode */
	int wcet_ms_hi; /* WCET in HI-criticality mode */
	pthread_t thread;
};

struct edfvd_task_set {
	int num_tasks;
	struct edfvd_task tasks[MAX_TASKS];
};

#endif  // __SCX_EDFVD_COMMON_H