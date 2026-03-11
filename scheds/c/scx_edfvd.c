/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_edfvd.bpf.skel.h"

#include "scx_edfvd.h"
#include "scx_edfvd_examples/task_set_examples.h"

const char help_fmt[] =
"An EDF-VD scheduler.\n"
"-v: verbose output\n"
"-t <task_set>: specify task set to use (e.g., -t 1)\n"
;

static bool verbose;
static volatile int exit_req;
static struct edfvd_task_set task_set;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int simple)
{
	exit_req = 1;
}

/* 
 * Calculates the x parameter for the EDF-VD pre-processing.
 * Returns -1 if not schedulable.
 */
float edfvd_calculate_x_parameter(struct edfvd_task_set *ts)
{
	/* 
	 * Utilization sum for HI-criticality tasks using its
	 * LO-criticality WCET estimate.
	 */
	float sum_hi_lo = 0.0;
	for(int i = 0; i < ts->num_tasks; i++) {
		struct edfvd_task *task = &ts->tasks[i];
		if (task->criticality == HI){
			sum_hi_lo += (float) task->wcet_ms_lo / task->period_ms;
		}
	}

	/* 
	 * Utilization sum for HI-criticality tasks using its
	 * HI-criticality WCET estimate.
	 */
	float sum_hi_hi = 0.0;
	for(int i = 0; i < ts->num_tasks; i++) {
		struct edfvd_task *task = &ts->tasks[i];
		if (task->criticality == HI){
			sum_hi_hi += (float) task->wcet_ms_hi / task->period_ms;
		}
	}

	/* Utilization sum for LO-criticality tasks using its
	 * LO-criticality WCET estimate.
	 */
	float sum_lo_lo = 0.0;
	for(int i = 0; i < ts->num_tasks; i++) {
		struct edfvd_task *task = &ts->tasks[i];
		if (task->criticality == LO){
			sum_lo_lo += (float) task->wcet_ms_lo / task->period_ms;
		}
	}

	/* Calculate the x parameter */
	float x = sum_hi_lo / (1.0 - sum_lo_lo);

	/* Check schedulability condition */
	if(x * sum_lo_lo + sum_hi_hi > 1.0) {
		return -1;
	}
	return x;
}

/* 
 * Calculate the modified_period_ms for HI-criticality tasks
 *
 * modified_period_ms = x * period_ms for HI-criticality tasks
 * 
 * Algorithm based on Figure 1 in the paper: 
 *   S. Baruah et al., 
 *   "The Preemptive Uniprocessor Scheduling of Mixed-Criticality 
 *   Implicit-Deadline Sporadic Task Systems,"
 *   2012 24th Euromicro Conference on Real-Time Systems, 
 *   Pisa, Italy, 2012, pp. 145-154, doi: 10.1109/ECRTS.2012.42.
 */
void edfvd_pre_processing(struct edfvd_task_set *ts)
{
	float x = edfvd_calculate_x_parameter(ts);

	if(x == -1) {
		fprintf(stderr, "Task set is not schedulable under EDF-VD.\n");
		exit(EXIT_FAILURE);
	}

	for(int i = 0; i < ts->num_tasks; i++) {
		struct edfvd_task *task = &ts->tasks[i];
		if (task->criticality == HI){
			task->modified_period_ms = x * task->period_ms;
		}
	}
	return;
}

/* Fill out eBPF map used by the scheduler */
void edfvd_copy_task_set_to_map(struct edfvd_task_set *ts)
{
	return;
}

/* 
 * Starts dummy jobs based on the task set and schedule them on the EDF-VD scheduler.
 * Assumes that the EDF-VD scheduler is already loaded and attached.
 */
void edfvd_start_tasks(struct edfvd_task_set *ts, struct scx_edfvd *skel)
{
	return;
}

/*
 * Dummy job, burn cpu time for a specified amount of time.
 * A job is an individual release of a task.
 */
void edfvd_dummy_job(struct edfvd_task *task)
{
	/* To begin burn cpu-time < wcet_ms_lo*/
	return;
}

void edfvd_print_task_set(struct edfvd_task_set *ts)
{
	printf("Task set:\n");
	for(int i = 0; i < ts->num_tasks; i++) {
		struct edfvd_task *task = &ts->tasks[i];
		printf("Task %d: criticality=%s, period=%d ms, modified_period=%d ms, wcet_lo=%d ms, wcet_hi=%d ms\n",
			task->id,
			task->criticality == LO ? "LO" : "HI",
			task->period_ms,
			task->modified_period_ms,
			task->wcet_ms_lo,
			task->wcet_ms_hi);
	}
}

int main(int argc, char **argv)
{
	struct scx_edfvd *skel;
	struct bpf_link *link;
	u32 opt;
	u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(edfvd_ops, scx_edfvd);
	int task_set_selected = 0;
	while ((opt = getopt(argc, argv, "vht:")) != -1) {
		switch (opt) {
		case 'v':
			verbose = true;
			break;
		case 't':
			task_set = get_task_set(optarg);
			task_set_selected = 1;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}
	if (!task_set_selected) {
		fprintf(stderr, "No task set selected. Use -t <task_set> to select a task set.\n");
		exit(EXIT_FAILURE);
	}
	
	edfvd_pre_processing(&task_set);
	printf("Task set preprocessed.\n");

	edfvd_print_task_set(&task_set);
	
	edfvd_start_tasks(&task_set, skel);
	printf("Task set started.\n");
	
	SCX_OPS_LOAD(skel, edfvd_ops, scx_edfvd, uei);
	edfvd_copy_task_set_to_map(&task_set);
	link = SCX_OPS_ATTACH(skel, edfvd_ops, scx_edfvd);
    printf("EDF-VD scheduler loaded and attached.\n");

	printf("Press Ctrl+C to exit.\n");
	while (!exit_req && !UEI_EXITED(skel, uei)) {
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_edfvd__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
