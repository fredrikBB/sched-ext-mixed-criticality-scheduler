#include <stdio.h>
#include <stdlib.h>
#include "../scx_edfvd.h"

struct edfvd_task_set
	task_set_1 = { .num_tasks = 3,
		       .tasks = {
			       {
				       .task_nr = 1,
				       .criticality = LO,
				       .period_ms = 1000,
				       .wcet_ms_lo = 200,
			       },
			       {
				       .task_nr = 2,
				       .criticality = LO,
				       .period_ms = 1000,
				       .wcet_ms_lo = 300,
			       },
			       {
				       .task_nr = 3,
				       .criticality = HI,
				       .period_ms = 2000,
				       .modified_period_ms =
					       0, /* To be calculated by the pre-processing step */
				       .wcet_ms_lo = 500,
				       .wcet_ms_hi = 1000,
			       },
		       } };

struct edfvd_task_set task_set_2 = { .num_tasks = 1,
				     .tasks = {
					     {
						     .task_nr = 1,
						     .criticality = LO,
						     .period_ms = 1000,
						     .wcet_ms_lo = 500,
					     },
				     } };

struct edfvd_task_set
	task_set_unschedulable = { .num_tasks = 2,
				   .tasks = {
					   {
						   .task_nr = 1,
						   .criticality = LO,
						   .period_ms = 1000,
						   .wcet_ms_lo = 700,
					   },
					   {
						   .task_nr = 2,
						   .criticality = HI,
						   .period_ms = 1000,
						   .modified_period_ms = -1,
						   .wcet_ms_lo = 400,
						   .wcet_ms_hi = 900,
					   },
				   } };

/* 
 * Task set used in:
 * Godabole, P., Samudre, A., Udmale, S.S. et al.
 * Clustering-based task allocation for overhead reduction
 * in multi-core mixed-critical systems. J Supercomput 81, 1549 (2025).
 * https://doi.org/10.1007/s11227-025-08035-7
 * 
 * They simulate on a Linux system with homogenous quad-core architecture.
 * 
 * But the task set does not contain multiple WCETs for each task
 */
struct edfvd_task_set task_set_4 = {
	.num_tasks = 5,
	/* Instrumentation control system task set */
	.tasks = { {
			   /* Mode management */
			   .task_nr = 1,
			   .criticality = HI,
			   .period_ms = 100,
			   .wcet_ms_lo = 25,
			   .wcet_ms_hi = 50, /* Not given in paper */
		   },
		   {
			   /* Mission data management */
			   .task_nr = 2,
			   .criticality = LO,
			   .period_ms = 200,
			   .wcet_ms_lo = 12,
		   },
		   {
			   /* Instrument monitoring */
			   .task_nr = 3,
			   .criticality = HI,
			   .period_ms = 250,
			   .wcet_ms_lo = 10,
			   .wcet_ms_hi = 20, /* Not given in paper */
		   },
		   {
			   /* Instrument configuration */
			   .task_nr = 4,
			   .criticality = LO,
			   .period_ms = 200,
			   .wcet_ms_lo = 42,
		   },
		   {
			   /* Instrument processing */
			   .task_nr = 5,
			   .criticality = HI,
			   .period_ms = 300,
			   .wcet_ms_lo = 25,
			   .wcet_ms_hi = 50, /* Not given in paper */
		   } }
};

/*
 * - LO-mode total utilization: 0.95
 * - HI-mode total utilization: 0.95
 */
struct edfvd_task_set task_set_5 = { .num_tasks = 4,
				     .tasks = {
					     {
						     .task_nr = 1,
						     .criticality = LO,
						     .period_ms = 800,
						     .wcet_ms_lo = 20,
					     },
					     {
						     .task_nr = 2,
						     .criticality = LO,
						     .period_ms = 1000,
						     .wcet_ms_lo = 25,
					     },
					     {
						     .task_nr = 3,
						     .criticality = HI,
						     .period_ms = 1200,
						     .wcet_ms_lo = 540,
						     .wcet_ms_hi = 570,
					     },
					     {
						     .task_nr = 4,
						     .criticality = HI,
						     .period_ms = 1000,
						     .wcet_ms_lo = 450,
						     .wcet_ms_hi = 475,
					     },
				     } };

struct edfvd_task_set task_set_6 = { .num_tasks = 1,
				     .tasks = {
					     {
						     .task_nr = 1,
						     .criticality = LO,
						     .period_ms = 200,
						     .wcet_ms_lo = 50,
					     },
				     } };

struct edfvd_task_set task_set_7 = { .num_tasks = 8,
				     .tasks = {
					     {
						     .task_nr = 1,
						     .criticality = LO,
						     .period_ms = 1000,
						     .wcet_ms_lo = 100,
					     },
					     {
						     .task_nr = 2,
						     .criticality = LO,
						     .period_ms = 1000,
						     .wcet_ms_lo = 100,
					     },
					     {
						     .task_nr = 3,
						     .criticality = LO,
						     .period_ms = 1000,
						     .wcet_ms_lo = 100,
					     },
					     {
						     .task_nr = 4,
						     .criticality = LO,
						     .period_ms = 1000,
						     .wcet_ms_lo = 100,
					     },
					     {
						     .task_nr = 5,
						     .criticality = HI,
						     .period_ms = 1000,
						     .wcet_ms_lo = 100,
						     .wcet_ms_hi = 200,
					     },
					     {
						     .task_nr = 6,
						     .criticality = HI,
						     .period_ms = 1000,
						     .wcet_ms_lo = 100,
						     .wcet_ms_hi = 200,
					     },
					     {
						     .task_nr = 7,
						     .criticality = HI,
						     .period_ms = 1000,
						     .wcet_ms_lo = 100,
						     .wcet_ms_hi = 200,
					     },
					     {
						     .task_nr = 8,
						     .criticality = HI,
						     .period_ms = 1000,
						     .wcet_ms_lo = 100,
						     .wcet_ms_hi = 200,
					     },
				     } };

struct edfvd_task_set task_set_8 = { .num_tasks = 8,
				     .tasks = {
					     {
						     .task_nr = 1,
						     .criticality = HI,
						     .period_ms = 1000,
						     .wcet_ms_lo = 100,
						     .wcet_ms_hi = 100,
					     },
					     {
						     .task_nr = 2,
						     .criticality = HI,
						     .period_ms = 1000,
						     .wcet_ms_lo = 100,
						     .wcet_ms_hi = 100,
					     },
					     {
						     .task_nr = 3,
						     .criticality = HI,
						     .period_ms = 1000,
						     .wcet_ms_lo = 100,
						     .wcet_ms_hi = 100,
					     },
					     {
						     .task_nr = 4,
						     .criticality = HI,
						     .period_ms = 1000,
						     .wcet_ms_lo = 100,
						     .wcet_ms_hi = 100,
					     },
					     {
						     .task_nr = 5,
						     .criticality = HI,
						     .period_ms = 1000,
						     .wcet_ms_lo = 100,
						     .wcet_ms_hi = 100,

					     },
					     {
						     .task_nr = 6,
						     .criticality = HI,
						     .period_ms = 1000,
						     .wcet_ms_lo = 100,
						     .wcet_ms_hi = 100,
					     },
					     {
						     .task_nr = 7,
						     .criticality = HI,
						     .period_ms = 1000,
						     .wcet_ms_lo = 100,
						     .wcet_ms_hi = 100,
					     },
					     {
						     .task_nr = 8,
						     .criticality = HI,
						     .period_ms = 1000,
						     .wcet_ms_lo = 100,
						     .wcet_ms_hi = 100,
					     },
				     } };

void scale_task_set(struct edfvd_task_set *ts, float scale_factor)
{
	for (int i = 0; i < ts->num_tasks; i++) {
		ts->tasks[i].wcet_ms_lo =
			(u64)(ts->tasks[i].wcet_ms_lo * scale_factor + 0.5f);
		ts->tasks[i].wcet_ms_hi =
			(u64)(ts->tasks[i].wcet_ms_hi * scale_factor + 0.5f);
	}
}

struct edfvd_task_set get_task_set(char *optarg)
{
	if (strcmp(optarg, "1") == 0) {
		return task_set_1;
	}
	if (strcmp(optarg, "2") == 0) {
		return task_set_2;
	}
	if (strcmp(optarg, "3") == 0) {
		return task_set_unschedulable;
	}
	if (strcmp(optarg, "4") == 0) {
		return task_set_4;
	}
	if (strcmp(optarg, "5") == 0) {
		return task_set_5;
	}
	if (strcmp(optarg, "6") == 0) {
		return task_set_6;
	}
	if (strcmp(optarg, "7") == 0) {
		float scale_factor = 1.0; /* Default scaling factor */
		printf("Input factor to scale WCET of every task in task set 7 by (e.g., 0.5 to halve the WCETs, 2 to double them):\n");
		scanf("%f", &scale_factor);
		scale_task_set(&task_set_7, scale_factor);
		return task_set_7;
	}
	if (strcmp(optarg, "8") == 0) {
		float scale_factor = 1.0; /* Default scaling factor */
		printf("Input factor to scale WCET of every task in task set 8 by (e.g., 0.5 to halve the WCETs, 2 to double them):\n");
		scanf("%f", &scale_factor);
		scale_task_set(&task_set_8, scale_factor);
		return task_set_8;
	}
	fprintf(stderr, "Unknown task set: %s\n", optarg);
	exit(EXIT_FAILURE);
}