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
						   .period_ms = 1000,git 
						   .modified_period_ms = -1,
						   .wcet_ms_lo = 400,
						   .wcet_ms_hi = 900,
					   },
				   } };

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
	fprintf(stderr, "Unknown task set: %s\n", optarg);
	exit(EXIT_FAILURE);
}