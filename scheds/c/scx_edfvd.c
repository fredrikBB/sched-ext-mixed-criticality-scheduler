/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <libgen.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_edfvd.bpf.skel.h"

#include "scx_edfvd.h"
#include "scx_edfvd_examples/task_set_examples.h"

/* Defined in UAPI */
#ifndef SCHED_EXT
#define SCHED_EXT 7
#endif

const char help_fmt[] =
	"An EDF-VD scheduler.\n"
	"-v: verbose output\n"
	"-t <task_set>: specify task set to use (e.g., -t 1)\n"
	"-c <cpu>: pin all EDF-VD task threads to one CPU in [0, 3]\n"
	"(default: use all 4 CPUs)\n";

static bool verbose;
static volatile int exit_req;
static int task_ctx_map_fd;
static int cpu_pin_map_fd;
static bool pin_to_single_cpu;
static int target_cpu = -1;
pthread_t pthreads[MAX_TASKS];

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int simple)
{
	exit_req = 1;
}

static int parse_cpu_arg(const char *optarg)
{
	char *end = NULL;
	long parsed;
	parsed = strtol(optarg, &end, 10);
	if (end == optarg || *end != '\0') {
		fprintf(stderr, "Invalid CPU id: %s\n", optarg);
		return -1;
	}

	if (parsed < 0 || parsed >= NO_CPUS) {
		fprintf(stderr, "CPU id %ld out of range [0, %d]\n", parsed,
			NO_CPUS - 1);
		return -1;
	}

	return (int)parsed;
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
	for (int i = 0; i < ts->num_tasks; i++) {
		struct edfvd_task *task = &ts->tasks[i];
		if (task->criticality == HI) {
			sum_hi_lo += (float)task->wcet_ms_lo / task->period_ms;
		}
	}

	/* 
	 * Utilization sum for HI-criticality tasks using its
	 * HI-criticality WCET estimate.
	 */
	float sum_hi_hi = 0.0;
	for (int i = 0; i < ts->num_tasks; i++) {
		struct edfvd_task *task = &ts->tasks[i];
		if (task->criticality == HI) {
			sum_hi_hi += (float)task->wcet_ms_hi / task->period_ms;
		}
	}

	/* Utilization sum for LO-criticality tasks using its
	 * LO-criticality WCET estimate.
	 */
	float sum_lo_lo = 0.0;
	for (int i = 0; i < ts->num_tasks; i++) {
		struct edfvd_task *task = &ts->tasks[i];
		if (task->criticality == LO) {
			sum_lo_lo += (float)task->wcet_ms_lo / task->period_ms;
		}
	}

	printf("Calculated total utilization: In LO-mode=%.4f, In HI-mode=%.4f \n",
	       sum_hi_lo + sum_lo_lo, sum_hi_hi);

	/* Calculate the x parameter */
	float x = sum_hi_lo / (1.0 - sum_lo_lo);

	printf("Calculated x parameter: %.4f\n", x);

	/* Check schedulability condition */
	if (x * sum_lo_lo + sum_hi_hi > 1.0) {
		return -1;
	}
	return x;
}

/* 
 * Calculate the modified_period_ms for HI-criticality tasks
 *
 * modified_period_ms = x * period_ms for HI-criticality tasks
 * 
 * set modified_period_ms = period_ms for LO-criticality tasks
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

	if (x == -1) {
		fprintf(stderr, "Task set is not schedulable under EDF-VD.\n");
		exit(EXIT_FAILURE);
	}

	for (int i = 0; i < ts->num_tasks; i++) {
		struct edfvd_task *task = &ts->tasks[i];
		if (task->criticality == HI) {
			task->modified_period_ms = x * task->period_ms;
		} else {
			task->modified_period_ms = task->period_ms;
		}
	}
	return;
}

void edfvd_copy_cpu_pinning_to_map()
{
	if (!pin_to_single_cpu)
		return;

	u8 pinned = 1;
	for (u32 cpu = 0; cpu < NO_CPUS; cpu++) {
		u8 value = (cpu == target_cpu) ? pinned : 0;
		int err = bpf_map_update_elem(cpu_pin_map_fd, &cpu, &value,
					      BPF_ANY);
		if (err) {
			fprintf(stderr,
				"Failed to update CPU pinning for CPU %d\n",
				cpu);
			exit(EXIT_FAILURE);
		}
	}
	return;
}

void edfvd_copy_task_to_map(struct edfvd_task *task)
{
	pid_t pid = syscall(
		SYS_gettid); /* Thread ID, but called pid in task_struct */
	struct task_ctx tctx = {
		.task_nr = task->task_nr,
		.criticality = task->criticality,
		.period_ms = task->period_ms,
		.modified_period_ms = task->modified_period_ms,
		.wcet_ms_lo = task->wcet_ms_lo,
		.wcet_ms_hi = task->wcet_ms_hi,
	};
	int err = bpf_map_update_elem(task_ctx_map_fd, &pid, &tctx, BPF_ANY);
	if (err) {
		fprintf(stderr, "Failed to update task ctx for pid %d\n", pid);
		exit(EXIT_FAILURE);
	}
	return;
}

void do_variable_work(struct edfvd_task *task, u64 job_count, int overrun)
{
	float percantage_of_wcet = 0.8;
	struct timespec start_time, current_time;

	if (overrun) {
		percantage_of_wcet = 1.2;
	}

	u64 work_time_ms = (u64)(percantage_of_wcet * task->wcet_ms_lo);
	u64 elapsed_ms = 0;

	clock_gettime(CLOCK_MONOTONIC, &start_time);
	while (elapsed_ms < work_time_ms) {
		clock_gettime(CLOCK_MONOTONIC, &current_time);
		elapsed_ms =
			(current_time.tv_sec - start_time.tv_sec) * 1000 +
			(current_time.tv_nsec - start_time.tv_nsec) / 1000000;
	}

	if (verbose) {
		printf("Task %lu completed job %lu after %lu ms of work (overrun=%d)\n",
		       task->task_nr, job_count, elapsed_ms, overrun);
	}
}

void *dummy_task(void *arg)
{
	struct edfvd_task *task = (struct edfvd_task *)arg;
	struct timespec current_time;
	struct timespec next_job_release;
	u64 job_count = 0;
	pid_t pid = syscall(
		SYS_gettid); /* Thread ID, but called pid in task_struct */

	/* Provide necessary task information to the scheduler */
	edfvd_copy_task_to_map(task);

	struct sched_param param = { .sched_priority = 0 };
	if (sched_setscheduler(pid, SCHED_EXT, &param) != 0) {
		fprintf(stderr, "Failed to set SCHED_EXT for task %lu\n",
			task->task_nr);
		exit(EXIT_FAILURE);
	}

	clock_gettime(CLOCK_MONOTONIC, &next_job_release);
	while (1) {
		clock_gettime(CLOCK_MONOTONIC, &current_time);

		if (verbose) {
			printf("Task %lu released job %lu at time %lu.%09lu seconds\n",
			       task->task_nr, job_count, current_time.tv_sec,
			       current_time.tv_nsec);
		}

		if (job_count > 10) {
			do_variable_work(task, job_count, 1);
		} else {
			do_variable_work(task, job_count, 0);
		}

		// Calculate absolute next release time
		next_job_release.tv_sec += task->period_ms / 1000;
		next_job_release.tv_nsec += (task->period_ms % 1000) * 1000000;
		if (next_job_release.tv_nsec >= 1000000000) {
			next_job_release.tv_sec +=
				next_job_release.tv_nsec / 1000000000;
			next_job_release.tv_nsec =
				next_job_release.tv_nsec % 1000000000;
		}
		job_count++;
		clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME,
				&next_job_release, NULL);
	}
}

/* Policy is set to SCHED_EXT by the thread itself */
void edfvd_start_tasks(struct edfvd_task_set *ts)
{
	for (int i = 0; i < ts->num_tasks; i++) {
		struct edfvd_task *task = &ts->tasks[i];
		pthread_attr_t attr;
		cpu_set_t cpuset;
		pthread_attr_init(&attr);

		if (pin_to_single_cpu) {
			CPU_ZERO(&cpuset);
			CPU_SET(target_cpu, &cpuset);
			if (pthread_attr_setaffinity_np(&attr, sizeof(cpuset),
							&cpuset) != 0) {
				fprintf(stderr,
					"Failed to set thread affinity to CPU %d for task %lu\n",
					target_cpu, task->task_nr);
				exit(EXIT_FAILURE);
			}
		}

		if (pthread_create(&pthreads[i], &attr, dummy_task, task) !=
		    0) {
			fprintf(stderr,
				"Failed to create thread for task %lu\n",
				task->task_nr);
			exit(EXIT_FAILURE);
		}
		pthread_attr_destroy(&attr);
	}
	return;
}

void edfvd_stop_tasks(struct edfvd_task_set *ts)
{
	for (int i = 0; i < ts->num_tasks; i++) {
		struct edfvd_task *task = &ts->tasks[i];
		pthread_cancel(pthreads[i]);
	}
	return;
}

void edfvd_print_task_set(struct edfvd_task_set *ts)
{
	printf("Task set:\n");
	for (int i = 0; i < ts->num_tasks; i++) {
		struct edfvd_task *task = &ts->tasks[i];
		printf("Task %lu: criticality=%s, period=%lu ms, modified_period=%lu ms, wcet_lo=%lu ms, wcet_hi=%lu ms\n",
		       task->task_nr, task->criticality == LO ? "LO" : "HI",
		       task->period_ms, task->modified_period_ms,
		       task->wcet_ms_lo, task->wcet_ms_hi);
	}
}

int main(int argc, char **argv)
{
	struct scx_edfvd *skel;
	struct bpf_link *link;
	u32 opt;
	u64 ecode;
	struct edfvd_task_set task_set;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(edfvd_ops, scx_edfvd);
	int task_set_selected = 0;
	while ((opt = getopt(argc, argv, "vht:c:")) != -1) {
		switch (opt) {
		case 'v':
			verbose = true;
			break;
		case 't':
			task_set = get_task_set(optarg);
			task_set_selected = 1;
			break;
		case 'c':
			target_cpu = parse_cpu_arg(optarg);
			if (target_cpu < 0)
				exit(EXIT_FAILURE);
			pin_to_single_cpu = true;
			break;
		default:
			fprintf(stderr, "%s", help_fmt);
			return opt != 'h';
		}
	}
	if (!task_set_selected) {
		fprintf(stderr,
			"No task set selected. Use -t <task_set> to select a task set.\n");
		exit(EXIT_FAILURE);
	}

	SCX_OPS_LOAD(skel, edfvd_ops, scx_edfvd, uei);
	task_ctx_map_fd = bpf_map__fd(skel->maps.task_ctx);
	cpu_pin_map_fd = bpf_map__fd(skel->maps.cpu_pin);
	if (pin_to_single_cpu) {
		printf("Pinning task threads to CPU %d.\n", target_cpu);
		edfvd_copy_cpu_pinning_to_map();
	} else
		printf("Task threads can run on all %d CPUs.\n", NO_CPUS);
	link = SCX_OPS_ATTACH(skel, edfvd_ops, scx_edfvd);
	printf("EDF-VD scheduler loaded and attached.\n");

	edfvd_pre_processing(&task_set);
	printf("Task set preprocessed.\n");

	edfvd_print_task_set(&task_set);

	edfvd_start_tasks(&task_set);
	printf("Task set started.\n");

	printf("Press Ctrl+C to exit.\n");
	while (!exit_req && !UEI_EXITED(skel, uei)) {
		sleep(1);
	}

	edfvd_stop_tasks(&task_set);
	printf("Task set stopped.\n");

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_edfvd__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
