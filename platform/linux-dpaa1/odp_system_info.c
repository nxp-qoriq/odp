/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/system_info.h>
#include <odp_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/align.h>
#include <odp/api/cpu.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <stdio.h>

/* sysconf */
#include <unistd.h>
#include <sys/sysinfo.h>

/* opendir, readdir */
#include <sys/types.h>
#include <dirent.h>



typedef struct {
	const char *cpu_arch_str;
	int (*cpuinfo_parser)(FILE *file, odp_system_info_t *sysinfo);
#if defined __arm__ || defined __aarch64__
	int (*cpuinfo_clk_summary)(FILE *file, odp_system_info_t *sysinfo);
#endif
} odp_compiler_info_t;

#define CACHE_LNSZ_FILE \
	"/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size"

#define HUGE_PAGE_DIR "/sys/kernel/mm/hugepages"

#if defined __powerpc__
	static int cpuinfo_powerpc(FILE *file, odp_system_info_t *sysinfo);

	static odp_compiler_info_t compiler_info = {
		.cpu_arch_str = "powerpc",
		.cpuinfo_parser = cpuinfo_powerpc
	};
#elif defined __arm__ || defined __aarch64__
	static int cpuinfo_arm(FILE *file, odp_system_info_t *sysinfo);
	static int clk_summary_arm(FILE *file, odp_system_info_t *sysinfo);

	static odp_compiler_info_t compiler_info = {
		.cpu_arch_str = "arm",
		.cpuinfo_parser = cpuinfo_arm,
		.cpuinfo_clk_summary = clk_summary_arm
	};
#else
	#error GCC target not found
#endif

/*
 * Report the number of online CPU's
 */
static int sysconf_cpu_count(void)
{
	long ret;

	ret = sysconf(_SC_NPROCESSORS_ONLN);
	if (ret < 0)
		return 0;

	return (int)ret;
}

/*
 * Analysis of /sys/devices/system/cpu/ files
 */
static int systemcpu_cache_line_size(void)
{
	int size = 0;
#if defined __powerpc__
	FILE  *file;
	char str[128];

	file = fopen(CACHE_LNSZ_FILE, "rt");
	if (file == NULL) {
		/* File not found */
		return 0;
	}

	if (fgets(str, sizeof(str), file) != NULL) {
		/* Read cache line size */
		sscanf(str, "%i", &size);
	}

	fclose(file);
#elif defined __arm__ || defined __aarch64__
	/* Now, the ARM Linux distribution doesn't put the information in
	 * a system file, in order to be read by an US application.
	 *
	 * Use a hard-coded value till this information will be present.
	 */
	size = ODP_CACHE_LINE_SIZE;
#else
	#error GCC target not found
#endif

	return size;
}

static int huge_page_size(void)
{
	DIR *dir;
	struct dirent *dirent;
	int size = 0;

	dir = opendir(HUGE_PAGE_DIR);
	if (dir == NULL) {
		ODP_ERR("%s not found\n", HUGE_PAGE_DIR);
		return 0;
	}

	while ((dirent = readdir(dir)) != NULL) {
		int temp = 0;
		sscanf(dirent->d_name, "hugepages-%i", &temp);

		if (temp > size)
			size = temp;
	}

	if (closedir(dir)) {
		ODP_ERR("closedir failed\n");
		return 0;
	}

	return size*1024;
}

/*
 * HW specific /proc/cpuinfo file parsing
 */
#if defined __powerpc__
static int cpuinfo_powerpc(FILE *file, odp_system_info_t *sysinfo)
{
	char str[1024];
	char *pos;
	double mhz = 0.0;
	int model = 0;
	int count = 2;

	while (fgets(str, sizeof(str), file) != NULL && count > 0) {
		if (!mhz) {
			pos = strstr(str, "clock");

			if (pos) {
				sscanf(pos, "clock : %lf", &mhz);
				count--;
			}
		}

		if (!model) {
			pos = strstr(str, "cpu");

			if (pos) {
				size_t len;
				pos = strchr(str, ':');
				strncpy(sysinfo->model_str, pos+2,
					sizeof(sysinfo->model_str));
				len = strlen(sysinfo->model_str);

				if (!len) {
					ODP_ERR("len of sysinfo->model_str is zero\n");
					return -1;
				}

				sysinfo->model_str[len - 1] = 0;
				model = 1;
				count--;
			}
		}

		sysinfo->cpu_hz = (uint64_t) (mhz * 1000000.0);
	}

	return 0;
}
#endif

#if defined __arm__ || defined __aarch64__
static int cpuinfo_arm(FILE *file, odp_system_info_t *sysinfo)
{
	char		str[128], *pos;
	int		impl = -1, arch = -1, var = -1, part = -1, rev = -1;

	#define ARM_CORTEX_A53		0xD03
	#define ARM_CORTEX_A53_INFO	"Cortex-A53"

	#define ARM_IMPLEMENTER		0x41
	#define ARM_IMPLEMENTER_INFO	"ARM"

	while (fgets(str, sizeof(str), file) != NULL) {
		if (arch >= 0 && var >= 0 && part >= 0 && rev >= 0)
			break;

		if ((pos = strstr(str, "CPU implementer")) != NULL &&
				(pos = strchr(pos, ':')) != NULL)
			sscanf(++pos, "%d", &impl);
		if ((pos = strstr(str, "CPU architecture")) != NULL &&
				(pos = strchr(pos, ':')) != NULL)
			sscanf(++pos, "%d", &arch);
		else if ((pos = strstr(str, "CPU variant")) != NULL &&
				(pos = strchr(pos, ':')) != NULL)
			sscanf(++pos, "%x", &var);
		else if ((pos = strstr(str, "CPU part")) != NULL &&
				(pos = strchr(pos, ':')) != NULL)
			sscanf(++pos, "%x", &part);
		else if ((pos = strstr(str, "CPU revision")) != NULL &&
				(pos = strchr(pos, ':')) != NULL)
			sscanf(++pos, "%d", &rev);
	}

	if (impl < 0 || arch < 0 || var < 0 || part < 0 || rev < 0) {
		strcpy(sysinfo->model_str, compiler_info.cpu_arch_str);
		return -1;
	}

	if (impl == ARM_IMPLEMENTER)
		sprintf(sysinfo->model_str, "%sv%d.%d rev %d ",
				ARM_IMPLEMENTER_INFO, arch, var, rev);
	else
		sprintf(sysinfo->model_str, "%sv%d.%d rev %d ",
				compiler_info.cpu_arch_str, arch, var, rev);

	if (part == ARM_CORTEX_A53)
		strcat(sysinfo->model_str, ARM_CORTEX_A53_INFO);

	return 0;
}

static int clk_summary_arm(FILE *file, odp_system_info_t *sysinfo)
{
	char str[128];

	if (fgets(str, sizeof(str), file) != NULL) {
		/* Read cpu current frequency in KHz */
		sscanf(str, "%i", &sysinfo->cpu_hz);
		/* Converting freq into Hz */
		sysinfo->cpu_hz *= 1000;
	}
	return 0;
}
#endif

/*
 * Analysis of /sys/devices/system/cpu/ files
 */
static int systemcpu(odp_system_info_t *sysinfo)
{
	int ret = 0;

	if (!(sysinfo->cpu_count = sysconf_cpu_count())) {
		ODP_ERR("sysconf_cpu_count failed.\n");
		ret = -1;
	}

	if (!(sysinfo->cache_line_size = systemcpu_cache_line_size())) {
		ODP_ERR("systemcpu_cache_line_size failed.\n");
		ret = -1;
	}

	if (sysinfo->cache_line_size != ODP_CACHE_LINE_SIZE) {
		ODP_ERR("Cache line sizes definitions don't match.\n");
		ret = -1;
	}

	odp_global_data.system_info.huge_page_size = huge_page_size();

	return ret;
}

/*
 * System info initialization
 */
int odp_system_info_init(void)
{
	FILE  *file;

	memset(&odp_global_data.system_info, 0, sizeof(odp_system_info_t));

	odp_global_data.system_info.page_size = ODP_PAGE_SIZE;

	file = fopen("/proc/cpuinfo", "rt");
	if (file == NULL) {
		ODP_ERR("Failed to open /proc/cpuinfo\n");
		return -1;
	}

	compiler_info.cpuinfo_parser(file, &odp_global_data.system_info);

	fclose(file);

#if defined __arm__ || defined __aarch64__
	file = fopen("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_cur_freq", "rt");
	if (file == NULL) {
		ODP_ERR("Failed to open /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_cur_freq\n");
		return -1;
	}

	compiler_info.cpuinfo_clk_summary(file, &odp_global_data.system_info);

	fclose(file);
#endif

	if (systemcpu(&odp_global_data.system_info)) {
		ODP_ERR("systemcpu failed\n");
		return -1;
	}

	return 0;
}

/*
 *************************
 * Public access functions
 *************************
 */

uint64_t odp_cpu_hz_current(int id ODP_UNUSED)
{
	return 0;
}

uint64_t odp_cpu_hz(void)
{
	int id = sched_getcpu();

	return odp_cpu_hz_current(id);
}

uint64_t odp_cpu_hz_id(int id)
{
	return odp_cpu_hz_current(id);
}

uint64_t odp_cpu_hz_max(void)
{
	return odp_cpu_hz_max_id(0);
}

uint64_t odp_cpu_hz_max_id(int id)
{
	if (id >= 0 && id < MAX_CPU_NUMBER)
		return odp_global_data.system_info.cpu_hz;
	else
		return 0;
}

uint64_t odp_sys_huge_page_size(void)
{
	return odp_global_data.system_info.huge_page_size;
}

uint64_t odp_sys_page_size(void)
{
	return odp_global_data.system_info.page_size;
}

const char *odp_cpu_model_str(void)
{
	return odp_cpu_model_str_id(0);
}

const char *odp_cpu_model_str_id(int id)
{
	if (id >= 0 && id < MAX_CPU_NUMBER)
		return odp_global_data.system_info.model_str;
	else
		return NULL;
}

int odp_sys_cache_line_size(void)
{
	return odp_global_data.system_info.cache_line_size;
}

int odp_cpu_count(void)
{
	return odp_global_data.system_info.cpu_count;
}
