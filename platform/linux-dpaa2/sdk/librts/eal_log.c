/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/*   Derived from DPDK's eal_log.h
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <syslog.h>

#include <dpaa2_queue.h>
#include <odp/api/spinlock.h>
#include <odp/api/hints.h>
#include <dpaa2_mpool.h>
#include <dpaa2_log.h>
#include <dpaa2_internal.h>

/*
 * default log function, used once mempool (hence log history) is
 * available
 */
static ssize_t
console_log_write(__attribute__((unused)) void *c, const char *buf, size_t size)
{
	char copybuf[BUFSIZ + 1];
	ssize_t ret;
	uint32_t loglevel;

	/* add this log in history */
	dpaa2_log_add_in_history(buf, size);

	/* write on stdout */
	ret = fwrite(buf, 1, size, stdout);
	fflush(stdout);

	/* truncate message if too big (should not happen) */
	if (size > BUFSIZ)
		size = BUFSIZ;

	/* Syslog error levels are from 0 to 7, so subtract 1 to convert */
	loglevel = dpaa2_log_cur_msg_loglevel() - 1;
	memcpy(copybuf, buf, size);
	copybuf[size] = '\0';

	/* write on syslog too */
	syslog(loglevel, "%s", copybuf);

	return ret;
}

static ssize_t
console_log_read(__attribute__((unused)) void *c,
		 __attribute__((unused)) char *buf,
		 __attribute__((unused)) size_t size)
{
	return 0;
}

static int
console_log_seek(__attribute__((unused)) void *c,
		 __attribute__((unused)) off64_t *offset,
		 __attribute__((unused)) int whence)
{
	return -1;
}

static int
console_log_close(__attribute__((unused)) void *c)
{
	return 0;
}

static cookie_io_functions_t console_log_func = {
	.read  = console_log_read,
	.write = console_log_write,
	.seek  = console_log_seek,
	.close = console_log_close
};

/*
 * set the log to default function, called during eal init process,
 * once memzones are available.
 */
int
dpaa2_eal_log_init(struct dpaa2_init_cfg *cfg, const char *id, int facility)
{
	FILE  *f;
	/*FILE Logging disabled */
	if (cfg->flags & DPAA2_LOG_FILE) {
		dpaa2_logs.file_logging = 1;
		/* Validate input parameters */
		uint64_t total_file_size;
		total_file_size = (uint64_t)(cfg->log_file_size) * (cfg->log_files);
		if (total_file_size > DPAA2_MAX_LOG_FILES_SIZE) {
			printf("\n Log file can have maximum size 1MB\n");
			cfg->log_file_size = DPAA2_DEF_LOG_FILE_SIZE;
		}
		if (cfg->log_files > DPAA2_MAX_LOG_FILES) {
			cfg->log_files = DPAA2_MAX_LOG_FILES;
		}
		if (cfg->log_file_size <= 0 || cfg->log_files <= 0) {
			cfg->log_file_size = DPAA2_DEF_LOG_FILE_SIZE;
			cfg->log_files = DPAA2_DEF_LOG_FILES;
		}
	}

	f = fopencookie(NULL, "w+", console_log_func);
	if (f == NULL) {
		printf("\n console log failed");
		return -1;
	}

	openlog(id, LOG_NDELAY | LOG_PID, facility);
	dpaa2_openearlylog_stream(f);

	if (dpaa2_eal_common_log_init(cfg) < 0) {
		printf("\n dpaa2_eal_common_log_init failed");
		return -1;
	}

	return 0;
}

int
dpaa2_eal_log_exit(void)
{
	/* disable history */
	dpaa2_log_set_history(0);
	closelog();
	dpaa2_eal_common_log_exit();
	return DPAA2_SUCCESS;
}

/*
 * init the log library, called by dpaa2_eal_init() to enable early
 * logs
 */
int
dpaa2_eal_log_early_init(void)
{
	dpaa2_openearlylog_stream(stdout);
	return 0;
}
