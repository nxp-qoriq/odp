/*-
 *   Derived from DPDK's rte_tailq.h
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

#ifndef _DPAA2_TAILQ_H_
#define _DPAA2_TAILQ_H_

/**
 * @file
 *  Here defines dpaa2_tailq APIs for only internal use
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <dpaa2_queue.h>

#include <stdio.h>

/** dummy structure type used by the dpaa2_tailq APIs */
struct dpaa2_tailq_entry {
	TAILQ_ENTRY(dpaa2_tailq_entry) next; /**< Pointer entries for a tailq list */
	void *data; /**< Pointer to the data referenced by this tailq entry */
};
/** dummy */
TAILQ_HEAD(dpaa2_tailq_entry_head, dpaa2_tailq_entry);

#define DPAA2_TAILQ_NAMESIZE 32

/**
 * The structure defining a tailq header entry for storing
 * in the dpaa2_config structure in shared memory. Each tailq
 * is identified by name.
 * Any library storing a set of objects e.g. rings, mempools, hash-tables,
 * is recommended to use an entry here, so as to make it easy for
 * a multi-process app to find already-created elements in shared memory.
 */
struct dpaa2_tailq_head {
	struct dpaa2_tailq_entry_head tailq_head; /**< NOTE: must be first element */
};

#ifdef __cplusplus
}
#endif

#endif /* _DPAA2_TAILQ_H_ */
