/*
 * Copyright (C) 2015,2016 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** @file
 * This file provides APIs for RCU locks
 */

#ifndef LIB_COMMON_RCU_LOCK_H
#define LIB_COMMON_RCU_LOCK_H

#ifdef __cplusplus
	extern "C" {
#endif
#include <stdint.h>
#include <compiler.h>

struct rcu_reclaimer_t;

typedef void (*free_func_t) (void *, void *);

/**
\brief          RCU library initialisation routine.
\details        This routine initialises the RCU lib.
\return         Handle to a RCU reclaimer object.
*/
struct rcu_reclaimer_t *rcu_initialize(void);

/**
\brief		RCU read lock routine
\details	Used by a reader to inform the reclaimer that the reader
		is entering an RCU read-side critical section. It is
		illegal to block while in an RCU read-side critical section.
		Any RCU-protected data structure accessed during an RCU
		read-side critical section is guaranteed to remain unreclaimed
		for the full duration of that critical section.
\return		None
 */
static inline void
rcu_read_lock(void)
{
}

/**
\brief		RCU read unlock routine
\details	Used by a reader to inform the reclaimer that the reader
		is exiting an RCU read-side critical section.  Note that
		RCU read-side critical sections may be nested and/or
		overlapping.
\return		None
 */

static inline void
rcu_read_unlock(void)
{
}

/**
\brief		Synchronizes a CPU
\details	Indicates that a particular CPU is done with all RCU
		read-side critical sections.
 \param[in]	cpu_id -- ID of the CPU
\return		None
 */
void rcu_synchronize_cpu(uint32_t cpu_id);

/* void rcu_free(free_func_t free_func, void *data_to_free, void *cxt); */

/**
\brief		Join a CPU into RCU
\details	This routine is called by a CPU to announce that it wants
		to protect a RCU protected database.
 \param[in]	cpu_id -- ID of the CPU
\return		None
 */
void rcu_join(uint32_t cpu_id);

/**
\brief		Removes a CPU from RCU
\details	This routine is called by a CPU to announce that it is
		stopping using a RCU protected database.
 \param[in]	cpu_id -- ID of the CPU
\return		None
 */
void rcu_leave(uint32_t cpu_id);

/** RCU reclaimer
 * @param[in] free_func Name of reclaimer function which does the work
 *	      of freeing memory or deletion of data etc.
 * @param[in] data_to_free Argument of reclaimer function.
 * @param[in] ctxt Argument of reclaimer function.
 */
void rcu_free(free_func_t free_func, void *data_to_free, void *ctxt);

/** Atomically set the specified pointer to the new value, and guarantee
 * that the set of the pointer appears to "happen-after" every modification
 * to the data structure to which parameter v refers.
 */
#define rcu_assign_pointer(p, v) {__EXTENSION	\
	{					\
		wmb();				\
		(p) = (v);			\
	} }

/** Acquire a reference to RCU-protected pointer P.  This should compile to a
 * simple dereference on almost all architectures.  There is really no way to
 * do this as a function - written as a #define here.
 */
#define rcu_dereference(p) {__EXTENSION		\
	{					\
		typeof(p) ______tmp = p;	\
		ddb();				\
		(______tmp);			\
	} }

#ifdef __cplusplus
	}
#endif
#endif				/* ifndef LIB_COMMON_RCU_LOCK_H */
