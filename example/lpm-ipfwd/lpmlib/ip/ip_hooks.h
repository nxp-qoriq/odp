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

/**
 \file ip_hooks.h
 \brief This file provides the hooks that can be operated on the IP
 packet during different stages of its Life in a system
 */

#ifndef __IP_HOOKS_H
#define __IP_HOOKS_H
#include "ip.h"
#ifdef IP_RCU_ENABLE
#include "rcu_lock.h"
#endif
#include "ip_common.h"
#include <odp.h>

/*
	------------			       -------------
  IN-->| PREROUTING |			   -->| POSTROUTING |-->OUT
	------------			     |	  -------------
		|			     |		^
		v			     |		|
	------------	       -----------   |	   -----------
	|   ROUTE    |----->   |  FORWARD  |--	   |   ROUTE   |
	------------		-----------	    -----------
		|					^
		v					|
	------------	       -----------	   -----------
	|   INPUT    |----->  |	  LOCAL	  |------>|  OUTPUT   |
	------------	      |	 PROCESS  |	   -----------
				-----------
 */


/**
 \brief Different Hook Types
 \details Specifies the different stages at which the hooks can be operated
 */
enum IP_HOOK {
	IP_HOOK_PREROUTING,
	/**< InBound packet; Before Route LookUp*/
	IP_HOOK_INPUT,
	/**< Local Packet; Just After Route LookUp*/
	IP_HOOK_FORWARD,
	/**< For making Forwarding decisions*/
	IP_HOOK_OUTPUT,
	/**< Locally generated Packet that needs to be sent out*/
	IP_HOOK_POSTROUTING,
	/**< OutBound Packet; After Route LookUp; Before Sending it out*/
	__IP_HOOK_COUNT
};

enum IP_HOOK_PRAGMA {
	IP_HOOK_PRAGMA_NEXT
};

#define IP_HOOK_MAX_FUNCS_PER_HOOK	4
/**< Maximum number of Functions per Stage*/
#define IP_HOOK_ENTRIES_POOL_SIZE      (IP_HOOK_MAX_FUNCS_PER_HOOK *  \
					__IP_HOOK_COUNT * 2)

/**< Definition for the Hook Funciton to be called */
typedef enum IP_STATUS (*hookfn_t) (odp_packet_t buf, enum state);

/**
 \brief Hook Entry
 \details The Structure is a node containing the Hook Function, and
 the pointer to the next node in List
 */
struct ip_hook_entry_t {
	hookfn_t func;			/**< Hook Function*/
	struct ip_hook_entry_t *next;	/**< Next Node in the List*/
};

/**
 \brief Hook Chain
 \details The Structure has a list of Hook Function related to a
 particular Stage
 */
struct ip_hook_chain_t {
	struct ip_hook_entry_t *head;
	/**< Pointer to the List of Hook functions*/
	uint32_t func_count;
	/**< Number of Functions in the above list*/
	pthread_mutex_t wlock;
	/**< Lock to guard the List*/
};

/**
 \brief Hook Table
 \details The Structure has a list of Hook Chains, a chain per Stage
 */
struct ip_hooks_t {
	struct ip_hook_chain_t chains[__IP_HOOK_COUNT];
	/**< Array of Hook Chain*/
};

/**
 \brief Creates a Hook table
 \return Pointer to the Hook Table
 */
int ip_hooks_init(struct ip_hooks_t *hooks);

/**
 \brief Adds a Hook function to a particular Hook Chain in the table depending on the Hook Type/ stage
 \param[in] Pointer to the Hook table
 \param[in] hook Hook Type/ Stage
 \param[in] pragma Pragma Type
 \param[in] func Function Pointer to be added
 \return True if the Addiiton of the function was successfull, else False
 */
bool ip_hook_add_func(struct ip_hooks_t *hooks, enum IP_HOOK hook,
		      enum IP_HOOK_PRAGMA pragma, hookfn_t func);

/**
 \brief Returns the number of Hook function in a particular Hook Chain
 \param[in] Pointer to the Hook table
 \param[in] hook Hook Type/ Stage to find out the Chain
 \return number of Hook Functions related to Stage/ hook Type
 */
uint32_t ip_hook_count(struct ip_hooks_t *hooks, enum IP_HOOK hook);

/**
 \brief			Finds and Executes a Hook function from the Hook Table
			depending on the Hook type
 \param[in]	buf	Packet to be processed
 \param[in]	hooks	ip hooks structure pointer
 \param[in]	hook	Hook Type/ Stage
 \param[in] callback	Function Pointer to be executed after executing
			the Hook functions
 \param[in]	source	source of packet
 \return	True if the addition of the function was successfull, else False
 */
static inline enum IP_STATUS exec_hook(odp_packet_t buf,
					struct ip_hooks_t *hooks,
					enum IP_HOOK hook,
					hookfn_t callback,
					enum state source)
{
	struct ip_hook_chain_t *chain;
	struct ip_hook_entry_t *entry;
	enum IP_STATUS status;

#ifdef IP_RCU_ENABLE
	rcu_read_lock();
#endif
	status = IP_STATUS_ACCEPT;
	chain = hooks->chains + hook;
#ifdef IP_RCU_ENABLE
	entry = rcu_dereference(chain->head);
#else
	entry = chain->head;
#endif
	while ((entry != NULL) && (status == IP_STATUS_ACCEPT)) {
		status = entry->func(buf, source);
#ifdef IP_RCU_ENABLE
		entry = rcu_dereference(entry->next);
#else
		entry = entry->next;
#endif
	}
#ifdef IP_RCU_ENABLE
	rcu_read_unlock();
#endif
	if ((status == IP_STATUS_ACCEPT) && (callback != NULL))
		status = callback(buf, source);

	return status;
}

#endif	/* __IP_HOOKS_H */
