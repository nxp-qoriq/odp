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
 \file ip_hooks.c
 */

#include "ip_hooks.h"
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

int ip_hooks_init(struct ip_hooks_t *hooks)
{
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(hooks->chains); i++) {
		hooks->chains[i].head = NULL;
		hooks->chains[i].func_count = 0;
		pthread_mutex_init(&hooks->chains[i].wlock, NULL);
	}
	return 0;
}

bool ip_hook_add_func(struct ip_hooks_t *hooks, enum IP_HOOK hook,
		      enum IP_HOOK_PRAGMA pragma, hookfn_t func)
{
	struct ip_hook_chain_t *chain;
	struct ip_hook_entry_t *new_entry;
	struct ip_hook_entry_t *entry;
	struct ip_hook_entry_t **entry_ptr;

#ifdef IP_RCU_ENABLE
	rcu_read_lock();
#endif
	chain = &(hooks->chains[hook]);
	pthread_mutex_lock(&(chain->wlock));
	if (chain->func_count >= IP_HOOK_MAX_FUNCS_PER_HOOK) {
		pthread_mutex_unlock(&(chain->wlock));
#ifdef IP_RCU_ENABLE
		rcu_read_unlock();
#endif
		return false;
	}

	new_entry = (struct ip_hook_entry_t *)malloc(
			sizeof(struct ip_hook_entry_t));
	if (new_entry == NULL) {
		pthread_mutex_unlock(&(chain->wlock));
#ifdef IP_RCU_ENABLE
		rcu_read_unlock();
#endif
		return false;
	}

	new_entry->func = func;
	switch (pragma) {
	case IP_HOOK_PRAGMA_NEXT:
		new_entry->next = NULL;
		entry_ptr = &(chain->head);
#ifdef IP_RCU_ENABLE
		entry = rcu_dereference(*entry_ptr);
#else
		entry = *entry_ptr;
#endif
		while (entry != NULL) {
			entry_ptr = &(entry->next);
#ifdef IP_RCU_ENABLE
			entry = rcu_dereference(*entry_ptr);
#else
			entry = *entry_ptr;
#endif
		}

#ifdef IP_RCU_ENABLE
		rcu_assign_pointer(*entry_ptr, new_entry);
#else
		*entry_ptr = new_entry;
#endif

		break;
	default:
		return false;
	}
	++chain->func_count;

	pthread_mutex_unlock(&(chain->wlock));
#ifdef IP_RCU_ENABLE
	rcu_read_unlock();
#endif
	return true;
}

uint32_t ip_hook_count(struct ip_hooks_t *hooks, enum IP_HOOK hook)
{
	struct ip_hook_chain_t *chain;
	uint32_t count;

	chain = &(hooks->chains[hook]);
	pthread_mutex_lock(&(chain->wlock));
	count = chain->func_count;
	pthread_mutex_unlock(&(chain->wlock));
	return count;
}
