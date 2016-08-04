/**
 \file rt.c
 \brief Implements a simple, fast route cache for ip forwarding.
 */
/*
 * Copyright (C) 2015-2016 Freescale Semiconductor, Inc.
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

#include "rt.h"
#include "common/refcount.h"
#include <odp.h>

int rt_init(struct rt_t *rt)
{
	uint32_t entries;

	memset(rt, 0, sizeof(*rt));
	rt->free_entries = mem_cache_create(sizeof(*rt->free_entries),
					    RT_DEST_POOL_SIZE);
	if (odp_unlikely(rt->free_entries == NULL))
		return -ENOMEM;

	entries = mem_cache_refill(rt->free_entries, RT_DEST_POOL_SIZE);
	if (odp_unlikely(entries != RT_DEST_POOL_SIZE)) {
		/** \todo mem_cache_destory(rt->free_entries); */
		return -ENOMEM;
	}

	return 0;
}

struct rt_dest_t *rt_dest_alloc(struct rt_t *rt)
{
	struct rt_dest_t *dest;

	dest = mem_cache_alloc(rt->free_entries);
	if (odp_likely(NULL != dest)) {
		dest->refcnt = refcount_create();
		if (dest->refcnt == NULL)
			return NULL;
	}
	return dest;
}

bool rt_dest_try_free(struct rt_t *rt, struct rt_dest_t *dest)
{
	bool retval;

	if (refcount_try_await_zero(dest->refcnt)) {
		refcount_destroy((void *)dest->refcnt);
		mem_cache_free(rt->free_entries, dest);
		retval = true;
	} else {
		retval = false;
	}

	return retval;
}

void rt_dest_free(struct rt_t *rt, struct rt_dest_t *dest)
{
	bool done;

	do {
		done = rt_dest_try_free(rt, dest);
	} while (done == false);
}
