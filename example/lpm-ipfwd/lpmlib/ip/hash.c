/**
 \file hash.c
 \brief hash table functions
 */
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
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

#include "hash.h"
#include <example_debug.h>
#include <errno.h>

/* get a new entry from the pool to use.
 * clear the according bit of indexpool to indicate the usage of that node.
 * pool - address of the entry array which has been allocated already.
 * idxtbl - the index array of pool which has been allocated already.
 * idxsz - the index array size (poolsize / 32 / weight)
 * weight - might has dozen of entries as a unit for indexing
 * (like fib subtable).
 *
 * return the entry address.
 */
uintptr_t idx_getnode(uintptr_t pool, uint32_t entrysz, uint32_t *idxtbl,
		     uint32_t idxsz, uint32_t weight)
{
	uint32_t i, j, val;

	for (i = 0; i < idxsz; i++) {
		if (idxtbl[i] != 0)
			break;
	}
	if (i == idxsz)
		return 0;

	val = idxtbl[i];
	for (j = 0; j < 32; j++) {
		if ((val >> j) & 1)
			break;
	}

	/* clear bit j of index[i] to indicate that linknode is allocated */
	idxtbl[i] &= ~((uint32_t) (1 << j));
	val = (i * 32 + j) * weight;

	return pool + (val * entrysz);
}

/* put the not-used entry back to freepool.
 * set the according bit of indexpool to indicate that node is available again.
 * pool - address of the entry array which has been allocated already.
 * poolsz - pool size of entry number.
 * entrysz - size in bytes of each entry.
 * idxtbl - the index array of pool which has been allocated already.
 * node - address of the entry to release.
 * weight - might has dozen of entries as a unit for indexing
 * (like fib subtable).
 */
int idx_putnode(uintptr_t pool, uint32_t poolsz, uint32_t entrysz,
		uint32_t *idxtbl, uintptr_t node, uint32_t weight)
{
	uint32_t i;

	if ((node < pool) || (node >= (pool + poolsz * entrysz))) {
		EXAMPLE_ERR
		    ("\r\n%s: invalid node pointer %"PRIxPTR"  to release.",
			__func__, node);
		return -EINVAL;
	}

	i = (node - pool) / (entrysz * weight);
	idxtbl[i / 32] |= (uint32_t) (1 << (i % 32));

	memset((char *)node, 0, entrysz * weight);

	return 0;
}
