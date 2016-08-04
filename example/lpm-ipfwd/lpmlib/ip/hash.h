/**
\file	hash.h
\brief	Common datatypes and defines related to hash table implementation
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

#ifndef _HASH_H_
#define _HASH_H_

#include <stdio.h>
#include <odp.h>

#define MAX_HASH_KEY_SIZE	16
#define CLASSIFY_HASHTAB_SIZE	(128*1024)
#define ARP_HASHTAB_SIZE	(4*1024)

struct linknode {
	struct linknode *prev, *next;
	uint32_t key;	/* hash key value */
	uint8_t strkey[MAX_HASH_KEY_SIZE];	/* hash key string */
	void *data;	/* data pointer */
};

struct bucket {
	struct linknode *linklist;
};

struct hashtable {
	struct bucket *htable;
	uint32_t size;	/* should be multiple of 32 */
	uint32_t nel;	/* current number of elements in the hash table */
	int keysize;	/* each hash table has the same keysize */
	uint64_t (*hash_func)(struct hashtable *h, const void *key);
	int (*key_cmp)(struct hashtable *h, const void *key1, const void *key2);
	int (*key_cpy)(struct hashtable *h, void *keyto, const void *keyfrom);
	struct linknode *freepool;
	uint32_t *indexpool;	/* bitmap pool of linknodes which
						indicating used or not */
	uint32_t isize;	/* equal to (size/32) */
};

extern struct hashtable *hashtab_create
			(uint64_t (*hash_func)(struct hashtable *h,
			const void *key), int (*key_cmp)(struct hashtable *h,
			const void *key1, const void *key2), int (*key_cpy)
			(struct hashtable *h, void *key1, const void *key2),
			uint32_t size, int keysize);
extern int hashtab_add(struct hashtable *h, void *key, void *data);
extern int hashtab_delete(struct hashtable *h, void *key, void *data);
extern int hashtab_update(struct hashtable *h, void *key, void *data,
							void *olddata);
extern int hashtab_destroy(struct hashtable *h);
extern void *hashtab_search(struct hashtable *h, const void *key,
							void *hash_res);
extern uintptr_t idx_getnode(uintptr_t pool, uint32_t entrysz, uint32_t *idxtbl,
					uint32_t idxsz, uint32_t weight);
extern int idx_putnode(uintptr_t pool, uint32_t poolsz, uint32_t entrysz,
			uint32_t *idxtbl, uintptr_t node, uint32_t weight);

#endif /*_HASH_H_*/
