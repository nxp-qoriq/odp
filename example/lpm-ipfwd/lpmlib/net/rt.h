/**
 \file rt.h
 \brief This file contains data structures, and functions to manage the Route
 table
 */
/*
 * Copyright (C) 2015 - 2016 Freescale Semiconductor, Inc.
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

#ifndef LIB_NET_RT_H
#define LIB_NET_RT_H

#include <statistics.h>
#include "app_common.h"
#include <stdbool.h>

/**< Pool Size for Routing Table Entries */
#ifdef ONE_MILLION_ROUTE_SUPPORT
#define RT_DEST_POOL_SIZE	(1024*1024)
#else
#define RT_DEST_POOL_SIZE	(2048)
#endif

/**
 \brief Routing Scope of the Packet - Local or Global
 */
enum ROUTE_SCOPE {
	ROUTE_LOCAL = 0,	/**< Packet which is self terminated*/
	ROUTE_GLOBAL,	/**< Packet which needs to be forwarded*/
	ROUTE_DECAP,	/** < Packet has associated Decap SA */
	ROUTE_ENCAP,	/** < Packet has associated Encap SA */
	ROUTE_PME	/**< Packet which needs to be scanned through PME & then forwarded */
};

/**< Packet which is self terminated */
#define	ROUTE_SCOPE_LOCAL (1<<ROUTE_LOCAL)
/**< Packet which needs to be forwarded */
#define	ROUTE_SCOPE_GLOBAL (1<<ROUTE_GLOBAL)
/** < Packet has associated Decap SA */
#define	ROUTE_SCOPE_DECAP (1<<ROUTE_DECAP)
/** < Packet has associated Encap SA */
#define	ROUTE_SCOPE_ENCAP (1<<ROUTE_ENCAP)
/**< Packet which needs to be scanned through PME & then forwarded */
#define	ROUTE_SCOPE_PME (1<<ROUTE_PME)
/**
 \brief Routing table destination Structure
 */
struct rt_dest_t {
	struct rt_dest_t *next;
	/**< Pointer to the next node in the Link List*/
	struct neigh_t *neighbor;
	/**< Pointer to th einformation related to next hop*/
	struct ppac_interface *dev;
	/**< Pointer to the Net Device*/
	void *tunnel;
	/**< Pointer to associated Tunnel for IPsec */
	uint8_t scope;
	/**< Scope of the Packet LOCAL/GLOBAL/TUNNEL*/
	stat32_t *refcnt;
	/**< Counter of application code references */
};

/** \brief		Initialize the route table
 *  \param[out] rt	Route table
 *  \return		On success, zero. On error, a negative value as per errno.h
 */
int rt_init(struct rt_dest_t *rt);


#if 0
/**
 \brief Free Entries Table Structure for Routing Entries
*/

struct rt_t {
	struct mem_cache_t *free_entries; /**< List of Free Entries */
} __attribute__((aligned(L1_CACHE_BYTES)));

/**
 \brief Route Table manipulation functions
 \param[in] Free Entry Table
 \return Pointer to the allocated Entry
 */
struct rt_dest_t *rt_dest_alloc(struct rt_t *rt);

/**
 \brief Frees the Route Table Entry if the ref count is zero
 \param[in] rt Pointer to the Routing Table
 \param[in] dest Pointer to the Entry to be freed
 \return True if Entry Freed else False
 */
bool rt_dest_try_free(struct rt_t *rt, struct rt_dest_t *dest);

/**
 \brief Frees the Route Table Entry when the ref count becomes zero
 \param[in] rt Pointer to the Routing Table
 \param[in] dest Pointer to the Entry to be freed
 */
void rt_dest_free(struct rt_t *rt, struct rt_dest_t *dest);
#endif

#endif	/* LIB_NET_RT_H */
