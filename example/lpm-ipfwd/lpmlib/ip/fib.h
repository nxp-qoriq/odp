/**
\file	fib.h
\brief	Common datatypes and hash-defines related to FIB lookup table
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

#ifndef _FIB_H_
#define _FIB_H_
#include "net/neigh.h"

#define FIB_TABLE_SIZE	(1024*1024)
#define FIB_NHPOOL_SIZE	FIB_TABLE_SIZE
#define FIB_DPOOL_SIZE	FIB_TABLE_SIZE

#define FIBTBL_MAX_LEVEL	5
#define FIBTBL_1STLVL_BITS	16
#define FIBTBL_2NDLVL_BITS	4
#define FIBTBL_3RDLVL_BITS	4
#define FIBTBL_4THLVL_BITS	4
#define FIBTBL_5THLVL_BITS	4

#define FIBTBL_1STLVL_SIZE	65536
#define FIBTBL_OTHLVL_SIZE	16

#define FIB_ENTRY_NUM	4096

#define FIB_RET_DROP	-1
#define FIB_RET_RECV	-2
#define FIB_RET_MISS	-3	/* route not found */

typedef enum {
	NH_DROP,	/* drop the packet */
	NH_RECV,	/* receive the packet for self-handling */
	NH_FWD	/* forward the packet according to route-table */
} __attribute__((packed)) nh_action_t;


extern int fib_init(void);
extern int fib_add_route(uint32_t ipaddr, uint8_t maskbits,
			uint32_t gw, uint16_t port, nh_action_t act,
			struct neigh_t *n);
extern int ip_route_lookup(uint32_t daddr, uint32_t *gwaddr,
			struct neigh_t *notes);
extern int fib_table_dump(void);

#endif	/*_FIB_H_*/
