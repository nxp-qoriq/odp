/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP buffer descriptor - implementation internal
 */

#ifndef ODP_BUFFER_INTERNAL_H_
#define ODP_BUFFER_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/atomic.h>
#include <odp/api/pool.h>
#include <odp/api/buffer.h>
#include <odp/api/debug.h>
#include <odp/api/align.h>
#include <odp_align_internal.h>
#include <odp_config_internal.h>
#include <odp/api/byteorder.h>
#include <odp/api/plat/sdk/rts/dpaa2_mbuf.h>

#define ODP_BITSIZE(x) \
	((x) <=     2 ?  1 : \
	((x) <=     4 ?  2 : \
	((x) <=     8 ?  3 : \
	((x) <=    16 ?  4 : \
	((x) <=    32 ?  5 : \
	((x) <=    64 ?  6 : \
	((x) <=   128 ?  7 : \
	((x) <=   256 ?  8 : \
	((x) <=   512 ?  9 : \
	((x) <=  1024 ? 10 : \
	((x) <=  2048 ? 11 : \
	((x) <=  4096 ? 12 : \
	((x) <=  8196 ? 13 : \
	((x) <= 16384 ? 14 : \
	((x) <= 32768 ? 15 : \
	((x) <= 65536 ? 16 : \
	 (0/0)))))))))))))))))

/* TODO: move these to correct files */

#define ODP_BUFFER_MAX_INDEX     (ODP_BUFFER_MAX_BUFFERS - 2)
#define ODP_BUFFER_INVALID_INDEX (ODP_BUFFER_MAX_BUFFERS - 1)

#define ODP_BUFS_PER_CHUNK       16
#define ODP_BUFS_PER_SCATTER      4

#define ODP_BUFFER_TYPE_CHUNK    0xffff
#define ODP_BUFFER_MAX_SEG \
	(ODP_CONFIG_PACKET_BUF_LEN_MAX / ODP_CONFIG_PACKET_SEG_LEN_MIN)

/* We can optimize storage of small raw buffers within metadata area */
#define ODP_MAX_INLINE_BUF     ((sizeof(void *)) * (ODP_BUFFER_MAX_SEG - 1))

#define ODP_BUFFER_POOL_BITS   ODP_BITSIZE(ODP_CONFIG_POOLS)
#define ODP_BUFFER_SEG_BITS    ODP_BITSIZE(ODP_BUFFER_MAX_SEG)
#define ODP_BUFFER_INDEX_BITS  (32 - ODP_BUFFER_POOL_BITS - ODP_BUFFER_SEG_BITS)
#define ODP_BUFFER_PREFIX_BITS (ODP_BUFFER_POOL_BITS + ODP_BUFFER_INDEX_BITS)
#define ODP_BUFFER_MAX_POOLS   (1 << ODP_BUFFER_POOL_BITS)
#define ODP_BUFFER_MAX_BUFFERS (1 << ODP_BUFFER_INDEX_BITS)

typedef union odp_buffer_bits_t {
	uint32_t     u32;
	odp_buffer_t handle;

	struct {
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
			uint32_t pool:ODP_BUFFER_POOL_BITS;
			uint32_t index:ODP_BUFFER_INDEX_BITS;
#else
			uint32_t index:ODP_BUFFER_INDEX_BITS;
			uint32_t pool:ODP_BUFFER_POOL_BITS;
#endif
	};
} odp_buffer_bits_t;


/* forward declaration */
struct odp_buffer_hdr_t;


typedef struct dpaa2_mbuf odp_buffer_hdr_t;

static inline odp_buffer_t odp_hdr_to_buf(odp_buffer_hdr_t *hdr)
{
	return (odp_buffer_t) hdr;
}


static inline odp_buffer_hdr_t *odp_buf_to_hdr(odp_buffer_t buf)
{
	return (odp_buffer_hdr_t *)buf;
}

static inline void _odp_buffer_type_set(odp_buffer_t buf, uint8_t type)
{
	odp_buffer_hdr_t *hdr = odp_buf_to_hdr(buf);

	/* resetting the event related bits*/
	hdr->usr_flags &= ~ODP_EVENT_TYPES;
	hdr->usr_flags |= (type & ODP_EVENT_TYPES);
}

/*
 * Buffer type
 *
 * @param buf      Buffer handle
 *
 * @return Buffer type
 */
int _odp_buffer_type(odp_buffer_t buf);

/*
 * Buffer type set
 *
 * @param buf      Buffer handle
 * @param type     New type value
 *
 */
void _odp_buffer_type_set(odp_buffer_t buf, uint8_t type);

int odp_buffer_snprint(char *str, uint32_t n, odp_buffer_t buf);

#ifdef __cplusplus
}
#endif

#endif
