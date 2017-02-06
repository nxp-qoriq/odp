/* Copyright 2016-2017 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_IPSEC_INTERNAL_H_
#define ODP_IPSEC_INTERNAL_H_
#ifdef __cplusplus
extern "C" {
#endif
#include <odp/api/ipsec.h>

#define ODP_CONFIG_IPSEC_SA 1024
#define ODP_CONFIG_IPSEC_BUCKET 1024
#define SEC_FLC_DHR_OUTBOUND -114
#define SEC_FLC_DHR_INBOUND 0

#define SA_STATUS_FREE     0
#define SA_STATUS_INUSE    1

typedef struct ipsec_sa_entry_u {

	/** SPI value */
	uint32_t spi;

	/** Destination queue for IPSEC events
	 *
	 *  Operations in asynchronous mode enqueue resulting events into
	 *  this queue.
	 */
	odp_queue_t dest_queue;

	/** SA lookup mode */
	uint8_t lookup_mode;
	uint8_t dir;
	uint8_t status;

	/** User defined SA context pointer
	 *
	 *  User defined context pointer associated with the SA.
	 *  The implementation may prefetch the context data. Default value
	 *  of the pointer is NULL.
	 */
	void *user_context;
	void *context;
	void *cipher_key;
	void *auth_key;
	void *next;

} ipsec_sa_entry_t;

typedef struct ipsec_sa_table_t {
	ipsec_sa_entry_t sa[ODP_CONFIG_IPSEC_SA];
} ipsec_sa_table_t;

typedef struct ipsec_vq_t {
	void *rx_vq;
	uint8_t vq_id;
	int num_sa;
} ipsec_vq_t;

#define SLOCK(a)      odp_spinlock_lock(a)
#define SUNLOCK(a)    odp_spinlock_unlock(a)
#define SLOCK_INIT(a) odp_spinlock_init(a)

/**
 * Hash calculation utility
 */
#define JHASH_GOLDEN_RATIO	0x9e3779b9
#define rot(x, k) (((x) << (k)) | ((x) >> (32 - (k))))
#define ODP_BJ3_MIX(a, b, c) \
{ \
	a -= c; a ^= rot(c, 4); c += b; \
	b -= a; b ^= rot(a, 6); a += c; \
	c -= b; c ^= rot(b, 8); b += a; \
	a -= c; a ^= rot(c, 16); c += b; \
	b -= a; b ^= rot(a, 19); a += c; \
	c -= b; c ^= rot(b, 4); b += a; \
}

/**
 * Flow cache table bucket
 */
typedef struct {
	odp_spinlock_t		lock;	/**< Bucket lock*/
	ipsec_sa_entry_t	*next;	/**< Pointer to first sa entry in bucket*/
} sa_bucket_t;

#ifdef __cplusplus
}
#endif

#endif
