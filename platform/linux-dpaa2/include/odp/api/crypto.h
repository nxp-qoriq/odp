/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP crypto
 */

#ifndef ODP_PLAT_CRYPTO_H_
#define ODP_PLAT_CRYPTO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/buffer.h>
#include <odp/api/pool.h>
#include <odp/api/queue.h>
#include <odp/api/packet.h>

#include <odp/api/plat/crypto_types.h>
#include <odp/api/plat/crypto_pdcp_types.h>
/** @ingroup odp_crypto
 *  @{
 */

/**
 * @}
 */

#include <odp/api/spec/crypto.h>
#include <odp/api/spec/crypto_pdcp.h>

typedef struct {
	uint64_t	op_requests;  /*! Number of sec operations requested*/
	uint64_t	op_complete;  /*! Number of sec operations completed*/
	uint64_t	bytes;	      /*! Total number of bytes Encrypted/Decrypted*/
	uint64_t	errors;	      /*! Number of sec operations failed*/
} odp_crypto_ses_stats_t;

typedef struct {
	uint64_t	dequeued_requests;	/*! Number of Requests Dequeued*/
	uint64_t	ob_enc_requests;	/*! Number of Outbound Encrypt Requests*/
	uint64_t	ib_dec_requests;	/*! Number of Inbound Decrypt Requests*/
	uint64_t	ob_enc_bytes;		/*! Number of Outbound Bytes Encrypted*/
	uint64_t	ob_prot_bytes;		/*! Number of Outbound Bytes Protected*/
	uint64_t	ib_dec_bytes;		/*! Number of Inbound Bytes Decrypted*/
	uint64_t	ib_valid_bytes;		/*! Number of Inbound Bytes Validated*/
} odp_crypto_global_stats_t;


/**
 * Prints the packets stats for each SA
 */
void odp_crypto_print_stats(void);

/**
 * Get Session statistics
 *
 * @param	session	Session handle
 * @param[out]	stats	Output buffer for statistics
 * @return	0 on success or -1 on failure
 */
int odp_crypto_session_stats(odp_crypto_session_t session, odp_crypto_ses_stats_t *stats);

/**
 * Reset statistics for session
 *
 * @param	session	 session handle
 * @retval  0 on success
 * @retval <0 on failure
 *
 */
int odp_crypto_session_stats_reset(odp_crypto_session_t session);

/**
 * Get global crypto stats.
 *
 * @param[out]	stats	Output buffer for statistics
 * @retval	0	on success
 * @retval	-1	on failure
 */
int odp_crypto_global_stats(odp_crypto_global_stats_t *stats);
#ifdef __cplusplus
}
#endif

#endif
