/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/**
 * @file
 *
 * ODP crypto
 */

#ifndef ODP_CRYPTO_IPSEC_TYPES_H_
#define ODP_CRYPTO_IPSEC_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_crypto
 *  @{
 */

enum odp_ipsec_mode {
	ODP_IPSEC_MODE_TUNNEL,	    /**< IPSec tunnel mode */
	ODP_IPSEC_MODE_TRANSPORT,   /**< IPSec transport mode */
};

enum odp_ipsec_proto {
	ODP_IPSEC_ESP,		   /**< ESP protocol */
};

enum odp_ipsec_outhdr_type {
	ODP_IPSEC_OUTHDR_IPV4,	  /**< Outer header is IPv4 */
	ODP_IPSEC_OUTHDR_IPV6,	  /**< Outer header is IPv6 */
};

enum odp_ipsec_ar_ws {
	ODP_IPSEC_AR_WS_NONE,	   /**< Anti-replay is not enabled */
	ODP_IPSEC_AR_WS_32,	   /**< Anti-replay window size 32 */
	ODP_IPSEC_AR_WS_64,	   /**< Anti-replay window size 64 */
	ODP_IPSEC_AR_WS_128,	   /**< Anti-replay window size 128 */
};

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
