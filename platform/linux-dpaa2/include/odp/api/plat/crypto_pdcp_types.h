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

#ifndef ODP_CRYPTO_PDCP_TYPES_H_
#define ODP_CRYPTO_PDCP_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_crypto
 *  @{
 */

/**
 * Crypto PDCP API PDCP Mode of session
 */
typedef enum {
	ODP_PDCP_MODE_CONTROL,	    /**< PDCP control plane mode */
	ODP_PDCP_MODE_DATA,   /**< PDCP data plane mode */
} odp_pdcp_mode_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
