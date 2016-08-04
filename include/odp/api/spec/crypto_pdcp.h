/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/**
 * @file
 *
 * ODP crypto PDCP extension
 */

/** @addtogroup odp_crypto
 *  @{
 */

#ifndef ODP_API_CRYPTO_PDCP_H_
#define ODP_API_CRYPTO_PDCP_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * PDCP CONFIG API session parameters
 */
typedef struct odp_pdcp_params_s {
	int8_t bearer;	/**< PDCP bearer ID */
	int8_t pkt_dir; /**< PDCP Frame Direction 0:UL 1:DL*/
	int8_t hfn_ovd; /**< Overwrite HFN per operation.
			 * Use override_iv_ptr for overriding*/
	uint8_t	sn_size; /**< Sequence number size, 5/7/12/15 */
	uint32_t hfn;	/**< Hyper Frame Number */
	uint32_t hfn_threshold;	/**< HFN Threashold for key renegotiation */
} odp_pdcp_params_t;

/**
 * Enhance a crypto session to provide PDCP protocol processing as well.
 *
 * If an implementation does not support a particular set of
 * arguments it should return error.
 *
 * @param session	    Session handle
 * @param pdcp_mode	    Control Plane or Data Plane
 * @param pdcp_params	    PDCP parameters.
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_crypto_session_config_pdcp(odp_crypto_session_t session,
				   odp_pdcp_mode_t pdcp_mode,
				    odp_pdcp_params_t* pdcp_params);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
