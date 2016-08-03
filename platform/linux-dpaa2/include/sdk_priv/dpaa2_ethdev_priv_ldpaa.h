/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 *
 */

/*!
 * @file	dpaa2_ethdev_priv_ldpaa.h
 *
 * @brief	Private API's required by Ethernet Configuration APIs implementation.
 *
 * @addtogroup	DPAA2_ETH
 * @ingroup	DPAA2_DEV
 * @{
 */

#include <dpaa2_ethdev.h>

/*MC header files*/
#include <fsl_dpkg.h>

/*!
 * @details	This API converts the req_dist_set, which is set by the user
 *		of this API to the MC's understandable form (dpkg_profile_cfg).
 *
 * @param[in]	req_dist_set - The distribution set on which the hashi
 *		distibution is to be configured.
 *
 * @param[out]	kg_cfg - The dpkg_profile_cfg corresponding to req_dist_set
 *
 * @returns	none
 *
 */
void dpaa2_distset_to_dpkg_profile_cfg(
		uint32_t req_dist_set,
		struct dpkg_profile_cfg *kg_cfg);

/*! @} */
