/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP ipsec
 */

#ifndef ODP_PLAT_IPSEC_H_
#define ODP_PLAT_IPSEC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/buffer.h>
#include <odp/api/pool.h>
#include <odp/api/queue.h>
#include <odp/api/packet.h>

/** @ingroup odp_crypto
 *  @{
 */

/**
 * @}
 */

#define ODP_IPSEC_SA_INVALID (0xffffffffffffffffULL)

typedef uint64_t odp_ipsec_sa_t;

#include <odp/api/spec/ipsec.h>
#ifdef __cplusplus
}
#endif

#endif
