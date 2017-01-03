/* Copyright (c) 2015, Linaro Limited
 *  * All rights reserved.
 *   *
 *    * SPDX-License-Identifier:     BSD-3-Clause
 *     */
#define _POSIX_C_SOURCE 200809L

#include <odp/api/time.h>
#include <odp/api/hints.h>
#include <odp/api/system_info.h>
#include <usdpaa/fsl_usd.h>

static inline uint64_t odp_time_cycles(void)
{
        return mfatb();
}
