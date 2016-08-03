/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */


/*!
 * @file dpaa2_time.h
 *
 * @brief Time related functions
 *
 * @addtogroup DPAA2_TIMER
 * @ingroup DPAA2_RTS
 * @{
 */

#ifndef _DPAA2_TIME_H_
#define _DPAA2_TIME_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>

#define MS_PER_S 1000ULL /*!< Seconds in a Millisecond */
#define US_PER_S 1000000ULL /*!< Seconds in a Microsecond */
#define NS_PER_S 1000000000ULL /*!< Seconds in a Nanosecond */

/*!
 * @details	get the system ticks. (equivalent to jiffies)
 *
 * @param[out]	 number of ticks since the start of the system
 *
 */
uint64_t dpaa2_time_get_cycles(void);


/*!
 * @details	Time difference
 *
 * @param[in]	t1    First time stamp
 * @param[in]	t2    Second time stamp
 *
 * @param[out]	Difference of time stamps
 */
uint64_t dpaa2_time_diff_cycles(uint64_t t2, uint64_t t1);


/*!
 * @details	Convert CPU cycles to nanoseconds
 *
 * @param[in]	cycles  Time in CPU cycles
 *
 * @param[out]	Time in nanoseconds
 */
uint64_t dpaa2_time_cycles_to_ns(uint64_t cycles);

/*!
 * @details	Sleep for millisecond
 *
 * @param[in]	mst  Time in miliseconds
 *
 *
 */
void dpaa2_msleep(uint32_t mst);

/*!
 * @details	Sleep for microsecond
 *
 * @param[in]	ust  Time in microseconds
 *
 *
 */
void dpaa2_usleep(uint32_t ust);

#ifdef __cplusplus
}
#endif

/*! @} */

#endif /* _DPAA2_TIME_H_ */
