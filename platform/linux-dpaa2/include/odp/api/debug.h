/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP debug
 */

#ifndef ODP_PLAT_DEBUG_H_
#define ODP_PLAT_DEBUG_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @ingroup odp_ver_abt_log_dbg
 *  @{
 */

#ifndef ODP_UNIMPLEMENTED
/**
 * This macro is used to indicate when a given function is not implemented
 */
#define ODP_UNIMPLEMENTED() \
		printf("%s:%d:The function %s() is not implemented\n", \
			__FILE__, __LINE__, __func__)

#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/counters/counters.h>

/**
 *  Macros to define Object Identifier
 */

enum dpaa2_debug_object_identifier {
	DPAA2_DEBUG_DPNI_STATS = 0,
	DPAA2_DEBUG_DPNI_ATTRIBUTES,
	DPAA2_DEBUG_DPNI_LINK_STATE,
	DPAA2_DEBUG_DPNI_MAX_FRAME_LENGTH,
	DPAA2_DEBUG_DPNI_MTU,
	DPAA2_DEBUG_DPNI_L3_CHKSUM_VALIDATION,
	DPAA2_DEBUG_DPNI_L4_CHKSUM_VALIDATION,
	DPAA2_DEBUG_DPNI_PRIMARY_MAC_ADDR,
	DPAA2_DEBUG_QBMAN_FQ_ATTR_CGRID,
	DPAA2_DEBUG_QBMAN_FQ_ATTR_DESTWQ,
	DPAA2_DEBUG_QBMAN_FQ_ATTR_TDTHRESH,
	DPAA2_DEBUG_QBMAN_FQ_ATTR_CTX,
	DPAA2_DEBUG_QBMAN_FQ_STATE_SCHEDSTATE,
	DPAA2_DEBUG_QBMAN_FQ_STATE_FRAME_COUNT,
	DPAA2_DEBUG_QBMAN_FQ_STATE_BYTE_COUNT,
	DPAA2_DEBUG_QBMAN_BP_INFO_HAS_FREE_BUFS,
	DPAA2_DEBUG_QBMAN_BP_INFO_IS_DEPLETED,
	DPAA2_DEBUG_QBMAN_BP_INFO_NUM_FREE_BUFS,
	DPAA2_DEBUG_DPSECI_ATTRIBUTES,
	DPAA2_DEBUG_DPSECI_COUNTERS,
	DPAA2_DEBUG_PER_SA_STATS,
	/*TODO: More objects need to be added as per requirement*/
};

/**
 *  Macros to define command on given object
 */

enum dpaa2_debug_command {
	DPAA2_DEBUG_CMD_GET = 0,
	DPAA2_DEBUG_CMD_RESET,
	DPAA2_DEBUG_CMD_SET
	/*TODO: More commands need to be added for other object operations*/
};

/**
 * Structure to define message format accepted by ODP debug control thread
 *
 * @params
 * obj_id	Object identifier given by user. Use 'DPAA2_DEBUG_<X>' values.
 * cmd		Command like get/set/reset,given by user. Use 'DPAA2_DEBUG_<X>' values.
 * buffer_len	Length of buffer
 * buffer	Device name given by user.
 *
 */
typedef struct ipc_msg {
	uint16_t obj_id;
	uint8_t cmd;
	uint8_t buffer_len;
	char buffer[64];
} ipc_msg_t;

/**
 * @}
 */

#include <odp/api/spec/debug.h>

#if defined(__GNUC__) && !defined(__clang__)

#if __GNUC__ < 4 || (__GNUC__ == 4 && (__GNUC_MINOR__ < 6))

/**
 * @internal _Static_assert was only added in GCC 4.6. Provide a weak replacement
 * for previous versions.
 */
#define _Static_assert(e, s) (extern int (*static_assert_checker(void)) \
	[sizeof(struct { unsigned int error_if_negative:(e) ? 1 : -1; })])

#else
#define _Static_assert(e, s)
#endif

#else
#define _Static_assert(e, s)
#endif

/**
 * @internal Compile time assertion macro. Fails compilation and outputs 'msg'
 * if condition 'cond' is false. Macro definition is empty when compiler is not
 * supported or the compiler does not support static assertion.
 */
#define ODP_STATIC_ASSERT(cond, msg)  _Static_assert(cond, msg)

#ifdef __cplusplus
}
#endif

#endif
