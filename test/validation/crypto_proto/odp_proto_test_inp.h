/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */
#ifndef ODP_proto_TEST_ASYNC_INP_
#define ODP_proto_TEST_ASYNC_INP_

#include <odp_cunit_common.h>

/* Suite names */
#define ODP_PDCP_CPLANE_ENCAP	"proto_test_pdcp_cplane_encap"
#define ODP_PDCP_UPLANE_ENCAP    "proto_test_pdcp_uplane_encap"
#define ODP_PDCP_CPLANE_DECAP	"proto_test_pdcp_cplane_decap"
#define ODP_PDCP_UPLANE_DECAP    "proto_test_pdcp_uplane_decap"

/* Suite test array */
extern odp_testinfo_t proto_suite_cplane_encap[];
extern odp_testinfo_t proto_suite_uplane_encap[];
extern odp_testinfo_t proto_suite_cplane_decap[];
extern odp_testinfo_t proto_suite_uplane_decap[];

int proto_suite_async_init(void);

#endif
