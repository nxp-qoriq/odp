/* Copyright (c) 2015, Linaro Limited
 * Copyright (C) 2015-2016 Freescale Semiconductor,Inc
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_proto_H_
#define _ODP_TEST_proto_H_

#include "odp_cunit_common.h"
/* test functions: */
void proto_test_pdcp_cplane_encap(int i);
void proto_test_pdcp_uplane_encap(int i);
void proto_test_pdcp_cplane_decap(int i);
void proto_test_pdcp_uplane_decap(int i);
void cplane_null_null_ul_encap(void);
void cplane_null_null_dl_encap(void);
void cplane_null_snow_ul_encap(void);
void cplane_null_snow_dl_encap(void);
void cplane_null_aes_ul_encap(void);
void cplane_null_aes_dl_encap(void);
void cplane_null_zuc_ul_encap(void);
void cplane_null_zuc_dl_encap(void);
void cplane_snow_null_ul_encap(void);
void cplane_snow_null_dl_encap(void);
void cplane_snow_snow_ul_encap(void);
void cplane_snow_snow_dl_encap(void);
void cplane_snow_aes_ul_encap(void);
void cplane_snow_aes_dl_encap(void);
void cplane_snow_zuc_ul_encap(void);
void cplane_snow_zuc_dl_encap(void);
void cplane_aes_null_ul_encap(void);
void cplane_aes_null_dl_encap(void);
void cplane_aes_snow_ul_encap(void);
void cplane_aes_snow_dl_encap(void);
void cplane_aes_aes_ul_encap(void);
void cplane_aes_aes_dl_encap(void);
void cplane_aes_zuc_ul_encap(void);
void cplane_aes_zuc_dl_encap(void);
void cplane_zuc_null_ul_encap(void);
void cplane_zuc_null_dl_encap(void);
void cplane_zuc_snow_ul_encap(void);
void cplane_zuc_snow_dl_encap(void);
void cplane_zuc_aes_ul_encap(void);
void cplane_zuc_aes_dl_encap(void);
void cplane_zuc_zuc_ul_encap(void);
void cplane_zuc_zuc_dl_encap(void);
void cplane_null_null_ul_decap(void);
void cplane_null_null_dl_decap(void);
void cplane_null_snow_ul_decap(void);
void cplane_null_snow_dl_decap(void);
void cplane_null_aes_ul_decap(void);
void cplane_null_aes_dl_decap(void);
void cplane_null_zuc_ul_decap(void);
void cplane_null_zuc_dl_decap(void);
void cplane_snow_null_ul_decap(void);
void cplane_snow_null_dl_decap(void);
void cplane_snow_snow_ul_decap(void);
void cplane_snow_snow_dl_decap(void);
void cplane_snow_aes_ul_decap(void);
void cplane_snow_aes_dl_decap(void);
void cplane_snow_zuc_ul_decap(void);
void cplane_snow_zuc_dl_decap(void);
void cplane_aes_null_ul_decap(void);
void cplane_aes_null_dl_decap(void);
void cplane_aes_snow_ul_decap(void);
void cplane_aes_snow_dl_decap(void);
void cplane_aes_aes_ul_decap(void);
void cplane_aes_aes_dl_decap(void);
void cplane_aes_zuc_ul_decap(void);
void cplane_aes_zuc_dl_decap(void);
void cplane_zuc_null_ul_decap(void);
void cplane_zuc_null_dl_decap(void);
void cplane_zuc_snow_ul_decap(void);
void cplane_zuc_snow_dl_decap(void);
void cplane_zuc_aes_ul_decap(void);
void cplane_zuc_aes_dl_decap(void);
void cplane_zuc_zuc_ul_decap(void);
void cplane_zuc_zuc_dl_decap(void);
void uplane_null_ul_12bit_encap(void);
void uplane_null_dl_12bit_encap(void);
void uplane_null_ul_7bit_encap(void);
void uplane_null_dl_7bit_encap(void);
void uplane_null_ul_15bit_encap(void);
void uplane_null_dl_15bit_encap(void);
void uplane_snow_ul_12bit_encap(void);
void uplane_snow_dl_12bit_encap(void);
void uplane_snow_ul_7bit_encap(void);
void uplane_snow_dl_7bit_encap(void);
void uplane_snow_ul_15bit_encap(void);
void uplane_snow_dl_15bit_encap(void);
void uplane_aes_ul_12bit_encap(void);
void uplane_aes_dl_12bit_encap(void);
void uplane_aes_ul_7bit_encap(void);
void uplane_aes_dl_7bit_encap(void);
void uplane_aes_ul_15bit_encap(void);
void uplane_aes_dl_15bit_encap(void);
void uplane_zuc_ul_12bit_encap(void);
void uplane_zuc_dl_12bit_encap(void);
void uplane_zuc_ul_7bit_encap(void);
void uplane_zuc_dl_7bit_encap(void);
void uplane_zuc_ul_15bit_encap(void);
void uplane_zuc_dl_15bit_encap(void);
void uplane_null_ul_12bit_decap(void);
void uplane_null_dl_12bit_decap(void);
void uplane_null_ul_7bit_decap(void);
void uplane_null_dl_7bit_decap(void);
void uplane_null_ul_15bit_decap(void);
void uplane_null_dl_15bit_decap(void);
void uplane_snow_ul_12bit_decap(void);
void uplane_snow_dl_12bit_decap(void);
void uplane_snow_ul_7bit_decap(void);
void uplane_snow_dl_7bit_decap(void);
void uplane_snow_ul_15bit_decap(void);
void uplane_snow_dl_15bit_decap(void);
void uplane_aes_ul_12bit_decap(void);
void uplane_aes_dl_12bit_decap(void);
void uplane_aes_ul_7bit_decap(void);
void uplane_aes_dl_7bit_decap(void);
void uplane_aes_ul_15bit_decap(void);
void uplane_aes_dl_15bit_decap(void);
void uplane_zuc_ul_12bit_decap(void);
void uplane_zuc_dl_12bit_decap(void);
void uplane_zuc_ul_7bit_decap(void);
void uplane_zuc_dl_7bit_decap(void);
void uplane_zuc_ul_15bit_decap(void);
void uplane_zuc_dl_15bit_decap(void);

/* test arrays: */
extern odp_testinfo_t proto_suite_cplane_encap[];
extern odp_testinfo_t proto_suite_uplane_encap[];
extern odp_testinfo_t proto_suite_cplane_decap[];
extern odp_testinfo_t proto_suite_uplane_decap[];

/* test array init/term functions: */
int proto_suite_async_init(void);

/* test registry: */
extern odp_suiteinfo_t proto_suites[];

/* executable init/term functions: */
int proto_init(odp_instance_t *inst);
int proto_term(odp_instance_t inst);

/* main test program: */
int proto_main(void);

#endif
