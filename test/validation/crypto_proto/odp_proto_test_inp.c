/* Copyright (c) 2014, Linaro Limited
 * Copyright (C) 2015-2016 Freescale Semiconductor,Inc
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <unistd.h>

#include <odp.h>
#include <CUnit/Basic.h>
#include <odp_cunit_common.h>
#include "pdcp_test_vector.h"
#include "odp_proto_test_inp.h"
#include "proto.h"

struct suite_context_s {
	odp_crypto_op_mode_t pref_mode;
	odp_pool_t pool;
	odp_queue_t queue;
};

static struct suite_context_s suite_context;

/* Basic algorithm run function for async inplace mode.
 * Creates a session from input parameters and runs one operation
 * on input_vec. Checks the output of the crypto operation against
 * output_vec. Operation completion event is dequeued polling the
 * session output queue. Completion context pointer is retrieved
 * and checked against the one set before the operation.
 * Completion event can be a separate buffer or the input packet
 * buffer can be used.
 * */
static void proto_test(odp_crypto_op_t op,
		odp_cipher_alg_t cipher_alg,
		odp_crypto_iv_t ses_iv,
		uint8_t *op_hfn_ptr,
		odp_crypto_key_t cipher_key,
		odp_auth_alg_t auth_alg,
		odp_crypto_key_t auth_key,
		uint8_t *input_vec,
		unsigned int input_vec_len,
		uint8_t *output_vec,
		unsigned int output_vec_len,
		odp_pdcp_mode_t pdcp_mode,
		odp_pdcp_params_t *pdcp_params)
{
	odp_crypto_session_t session;
	int rc;
	odp_crypto_ses_create_err_t status;
	odp_bool_t posted;
	odp_event_t event;
	odp_crypto_compl_t compl_event;
	odp_crypto_op_result_t result;
	odp_crypto_session_params_t ses_params;

	/* Create a crypto session */
	memset(&ses_params, 0, sizeof(ses_params));
	ses_params.op = op;
	ses_params.auth_cipher_text = false;
	ses_params.pref_mode = suite_context.pref_mode;
	ses_params.cipher_alg = cipher_alg;
	ses_params.auth_alg = auth_alg;
	ses_params.compl_queue = suite_context.queue;
	ses_params.output_pool = suite_context.pool;
	ses_params.cipher_key = cipher_key;
	ses_params.iv = ses_iv;
	ses_params.auth_key = auth_key;

	rc = odp_crypto_session_create(&ses_params, &session, &status);
	CU_ASSERT(!rc);
	CU_ASSERT(status == ODP_CRYPTO_SES_CREATE_ERR_NONE);
	CU_ASSERT(odp_crypto_session_to_u64(session) !=
		  odp_crypto_session_to_u64(ODP_CRYPTO_SESSION_INVALID));
	rc = odp_crypto_session_config_pdcp(session, pdcp_mode, pdcp_params);
	CU_ASSERT(!rc);

	odp_packet_t pkt = odp_packet_alloc(suite_context.pool, input_vec_len);

	CU_ASSERT(pkt != ODP_PACKET_INVALID);
	uint8_t *data_addr = odp_packet_data(pkt);

	memcpy(data_addr, input_vec, input_vec_len);
	const int data_off = 0;

	/* Prepare input/output params */
	odp_crypto_op_params_t op_params;

	memset(&op_params, 0, sizeof(op_params));
	op_params.session = session;
	op_params.pkt = pkt;
	op_params.out_pkt = pkt;
	op_params.ctx = (void *)0xdeadbeef;
	op_params.override_iv_ptr = op_hfn_ptr;
	if (cipher_alg != ODP_CIPHER_ALG_NULL &&
	    auth_alg == ODP_AUTH_ALG_NULL) {
		op_params.cipher_range.offset = data_off;
		op_params.cipher_range.length = input_vec_len;
	} else if (cipher_alg == ODP_CIPHER_ALG_NULL &&
		 auth_alg != ODP_AUTH_ALG_NULL) {
		op_params.auth_range.offset = data_off;
		op_params.auth_range.length = input_vec_len;
		op_params.hash_result_offset = data_off;
	} else {
		op_params.cipher_range.offset = data_off;
		op_params.cipher_range.length = input_vec_len;
	}
	rc = odp_crypto_operation(&op_params, &posted, &result);
	if (rc < 0) {
		CU_FAIL("Failed odp_crypto_operation()");
		goto cleanup;
	}

	if (posted) {
		/* Poll completion queue for results */
		do {
			event = odp_queue_deq(suite_context.queue);
		} while (event == ODP_EVENT_INVALID);

		compl_event = odp_crypto_compl_from_event(event);
		CU_ASSERT(odp_crypto_compl_to_u64(compl_event) ==
			  odp_crypto_compl_to_u64(
				  odp_crypto_compl_from_event(event)));
		odp_crypto_compl_result(compl_event, &result);
		odp_crypto_compl_free(compl_event);
	}

	CU_ASSERT(result.ok);
	CU_ASSERT(result.pkt == pkt);

	CU_ASSERT(!memcmp(data_addr, output_vec, output_vec_len));

	CU_ASSERT(result.ctx == (void *)0xdeadbeef);
cleanup:
	rc = odp_crypto_session_destroy(session);
	CU_ASSERT(!rc);

	odp_packet_free(pkt);
}

void proto_test_pdcp_cplane_encap(int i)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv;
	odp_pdcp_params_t pdcp_params;

	cipher_key.data = pdcp_test_crypto_key[i];
	cipher_key.length = 16;
	auth_key.data = pdcp_test_auth_key[i];
	auth_key.length = 16;
	iv.data = NULL;
	iv.length = 0;
	pdcp_params.bearer = pdcp_test_bearer[i];
	pdcp_params.pkt_dir = pdcp_test_packet_direction[i];
	pdcp_params.hfn_ovd = 0;
	pdcp_params.sn_size = pdcp_test_data_sn_size[i];
	pdcp_params.hfn = pdcp_test_hfn[i];
	pdcp_params.hfn_threshold = pdcp_test_hfn_threshold[i];

	proto_test(ODP_CRYPTO_OP_ENCODE,
			pdcp_test_params[i].cipher_alg,
			iv,
			NULL,
			cipher_key,
			pdcp_test_params[i].auth_alg,
			auth_key,
			pdcp_test_data_in[i],
			pdcp_test_data_in_len[i],
			pdcp_test_data_out[i],
			pdcp_test_data_in_len[i] + 4,
			ODP_PDCP_MODE_CONTROL,
			&pdcp_params);
}

void proto_test_pdcp_uplane_encap(int i)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv;
	odp_pdcp_params_t pdcp_params;

	cipher_key.data = pdcp_test_crypto_key[i];
	cipher_key.length = 16;
	iv.data = NULL;
	iv.length = 0;
	pdcp_params.bearer = pdcp_test_bearer[i];
	pdcp_params.pkt_dir = pdcp_test_packet_direction[i];
	pdcp_params.hfn_ovd = 0;
	pdcp_params.sn_size = pdcp_test_data_sn_size[i];
	pdcp_params.hfn = pdcp_test_hfn[i];
	pdcp_params.hfn_threshold = pdcp_test_hfn_threshold[i];

	proto_test(ODP_CRYPTO_OP_ENCODE,
			pdcp_test_params[i].cipher_alg,
			iv,
			NULL,
			cipher_key,
			pdcp_test_params[i].auth_alg,
			auth_key,
			pdcp_test_data_in[i],
			pdcp_test_data_in_len[i],
			pdcp_test_data_out[i],
			pdcp_test_data_in_len[i],
			ODP_PDCP_MODE_DATA,
			&pdcp_params);
}

void proto_test_pdcp_cplane_decap(int i)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv;
	odp_pdcp_params_t pdcp_params;

	cipher_key.data = pdcp_test_crypto_key[i];
	cipher_key.length = 16;
	auth_key.data = pdcp_test_auth_key[i];
	auth_key.length = 16;
	iv.data = NULL;
	iv.length = 0;
	pdcp_params.bearer = pdcp_test_bearer[i];
	pdcp_params.pkt_dir = pdcp_test_packet_direction[i];
	pdcp_params.hfn_ovd = 0;
	pdcp_params.sn_size = pdcp_test_data_sn_size[i];
	pdcp_params.hfn = pdcp_test_hfn[i];
	pdcp_params.hfn_threshold = pdcp_test_hfn_threshold[i];

	proto_test(ODP_CRYPTO_OP_DECODE,
			pdcp_test_params[i].cipher_alg,
			iv,
			NULL,
			cipher_key,
			pdcp_test_params[i].auth_alg,
			auth_key,
			pdcp_test_data_out[i],
			pdcp_test_data_in_len[i] + 4,
			pdcp_test_data_in[i],
			pdcp_test_data_in_len[i],
			ODP_PDCP_MODE_CONTROL,
			&pdcp_params);
}

void proto_test_pdcp_uplane_decap(int i)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv;
	odp_pdcp_params_t pdcp_params;

	cipher_key.data = pdcp_test_crypto_key[i];
	cipher_key.length = 16;
	iv.data = NULL;
	iv.length = 0;
	pdcp_params.bearer = pdcp_test_bearer[i];
	pdcp_params.pkt_dir = pdcp_test_packet_direction[i];
	pdcp_params.hfn_ovd = 0;
	pdcp_params.sn_size = pdcp_test_data_sn_size[i];
	pdcp_params.hfn = pdcp_test_hfn[i];
	pdcp_params.hfn_threshold = pdcp_test_hfn_threshold[i];

	proto_test(ODP_CRYPTO_OP_DECODE,
			pdcp_test_params[i].cipher_alg,
			iv,
			NULL,
			cipher_key,
			pdcp_test_params[i].auth_alg,
			auth_key,
			pdcp_test_data_out[i],
			pdcp_test_data_in_len[i],
			pdcp_test_data_in[i],
			pdcp_test_data_in_len[i],
			ODP_PDCP_MODE_DATA,
			&pdcp_params);
}

int proto_suite_async_init(void)
{
	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;
	suite_context.queue = odp_queue_lookup("crypto-out");
	if (suite_context.queue == ODP_QUEUE_INVALID)
		return -1;

	suite_context.pref_mode = ODP_CRYPTO_ASYNC;
	return 0;
}

void cplane_null_null_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_null_null_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_null_snow_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_null_snow_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_null_aes_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_null_aes_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_null_zuc_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_null_zuc_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_snow_null_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_snow_null_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_snow_snow_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_snow_snow_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_snow_aes_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_snow_aes_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_snow_zuc_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_snow_zuc_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_aes_null_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_aes_null_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_aes_snow_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_aes_snow_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_aes_aes_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_aes_aes_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_aes_zuc_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_aes_zuc_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_zuc_null_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_zuc_null_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_zuc_snow_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_zuc_snow_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_zuc_aes_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_zuc_aes_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_zuc_zuc_ul_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_zuc_zuc_dl_encap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_encap(i);
}

void cplane_null_null_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_null_null_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_null_snow_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_null_snow_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_null_aes_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_null_aes_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_null_zuc_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_null_zuc_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_NULL_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_snow_null_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_snow_null_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_snow_snow_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_snow_snow_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_snow_aes_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_snow_aes_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_snow_zuc_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_snow_zuc_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_SNOW_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_aes_null_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_aes_null_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_aes_snow_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_aes_snow_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_aes_aes_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_aes_aes_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_aes_zuc_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_aes_zuc_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_AES_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_zuc_null_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_zuc_null_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_NULL_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_zuc_snow_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_zuc_snow_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_SNOW_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_zuc_aes_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_zuc_aes_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_AES_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_zuc_zuc_ul_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + UPLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void cplane_zuc_zuc_dl_decap(void)
{
	int i = PDCP_CPLANE_OFFSET + CPLANE_ZUC_ENC_OFFSET +
		CPLANE_ZUC_AUTH_OFFSET + DOWNLINK_OFFSET;
	proto_test_pdcp_cplane_decap(i);
}

void uplane_null_ul_12bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + LONG_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_null_dl_12bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + LONG_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_null_ul_7bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + SHORT_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_null_dl_7bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + SHORT_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_null_ul_15bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_null_dl_15bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_snow_ul_12bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + LONG_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_snow_dl_12bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + LONG_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_snow_ul_7bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + SHORT_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_snow_dl_7bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + SHORT_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_snow_ul_15bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_snow_dl_15bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_aes_ul_12bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + LONG_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_aes_dl_12bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + LONG_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_aes_ul_7bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + SHORT_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_aes_dl_7bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + SHORT_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_aes_ul_15bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_aes_dl_15bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_zuc_ul_12bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + LONG_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_zuc_dl_12bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + LONG_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_zuc_ul_7bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + SHORT_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_zuc_dl_7bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + SHORT_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_zuc_ul_15bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_zuc_dl_15bit_encap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_encap(i);
}

void uplane_null_ul_12bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + LONG_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_null_dl_12bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + LONG_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_null_ul_7bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + SHORT_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_null_dl_7bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + SHORT_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_null_ul_15bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_null_dl_15bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + NULL_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_snow_ul_12bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + LONG_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_snow_dl_12bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + LONG_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_snow_ul_7bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + SHORT_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_snow_dl_7bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + SHORT_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_snow_ul_15bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_snow_dl_15bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + SNOW_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_aes_ul_12bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + LONG_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_aes_dl_12bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + LONG_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_aes_ul_7bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + SHORT_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_aes_dl_7bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + SHORT_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_aes_ul_15bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_aes_dl_15bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + AES_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_zuc_ul_12bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + LONG_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_zuc_dl_12bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + LONG_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_zuc_ul_7bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + SHORT_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_zuc_dl_7bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + SHORT_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_zuc_ul_15bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFSET
		+ UPLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

void uplane_zuc_dl_15bit_decap(void)
{
	int i;

	i = PDCP_UPLANE_OFFSET + ZUC_PROTO_OFFSET + FIFTEEN_BIT_SEQ_NUM_OFSET
		+ DOWNLINK_OFFSET;
	proto_test_pdcp_uplane_decap(i);
}

odp_testinfo_t proto_suite_cplane_encap[] = {
#if 0
	ODP_TEST_INFO(cplane_null_null_ul_encap),
	ODP_TEST_INFO(cplane_null_null_dl_encap),
#endif
	ODP_TEST_INFO(cplane_null_snow_ul_encap),
	ODP_TEST_INFO(cplane_null_snow_dl_encap),
	ODP_TEST_INFO(cplane_null_aes_ul_encap),
	ODP_TEST_INFO(cplane_null_aes_dl_encap),
	ODP_TEST_INFO(cplane_null_zuc_ul_encap),
	ODP_TEST_INFO(cplane_null_zuc_dl_encap),
	ODP_TEST_INFO(cplane_snow_null_ul_encap),
	ODP_TEST_INFO(cplane_snow_null_dl_encap),
	ODP_TEST_INFO(cplane_snow_snow_ul_encap),
	ODP_TEST_INFO(cplane_snow_snow_dl_encap),
	ODP_TEST_INFO(cplane_snow_aes_ul_encap),
	ODP_TEST_INFO(cplane_snow_aes_dl_encap),
	ODP_TEST_INFO(cplane_snow_zuc_ul_encap),
	ODP_TEST_INFO(cplane_snow_zuc_dl_encap),
	ODP_TEST_INFO(cplane_aes_null_ul_encap),
	ODP_TEST_INFO(cplane_aes_null_dl_encap),
	ODP_TEST_INFO(cplane_aes_snow_ul_encap),
	ODP_TEST_INFO(cplane_aes_snow_dl_encap),
	ODP_TEST_INFO(cplane_aes_aes_ul_encap),
	ODP_TEST_INFO(cplane_aes_aes_dl_encap),
	ODP_TEST_INFO(cplane_aes_zuc_ul_encap),
	ODP_TEST_INFO(cplane_aes_zuc_dl_encap),
	ODP_TEST_INFO(cplane_zuc_null_ul_encap),
	ODP_TEST_INFO(cplane_zuc_null_dl_encap),
	ODP_TEST_INFO(cplane_zuc_snow_ul_encap),
	ODP_TEST_INFO(cplane_zuc_snow_dl_encap),
	ODP_TEST_INFO(cplane_zuc_aes_ul_encap),
	ODP_TEST_INFO(cplane_zuc_aes_dl_encap),
	ODP_TEST_INFO(cplane_zuc_zuc_ul_encap),
	ODP_TEST_INFO(cplane_zuc_zuc_dl_encap),
	ODP_TEST_INFO_NULL,
};

odp_testinfo_t proto_suite_cplane_decap[] = {
#if 0
	ODP_TEST_INFO(cplane_null_null_ul_decap),
	ODP_TEST_INFO(cplane_null_null_dl_decap),
#endif
	ODP_TEST_INFO(cplane_null_snow_ul_decap),
	ODP_TEST_INFO(cplane_null_snow_dl_decap),
	ODP_TEST_INFO(cplane_null_aes_ul_decap),
	ODP_TEST_INFO(cplane_null_aes_dl_decap),
	ODP_TEST_INFO(cplane_null_zuc_ul_decap),
	ODP_TEST_INFO(cplane_null_zuc_dl_decap),
	ODP_TEST_INFO(cplane_snow_null_ul_decap),
	ODP_TEST_INFO(cplane_snow_null_dl_decap),
	ODP_TEST_INFO(cplane_snow_snow_ul_decap),
	ODP_TEST_INFO(cplane_snow_snow_dl_decap),
	ODP_TEST_INFO(cplane_snow_aes_ul_decap),
	ODP_TEST_INFO(cplane_snow_aes_dl_decap),
	ODP_TEST_INFO(cplane_snow_zuc_ul_decap),
	ODP_TEST_INFO(cplane_snow_zuc_dl_decap),
	ODP_TEST_INFO(cplane_aes_null_ul_decap),
	ODP_TEST_INFO(cplane_aes_null_dl_decap),
	ODP_TEST_INFO(cplane_aes_snow_ul_decap),
	ODP_TEST_INFO(cplane_aes_snow_dl_decap),
	ODP_TEST_INFO(cplane_aes_aes_ul_decap),
	ODP_TEST_INFO(cplane_aes_aes_dl_decap),
	ODP_TEST_INFO(cplane_aes_zuc_ul_decap),
	ODP_TEST_INFO(cplane_aes_zuc_dl_decap),
	ODP_TEST_INFO(cplane_zuc_null_ul_decap),
	ODP_TEST_INFO(cplane_zuc_null_dl_decap),
	ODP_TEST_INFO(cplane_zuc_snow_ul_decap),
	ODP_TEST_INFO(cplane_zuc_snow_dl_decap),
	ODP_TEST_INFO(cplane_zuc_aes_ul_decap),
	ODP_TEST_INFO(cplane_zuc_aes_dl_decap),
	ODP_TEST_INFO(cplane_zuc_zuc_ul_decap),
	ODP_TEST_INFO(cplane_zuc_zuc_dl_decap),
	ODP_TEST_INFO_NULL,
};

odp_testinfo_t proto_suite_uplane_encap[] = {
#if 0
	ODP_TEST_INFO(uplane_null_ul_12bit_encap),
	ODP_TEST_INFO(uplane_null_dl_12bit_encap),
	ODP_TEST_INFO(uplane_null_ul_7bit_encap),
	ODP_TEST_INFO(uplane_null_dl_7bit_encap),
	ODP_TEST_INFO(uplane_null_ul_15bit_encap),
	ODP_TEST_INFO(uplane_null_dl_15bit_encap),
#endif
	ODP_TEST_INFO(uplane_snow_ul_12bit_encap),
	ODP_TEST_INFO(uplane_snow_dl_12bit_encap),
	ODP_TEST_INFO(uplane_snow_ul_7bit_encap),
	ODP_TEST_INFO(uplane_snow_dl_7bit_encap),
	ODP_TEST_INFO(uplane_snow_ul_15bit_encap),
	ODP_TEST_INFO(uplane_snow_dl_15bit_encap),
	ODP_TEST_INFO(uplane_aes_ul_12bit_encap),
	ODP_TEST_INFO(uplane_aes_dl_12bit_encap),
	ODP_TEST_INFO(uplane_aes_ul_7bit_encap),
	ODP_TEST_INFO(uplane_aes_dl_7bit_encap),
	ODP_TEST_INFO(uplane_aes_ul_15bit_encap),
	ODP_TEST_INFO(uplane_aes_dl_15bit_encap),
	ODP_TEST_INFO(uplane_zuc_ul_12bit_encap),
	ODP_TEST_INFO(uplane_zuc_dl_12bit_encap),
	ODP_TEST_INFO(uplane_zuc_ul_7bit_encap),
	ODP_TEST_INFO(uplane_zuc_dl_7bit_encap),
	ODP_TEST_INFO(uplane_zuc_ul_15bit_encap),
	ODP_TEST_INFO(uplane_zuc_dl_15bit_encap),
	ODP_TEST_INFO_NULL,
};

odp_testinfo_t proto_suite_uplane_decap[] = {
#if 0
	ODP_TEST_INFO(uplane_null_ul_12bit_decap),
	ODP_TEST_INFO(uplane_null_dl_12bit_decap),
	ODP_TEST_INFO(uplane_null_ul_7bit_decap),
	ODP_TEST_INFO(uplane_null_dl_7bit_decap),
	ODP_TEST_INFO(uplane_null_ul_15bit_decap),
	ODP_TEST_INFO(uplane_null_dl_15bit_decap),
#endif
	ODP_TEST_INFO(uplane_snow_ul_12bit_decap),
	ODP_TEST_INFO(uplane_snow_dl_12bit_decap),
	ODP_TEST_INFO(uplane_snow_ul_7bit_decap),
	ODP_TEST_INFO(uplane_snow_dl_7bit_decap),
	ODP_TEST_INFO(uplane_snow_ul_15bit_decap),
	ODP_TEST_INFO(uplane_snow_dl_15bit_decap),
	ODP_TEST_INFO(uplane_aes_ul_12bit_decap),
	ODP_TEST_INFO(uplane_aes_dl_12bit_decap),
	ODP_TEST_INFO(uplane_aes_ul_7bit_decap),
	ODP_TEST_INFO(uplane_aes_dl_7bit_decap),
	ODP_TEST_INFO(uplane_aes_ul_15bit_decap),
	ODP_TEST_INFO(uplane_aes_dl_15bit_decap),
	ODP_TEST_INFO(uplane_zuc_ul_12bit_decap),
	ODP_TEST_INFO(uplane_zuc_dl_12bit_decap),
	ODP_TEST_INFO(uplane_zuc_ul_7bit_decap),
	ODP_TEST_INFO(uplane_zuc_dl_7bit_decap),
	ODP_TEST_INFO(uplane_zuc_ul_15bit_decap),
	ODP_TEST_INFO(uplane_zuc_dl_15bit_decap),
	ODP_TEST_INFO_NULL,
};
