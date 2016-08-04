/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/crypto.h>
#include <odp_internal.h>
#include <odp/api/atomic.h>
#include <odp/api/spinlock.h>
#include <odp/api/sync.h>
#include <odp/api/debug.h>
#include <odp/api/align.h>
#include <odp/api/shared_memory.h>
#include <odp_crypto_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/hints.h>
#include <odp/api/random.h>
#include <odp_packet_internal.h>

#include <odp/helper/ipsec.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>

#include <string.h>

#include <openssl/des.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#define MAX_SESSIONS 32

#define ipv4_data_p(ip) ((uint8_t *)((odph_ipv4hdr_t *)ip + 1))
#define ipv4_data_len(ip) (odp_be_to_cpu_16(ip->tot_len) -\
			   sizeof(odph_ipv4hdr_t))
#define ESP_ENCODE_LEN(x, b) ((((x) + (b - 1)) / b) * b)

typedef struct odp_crypto_global_s odp_crypto_global_t;

/**
 * Dummy function that is called when proto-ipsec option is not selected.
 */
static void void_func(odp_crypto_op_params_t *params ODP_UNUSED,
		      odp_crypto_generic_session_t *session ODP_UNUSED)
{
}

static inline void ipv4_adjust_len(odph_ipv4hdr_t *ip, int adj)
{
	ip->tot_len = odp_cpu_to_be_16(odp_be_to_cpu_16(ip->tot_len) + adj);
}

struct odp_crypto_global_s {
	odp_spinlock_t                lock;
	odp_crypto_generic_session_t *free;
	odp_crypto_generic_session_t  sessions[0];
};

static odp_crypto_global_t *global;

static
odp_crypto_generic_op_result_t *get_op_result_from_event(odp_event_t ev)
{
	return &(odp_packet_hdr(odp_packet_from_event(ev))->op_result);
}

static
odp_crypto_generic_session_t *alloc_session(void)
{
	odp_crypto_generic_session_t *session = NULL;

	odp_spinlock_lock(&global->lock);
	session = global->free;
	if (session)
		global->free = session->next;
	odp_spinlock_unlock(&global->lock);

	return session;
}

static
void free_session(odp_crypto_generic_session_t *session)
{
	odp_spinlock_lock(&global->lock);
	if (session->ipsec_params.out_hdr)
		free(session->ipsec_params.out_hdr);
	session->next = global->free;
	global->free = session;
	odp_spinlock_unlock(&global->lock);
}

static odp_crypto_alg_err_t
null_crypto_routine(odp_crypto_op_params_t *params ODP_UNUSED,
		    odp_crypto_generic_session_t *session ODP_UNUSED)
{
	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t md5_gen(odp_crypto_op_params_t *params,
			     odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint8_t *icv   = data;
	uint32_t len   = params->auth_range.length;
	uint8_t  hash[EVP_MAX_MD_SIZE];

	/* Adjust pointer for beginning of area to auth */
	data += params->auth_range.offset;
	icv  += params->hash_result_offset;

	/* Hash it */
	HMAC(EVP_md5(),
	     session->auth.data.md5.key,
	     16,
	     data,
	     len,
	     hash,
	     NULL);

	/* Copy to the output location */
	memcpy(icv, hash, session->auth.data.md5.bytes);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t md5_check(odp_crypto_op_params_t *params,
			       odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint8_t *icv   = data;
	uint32_t len   = params->auth_range.length;
	uint32_t bytes = session->auth.data.md5.bytes;
	uint8_t  hash_in[EVP_MAX_MD_SIZE];
	uint8_t  hash_out[EVP_MAX_MD_SIZE];

	/* Adjust pointer for beginning of area to auth */
	data += params->auth_range.offset;
	icv  += params->hash_result_offset;

	/* Copy current value out and clear it before authentication */
	memset(hash_in, 0, sizeof(hash_in));
	memcpy(hash_in, icv, bytes);
	memset(icv, 0, bytes);
	memset(hash_out, 0, sizeof(hash_out));

	/* Hash it */
	HMAC(EVP_md5(),
	     session->auth.data.md5.key,
	     16,
	     data,
	     len,
	     hash_out,
	     NULL);

	/* Verify match */
	if (0 != memcmp(hash_in, hash_out, bytes))
		return ODP_CRYPTO_ALG_ERR_ICV_CHECK;

	/* Matched */
	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t sha256_gen(odp_crypto_op_params_t *params,
				odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint8_t *icv   = data;
	uint32_t len   = params->auth_range.length;
	uint8_t  hash[EVP_MAX_MD_SIZE];

	/* Adjust pointer for beginning of area to auth */
	data += params->auth_range.offset;
	icv  += params->hash_result_offset;

	/* Hash it */
	HMAC(EVP_sha256(),
	     session->auth.data.sha256.key,
	     32,
	     data,
	     len,
	     hash,
	     NULL);

	/* Copy to the output location */
	memcpy(icv, hash, session->auth.data.sha256.bytes);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t sha256_check(odp_crypto_op_params_t *params,
				  odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint8_t *icv   = data;
	uint32_t len   = params->auth_range.length;
	uint32_t bytes = session->auth.data.sha256.bytes;
	uint8_t  hash_in[EVP_MAX_MD_SIZE];
	uint8_t  hash_out[EVP_MAX_MD_SIZE];

	/* Adjust pointer for beginning of area to auth */
	data += params->auth_range.offset;
	icv  += params->hash_result_offset;

	/* Copy current value out and clear it before authentication */
	memset(hash_in, 0, sizeof(hash_in));
	memcpy(hash_in, icv, bytes);
	memset(icv, 0, bytes);
	memset(hash_out, 0, sizeof(hash_out));

	/* Hash it */
	HMAC(EVP_sha256(),
	     session->auth.data.sha256.key,
	     32,
	     data,
	     len,
	     hash_out,
	     NULL);

	/* Verify match */
	if (0 != memcmp(hash_in, hash_out, bytes))
		return ODP_CRYPTO_ALG_ERR_ICV_CHECK;

	/* Matched */
	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t aes_encrypt(odp_crypto_op_params_t *params,
				 odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint32_t len   = params->cipher_range.length;
	unsigned char iv_enc[AES_BLOCK_SIZE];
	void *iv_ptr;

	if (params->override_iv_ptr)
		iv_ptr = params->override_iv_ptr;
	else if (session->cipher.iv.data)
		iv_ptr = session->cipher.iv.data;
	else
		return ODP_CRYPTO_ALG_ERR_IV_INVALID;

	/*
	 * Create a copy of the IV.  The DES library modifies IV
	 * and if we are processing packets on parallel threads
	 * we could get corruption.
	 */
	memcpy(iv_enc, iv_ptr, AES_BLOCK_SIZE);

	/* Adjust pointer for beginning of area to cipher */
	data += params->cipher_range.offset;
	/* Encrypt it */
	AES_cbc_encrypt(data, data, len, &session->cipher.data.aes.key,
			iv_enc, AES_ENCRYPT);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t aes_decrypt(odp_crypto_op_params_t *params,
				 odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint32_t len   = params->cipher_range.length;
	unsigned char iv_enc[AES_BLOCK_SIZE];
	void *iv_ptr;

	if (params->override_iv_ptr)
		iv_ptr = params->override_iv_ptr;
	else if (session->cipher.iv.data)
		iv_ptr = session->cipher.iv.data;
	else
		return ODP_CRYPTO_ALG_ERR_IV_INVALID;

	/*
	 * Create a copy of the IV.  The DES library modifies IV
	 * and if we are processing packets on parallel threads
	 * we could get corruption.
	 */
	memcpy(iv_enc, iv_ptr, AES_BLOCK_SIZE);

	/* Adjust pointer for beginning of area to cipher */
	data += params->cipher_range.offset;
	/* Encrypt it */
	AES_cbc_encrypt(data, data, len, &session->cipher.data.aes.key,
			iv_enc, AES_DECRYPT);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
int process_aes_params(odp_crypto_generic_session_t *session,
		       odp_crypto_session_params_t *params)
{
	/* Verify IV len is either 0 or 16 */
	if (!((0 == params->iv.length) || (16 == params->iv.length)))
		return -1;

	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == params->op) {
		session->cipher.func = aes_encrypt;
		AES_set_encrypt_key(params->cipher_key.data, 128,
				    &session->cipher.data.aes.key);
	} else {
		session->cipher.func = aes_decrypt;
		AES_set_decrypt_key(params->cipher_key.data, 128,
				    &session->cipher.data.aes.key);
	}

	return 0;
}

static
odp_crypto_alg_err_t aes_gcm_encrypt(odp_crypto_op_params_t *params,
				     odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint32_t plain_len   = params->cipher_range.length;
	uint8_t *aad_head = data + params->auth_range.offset;
	uint8_t *aad_tail = data + params->cipher_range.offset +
		params->cipher_range.length;
	uint32_t auth_len = params->auth_range.length;
	unsigned char iv_enc[AES_BLOCK_SIZE];
	void *iv_ptr;
	uint8_t *tag = data + params->hash_result_offset;

	if (params->override_iv_ptr)
		iv_ptr = params->override_iv_ptr;
	else if (session->cipher.iv.data)
		iv_ptr = session->cipher.iv.data;
	else
		return ODP_CRYPTO_ALG_ERR_IV_INVALID;

	/* All cipher data must be part of the authentication */
	if (params->auth_range.offset > params->cipher_range.offset ||
	    params->auth_range.offset + auth_len <
	    params->cipher_range.offset + plain_len)
		return ODP_CRYPTO_ALG_ERR_DATA_SIZE;

	/*
	 * Create a copy of the IV.  The DES library modifies IV
	 * and if we are processing packets on parallel threads
	 * we could get corruption.
	 */
	memcpy(iv_enc, iv_ptr, AES_BLOCK_SIZE);

	/* Adjust pointer for beginning of area to cipher/auth */
	uint8_t *plaindata = data + params->cipher_range.offset;

	/* Encrypt it */
	EVP_CIPHER_CTX *ctx = session->cipher.data.aes_gcm.ctx;
	int cipher_len = 0;

	EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv_enc);

	/* Authenticate header data (if any) without encrypting them */
	if (aad_head < plaindata) {
		EVP_EncryptUpdate(ctx, NULL, &cipher_len,
				  aad_head, plaindata - aad_head);
	}

	EVP_EncryptUpdate(ctx, plaindata, &cipher_len,
			  plaindata, plain_len);
	cipher_len = plain_len;

	/* Authenticate footer data (if any) without encrypting them */
	if (aad_head + auth_len > plaindata + plain_len) {
		EVP_EncryptUpdate(ctx, NULL, NULL, aad_tail,
				  auth_len - (aad_tail - aad_head));
	}

	EVP_EncryptFinal_ex(ctx, plaindata + cipher_len, &cipher_len);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t aes_gcm_decrypt(odp_crypto_op_params_t *params,
				     odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint32_t cipher_len   = params->cipher_range.length;
	uint8_t *aad_head = data + params->auth_range.offset;
	uint8_t *aad_tail = data + params->cipher_range.offset +
		params->cipher_range.length;
	uint32_t auth_len = params->auth_range.length;
	unsigned char iv_enc[AES_BLOCK_SIZE];
	void *iv_ptr;
	uint8_t *tag   = data + params->hash_result_offset;

	if (params->override_iv_ptr)
		iv_ptr = params->override_iv_ptr;
	else if (session->cipher.iv.data)
		iv_ptr = session->cipher.iv.data;
	else
		return ODP_CRYPTO_ALG_ERR_IV_INVALID;

	/* All cipher data must be part of the authentication */
	if (params->auth_range.offset > params->cipher_range.offset ||
	    params->auth_range.offset + auth_len <
	    params->cipher_range.offset + cipher_len)
		return ODP_CRYPTO_ALG_ERR_DATA_SIZE;

	/*
	 * Create a copy of the IV.  The DES library modifies IV
	 * and if we are processing packets on parallel threads
	 * we could get corruption.
	 */
	memcpy(iv_enc, iv_ptr, AES_BLOCK_SIZE);

	/* Adjust pointer for beginning of area to cipher/auth */
	uint8_t *cipherdata = data + params->cipher_range.offset;
	/* Encrypt it */
	EVP_CIPHER_CTX *ctx = session->cipher.data.aes_gcm.ctx;
	int plain_len = 0;

	EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, iv_enc);

	/* Authenticate header data (if any) without encrypting them */
	if (aad_head < cipherdata) {
		EVP_DecryptUpdate(ctx, NULL, &plain_len,
				  aad_head, cipherdata - aad_head);
	}

	EVP_DecryptUpdate(ctx, cipherdata, &plain_len,
			  cipherdata, cipher_len);
	plain_len = cipher_len;

	/* Authenticate footer data (if any) without encrypting them */
	if (aad_head + auth_len > cipherdata + cipher_len) {
		EVP_DecryptUpdate(ctx, NULL, NULL, aad_tail,
				  auth_len - (aad_tail - aad_head));
	}

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);

	if (EVP_DecryptFinal_ex(ctx, cipherdata + cipher_len, &plain_len) < 0)
		return ODP_CRYPTO_ALG_ERR_ICV_CHECK;

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
int process_aes_gcm_params(odp_crypto_generic_session_t *session,
			   odp_crypto_session_params_t *params)
{
	/* Verify Key len is 16 */
	if (params->cipher_key.length != 16)
		return -1;

	/* Set function */
	EVP_CIPHER_CTX *ctx =
		session->cipher.data.aes_gcm.ctx = EVP_CIPHER_CTX_new();

	if (ODP_CRYPTO_OP_ENCODE == params->op) {
		session->cipher.func = aes_gcm_encrypt;
		EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
	} else {
		session->cipher.func = aes_gcm_decrypt;
		EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
	}

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
			    params->iv.length, NULL);
	if (ODP_CRYPTO_OP_ENCODE == params->op) {
		EVP_EncryptInit_ex(ctx, NULL, NULL,
				   params->cipher_key.data, NULL);
	} else {
		EVP_DecryptInit_ex(ctx, NULL, NULL,
				   params->cipher_key.data, NULL);
	}

	return 0;
}

static
odp_crypto_alg_err_t des_encrypt(odp_crypto_op_params_t *params,
				 odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint32_t len   = params->cipher_range.length;
	DES_cblock iv;
	void *iv_ptr;

	if (params->override_iv_ptr)
		iv_ptr = params->override_iv_ptr;
	else if (session->cipher.iv.data)
		iv_ptr = session->cipher.iv.data;
	else
		return ODP_CRYPTO_ALG_ERR_IV_INVALID;

	/*
	 * Create a copy of the IV.  The DES library modifies IV
	 * and if we are processing packets on parallel threads
	 * we could get corruption.
	 */
	memcpy(iv, iv_ptr, sizeof(iv));

	/* Adjust pointer for beginning of area to cipher */
	data += params->cipher_range.offset;
	/* Encrypt it */
	DES_ede3_cbc_encrypt(data,
			     data,
			     len,
			     &session->cipher.data.des.ks1,
			     &session->cipher.data.des.ks2,
			     &session->cipher.data.des.ks3,
			     &iv,
			     1);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t des_decrypt(odp_crypto_op_params_t *params,
				 odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint32_t len   = params->cipher_range.length;
	DES_cblock iv;
	void *iv_ptr;

	if (params->override_iv_ptr)
		iv_ptr = params->override_iv_ptr;
	else if (session->cipher.iv.data)
		iv_ptr = session->cipher.iv.data;
	else
		return ODP_CRYPTO_ALG_ERR_IV_INVALID;

	/*
	 * Create a copy of the IV.  The DES library modifies IV
	 * and if we are processing packets on parallel threads
	 * we could get corruption.
	 */
	memcpy(iv, iv_ptr, sizeof(iv));

	/* Adjust pointer for beginning of area to cipher */
	data += params->cipher_range.offset;

	/* Decrypt it */
	DES_ede3_cbc_encrypt(data,
			     data,
			     len,
			     &session->cipher.data.des.ks1,
			     &session->cipher.data.des.ks2,
			     &session->cipher.data.des.ks3,
			     &iv,
			     0);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
int process_des_params(odp_crypto_generic_session_t *session,
		       odp_crypto_session_params_t *params)
{
	/* Verify IV len is either 0 or 8 */
	if (!((0 == params->iv.length) || (8 == params->iv.length)))
		return -1;

	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == params->op)
		session->cipher.func = des_encrypt;
	else
		session->cipher.func = des_decrypt;

	/* Convert keys */
	DES_set_key((DES_cblock *)&params->cipher_key.data[0],
		    &session->cipher.data.des.ks1);
	DES_set_key((DES_cblock *)&params->cipher_key.data[8],
		    &session->cipher.data.des.ks2);
	DES_set_key((DES_cblock *)&params->cipher_key.data[16],
		    &session->cipher.data.des.ks3);

	return 0;
}

static
int process_md5_params(odp_crypto_generic_session_t *session,
		       odp_crypto_session_params_t *params,
		       uint32_t bits)
{
	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == params->op)
		session->auth.func = md5_gen;
	else
		session->auth.func = md5_check;

	/* Number of valid bytes */
	session->auth.data.md5.bytes = bits / 8;

	/* Convert keys */
	memcpy(session->auth.data.md5.key, params->auth_key.data, 16);

	return 0;
}

static
int process_sha256_params(odp_crypto_generic_session_t *session,
			  odp_crypto_session_params_t *params,
			  uint32_t bits)
{
	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == params->op)
		session->auth.func = sha256_gen;
	else
		session->auth.func = sha256_check;

	/* Number of valid bytes */
	session->auth.data.sha256.bytes = bits / 8;

	/* Convert keys */
	memcpy(session->auth.data.sha256.key, params->auth_key.data, 32);

	return 0;
}

int odp_crypto_capability(odp_crypto_capability_t *capa)
{
	if (NULL == capa)
		return -1;

	/* Initialize crypto capability structure */
	memset(capa, 0, sizeof(odp_crypto_capability_t));

	capa->ciphers.bit.null = 1;
	capa->ciphers.bit.des = 1;
	capa->ciphers.bit.trides_cbc  = 1;
	capa->ciphers.bit.aes128_cbc  = 1;
	capa->ciphers.bit.aes128_gcm  = 1;

	capa->auths.bit.null = 1;
	capa->auths.bit.md5_96 = 1;
	capa->auths.bit.sha256_128 = 1;
	capa->auths.bit.aes128_gcm  = 1;

	capa->max_sessions = MAX_SESSIONS;

	return 0;
}

int
odp_crypto_session_create(odp_crypto_session_params_t *params,
			  odp_crypto_session_t *session_out,
			  odp_crypto_ses_create_err_t *status)
{
	int rc;
	odp_crypto_generic_session_t *session;

	/* Default to successful result */
	*status = ODP_CRYPTO_SES_CREATE_ERR_NONE;

	/* Allocate memory for this session */
	session = alloc_session();
	if (NULL == session) {
		*status = ODP_CRYPTO_SES_CREATE_ERR_ENOMEM;
		return -1;
	}

	/* Derive order */
	if (ODP_CRYPTO_OP_ENCODE == params->op)
		session->do_cipher_first =  params->auth_cipher_text;
	else
		session->do_cipher_first = !params->auth_cipher_text;

	/* Copy stuff over */
	session->op = params->op;
	session->compl_queue = params->compl_queue;
	session->cipher.alg  = params->cipher_alg;
	session->cipher.iv.data = params->iv.data;
	session->cipher.iv.len  = params->iv.length;
	session->auth.alg  = params->auth_alg;
	session->output_pool = params->output_pool;
	/* When a session is created, is considered that proto-esp option
	* is off. If it is on, in "odp_crypto_session_config_ipsec" function
	* will be configured ipsec_proto value, before and after functions.
	*/
	session->ipsec_proto = -1;
	session->in_crypto_func.before = &void_func;
	session->in_crypto_func.after = &void_func;

	/* Process based on cipher */
	switch (params->cipher_alg) {
	case ODP_CIPHER_ALG_NULL:
		session->cipher.func = null_crypto_routine;
		rc = 0;
		break;
	case ODP_CIPHER_ALG_DES:
	case ODP_CIPHER_ALG_3DES_CBC:
		rc = process_des_params(session, params);
		break;
	case ODP_CIPHER_ALG_AES128_CBC:
		rc = process_aes_params(session, params);
		break;
	case ODP_CIPHER_ALG_AES128_GCM:
		/* AES-GCM requires to do both auth and
		 * cipher at the same time */
		if (params->auth_alg != ODP_AUTH_ALG_AES128_GCM) {
			rc = -1;
			break;
		}
		rc = process_aes_gcm_params(session, params);
		break;
	default:
		rc = -1;
	}

	/* Check result */
	if (rc) {
		*status = ODP_CRYPTO_SES_CREATE_ERR_INV_CIPHER;
		return -1;
	}

	/* Process based on auth */
	switch (params->auth_alg) {
	case ODP_AUTH_ALG_NULL:
		session->auth.func = null_crypto_routine;
		rc = 0;
		break;
	case ODP_AUTH_ALG_MD5_96:
		rc = process_md5_params(session, params, 96);
		break;
	case ODP_AUTH_ALG_SHA256_128:
		rc = process_sha256_params(session, params, 128);
		break;
	case ODP_AUTH_ALG_AES128_GCM:
		/* AES-GCM requires to do both auth and
		 * cipher at the same time */
		if (params->cipher_alg != ODP_CIPHER_ALG_AES128_GCM) {
			rc = -1;
			break;
		}
		session->auth.func = null_crypto_routine;
		rc = 0;
		break;
	default:
		rc = -1;
	}

	/* Check result */
	if (rc) {
		*status = ODP_CRYPTO_SES_CREATE_ERR_INV_AUTH;
		return -1;
	}

	/* We're happy */
	*session_out = (intptr_t)session;
	return 0;
}

int odp_crypto_session_destroy(odp_crypto_session_t session)
{
	odp_crypto_generic_session_t *generic;

	generic = (odp_crypto_generic_session_t *)(intptr_t)session;
	if (generic->cipher.alg == ODP_CIPHER_ALG_AES128_GCM)
		EVP_CIPHER_CTX_free(generic->cipher.data.aes_gcm.ctx);
	memset(generic, 0, sizeof(*generic));
	free_session(generic);
	return 0;
}

static inline int locate_ipsec_headers(odph_ipv4hdr_t *ip,
				       odph_esphdr_t **esp_p)
{
	uint8_t *in = ipv4_data_p(ip);

	if (ODPH_IPPROTO_ESP == ip->proto) {
		*esp_p = (odph_esphdr_t *)in;
		in += sizeof(odph_esphdr_t);
	} else {
		*esp_p = NULL;
	}
	return in - (ipv4_data_p(ip));
}

/**
 * Function that prepares the headers for ESP encryption and authentication
 * before doing the crypto operation
 */
static void encode_before_crypto(odp_crypto_op_params_t *params,
				 odp_crypto_generic_session_t *session)
{
	int hdr_len = 0;
	int trl_len = 0;
	odph_esphdr_t *esp;
	odph_ipv4hdr_t *ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr
			     (params->pkt, NULL);
	uint16_t ip_data_len = ipv4_data_len(ip);
	uint8_t *ip_data = ipv4_data_p(ip);

	if (ODP_IPSEC_MODE_TUNNEL == session->ipsec_mode) {
		hdr_len += sizeof(odph_ipv4hdr_t);
		ip_data = (uint8_t *)ip;
		ip_data_len += sizeof(odph_ipv4hdr_t);
	}
	esp = (odph_esphdr_t *)(ip_data + hdr_len);
	hdr_len += sizeof(odph_esphdr_t) + session->cipher.iv.len;

	if (!odp_packet_push_tail(params->pkt, hdr_len))
		abort();
	memmove(ip_data + hdr_len, ip_data, ip_data_len);

	ip_data += hdr_len;

	if (esp) {
		uint32_t encrypt_len;
		odph_esptrl_t *esp_t;
		uint8_t *icv;
		uint8_t *buf = odp_packet_data(params->pkt);

		encrypt_len = ESP_ENCODE_LEN(ip_data_len +
					     sizeof(*esp_t), 8);
		trl_len = encrypt_len - ip_data_len;

		if (!odp_packet_push_tail(params->pkt, trl_len +
					  session->auth.icv_len))
			abort();

		esp->spi = odp_cpu_to_be_32(session->ipsec_params.spi);
		esp->seq_no = odp_cpu_to_be_32((uint32_t)
						odp_atomic_fetch_inc_u64
						(&session->seq_no));

		memcpy(esp + 1, session->cipher.iv.data,
		       session->cipher.iv.len);

		esp_t = (odph_esptrl_t *)(ip_data + encrypt_len) - 1;
		esp_t->pad_len = trl_len - sizeof(*esp_t);

		icv = (uint8_t *)(esp_t + 1);

		if (ODP_IPSEC_MODE_TUNNEL == session->ipsec_mode)
			esp_t->next_header = ODPH_IPV4;
		else
			esp_t->next_header = ip->proto;
		ip->proto =  ODPH_IPPROTO_ESP;

		params->cipher_range.offset = ip_data - buf;
		params->cipher_range.length = encrypt_len;

		params->auth_range.offset = ((uint8_t *)(ip + 1)) - buf;
		params->auth_range.length = (uint8_t *)
					    ((odph_esptrl_t *)esp_t + 1) -
					    (uint8_t *)esp;
		params->hash_result_offset = icv - buf;
		/* In case of ESN */
		if (session->ipsec_params.esn) {
			uint8_t *tail;
			/* Take the high part of 64 bits sequence number. */
			uint32_t esn = odp_cpu_to_be_32((uint32_t)
							(odp_atomic_load_u64
							(&session->seq_no) >>
							32));
			odp_packet_push_tail(params->pkt, sizeof(uint32_t));
			/* Authenticated data includes the ESN (4 bytes) */
			tail = (uint8_t *)(esp_t + 1);
			*((uint32_t *)(intptr_t)tail) = esn;
			params->auth_range.length += sizeof(uint32_t);
		}
	}
	/* Set IPv4 length before authentication */
	ipv4_adjust_len(ip, hdr_len + trl_len + session->auth.icv_len);
	/* Header processing */
	if (ODP_IPSEC_MODE_TUNNEL == session->ipsec_mode) {
		odph_ipv4hdr_t *out_hdr_ptr = (odph_ipv4hdr_t *)
					       session->ipsec_params.out_hdr;

		ip->proto = out_hdr_ptr->proto;
		ip->src_addr = out_hdr_ptr->src_addr;
		ip->dst_addr = out_hdr_ptr->dst_addr;
		ip->ttl = out_hdr_ptr->ttl;
		ip->id = out_hdr_ptr->id++;
		if (!ip->id) {
			/* re-init tunnel hdr id */
			if (odp_random_data((uint8_t *)&out_hdr_ptr->id,
					    sizeof(uint16_t), 1) !=
			    sizeof(out_hdr_ptr->id))
				abort();
		}
	}
	ip->chksum = 0;
	odph_ipv4_csum_update(params->out_pkt);
}

/**
 * Function that prepares the headers for ESP encryption and authentication
 * after doing the crypto operation
 */
static void encode_after_crypto(odp_crypto_op_params_t *params,
				odp_crypto_generic_session_t *session
				ODP_UNUSED)
{
	odp_packet_pull_tail(params->out_pkt, sizeof(uint32_t));
}

/**
 * Function that prepares the headers for ESP decryption and authentication
 * before doing the crypto operation
 */
static void decode_before_crypto(odp_crypto_op_params_t *params,
				 odp_crypto_generic_session_t *session)
{
	int hdr_len = 0;
	odph_esphdr_t *esp;
	odph_ipv4hdr_t *ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr
			     (params->pkt, NULL);
	hdr_len = locate_ipsec_headers(ip, &esp);
	hdr_len += session->cipher.iv.len;

	if (esp) {
		uint16_t ip_data_len = ipv4_data_len(ip);
		uint8_t *eop = (uint8_t *)(ip) + odp_be_to_cpu_16(ip->tot_len);
		uint8_t *buf = odp_packet_data(params->pkt);

		params->auth_range.offset = ((uint8_t *)(ip + 1)) - buf;
		params->auth_range.length = ip_data_len - session->auth.icv_len;
		params->hash_result_offset = (eop - buf) -
					      session->auth.icv_len;

		params->cipher_range.offset = ipv4_data_p(ip) + hdr_len - buf;
		params->cipher_range.length = ipv4_data_len(ip) -
					      hdr_len - session->auth.icv_len;
		params->override_iv_ptr = esp->iv;
		/* Compute ICV with ESN if present */
		if (session->ipsec_params.esn) {
			uint8_t *icv = eop - session->auth.icv_len;
			uint32_t esn;

			/* Increment seq number and take the high part of it */
			odp_atomic_fetch_inc_u64(&session->seq_no);
			esn = odp_cpu_to_be_32((uint32_t)(odp_atomic_load_u64
							 (&session->seq_no) >>
							 32));
			if (!odp_packet_push_tail(params->pkt,
						  sizeof(uint32_t)))
				abort();
			memmove(icv + sizeof(uint32_t), icv,
				session->auth.icv_len);
			*((uint32_t *)(intptr_t)icv) = esn;
			params->auth_range.length += sizeof(uint32_t);
			params->hash_result_offset += sizeof(uint32_t);
		}
	}
}

/**
 * Function that prepares the headers for ESP decryption and authentication
 * after doing the crypto operation
 */
static void decode_after_crypto(odp_crypto_op_params_t *params,
				odp_crypto_generic_session_t *session)
{
	int trl_len = 0;
	int hdr_len = 0;
	odph_ipv4hdr_t *ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr
			     (params->out_pkt, NULL);
	uint8_t *eop = (uint8_t *)(ip) + odp_be_to_cpu_16(ip->tot_len)
			- session->auth.icv_len;
	odph_esptrl_t *esp_t = (odph_esptrl_t *)(eop) - 1;
	odph_esphdr_t *esp;

	if (session->ipsec_params.esn) {
		if (!odp_packet_pull_tail(params->out_pkt, sizeof(uint32_t)))
			abort();
	}
	hdr_len = locate_ipsec_headers(ip, &esp);
	hdr_len += session->cipher.iv.len;
	ip->proto = esp_t->next_header;
	trl_len += esp_t->pad_len + sizeof(*esp_t) + session->auth.icv_len;

	if (ODPH_IPV4 == ip->proto) {
		odph_ethhdr_t *eth;

		odp_packet_pull_head(params->out_pkt, sizeof(*ip) + hdr_len);
		odp_packet_pull_tail(params->out_pkt, trl_len);
		eth = (odph_ethhdr_t *)odp_packet_l2_ptr(params->out_pkt, NULL);
		eth->type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);
		ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(params->out_pkt, NULL);
	} else {
		ipv4_adjust_len(ip, -(hdr_len + trl_len));
		ip->chksum = 0;
		odph_ipv4_csum_update(params->out_pkt);
		/* Correct the packet length and move payload into position */
		memmove(ipv4_data_p(ip), ipv4_data_p(ip) + hdr_len,
			odp_be_to_cpu_16(ip->tot_len));
		if (!odp_packet_pull_tail(params->out_pkt, hdr_len + trl_len))
			abort();
	}
}

int
odp_crypto_operation(odp_crypto_op_params_t *params,
		     odp_bool_t *posted,
		     odp_crypto_op_result_t *result)
{
	odp_crypto_alg_err_t rc_cipher = ODP_CRYPTO_ALG_ERR_NONE;
	odp_crypto_alg_err_t rc_auth = ODP_CRYPTO_ALG_ERR_NONE;
	odp_crypto_generic_session_t *session;
	odp_crypto_op_result_t local_result;

	session = (odp_crypto_generic_session_t *)(intptr_t)params->session;
	/* Call the function for processing the headers before encode/decode */
	session->in_crypto_func.before(params, session);

	/* Resolve output buffer */
	if (ODP_PACKET_INVALID == params->out_pkt &&
	    ODP_POOL_INVALID != session->output_pool)
		params->out_pkt = odp_packet_alloc(session->output_pool,
				odp_packet_len(params->pkt));
	if (params->pkt != params->out_pkt) {
		if (odp_unlikely(ODP_PACKET_INVALID == params->out_pkt))
			ODP_ABORT();
		(void)odp_packet_copy_from_pkt(params->out_pkt,
					       0,
					       params->pkt,
					       0,
					       odp_packet_len(params->pkt));
		_odp_packet_copy_md_to_packet(params->pkt, params->out_pkt);
		odp_packet_free(params->pkt);
		params->pkt = ODP_PACKET_INVALID;
	}

	/* Invoke the functions */
	if (session->do_cipher_first) {
		rc_cipher = session->cipher.func(params, session);
		rc_auth = session->auth.func(params, session);
	} else {
		rc_auth = session->auth.func(params, session);
		rc_cipher = session->cipher.func(params, session);
	}

	/* Fill in result */
	local_result.ctx = params->ctx;
	local_result.pkt = params->out_pkt;
	local_result.cipher_status.alg_err = rc_cipher;
	local_result.cipher_status.hw_err = ODP_CRYPTO_HW_ERR_NONE;
	local_result.auth_status.alg_err = rc_auth;
	local_result.auth_status.hw_err = ODP_CRYPTO_HW_ERR_NONE;
	local_result.ok =
		(rc_cipher == ODP_CRYPTO_ALG_ERR_NONE) &&
		(rc_auth == ODP_CRYPTO_ALG_ERR_NONE);
	/* Call the function for processing the headers after encode/decode */
	session->in_crypto_func.after(params, session);

	/* If specified during creation post event to completion queue */
	if (ODP_QUEUE_INVALID != session->compl_queue) {
		odp_event_t completion_event;
		odp_crypto_generic_op_result_t *op_result;

		/* Linux generic will always use packet for completion event */
		completion_event = odp_packet_to_event(params->out_pkt);
		_odp_buffer_event_type_set(
			odp_buffer_from_event(completion_event),
			ODP_EVENT_CRYPTO_COMPL);
		/* Asynchronous, build result (no HW so no errors) and send it*/
		op_result = get_op_result_from_event(completion_event);
		op_result->magic = OP_RESULT_MAGIC;
		op_result->result = local_result;
		if (odp_queue_enq(session->compl_queue, completion_event)) {
			odp_event_free(completion_event);
			return -1;
		}

		/* Indicate to caller operation was async */
		*posted = 1;
	} else {
		/* Synchronous, simply return results */
		if (!result)
			return -1;
		*result = local_result;

		/* Indicate to caller operation was sync */
		*posted = 0;
	}
	return 0;
}

int
odp_crypto_init_global(void)
{
	size_t mem_size;
	odp_shm_t shm;
	int idx;

	/* Calculate the memory size we need */
	mem_size  = sizeof(*global);
	mem_size += (MAX_SESSIONS * sizeof(odp_crypto_generic_session_t));

	/* Allocate our globally shared memory */
	shm = odp_shm_reserve("crypto_pool", mem_size,
			      ODP_CACHE_LINE_SIZE, 0);

	global = odp_shm_addr(shm);

	/* Clear it out */
	memset(global, 0, mem_size);

	/* Initialize free list and lock */
	for (idx = 0; idx < MAX_SESSIONS; idx++) {
		global->sessions[idx].next = global->free;
		global->free = &global->sessions[idx];
	}
	odp_spinlock_init(&global->lock);

	return 0;
}

int odp_crypto_term_global(void)
{
	int rc = 0;
	int ret;
	int count = 0;
	odp_crypto_generic_session_t *session;

	for (session = global->free; session != NULL; session = session->next)
		count++;
	if (count != MAX_SESSIONS) {
		ODP_ERR("crypto sessions still active\n");
		rc = -1;
	}

	ret = odp_shm_free(odp_shm_lookup("crypto_pool"));
	if (ret < 0) {
		ODP_ERR("shm free failed for crypto_pool\n");
		rc = -1;
	}

	return rc;
}

int32_t
odp_random_data(uint8_t *buf, int32_t len, odp_bool_t use_entropy ODP_UNUSED)
{
	int32_t rc;
	rc = RAND_bytes(buf, len);
	return (1 == rc) ? len /*success*/: -1 /*failure*/;
}

odp_crypto_compl_t odp_crypto_compl_from_event(odp_event_t ev)
{
	/* This check not mandated by the API specification */
	if (odp_event_type(ev) != ODP_EVENT_CRYPTO_COMPL)
		ODP_ABORT("Event not a crypto completion");
	return (odp_crypto_compl_t)ev;
}

odp_event_t odp_crypto_compl_to_event(odp_crypto_compl_t completion_event)
{
	return (odp_event_t)completion_event;
}

void
odp_crypto_compl_result(odp_crypto_compl_t completion_event,
			odp_crypto_op_result_t *result)
{
	odp_event_t ev = odp_crypto_compl_to_event(completion_event);
	odp_crypto_generic_op_result_t *op_result;

	op_result = get_op_result_from_event(ev);

	if (OP_RESULT_MAGIC != op_result->magic)
		ODP_ABORT();

	memcpy(result, &op_result->result, sizeof(*result));
}

void
odp_crypto_compl_free(odp_crypto_compl_t completion_event)
{
	_odp_buffer_event_type_set(
		odp_buffer_from_event((odp_event_t)completion_event),
		ODP_EVENT_PACKET);
}

int odp_crypto_session_config_ipsec(odp_crypto_session_t session,
				    enum odp_ipsec_mode ipsec_mode,
				    enum odp_ipsec_proto ipsec_proto,
				    odp_ipsec_params_t *ipsec_params)
{
	odp_crypto_generic_session_t *ses;

	ses = (odp_crypto_generic_session_t *)(intptr_t)session;
	if (!memcpy(&ses->ipsec_params, ipsec_params,
		    sizeof(odp_ipsec_params_t)))
		abort();
	/* Initialize ESP sequence number with 1 */
	odp_atomic_init_u64(&ses->seq_no, 1);

	ses->ipsec_mode = ipsec_mode;
	ses->ipsec_proto = ipsec_proto;

	/* Find the ICV length for a specific authentication algorithm */
	if (ODP_AUTH_ALG_MD5_96 == ses->auth.alg)
		ses->auth.icv_len = 12;
	else if (ODP_AUTH_ALG_SHA256_128 == ses->auth.alg)
		ses->auth.icv_len = 16;
	/* Set functions in case of encrypt */
	if (ODP_IPSEC_ESP == ipsec_proto && ODP_CRYPTO_OP_ENCODE == ses->op) {
		ses->in_crypto_func.before = &encode_before_crypto;
		if (ses->ipsec_params.esn)
			ses->in_crypto_func.after = &encode_after_crypto;
		else
			ses->in_crypto_func.after = &void_func;
	}
	/* Set functions in case of decrypt */
	if (ODP_IPSEC_ESP == ipsec_proto && ODP_CRYPTO_OP_DECODE == ses->op) {
		ses->in_crypto_func.before = &decode_before_crypto;
		ses->in_crypto_func.after = &decode_after_crypto;
	}

	if (ODP_IPSEC_MODE_TUNNEL == ses->ipsec_mode) {
		odph_ipv4hdr_t *out_hdr_ptr;

		ses->ipsec_params.out_hdr = malloc(sizeof(odph_ipv4hdr_t));
		if (!ses->ipsec_params.out_hdr)
			abort();
		out_hdr_ptr = (odph_ipv4hdr_t *)ipsec_params->out_hdr;
		/* Set Outer header non configurable fields (encap) */
		out_hdr_ptr->proto = ODPH_IPPROTO_ESP;
		out_hdr_ptr->ttl = 64; /* Default TTL */

		if (!memcpy(ses->ipsec_params.out_hdr, ipsec_params->out_hdr,
			    sizeof(odph_ipv4hdr_t)))
			abort();
	}

	return 0;
}
