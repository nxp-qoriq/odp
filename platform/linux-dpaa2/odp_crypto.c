/* Copyright (c) 2014, Linaro Limited
 * Copyright (C) 2011-2014 Freescale Semiconductor,Inc
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <odp/api/crypto.h>
#include <odp_internal.h>
#include <odp/api/atomic.h>
#include <odp/api/spinlock.h>
#include <odp/api/sync.h>
#include <odp/api/debug.h>
#include <odp/api/event.h>
#include <odp/api/align.h>
#include <odp/api/random.h>
#include <odp/api/shared_memory.h>
#include <odp_debug_internal.h>
#include <odp/api/hints.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_queue.h>
#include <odp_crypto_internal.h>
#include <odp_queue_internal.h>
#include <odp_schedule_internal.h>
#include <odp/api/init.h>
#include <dpaa2_sec_priv.h>
#include <dpaa2_dev_priv.h>
#include <dpaa2_mbuf_priv.h>
#include <dpaa2_io_portal_priv.h>
#include <dpaa2_eth_ldpaa_qbman.h>
#include <odp/helper/ip.h>
#include <odp/helper/ipsec.h>
#include <odp/helper/eth.h>
#include <flib/desc/ipsec.h>
#include <flib/desc/pdcp.h>
#include <flib/desc/algo.h>
#include <fsl_dpseci.h>
#include <odp/api/plat/sdk/eth/dpaa2_eth_ldpaa_annot.h>

#include <string.h>
#include <pthread.h>

#define ODP_DPAA2_CRYPTO_MIN_REQ_VQ 1
#define ODP_DPAA2_CRYPTO_ENABLE_RX_NOTIF FALSE
#define SYNC_MODE_EN 0
#define RNG_DEV "/dev/urandom"

extern int32_t dpaa2_sec_dev_list_add(struct dpaa2_dev *dev);

odp_spinlock_t vq_lock;
uint8_t avail_vq_mask = 0xff;
static crypto_ses_table_t *crypto_ses_tbl;
static odp_spinlock_t lock;
struct dpaa2_dev *sec_dev;
static int rng_dev_fd = -1;


/*
 * @todo This is a serious hack to allow us to use packet buffer to convey
 *	crypto operation results by placing them at the very end of the
 *	packet buffer. The issue should be resolved shortly once the issue
 *	of packets versus events on completion queues is closed.
 */

/*
 * get_vq_id(void) returns the next available vq in the mask "avail_vq_mask"
 * avail_vq_mask is a 8 bit mask, each bit is for a particular queue.
 * free_vq_id() shall be called for releasing a particular vq.
 * Every Session/Tunnel must be attached with one of these 8 VQs.
 */
static inline int get_vq_id(void)
{
	int n = 0;
	int max_rx_vq = dpaa2_dev_get_max_rx_vq(sec_dev);

	odp_spinlock_lock(&vq_lock);
	while (!((avail_vq_mask >> n) & 0x01) && n < max_rx_vq)
		n++;
	if (n >= max_rx_vq) {
		ODP_ERR("No free Queue Available for Crypto Session");
		return -1;
	}

	avail_vq_mask &= ~(0x01 << n);
	odp_spinlock_unlock(&vq_lock);

	return n;
}

static inline void free_vq_id(int n)
{
	odp_spinlock_lock(&vq_lock);
	avail_vq_mask |= (0x01 << n);
	odp_spinlock_unlock(&vq_lock);
}

static inline void print_desc(uint32_t *buff, int size)
{
	int i;
	uint8_t *it;

	if (size < 0) {
		printf("Invalid descriptor size (%d)\n", size);
		return;
	}

	for (i = 0; i < size; i++) {
		it = (uint8_t *)&buff[i];
		printf("%02x", *it);
		printf("%02x", *(it + 1));
		printf("%02x", *(it + 2));
		printf("%02x\n", *(it + 3));
	}
}

static int dpaa2_cipher_init(crypto_ses_entry_t *session)
{
	struct dpaa2_cipher_ctxt *ctxt = &(session->ext_params.cipher_ctxt);
	struct alginfo cipherdata;
	uint8_t dir;
	unsigned int bufsize;
	struct ctxt_priv *priv;
	struct sec_flow_context *flc;
	queue_entry_t *qentry = queue_to_qentry(session->compl_queue);
	crypto_vq_t *crypto_vq = qentry->s.priv;

	/* For SEC CIPHER only one descriptor is required. */
	priv = (struct ctxt_priv *)dpaa2_data_zmalloc(NULL,
			sizeof(struct ctxt_priv) + sizeof(struct sec_flc_desc),
			ODP_CACHE_LINE_SIZE);
	if (priv == NULL) {
		DPAA2_ERR(SEC, "\nNo Memory for priv CTXT");
		return DPAA2_FAILURE;
	}
	flc = &priv->flc_desc[0].flc;
	cipherdata.key = (uint64_t)session->cipher_key.data;
	cipherdata.keylen = session->cipher_key.length;
	cipherdata.key_enc_flags = 0;
	cipherdata.key_type = RTA_DATA_IMM;

	dir = (session->dir == ODP_CRYPTO_OP_ENCODE) ? DIR_ENC : DIR_DEC;

	switch (session->cipher_alg) {
	case ODP_CIPHER_ALG_AES128_CBC:
		cipherdata.algtype = OP_ALG_ALGSEL_AES;
		cipherdata.algmode = OP_ALG_AAI_CBC;
		break;
	case ODP_CIPHER_ALG_DES:
		cipherdata.algtype = OP_ALG_ALGSEL_DES;
		cipherdata.algmode = OP_ALG_AAI_CBC;
		break;
	case ODP_CIPHER_ALG_3DES_CBC:
		cipherdata.algtype = OP_ALG_ALGSEL_3DES;
		cipherdata.algmode = OP_ALG_AAI_CBC;
		break;
	case ODP_CIPHER_ALG_NULL:
	case ODP_CIPHER_ALG_AES_CTR:
	case ODP_CIPHER_ALG_SNOW_F8:
	case ODP_CIPHER_ALG_ZUC:
		DPAA2_WARN(SEC, "Alg type is supported only for PDCP Offload\n");
		return DPAA2_SUCCESS;
	default:
		DPAA2_ERR(SEC, "Invalid Alg type");
		dpaa2_data_free(priv);
		session->ctxt = NULL;
		return DPAA2_FAILURE;
	}

	bufsize = cnstr_shdsc_blkcipher(priv->flc_desc[0].desc, 1, 0,
			&cipherdata, NULL, ctxt->iv.length,
			dir);

	flc->word1_sdl = (uint8_t)bufsize;
	flc->dhr = 0;
	flc->bpv0 = 0x1;
	flc->mode_bits = 0x8000;
	flc->word2_rflc_31_0 = lower_32_bits(
			(uint64_t)sec_dev->rx_vq[crypto_vq->vq_id]);
	flc->word3_rflc_63_32 = upper_32_bits(
			(uint64_t)sec_dev->rx_vq[crypto_vq->vq_id]);
	session->ctxt = priv;

	return DPAA2_SUCCESS;
}

static int dpaa2_auth_init(crypto_ses_entry_t *session)
{
	struct dpaa2_auth_ctxt *ctxt = &(session->ext_params.auth_ctxt);
	struct alginfo authdata;
	unsigned int bufsize;
	struct ctxt_priv *priv;
	struct sec_flow_context *flc;
	queue_entry_t *qentry = queue_to_qentry(session->compl_queue);
	crypto_vq_t *crypto_vq = qentry->s.priv;

	/* For AUTH three descriptors are required for various stages */
	priv = (struct ctxt_priv *)dpaa2_data_zmalloc(NULL,
			sizeof(struct ctxt_priv) +
			3 * sizeof(struct sec_flc_desc), ODP_CACHE_LINE_SIZE);
	if (priv == NULL) {
		DPAA2_ERR(SEC, "\nNo memory for priv CTXT");
		return DPAA2_FAILURE;
	}

	authdata.key = (uint64_t)session->auth_key.data;
	authdata.keylen = session->auth_key.length;
	authdata.key_enc_flags = 0;
	authdata.algmode = OP_ALG_AAI_HMAC;
	authdata.key_type = RTA_DATA_IMM;

	switch (session->auth_alg) {
	case ODP_AUTH_ALG_MD5_96:
		authdata.algtype = OP_ALG_ALGSEL_MD5;
		ctxt->trunc_len = 12;
		break;
	case ODP_AUTH_ALG_SHA1_96:
		authdata.algtype = OP_ALG_ALGSEL_SHA1;
		ctxt->trunc_len = 12;
		break;
	case ODP_AUTH_ALG_SHA1_160:
		authdata.algtype = OP_ALG_ALGSEL_SHA1;
		ctxt->trunc_len = 20;
		break;
	case ODP_AUTH_ALG_SHA256_128:
		authdata.algtype = OP_ALG_ALGSEL_SHA256;
		ctxt->trunc_len = 32;
		break;
	case ODP_AUTH_ALG_SHA384_192:
		authdata.algtype = OP_ALG_ALGSEL_SHA384;
		ctxt->trunc_len = 48;
		break;
	case ODP_AUTH_ALG_SHA512_256:
		authdata.algtype = OP_ALG_ALGSEL_SHA512;
		ctxt->trunc_len = 64;
		break;
	case ODP_AUTH_ALG_NULL:
	case ODP_AUTH_ALG_AES_CMAC:
	case ODP_AUTH_ALG_SNOW_3G:
	case ODP_AUTH_ALG_ZUC:
		DPAA2_WARN(SEC, "Alg type is supported only for PDCP Offload\n");
		return DPAA2_SUCCESS;
	default:
		DPAA2_ERR(SEC, "Invalid ALG TYPE: %d", session->auth_alg);
		dpaa2_data_free(priv);
		session->ctxt = NULL;
		return DPAA2_FAILURE;
	}

	bufsize = cnstr_shdsc_hmac(priv->flc_desc[DESC_INITFINAL].desc,
			1, 0, &authdata, session->dir, ctxt->trunc_len);
	/* Other Descriptors to be added when RTA APIs are available. */
	flc = &priv->flc_desc[DESC_INITFINAL].flc;
	flc->word1_sdl = (uint8_t)bufsize;
	flc->word2_rflc_31_0 = lower_32_bits(
			(uint64_t)sec_dev->rx_vq[crypto_vq->vq_id]);
	flc->word3_rflc_63_32 = upper_32_bits(
			(uint64_t)sec_dev->rx_vq[crypto_vq->vq_id]);
	session->ctxt = priv;
	return DPAA2_SUCCESS;
}

static int dpaa2_aead_init(crypto_ses_entry_t *session)
{
	struct dpaa2_aead_ctxt *ctxt = &(session->ext_params.aead_ctxt);
	struct ctxt_priv *priv;
	unsigned int bufsize;
	struct alginfo cipherdata, authdata;
	uint8_t dir;
	struct sec_flow_context *flc;
	queue_entry_t *qentry = queue_to_qentry(session->compl_queue);
	crypto_vq_t *crypto_vq = qentry->s.priv;

	/* For Sec AEAD only one descriptor is required. */
	priv = (struct ctxt_priv *)dpaa2_data_zmalloc(NULL,
			sizeof(struct ctxt_priv) + sizeof(struct sec_flc_desc),
			ODP_CACHE_LINE_SIZE);
	if (priv == NULL) {
		DPAA2_ERR(SEC, "\nNo memory for priv CTXT");
		return DPAA2_FAILURE;
	}

	cipherdata.key = (uint64_t)session->cipher_key.data;
	cipherdata.keylen = session->cipher_key.length;
	cipherdata.key_enc_flags = 0;
	cipherdata.key_type = RTA_DATA_IMM;
	switch (session->cipher_alg) {
	case ODP_CIPHER_ALG_AES128_CBC:
		cipherdata.algtype = OP_ALG_ALGSEL_AES;
		cipherdata.algmode = OP_ALG_AAI_CBC;
		break;
	case ODP_CIPHER_ALG_DES:
		cipherdata.algtype = OP_ALG_ALGSEL_DES;
		cipherdata.algmode = OP_ALG_AAI_CBC;
		break;
	case ODP_CIPHER_ALG_3DES_CBC:
		cipherdata.algtype = OP_ALG_ALGSEL_3DES;
		cipherdata.algmode = OP_ALG_AAI_CBC;
		break;
	case ODP_CIPHER_ALG_NULL:
	case ODP_CIPHER_ALG_AES_CTR:
	case ODP_CIPHER_ALG_SNOW_F8:
	case ODP_CIPHER_ALG_ZUC:
		DPAA2_WARN(SEC, "Alg type is supported only for PDCP Offload\n");
		return DPAA2_SUCCESS;
	default:
		DPAA2_ERR(SEC, "Invalid Alg type");
		dpaa2_data_free(priv);
		session->ctxt = NULL;
		return DPAA2_FAILURE;
	}

	switch (session->auth_alg) {
	case ODP_AUTH_ALG_MD5_96:
		authdata.algtype = OP_ALG_ALGSEL_MD5;
		ctxt->trunc_len = 12;
		break;
	case ODP_AUTH_ALG_SHA1_96:
		authdata.algtype = OP_ALG_ALGSEL_SHA1;
		ctxt->trunc_len = 12;
		break;
	case ODP_AUTH_ALG_SHA1_160:
		authdata.algtype = OP_ALG_ALGSEL_SHA1;
		ctxt->trunc_len = 20;
		break;
	case ODP_AUTH_ALG_SHA256_128:
		authdata.algtype = OP_ALG_ALGSEL_SHA256;
		ctxt->trunc_len = 32;
		break;
	case ODP_AUTH_ALG_SHA384_192:
		authdata.algtype = OP_ALG_ALGSEL_SHA384;
		ctxt->trunc_len = 48;
		break;
	case ODP_AUTH_ALG_SHA512_256:
		authdata.algtype = OP_ALG_ALGSEL_SHA512;
		ctxt->trunc_len = 64;
		break;
	case ODP_AUTH_ALG_NULL:
	case ODP_AUTH_ALG_AES_CMAC:
	case ODP_AUTH_ALG_SNOW_3G:
	case ODP_AUTH_ALG_ZUC:
		DPAA2_WARN(SEC, "Alg type is supported only for PDCP Offload\n");
		return DPAA2_SUCCESS;
	default:
		DPAA2_ERR(SEC, "Invalid Alg type");
		dpaa2_data_free(priv);
		session->ctxt = NULL;
		return DPAA2_FAILURE;
	}

	authdata.key = (uint64_t)session->auth_key.data;
	authdata.keylen = session->auth_key.length;
	authdata.key_enc_flags = 0;
	authdata.key_type = RTA_DATA_IMM;
	/* To be Overriden in FD for every packet. */
	ctxt->auth_only_len = 0;

	dir = (session->dir == ODP_CRYPTO_OP_ENCODE) ? DIR_ENC : DIR_DEC;

	bufsize = cnstr_shdsc_authenc(priv->flc_desc[0].desc, 1,
			0, &cipherdata, &authdata, ctxt->iv.length,
			ctxt->auth_only_len, ctxt->trunc_len, dir);

	flc = &priv->flc_desc[0].flc;
	flc->word1_sdl = (uint8_t)bufsize;
	flc->word2_rflc_31_0 = lower_32_bits(
			(uint64_t)sec_dev->rx_vq[crypto_vq->vq_id]);
	flc->word3_rflc_63_32 = upper_32_bits(
			(uint64_t)sec_dev->rx_vq[crypto_vq->vq_id]);
	session->ctxt = priv;

	return DPAA2_SUCCESS;
}

static int dpaa2_sec_pdcp_uplane_init(crypto_ses_entry_t *session)
{
	struct dpaa2_pdcp_ctxt *ctxt = &(session->ext_params.pdcp_ctxt);
	struct ctxt_priv *priv;
	unsigned int bufsize;
	struct alginfo cipherdata;
	struct sec_flow_context *flc;
	queue_entry_t *qentry = queue_to_qentry(session->compl_queue);
	crypto_vq_t *crypto_vq = qentry->s.priv;

	/* For Sec Proto only one descriptor is required. */
	if (session->ctxt == NULL)
		session->ctxt = (struct ctxt_priv *)dpaa2_data_zmalloc(NULL,
				sizeof(struct ctxt_priv) +
				sizeof(struct sec_flc_desc),
				ODP_CACHE_LINE_SIZE);

	if (session->ctxt == NULL) {
		DPAA2_ERR(SEC, "\nNo memory for priv CTXT");
		return DPAA2_FAILURE;
	}
	priv = session->ctxt;

	cipherdata.key = (uint64_t)session->cipher_key.data;
	cipherdata.keylen = session->cipher_key.length;
	cipherdata.key_enc_flags = 0;
	cipherdata.key_type = RTA_DATA_IMM;

	switch (session->cipher_alg) {
	case ODP_CIPHER_ALG_SNOW_F8:
		cipherdata.algtype = PDCP_CIPHER_TYPE_SNOW;
		break;
	case ODP_CIPHER_ALG_ZUC:
		cipherdata.algtype = PDCP_CIPHER_TYPE_ZUC;
		break;
	case ODP_CIPHER_ALG_AES_CTR:
		cipherdata.algtype = PDCP_CIPHER_TYPE_AES;
		break;
	case ODP_CIPHER_ALG_NULL:
		cipherdata.algtype = PDCP_CIPHER_TYPE_NULL;
		break;
	default:
		DPAA2_ERR(SEC, "Invalid Cipher Algo");
		goto out;
	}

	if (ODP_CRYPTO_OP_ENCODE == session->dir) {
		bufsize = cnstr_shdsc_pdcp_u_plane_encap(
				priv->flc_desc[0].desc, 1, 0,
				ctxt->sn_size,
				ctxt->hfn,
				ctxt->bearer,
				ctxt->pkt_dir,
				ctxt->hfn_threshold,
				&cipherdata, 0);
	} else if (ODP_CRYPTO_OP_DECODE == session->dir) {
		bufsize = cnstr_shdsc_pdcp_u_plane_decap(
				priv->flc_desc[0].desc, 1, 0,
				ctxt->sn_size,
				ctxt->hfn,
				ctxt->bearer,
				ctxt->pkt_dir,
				ctxt->hfn_threshold,
				&cipherdata, 0);
	} else
		goto out;
	flc = &priv->flc_desc[0].flc;
	flc->word1_sdl = (uint8_t)bufsize;
	flc->word2_rflc_31_0 = lower_32_bits(
			(uint64_t)sec_dev->rx_vq[crypto_vq->vq_id]);
	flc->word3_rflc_63_32 = upper_32_bits(
			(uint64_t)sec_dev->rx_vq[crypto_vq->vq_id]);

	return DPAA2_SUCCESS;
out:
	DPAA2_ERR(SEC, "Invalid Algo Direction");
	return DPAA2_FAILURE;
}

static int dpaa2_sec_pdcp_cplane_init(crypto_ses_entry_t *session)
{
	struct dpaa2_pdcp_ctxt *ctxt = &(session->ext_params.pdcp_ctxt);
	struct ctxt_priv *priv;
	unsigned int bufsize;
	struct alginfo cipherdata, authdata;
	struct sec_flow_context *flc;
	queue_entry_t *qentry = queue_to_qentry(session->compl_queue);
	crypto_vq_t *crypto_vq = qentry->s.priv;

	/* For Sec Proto only one descriptor is required. */
	if (session->ctxt == NULL)
		session->ctxt = (struct ctxt_priv *)dpaa2_data_zmalloc(NULL,
				sizeof(struct ctxt_priv) +
				sizeof(struct sec_flc_desc),
				ODP_CACHE_LINE_SIZE);

	if (session->ctxt == NULL) {
		DPAA2_ERR(SEC, "\nNo memory for priv CTXT");
		return DPAA2_FAILURE;
	}
	priv = session->ctxt;

	cipherdata.key = (uint64_t)session->cipher_key.data;
	cipherdata.keylen = session->cipher_key.length;
	cipherdata.key_enc_flags = 0;
	cipherdata.key_type = RTA_DATA_IMM;
	switch (session->cipher_alg) {
	case ODP_CIPHER_ALG_SNOW_F8:
		cipherdata.algtype = PDCP_CIPHER_TYPE_SNOW;
		break;
	case ODP_CIPHER_ALG_ZUC:
		cipherdata.algtype = PDCP_CIPHER_TYPE_ZUC;
		break;
	case ODP_CIPHER_ALG_AES_CTR:
		cipherdata.algtype = PDCP_CIPHER_TYPE_AES;
		break;
	case ODP_CIPHER_ALG_NULL:
		cipherdata.algtype = PDCP_CIPHER_TYPE_NULL;
		break;
	default:
		DPAA2_ERR(SEC, "Invalid Cipher Algo %d ",
				session->cipher_alg);
		goto out;
	}

	authdata.key = (uint64_t)session->auth_key.data;
	authdata.keylen = session->auth_key.length;
	authdata.key_enc_flags = 0;
	authdata.key_type = RTA_DATA_IMM;

	switch (session->auth_alg) {
	case ODP_AUTH_ALG_SNOW_3G:
		authdata.algtype = PDCP_AUTH_TYPE_SNOW;
		break;
	case ODP_AUTH_ALG_ZUC:
		authdata.algtype = PDCP_AUTH_TYPE_ZUC;
		break;
	case ODP_AUTH_ALG_AES_CMAC:
		authdata.algtype = PDCP_AUTH_TYPE_AES;
		break;
	case ODP_AUTH_ALG_NULL:
		authdata.algtype = PDCP_AUTH_TYPE_NULL;
		break;
	default:
		DPAA2_ERR(SEC, "Invalid AUTH Algo %d",
				session->auth_alg);
		goto out;
	}

	if (ODP_CRYPTO_OP_ENCODE == session->dir)
		bufsize = cnstr_shdsc_pdcp_c_plane_encap(
				priv->flc_desc[0].desc, 1, 0,
				ctxt->hfn,
				ctxt->bearer,
				ctxt->pkt_dir,
				ctxt->hfn_threshold,
				&cipherdata, &authdata,
				0);
	else if (ODP_CRYPTO_OP_DECODE == session->dir)
		bufsize = cnstr_shdsc_pdcp_c_plane_decap(
				priv->flc_desc[0].desc, 1, 0,
				ctxt->hfn,
				ctxt->bearer,
				ctxt->pkt_dir,
				ctxt->hfn_threshold,
				&cipherdata, &authdata,
				0);
	else
		goto out;
	flc = &priv->flc_desc[0].flc;
	flc->word1_sdl = (uint8_t)bufsize;
	flc->word2_rflc_31_0 = lower_32_bits(
			(uint64_t)sec_dev->rx_vq[crypto_vq->vq_id]);
	flc->word3_rflc_63_32 = upper_32_bits(
			(uint64_t)sec_dev->rx_vq[crypto_vq->vq_id]);

	return DPAA2_SUCCESS;
out:
	DPAA2_ERR(SEC, "Invalid Algo Direction");
	return DPAA2_FAILURE;
}

static int sync_session_create(odp_crypto_session_params_t *params,
		odp_crypto_session_t *session_out,
		odp_crypto_ses_create_err_t *status)
{
	crypto_ses_entry_t *session = NULL;
	uint32_t i;

	for (i = 0; i < ODP_CONFIG_CRYPTO_SES; i++) {
		session = &crypto_ses_tbl->ses[i];
		if (session->status != SES_STATUS_FREE)
			continue;
		odp_spinlock_lock(&lock);
		if (session->status == SES_STATUS_FREE) {
			session->status = SES_STATUS_INUSE;
			odp_spinlock_unlock(&lock);
			break;
		}
		odp_spinlock_unlock(&lock);
	}

	if (ODP_CONFIG_CRYPTO_SES == i) {
		ODP_ERR("NO free session \n");
		*status = ODP_CRYPTO_SES_CREATE_ERR_ENOMEM;
		return -1;
	}
	session->cipher_alg = params->cipher_alg;
	session->auth_alg = params->auth_alg;
	session->dir = params->op;
	session->ctxt_type = DPAA2_SEC_NONE;
	session->compl_queue = params->compl_queue;
	session->ext_params.null_sec_ctxt.null_ctxt_type = NULL_CRYPTO;
	*session_out = (odp_crypto_session_t) session;
	*status = ODP_CRYPTO_SES_CREATE_ERR_NONE;
	return 0;
}

int odp_crypto_session_create(odp_crypto_session_params_t *params,
			odp_crypto_session_t *session_out,
			odp_crypto_ses_create_err_t *status)
{
	crypto_ses_entry_t *session = NULL;
	void *dma_key1 = NULL, *dma_key2 = NULL, *dma_iv = NULL;
	uint32_t i;
	int32_t rc;
	queue_entry_t *qentry;
	crypto_vq_t *crypto_vq;
	struct dpaa2_vq_param vq_cfg;
	int k = -1;

	/*Initialize the session with NULL*/
	*session_out = ODP_CRYPTO_SESSION_INVALID;

	if(!sec_dev) {
		ODP_ERR("No hardware crypto device\n");
		*status = ODP_CRYPTO_SES_CREATE_ERR_ENOTSUP;
		return -1;
	}
	if (params->pref_mode == ODP_CRYPTO_SYNC ||
			params->compl_queue == ODP_QUEUE_INVALID) {
		if (params->cipher_alg == ODP_CIPHER_ALG_NULL &&
				params->auth_alg == ODP_AUTH_ALG_NULL) {
			rc = sync_session_create(params, session_out, status);
			return rc;
		}
		*status = ODP_CRYPTO_SES_CREATE_ERR_ENOTSUP;
		ODP_ERR("Sync Mode not supported by the underlying platform");
		return -1;
	}

	/* Auth Cipher order */
	if (!params->auth_cipher_text &&
			(params->cipher_alg != ODP_CIPHER_ALG_NULL
			 && params->auth_alg != ODP_AUTH_ALG_NULL)) {
		ODP_PRINT("This mode of auth before cipher"
				" is supported only for PDCP Offload");
	}

	qentry = queue_to_qentry(params->compl_queue);
	memset(&vq_cfg, 0, sizeof(struct dpaa2_vq_param));
	queue_lock(qentry);
	qentry->s.status = QUEUE_STATUS_SCHED;
	if (qentry->s.dev_type != ODP_DEV_SEC) {
		k = get_vq_id();
		if (k < 0)
			return -1;
		crypto_vq = (crypto_vq_t *)malloc(sizeof(crypto_vq_t));
		if (!crypto_vq) {
			ODP_ERR("Fail to alloc crypto vq\n");
			*status = ODP_CRYPTO_SES_CREATE_ERR_ENOMEM;
			return -1;
		}
		crypto_vq->rx_vq = sec_dev->rx_vq[k];
		crypto_vq->num_sessions = 1;
		crypto_vq->vq_id = k;
		qentry->s.priv = crypto_vq;
		qentry->s.dev_type = ODP_DEV_SEC;

		if (qentry->s.param.type == ODP_QUEUE_TYPE_PLAIN) {
			qentry->s.dequeue_multi = sec_dequeue_multi;
			qentry->s.dequeue = sec_dequeue;
		} else {
			vq_cfg.conc_dev = odp_get_conc_from_grp(
						qentry->s.param.sched.group);
			vq_cfg.prio = ODP_SCHED_PRIO_DEFAULT;
			vq_cfg.sync = qentry->s.param.sched.sync;
		}

		dpaa2_dev_set_vq_handle(crypto_vq->rx_vq,
				(uint64_t)qentry->s.handle);
		rc = dpaa2_sec_setup_rx_vq(sec_dev, k, &vq_cfg);
		if (DPAA2_FAILURE == rc) {
			qentry->s.dev_type = ODP_DEV_ANY;
			free_vq_id(crypto_vq->vq_id);
			free(crypto_vq);
			*status = ODP_CRYPTO_SES_CREATE_ERR_ENOMEM;
			ODP_ERR("Fail to setup RX VQ with CONC\n");
			return -1;
		}
	} else {
		crypto_vq = qentry->s.priv;
		crypto_vq->num_sessions++;
	}
	queue_unlock(qentry);
	for (i = 0; i < ODP_CONFIG_CRYPTO_SES; i++) {
		session = &crypto_ses_tbl->ses[i];
		if (session->status != SES_STATUS_FREE)
			continue;
		odp_spinlock_lock(&lock);
		if (session->status == SES_STATUS_FREE) {
			session->status = SES_STATUS_INUSE;
			odp_spinlock_unlock(&lock);
			break;
		}
		odp_spinlock_unlock(&lock);
	}

	if (ODP_CONFIG_CRYPTO_SES == i) {
		ODP_ERR("NO free session \n");
		*status = ODP_CRYPTO_SES_CREATE_ERR_ENOMEM;
		crypto_vq->num_sessions--;
		if (crypto_vq->num_sessions == 0) {
			qentry->s.dev_type = ODP_DEV_ANY;
			free_vq_id(crypto_vq->vq_id);
			free(crypto_vq);
		}
		return -1;
	}
	session->cipher_alg = params->cipher_alg;
	session->auth_alg = params->auth_alg;
	session->dir = params->op;
	session->compl_queue = params->compl_queue;

	if (params->cipher_alg != ODP_CIPHER_ALG_NULL
			&& params->auth_alg == ODP_AUTH_ALG_NULL) {

		struct dpaa2_cipher_ctxt *cipher_ctxt =
					&(session->ext_params.cipher_ctxt);

		dma_key1 = dpaa2_data_zmalloc(NULL, params->cipher_key.length,
				ODP_CACHE_LINE_SIZE);
		if (!dma_key1) {
			DPAA2_ERR(APP1, "dpaa2_data_zmalloc() failed");
			goto key_fail;
		}

		memcpy(dma_key1, params->cipher_key.data,
				params->cipher_key.length);

		session->cipher_key.data = dma_key1;
		session->cipher_key.length = params->cipher_key.length;
		session->auth_key.data = NULL;
		session->auth_key.length = 0;
		cipher_ctxt->iv.length = params->iv.length;

		if (params->iv.data) {
			dma_iv = dpaa2_data_zmalloc(NULL, params->iv.length,
					ODP_CACHE_LINE_SIZE);
			if (!dma_iv) {
				DPAA2_ERR(APP1, "dpaa2_data_zmalloc() failed");
				goto iv_fail;
			}
			memcpy(dma_iv, params->iv.data, params->iv.length);
			cipher_ctxt->iv.data = dma_iv;
		} else {
			cipher_ctxt->iv.data = NULL;
		}
		if (dpaa2_cipher_init(session) == DPAA2_FAILURE) {
			DPAA2_ERR(APP1, "dpaa2_cipher_init_failed\n");
			goto init_fail;
		}
		session->ctxt_type = DPAA2_SEC_CIPHER;

	} else if (params->cipher_alg == ODP_CIPHER_ALG_NULL
			&& params->auth_alg != ODP_AUTH_ALG_NULL) {

		dma_key2 = dpaa2_data_zmalloc(NULL, params->auth_key.length,
				ODP_CACHE_LINE_SIZE);
		if (!dma_key2) {
			DPAA2_ERR(APP1, "dpaa2_data_zmalloc() failed");
			goto key_fail;
		}

		memcpy(dma_key2, params->auth_key.data,
				params->auth_key.length);

		session->cipher_key.data = NULL;
		session->cipher_key.length = 0;
		session->auth_key.data = dma_key2;
		session->auth_key.length = params->auth_key.length;
		session->dir = params->op;

		if (dpaa2_auth_init(session) == DPAA2_FAILURE) {
			DPAA2_ERR(APP1, "dpaa2_auth_init() failed");
			goto init_fail;
		}
		session->ctxt_type = DPAA2_SEC_AUTH;

	} else if (params->cipher_alg != ODP_CIPHER_ALG_NULL
			&& params->auth_alg != ODP_AUTH_ALG_NULL) {

		struct dpaa2_aead_ctxt *aead_ctxt =
				&(session->ext_params.aead_ctxt);

		dma_key1 = dpaa2_data_zmalloc(NULL, params->cipher_key.length,
				ODP_CACHE_LINE_SIZE);
		if (!dma_key1) {
			DPAA2_ERR(APP1, "dpaa2_data_zmalloc() failed");
			goto key_fail;
		}

		memcpy(dma_key1, params->cipher_key.data,
				params->cipher_key.length);

		dma_key2 = dpaa2_data_zmalloc(NULL, params->auth_key.length,
				ODP_CACHE_LINE_SIZE);
		if (!dma_key2) {
			DPAA2_ERR(APP1, "dpaa2_data_zmalloc() failed");
			goto key2_fail;
		}
		memcpy(dma_key2, params->auth_key.data, params->auth_key.length);

		session->cipher_key.data = dma_key1;
		session->cipher_key.length = params->cipher_key.length;
		/*TODO align DPAA2 and ODP alg_type*/
		session->auth_key.data = dma_key2;
		session->auth_key.length = params->auth_key.length;
		aead_ctxt->iv.length = params->iv.length;
		aead_ctxt->auth_cipher_text = params->auth_cipher_text;
		if (params->iv.data) {
			dma_iv = dpaa2_data_zmalloc(NULL, params->iv.length,
					ODP_CACHE_LINE_SIZE);
			if (!dma_iv) {
				DPAA2_ERR(APP1, "dpaa2_data_zmalloc() failed");
				goto iv_fail;
			}
			memcpy(dma_iv, params->iv.data, params->iv.length);
			aead_ctxt->iv.data = dma_iv;
		} else {
			aead_ctxt->iv.data = NULL;
		}
		if (dpaa2_aead_init(session) == DPAA2_FAILURE) {
			DPAA2_ERR(APP1, "dpaa2_aead_init_failed\n");
			goto init_fail;
		}
		session->ctxt_type = DPAA2_SEC_AEAD;
	} else {
		ODP_ERR("NO crypto ALGO specified\n");
		goto config_fail;
	}
#ifdef ODP_IPSEC_DEBUG
	odp_atomic_init_u64(&session->stats.op_requests, 0);
	odp_atomic_init_u64(&session->stats.op_complete, 0);
	odp_atomic_init_u64(&session->stats.bytes, 0);
	odp_atomic_init_u64(&session->stats.errors, 0);
#endif
	*session_out = (odp_crypto_session_t) session;
	*status = ODP_CRYPTO_SES_CREATE_ERR_NONE;
	return 0;

init_fail:
	dpaa2_data_free((void *)dma_iv);
iv_fail:
	dpaa2_data_free((void *)dma_key2);
key2_fail:
	dpaa2_data_free((void *)dma_key1);
key_fail:
config_fail:
	crypto_vq->num_sessions--;
	if (crypto_vq->num_sessions == 0) {
		qentry->s.dev_type = ODP_DEV_ANY;
		free_vq_id(crypto_vq->vq_id);
		free(crypto_vq);
	}
	session->status = SES_STATUS_FREE;
	*status = ODP_CRYPTO_SES_CREATE_ERR_ENOMEM;
	return -1;
}

int odp_crypto_session_destroy(odp_crypto_session_t session)
{
	crypto_ses_entry_t *ses = (crypto_ses_entry_t *)session;
	queue_entry_t *qentry;
	crypto_vq_t *crypto_vq = NULL;
	struct dpaa2_cipher_ctxt *cipher_ctxt = NULL;
	struct dpaa2_aead_ctxt *aead_ctxt = NULL;

	if (!ses || session == ODP_CRYPTO_SESSION_INVALID) {
		ODP_ERR("Not a valid session");
		return DPAA2_FAILURE;
	}

	dpaa2_data_free(ses->ctxt);
	ses->ctxt = NULL;
	if (ses->cipher_key.data)
		dpaa2_data_free((void *)(ses->cipher_key.data));
	if (ses->auth_key.data)
		dpaa2_data_free((void *)(ses->auth_key.data));

	switch (ses->ctxt_type) {
	case DPAA2_SEC_CIPHER:

		cipher_ctxt = &(ses->ext_params.cipher_ctxt);

		if (cipher_ctxt->iv.data)
			dpaa2_data_free((void *)(cipher_ctxt->iv.data));
		break;

	case DPAA2_SEC_AEAD:

		aead_ctxt = &(ses->ext_params.aead_ctxt);

		if (aead_ctxt->iv.data)
			dpaa2_data_free((void *)(aead_ctxt->iv.data));
		break;

	default:
		break;

	}

	qentry = queue_to_qentry(ses->compl_queue);
	if (qentry)
		crypto_vq = qentry->s.priv;
	if (crypto_vq) {
		crypto_vq->num_sessions--;
		if (crypto_vq->num_sessions == 0) {
			qentry->s.dev_type = ODP_DEV_ANY;
			free_vq_id(crypto_vq->vq_id);
			free(crypto_vq);
		}
	}
	odp_spinlock_lock(&lock);
	ses->status = SES_STATUS_FREE;
	odp_spinlock_unlock(&lock);

	return 0;
}

int odp_crypto_session_config_pdcp(odp_crypto_session_t session,
				   odp_pdcp_mode_t pdcp_mode,
				    odp_pdcp_params_t *pdcp_params)
{
	crypto_ses_entry_t *ses = (crypto_ses_entry_t *)session;
	struct dpaa2_pdcp_ctxt *pdcp_ctxt = &(ses->ext_params.pdcp_ctxt);
	if (!ses || session == ODP_CRYPTO_SESSION_INVALID) {
		ODP_ERR("Not a valid session");
		return DPAA2_FAILURE;
	}

	/*Backup and clear existing contexts*/
	switch (ses->ctxt_type) {
	case DPAA2_SEC_AEAD:
	{
		struct dpaa2_aead_ctxt *aead_ctxt = &(ses->ext_params.aead_ctxt);
		if (ODP_PDCP_MODE_CONTROL != pdcp_mode) {
			ODP_ERR("PDCP User plane mode:only Encyption sessions"
					" are supported");
			return DPAA2_FAILURE;
		}

		if (aead_ctxt->iv.data)
			dpaa2_data_free(aead_ctxt->iv.data);
		break;
	}
	case DPAA2_SEC_AUTH:
	{
		if (ODP_PDCP_MODE_CONTROL != pdcp_mode) {
			ODP_ERR("PDCP User plane mode:only Encyption sessions"
					" are supported");
			return DPAA2_FAILURE;
		}
		break;
	}
	case DPAA2_SEC_CIPHER:
	{
		struct dpaa2_cipher_ctxt *cipher_ctxt =
					&(ses->ext_params.cipher_ctxt);
		if (cipher_ctxt->iv.data)
			dpaa2_data_free(cipher_ctxt->iv.data);
		break;
	}
	default:
		ODP_ERR("unsupported session");
		return -1;
	}

	memset(pdcp_ctxt, 0, sizeof(struct dpaa2_pdcp_ctxt));
	pdcp_ctxt->pdcp_mode = pdcp_mode;
	pdcp_ctxt->sn_size = pdcp_params->sn_size;
	pdcp_ctxt->bearer = pdcp_params->bearer;
	pdcp_ctxt->pkt_dir = pdcp_params->pkt_dir;
	pdcp_ctxt->hfn_ovd = pdcp_params->hfn_ovd;
	pdcp_ctxt->hfn = pdcp_params->hfn;
	pdcp_ctxt->hfn_threshold = pdcp_params->hfn_threshold;

	if (ODP_PDCP_MODE_CONTROL == pdcp_mode) {
		if (pdcp_params->sn_size != 5) {
			ODP_ERR("Sequence Number size should be 5"
					" bits for control mode");
			return -1;
		}
		if (dpaa2_sec_pdcp_cplane_init(ses) == DPAA2_FAILURE) {
			ODP_ERR("dpaa2_sec_proto_init() failed");
			goto init_fail;
		}
	} else {
		if (dpaa2_sec_pdcp_uplane_init(ses) == DPAA2_FAILURE) {
			ODP_ERR("dpaa2_sec_proto_init() failed");
			goto init_fail;
		}
	}

	ses->ctxt_type = DPAA2_SEC_PDCP;
	return 0;

init_fail:
	dpaa2_data_free((void *)ses->cipher_key.data);
	dpaa2_data_free((void *)ses->auth_key.data);
	return -1;
}

static inline int build_eq_desc(struct qbman_eq_desc *eqdesc,
		struct dpaa2_vq *sec_tx_vq)
{
	uint64_t eq_storage_phys = 0;

	/*Prepare enqueue descriptor*/
	qbman_eq_desc_clear(eqdesc);
	qbman_eq_desc_set_no_orp(eqdesc, DPAA2_EQ_RESP_ERR_FQ);
	qbman_eq_desc_set_response(eqdesc, eq_storage_phys, 0);
	qbman_eq_desc_set_fq(eqdesc, sec_tx_vq->fqid);
	return 0;
}

static inline int build_cipher_fd(crypto_ses_entry_t *session, dpaa2_mbuf_pt mbuf,
		odp_crypto_data_range_t *range, uint8_t *override_iv_ptr,
		struct qbman_fd *fd)
{
	uint8_t *dma_iv;
	uint32_t mem_len;
	struct ctxt_priv *priv;
	struct qbman_fle *fle, *sge;
	struct sec_flow_context *flc;
	struct dpaa2_cipher_ctxt *cipher_ctxt =
				&(session->ext_params.cipher_ctxt);

	if (override_iv_ptr) {
		mem_len = (2*sizeof(struct qbman_fle)) + cipher_ctxt->iv.length;
	} else {
		mem_len = (2*sizeof(struct qbman_fle));
		dma_iv = cipher_ctxt->iv.data;
	}

	sge = dpaa2_data_zmalloc(NULL, mem_len, ODP_CACHE_LINE_SIZE);
	if (!sge) {
		DPAA2_ERR(SEC, "Failed to allocate fle\n");
		return -1;
	}
	if (override_iv_ptr) {
		dma_iv = (uint8_t *)(sge+2);
		memcpy(dma_iv, override_iv_ptr, cipher_ctxt->iv.length);
	}
	if ((mbuf->priv_meta_off - DPAA2_MBUF_HW_ANNOTATION) >=
			2*sizeof(struct qbman_fle)) {
		fle = (struct qbman_fle *)dpaa2_mbuf_frame_addr(mbuf);
		memset(fle, 0, 2*sizeof(*fle));
		DPAA2_DBG(SEC, "fle not allocated separately");
	} else {
		fle = dpaa2_data_zmalloc(NULL, (2*sizeof(struct qbman_fle)),
				ODP_CACHE_LINE_SIZE);
		if (!fle) {
			DPAA2_ERR(SEC, "Failed to allocate fle\n");
			dpaa2_data_free(sge);
			return -1;
		}
		DPAA2_DBG(SEC, "fle allocated separately");
	}

	if (odp_likely(mbuf->bpid < MAX_BPID)) {
		DPAA2_SET_FD_BPID(fd, mbuf->bpid);
		DPAA2_SET_FLE_BPID(fle, mbuf->bpid);
		DPAA2_SET_FLE_BPID((fle+1), mbuf->bpid);
		DPAA2_SET_FLE_BPID(sge, mbuf->bpid);
		DPAA2_SET_FLE_BPID((sge+1), mbuf->bpid);
	} else {
		DPAA2_SET_FD_IVP(fd);
		DPAA2_SET_FLE_IVP(fle);
		DPAA2_SET_FLE_IVP((fle+1));
		DPAA2_SET_FLE_IVP(sge);
		DPAA2_SET_FLE_IVP((sge+1));
	}

	/* Save the shared descriptor */
	priv = session->ctxt;
	flc = &priv->flc_desc[0].flc;

	DPAA2_SET_FD_ADDR(fd, fle);
	DPAA2_SET_FD_LEN(fd, (range->length + cipher_ctxt->iv.length));
	DPAA2_SET_FD_COMPOUND_FMT(fd);
	DPAA2_SET_FD_FLC(fd, ((uint64_t)flc));

	DPAA2_SET_FLE_ADDR(fle, (mbuf->data + range->offset));
	fle->length = range->length;

	fle++;

	DPAA2_SET_FLE_ADDR(fle, sge);
	fle->length = range->length + cipher_ctxt->iv.length;

	DPAA2_SET_FLE_SG_EXT(fle);

	DPAA2_SET_FLE_ADDR(sge, dma_iv);
	sge->length = cipher_ctxt->iv.length;

	sge++;
	DPAA2_SET_FLE_ADDR(sge, mbuf->data + range->offset);
	sge->length = range->length;
	DPAA2_SET_FLE_FIN(sge);

	DPAA2_SET_FLE_FIN(fle);

	return 0;
}

static inline int build_auth_fd(crypto_ses_entry_t *session,
		dpaa2_mbuf_pt mbuf,
		odp_crypto_data_range_t *range,
		uint32_t hash_result_offset,
		struct qbman_fd *fd)
{
	struct ctxt_priv *priv;
	struct qbman_fle *fle, *sge;
	struct sec_flow_context *flc;
	int icv_len = session->ext_params.auth_ctxt.trunc_len;
	uint8_t *old_icv;

	if ((mbuf->priv_meta_off - DPAA2_MBUF_HW_ANNOTATION) >=
			2*sizeof(struct qbman_fle)) {
		fle = (struct qbman_fle *)dpaa2_mbuf_frame_addr(mbuf);
		memset(fle, 0, 2*sizeof(*fle));
		DPAA2_DBG(SEC, "fle not allocated separately");
	} else {
		fle = dpaa2_data_zmalloc(NULL, (2*sizeof(struct qbman_fle)),
				ODP_CACHE_LINE_SIZE);
		if (!fle) {
			DPAA2_ERR(SEC, "Failed to allocate fle\n");
			return -1;
		}
		DPAA2_DBG(SEC, "fle allocated separately");
	}

	if (odp_likely(mbuf->bpid < MAX_BPID)) {
		DPAA2_SET_FD_BPID(fd, mbuf->bpid);
		DPAA2_SET_FLE_BPID(fle, mbuf->bpid);
		DPAA2_SET_FLE_BPID((fle+1), mbuf->bpid);
	} else {
		DPAA2_SET_FD_IVP(fd);
		DPAA2_SET_FLE_IVP(fle);
		DPAA2_SET_FLE_IVP((fle+1));
	}

	/* Save the shared descriptor */
	priv = session->ctxt;
	flc = &priv->flc_desc[2].flc;
	DPAA2_SET_FLE_ADDR(fle, (mbuf->data + hash_result_offset));
	fle->length = icv_len;
	DPAA2_SET_FD_ADDR(fd, fle);
	DPAA2_SET_FD_COMPOUND_FMT(fd);
	fle++;
	if (session->dir == ODP_CRYPTO_OP_ENCODE) {
		DPAA2_SET_FLE_ADDR(fle, (mbuf->data + range->offset));
		DPAA2_SET_FD_LEN(fd, range->length);
		fle->length = range->length;
	} else {
		sge = dpaa2_data_zmalloc(NULL, (2*sizeof(struct qbman_fle))
				+ icv_len, ODP_CACHE_LINE_SIZE);
		if (!sge) {
			DPAA2_ERR(SEC, "Failed to allocate fle\n");
			if ((mbuf->priv_meta_off - DPAA2_MBUF_HW_ANNOTATION) <
					2*sizeof(struct qbman_fle)) {
				dpaa2_data_free(fle);
			}
			return -1;
		}

		DPAA2_SET_FLE_SG_EXT(fle);
		DPAA2_SET_FLE_ADDR(fle, sge);
		DPAA2_SET_FLE_BPID(sge, mbuf->bpid);
		DPAA2_SET_FLE_ADDR(sge, (mbuf->data + range->offset));
		DPAA2_SET_FD_LEN(fd, range->length+icv_len);
		sge->length = range->length;
		sge++;
		old_icv = (uint8_t *)(sge +1);
		memcpy(old_icv,	(mbuf->data + hash_result_offset), icv_len);
		memset((mbuf->data + hash_result_offset), 0, icv_len);
		DPAA2_SET_FLE_BPID(sge, mbuf->bpid);
		DPAA2_SET_FLE_ADDR(sge, old_icv);
		sge->length = icv_len;
		fle->length = range->length + icv_len;
		DPAA2_SET_FLE_FIN(sge);
	}

	DPAA2_SET_FLE_FIN(fle);
	DPAA2_SET_FD_FLC(fd, ((uint64_t)flc));

	return 0;
}

static inline int build_proto_sg_fd(crypto_ses_entry_t *session, dpaa2_mbuf_pt mbuf,
		odp_crypto_data_range_t *range, struct qbman_fd *fd)
{
	struct ctxt_priv *priv;
	struct qbman_fle *fle, *out_fle, *in_fle, *sge, *out_sge, *in_sge;
	struct sec_flow_context *flc;
	struct dpaa2_mbuf *cur_seg = mbuf, *seg = mbuf;
	int no_of_seg = 0, seg_index = 0;

	/* Total number of segment in mbuf */
	while (seg) {
		no_of_seg++;
		seg = seg->next_sg;
	}

	if ((mbuf->priv_meta_off - DPAA2_MBUF_HW_ANNOTATION) >=
			2*sizeof(struct qbman_fle)) {
		/* FLE pointing to SW annotation addr */
		fle = (struct qbman_fle *)((void *)mbuf->hw_annot - DPAA2_FD_PTA_SIZE);
		memset(fle, 0, 2*sizeof(*fle));
		DPAA2_DBG(SEC, "fle not allocated separately");
	} else {
		fle = dpaa2_data_zmalloc(NULL, (2*sizeof(struct qbman_fle)),
				ODP_CACHE_LINE_SIZE);
		if (!fle) {
			DPAA2_ERR(SEC, "Failed to allocate fle\n");
			return -1;
		}
		DPAA2_DBG(SEC, "fle allocated separately");
	}

	/* sge pointing to hw_annot addr + hw annot size */
	sge = (struct qbman_fle *)((void *)mbuf->hw_annot + DPAA2_MBUF_HW_ANNOTATION);
	memset(sge, 0, (2*no_of_seg*(sizeof(struct qbman_fle))));

	/* OUT FLE points to FLE ADDR */
	out_fle = (struct qbman_fle *)fle;

	/* IN FLE starts after OUT FLE ends */
	in_fle = (struct qbman_fle *)(fle + 1);

	/* OUT SGE points to SGE ADDR*/
	out_sge = (struct qbman_fle *)sge;

	/* IN SGE starts after OUT SGE ends */
	in_sge = (struct qbman_fle *)(sge + no_of_seg);

	/* Setting BPID in FD, FLE and SGE */
	if (odp_likely(mbuf->bpid < MAX_BPID)) {
		DPAA2_SET_FD_BPID(fd, mbuf->bpid);
		DPAA2_SET_FLE_BPID(out_fle, mbuf->bpid);
		DPAA2_SET_FLE_BPID(in_fle, mbuf->bpid);
	} else {
		DPAA2_SET_FD_IVP(fd);
		DPAA2_SET_FLE_IVP(out_fle);
		DPAA2_SET_FLE_IVP(in_fle);
	}

	/* Save the shared descriptor */
	priv = session->ctxt;
	flc = &priv->flc_desc[0].flc;

	/* Set Output FLE ADDR */
	DPAA2_SET_FLE_ADDR(out_fle, out_sge);

	/* Set Input FLE ADDR */
	DPAA2_SET_FLE_ADDR(in_fle, in_sge);

	/* Set Output FLE SG-EXT */
	DPAA2_SET_FLE_SG_EXT(out_fle);

	/* Set Input FLE SG-EXT */
	DPAA2_SET_FLE_SG_EXT(in_fle);

	/* Set offset of first output sge */
	DPAA2_SET_FLE_OFFSET(out_sge, range->offset);

	/* Set offset of first input sge */
	DPAA2_SET_FLE_OFFSET(in_sge, range->offset);

	while (cur_seg) {
		DPAA2_SET_FLE_ADDR((out_sge + seg_index), cur_seg->data);
		(out_sge + seg_index)->length = cur_seg->frame_len;
		DPAA2_SET_FLE_ADDR((in_sge + seg_index), cur_seg->data);
		(in_sge + seg_index)->length = cur_seg->frame_len;
		cur_seg = cur_seg->next_sg;
		seg_index++;
	}

	/* Set OUT SGE first seg length */
	out_sge->length = mbuf->end_off - dpaa2_mbuf_head_room - range->offset;

	/* Set IN SGE first seg length */
	in_sge->length = mbuf->frame_len - range->offset;

	if (seg_index == 1) {
		/* Set Output SGE first/last seg length */
		out_sge->length = mbuf->end_off - dpaa2_mbuf_head_room + dpaa2_mbuf_tail_room - range->offset;
		/* Set Output FLE length */
		out_fle->length = (out_sge + seg_index - 1)->length;
	} else {
		/* Set Output SGE last seg length */
		(out_sge + seg_index - 1)->length = mbuf->end_off + dpaa2_mbuf_tail_room;
		/* Set Output FLE length */
		out_fle->length = (mbuf->end_off * seg_index) - dpaa2_mbuf_head_room + dpaa2_mbuf_tail_room;
	}

	/* Set Input FLE length */
	in_fle->length = mbuf->tot_frame_len - range->offset;

	/* Set FIN BIT in Input SGE last seg */
	DPAA2_SET_FLE_FIN((in_sge + seg_index - 1));

	/* Set FIN BIT in Output SGE last seg */
	DPAA2_SET_FLE_FIN((out_sge + seg_index - 1));

	/* Set FIN BIT in Input FLE */
	DPAA2_SET_FLE_FIN(in_fle);

	/* Configure FD */
	DPAA2_SET_FD_COMPOUND_FMT(fd);
	DPAA2_SET_FD_LEN(fd, (in_fle->length));
	DPAA2_SET_FD_FLC(fd, ((uint64_t)flc));
	DPAA2_SET_FD_ADDR(fd, fle);

	return 0;
}

static inline int build_proto_fd(crypto_ses_entry_t *session, dpaa2_mbuf_pt mbuf,
		odp_crypto_data_range_t *range, struct qbman_fd *fd)
{
	struct ctxt_priv *priv;
	struct qbman_fle *fle;
	struct sec_flow_context *flc;

	if ((mbuf->priv_meta_off - DPAA2_MBUF_HW_ANNOTATION) >=
			2*sizeof(struct qbman_fle)) {
		fle = (struct qbman_fle *)dpaa2_mbuf_frame_addr(mbuf);
		memset(fle, 0, 2*sizeof(*fle));
		DPAA2_DBG(SEC, "fle not allocated separately");
	} else {
		fle = dpaa2_data_zmalloc(NULL, (2*sizeof(struct qbman_fle)),
				ODP_CACHE_LINE_SIZE);
		if (!fle) {
			DPAA2_ERR(SEC, "Failed to allocate fle\n");
			return -1;
		}
		DPAA2_DBG(SEC, "fle allocated separately");
	}

	if (odp_likely(mbuf->bpid < MAX_BPID)) {
		DPAA2_SET_FD_BPID(fd, mbuf->bpid);
		DPAA2_SET_FLE_BPID(fle, mbuf->bpid);
		DPAA2_SET_FLE_BPID((fle+1), mbuf->bpid);
	} else {
		DPAA2_SET_FD_IVP(fd);
		DPAA2_SET_FLE_IVP(fle);
		DPAA2_SET_FLE_IVP((fle+1));
	}

	/* Save the shared descriptor */
	priv = session->ctxt;
	flc = &priv->flc_desc[0].flc;
	DPAA2_SET_FLE_ADDR(fle, mbuf->data + range->offset);
	fle->length = mbuf->end_off - dpaa2_mbuf_headroom(mbuf);

	DPAA2_SET_FD_ADDR(fd, fle);
	DPAA2_SET_FD_LEN(fd, mbuf->frame_len - range->offset);
	DPAA2_SET_FD_COMPOUND_FMT(fd);
	fle++;
	DPAA2_SET_FLE_ADDR(fle, mbuf->data + range->offset);
	fle->length = mbuf->frame_len - range->offset;
	DPAA2_SET_FLE_FIN(fle);
	DPAA2_SET_FD_FLC(fd, ((uint64_t)flc));

	return 0;
}

static inline int build_authenc_fd(crypto_ses_entry_t *session,
		dpaa2_mbuf_pt mbuf,
		odp_crypto_op_params_t *params,
		struct qbman_fd *fd)
{
	struct ctxt_priv *priv;
	struct qbman_fle *fle, *sge;
	struct sec_flow_context *flc;
	struct dpaa2_aead_ctxt *aead_ctxt = &(session->ext_params.aead_ctxt);
	odp_crypto_data_range_t *c_range = &params->cipher_range;
	odp_crypto_data_range_t *a_range = &params->auth_range;
	uint32_t hash_result_offset = params->hash_result_offset;
	uint32_t auth_only_len = a_range->length - c_range->length;
	int icv_len = aead_ctxt->trunc_len;
	int iv_len = aead_ctxt->iv.length;
	uint8_t *old_icv;
	uint8_t *dma_iv = NULL;
	uint32_t mem_len;

	if ((mbuf->priv_meta_off - DPAA2_MBUF_HW_ANNOTATION) >=
			2*sizeof(struct qbman_fle)) {
		fle = (struct qbman_fle *)dpaa2_mbuf_frame_addr(mbuf);
		memset(fle, 0, 2*sizeof(*fle));
		DPAA2_DBG(SEC, "fle not allocated separately");
	} else {
		fle = dpaa2_data_zmalloc(NULL, (2*sizeof(struct qbman_fle)),
				ODP_CACHE_LINE_SIZE);
		if (!fle) {
			DPAA2_ERR(SEC, "Failed to allocate fle\n");
			return -1;
		}
		DPAA2_DBG(SEC, "fle allocated separately");
	}
	if (params->override_iv_ptr) {
		mem_len = (4*sizeof(struct qbman_fle)) + icv_len + aead_ctxt->iv.length;
	} else {
		mem_len = (4*sizeof(struct qbman_fle)) + icv_len;
		dma_iv = aead_ctxt->iv.data;
	}

	sge = dpaa2_data_zmalloc(NULL, mem_len, ODP_CACHE_LINE_SIZE);
	if (!sge) {
		DPAA2_ERR(SEC, "Failed to allocate fle\n");
		if ((mbuf->priv_meta_off - DPAA2_MBUF_HW_ANNOTATION) <
				2*sizeof(struct qbman_fle)) {
			dpaa2_data_free(fle);
		}
		return -1;
	}

	if (params->override_iv_ptr) {
		dma_iv = ((uint8_t *)(sge+4)) + icv_len;
		memcpy(dma_iv, params->override_iv_ptr, aead_ctxt->iv.length);
	}

	if (odp_likely(mbuf->bpid < MAX_BPID)) {
		DPAA2_SET_FD_BPID(fd, mbuf->bpid);
		DPAA2_SET_FLE_BPID(fle, mbuf->bpid);
		DPAA2_SET_FLE_BPID((fle+1), mbuf->bpid);
		DPAA2_SET_FLE_BPID(sge, mbuf->bpid);
		DPAA2_SET_FLE_BPID((sge+1), mbuf->bpid);
		DPAA2_SET_FLE_BPID((sge+2), mbuf->bpid);
		DPAA2_SET_FLE_BPID((sge+3), mbuf->bpid);
	} else {
		DPAA2_SET_FD_IVP(fd);
		DPAA2_SET_FLE_IVP(fle);
		DPAA2_SET_FLE_IVP((fle+1));
		DPAA2_SET_FLE_IVP(sge);
		DPAA2_SET_FLE_IVP((sge+1));
		DPAA2_SET_FLE_IVP((sge+2));
		DPAA2_SET_FLE_IVP((sge+3));
	}

	/* Save the shared descriptor */
	priv = session->ctxt;
	flc = &priv->flc_desc[0].flc;

	/* Configure FD as a FRAME LIST */
	DPAA2_SET_FD_ADDR(fd, fle);
	DPAA2_SET_FD_COMPOUND_FMT(fd);
	DPAA2_SET_FD_FLC(fd, ((uint64_t)flc));

	/* Configure Output FLE with Scatter/Gather Entry */
	DPAA2_SET_FLE_ADDR(fle, sge);
	if (auth_only_len)
		DPAA2_SET_FLE_INTERNAL_JD(fle, auth_only_len);
	fle->length = (session->dir == ODP_CRYPTO_OP_ENCODE) ?
			(c_range->length + icv_len) : c_range->length;
	DPAA2_SET_FLE_SG_EXT(fle);

	/* Configure Output SGE for Encap/Decap */
	DPAA2_SET_FLE_ADDR(sge, (mbuf->data + c_range->offset));
	sge->length = c_range->length;

	if (session->dir == ODP_CRYPTO_OP_ENCODE) {
		sge++;
		DPAA2_SET_FLE_ADDR(sge, (mbuf->data + hash_result_offset));
		sge->length = icv_len;
		DPAA2_SET_FD_LEN(fd, (a_range->length + iv_len));
	}
	DPAA2_SET_FLE_FIN(sge);

	sge++;
	fle++;

	/* Configure Input FLE with Scatter/Gather Entry */
	DPAA2_SET_FLE_ADDR(fle, sge);
	DPAA2_SET_FLE_SG_EXT(fle);
	DPAA2_SET_FLE_FIN(fle);
	fle->length = (session->dir == ODP_CRYPTO_OP_ENCODE) ?
			(a_range->length + iv_len) :
			(a_range->length + iv_len + icv_len);

	/* Configure Input SGE for Encap/Decap */
	DPAA2_SET_FLE_ADDR(sge, dma_iv);
	sge->length = iv_len;
	sge++;

	DPAA2_SET_FLE_ADDR(sge, (mbuf->data + a_range->offset));
	sge->length = a_range->length;
	if (session->dir == ODP_CRYPTO_OP_DECODE) {
		sge++;
		old_icv = (uint8_t *)(sge +1);
		memcpy(old_icv,	(mbuf->data + hash_result_offset), icv_len);
		memset((mbuf->data + hash_result_offset), 0, icv_len);
		DPAA2_SET_FLE_ADDR(sge, old_icv);
		sge->length = icv_len;
		DPAA2_SET_FD_LEN(fd, (a_range->length + icv_len + iv_len));
	}
	DPAA2_SET_FLE_FIN(sge);
	if (auth_only_len) {
		DPAA2_SET_FLE_INTERNAL_JD(fle, auth_only_len);
		DPAA2_SET_FD_INTERNAL_JD(fd, auth_only_len);
	}
	return 0;
}

static inline int process_null_op_with_sync(crypto_ses_entry_t *session, dpaa2_mbuf_pt mbuf)
{
	struct dpaa2_null_sec_ctxt *null_ctxt = &(session->ext_params.null_sec_ctxt);
	odph_esphdr_t *esp;
	odph_esptrl_t *esp_t;
	odph_ipv4hdr_t *ip_tun, *ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(mbuf, NULL);

	if (null_ctxt->null_ctxt_type == NULL_CRYPTO) {
		/*No Operation needs to be done for null Cypto operation.*/
		return DPAA2_SUCCESS;
	}

	if (session->dir == ODP_CRYPTO_OP_ENCODE) {
		if (odp_packet_headroom(mbuf) < (ODPH_ESPHDR_LEN + ODPH_IPV4HDR_LEN)) {
			ODP_ERR("Insufficient Headroom for NULL AUTH + NULL CIPHER");
			return DPAA2_FAILURE;
		}

		mbuf->data -= (ODPH_ESPHDR_LEN + ODPH_IPV4HDR_LEN);
		mbuf->frame_len += (ODPH_ESPHDR_LEN + ODPH_IPV4HDR_LEN + ODPH_ESPTRL_LEN);

		mbuf->tot_frame_len = mbuf->frame_len;
		memcpy(mbuf->data, (mbuf->data + ODPH_ESPHDR_LEN + ODPH_IPV4HDR_LEN),
				ODPH_ETHHDR_LEN);
		memcpy((mbuf->data + ODPH_ETHHDR_LEN),
				&null_ctxt->hdr.ip4_hdr,
				ODPH_IPV4HDR_LEN);
		esp = (odph_esphdr_t *)(mbuf->data + ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);

		esp->seq_no = odp_cpu_to_be_32((null_ctxt->seq_no)++);
		esp->spi = odp_cpu_to_be_32(null_ctxt->spi);
		esp_t = (odph_esptrl_t *)(mbuf->data + mbuf->frame_len) - 1;
		esp_t->pad_len     = 0;
		esp_t->next_header = ODPH_IPV4;

		ip_tun = (odph_ipv4hdr_t *)odp_packet_l3_ptr(mbuf, NULL);
		ip_tun->proto = ODPH_IPPROTO_ESP;
		ip_tun->tot_len = odp_cpu_to_be_16(odp_be_to_cpu_16(ip->tot_len) +
				(ODPH_ESPHDR_LEN + ODPH_IPV4HDR_LEN + ODPH_ESPTRL_LEN));
		odph_ipv4_csum_update(mbuf);
	} else {
		memcpy(mbuf->data + ODPH_ESPHDR_LEN + ODPH_IPV4HDR_LEN, mbuf->data,
				ODPH_ETHHDR_LEN);
		mbuf->data += (ODPH_ESPHDR_LEN + ODPH_IPV4HDR_LEN);
		mbuf->frame_len -= (ODPH_ESPHDR_LEN + ODPH_IPV4HDR_LEN + ODPH_ESPTRL_LEN);
		mbuf->tot_frame_len = mbuf->frame_len;
	}
	return DPAA2_SUCCESS;
}

int
odp_crypto_operation(odp_crypto_op_params_t *params,
		odp_bool_t *posted,
		odp_crypto_op_result_t *result)
{
	crypto_ses_entry_t *session = (crypto_ses_entry_t *) (params->session);
	odp_event_t completion_event;
	struct qbman_fd fd;
	dpaa2_mbuf_pt mbuf = (dpaa2_mbuf_pt) params->pkt;
	int ret, offset = 0;
	struct qbman_eq_desc eqdesc;
	struct qbman_swp *swp;
	void *vq = NULL;
	queue_entry_t *qentry;
	crypto_vq_t *crypto_vq;

	if (odp_unlikely(!session)) {
		*posted = 0;
		ODP_ERR("No Session specified for crypto operation");
		return DPAA2_FAILURE;
	}

	if (odp_unlikely(params->out_pkt == ODP_PACKET_INVALID ||
				params->out_pkt != params->pkt)) {
		*posted = 0;
		ODP_ERR("only in_place crypto operation supported");
		return DPAA2_FAILURE;
	}

	memset(&fd, 0, sizeof(struct qbman_fd));
	switch (session->ctxt_type) {

	case DPAA2_SEC_PDCP:
			offset = params->cipher_range.offset;
			if (odp_likely(!BIT_ISSET_AT_POS(mbuf->eth_flags,
					DPAA2BUF_IS_SEGMENTED)))
				ret = build_proto_fd(session, mbuf,
					     &params->cipher_range, &fd);
			else
				ret = build_proto_sg_fd(session, mbuf,
					     &params->cipher_range, &fd);
			break;

	case DPAA2_SEC_CIPHER:
			offset = params->cipher_range.offset;
			ret = build_cipher_fd(session, mbuf,
					&params->cipher_range,
					params->override_iv_ptr, &fd);
			break;
	case DPAA2_SEC_AUTH:
			offset = mbuf->frame_len;
			/* offset need to be adjusted for ENCODE as the out
			   FD len would be generated ICV len and for DECODE
			   it would be 0, So offset should be frame_len for
			   DECODE and  frame_len - ICV for ENCODE. */
			offset -= session->dir ? 0 :
				session->ext_params.auth_ctxt.trunc_len;
			ret = build_auth_fd(session, mbuf,
					&params->auth_range,
					params->hash_result_offset,
					&fd);
			break;
	case DPAA2_SEC_AEAD:
			offset = params->cipher_range.offset;
			ret = build_authenc_fd(session, mbuf,
					params, &fd);
			break;
	case DPAA2_SEC_NONE:
			ret = process_null_op_with_sync(session, mbuf);
			*posted = 0;
			if (odp_unlikely(ret)) {
				result->ok = FALSE;
				ODP_ERR("Improper packet contents for crypto operation");
				return DPAA2_FAILURE;
			}
			result->ok = TRUE;
			result->ctx = params->ctx;
			result->pkt = params->out_pkt;
			result->cipher_status.alg_err = ODP_CRYPTO_ALG_ERR_NONE;
			result->cipher_status.hw_err = ODP_CRYPTO_HW_ERR_NONE;
			result->auth_status.alg_err = ODP_CRYPTO_ALG_ERR_NONE;
			result->auth_status.hw_err = ODP_CRYPTO_HW_ERR_NONE;

			return 0;
		default:
			ODP_ERR("TODO: Not yet supported");
			return -1;
	}

	if (odp_unlikely(ret)) {
		*posted = 0;
		ODP_ERR("Improper packet contents for crypto operation");
		return DPAA2_FAILURE;
	}

	qentry = queue_to_qentry(session->compl_queue);
	crypto_vq = qentry->s.priv;
	vq = sec_dev->tx_vq[crypto_vq->vq_id];
	ret = build_eq_desc(&eqdesc, (struct dpaa2_vq *) vq);
	if (odp_unlikely(ret)) {
		*posted = 0;
		ODP_ERR("Improper Queue for Crypto Operation");
		return DPAA2_FAILURE;
	}

	swp = thread_io_info.dpio_dev->sw_portal;
	if (odp_unlikely(!swp)) {
		*posted = 0;
		ODP_ERR("No portal found");
		return DPAA2_FAILURE;
	}

	/* Set DCA for freeing DQRR if required. We are saving
	   DQRR entry index in buffer when using DQRR mode.
	   The same need to be freed by H/W.
	*/
	if (ANY_ATOMIC_CNTXT_TO_FREE(mbuf)) {
		qbman_eq_desc_set_dca(&eqdesc, 1,
					GET_HOLD_DQRR_IDX(mbuf->index), 0);
		MARK_HOLD_DQRR_PTR_INVALID(mbuf->index);
	} else if (mbuf->opr.orpid != INVALID_ORPID) {
		qbman_eq_desc_set_orp(&eqdesc, 0, mbuf->opr.orpid,
					mbuf->opr.seqnum, 0);
	}

	_odp_buffer_type_set(mbuf, ODP_EVENT_CRYPTO_COMPL);
#if SYNC_MODE_EN
	if (session->compl_queue != ODP_QUEUE_INVALID) {
#endif
		/*use packet for completion event */
		completion_event = params->out_pkt;
		completion_event->drv_priv_cnxt = params->ctx;
		completion_event->drv_priv_resv[0] = offset;
#ifdef ODP_IPSEC_DEBUG
		completion_event->drv_priv_cnxt1 = session;
#endif
		do {
			ret = qbman_swp_enqueue(swp, &eqdesc, &fd);
			if (ret != 0) {
				ODP_DBG("VEQ command is not issued. QBMAN is busy\n");
			}
		} while (ret == -EBUSY);

#ifdef ODP_IPSEC_DEBUG
		odp_atomic_inc_u64(&session->stats.op_requests);
#endif
		*posted = 1;
		return 0;
#if SYNC_MODE_EN
	} else {
		dpaa2_mbuf_pt buf_ptr[1];
		odp_crypto_op_result_t local_result;

		/* Fill in result */
		local_result.ctx = params->ctx;
		local_result.pkt = params->out_pkt;
		local_result.cipher_status.alg_err = ODP_CRYPTO_ALG_ERR_NONE;
		local_result.cipher_status.hw_err = ODP_CRYPTO_HW_ERR_NONE;
		local_result.auth_status.alg_err = ODP_CRYPTO_ALG_ERR_NONE;
		local_result.auth_status.hw_err = ODP_CRYPTO_HW_ERR_NONE;
		local_result.ok = TRUE;

		do {
			ret = qbman_swp_enqueue(swp, &eqdesc, &fd);
			if (ret != 0) {
				ODP_DBG("VEQ command is not issued. QBMAN is busy\n");
			}
		} while (ret == -EBUSY);
		do {
			queue_entry_t *qentry = queue_to_qentry(
					session->compl_queue);
			crypto_vq_t *crypto_vq = qentry->s.priv;

			ret = dpaa2_sec_recv(crypto_vq->rx_vq, 1,
					buf_ptr);
			if (ret != 0) {
				break;
			}
			if (odp_unlikely(received_sigint)) {
				if (odp_term_local() < 0)
					fprintf(stderr, "error: odp_term_local() failed.\n");
				pthread_exit(NULL);
			}

		} while (1);

		if (ret < 0) {
			local_result.pkt = ODP_PACKET_INVALID;
			local_result.cipher_status.hw_err =
						ODP_CRYPTO_HW_ERR_UNSPEC;
			local_result.ok = FALSE;
			*result = local_result;
			return 0;
		}

		buf_ptr[0]->data -= offset;
		if (session->ctxt_type == DPAA2_SEC_PDCP) {
			buf_ptr[0]->frame_len += offset;
			buf_ptr[0]->tot_frame_len += offset;
		} else {
			buf_ptr[0]->frame_len = len;
			buf_ptr[0]->tot_frame_len = len;
		}
		if(!result)
			return -1;
		*result = local_result;
		*posted = 0;
	}
	return 0;
#endif
}

int
odp_crypto_init_global(void)
{
	struct dpaa2_dev *dev;
	odp_shm_t shm;
	int ret;
	uint32_t i, max_rx_vq;

	ODP_DBG("Crypto init ... ");
	shm = odp_shm_reserve("odp_crypto_ses",
				sizeof(crypto_ses_table_t),
				0, ODP_SHM_SW_ONLY);
	crypto_ses_tbl = odp_shm_addr(shm);
	if (crypto_ses_tbl == NULL)
		return -1;

	odp_spinlock_init(&lock);

	memset(crypto_ses_tbl, 0, sizeof(crypto_ses_table_t));


	TAILQ_FOREACH(dev, &device_list, next) {
		if (DPAA2_SEC == dev->dev_type) {
			/* Get Max available RX & TX VQs for this device */
			max_rx_vq = dpaa2_dev_get_max_rx_vq(dev);
			if (max_rx_vq < ODP_DPAA2_CRYPTO_MIN_REQ_VQ) {
				DPAA2_ERR(APP1, "Not enough Resource to run\n");
				return -1;
			}
			/* Add RX Virtual queues to this device*/
			for (i = 0; i < max_rx_vq; i++) {
				dpaa2_sec_setup_rx_vq(dev, i, NULL);
			}
			ret = dpaa2_sec_start(dev);
			if (ret == DPAA2_FAILURE) {
				DPAA2_ERR(APP1, "dpaa2_sec_start_failed\n");
				return -1;
			}
			/*
			* dpaa2_sec_dev_list_add - It adds the device
			* passed to the SEC list SEC could perform
			* operation for this device.
			*/
			dpaa2_sec_dev_list_add(dev);
			/* Setting up TX VQ after dpni_enable */
			sec_dev = dev;
		}
	}
	if(sec_dev == NULL) {
		printf("\n************Warning*************\n");
		ODP_PRINT("NO SEC device for Application\n");
	}
	/* Open RNG device */
	rng_dev_fd = open(RNG_DEV, O_RDONLY);
	if (rng_dev_fd < 0) {
		printf("\n************Warning*************\n");
		ODP_PRINT("NO RNG device for Application\n");
	}

	return 0;
}

int odp_crypto_term_global(void)
{
	int ret, rc = 0;
	struct dpaa2_dev *dev;

	TAILQ_FOREACH(dev, &device_list, next) {
		switch (dev->dev_type) {
		case DPAA2_SEC:
			dpaa2_sec_stop(dev);
			break;
		default:
			break;
		}
	}

	ret = odp_shm_free(odp_shm_lookup("odp_crypto_ses"));
	if (ret < 0) {
		ODP_ERR("shm free failed for odp_crypto_ses\n");
		rc = -1;
	}

	ret = close(rng_dev_fd);
	if (ret < 0) {
		ODP_ERR("rng_dev_fd close failed\n");
		rc = -1;
	}


	return rc;
}

int32_t
odp_random_data(uint8_t *buf, int32_t len, odp_bool_t use_entropy ODP_UNUSED)
{
	int32_t rlen;

	rlen = read(rng_dev_fd, buf, len);

	if (!rlen)
		return -1;

	return rlen;
}

odp_crypto_compl_t odp_crypto_compl_from_event(odp_event_t ev)
{
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
	odp_packet_t pkt = completion_event;

	pkt->frame_len += pkt->drv_priv_resv[0];
	pkt->tot_frame_len += pkt->drv_priv_resv[0];

	if (odp_unlikely(pkt->drv_priv_resv[1])) {
		/* TODO Parse SEC errors */
		ODP_ERR("SEC returned Error - %x\n", pkt->drv_priv_resv[1]);
		result->ok = FALSE;
	} else {
		result->ok = TRUE;
	}
	result->ctx = pkt->drv_priv_cnxt;
	result->pkt = pkt;
}

void
odp_crypto_compl_free(odp_crypto_compl_t completion_event ODP_UNUSED)
{
	/* We use the packet as the completion event so nothing to do here */
}

int odp_crypto_capability(odp_crypto_capability_t *capa)
{
	if (!capa)
		return -1;

	/* Initialize crypto capability structure */
	memset(capa, 0, sizeof(odp_crypto_capability_t));
	capa->op_mode_sync = 0;
	capa->op_mode_async = 2;
	capa->ciphers.bit.null = 1;
	capa->ciphers.bit.des = 1;
	capa->ciphers.bit.trides_cbc  = 1;
	capa->ciphers.bit.aes128_cbc  = 1;
	capa->ciphers.bit.aes128_gcm  = 0;

	capa->auths.bit.null = 1;
	capa->auths.bit.md5_96 = 1;
	capa->auths.bit.sha256_128 = 1;
	capa->auths.bit.aes128_gcm  = 0;

	capa->hw_ciphers.bit.null = 1;
	capa->hw_ciphers.bit.des = 1;
	capa->hw_ciphers.bit.trides_cbc  = 1;
	capa->hw_ciphers.bit.aes128_cbc  = 1;
	capa->hw_ciphers.bit.aes128_gcm  = 0;

	capa->hw_auths.bit.null = 1;
	capa->hw_auths.bit.md5_96 = 1;
	capa->hw_auths.bit.sha256_128 = 1;
	capa->hw_auths.bit.aes128_gcm  = 0;

	capa->max_sessions = ODP_CONFIG_CRYPTO_SES;

	return 0;
}

void
odp_crypto_print_stats(void)
{
	crypto_ses_entry_t *session;
	odp_crypto_ses_stats_t stats;
	int i = 0, j = 0, ret;

	printf("########################## SAs for Encryption #####################################\n\n");
	session = &crypto_ses_tbl->ses[i];

	while (i < ODP_CONFIG_CRYPTO_SES) {
		if ((session->status != SES_STATUS_FREE) && (session->dir == ODP_CRYPTO_OP_ENCODE)) {
			ret = odp_crypto_session_stats((odp_crypto_session_t)session, &stats);
			if (ret) {
				ODP_ERR("Unable to get stats\n");
				break;
			}
			printf("%d. Session handle = 0x%lx Operation type = %d\n", j, (odp_crypto_session_t)session,
					session->ctxt_type);
			printf("\t  Number of Operations Requests   = %28ld\n", stats.op_requests);
			printf("\t  Number of Operations Completed  = %28ld\n", stats.op_complete);
			printf("\t  Total Bytes Processed           = %28ld\n", stats.bytes);
			printf("\t  Number of error packets         = %28ld\n\n", stats.errors);
			j++;
		}
		i++;
		session = &crypto_ses_tbl->ses[i];
	}
	i = 0;
	j = 0;
	printf("########################### SAs for Decryption ####################################\n\n");
	session = &crypto_ses_tbl->ses[i];
	while (i < ODP_CONFIG_CRYPTO_SES) {
		if ((session->status != SES_STATUS_FREE) && (session->dir == ODP_CRYPTO_OP_DECODE)) {
			ret = odp_crypto_session_stats((odp_crypto_session_t)session, &stats);
			if (ret) {
				ODP_ERR("Unable to get stats\n");
				break;
			}
			printf("%d. Session handle = 0x%lx Operation type = %d\n", j, (odp_crypto_session_t)session,
					session->ctxt_type);
			printf("\t  Number of Operations Requests   = %28ld\n", stats.op_requests);
			printf("\t  Number of Operations Completed  = %28ld\n", stats.op_complete);
			printf("\t  Total Bytes Processed           = %28ld\n", stats.bytes);
			printf("\t  Number of error packets         = %28ld\n\n", stats.errors);
			j++;
		}
		i++;
		session = &crypto_ses_tbl->ses[i];
	}
}

int
odp_crypto_session_stats(odp_crypto_session_t session,
		odp_crypto_ses_stats_t *stats)
{
#ifndef ODP_IPSEC_DEBUG
	(void) session;	/* unused variable*/
	(void) stats;	/* unused variable*/
	ODP_ERR("IPSEC_DEBUGS are disabled\n");
	return -1;
#else
	crypto_ses_entry_t *ses = (crypto_ses_entry_t *)session;

	if (!ses)
		return -1;
	if (!stats)
		return -1;
	stats->op_requests = odp_atomic_load_u64(&ses->stats.op_requests);
	stats->op_complete = odp_atomic_load_u64(&ses->stats.op_complete);
	stats->bytes = odp_atomic_load_u64(&ses->stats.bytes);
	stats->errors = odp_atomic_load_u64(&ses->stats.errors);
#endif
	return 0;
}

int
odp_crypto_session_stats_reset(odp_crypto_session_t session)
{
#ifndef ODP_IPSEC_DEBUG
	(void) session;	/* Unused variable*/
	ODP_ERR("IPSEC_DEBUGS are disabled\n");
	return -1;
#else
	crypto_ses_entry_t *ses = (crypto_ses_entry_t *)session;

	if (!ses)
		return -1;
	odp_atomic_store_u64(&ses->stats.op_requests, 0);
	odp_atomic_store_u64(&ses->stats.op_complete, 0);
	odp_atomic_store_u64(&ses->stats.bytes, 0);
	odp_atomic_store_u64(&ses->stats.errors, 0);
#endif
	return 0;
}

int
odp_crypto_global_stats(odp_crypto_global_stats_t *stats)
{
	struct dpaa2_dev_priv *dev_priv;
	struct fsl_mc_io *dpseci_dev;
	int ret;

	if (!stats)
		return -1;

	if (!sec_dev) {
		ODP_ERR("Sec device not Found\n");
		return -1;
	}

	dev_priv = sec_dev->priv;
	if (!dev_priv) {
		ODP_ERR("Error: DPAA2 DEV %s PRIV NOT FOUND!\n", sec_dev->dev_string);
		return -1;
	}

	dpseci_dev = (struct fsl_mc_io *)dev_priv->hw;
	if (!dpseci_dev) {
		ODP_ERR("Error: FSL MC IO HANDLE NOT FOUND!\n");
		return -1;
	}

	ret = dpseci_get_sec_counters(dpseci_dev, CMD_PRI_LOW, dev_priv->token,
			(struct dpseci_sec_counters *)stats);
	if (ret) {
		ODP_ERR("Error while getting counters. Error Code = %d\n", ret);
		return -1;
	}

	return 0;
}
