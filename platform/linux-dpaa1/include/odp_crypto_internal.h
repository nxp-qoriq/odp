/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/**
 * @file
 *
 * ODP crypto - implementation internal
 */

#ifndef ODP_CRYPTO_INTERNAL_H_
#define ODP_CRYPTO_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/pool.h>
#include <odp/api/buffer.h>
#include <odp/api/debug.h>
#include <odp/api/align.h>
#include <odp/api/crypto.h>
#include <odp/helper/ip.h>
#include <configs/odp_config_platform.h>
#include <odp_pool_internal.h>
#include <usdpaa/fsl_usd.h>
#include <usdpaa/fsl_qman.h>
#include <flib/desc/common.h>
#include <flib/rta.h>
#include <flib/desc/algo.h>
#include <flib/desc/ipsec.h>
#include <flib/desc/jobdesc.h>
#include <flib/desc.h>
#include <flib/rta/protocol_cmd.h>

/** apps/lib/crypto/sec.h */
#define MAX_DESCRIPTOR_SIZE	 64
#define SEC_PREHDR_SDLEN_MASK	 0x0000007F /**< Bit mask for PreHeader length
						 field */
/* Optimization -
   ignore override_iv_ptr crypto arg and read IV from packet */
#undef ODP_CRYPTO_IV_FROM_PACKET

/* Use ICV SW check until HW check is available
 */
#define ODP_CRYPTO_ICV_HW_CHECK

#ifdef ODP_CRYPTO_ICV_HW_CHECK
#define ICV_CHECK_SG_NUM	4
#else
#define ICV_CHECK_SG_NUM	3
#endif

struct preheader_s {
	union {
		uint32_t word;
		struct {
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
			uint16_t rsvd63_48;
			unsigned int rsvd47_39:9;
			unsigned int idlen:7;
#else
			unsigned int idlen:7;
			unsigned int rsvd47_39:9;
			uint16_t rsvd63_48;
#endif
		} field;
	} __packed hi;

	union {
		uint32_t word;
		struct {
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
			unsigned int rsvd31_30:2;
			unsigned int fsgt:1;
			unsigned int lng:1;
			unsigned int offset:2;
			unsigned int abs:1;
			unsigned int add_buf:1;
			uint8_t pool_id;
			uint16_t pool_buffer_size;
#else
			uint16_t pool_buffer_size;
			uint8_t pool_id;
			unsigned int add_buf:1;
			unsigned int abs:1;
			unsigned int offset:2;
			unsigned int lng:1;
			unsigned int fsgt:1;
			unsigned int rsvd31_30:2;
#endif
		} field;
	} __packed lo;
} __packed;

struct sec_descriptor_t {
	struct preheader_s prehdr;
	uint32_t descbuf[MAX_DESCRIPTOR_SIZE];
};

/** apps/lib/crypto/sec.h end*/

#define SES_STATUS_FREE     0
#define SES_STATUS_INIT     1
#define SES_STATUS_READY    2

struct sg_priv;
typedef	void (*build_compound_fd_t)(struct odp_crypto_op_params *params,
							struct sg_priv *sgp);

struct crypto_ses_s {
	/* session params section */
	odp_crypto_op_t op;
	struct {
		odp_cipher_alg_t cipher_alg;
		odp_crypto_key_t key;
		uint8_t *iv;
		dma_addr_t iv_p;
		size_t iv_len;
	} cipher;

	struct {
		odp_auth_alg_t auth_alg;
		odp_crypto_key_t key;
	} auth;

	odp_crypto_op_mode_t op_mode;

	odp_pool_t output_pool;
	odp_buffer_t out_buf_size;
	odp_queue_t compl_queue;

	/* session internals */
	odp_spinlock_t		lock ODP_ALIGNED_CACHE;
	int			status;
	odp_crypto_session_t	handle;
	odp_queue_t		input_queue;
	struct qman_fq		input_fq;
	struct sec_descriptor_t *prehdr_desc;
	build_compound_fd_t	build_compound_fd;
	uint32_t		auth_only_len;
	/* IPSEC specific */
	/* Split key generation context */
	struct qman_fq		*to_sec_sk_fq;
	struct qman_fq		*from_sec_sk_fq;
	void			*sk_desc; /* Split key Job Queue Descriptor */
	void			*split_key;
	uint32_t		sk_algtype;
};

typedef union crypto_ses_entry_u {
	struct crypto_ses_s s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct crypto_ses_s))];
} crypto_ses_entry_t;

#define SESSION_FROM_FQ(fq)	 \
	((crypto_ses_entry_t *)container_of(fq, struct crypto_ses_s, input_fq))

/*
 * Operation completion event structure
 * */
struct ODP_PACKED op_compl_event {
	/* output packet */
	odp_packet_t out_pkt;
	/* output fd status*/
	uint32_t status;
	/* operation context */
	void *ctx;
};
#define MAX_ICV_LEN	32

/*
 * S/G entry for submitting CAAM jobs
 * */
struct ODP_PACKED sg_priv {
	struct op_compl_event __ev; /* used when completion event is the input buffer */
	struct qm_sg_entry sg[2]; /* input & output */
	crypto_ses_entry_t *ses;
	odp_buffer_t compl_ev;
	uint8_t icv[MAX_ICV_LEN]; /* computed ICV when checking */
	odp_packet_t in_pkt;
};

/* S/G entries and data for AH ICV check */
struct ODP_PACKED ah_icv_chk_in {
	struct qm_sg_entry sg[ICV_CHECK_SG_NUM]; /* ip_hdr, AH, zero_icv, IP payload, ICV to be checked */
};

struct ODP_PACKED cbc_cipher_in {
	struct qm_sg_entry sg[2]; /* IV + data block */
	uint8_t iv[IV_MAX_LEN];   /* IV */
};

struct ODP_PACKED authenc_encap_in {
	struct qm_sg_entry sg[5]; /* in :IV + auth_only + enc
				    out : enc + ICV */
};

struct ODP_PACKED authenc_decap_in {
	struct qm_sg_entry sg[6]; /* in : IV + ip_hdr|ah + zero ICV + ESP|ESP payload
				     out: decrypted payload + ICV to compare with */
};

/*
 * S/G entry is carried in fd annotation area
 * */
ODP_STATIC_ASSERT((sizeof(struct sg_priv) <=
		   FD_DEFAULT_OFFSET), "ERR_CAAM_SG_SIZE");

ODP_STATIC_ASSERT((sizeof(struct ah_icv_chk_in) <=
		   ODP_CONFIG_PACKET_TAILROOM), "ERR_CAAM_SG_SIZE");

ODP_STATIC_ASSERT((sizeof(struct cbc_cipher_in) <=
		   ODP_CONFIG_PACKET_TAILROOM), "ERR_CAAM_SG_SIZE");

ODP_STATIC_ASSERT((sizeof(struct authenc_encap_in) <=
		   ODP_CONFIG_PACKET_TAILROOM), "ERR_CAAM_SG_SIZE");

ODP_STATIC_ASSERT((sizeof(struct authenc_decap_in) <=
		   ODP_CONFIG_PACKET_TAILROOM), "ERR_CAAM_SG_SIZE");

crypto_ses_entry_t *get_ses_entry(uint32_t ses_id);

uint32_t get_sesid(crypto_ses_entry_t *entry);

static inline uint32_t session_to_id(odp_crypto_session_t handle)
{
	return handle - 1;
}

static inline odp_crypto_session_t session_from_id(uint32_t ses_id)
{
	return ses_id + 1;
}

static inline crypto_ses_entry_t *session_to_entry(odp_crypto_session_t handle)
{
	uint32_t ses_id;

	ses_id = session_to_id(handle);
	return get_ses_entry(ses_id);
}
#endif
