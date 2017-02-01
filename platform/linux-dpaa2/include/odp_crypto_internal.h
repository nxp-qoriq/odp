/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_CRYPTO_INTERNAL_H_
#define ODP_CRYPTO_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif
#include <odp/api/crypto.h>
#include <odp/api/ipsec.h>
#include <odp/helper/ip.h>
#include <odp/helper/udp.h>
#include <dpaa2_sec_priv.h>

#define SES_STATUS_FREE     0
#define SES_STATUS_INUSE    1

/**
 * Maximum number of crypto sessions
 */
#define ODP_CONFIG_CRYPTO_SES   1024

extern struct dpaa2_dev *sec_dev;

/*!
 * The type of operation supported by DPAA2 SEC Library
 */
enum dpaa2_op_type {
	DPAA2_SEC_NONE,	/*!< No Cipher operations*/
	DPAA2_SEC_CIPHER,/*!< CIPHER operations */
	DPAA2_SEC_AUTH,	/*!< Authentication Operations */
	DPAA2_SEC_AEAD,	/*!< Authenticated Encryption with associated data */
	DPAA2_SEC_PDCP,	/*!< PDCP protocol operations*/
	DPAA2_SEC_PKC,	/*!< Public Key Cryptographic Operations */
	DPAA2_SEC_MAX
};

/*!
 * Class 1 context to be supplied by application
 */
struct dpaa2_cipher_ctxt {
	odp_crypto_iv_t  iv;	/**< Cipher Initialization Vector (IV) */
	uint8_t *init_counter;	/*!< Set initial counter for CTR mode */
};

/*!
 *  Class 2 context to be supplied by application
 */
struct dpaa2_auth_ctxt {
	uint8_t trunc_len;              /*!< Length for output ICV, should
					  * be 0 if no truncation required */
};

/*!
 * AEAD Processing context for single pass non-protocol processing
 */
struct dpaa2_aead_ctxt {
	odp_bool_t auth_cipher_text;       /**< Authenticate/cipher ordering */
	odp_crypto_iv_t  iv;	/**< Cipher Initialization Vector (IV) */
	uint16_t auth_only_len; /*!< Length of data for Auth only */
	uint8_t trunc_len;              /*!< Length for output ICV, should
					  * be 0 if no truncation required */
};

/*!
 * dpaa2 header for NAT-T support in IPSec ESP
 */
struct dpaa2_sec_natt_hdr {
	odph_ipv4hdr_t tunnel_header;	/*!< Outer IP Header for
			* tunnel mode*/
	odph_udphdr_t udp_header;	/*!< UDP Header for NAT Traversal
			* support. Valid for NAT-T tunnels*/
};

/*!
 * Additional IPSec header and options
 */
union header {
	struct dpaa2_sec_natt_hdr natt;	/*!< Outer NATT Header */
	odph_ipv4hdr_t ip4_hdr;	/*!< Outer IPv4 Header */
};

#define DPAA2_IPSEC_ESN 0x0001	/*!< Extended sequence number in IPSec */
#define DPAA2_IV_RANDOM 0x0002	/*!< Random IV for Class 1 Operation */
#define DPAA2_IPSEC_NATT 0x0004	/*!< NAT-Traversal required */
#define DPAA2_IPSEC_ANTIREPLAY_NONE 0x0008	/*!< No Antireplay Support*/
#define DPAA2_IPSEC_ANTIREPLAY_32 0x0010	/*!< Antireplay window of 32 bit */
#define DPAA2_IPSEC_ANTIREPLAY_64 0x0018	/*!< Antireplay window of 64 bit */
#define DPAA2_IPSEC_ANTIREPLAY_MASK 0x0018 /*!< Antireplay flag mask */
#define DPAA2_IPSEC_IP_CHECKSUM	0x0020	/*!<IP Header checksum update */
#define DPAA2_IPSEC_DTTL	0x0040	/*!<IP Header TTL Decrement */

/*!
 * The structure is to be filled by user as a part of
 * dpaa2_sec_proto_ctxt for PDCP Control Plane Protocol
 */
struct dpaa2_pdcp_ctxt {
	odp_pdcp_mode_t pdcp_mode;	/*!< Data/Control mode*/
	int8_t bearer;	/*!< PDCP bearer ID */
	int8_t pkt_dir;/*!< PDCP Frame Direction 0:UL 1:DL*/
	int8_t hfn_ovd;/*!< Overwrite HFN per packet*/
	uint32_t hfn;	/*!< Hyper Frame Number */
	uint32_t hfn_threshold;	/*!< HFN Threashold for key renegotiation */
	uint8_t sn_size;	/*!< Sequence number size, 7/12/15 */
	/*!< Type of the Class 2 algorithm. Supports SHA1 */

};

#define NULL_CRYPTO	1
#define NULL_IPSEC	2
struct dpaa2_null_sec_ctxt {
	uint8_t null_ctxt_type; /*!< NULL CRYPTO or NULL IPSEC context */
	uint32_t spi;           /*!< SPI value */
	uint32_t seq_no;         /**< ESP TX sequence number */
	union header hdr;	/*!< Header options for IPSec Protocol */
};

typedef struct crypto_ses_entry_u {
	odp_queue_t compl_queue;
	void *ctxt;	/*!< Additional opaque context maintained for DPAA2
			 * Driver. The relevant information to be filled by
			 * DPAA2 SEC driver are per flow FLC, associated SEC
			 * Object */
	uint8_t ctxt_type;
	odp_crypto_op_t dir;		/*!< Operation Direction */
	odp_cipher_alg_t cipher_alg;	/*!< Cipher Algorithm*/
	odp_auth_alg_t auth_alg;	/*!< Authentication Algorithm*/
	odp_crypto_key_t cipher_key;	/**< Cipher key */
	odp_crypto_key_t auth_key;	/**< Authentication key */
	uint8_t status;
	union {
		struct dpaa2_cipher_ctxt cipher_ctxt;
		struct dpaa2_auth_ctxt auth_ctxt;
		struct dpaa2_aead_ctxt aead_ctxt;
		struct dpaa2_pdcp_ctxt pdcp_ctxt;
		struct dpaa2_null_sec_ctxt null_sec_ctxt;
	} ext_params;
#ifdef ODP_IPSEC_DEBUG
	struct {
		odp_atomic_u64_t op_requests; /*!< Number of sec operations requested */
		odp_atomic_u64_t op_complete; /*!< Number of sec operations Completed */
		odp_atomic_u64_t bytes;	      /*!< Total number of bytes processed */
		odp_atomic_u64_t errors;      /*!< Number of sec operations failed */
	} stats;
#endif
} crypto_ses_entry_t;

typedef struct crypto_ses_table_t {
	crypto_ses_entry_t ses[ODP_CONFIG_CRYPTO_SES];
} crypto_ses_table_t;

typedef struct crypto_vq_t {
	void *rx_vq;
	uint8_t vq_id;
	int num_sessions;
} crypto_vq_t;

#ifdef __cplusplus
}
#endif

#endif
