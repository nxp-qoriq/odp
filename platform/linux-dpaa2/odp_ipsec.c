/* Copyright 2016-2017 NXP
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/crypto.h>
#include <odp/api/ipsec.h>
#include <odp_internal.h>
#include <odp/api/atomic.h>
#include <odp/api/spinlock.h>
#include <odp/api/event.h>
#include <odp/api/align.h>
#include <odp/api/shared_memory.h>
#include <odp_packet_io_queue.h>
#include <flib/desc/algo.h>
#include <flib/desc/pdcp.h>
#include <flib/desc/ipsec.h>
#include <odp/helper/ip.h>
#include <odp/helper/ipsec.h>
#include <odp/helper/eth.h>
#include <dpaa2_io_portal_priv.h>
#include <dpaa2_sec_priv.h>
#include <dpaa2_dev_priv.h>
#include <dpaa2_mbuf_priv.h>
#include <dpaa2_eth_ldpaa_qbman.h>
#include <odp_queue_internal.h>
#include <odp_schedule_internal.h>
#include <odp/api/init.h>
#include <odp/api/debug.h>
#include <odp/api/sync.h>
#include <odp_ipsec_internal.h>
#include <string.h>
#include <pthread.h>
#include <odp_debug_internal.h>
#include <odp/api/plat/sdk/eth/dpaa2_eth_ldpaa_annot.h>
#include <odp/api/plat/sdk/eth/dpaa2_eth_ldpaa_qbman.h>
#include <sdk_priv/dpaa2_mbuf_priv.h>
#include <sdk_priv/dpaa2_fd_priv.h>

extern struct dpaa2_dev *sec_dev;
static odp_spinlock_t lock;
extern odp_spinlock_t vq_lock;
extern uint8_t avail_vq_mask;
static uint32_t bucket_count = ODP_CONFIG_IPSEC_BUCKET;
static ipsec_sa_table_t *ipsec_sa_tbl;
static sa_bucket_t *insa_hash_table;

static inline uint64_t calculate_hash(uint32_t spi)
{
	uint64_t hash = 0;
	uint64_t gr = JHASH_GOLDEN_RATIO;
	ODP_BJ3_MIX(spi, gr, hash);
	return hash;
}

static inline ipsec_sa_entry_t *sa_lookup_in_bucket(uint32_t spi, void *bucket)
{
	ipsec_sa_entry_t      *sa, *head;

	head = ((sa_bucket_t *)bucket)->next;
	for (sa = head; sa != NULL; sa = sa->next) {
		if (sa->spi == spi)
			return sa;
	}
	return NULL;
}

static inline void sa_insert_in_bucket(ipsec_sa_entry_t *sa, void *bucket)
{
	ipsec_sa_entry_t *head, *temp;
	sa_bucket_t *bkt = (sa_bucket_t *)bucket;

	if (!sa) {
		ODP_ERR("Invalid SA entry passed\n");
		return;
	}

	SLOCK(&bkt->lock);
	/*Check that entry already exist or not*/
	temp = sa_lookup_in_bucket(sa->spi, bkt);

	if (temp) {
		SUNLOCK(&bkt->lock);
		return;
	}

	if (!bkt->next) {
		bkt->next = sa;
	} else {
		head = bkt->next;
		sa->next = head;
		bkt->next = sa;
	}
	SUNLOCK(&bkt->lock);
}

static inline void sa_delete_in_bucket(ipsec_sa_entry_t *sa, void *bucket)
{
	ipsec_sa_entry_t *head, *temp, *prev = NULL;
	sa_bucket_t *bkt = (sa_bucket_t *)bucket;

	if (!sa) {
		ODP_ERR("Invalid SA entry passed\n");
		return;
	}

	SLOCK(&bkt->lock);
	/*Check that entry exist or not*/

	head = ((sa_bucket_t *)bucket)->next;

	if (!head) {
		ODP_DBG("SA entry not found\n");
		SUNLOCK(&bkt->lock);
		return;
	}

	if (head->next == NULL && head->spi == sa->spi) {
		bkt->next = NULL;
		SUNLOCK(&bkt->lock);
		return;
	}

	prev = head;

	for (temp = head->next; temp != NULL; temp = temp->next) {
		if (temp->spi == sa->spi) {
			prev->next = temp->next;
			temp->next = NULL;
			break;
		}
		prev = temp;
	}

	if (!temp)
		ODP_DBG("SA entry not found\n");

	SUNLOCK(&bkt->lock);
}

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

/**
 * Query IPSEC capabilities
 *
 * Outputs IPSEC capabilities on success.
 *
 * @param[out] capa   Pointer to capability structure for output
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_ipsec_capability(odp_ipsec_capability_t *capa)
{
	if (!capa)
		return DPAA2_FAILURE;

	/* Initialize ipsec capability structure */
	memset(capa, 0, sizeof(odp_ipsec_capability_t));

	capa->max_num_sa = ODP_CONFIG_IPSEC_SA;
	capa->op_mode_sync = 0;
	capa->op_mode_async = 2;
	capa->soft_limit_sec = 0;
	capa->hard_limit_sec = 0;

	capa->ciphers.bit.null = 1;
	capa->ciphers.bit.des = 1;
	capa->ciphers.bit.trides_cbc  = 1;
	capa->ciphers.bit.aes128_cbc  = 1;
	capa->ciphers.bit.aes128_gcm  = 0;

	capa->auths.bit.null = 1;
	capa->auths.bit.md5_96 = 1;
	capa->auths.bit.sha256_128 = 1;
	capa->auths.bit.aes128_gcm  = 0;

	return DPAA2_SUCCESS;
}

/**
 * Initialize IPSEC configuration options
 *
 * Initialize an odp_ipsec_config_t to its default values.
 *
 * @param[out] config  Pointer to IPSEC configuration structure
 */
void odp_ipsec_config_init(odp_ipsec_config_t *config)
{
	config->op_mode = ODP_IPSEC_OP_MODE_ASYNC;
}

/**
 * Global IPSEC configuration
 *
 * Initialize and configure IPSEC offload with global configuration options.
 * This must be called before any SAs are created. Use odp_ipsec_capability()
 * to examine which features and modes are supported.
 *
 * @param config   Pointer to IPSEC configuration structure
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @see odp_ipsec_capability(), odp_ipsec_config_init()
 */
int odp_ipsec_config(const odp_ipsec_config_t *config)
{
	odp_shm_t shm;
	odp_shm_t hash_shm;
	uint32_t i;
	sa_bucket_t *bucket;

	if (!config)
		return DPAA2_FAILURE;

	if (config->op_mode == ODP_IPSEC_OP_MODE_SYNC) {
		ODP_ERR("IPsec sync mode not supported\n");
		return DPAA2_FAILURE;
	}

	ODP_DBG("IPsec init ... ");
	shm = odp_shm_reserve("odp_ipsec_sa",
				sizeof(ipsec_sa_table_t),
				0, ODP_SHM_SW_ONLY);
	ipsec_sa_tbl = odp_shm_addr(shm);
	if (ipsec_sa_tbl == NULL) {
		ODP_ERR("Unable to reserve memory for IPSEC SA table\n");
		return DPAA2_FAILURE;
	}


	memset(ipsec_sa_tbl, 0, sizeof(ipsec_sa_table_t));

	/*Reserve memory for sa hash table*/
	hash_shm = odp_shm_reserve("sa_hash_table",
			sizeof(sa_bucket_t) * bucket_count,
						ODP_CACHE_LINE_SIZE, 0);
	insa_hash_table = odp_shm_addr(hash_shm);
	if (!insa_hash_table) {
		ODP_ERR("Error: shared mem alloc failed.\n");
		odp_shm_free(shm);
		return DPAA2_FAILURE;
	}

	/*Inialize Locks*/
	for (i = 0; i < bucket_count; i++) {
		bucket = &insa_hash_table[i];
		SLOCK_INIT(&bucket->lock);
	}

	memset(insa_hash_table, 0, bucket_count * sizeof(sa_bucket_t));

	odp_spinlock_init(&lock);

	return DPAA2_SUCCESS;
}

/**
 * Initialize IPSEC SA parameters
 *
 * Initialize an odp_ipsec_sa_param_t to its default values for all fields.
 *
 * @param param   Pointer to the parameter structure
 */
void odp_ipsec_sa_param_init(odp_ipsec_sa_param_t *param)
{
	memset(param, 0, sizeof(odp_ipsec_sa_param_t));
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

static int dpaa2_ipsec_init(ipsec_sa_entry_t *sa, odp_ipsec_sa_param_t *param)
{
	struct ctxt_priv *priv;
	unsigned int bufsize;
	struct alginfo cipherdata, authdata;
	struct ipsec_encap_pdb encap_pdb;
	struct ipsec_decap_pdb decap_pdb;
	struct sec_flow_context *flc;
	queue_entry_t *qentry = queue_to_qentry(sa->dest_queue);
	ipsec_vq_t *ipsec_vq = qentry->s.priv;

	if (sa->context == NULL)
		sa->context = (struct ctxt_priv *)dpaa2_data_zmalloc(NULL,
				sizeof(struct ctxt_priv) +
				sizeof(struct sec_flc_desc),
				ODP_CACHE_LINE_SIZE);

	if (sa->context == NULL) {
		DPAA2_ERR(SEC, "\nNo memory for priv CTXT");
		return DPAA2_FAILURE;
	}
	priv = sa->context;

	cipherdata.key = (uint64_t)param->crypto.cipher_key.data;
	cipherdata.keylen = param->crypto.cipher_key.length;
	cipherdata.key_enc_flags = 0;
	cipherdata.key_type = RTA_DATA_IMM;

	switch (param->crypto.cipher_alg) {

	case ODP_CIPHER_ALG_AES128_CBC:
		cipherdata.algtype = OP_PCL_IPSEC_AES_CBC;
		cipherdata.algmode = OP_ALG_AAI_CBC;
		break;
	case ODP_CIPHER_ALG_DES:
		cipherdata.algtype = OP_PCL_IPSEC_DES;
		cipherdata.algmode = OP_ALG_AAI_CBC;
		break;
	case ODP_CIPHER_ALG_3DES_CBC:
		cipherdata.algtype = OP_PCL_IPSEC_3DES;
		cipherdata.algmode = OP_ALG_AAI_CBC;
		break;
	case ODP_CIPHER_ALG_NULL:
		cipherdata.algtype = OP_PCL_IPSEC_NULL;
		break;
	default:
		DPAA2_ERR(SEC, "Invalid Cipher Algo");
		goto out;
	}

	switch (param->crypto.auth_alg) {

	case ODP_AUTH_ALG_SHA1_96:
		authdata.algtype = OP_PCL_IPSEC_HMAC_SHA1_96;
		break;
	case ODP_AUTH_ALG_MD5_96:
		authdata.algtype = OP_PCL_IPSEC_HMAC_MD5_96;
		break;
	case ODP_AUTH_ALG_SHA1_160:
		authdata.algtype = OP_PCL_IPSEC_HMAC_SHA1_160;
		break;
	case ODP_AUTH_ALG_SHA256_128:
		authdata.algtype = OP_PCL_IPSEC_HMAC_SHA2_256_128;
		break;
	case ODP_AUTH_ALG_SHA384_192:
		authdata.algtype = OP_PCL_IPSEC_HMAC_SHA2_384_192;
		break;
	case ODP_AUTH_ALG_SHA512_256:
		authdata.algtype = OP_PCL_IPSEC_HMAC_SHA2_512_256;
		break;
	case ODP_AUTH_ALG_AES_CMAC:
		authdata.algtype = OP_PCL_IPSEC_AES_CMAC_96;
		break;
	case ODP_AUTH_ALG_NULL:
		authdata.algtype = OP_PCL_IPSEC_HMAC_NULL;
		break;
	default:
		DPAA2_ERR(SEC, "Invalid AUTH Algo");
		goto out;
	}

	authdata.key = (uint64_t)param->crypto.auth_key.data;
	authdata.keylen = param->crypto.auth_key.length;
	authdata.key_enc_flags = 0;
	authdata.algmode = OP_ALG_AAI_HMAC;
	authdata.key_type = RTA_DATA_IMM;
	flc = &priv->flc_desc[0].flc;
	if (param->dir == ODP_IPSEC_DIR_OUTBOUND) {
		flc->dhr = SEC_FLC_DHR_OUTBOUND;
		odph_ipv4hdr_t ip4_hdr;
		ip4_hdr.ver_ihl = (ODPH_IPV4 << 4) | ODPH_IPV4HDR_IHL_MIN;;
		ip4_hdr.tot_len = odp_cpu_to_be_16(sizeof(ip4_hdr));
		ip4_hdr.tos = param->tunnel.ipv4.dscp;
		ip4_hdr.id = 0;
		ip4_hdr.frag_offset = 0;
		ip4_hdr.ttl = param->tunnel.ipv4.ttl;
		ip4_hdr.proto = ODPH_IPPROTO_ESP;
		ip4_hdr.chksum = 0;
		memcpy(&ip4_hdr.src_addr, param->tunnel.ipv4.src_addr, sizeof(ip4_hdr.src_addr));
		memcpy(&ip4_hdr.dst_addr, param->tunnel.ipv4.dst_addr, sizeof(ip4_hdr.dst_addr));
		ip4_hdr.chksum = odph_chksum((uint16_t *)(void *)&ip4_hdr,
			sizeof(odph_ipv4hdr_t));

		/* For Sec Proto only one descriptor is required. */
		memset(&encap_pdb, 0, sizeof(struct ipsec_encap_pdb));
		encap_pdb.options = (ODPH_IPV4 << PDBNH_ESP_ENCAP_SHIFT) |
			PDBOPTS_ESP_OIHI_PDB_INL |
			PDBOPTS_ESP_IVSRC |
			PDBHMO_ESP_ENCAP_DTTL;
		encap_pdb.spi = param->spi;
		encap_pdb.ip_hdr_len = sizeof(odph_ipv4hdr_t);

		bufsize = cnstr_shdsc_ipsec_new_encap(priv->flc_desc[0].desc,
				1, 0, &encap_pdb,
				(uint8_t *)&ip4_hdr,
				&cipherdata, &authdata);
	} else if (param->dir == ODP_IPSEC_DIR_INBOUND) {
		flc->dhr = SEC_FLC_DHR_INBOUND;
		memset(&decap_pdb, 0, sizeof(struct ipsec_decap_pdb));
		decap_pdb.options = sizeof(odph_ipv4hdr_t) << 16;
		bufsize = cnstr_shdsc_ipsec_new_decap(priv->flc_desc[0].desc, 1, 0,
				&decap_pdb, &cipherdata, &authdata);
	} else
		goto out;
	flc->word1_sdl = (uint8_t)bufsize;
#if !defined(BUILD_LS2080) && !defined(BUILD_LS2085)
	/*Enable the stashing control bit*/
	DPAA2_SET_FLC_RSC(flc);
	flc->word2_rflc_31_0 = lower_32_bits(
			(uint64_t)sec_dev->rx_vq[ipsec_vq->vq_id] | 0x14);
	flc->word3_rflc_63_32 = upper_32_bits(
			(uint64_t)sec_dev->rx_vq[ipsec_vq->vq_id]);
#endif
	/* Set EWS bit i.e. enable write-safe */
	DPAA2_SET_FLC_EWS(flc);
	/* Set BS = 1 i.e reuse input buffers as output buffers */
	DPAA2_SET_FLC_REUSE_BS(flc);
	/* Set FF = 10 (bit)
	Reuse input buffers if they provide sufficient space */
	DPAA2_SET_FLC_REUSE_FF(flc);

	return DPAA2_SUCCESS;
out:
	dpaa2_data_free(sa->context);
	return DPAA2_FAILURE;
}

/**
 * Create IPSEC SA
 *
 * Create a new IPSEC SA according to the parameters.
 *
 * @param param   IPSEC SA parameters
 *
 * @return IPSEC SA handle
 * @retval ODP_IPSEC_SA_INVALID on failure
 *
 * @see odp_ipsec_sa_param_init()
 */
odp_ipsec_sa_t odp_ipsec_sa_create(odp_ipsec_sa_param_t *param)
{
	ipsec_sa_entry_t *sa = NULL;
	void *dma_key1 = NULL, *dma_key2 = NULL;
	odp_ipsec_sa_param_t sa_param;
	uint32_t i;
	uint64_t hash;
	int32_t k = -1, rc;
	ipsec_vq_t *ipsec_vq;
	queue_entry_t *qentry;
	struct dpaa2_vq_param vq_cfg;

	if (param->mode == ODP_IPSEC_MODE_TRANSPORT) {
		ODP_ERR("Transport mode not supported\n");
		return ODP_IPSEC_SA_INVALID;
	}

	if (param->proto == ODP_IPSEC_AH) {
		ODP_ERR("AH mode not supported\n");
		return ODP_IPSEC_SA_INVALID;
	}

	if (param->frag_mode != ODP_IPSEC_FRAG_DISABLED) {
		ODP_ERR("Frag mode not supported\n");
		return ODP_IPSEC_SA_INVALID;
	}
	memset(&vq_cfg, 0, sizeof(struct dpaa2_vq_param));
	qentry = queue_to_qentry(param->dest_queue);
	queue_lock(qentry);

	if (qentry->s.dev_type != ODP_DEV_SEC) {
		k = get_vq_id();
		if (k < 0)
			return ODP_IPSEC_SA_INVALID;
		ipsec_vq = (ipsec_vq_t *)malloc(sizeof(ipsec_vq_t));
		if (!ipsec_vq) {
			free_vq_id(k);
			ODP_ERR("Fail to alloc ipsec vq\n");
			return ODP_IPSEC_SA_INVALID;
		}
		ipsec_vq->rx_vq = sec_dev->rx_vq[k];
		ipsec_vq->num_sa = 1;
		ipsec_vq->vq_id = k;
		qentry->s.priv = ipsec_vq;
		qentry->s.dev_type = ODP_DEV_SEC;

		if (qentry->s.param.type == ODP_QUEUE_TYPE_PLAIN) {
			qentry->s.dequeue_multi = sec_dequeue_multi;
			qentry->s.dequeue = sec_dequeue;
		} else {
			qentry->s.status = QUEUE_STATUS_SCHED;
			vq_cfg.conc_dev = odp_get_conc_from_grp(
						qentry->s.param.sched.group);
			vq_cfg.prio = ODP_SCHED_PRIO_DEFAULT;
			vq_cfg.sync = qentry->s.param.sched.sync;
		}
		dpaa2_dev_set_vq_handle(ipsec_vq->rx_vq,
				(uint64_t)qentry->s.handle);
		rc = dpaa2_sec_setup_rx_vq(sec_dev, k, &vq_cfg);
		if (DPAA2_FAILURE == rc) {
			qentry->s.dev_type = ODP_DEV_ANY;
			free_vq_id(ipsec_vq->vq_id);
			free(ipsec_vq);
			ODP_ERR("Fail to setup RX VQ with CONC\n");
			return ODP_IPSEC_SA_INVALID;
		}
	} else {
		ipsec_vq = qentry->s.priv;
		ipsec_vq->num_sa++;
	}
	queue_unlock(qentry);

	for (i = 0; i < ODP_CONFIG_IPSEC_SA; i++) {
		sa = &ipsec_sa_tbl->sa[i];
		if (sa->status != SA_STATUS_FREE)
			continue;
		odp_spinlock_lock(&lock);
		sa->status = SA_STATUS_INUSE;
		odp_spinlock_unlock(&lock);
		break;
	}

	if (ODP_CONFIG_IPSEC_SA == i) {
		ODP_ERR("NO free SA entry \n");
		ipsec_vq->num_sa--;
		if (ipsec_vq->num_sa == 0) {
			qentry->s.dev_type = ODP_DEV_ANY;
			free_vq_id(ipsec_vq->vq_id);
			free(ipsec_vq);
		}
		return ODP_IPSEC_SA_INVALID;
	}

	memcpy(&sa_param, param, sizeof(odp_ipsec_sa_param_t));

	sa->dest_queue = param->dest_queue;
	sa->user_context = param->context;
	sa->lookup_mode = param->lookup_mode;
	sa->dir = param->dir;

	if (param->crypto.cipher_alg != ODP_CIPHER_ALG_NULL
			&& param->crypto.auth_alg == ODP_AUTH_ALG_NULL) {

		dma_key1 = dpaa2_data_zmalloc(NULL, param->crypto.cipher_key.length,
				ODP_CACHE_LINE_SIZE);
		if (!dma_key1) {
			DPAA2_ERR(APP1, "dpaa2_data_zmalloc() failed");
			goto key_fail;
		}

		memcpy(dma_key1, param->crypto.cipher_key.data,
				param->crypto.cipher_key.length);

		sa->cipher_key = dma_key1;
		sa_param.crypto.cipher_key.data = dma_key1;
		sa_param.crypto.cipher_key.length = param->crypto.cipher_key.length;
		sa_param.crypto.auth_key.data = NULL;
		sa_param.crypto.auth_key.length = 0;

	} else if (param->crypto.cipher_alg == ODP_CIPHER_ALG_NULL
			&& param->crypto.auth_alg != ODP_AUTH_ALG_NULL) {

		dma_key2 = dpaa2_data_zmalloc(NULL, param->crypto.auth_key.length,
				ODP_CACHE_LINE_SIZE);
		if (!dma_key2) {
			DPAA2_ERR(APP1, "dpaa2_data_zmalloc() failed");
			goto key_fail;
		}

		memcpy(dma_key2, param->crypto.auth_key.data,
				param->crypto.auth_key.length);

		sa->auth_key = dma_key2;
		sa_param.crypto.cipher_key.data = NULL;
		sa_param.crypto.cipher_key.length = 0;
		sa_param.crypto.auth_key.data = dma_key2;
		sa_param.crypto.auth_key.length = param->crypto.auth_key.length;

	} else if (param->crypto.cipher_alg != ODP_CIPHER_ALG_NULL
			&& param->crypto.auth_alg != ODP_AUTH_ALG_NULL) {
		dma_key1 = dpaa2_data_zmalloc(NULL, param->crypto.cipher_key.length,
				ODP_CACHE_LINE_SIZE);
		if (!dma_key1) {
			DPAA2_ERR(APP1, "dpaa2_data_zmalloc() failed");
			goto key_fail;
		}

		memcpy(dma_key1, param->crypto.cipher_key.data,
				param->crypto.cipher_key.length);

		dma_key2 = dpaa2_data_zmalloc(NULL, param->crypto.auth_key.length,
				ODP_CACHE_LINE_SIZE);
		if (!dma_key2) {
			DPAA2_ERR(APP1, "dpaa2_data_zmalloc() failed");
			goto key2_fail;
		}
		memcpy(dma_key2, param->crypto.auth_key.data, param->crypto.auth_key.length);

		sa->cipher_key = dma_key1;
		sa->auth_key = dma_key2;
		sa_param.crypto.cipher_key.data = dma_key1;
		sa_param.crypto.cipher_key.length = param->crypto.cipher_key.length;
		sa_param.crypto.auth_key.data = dma_key2;
		sa_param.crypto.auth_key.length = param->crypto.auth_key.length;
	} else {
		ODP_ERR("NO crypto ALGO specified\n");
		goto config_fail;
	}
	sa->spi = odp_cpu_to_be_32(param->spi);

	if (dpaa2_ipsec_init(sa, &sa_param) == DPAA2_FAILURE) {
		ODP_ERR("dpaa2_sec_proto_init() failed");
		goto config_fail;
	}
	if (param->dir == ODP_IPSEC_DIR_INBOUND
		&& param->lookup_mode == ODP_IPSEC_LOOKUP_IN_UNIQUE_SA) {
		hash = calculate_hash(sa->spi);
		sa_insert_in_bucket(sa, &insa_hash_table[hash & (bucket_count - 1)]);
	}

	return (odp_ipsec_sa_t)sa;

config_fail:
	if (dma_key2)
		dpaa2_data_free(dma_key2);
key2_fail:
	if (dma_key1)
		dpaa2_data_free(dma_key1);
key_fail:
	sa->cipher_key = NULL;
	sa->auth_key = NULL;
	ipsec_vq->num_sa--;
	if (ipsec_vq->num_sa == 0) {
		qentry->s.dev_type = ODP_DEV_ANY;
		free_vq_id(ipsec_vq->vq_id);
		free(ipsec_vq);
	}
	sa->status = SA_STATUS_FREE;
	return ODP_IPSEC_SA_INVALID;
}

/**
 * Destroy IPSEC SA
 *
 * Destroy an unused IPSEC SA. Result is undefined if the SA is being used
 * (i.e. asynchronous operation is in progress).
 *
 * @param sa      IPSEC SA to be destroyed
 *
 * @retval 0      On success
 * @retval <0     On failure
 *
 * @see odp_ipsec_sa_create()
 */
int odp_ipsec_sa_destroy(odp_ipsec_sa_t sa)
{
	ipsec_sa_entry_t *sa_entry = (ipsec_sa_entry_t *)sa;
	queue_entry_t *qentry;
	uint64_t hash;
	ipsec_vq_t *ipsec_vq = NULL;

	if (!sa_entry || sa == ODP_IPSEC_SA_INVALID) {
		ODP_ERR("Not a valid sa");
		return DPAA2_FAILURE;
	}

	if (sa_entry->lookup_mode == ODP_IPSEC_LOOKUP_IN_UNIQUE_SA) {
		hash = calculate_hash(sa_entry->spi);
		sa_delete_in_bucket(sa_entry, &insa_hash_table[hash & (bucket_count - 1)]);
	}

	dpaa2_data_free(sa_entry->context);
	sa_entry->context = NULL;
	if (sa_entry->cipher_key)
		dpaa2_data_free(sa_entry->cipher_key);
	if (sa_entry->auth_key)
		dpaa2_data_free(sa_entry->auth_key);
	sa_entry->cipher_key = NULL;
	sa_entry->auth_key = NULL;


	qentry = queue_to_qentry(sa_entry->dest_queue);
	if (qentry)
		ipsec_vq = qentry->s.priv;
	if (ipsec_vq) {
		ipsec_vq->num_sa--;
		if (ipsec_vq->num_sa == 0) {
			qentry->s.dev_type = ODP_DEV_ANY;
			free_vq_id(ipsec_vq->vq_id);
			free(ipsec_vq);
		}
	}
	odp_spinlock_lock(&lock);
	sa_entry->status = SA_STATUS_FREE;
	odp_spinlock_unlock(&lock);

	return DPAA2_SUCCESS;

}

static inline ipsec_sa_entry_t *lookup_sa_entry(odp_packet_t pkt)
{
	uint32_t spi;
	uint64_t hash;

	spi = *(uint32_t *)odp_packet_l4_ptr(pkt, NULL);
	hash = calculate_hash(spi);
	return sa_lookup_in_bucket(spi, &insa_hash_table[hash & (bucket_count - 1)]);
}

static inline int build_proto_sg_fd(ipsec_sa_entry_t *sa, dpaa2_mbuf_pt mbuf,
					struct qbman_fd *fd)
{
	struct dpaa2_mbuf *cur_seg = mbuf;
	struct dpaa2_sg_entry *sgt, *sge;
	struct ctxt_priv *priv;
	struct sec_flow_context *flc;
	uint32_t offset, i;

	offset = odp_packet_l3_offset((odp_packet_t)mbuf);

	/* Prepare FD */
	DPAA2_SET_FD_ADDR(fd, (mbuf->hw_annot - DPAA2_FD_PTA_SIZE));
	DPAA2_SET_FD_LEN(fd, (mbuf->tot_frame_len - offset));
	DPAA2_SET_FD_BPID(fd, mbuf->bpid);
	DPAA2_SET_FD_OFFSET(fd, mbuf->priv_meta_off);
	qbman_fd_set_format(fd, qbman_fd_sg);

	/*Set Scatter gather table and Scatter gather entries*/
	sgt = (struct dpaa2_sg_entry *)((DPAA2_GET_FD_ADDR(fd))
					   + (DPAA2_GET_FD_OFFSET(fd)));
	i = 0;
	while (cur_seg) {
		/*First Scatter gather entry*/
		sge = &sgt[i++];
		memset(sge, 0, sizeof(struct dpaa2_sg_entry));
		dpaa2_sg_set_addr(sge,
				  (dma_addr_t)(cur_seg->head));
		if (i == 1) {
			dpaa2_sg_set_offset(sge, odp_packet_headroom(mbuf) + offset);
			dpaa2_sg_set_len(sge, cur_seg->frame_len - offset);
		} else {
			dpaa2_sg_set_len(sge, cur_seg->frame_len);
		}
		dpaa2_sg_set_bpid(sge, cur_seg->bpid);
		cur_seg = cur_seg->next_sg;
	}
	dpaa2_sg_set_final(sge, true);

	/* Save the shared descriptor */
	priv = sa->context;
	flc = &priv->flc_desc[0].flc;
	DPAA2_SET_FD_FLC(fd, ((uint64_t)flc));
	return 0;
}

static inline int build_proto_fd(ipsec_sa_entry_t *sa, dpaa2_mbuf_pt mbuf,
				struct qbman_fd *fd)
{
	struct ctxt_priv *priv;
	struct sec_flow_context *flc;

	if (odp_likely(mbuf->bpid < MAX_BPID)) {
		DPAA2_SET_FD_BPID(fd, mbuf->bpid);
	} else {
		DPAA2_SET_FD_IVP(fd);
	}

	/* Save the shared descriptor */
	priv = sa->context;
	flc = &priv->flc_desc[0].flc;

	DPAA2_SET_FD_ADDR(fd, mbuf->head);
	DPAA2_SET_FD_OFFSET(fd, (odp_packet_headroom(mbuf) + odp_packet_l3_offset((odp_packet_t)mbuf)));
	DPAA2_SET_FD_LEN(fd, mbuf->frame_len - odp_packet_l3_offset((odp_packet_t)mbuf));
	DPAA2_SET_FD_FLC(fd, ((uint64_t)flc));

	return DPAA2_SUCCESS;
}

/**
 * Inbound asynchronous IPSEC operation
 *
 * This operation does inbound IPSEC processing in asynchronous mode
 * (ODP_IPSEC_OP_MODE_ASYNC). It processes packets otherwise identically to
 * odp_ipsec_in(), but outputs all results through one or more
 * ODP_EVENT_IPSEC_RESULT events with the following ordering considerations.
 *
 * Asynchronous mode maintains (operation input) packet order per SA when
 * application calls the operation within an ordered or atomic scheduler context
 * of the same queue. Packet order is also maintained when application
 * otherwise guarantees (e.g. using locks) that the operation is not called
 * simultaneously from multiple threads for the same SA(s). Resulting
 * events for the same SA are enqueued in order, and packet handles (for the
 * same SA) are stored in order within an event.
 *
 * @param         input   Operation input parameters
 *
 * @return Number of input packets consumed (0 ... input.num_pkt)
 * @retval <0     On failure
 *
 * @see odp_ipsec_in(), odp_ipsec_result()
 */
int odp_ipsec_in_enq(const odp_ipsec_op_param_t *input)
{
	ipsec_sa_entry_t **psa = (ipsec_sa_entry_t **) (input->sa);
	int ret;
	struct qbman_eq_desc eqdesc;
	struct qbman_swp *swp;
	struct dpaa2_vq *vq = NULL;
	queue_entry_t *qentry;
	ipsec_vq_t *ipsec_vq;
	uint32_t num_sa = 0, num_pkt = 0, i, j = 0, lookup = 0, count = 0, inc = 0;

	num_pkt = input->num_pkt;
	num_sa = input->num_sa;

	if (num_sa == 1) {
		/* single SA for all pkt */
		inc = 0;
	} else if (num_sa == num_pkt) {
		/* 1 SA for each pkt */
		inc = 1;
	} else if (num_sa == 0) {
		lookup = 1;
	} else {
		/* Invalid num of SA */
		ODP_DBG("Invalid num of SA\n");
		return DPAA2_FAILURE;
	}
	for (i = 0; i < num_pkt; i++) {
		struct qbman_fd fd;
		memset(&fd, 0, sizeof(struct qbman_fd));
		dpaa2_mbuf_pt mbuf = (dpaa2_mbuf_pt) input->pkt[i];
		if (lookup) {
			ipsec_sa_entry_t *sa = lookup_sa_entry(input->pkt[i]);
			if (!sa) {
				ODP_ERR("SA NOT FOUND\n");
				return DPAA2_FAILURE;
			}
			if (odp_likely(!BIT_ISSET_AT_POS(mbuf->eth_flags,
							DPAA2BUF_IS_SEGMENTED)))
				ret = build_proto_fd(sa, mbuf, &fd);
			else
				ret = build_proto_sg_fd(sa, mbuf, &fd);

			qentry = queue_to_qentry(sa->dest_queue);
			mbuf->drv_priv_cnxt = sa;
		} else {
			if (odp_likely(!BIT_ISSET_AT_POS(mbuf->eth_flags,
							DPAA2BUF_IS_SEGMENTED)))
				ret = build_proto_fd(psa[j], mbuf, &fd);
			else
				ret = build_proto_sg_fd(psa[j], mbuf, &fd);

			qentry = queue_to_qentry(psa[j]->dest_queue);
			mbuf->drv_priv_cnxt = psa[j];
		}
		ipsec_vq = qentry->s.priv;
		vq = (struct dpaa2_vq *) sec_dev->tx_vq[ipsec_vq->vq_id];
		swp = thread_io_info.dpio_dev->sw_portal;

		/*Prepare enqueue descriptor*/
		build_eq_desc(&eqdesc, vq);

		/* Set DCA for freeing DQRR if required. We are saving
		   DQRR entry index in buffer when using DQRR mode.
		   The same need to be freed by H/W.
		*/
		if (ANY_ATOMIC_CNTXT_TO_FREE(mbuf)) {
			qbman_eq_desc_set_dca(&eqdesc, 1,
						GET_HOLD_DQRR_IDX(mbuf->index),
						0);
			MARK_HOLD_DQRR_PTR_INVALID(mbuf->index);
		} else if (mbuf->opr.orpid != INVALID_ORPID) {
			qbman_eq_desc_set_orp(&eqdesc, 0, mbuf->opr.orpid,
						mbuf->opr.seqnum, 0);
		}

		mbuf->drv_priv_resv[0] = odp_packet_l3_offset((odp_packet_t)mbuf);
		_odp_buffer_type_set(mbuf, ODP_EVENT_IPSEC_RESULT);

		do {
			ret = qbman_swp_enqueue(swp, &eqdesc, &fd);
			if (odp_unlikely(ret)) {
				ODP_DBG("VEQ command is not issued. QBMAN is busy\n");
			} else
				count++;
		} while (ret == -EBUSY);
		j += inc;
	}
	return count;
}

/**
 * Outbound asynchronous IPSEC operation
 *
 * This operation does outbound IPSEC processing in asynchronous mode
 * (ODP_IPSEC_OP_MODE_ASYNC). It processes packets otherwise identically to
 * odp_ipsec_out(), but outputs all results through one or more
 * ODP_EVENT_IPSEC_RESULT events with the following ordering considerations.
 *
 * Asynchronous mode maintains (operation input) packet order per SA when
 * application calls the operation within an ordered or atomic scheduler context
 * of the same queue. Packet order is also maintained when application
 * otherwise guarantees (e.g. using locks) that the operation is not called
 * simultaneously from multiple threads for the same SA(s). Resulting
 * events for the same SA are enqueued in order, and packet handles (for the
 * same SA) are stored in order within an event.
 *
 * @param         input   Operation input parameters
 *
 * @return Number of input packets consumed (0 ... input.num_pkt)
 * @retval <0     On failure
 *
 * @see odp_ipsec_out(), odp_ipsec_result()
 */
int odp_ipsec_out_enq(const odp_ipsec_op_param_t *input)
{
	ipsec_sa_entry_t **sa = (ipsec_sa_entry_t **) (input->sa);

	int ret;
	struct qbman_eq_desc eqdesc;
	struct qbman_swp *swp;
	struct dpaa2_vq *vq = NULL;
	queue_entry_t *qentry;
	ipsec_vq_t *ipsec_vq;
	uint32_t num_sa = 0, num_pkt = 0, i, j = 0, count = 0, inc = 0;

	num_pkt = input->num_pkt;
	num_sa = input->num_sa;

	if (num_sa == 1) {
		/* single SA for all pkt */
		inc = 0;
	} else if (num_sa == num_pkt) {
		/* 1 SA for each pkt */
		inc = 1;
	} else {
		/* Invalid num of SA */
		ODP_ERR("Invalid num of SA\n");
		return DPAA2_FAILURE;
	}
	for (i = 0; i < num_pkt; i++) {
		struct qbman_fd fd;
		dpaa2_mbuf_pt mbuf = (dpaa2_mbuf_pt) input->pkt[i];
		memset(&fd, 0, sizeof(struct qbman_fd));
		if (odp_likely(!BIT_ISSET_AT_POS(mbuf->eth_flags,
						DPAA2BUF_IS_SEGMENTED)))
			ret = build_proto_fd(sa[j], mbuf, &fd);
		else
			ret = build_proto_sg_fd(sa[j], mbuf, &fd);

		mbuf->drv_priv_cnxt = sa[j];
		qentry = queue_to_qentry(sa[j]->dest_queue);
		ipsec_vq = qentry->s.priv;
		vq = (struct dpaa2_vq *) sec_dev->tx_vq[ipsec_vq->vq_id];

		swp = thread_io_info.dpio_dev->sw_portal;

		/*Prepare enqueue descriptor*/
		build_eq_desc(&eqdesc, vq);

		/* Set DCA for freeing DQRR if required. We are saving
		   DQRR entry index in buffer when using DQRR mode.
		   The same need to be freed by H/W.
		*/
		if (ANY_ATOMIC_CNTXT_TO_FREE(mbuf)) {
			qbman_eq_desc_set_dca(&eqdesc, 1,
						GET_HOLD_DQRR_IDX(mbuf->index),
						0);
			MARK_HOLD_DQRR_PTR_INVALID(mbuf->index);
		} else if (mbuf->opr.orpid != INVALID_ORPID) {
			qbman_eq_desc_set_orp(&eqdesc, 0, mbuf->opr.orpid,
						mbuf->opr.seqnum, 0);
		}

		mbuf->drv_priv_resv[0] = odp_packet_l3_offset((odp_packet_t)mbuf);
		_odp_buffer_type_set(mbuf, ODP_EVENT_IPSEC_RESULT);
		do {
			ret = qbman_swp_enqueue(swp, &eqdesc, &fd);
			if (odp_unlikely(ret)) {
				ODP_DBG("VEQ command is not issued. QBMAN is busy\n");
			} else
				count++;
		} while (ret == -EBUSY);
		j += inc;
	}
	return count;
}

/**
 * Get IPSEC results from an ODP_EVENT_IPSEC_RESULT event
 *
 * Copies IPSEC operation results from an event. The event must be of
 * type ODP_EVENT_IPSEC_RESULT. It must be freed before the application passes
 * any resulting packet handles to other ODP calls.
 *
 * @param[out]    result  Pointer to operation result for output. Maybe NULL, if
 *                        application is interested only on the number of
 *                        packets.
 * @param         event   An ODP_EVENT_IPSEC_RESULT event
 *
 * @return Number of packets in the event. If this is larger than
 *         'result.num_pkt', all packets did not fit into result struct and
 *         application must call the function again with a larger result struct.
 * @retval <0     On failure
 *
 * @see odp_ipsec_in_enq(), odp_ipsec_out_enq()
 */
int odp_ipsec_result(odp_ipsec_op_result_t *result, odp_event_t event)
{
	odp_packet_t pkt;
	pkt = event;

	pkt->frame_len += pkt->drv_priv_resv[0];
	pkt->tot_frame_len += pkt->drv_priv_resv[0];

	if (odp_unlikely(pkt->drv_priv_resv[1])) {
		ODP_ERR("SEC returned Error - %x\n", pkt->drv_priv_resv[1]);
		result->res->status.all = pkt->drv_priv_resv[1];
		return DPAA2_FAILURE;
	} else
		result->res->status.all = ODP_IPSEC_OK;

	*(result->pkt) = event;
	result->num_pkt = 1;
	result->res->num_out = 1;
	result->res->sa = (odp_ipsec_sa_t)pkt->drv_priv_cnxt;

	return 1;
}

/**
 * Printable format of odp_ipsec_sa_t
 *
 * @param sa      IPSEC SA handle
 *
 * @return uint64_t value that can be used to print/display this handle
 */
uint64_t odp_ipsec_sa_to_u64(odp_ipsec_sa_t sa)
{
	return (uint64_t)sa;
}

/**
 * Get user defined SA context pointer
 *
 * @param sa      IPSEC SA handle
 *
 * @return User defined SA context pointer value
 * @retval NULL   On failure
 */
void *odp_ipsec_sa_context(odp_ipsec_sa_t sa)
{
	ipsec_sa_entry_t *sa_entry = (ipsec_sa_entry_t *)sa;
	return sa_entry->user_context;
}

/**
 * Update MTU for outbound IP fragmentation
 *
 * When IP fragmentation offload is enabled, the SA is created with an MTU.
 * This call may be used to update MTU at any time. MTU updates are not
 * expected to happen very frequently.
 *
 * @param sa      IPSEC SA to be updated
 * @param mtu     The new MTU value
 *
 * @retval 0      On success
 * @retval <0     On failure
 */
int odp_ipsec_mtu_update(odp_ipsec_sa_t sa ODP_UNUSED, uint32_t mtu ODP_UNUSED)
{
	/* Not supported */
	ODP_UNIMPLEMENTED();
	return DPAA2_FAILURE;
}

/**
 * Inbound synchronous IPSEC operation
 */
int odp_ipsec_in(const odp_ipsec_op_param_t *input ODP_UNUSED,
		 odp_ipsec_op_result_t *output ODP_UNUSED)
{
	/* Not supported */
	ODP_UNIMPLEMENTED();
	return DPAA2_FAILURE;
}

/**
 * Outbound synchronous IPSEC operation
 */
int odp_ipsec_out(const odp_ipsec_op_param_t *input ODP_UNUSED,
		  odp_ipsec_op_result_t *output ODP_UNUSED)
{
	/* Not supported */
	ODP_UNIMPLEMENTED();
	return DPAA2_FAILURE;
}
/**
 * @}
 */
