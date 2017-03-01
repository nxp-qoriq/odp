/* Copyright 2017 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp/api/packet_io.h>
#include <odp/api/packet.h>
#include <odp/api/packet_flags.h>
#include <odp_internal.h>
#include <odp/api/spinlock.h>
#include <odp/api/shared_memory.h>
#include <odp/api/hints.h>
#include <odp/api/random.h>
#include <odp_config_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/thread.h>
#include <odp/helper/ipsec.h>
#include <odp/api/system_info.h>
#include <odp/api/pool.h>

#include <odp_queue_internal.h>
#include <odp_pool_internal.h>
#include <odp_schedule_internal.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_packet_io_queue.h>
#include <odp_crypto_internal.h>
#include <odp_ipsec_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/spinlock.h>

#include <configs/odp_config_platform.h>
#include <usdpaa/fsl_usd.h>
#include <usdpaa/of.h>
#include <usdpaa/fsl_qman.h>
#include <usdpaa/usdpaa_netcfg.h>
#include <usdpaa/dma_mem.h>
#include <sec.h>

#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>

#include <odp/helper/eth.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

static odp_spinlock_t lock ODP_ALIGNED_CACHE;
static uint32_t bucket_count = ODP_CONFIG_IPSEC_BUCKET;
static ipsec_sa_table_t *ipsec_sa_tbl;
static sa_bucket_t *insa_hash_table;

static enum qman_cb_dqrr_result dqrr_cb_ipsec(struct qman_fq *fq,
		const struct qm_dqrr_entry *dqrr,
		uint64_t *user_context)
{
	uint32_t len, shift;
	uint8_t esp_padlen = 0;
	void *sg_addr;
	odp_packet_hdr_t *pkthdr;
	ipsec_sa_entry_t *sa;
	queue_entry_t *qentry;
	struct qm_sg_entry *sg;

	sg = __dma_mem_ptov(qm_fd_addr(&(dqrr->fd)));
	hw_sg_to_cpu(sg);

	pkthdr = (odp_packet_hdr_t *)((void *)sg - ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(odp_packet_hdr_t)));
	len = sg->length;
	shift = MAX_IV_LEN + ODPH_IPV4HDR_LEN + ODPH_ESPHDR_LEN;

	sg_addr = __dma_mem_ptov(qm_sg_addr(sg));
	pkthdr->drv_priv_resv = dqrr->fd.status;

	pkthdr->headroom  = pkthdr->headroom - shift;
	sa = (ipsec_sa_entry_t *)(pkthdr->drv_priv_cnxt);

	if (sa->dir == ODP_IPSEC_DIR_INBOUND) {
		esp_padlen = *(uint8_t *)((uint8_t *)sg_addr + len - ESP_PADLEN_OFFSET) + ESP_PADLEN_OFFSET;
		pkthdr->frame_len = len - esp_padlen + ODPH_ETHHDR_LEN;
	} else
		pkthdr->frame_len = len + ODPH_ETHHDR_LEN;

	pkthdr->event_type = ODP_EVENT_IPSEC_RESULT;
	pkthdr->sched_index = sched_local.index;

	*user_context = (uint64_t)pkthdr;

	qentry = (queue_entry_t *)container_of(fq, struct queue_entry_s, fq);

	switch (qentry->s.param.sched.sync) {

	case ODP_SCHED_SYNC_ATOMIC:
		pkthdr->dqrr = dqrr;
		return qman_cb_dqrr_defer;	/* Return defer for Atomic case */

	case ODP_SCHED_SYNC_ORDERED:
		pkthdr->orp.seqnum = dqrr->seqnum;
		pkthdr->orp.flags = 0;

	case ODP_SCHED_SYNC_PARALLEL:
		return qman_cb_dqrr_consume;	/* Return consume for Parallel and Ordered case */

	default:
		ODP_DBG("Invalid queue sched type\n");
		return qman_cb_dqrr_stop;
	}
}

static void ipsec_ern_cb(struct qman_portal *p __always_unused,
			  struct qman_fq *fq __always_unused,
			  const struct qm_mr_entry *msg __always_unused)
{
	ODP_ERR("ODP ipsec fqid=0x%x rc=0x%x, seqnum=0x%x\n",
			fq->fqid, msg->ern.rc, msg->ern.seqnum);
}

static int create_sa_input_fq(struct qman_fq *fq, dma_addr_t ctxt_a_addr, uint32_t ctx_b)
{
	struct qm_mcc_initfq fq_opts;
	uint32_t flags;
	int ret = -1;

	/* Clear FQ options */
	memset(&fq_opts, 0x00, sizeof(struct qm_mcc_initfq));

	flags = QMAN_FQ_FLAG_LOCKED | QMAN_FQ_FLAG_DYNAMIC_FQID;
	flags |= QMAN_FQ_FLAG_TO_DCPORTAL;

	ret = qman_create_fq(0, flags, fq);
	if (unlikely(ret != 0)) {
		ODP_ERR("qman_create_fq failed in %s\n", __func__);
		return ret;
	}

	flags = QMAN_INITFQ_FLAG_SCHED;
	fq_opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_CONTEXTA;

	fq_opts.we_mask |= QM_INITFQ_WE_CONTEXTB;
	qm_fqd_context_a_set64(&fq_opts.fqd, ctxt_a_addr);
	fq_opts.fqd.context_b = ctx_b;
	fq_opts.fqd.dest.channel = qm_channel_caam;
	fq_opts.fqd.dest.wq = 0;

	ret = qman_init_fq(fq, flags, &fq_opts);
	if (unlikely(ret != 0)) {
		teardown_fq(fq);
		ODP_ERR("qman_init_fq failed in %s\n", __func__);
		return ret;
	}

	fq->cb.ern = ipsec_ern_cb;

	return ret;
}

static inline void build_proto_fd(odp_packet_t pkt, struct qm_fd *fd)
{
	uint32_t	len, l3_offset, shift;
	void		*in_data, *out_data;
	struct		qm_sg_entry *sg; /* input & output */
	odp_buffer_hdr_t	*in_hdr;

	in_hdr = (odp_buffer_hdr_t *)(odp_packet_hdr(pkt));

	sg = (struct qm_sg_entry *)((void *)in_hdr + ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(odp_packet_hdr_t)));
	memset(sg, 0, 2*sizeof(struct qm_sg_entry));

	l3_offset = odp_packet_l3_offset(pkt);
	len = odp_packet_len(pkt);

	/* Input SG frame */
	in_data = odp_packet_l3_ptr(pkt, NULL);
	qm_sg_entry_set64(&sg[1], __dma_mem_vtop(in_data));
	sg[1].length = len - l3_offset;
	sg[1].final = 1;

	/* Output SG frame */
	shift = MAX_IV_LEN + ODPH_IPV4HDR_LEN + ODPH_ESPHDR_LEN;
	out_data = in_data - shift;
	qm_sg_entry_set64(&sg[0], __dma_mem_vtop(out_data));
	sg[0].length = odp_packet_buf_len(pkt) - l3_offset;

	/* prepare fd  */
	qm_fd_addr_set64(fd, __dma_mem_vtop(sg));
	fd->_format2 = qm_fd_compound;
	fd->cong_weight = 0;
	fd->cmd = 0;

	/* Convert cpu to hw format */
	cpu_to_hw_sg(&sg[0]);
	cpu_to_hw_sg(&sg[1]);
}

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
		return DPAA1_FAILURE;

	/* Initialize ipsec capability structure */
	memset(capa, 0, sizeof(odp_ipsec_capability_t));

	capa->max_num_sa = ODP_CONFIG_IPSEC_SA;
	capa->op_mode_sync = 0;
	capa->op_mode_async = ODP_IPSEC_OP_MODE_ASYNC_PREF;
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

	return DPAA1_SUCCESS;
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
		return DPAA1_FAILURE;

	if (config->op_mode == ODP_IPSEC_OP_MODE_SYNC) {
		ODP_ERR("IPsec sync mode not supported\n");
		return DPAA1_FAILURE;
	}

	ODP_DBG("IPsec init ... ");
	shm = odp_shm_reserve("odp_ipsec_sa",
				sizeof(ipsec_sa_table_t),
				sizeof(ipsec_sa_entry_t),
				ODP_SHM_SW_ONLY);
	ipsec_sa_tbl = odp_shm_addr(shm);
	if (ipsec_sa_tbl == NULL) {
		ODP_ERR("Unable to reserve memory for IPSEC SA table\n");
		return DPAA1_FAILURE;
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
		return DPAA1_FAILURE;
	}

	/*Inialize Locks*/
	for (i = 0; i < bucket_count; i++) {
		bucket = &insa_hash_table[i];
		SLOCK_INIT(&bucket->lock);
	}

	memset(insa_hash_table, 0, bucket_count * sizeof(sa_bucket_t));

	SLOCK_INIT(&lock);

	return DPAA1_SUCCESS;
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

static int dpaa1_ipsec_init(ipsec_sa_entry_t *sa, odp_ipsec_sa_param_t *param)
{
	struct sec_descriptor_t		*prehdr_desc;
	uint32_t			*shared_desc;
	struct alginfo		alginfo_c, alginfo_a;
	uint32_t			caam_alg_c, caam_alg_a;
	int				desc_len;

#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
	odp_bool_t swap = FALSE;
#else
	odp_bool_t swap = TRUE;
#endif
	odp_bool_t ps = TRUE;

	prehdr_desc = __dma_mem_memalign(L1_CACHE_BYTES,
					 sizeof(*prehdr_desc));

	if (unlikely(!prehdr_desc)) {
		ODP_ERR("error: %s: dma_mem_memalign preheader\n", __func__);
		return DPAA1_FAILURE;
	}

	memset(prehdr_desc, 0, sizeof(struct sec_descriptor_t));

	shared_desc = (typeof(shared_desc))&prehdr_desc->descbuf;

	switch (param->crypto.cipher_alg) {
	
	case ODP_CIPHER_ALG_AES128_CBC:
		caam_alg_c = OP_PCL_IPSEC_AES_CBC;
		break;
	case ODP_CIPHER_ALG_3DES_CBC:
		caam_alg_c = OP_PCL_IPSEC_3DES;
		break;
	case ODP_CIPHER_ALG_NULL:
		caam_alg_c = OP_PCL_IPSEC_NULL;
		break;
	default:
		ODP_ERR("Non supoorted cipher algo: Setting to NULL cipher\n");
		caam_alg_c = OP_PCL_IPSEC_NULL;
	}

	switch (param->crypto.auth_alg) {

	case ODP_AUTH_ALG_SHA1_96:
		caam_alg_a = OP_PCL_IPSEC_HMAC_SHA1_96;
		break;
	case ODP_AUTH_ALG_SHA1_160:
		caam_alg_a = OP_PCL_IPSEC_HMAC_SHA1_160;
		break;
	case ODP_AUTH_ALG_SHA256_128:
		caam_alg_a = OP_PCL_IPSEC_HMAC_SHA2_256_128;
		break;
	case ODP_AUTH_ALG_MD5_96:
		caam_alg_a = OP_PCL_IPSEC_HMAC_MD5_96;
		break;
	case ODP_AUTH_ALG_NULL:
		caam_alg_a = OP_PCL_IPSEC_HMAC_NULL;
		break;
	default:
		ODP_ERR("Non supoorted auth algo: Setting to NULL auth\n");
		caam_alg_a = OP_PCL_IPSEC_HMAC_NULL;
	}

	alginfo_a.algtype = caam_alg_a;
	alginfo_a.key = (uintptr_t)(sa->auth_key);
	alginfo_a.keylen = param->crypto.auth_key.length;
	alginfo_a.key_enc_flags = 0;
	alginfo_a.key_type = RTA_DATA_IMM;
	alginfo_a.algmode = OP_ALG_AAI_HMAC;

	alginfo_c.algtype = caam_alg_c;
	alginfo_c.key = (uintptr_t)(sa->cipher_key);
	alginfo_c.keylen = param->crypto.cipher_key.length;
	alginfo_c.key_enc_flags = 0;
	alginfo_c.key_type = RTA_DATA_IMM;
	alginfo_c.algmode = OP_ALG_AAI_CBC;

	if (param->dir == ODP_IPSEC_DIR_OUTBOUND) {
		struct ipsec_encap_pdb *pdb;
		odph_ipv4hdr_t *ip4_hdr;

		ip4_hdr = (odph_ipv4hdr_t *)malloc(sizeof(odph_ipv4hdr_t));
		ip4_hdr->ver_ihl = (ODPH_IPV4 << 4) | ODPH_IPV4HDR_IHL_MIN;
		ip4_hdr->tot_len = odp_cpu_to_be_16(sizeof(odph_ipv4hdr_t));
		ip4_hdr->tos = param->tunnel.ipv4.dscp;
		ip4_hdr->id = 0;
		ip4_hdr->frag_offset = 0;
		ip4_hdr->ttl = param->tunnel.ipv4.ttl;
		ip4_hdr->proto = ODPH_IPPROTO_ESP;
		ip4_hdr->src_addr = *(uint32_t *)param->tunnel.ipv4.src_addr;
		ip4_hdr->dst_addr = *(uint32_t *)param->tunnel.ipv4.dst_addr;
		ip4_hdr->chksum = 0;
		ip4_hdr->chksum = odph_chksum((uint16_t *)(void *)ip4_hdr, sizeof(odph_ipv4hdr_t));

		pdb = (struct ipsec_encap_pdb *)malloc(sizeof(struct ipsec_encap_pdb) + sizeof(struct iphdr));

		if (odp_unlikely(!pdb)) {
			ODP_ERR("Malloc failed for pdb\n");
			__dma_mem_free(prehdr_desc);
			return DPAA1_FAILURE;
		}

		memset(pdb, 0, sizeof(struct ipsec_encap_pdb) + sizeof(struct iphdr));

		/* Prepend IP Header to Output Frame */
		pdb->options = PDBOPTS_ESP_INCIPHDR;

		/* IP Header Length */
		pdb->ip_hdr_len = sizeof(odph_ipv4hdr_t);

		/* Next Header is IP */
		pdb->options |= (IPPROTO_IPIP << PDBNH_ESP_ENCAP_SHIFT) & PDBNH_ESP_ENCAP_MASK;

		/* Tunnel mode + IP header in PDB */
		pdb->options |= PDBOPTS_ESP_TUNNEL | PDBOPTS_ESP_IPHDRSRC;

		/* Outer Header */
		memcpy(&pdb->ip_hdr, ip4_hdr, pdb->ip_hdr_len);

		/* Copy TOS from inner IP header to the outer IP header */
		if (param->opt.copy_dscp)
			pdb->options |= PDBOPTS_ESP_DIFFSERV;

		/* Copy DF bit from inner IP header to the outer IP header */
		if (param->opt.copy_df)
			pdb->options |= PDBHMO_ESP_DFBIT;

		/* Decrement inner header TTL */
		if (param->opt.dec_ttl)
			pdb->options |= PDBHMO_ESP_ENCAP_DTTL;

		/* SPI */
		pdb->spi = param->spi;

		/* Sequence Number */
		pdb->seq_num = param->seq;

		/* Extended Sequence Number */
		if (param->opt.esn)
			pdb->options |= PDBOPTS_ESP_ESN;

		/* Checksum */
		pdb->options |= PDBOPTS_ESP_UPDATE_CSUM;

		/* IV comes from SEC internal random generator */
		pdb->options |= PDBOPTS_ESP_IVSRC;

		desc_len = cnstr_shdsc_ipsec_encap(shared_desc,
				ps, swap, pdb,
				&alginfo_c, &alginfo_a);

		if (desc_len < 0) {
			ODP_ERR("Shared descriptor generation\n");
			free(pdb);
			__dma_mem_free(prehdr_desc);
			return DPAA1_FAILURE;
		}
	} else {	/* Decode */
		struct ipsec_decap_pdb *pdb;

		pdb = (struct ipsec_decap_pdb *)malloc(sizeof(struct ipsec_decap_pdb));

		if (odp_unlikely(!pdb)) {
			ODP_ERR("Malloc failed for decap pdb\n");
			__dma_mem_free(prehdr_desc);
			return DPAA1_FAILURE;
		}

		memset(pdb, 0, sizeof(struct ipsec_decap_pdb));

		/* IP Header Length */
		pdb->options = ((uint32_t)sizeof(odph_ipv4hdr_t) <<
			PDBHDRLEN_ESP_DECAP_SHIFT) & PDBHDRLEN_MASK;

		pdb->options |= PDBOPTS_ESP_TUNNEL;

		/* Remove outer header */
		pdb->options |= PDBOPTS_ESP_OUTFMT;

		/* Copy TOS from outer IP header to the inner IP header */
		if (param->opt.copy_dscp)
			pdb->options |= PDBHMO_ESP_DIFFSERV;

		/* Decrement inner header TTL */
		if (param->opt.dec_ttl)
			pdb->options |= PDBHMO_ESP_DECAP_DTTL;

		/* Anti-replay window size */
		switch (param->antireplay_ws) {
			case ODP_IPSEC_AR_WS_32:
				pdb->options |= PDBOPTS_ESP_ARS32;
				break;
			case ODP_IPSEC_AR_WS_64:
				pdb->options |= PDBOPTS_ESP_ARS64;
				break;
			case ODP_IPSEC_AR_WS_128:
				pdb->options |= PDBOPTS_ESP_ARS128;
				break;
			default:
				/*pdb.options |= PDBOPTS_ESP_ARSNONE;*/
				break;
		}

		/* Extended Sequence Number */
		if (param->opt.esn)
			pdb->options |= PDBOPTS_ESP_ESN;

		/* Checksum */
		pdb->options |= PDBOPTS_ESP_VERIFY_CSUM;

		desc_len = cnstr_shdsc_ipsec_decap(shared_desc,
				ps, swap, pdb,
				&alginfo_c, &alginfo_a);
		if (desc_len < 0) {
			ODP_ERR("Shared descriptor generation\n");
			free(pdb);
			__dma_mem_free(prehdr_desc);
			return DPAA1_FAILURE;
		}
	}

	prehdr_desc->prehdr.hi.field.idlen = desc_len;
	prehdr_desc->prehdr.lo.field.offset = CAAM_BURST_NUM_DEFAULT;
	/* Harcoding buffer pool id and buff size */
	prehdr_desc->prehdr.lo.field.pool_id = ODP_POOL_ID;
	prehdr_desc->prehdr.lo.field.pool_buffer_size = (uint16_t)ODP_POOL_BUF_SIZE;
	prehdr_desc->prehdr.hi.word = odp_cpu_to_be_32(prehdr_desc->prehdr.hi.word);
	prehdr_desc->prehdr.lo.word = odp_cpu_to_be_32(prehdr_desc->prehdr.lo.word);
	sa->context = prehdr_desc;

	return DPAA1_SUCCESS;
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
	queue_entry_t *out_qentry;
	uint32_t i, out_fqid;
	uint64_t hash;

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

	for (i = 0; i < ODP_CONFIG_IPSEC_SA; i++) {
		sa = &ipsec_sa_tbl->sa[i];
		if (sa->status != SA_STATUS_FREE)
			continue;
		SLOCK(&lock);
		sa->status = SA_STATUS_INUSE;
		SUNLOCK(&lock);
		break;
	}

	if (ODP_CONFIG_IPSEC_SA == i) {
		ODP_ERR("NO free SA entry \n");
		return ODP_IPSEC_SA_INVALID;
	}

	memcpy(&sa_param, param, sizeof(odp_ipsec_sa_param_t));

	sa->dest_queue = param->dest_queue;
	sa->user_context = param->context;
	sa->lookup_mode = param->lookup_mode;
	sa->dir = param->dir;

	if (param->crypto.cipher_alg != ODP_CIPHER_ALG_NULL
			&& param->crypto.auth_alg == ODP_AUTH_ALG_NULL) {
	
		dma_key1 = __dma_mem_memalign(ODP_CACHE_LINE_SIZE, param->crypto.cipher_key.length);
		if (!dma_key1) {
			ODP_ERR("DMA_MEM_ALIGN failed");
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

		dma_key2 = __dma_mem_memalign(ODP_CACHE_LINE_SIZE, param->crypto.cipher_key.length);
		if (!dma_key2) {
			ODP_ERR("DMA_MEM_ALIGN failed");
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
		dma_key1 = __dma_mem_memalign(ODP_CACHE_LINE_SIZE, param->crypto.cipher_key.length);
		if (!dma_key1) {
			ODP_ERR("DMA_MEM_ALIGN failed");
			goto key_fail;
		}

		memcpy(dma_key1, param->crypto.cipher_key.data,
				param->crypto.cipher_key.length);

		dma_key2 = __dma_mem_memalign(ODP_CACHE_LINE_SIZE, param->crypto.cipher_key.length);
		if (!dma_key2) {
			ODP_ERR("DMA_MEM_ALIGN failed");
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

	if (dpaa1_ipsec_init(sa, &sa_param) == DPAA1_FAILURE) {
		ODP_ERR("dpaa2_sec_proto_init() failed");
		goto config_fail;
	}

	/* Sec output queue */
	out_qentry = queue_to_qentry(param->dest_queue);
	out_qentry->s.fq.cb.dqrr_ctx = dqrr_cb_ipsec;
	out_fqid = qman_fq_fqid(&out_qentry->s.fq);

	/* Sec input queue */
	if (create_sa_input_fq(&sa->sec_infq, __dma_mem_vtop(sa->context), out_fqid))
		goto input_queue_fail;

	if (param->dir == ODP_IPSEC_DIR_INBOUND
		&& param->lookup_mode == ODP_IPSEC_LOOKUP_IN_UNIQUE_SA) {
		hash = calculate_hash(sa->spi);
		sa_insert_in_bucket(sa, &insa_hash_table[hash & (bucket_count - 1)]);
	}

	return (odp_ipsec_sa_t)sa;

input_queue_fail:
	teardown_fq(&sa->sec_infq);
	ODP_DBG(" input_queue_fail\n");
config_fail:
	if (dma_key2)
		__dma_mem_free(dma_key2);
key2_fail:
	if (dma_key1)
		__dma_mem_free(dma_key1);
key_fail:
	sa->cipher_key = NULL;
	sa->auth_key = NULL;
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
	uint64_t hash;

	if (!sa_entry || sa == ODP_IPSEC_SA_INVALID) {
		ODP_ERR("Not a valid sa");
		return DPAA1_FAILURE;
	}

	if (sa_entry->lookup_mode == ODP_IPSEC_LOOKUP_IN_UNIQUE_SA) {
		hash = calculate_hash(sa_entry->spi);
		sa_delete_in_bucket(sa_entry, &insa_hash_table[hash & (bucket_count - 1)]);
	}

	teardown_fq(&sa_entry->sec_infq);
	__dma_mem_free(sa_entry->context);
	sa_entry->context = NULL;
	if (sa_entry->cipher_key)
		__dma_mem_free(sa_entry->cipher_key);
	if (sa_entry->auth_key)
		__dma_mem_free(sa_entry->auth_key);
	sa_entry->cipher_key = NULL;
	sa_entry->auth_key = NULL;

	SLOCK(&lock);
	sa_entry->status = SA_STATUS_FREE;
	SUNLOCK(&lock);

	return DPAA1_SUCCESS;

}

static inline ipsec_sa_entry_t *lookup_sa_entry(odp_packet_t pkt)
{
	uint32_t spi;
	uint64_t hash;

	spi = *(uint32_t *)odp_packet_l4_ptr(pkt, NULL);
	hash = calculate_hash(spi);
	return sa_lookup_in_bucket(spi, &insa_hash_table[hash & (bucket_count - 1)]);
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
	queue_entry_t *pkt_rx_qentry = NULL;
	int ret;
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
		return DPAA1_FAILURE;
	}
	for (i = 0; i < num_pkt; i++) {
		odp_buffer_hdr_t *in_bufhdr;
		struct qman_fq sec_infq;
		struct qm_fd fd;

		memset(&fd, 0, sizeof(struct qm_fd));
		in_bufhdr = (odp_buffer_hdr_t *)(odp_packet_hdr(input->pkt[i]));
		/* Set buf event type */
		in_bufhdr->event_type = ODP_EVENT_IPSEC_RESULT;

		if (lookup) {
			ipsec_sa_entry_t *sa = lookup_sa_entry(input->pkt[i]);
			if (!sa) {
				ODP_ERR("SA NOT FOUND\n");
				return DPAA1_FAILURE;
			}
			sec_infq = sa->sec_infq;
			/* Set SA info in buf hdr */
			in_bufhdr->drv_priv_cnxt = (void *)sa;
		} else {
			/* Set SA info in buf hdr */
			in_bufhdr->drv_priv_cnxt = (void *)psa[j];
			sec_infq = psa[j]->sec_infq;
		}

		build_proto_fd(input->pkt[i], &fd);

		/* get pkt rx queue for params check in enq */
		odp_queue_t pkt_rx_queue = in_bufhdr->inq;
		pkt_rx_qentry = queue_to_qentry(pkt_rx_queue);

		ret = queue_enqueue_tx_fq(&sec_infq, &fd, in_bufhdr, pkt_rx_qentry);
		if (odp_likely(!ret))
			count++;
		else
			ODP_ERR("Err: Packet not enqueued to sec fq\n");
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
	uint32_t num_sa = 0, num_pkt = 0, i, j = 0, count = 0, inc = 0;
	queue_entry_t *pkt_rx_qentry = NULL;
	int ret;

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
		return DPAA1_FAILURE;
	}

	for (i = 0; i < num_pkt; i++) {
		struct qm_fd fd;
		odp_buffer_hdr_t *in_bufhdr;

		memset(&fd, 0, sizeof(struct qm_fd));

		/* get pkt rx queue for params check in enq */
		in_bufhdr = (odp_buffer_hdr_t *)(odp_packet_hdr(input->pkt[i]));
		odp_queue_t pkt_rx_queue = in_bufhdr->inq;
		pkt_rx_qentry = queue_to_qentry(pkt_rx_queue);

		build_proto_fd(input->pkt[i], &fd);

		/* Set SA info in buf hdr */
		in_bufhdr->drv_priv_cnxt = (void *)sa[j];

		/* Set buf event type */
		in_bufhdr->event_type = ODP_EVENT_IPSEC_RESULT;

		ret = queue_enqueue_tx_fq(&sa[j]->sec_infq, &fd, in_bufhdr, pkt_rx_qentry);
		if (odp_likely(!ret))
			count++;
		else
			ODP_ERR("Err: Packet not enqueued to sec fq\n");
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
	odp_buffer_hdr_t *bufhdr;
	odp_buffer_t buf;
	buf = odp_buffer_from_event(event);
	bufhdr = odp_buf_to_hdr(buf);

	bufhdr->event_type = ODP_EVENT_PACKET;
	if (result) {
		if (odp_unlikely(bufhdr->drv_priv_resv)) {
			ODP_ERR("SEC returned Error - %x\n", bufhdr->drv_priv_resv);
			result->res->status.all = bufhdr->drv_priv_resv;
			return DPAA1_FAILURE;
		} else
			result->res->status.all = ODP_IPSEC_OK;

		*(result->pkt) = odp_packet_from_event(event);
		result->num_pkt = 1;
		result->res->num_out = 1;
		result->res->sa = (odp_ipsec_sa_t)(bufhdr->drv_priv_cnxt);
		return result->num_pkt;
	} else {
		if (odp_unlikely(bufhdr->drv_priv_resv)) {
			ODP_ERR("SEC returned Error - %x\n", bufhdr->drv_priv_resv);
			return DPAA1_FAILURE;
		}
		return 1;
	}

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
	return DPAA1_FAILURE;
}

/**
 * Inbound synchronous IPSEC operation
 */
int odp_ipsec_in(const odp_ipsec_op_param_t *input ODP_UNUSED,
		 odp_ipsec_op_result_t *output ODP_UNUSED)
{
	/* Not supported */
	ODP_UNIMPLEMENTED();
	return DPAA1_FAILURE;
}

/**
 * Outbound synchronous IPSEC operation
 */
int odp_ipsec_out(const odp_ipsec_op_param_t *input ODP_UNUSED,
		  odp_ipsec_op_result_t *output ODP_UNUSED)
{
	/* Not supported */
	ODP_UNIMPLEMENTED();
	return DPAA1_FAILURE;
}
