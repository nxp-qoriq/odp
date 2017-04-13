/* Copyright (c) 2014, Freescale Semiconductor Inc.
 * Copyright 2016-2017 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp/api/crypto.h>
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
#include <odp_debug_internal.h>
#include <odp/api/spinlock.h>
#define LOCK(a)      odp_spinlock_lock(a)
#define UNLOCK(a)    odp_spinlock_unlock(a)
#define LOCK_INIT(a) odp_spinlock_init(a)

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

enum rta_sec_era rta_sec_era;

typedef struct crypto_ses_table_t {
	crypto_ses_entry_t ses[ODP_CONFIG_CRYPTO_SES];
} crypto_ses_table_t;

static crypto_ses_table_t *crypto_ses_tbl;

static odp_spinlock_t lock ODP_ALIGNED_CACHE;

static int rng_dev_fd = -1;

static dma_addr_t zero_icv_p;
static void *zero_icv_v;


crypto_ses_entry_t *get_ses_entry(uint32_t id)
{
	return &crypto_ses_tbl->ses[id];
}

uint32_t get_sesid(crypto_ses_entry_t *entry)
{
	return (entry - &crypto_ses_tbl->ses[0]) + 1;
}


/*
 * ODP cipher alg to CAAM constant
 * */
static inline uint32_t caam_cipher_alg(odp_cipher_alg_t odp_alg)
{
	switch (odp_alg) {
	case ODP_CIPHER_ALG_NULL:
		return 0;
	case ODP_CIPHER_ALG_DES:
		return OP_ALG_ALGSEL_DES;
	case ODP_CIPHER_ALG_3DES_CBC:
		return OP_ALG_ALGSEL_3DES;
	case ODP_CIPHER_ALG_AES128_CBC:
		return OP_ALG_ALGSEL_AES;
	default:
		return 0;
	}
};

/*
 * ODP auth alg to CAAM constant
 * */
static inline uint32_t caam_auth_alg(odp_auth_alg_t odp_alg)
{
	switch (odp_alg) {
	case ODP_AUTH_ALG_NULL:
		return 0;
	case ODP_AUTH_ALG_MD5_96:
		return OP_ALG_ALGSEL_MD5;
	case ODP_AUTH_ALG_SHA1_96:
	case ODP_AUTH_ALG_SHA1_160:
		return OP_ALG_ALGSEL_SHA1;
	case ODP_AUTH_ALG_SHA256_128:
		return OP_ALG_ALGSEL_SHA224;
#if 0
	case ODP_AUTH_ALG_SHA384_192:
		return OP_ALG_ALGSEL_SHA384;
	case ODP_AUTH_ALG_SHA512_256:
		return OP_ALG_ALGSEL_SHA512;
#endif
	default:
		return 0;
	}
}

/*
 * Errno codes to crypto status values
 * */
static inline odp_crypto_ses_create_err_t err_to_status(int err)
{
	odp_crypto_ses_create_err_t status;
	switch (err) {
	case -ENOMEM:
		status = ODP_CRYPTO_SES_CREATE_ERR_ENOMEM;
		break;
	case -ENOTSUP:
		status = ODP_CRYPTO_SES_CREATE_ERR_ENOTSUP;
		break;
	default:
		status = ODP_CRYPTO_SES_CREATE_ERR_EUNSPEC;
		break;
	};
	return status;
};

/*
 * ICV length
 * */
static inline unsigned int icv_len(odp_auth_alg_t auth_alg)
{
	unsigned int icv_len = 0;

	switch (auth_alg) {
	case ODP_AUTH_ALG_MD5_96:
		icv_len = 16;
		break;
	case ODP_AUTH_ALG_SHA1_96:
		icv_len = 20;
		break;
	case ODP_AUTH_ALG_SHA256_128:
		icv_len = 32;
		break;
	default:
		icv_len = 0;
	}
	return icv_len;
}

/*
 * ICV truncation length for auth alg
 * */
static inline unsigned int icv_trunc_len(odp_auth_alg_t auth_alg)
{
	unsigned int icv_len = 0;

	switch (auth_alg) {
	case ODP_AUTH_ALG_MD5_96:
	case ODP_AUTH_ALG_SHA1_96:
	case ODP_AUTH_ALG_AES_CMAC_96:
		icv_len = 12;
		break;
	case ODP_AUTH_ALG_SHA1_160:
		icv_len = 20;
		break;
	case ODP_AUTH_ALG_SHA256_128:
		icv_len = 16;
		break;
#if 0
	case ODP_AUTH_ALG_SHA384_192:
		icv_len = 24;
		break;
	case ODP_AUTH_ALG_SHA512_256:
		icv_len = 32;
		break;
#endif
	default:
		icv_len = 0;
	};
	return icv_len;
}

#ifndef ODP_CRYPTO_ICV_HW_CHECK
static inline int check_icv_ah(odp_packet_t pkt, uint8_t *icv,
			       size_t icv_len, uint32_t *status)
{
	odph_ipv4hdr_t *ip_hdr = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	odph_ahhdr_t *ah_hdr = (odph_ipv4hdr_t *)(ip_hdr + 1);
	if (memcmp(ah_hdr->icv, icv, icv_len)) {
		ODP_DBG("ICV check failed !\n");
		/* copy computed ICV over received ICV */
		memcpy(ah_hdr->icv, icv, icv_len);
		/* set status */
		*status = 0x2000004A; /*TODO - fd status for ICV check failed */
	}
}
#endif

static inline int is_cipher_only(crypto_ses_entry_t *ses)
{
	return ((ses->s.cipher.cipher_alg != ODP_CIPHER_ALG_NULL) &&
		(ses->s.auth.auth_alg == ODP_AUTH_ALG_NULL));
}

static inline int is_auth_only(crypto_ses_entry_t *ses)
{
	return ((ses->s.cipher.cipher_alg == ODP_CIPHER_ALG_NULL) &&
		(ses->s.auth.auth_alg != ODP_AUTH_ALG_NULL));
}

static inline int is_combined(crypto_ses_entry_t *ses)
{
	return ((ses->s.cipher.cipher_alg != ODP_CIPHER_ALG_NULL) &&
		(ses->s.auth.auth_alg != ODP_AUTH_ALG_NULL));
}

static inline int is_encode(crypto_ses_entry_t *ses)
{
	return (ses->s.op == ODP_CRYPTO_OP_ENCODE);
}

static inline int is_decode(crypto_ses_entry_t *ses)
{
	return (ses->s.op == ODP_CRYPTO_OP_DECODE);
}


static enum qman_cb_dqrr_result
crypto_dqrr_cb_inp(struct qman_fq *fq,
		   const struct qm_dqrr_entry *dqrr,
		   uint64_t *user_context)
{
	assert(dqrr->stat & QM_DQRR_STAT_FD_VALID);
	/*
	if (!(dqrr->stat & QM_DQRR_STAT_FD_VALID))
		return qman_cb_dqrr_consume;
	*/
	queue_entry_t *qentry = (queue_entry_t *)container_of(fq,
						 struct queue_entry_s, fq);
	if (qentry->s.type == ODP_QUEUE_TYPE_SCHED)
		assert(!(dqrr->stat & QM_DQRR_STAT_UNSCHEDULED));
	else if (qentry->s.type == ODP_QUEUE_TYPE_PLAIN)
		assert(dqrr->stat & QM_DQRR_STAT_UNSCHEDULED);

	dma_addr_t addr = qm_fd_addr_get64(&(dqrr->fd));
	struct qm_sg_entry *sg = __dma_mem_ptov(addr);
	struct sg_priv *sgp = container_of(sg, struct sg_priv, sg);

	odp_buffer_t compl_ev = sgp->compl_ev;
	struct op_compl_event *ev = odp_buffer_addr(compl_ev);
	crypto_ses_entry_t *ses = sgp->ses;
	odp_buffer_hdr_t *out_bufhdr;

	ev->status = dqrr->fd.status;
	/*TODO - handle error */
	if (ev->status)
		ODP_DBG("crypto status %08x\n", ev->status);

	/* return output packet */
	ev->out_pkt = sgp->in_pkt;

	odp_queue_set_input(_odp_packet_to_buffer(ev->out_pkt),
			    ses->s.compl_queue);
	out_bufhdr = odp_buf_to_hdr(_odp_packet_to_buffer(ev->out_pkt));
	*user_context = (uint64_t)compl_ev;

	_odp_buffer_event_type_set(compl_ev, ODP_EVENT_CRYPTO_COMPL);

#ifndef ODP_CRYPTO_ICV_HW_CHECK
	if (is_auth_only(ses) && is_decode(ses))
		check_icv_ah(ev->out_pkt, sgp->icv,
			     icv_trunc_len(ses->s.auth.auth_alg),
			     &ev->status);
#endif
	if (qentry->s.type == ODP_QUEUE_TYPE_PLAIN) {
		/*qentry->s.buf_hdr = &(odp_packet_hdr(ev->out_pkt)->buf_hdr);*/
		qentry->s.buf_hdr = odp_buf_to_hdr(compl_ev);
		return qman_cb_dqrr_consume;
	}

	/* schedule completion event */
	/* DCA/ORP when output/input packets are enqueued/freed */
	out_bufhdr->sched_index = sched_local.index;
	if (qentry->s.param.sched.sync == ODP_SCHED_SYNC_ORDERED) {
		out_bufhdr->orp.seqnum = dqrr->seqnum;
		out_bufhdr->orp.flags = 0;
	}

	if (qentry->s.param.sched.sync == ODP_SCHED_SYNC_ATOMIC) {
		out_bufhdr->dqrr = dqrr;
		return qman_cb_dqrr_defer;
	}

	return qman_cb_dqrr_consume;
}

int odp_crypto_init_global(void)
{
	uint32_t i;
	odp_shm_t shm;

	ODP_DBG("Crypto init ... \n");
	shm = odp_shm_reserve("odp_crypto_ses",
				    sizeof(crypto_ses_table_t),
				    sizeof(crypto_ses_entry_t),
				    ODP_SHM_SW_ONLY);
	crypto_ses_tbl = odp_shm_addr(shm);
	if (crypto_ses_tbl == NULL)
		return -1;

	LOCK_INIT(&lock);

	memset(crypto_ses_tbl, 0, sizeof(crypto_ses_table_t));

	for (i = 0; i < ODP_CONFIG_CRYPTO_SES; i++) {
		/* init locks */
		crypto_ses_entry_t *ses = get_ses_entry(i);
		LOCK_INIT(&ses->s.lock);
		ses->s.handle = session_from_id(i);
	}

	/* Set CAAM era TODO - get it programatically */
	rta_set_sec_era(SEC_ERA);

	/*ODP_DBG("rta_sec_era = RTA_SEC_ERA_%d\n", rta_sec_era + 1);*/

	/* allocate zero_icv buffer */
	zero_icv_v = __dma_mem_memalign(L1_CACHE_BYTES, MAX_ICV_LEN);
	if (!zero_icv_v)
		return -1;
	zero_icv_p = __dma_mem_vtop(zero_icv_v);
	memset(zero_icv_v, 0, MAX_ICV_LEN);

	/* Open RNG device */
	rng_dev_fd = open(RNG_DEV, O_RDONLY);
	if (rng_dev_fd < 0)
		return -1;

	ODP_DBG("Done\n");

	return 0;
}

/* ERN callback for session input fq */
static void crypto_ern_cb(struct qman_portal *p __always_unused,
			  struct qman_fq *fq __always_unused,
			  const struct qm_mr_entry *msg __always_unused)
{
	crypto_ses_entry_t *ses = SESSION_FROM_FQ(fq);
	uint32_t ses_id = get_sesid(ses);
	odp_crypto_session_t ses_handle = session_from_id(ses_id);

	ODP_ERR("ODP crypto ses=%llu : fqid=0x%x rc=0x%x, seqnum=0x%x\n",
		ses_handle, fq->fqid, msg->ern.rc, msg->ern.seqnum);
}

static int create_ses_input_fq(struct qman_fq *fq, dma_addr_t ctxt_a_addr,
				uint32_t ctx_b)
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
		ODP_ERR("qman_init_fq failed in %s\n", __func__);
		return ret;
	}

	fq->cb.ern = crypto_ern_cb;

	return ret;
}

/*
 * Create session shared descriptor
 * @return 0 - success, -1 - algorithm combination not supported
 * */
static int create_ses_shdesc(crypto_ses_entry_t *ses)
{
	struct sec_descriptor_t *prehdr_desc;
	uint32_t *shared_desc = NULL;
	struct alginfo alginfo_c, alginfo_a;
	uint32_t caam_alg_c, caam_alg_a;
	odp_pool_info_t pool_info;
	pool_entry_t *pool_entry;
	int ret;

#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
	odp_bool_t swap = FALSE;
#else
	odp_bool_t swap = TRUE;
#endif
	/* On most QorIQ platforms this value is TRUE. It is FALSE on P1023,
	 * on most LS1xxx excepting LS1043 ... */
	odp_bool_t ps = TRUE;

	prehdr_desc = __dma_mem_memalign(L1_CACHE_BYTES,
					 sizeof(*prehdr_desc));

	if (unlikely(!prehdr_desc)) {
		ODP_ERR("error: %s: dma_mem_memalign preheader\n", __func__);
		return -ENOMEM;
	}

	ses->s.prehdr_desc = prehdr_desc;
	memset(prehdr_desc, 0, sizeof(struct sec_descriptor_t));
	shared_desc = (typeof(shared_desc)) &prehdr_desc->descbuf;

	pool_entry = odp_pool_to_entry(ses->s.output_pool);
	ses->s.prehdr_desc->prehdr.lo.field.pool_id = pool_entry->s.bpid;

	ret = odp_pool_info(ses->s.output_pool, &pool_info);
	if (ret) {
		ODP_ERR("error: %s: cannot get pool %"PRIu64" info\n", __func__,
			odp_pool_to_u64(ses->s.output_pool));
		return -EINVAL;
	}

	ses->s.prehdr_desc->prehdr.lo.field.pool_buffer_size =
			pool_info.params.buf.size;

	ses->s.prehdr_desc->prehdr.lo.field.offset = CAAM_BURST_NUM_DEFAULT;

	if (is_cipher_only(ses)) {
		caam_alg_c = caam_cipher_alg(ses->s.cipher.cipher_alg);
		if (!caam_alg_c)
			return -ENOTSUP;
		alginfo_c.key = (uintptr_t)(ses->s.cipher.key.data);
		alginfo_c.keylen = ses->s.cipher.key.length;
		alginfo_c.key_enc_flags = 0;

		alginfo_c.key_type = RTA_DATA_IMM;
		alginfo_c.algtype = caam_alg_c;
		alginfo_c.algmode = OP_ALG_AAI_CBC;

		ret = cnstr_shdsc_blkcipher(shared_desc, ps, swap,
				&alginfo_c,
				(ses->s.op == ODP_CRYPTO_OP_ENCODE) ?
				ses->s.cipher.iv : NULL,
				ses->s.cipher.iv_len,
				(ses->s.op == ODP_CRYPTO_OP_ENCODE) ?
				DIR_ENC : DIR_DEC);
		if (ret < 0)
			return ret;
		ses->s.prehdr_desc->prehdr.hi.field.idlen = ret;
		ses->s.prehdr_desc->prehdr.hi.word =
				odp_cpu_to_be_32(prehdr_desc->prehdr.hi.word);

		return 0;
	} else if (is_auth_only(ses)) {
		caam_alg_a = caam_auth_alg(ses->s.auth.auth_alg);
		if (!caam_alg_a)
			return -ENOTSUP;

		alginfo_a.algtype = caam_alg_a;
		alginfo_a.key = (uintptr_t)(ses->s.auth.key.data);
		alginfo_a.keylen = ses->s.auth.key.length;
		alginfo_a.key_enc_flags = 0;

		alginfo_a.key_type = RTA_DATA_IMM;

		/* ret is an error code or the length of the shared
		 * descriptor */
		ret = cnstr_shdsc_hmac(shared_desc, ps, swap,
				&alginfo_a,
				    (ses->s.op == ODP_CRYPTO_OP_DECODE),
				    icv_trunc_len(ses->s.auth.auth_alg));
		if (ret < 0)
			return ret;
		ses->s.prehdr_desc->prehdr.hi.field.idlen = ret;
		ses->s.prehdr_desc->prehdr.hi.word =
				odp_cpu_to_be_32(prehdr_desc->prehdr.hi.word);

		return 0;
	} else {
		caam_alg_c = caam_cipher_alg(ses->s.cipher.cipher_alg);
		caam_alg_a = caam_auth_alg(ses->s.auth.auth_alg);
		if (!caam_alg_c || !caam_alg_a)
			return -ENOTSUP;

		/* sizeof data which is ONLY authenticated */
		ses->s.auth_only_len  = sizeof(odph_ipv4hdr_t) +
					sizeof(odph_ahhdr_t) +
					icv_trunc_len(ses->s.auth.auth_alg) +
					sizeof(odph_esphdr_t) +
					ses->s.cipher.iv_len;
		alginfo_c.algtype = caam_alg_c;
		alginfo_c.key = (uintptr_t)(ses->s.cipher.key.data);
		alginfo_c.keylen = ses->s.cipher.key.length;
		alginfo_c.key_enc_flags = 0;

		alginfo_c.key_type = RTA_DATA_IMM;
		alginfo_c.algmode = OP_ALG_AAI_CBC;

		alginfo_a.algtype = caam_alg_a;
		alginfo_a.key = (uintptr_t)(ses->s.auth.key.data);
		alginfo_a.keylen = ses->s.auth.key.length;
		alginfo_a.key_enc_flags = 0;

		alginfo_a.key_type = RTA_DATA_IMM;
		ret = cnstr_shdsc_authenc(shared_desc, ps, swap,
					&alginfo_c, &alginfo_a,
					ses->s.cipher.iv_len,
					ses->s.auth_only_len,
					icv_trunc_len(ses->s.auth.auth_alg),
					(ses->s.op == ODP_CRYPTO_OP_ENCODE) ?
					DIR_ENC : DIR_DEC);
		if (ret < 0)
			return ret;

		ses->s.prehdr_desc->prehdr.hi.field.idlen = ret;
		ses->s.prehdr_desc->prehdr.hi.word =
				odp_cpu_to_be_32(prehdr_desc->prehdr.hi.word);

		return 0;
	}

	__dma_mem_free(ses->s.prehdr_desc);
	return -1;
}

static struct qm_sg_entry
*build_cbc_cipher_input(crypto_ses_entry_t *ses,
			odp_packet_t pkt,
			odp_crypto_data_range_t *range,
			uint8_t *iv, size_t ivlen)
{
	odp_buffer_hdr_t *hdr = (odp_buffer_hdr_t *)(odp_packet_hdr(pkt));
	/* use buffer tailroom to accommodate input S/G list */
	uint8_t *tail = hdr->addr[0] + hdr->size - ODP_CONFIG_PACKET_TAILROOM;

	/* IV comes first */
	struct cbc_cipher_in *in =  (struct cbc_cipher_in *)tail;
	memset(in, 0, sizeof(*in));

	dma_addr_t start_addr = __dma_mem_vtop(odp_packet_data(pkt)) +
				range->offset;
	/* TODO - check if IV & range are contiguous */
	if (iv)
		memcpy(in->iv, iv, ivlen);
	else
		memcpy(in->iv, ses->s.cipher.iv, ses->s.cipher.iv_len);

	qm_sg_entry_set64(&in->sg[0], __dma_mem_vtop(/*iv*/in->iv));
	in->sg[0].length = ivlen;

	cpu_to_hw_sg(&in->sg[0]);

	qm_sg_entry_set64(&in->sg[1], start_addr);
	in->sg[1].length = range->length;
	in->sg[1].final = 1;

	cpu_to_hw_sg(&in->sg[1]);

	return &in->sg[0];
}

static struct qm_sg_entry
*build_ah_icv_check_input(odp_packet_t pkt,
			  struct odp_crypto_op_params *params,
			  odp_auth_alg_t auth_alg)
{
	odp_buffer_hdr_t *hdr = (odp_buffer_hdr_t *)(odp_packet_hdr(pkt));

	/* use buffer tailroom to accomodate input S/G list */
	uint8_t *tail = hdr->addr[0] + hdr->size - ODP_CONFIG_PACKET_TAILROOM;

	struct ah_icv_chk_in *in = (struct ah_icv_chk_in *)tail;
	memset(in, 0, sizeof(*in));

	/* auth range start address */
	dma_addr_t start_addr = __dma_mem_vtop(odp_packet_data(pkt))
				+ params->auth_range.offset;

	uint32_t alen = 0;
	/* auth range segment before ICV */
	qm_sg_entry_set64(&in->sg[0], start_addr);
	in->sg[0].length = params->hash_result_offset -
			   params->auth_range.offset;
	alen += in->sg[0].length;

	cpu_to_hw_sg(&in->sg[0]);

	/* add zero_icv */
	qm_sg_entry_set64(&in->sg[1], zero_icv_p);
	in->sg[1].length = icv_trunc_len(auth_alg);
	alen += in->sg[1].length;

	cpu_to_hw_sg(&in->sg[1]);

	/* rest of auth range */
	qm_sg_entry_set64(&in->sg[2], start_addr + alen);
	in->sg[2].length = params->auth_range.length - alen;

#ifdef ODP_CRYPTO_ICV_HW_CHECK
	/* ICV start address */
	dma_addr_t hash_result_addr = __dma_mem_vtop(odp_packet_data(pkt))
				     + params->hash_result_offset;
	/* ICV */
	qm_sg_entry_set64(&in->sg[3], hash_result_addr);
	in->sg[3].length = icv_trunc_len(auth_alg);

	in->sg[3].final = 1;

	cpu_to_hw_sg(&in->sg[3]);

#else
	in->sg[2].final = 1;
#endif
	cpu_to_hw_sg(&in->sg[2]);

	return &in->sg[0];
}

static inline struct qm_sg_entry
*build_in_combined_encap(crypto_ses_entry_t *ses,
			 struct odp_crypto_op_params *params)
{
	odp_buffer_hdr_t *hdr = (odp_buffer_hdr_t *)(odp_packet_hdr(params->pkt));
	uint8_t *tail = hdr->addr[0] + hdr->size - ODP_CONFIG_PACKET_TAILROOM;
	struct authenc_encap_in *in = (struct authenc_encap_in *)tail;

	memset(in, 0, sizeof(*in));

	dma_addr_t start_addr = __dma_mem_vtop(odp_packet_data(params->pkt)) +
				params->auth_range.offset;
	/* IV */
	qm_sg_entry_set64(&in->sg[0], ses->s.cipher.iv_p);
	in->sg[0].length = ses->s.cipher.iv_len;

	cpu_to_hw_sg(&in->sg[0]);

	/* auth_range : auth only + cipher */
	qm_sg_entry_set64(&in->sg[1], start_addr);
	in->sg[1].length = params->auth_range.length;

	in->sg[1].final = 1;

	cpu_to_hw_sg(&in->sg[1]);

	return &in->sg[0];
}

static inline struct qm_sg_entry
*build_in_combined_decap(crypto_ses_entry_t *ses,
			 struct odp_crypto_op_params *params)
{
	odp_buffer_hdr_t *hdr = (odp_buffer_hdr_t *)(odp_packet_hdr(params->pkt));
	uint8_t *tail = hdr->addr[0] + hdr->size - ODP_CONFIG_PACKET_TAILROOM;
	struct authenc_decap_in *in = (struct authenc_decap_in *)tail;
	memset(in, 0, sizeof(*in));

	/* IV */
	qm_sg_entry_set64(&in->sg[0],
			  __dma_mem_vtop(params->override_iv_ptr));
	in->sg[0].length = ses->s.cipher.iv_len;

	cpu_to_hw_sg(&in->sg[0]);

	/* auth range start address */
	dma_addr_t start_addr = __dma_mem_vtop(odp_packet_data(params->pkt))
				+ params->auth_range.offset;
	/* ICV start address */
	dma_addr_t hash_result_addr = __dma_mem_vtop(odp_packet_data(params->pkt))
				     + params->hash_result_offset;
	/* auth range before ICV */
	uint32_t alen = 0;
	qm_sg_entry_set64(&in->sg[1], start_addr);
	in->sg[1].length = params->hash_result_offset -
			   params->auth_range.offset;
	alen += in->sg[1].length;

	cpu_to_hw_sg(&in->sg[1]);

	/* add zero_icv */
	qm_sg_entry_set64(&in->sg[2], zero_icv_p);
	in->sg[2].length = icv_trunc_len(ses->s.auth.auth_alg);
	alen += in->sg[2].length;

	cpu_to_hw_sg(&in->sg[2]);

	/* rest of auth range */
	qm_sg_entry_set64(&in->sg[3], start_addr + alen);
	in->sg[3].length = params->auth_range.length - alen;

#ifdef ODP_CRYPTO_ICV_HW_CHECK
	/* ICV */
	qm_sg_entry_set64(&in->sg[4], hash_result_addr);
	in->sg[4].length = icv_trunc_len(ses->s.auth.auth_alg);
	in->sg[4].final = 1;

	cpu_to_hw_sg(&in->sg[4]);

#else
	in->sg[3].final = 1;
#endif
	cpu_to_hw_sg(&in->sg[3]);

	return &in->sg[0];
}

static inline struct qm_sg_entry
*build_out_combined_decap(struct odp_crypto_op_params *params)
{
	odp_buffer_hdr_t *hdr = (odp_buffer_hdr_t *)(odp_packet_hdr(params->pkt));
	uint8_t *tail = hdr->addr[0] + hdr->size - ODP_CONFIG_PACKET_TAILROOM;
	struct authenc_decap_in *in = (struct authenc_decap_in *)tail;

	dma_addr_t cipher_start_addr = __dma_mem_vtop(odp_packet_data(params->pkt)) +
				       params->cipher_range.offset;
	/* decrypted */
	qm_sg_entry_set64(&in->sg[5], cipher_start_addr);
	in->sg[5].length = params->cipher_range.length;

	in->sg[5].final = 1;

	cpu_to_hw_sg(&in->sg[5]);

	return &in->sg[5];
}


static inline struct qm_sg_entry
*build_out_combined_encap(crypto_ses_entry_t *ses,
			  struct odp_crypto_op_params *params)
{
	odp_buffer_hdr_t *hdr = (odp_buffer_hdr_t *)(odp_packet_hdr(params->pkt));
	uint8_t *tail = hdr->addr[0] + hdr->size - ODP_CONFIG_PACKET_TAILROOM;
	struct authenc_encap_in *in = (struct authenc_encap_in *)tail;

	dma_addr_t cipher_start_addr = __dma_mem_vtop(odp_packet_data(params->pkt)) +
				       params->cipher_range.offset;
	dma_addr_t hash_start_addr = __dma_mem_vtop(odp_packet_data(params->pkt)) +
				     params->hash_result_offset;
	/* encrypted */
	qm_sg_entry_set64(&in->sg[2], cipher_start_addr);
	in->sg[2].length = params->cipher_range.length;

	cpu_to_hw_sg(&in->sg[2]);

	/* ICV */
	qm_sg_entry_set64(&in->sg[3], hash_start_addr);
	in->sg[3].length = icv_trunc_len(ses->s.auth.auth_alg);

	in->sg[3].final = 1;

	cpu_to_hw_sg(&in->sg[3]);

	return &in->sg[2];
}

static inline void build_in_single_decap(crypto_ses_entry_t *ses,
					 odp_crypto_data_range_t *range,
					 struct odp_crypto_op_params *params,
					 struct sg_priv *sgp)
{
	struct qm_sg_entry *in_sg = NULL;

	if (is_auth_only(ses)) {
		/*assert(odp_packet_inflag_ipsec_ah(params->pkt));*/
		in_sg = build_ah_icv_check_input(params->pkt,
						 params,
						 ses->s.auth.auth_alg);
		qm_sg_entry_set64(&sgp->sg[1], __dma_mem_vtop(in_sg));
		sgp->sg[1].extension = 1;
		sgp->sg[1].length = range->length;
#ifdef ODP_CRYPTO_ICV_HW_CHECK
		sgp->sg[1].length += icv_trunc_len(ses->s.auth.auth_alg);
#endif
	} else if (is_cipher_only(ses)) {
#ifdef ODP_CRYPTO_IV_FROM_PACKET
		odp_buffer_hdr_t *hdr;
		dma_addr_t start_addr;
		hdr = (odp_buffer_hdr_t *)(odp_packet_hdr(params->pkt));
		/* IV is just before the cipher range */
		start_addr = __dma_mem_vtop(odp_packet_data(params->pkt)) +
			     range->offset - ses->s.cipher.iv_len;

		qm_sg_entry_set64(&sgp->sg[1], start_addr);
		sgp->sg[1].length = range->length + ses->s.cipher.iv_len;
#else
		in_sg = build_cbc_cipher_input(ses, params->pkt, range,
					       params->override_iv_ptr,
					       ses->s.cipher.iv_len);
		qm_sg_entry_set64(&sgp->sg[1], __dma_mem_vtop(in_sg));
		sgp->sg[1].extension = 1;
		sgp->sg[1].length = range->length + ses->s.cipher.iv_len;
#endif
	}
	sgp->sg[1].final = 1;

	cpu_to_hw_sg(&sgp->sg[1]);
}

static inline void build_in_single_encap(crypto_ses_entry_t *ses,
					 odp_crypto_data_range_t *range,
					 struct odp_crypto_op_params *params,
					 struct sg_priv *sgp)
{
	if (is_cipher_only(ses) && !ses->s.cipher.iv) {
		struct qm_sg_entry *in_sg = NULL;
		in_sg = build_cbc_cipher_input(ses, params->pkt, range,
			params->override_iv_ptr,
			ses->s.cipher.iv_len);
		qm_sg_entry_set64(&sgp->sg[1], __dma_mem_vtop(in_sg));
		sgp->sg[1].extension = 1;
		sgp->sg[1].length = range->length + ses->s.cipher.iv_len;

		sgp->sg[1].final = 1;

		cpu_to_hw_sg(&sgp->sg[1]);

		return;
	}

	dma_addr_t start_addr = __dma_mem_vtop(odp_packet_data(params->pkt)) +
				range->offset;

	qm_sg_entry_set64(&sgp->sg[1], start_addr);
	sgp->sg[1].length = range->length;

	sgp->sg[1].final = 1;

	cpu_to_hw_sg(&sgp->sg[1]);
}

static inline void build_in_single_sg(crypto_ses_entry_t *ses,
				      odp_crypto_data_range_t *range,
				      struct odp_crypto_op_params *params,
				      struct sg_priv *sgp)
{
	if (is_encode(ses))
		build_in_single_encap(ses, range, params, sgp);
	else
		build_in_single_decap(ses, range, params, sgp);
}

static inline void build_in_combined_sg(crypto_ses_entry_t *ses,
				       struct odp_crypto_op_params *params,
				       struct sg_priv *sgp)
{
	struct qm_sg_entry *in_sg = NULL;
	uint32_t length;

	assert(is_combined(ses));
	if (is_encode(ses)) {
		in_sg = build_in_combined_encap(ses, params);
		length = params->auth_range.length +
			 ses->s.cipher.iv_len;
	} else {
		in_sg = build_in_combined_decap(ses, params);
		length = params->auth_range.length +
			 ses->s.cipher.iv_len +
			 icv_trunc_len(ses->s.auth.auth_alg);
	}

	qm_sg_entry_set64(&sgp->sg[1], __dma_mem_vtop(in_sg));
	sgp->sg[1].extension = 1;
	sgp->sg[1].length = length;

	sgp->sg[1].final = 1;

	cpu_to_hw_sg(&sgp->sg[1]);
}

static inline void build_out_single_encap(crypto_ses_entry_t *ses,
					  odp_crypto_data_range_t *range,
					  struct odp_crypto_op_params *params,
					  struct sg_priv *sgp)
{
	dma_addr_t start_addr = __dma_mem_vtop(odp_packet_data(params->out_pkt));

	if (is_cipher_only(ses)) {
		start_addr += range->offset;
		sgp->sg[0].length = range->length;
	} else if (is_auth_only(ses)) {
		start_addr += params->hash_result_offset;
		sgp->sg[0].length = icv_len(ses->s.auth.auth_alg);
	}
	qm_sg_entry_set64(&sgp->sg[0], start_addr);

	cpu_to_hw_sg(&sgp->sg[0]);
}

static inline void build_out_single_decap(crypto_ses_entry_t *ses,
					  odp_crypto_data_range_t *range,
					  struct odp_crypto_op_params *params,
					  struct sg_priv *sgp)
{
	dma_addr_t start_addr = 0;

	if (is_cipher_only(ses)) {
		start_addr = __dma_mem_vtop(odp_packet_data(params->out_pkt))
			     + range->offset;
		sgp->sg[0].length = range->length;
	} else if (is_auth_only(ses)) {
		/* computed ICV is placed in the job block */
		start_addr = __dma_mem_vtop(&sgp->icv);
		sgp->sg[0].length = icv_trunc_len(ses->s.auth.auth_alg);
	}
	qm_sg_entry_set64(&sgp->sg[0], start_addr);

	cpu_to_hw_sg(&sgp->sg[0]);
}

static inline void build_out_single_sg(crypto_ses_entry_t *ses,
				       odp_crypto_data_range_t *range,
				       struct odp_crypto_op_params *params,
				       struct sg_priv *sgp)
{
	if (is_encode(ses))
		build_out_single_encap(ses, range, params, sgp);
	else
		build_out_single_decap(ses, range, params, sgp);
}

static inline void
build_out_combined_sg(crypto_ses_entry_t *ses,
		      struct odp_crypto_op_params *params,
		      struct sg_priv *sgp)
{
	struct qm_sg_entry *in_sg = NULL;
	uint32_t length;

	if (is_encode(ses)) {
		in_sg = build_out_combined_encap(ses, params);
		length = params->cipher_range.length +
			 icv_trunc_len(ses->s.auth.auth_alg);
	} else {
		in_sg = build_out_combined_decap(params);
		length = params->cipher_range.length;
	}

	qm_sg_entry_set64(&sgp->sg[0], __dma_mem_vtop(in_sg));
	sgp->sg[0].length = length;
	sgp->sg[0].extension = 1;

	cpu_to_hw_sg(&sgp->sg[0]);
}

static inline void build_fd(struct odp_crypto_op_params *params,
							struct sg_priv *sgp)
{
	odp_crypto_data_range_t *range = NULL;
	crypto_ses_entry_t	*ses;

	ses = session_to_entry(params->session);

	if (is_auth_only(ses))
		range = &params->auth_range;
	else if (is_cipher_only(ses))
		range = &params->cipher_range;
	if (range) {
		build_in_single_sg(ses, range, params, sgp);
		build_out_single_sg(ses, range, params, sgp);
	} else {
		/* combined descriptor has a fixed auth_only_len
		 * param */
		assert(params->auth_range.length ==
			       params->cipher_range.length +
					ses->s.auth_only_len);
		build_in_combined_sg(ses, params, sgp);
		build_out_combined_sg(ses, params, sgp);
	}
}

static inline void chaid_to_err(uint32_t status,
				struct odp_crypto_compl_status *auth,
				struct odp_crypto_compl_status *cipher ODP_UNUSED)
{
	/* CHAID bits */
	switch ((status & 0x000000f0) >> 4) {
	case 4: /* MD5, SHA-1, SH-224, SHA-256, SHA-384, SHA-512 */
		/* ERRID bits */
		if ((status & 0x0000000f) == 0xA) /* ICV check failed */
			auth->alg_err = ODP_CRYPTO_ALG_ERR_ICV_CHECK;
		break;
	}
}

static inline void
get_op_compl_status(struct op_compl_event *ev,
		    struct odp_crypto_compl_status *auth,
		    struct odp_crypto_compl_status *cipher)
{
	auth->alg_err = ODP_CRYPTO_ALG_ERR_NONE;
	auth->hw_err = ODP_CRYPTO_HW_ERR_NONE;
	cipher->alg_err = ODP_CRYPTO_ALG_ERR_NONE;
	cipher->hw_err = ODP_CRYPTO_HW_ERR_NONE;


	/*bits 0 - 3*/
	switch ((ev->status & 0xf0000000)>>28) {
	case 0:
		break;
	case 2:
		/* bits */
		chaid_to_err(ev->status, auth, cipher);
		break;
	default:
		auth->alg_err = ODP_CRYPTO_ALG_ERR_UNSPEC;
		auth->hw_err = ODP_CRYPTO_HW_ERR_UNSPEC;
		cipher->alg_err = ODP_CRYPTO_ALG_ERR_UNSPEC;
		cipher->hw_err = ODP_CRYPTO_HW_ERR_UNSPEC;
	}
}


static inline void
set_op_compl_ctx(odp_buffer_t completion_event, void *ctx)
{
	struct op_compl_event *ev = odp_buffer_addr(completion_event);
	ev->ctx = ctx;
}

static inline void *
get_op_compl_ctx(odp_buffer_t completion_event)
{
	struct op_compl_event *ev = odp_buffer_addr(completion_event);
	return ev->ctx;
}

int
odp_crypto_session_create(odp_crypto_session_params_t *params,
			  odp_crypto_session_t *session,
			  odp_crypto_ses_create_err_t *status)
{
	uint32_t i;
	int ret = -1;
	crypto_ses_entry_t *ses;
	odp_crypto_session_t handle = ODP_CRYPTO_SESSION_INVALID;
	uint32_t out_fqid;
	queue_entry_t *out_qentry;

	for (i = 0; i < ODP_CONFIG_CRYPTO_SES; i++) {
		ses = &crypto_ses_tbl->ses[i];
		if (ses->s.status != SES_STATUS_FREE)
			continue;

		LOCK(&ses->s.lock);

		if (ses->s.status == SES_STATUS_FREE) {
			handle = ses->s.handle;
			ses->s.status = SES_STATUS_INIT;
			UNLOCK(&ses->s.lock);
			break;
		}
	}

	if (handle == ODP_CRYPTO_SESSION_INVALID) {
		ret = -ENOMEM;
		goto ses_alloc_fail;
	}
	/* Fill & check session params */
	/* Crypto operation FD build function */
	ses->s.build_compound_fd = build_fd;
	ses->s.op = params->op;
	ses->s.cipher.cipher_alg = params->cipher_alg;
	ses->s.cipher.key = params->cipher_key;
	assert(params->iv.length <= IV_MAX_LEN);
	ses->s.cipher.iv = NULL;
	if (params->iv.data) {
		ses->s.cipher.iv =
				__dma_mem_memalign(L1_CACHE_BYTES, IV_MAX_LEN);
		if (!ses->s.cipher.iv)
			goto ses_shdesc_fail;
		ses->s.cipher.iv_p = __dma_mem_vtop(ses->s.cipher.iv);
		memcpy(ses->s.cipher.iv, params->iv.data, params->iv.length);
	}

	ses->s.cipher.iv_len = params->iv.length;
	ses->s.auth.auth_alg = params->auth_alg;
	ses->s.auth.key = params->auth_key;
	ses->s.op_mode = params->pref_mode;
	ses->s.output_pool = params->output_pool;
	ses->s.compl_queue = params->compl_queue;


	/* queue creation code locking */
	LOCK(&lock);

	/* create shared descriptor */
	ret = create_ses_shdesc(ses);
	if (ret < 0)
		goto ses_shdesc_fail;

	/* check completion queue */
	if (ses->s.compl_queue == ODP_QUEUE_INVALID)
		goto compl_queue_fail;
	out_qentry = queue_to_qentry(ses->s.compl_queue);
	if (!out_qentry)
		goto compl_queue_fail;

	/* set completion callback */
	out_qentry->s.fq.cb.dqrr_ctx = crypto_dqrr_cb_inp;

	/* create session input fq */
	out_fqid = qman_fq_fqid(&out_qentry->s.fq);
	ret = create_ses_input_fq(&ses->s.input_fq,
		__dma_mem_vtop(ses->s.prehdr_desc), out_fqid);
	if (ret)
		goto input_queue_fail;

	UNLOCK(&lock);

	*session = handle;
	*status = ODP_CRYPTO_SES_CREATE_ERR_NONE;
	return 0;

input_queue_fail:
	/* TODO : teardown_fq(compl_queue)*/
	ODP_DBG(" input_queue_fail\n");
compl_queue_fail:
	ODP_DBG(" compl_queue_fail\n");
ses_shdesc_fail:
	ODP_DBG(" ses_shdesc_fail\n");
	ses->s.status = SES_STATUS_FREE;
	UNLOCK(&lock);
ses_alloc_fail:
	ODP_DBG(" ses_alloc_fail\n");
	*status = err_to_status(ret);
	*session = ODP_CRYPTO_SESSION_INVALID;
	return -1;
}

int32_t
odp_random_data(uint8_t *buf, int32_t len, odp_bool_t use_entropy ODP_UNUSED)
{
	int32_t rlen;
	(void)use_entropy;

	rlen = read(rng_dev_fd, buf, len);
	if (rlen != len)
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
	odp_buffer_t buf;
	odp_event_t event;

	event = odp_crypto_compl_to_event(completion_event);
	buf = odp_buffer_from_event(event);
	struct op_compl_event *ev = odp_buffer_addr(buf);
	result->pkt = _odp_packet_from_buffer(buf);
	result->ctx = ev->ctx;
	get_op_compl_status(ev, &result->cipher_status, &result->auth_status);

	result->ok =
		(result->cipher_status.alg_err == ODP_CRYPTO_ALG_ERR_NONE) &&
		(result->auth_status.alg_err == ODP_CRYPTO_ALG_ERR_NONE) &&
		(result->auth_status.hw_err == ODP_CRYPTO_HW_ERR_NONE) &&
		(result->cipher_status.hw_err == ODP_CRYPTO_HW_ERR_NONE);
}

void
odp_crypto_compl_free(odp_crypto_compl_t completion_event ODP_UNUSED)
{
	odp_buffer_t buf;
	odp_event_t event;

	event = odp_crypto_compl_to_event(completion_event);
	buf = odp_buffer_from_event(event);

	_odp_buffer_event_type_set(buf, ODP_EVENT_PACKET);
}

int odp_crypto_session_destroy(odp_crypto_session_t session)
{
	crypto_ses_entry_t *ses_entry;
	queue_entry_t *qentry;
	struct qm_mcr_queryfq_np np;
	enum qman_fq_state state;
	uint32_t flags;
	int ret;


	ses_entry = session_to_entry(session);
	if (!ses_entry)
		return -1;

	LOCK(&ses_entry->s.lock);

	if (ses_entry->s.cipher.iv)
		__dma_mem_free(ses_entry->s.cipher.iv);

	if (ses_entry->s.prehdr_desc)
		__dma_mem_free(ses_entry->s.prehdr_desc);

	ses_entry->s.status = SES_STATUS_FREE;

	qentry = queue_to_qentry(ses_entry->s.compl_queue);

	if (qentry->s.status == QUEUE_STATUS_FREE) {
		UNLOCK(&ses_entry->s.lock);
		return 0;
	}

	/*
	 * Drain the completion queue.
	 * It's user responsibility to destroy this queue that was created
	 * outside crypto
	 */
	qman_query_fq_np(&qentry->s.fq, &np);
	if (np.frm_cnt) {
		/* FQ isn't empty, drain it */
		ret = qman_volatile_dequeue(&qentry->s.fq, 0,
			QM_VDQCR_NUMFRAMES_TILLEMPTY);
		if (ret) {
			UNLOCK(&ses_entry->s.lock);
			return -1;
		}
		/* Poll for completion */
		do {
			qman_poll();
			qman_fq_state(&qentry->s.fq, &state, &flags);
		} while (flags & QMAN_FQ_STATE_VDQCR);
	}
	qentry->s.buf_hdr = NULL;
	UNLOCK(&ses_entry->s.lock);
	return 0;
}

int odp_crypto_operation(struct odp_crypto_op_params *params,
			 odp_bool_t *posted,
			 odp_crypto_op_result_t *result ODP_UNUSED)
{
	struct qm_fd		fd;
	crypto_ses_entry_t	*ses;
	struct sg_priv		*sgp;
	odp_buffer_hdr_t	*in_hdr;
	queue_entry_t		*in_qentry = NULL;
	int			ret;

	ses = session_to_entry(params->session);
	assert(ses);
	/* support only for in-place */
	assert(params->out_pkt == params->pkt);

	/* input buffer */
	in_hdr = (odp_buffer_hdr_t *)(odp_packet_hdr(params->pkt));
	/* use buffer area after buf hdr for crypto job block */
	sgp = (struct sg_priv *)((void *)in_hdr + ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(odp_packet_hdr_t)));
	memset(&sgp->sg[0], 0, 2 * sizeof(struct qm_sg_entry));

	assert(ses->s.build_compound_fd);
	/* Build a compound frame descriptor */
	ses->s.build_compound_fd(params, sgp);
	/* pass session struct pointer */
	sgp->ses = ses;
	/* pass completion event handle */
	sgp->compl_ev = _odp_packet_to_buffer(params->pkt);
	/* pass input packet handle */
	sgp->in_pkt = params->pkt;
	/* pass packet context to be returned */
	set_op_compl_ctx(sgp->compl_ev, params->ctx);
	/* prepare fd and enqueue to crypto */
	qm_fd_addr_set64(&fd, __dma_mem_vtop(sgp->sg));
	fd._format2 = qm_fd_compound;
	/* get input queue */
	odp_queue_t inq = in_hdr->inq;
	if (inq != ODP_QUEUE_INVALID)
		in_qentry = queue_to_qentry(inq);
	if (!in_qentry)
		/* pktio burst mode */
		ret = qman_enqueue(&ses->s.input_fq, &fd, 0);
	else
		ret = queue_enqueue_tx_fq(&ses->s.input_fq, &fd, in_hdr,
					  in_qentry);
	*posted = !ret;
	return ret;
}

int odp_crypto_capability(odp_crypto_capability_t *capa)
{
	/* Initialize crypto capability structure */
	memset(capa, 0, sizeof(odp_crypto_capability_t));

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
