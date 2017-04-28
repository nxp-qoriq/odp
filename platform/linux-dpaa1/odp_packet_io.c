/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/packet_io.h>
#include <odp/api/packet.h>
#include <odp_internal.h>
#include <odp/api/spinlock.h>
#include <odp/api/shared_memory.h>
#include <odp/api/hints.h>
#include <odp_debug_internal.h>
#include <odp/api/thread.h>
#include <odp/api/system_info.h>

#include <odp_config_internal.h>
#include <odp_queue_internal.h>
#include <odp_pool_internal.h>
#include <odp_schedule_internal.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_packet_io_queue.h>
#include <odp_debug_internal.h>

#include <configs/odp_config_platform.h>
#include <usdpaa/fsl_usd.h>
#include <usdpaa/of.h>
#include <usdpaa/fsl_qman.h>
#include <usdpaa/usdpaa_netcfg.h>

#include <string.h>
#include <assert.h>

/* Direct receive pool channel */
static u32 sdqcr_vdq, pchannel_vdq;

/* pktio pointer entries ( for inlines) */
void *pktio_entry_ptr[ODP_CONFIG_PKTIO_ENTRIES];

/* MTU to be reported for the "loop" interface */
#define PKTIO_LOOP_MTU 1500

/* MAC address for the "loop" interface */
static const char pktio_loop_mac[] = {0x02, 0xe9, 0x34, 0x80, 0x73, 0x01};

/* Get fman_if from shared mac interface name */
static inline struct fman_if
*get_fman_if_byshmac(const char *name)
{
	int i;
	struct fm_eth_port_cfg *port_cfg;
	for (i = 0; i < netcfg->num_ethports; i++) {
		port_cfg = &netcfg->port_cfg[i];
		if (port_cfg->fman_if->shared_mac_info.is_shared_mac &&
		    port_cfg->fman_if->shared_mac_info.shared_mac_name &&
		    !strcmp(port_cfg->fman_if->shared_mac_info.shared_mac_name,
			   name))
			return port_cfg->fman_if;
	}
	return NULL;
}

/* Get fman_if from port name (fman index, port type/index */
static inline struct fman_if
*get_fman_if_byname(const char *name)
{
	char *cp;
	const char delim[] = "-";
	char *fm, *port, *end;
	int fm_idx = -1, port_idx = -1;
	int i;
	enum fman_mac_type mac_type = fman_offline;
	struct fm_eth_port_cfg *port_cfg;

	cp = strdup(name);
	if (!cp)
		return NULL;
	fm = strsep(&cp, delim);
	port = strsep(&cp, delim);
	end = strsep(&cp, delim);

	if (fm && port && !end) {
		if (!strncmp(fm, "fm", 2) && isdigit(fm[2]) &&
		    fm[3] == '\0')
			fm_idx = fm[2] - '0';
		if (!strncmp(port, "mac", 3) && isdigit(port[3]) &&
		    port[4] == '\0') {
			port_idx = port[3] - '0';
			if (port_idx >= 9) {
				mac_type = fman_mac_10g;
			} else {
				mac_type = fman_mac_1g;
			}
		}
		/* Support for fmx-mac10 interface */
		if (!strncmp(port, "mac", 3) && isdigit(port[4]) &&
		    port[5] == '\0') {
			port_idx = 10;
			mac_type = fman_mac_10g;
		}
		if (!strncmp(port, "oh", 2) && isdigit(port[2]) &&
		    port[3] == '\0') {
			port_idx = port[2] - '0';
			mac_type = fman_offline;
		}
	}
	if (fm_idx < 0 || port_idx < 0)
		return NULL;
	free(cp);
	for (i = 0; i < netcfg->num_ethports; i++) {
		port_cfg = &netcfg->port_cfg[i];
		if (port_cfg->fman_if->fman_idx == fm_idx &&
		    port_cfg->fman_if->mac_idx == port_idx &&
		    port_cfg->fman_if->mac_type == mac_type) {
			return port_cfg->fman_if;
		}

	}

	return NULL;
}

/* Get port configuration from fman_if */
static inline struct fm_eth_port_cfg
*get_port_cfg_byif(struct fman_if *__if)
{
	int i;
	struct fm_eth_port_cfg *port_cfg;
	for (i = 0; i < netcfg->num_ethports; i++) {
		port_cfg = &netcfg->port_cfg[i];
		if (port_cfg->fman_if == __if)
			return port_cfg;
	}
	return NULL;
}

/* Get first PCD range start fqid */
static inline uint32_t
get_pcd_start_fqid(struct fm_eth_port_cfg *p_cfg)
{
	struct fm_eth_port_fqrange *fqr;
	/* only first range */
	list_for_each_entry(fqr, p_cfg->list, list)
		return fqr->start;
	return 0;
}

/* Get fqids number of first PCD range*/
static inline uint32_t
get_pcd_count(struct fm_eth_port_cfg *p_cfg)
{
	struct fm_eth_port_fqrange *fqr;
	list_for_each_entry(fqr, p_cfg->list, list)
		return fqr->count;
	return 0;
}

/* Find buffer pool in the current configured port pool */
static inline bool
fman_if_find_bpid(struct fman_if *__if, uint32_t bpid)
{
	bool found = false;
	struct fman_if_bpool *bp;
	list_for_each_entry(bp, &__if->bpool_list, node) {
		if (bp->bpid == bpid) {
			found = true;
			break;
		}
	}
	return found;
}

typedef struct {
	pktio_entry_t entries[ODP_CONFIG_PKTIO_ENTRIES];
	netcfg_port_info port_info[];
} pktio_table_t;

static pktio_table_t *pktio_tbl;

netcfg_port_info  *pktio_get_port_info(struct fman_if *__if)
{
	int i;
	struct fm_eth_port_cfg *port_cfg;

	for (i = 0; i < netcfg->num_ethports; i++) {
		port_cfg = pktio_tbl->port_info[i].p_cfg;
		if (port_cfg->fman_if == __if)
			break;
	}

	return	&pktio_tbl->port_info[i];
}

static int is_free(pktio_entry_t *entry)
{
	return (entry->s.taken == 0);
}

static void set_free(pktio_entry_t *entry)
{
	entry->s.taken = 0;
}

static void set_taken(pktio_entry_t *entry)
{
	entry->s.taken = 1;
}
static void lock_entry(pktio_entry_t *entry)
{
	odp_spinlock_lock(&entry->s.lock);
}

static void unlock_entry(pktio_entry_t *entry)
{
	odp_spinlock_unlock(&entry->s.lock);
}

static void init_pktio_entry(pktio_entry_t *entry)
{
	set_taken(entry);
	entry->s.inq_default = ODP_QUEUE_INVALID;
	entry->s.outq_default = ODP_QUEUE_INVALID;
	entry->s.default_cos = ODP_COS_INVALID;
	entry->s.error_cos = ODP_COS_INVALID;
}

static odp_pktio_t alloc_lock_pktio_entry(void)
{
	odp_pktio_t id;
	pktio_entry_t *entry;
	int i;

	for (i = 0; i < ODP_CONFIG_PKTIO_ENTRIES; ++i) {
		entry = &pktio_tbl->entries[i];
		if (is_free(entry)) {
			lock_entry(entry);
			if (is_free(entry)) {
				init_pktio_entry(entry);
				id = _odp_cast_scalar(odp_pktio_t, i + 1);
				entry->s.id = id;
				unlock_entry(entry);
				return id; /* return with entry locked! */
			}
			unlock_entry(entry);
		}
	}

	return ODP_PKTIO_INVALID;
}

static int free_pktio_entry(odp_pktio_t id)
{
	pktio_entry_t *entry = get_pktio_entry(id);

	if (entry == NULL)
		return -1;

	set_free(entry);

	return 0;
}

int odp_pktio_init_local(void)
{
	return 0;
}

void odp_pktio_term_local(void)
{
	return;
}

int odp_pktio_init_global(void)
{
	pktio_entry_t *pktio_entry;
	int id, i, j, ret;
	struct fm_eth_port_cfg *p_cfg;
	odp_shm_t shm;
	struct fman_if_ic_params icp;
	struct fman_if_bpool *bp, *tmpbp;

	shm = odp_shm_reserve("odp_pktio_entries",
			sizeof(pktio_table_t) +
			netcfg->num_ethports * sizeof(netcfg_port_info),
			sizeof(pktio_entry_t), ODP_SHM_SW_ONLY);
	pktio_tbl = odp_shm_addr(shm);
	if (pktio_tbl == NULL)
		return -1;

	ret = qman_alloc_pool_range(&pchannel_vdq, 1, 1, 0);
	if (ret != 1)
		return -1;

	sdqcr_vdq = QM_SDQCR_CHANNELS_POOL_CONV(pchannel_vdq);

	memset(pktio_tbl, 0, sizeof(pktio_table_t));

	for (id = 1; id <= ODP_CONFIG_PKTIO_ENTRIES; ++id) {
		pktio_entry = &pktio_tbl->entries[id - 1];
		pktio_entry_ptr[id - 1] = pktio_entry;
		odp_spinlock_init(&pktio_entry->s.lock);
	}

	printf("\nPort info\n---------\n");
	for (i = 0; i < netcfg->num_ethports; i++) {
		p_cfg = &netcfg->port_cfg[i];

		/* reset bpool list for each port - we explicitly assign
		 buffer pools to ports when opening pktio devices  */
		list_for_each_entry_safe(bp, tmpbp,
					 &p_cfg->fman_if->bpool_list, node) {
			list_del(&bp->node);
			free(bp);
		}

		/* Set the ICIOF, ICEOF & ICSZ */
		memset(&icp, 0, sizeof(icp));
		icp.iciof = DEFAULT_ICIOF;
		icp.iceof = DEFAULT_ICEOF;
		icp.icsz = DEFAULT_ICSZ;
		fman_if_set_ic_params(p_cfg->fman_if, &icp);

		if (p_cfg->fman_if->mac_type == fman_offline) {
			if (fman_ip_rev >= FMAN_V3)
				fman_if_set_dnia(p_cfg->fman_if, OH_DEQ_NIA);
		}

		/* copy ports configuration to pktio table */
		pktio_tbl->port_info[i].p_cfg = p_cfg;
		pktio_tbl->port_info[i].fman_if = p_cfg->fman_if;
		pktio_tbl->port_info[i].first_fqid = get_pcd_start_fqid(p_cfg);
		pktio_tbl->port_info[i].default_fqid = p_cfg->rx_def;
		pktio_tbl->port_info[i].count = get_pcd_count(p_cfg);

		/* Print the MAC address */
		if (p_cfg->fman_if->mac_type == fman_mac_1g ||
			p_cfg->fman_if->mac_type == fman_mac_10g) {
			printf("interface fm%d-mac%d macaddr::",
				p_cfg->fman_if->fman_idx, p_cfg->fman_if->mac_idx);
			for (j = 0; j < ETH_ALEN; j++) {
				if (j != (ETH_ALEN - 1))
					printf("%02x:", p_cfg->fman_if->mac_addr.ether_addr_octet[j]);
				else
					printf("%02x\n", p_cfg->fman_if->mac_addr.ether_addr_octet[j]);
			}
		}
	}

	/* Initialize fman for hash distribution */
	if (pktio_fm_init()) {
		ODP_ERR("Pktio FM init: Failed\n");
		return -1;
	}

	return 0;
}

/* DQRR callback when pktio works in queue mode - static deq */
/* Handles PKTIN queues & PACKET buffer types */
enum qman_cb_dqrr_result dqrr_cb_qm(struct qman_fq *fq,
					 const struct qm_dqrr_entry *dqrr,
					 uint64_t *user_context)
{
	const struct qm_fd *fd = &dqrr->fd;
	void *fd_addr;
	odp_packet_hdr_t *pkthdr;

	queue_entry_t *qentry = QENTRY_FROM_FQ(fq);

	/* get packet header from frame start address */
	fd_addr = __dma_mem_ptov(qm_fd_addr(fd));
	pkthdr = odp_pkt_hdr_from_addr(fd_addr, NULL);

	/* Prefetch annotation and data */
	odp_prefetch(pkthdr->addr[0]);
	odp_prefetch(pkthdr->addr[0] + ODP_CONFIG_PACKET_HEADROOM);

	if (fd->format == qm_fd_sg) {
		struct qm_sg_entry *sgt;
		unsigned	sgcnt;

		sgt = (struct qm_sg_entry *)(fd_addr + fd->offset);
		/* On LE CPUs, converts the SG entry from the BE format as
		 * is provided by the HW to LE as expected by the LE CPUs,
		 * on BE CPUs does nothing */
		hw_sg_to_cpu(&sgt[0]);

		fd_addr = __dma_mem_ptov(qm_sg_addr(sgt));/* first sg entry */
		pkthdr = odp_buf_hdr_from_addr(fd_addr, NULL);
		sgcnt = 1;
		do {
			hw_sg_to_cpu(&sgt[sgcnt]);

			pkthdr->addr[sgcnt] = __dma_mem_ptov(
							qm_sg_addr(&sgt[sgcnt]));
			sgcnt++;
		} while (sgt[sgcnt - 1].final != 1);
		pkthdr->addr[sgcnt] = __dma_mem_ptov(qm_fd_addr(fd));
		pkthdr->segcount = sgcnt;
		fd_addr = pkthdr->addr[sgcnt];
	}

	pkthdr->headroom = ODP_CONFIG_PACKET_HEADROOM;
	pkthdr->tailroom = ODP_CONFIG_PACKET_TAILROOM;
	pkthdr->input = qentry->s.pktin;
	pkthdr->frame_len = fd->length20;
	pkthdr->inq = queue_from_id(get_qid(qentry));
	*user_context = (uint64_t)pkthdr;

	/* save sequence number when input queue is ORDERED */
	if (qentry->s.param.sched.sync == ODP_SCHED_SYNC_ORDERED) {
		pkthdr->orp.seqnum = dqrr->seqnum;
		/*buf_hdr->orp.flags = 0;*/
	}
	/* save whole dqrr entry as it is acked on next enqueue
	   dqrr entry is stored outside the buffer because it is
	   released by the port before DCA */
	else if (qentry->s.param.sched.sync == ODP_SCHED_SYNC_ATOMIC) {
		pkthdr->dqrr = dqrr;
		return qman_cb_dqrr_defer;
	}

	return qman_cb_dqrr_consume;
}

static enum qman_cb_dqrr_result
dqrr_cb_poll_pktin(struct qman_fq *fq,
		const struct qm_dqrr_entry *dqrr,
		uint64_t *user_context)
{
	const struct qm_fd *fd;
	struct qm_sg_entry *sgt;
	pool_entry_t *pool;
	void *fd_addr;
	odp_buffer_t buf;
	odp_buffer_hdr_t *buf_hdr;
	odp_packet_hdr_t *pkthdr;
	odp_packet_t pkt;
	size_t off;
	uint32_t i;

	fd = &dqrr->fd;
	i = bpid_to_index(fd->bpid);
	if (i == ODP_BUFFER_MAX_POOLS) {
		ODP_ERR("Invalid BPID\n");
		/* Buffer need to be freed here */
		return qman_cb_dqrr_consume;
	}
	pool = get_pool_entry(i);

	fd_addr = __dma_mem_ptov(qm_fd_addr(fd));
	off = fd->offset;
	buf_hdr = odp_buf_hdr_from_addr(fd_addr, pool);

	if (fd->format == qm_fd_sg) {
		unsigned	sgcnt;
#ifdef ODP_MULTI_POOL_SG_SUPPORT
		pool_entry_t	*pool_sg;
		odp_pool_t	pool_handle;
#endif
		sgt = (struct qm_sg_entry *)(fd_addr + fd->offset);
		/* On LE CPUs, converts the SG entry from the BE format
		 * as is provided by the HW to LE as expected by the
		 * LE CPUs, on BE CPUs does nothing */
		hw_sg_to_cpu(&sgt[0]);

		fd_addr = __dma_mem_ptov(qm_sg_addr(sgt));/* first sg entry */
#ifndef ODP_MULTI_POOL_SG_SUPPORT
		buf_hdr = odp_buf_hdr_from_addr(fd_addr, pool);
#else
		pool_sg = get_pool_entry(i);
		buf_hdr = odp_buf_hdr_from_addr(fd_addr, pool_sg);

		pool_handle = pool_index_to_handle(sgt->bpid);
		buf_hdr->sg_pool_hdl[0] = pool_handle;
#endif
		off = sgt->offset;
		sgcnt = 1;
		do {
			hw_sg_to_cpu(&sgt[sgcnt]);

			buf_hdr->addr[sgcnt] = __dma_mem_ptov(
						qm_sg_addr(&sgt[sgcnt]));
#ifdef ODP_MULTI_POOL_SG_SUPPORT
			pool_handle = pool_index_to_handle(sgt[sgcnt].bpid);
			buf_hdr->sg_pool_hdl[sgcnt] = pool_handle;
#endif
			sgcnt++;
		} while (sgt[sgcnt - 1].final != 1);
		buf_hdr->addr[sgcnt] = __dma_mem_ptov(qm_fd_addr(fd));
		buf_hdr->segcount = sgcnt;
		fd_addr = buf_hdr->addr[sgcnt];
	}
	buf = odp_hdr_to_buf(buf_hdr);

	queue_entry_t *qentry = QENTRY_FROM_FQ(fq);
	pktio_entry_t *pktio_entry = get_pktio_entry(qentry->s.pktin);

	pkthdr = (odp_packet_hdr_t *)buf_hdr;
	pkthdr->headroom = pool->s.headroom;
	pkthdr->tailroom = pool->s.tailroom;
	/* setup and receive ODP packet */
	pkt = _odp_packet_from_buffer(buf);
	odp_pktio_set_input(pkthdr, pktio_entry->s.id);
	odp_queue_set_input(_odp_packet_to_buffer(pkt), ODP_QUEUE_INVALID);
	_odp_packet_parse(pkthdr, fd->length20, off, fd_addr);
	*user_context = (uint64_t)pkt;

	if (pktio_entry->s.pkt_table) {
		*(pktio_entry->s.pkt_table) = pkt;
		(pktio_entry->s.pkt_table)++;
	}
	return qman_cb_dqrr_consume;
}

/* DQRR callback when pktio works in direct receive mode - volatile deq */
static enum qman_cb_dqrr_result
dqrr_cb_im(struct qman_fq *fq,
		const struct qm_dqrr_entry *dqrr,
		uint64_t *user_context)
{
	const struct qm_fd *fd;
	struct qm_sg_entry *sgt;
	pool_entry_t *pool;
	odp_buffer_hdr_t *buf_hdr;
	odp_packet_hdr_t *pkthdr;
	odp_buffer_t buf;
	odp_packet_t pkt;
	void *fd_addr;
	size_t off;
	uint32_t i;

	fd = &dqrr->fd;
	i = bpid_to_index(fd->bpid);
	if (i == ODP_BUFFER_MAX_POOLS) {
		ODP_ERR("Invalid BPID\n");
		/* Buffer need to be freed here */
		return qman_cb_dqrr_consume;
	}
	pool = get_pool_entry(i);

	/* get packet header from frame start address */
	fd_addr = __dma_mem_ptov(qm_fd_addr(fd));
	buf_hdr = odp_buf_hdr_from_addr(fd_addr, pool);
	off = fd->offset;
	if (fd->format == qm_fd_sg) {
		unsigned	sgcnt;

		sgt = (struct qm_sg_entry *)(fd_addr + fd->offset);
		/* On LE CPUs, converts the SG entry from the BE format
		 * as is provided by the HW to LE as expected by the
		 * LE CPUs, on BE CPUs does nothing */
		hw_sg_to_cpu(&sgt[0]);

		fd_addr = __dma_mem_ptov(qm_sg_addr(sgt));/* first sg entry */
		buf_hdr = odp_buf_hdr_from_addr(fd_addr, pool);
		off = sgt->offset;
		sgcnt = 1;
		do {
			hw_sg_to_cpu(&sgt[sgcnt]);

			buf_hdr->addr[sgcnt] = __dma_mem_ptov(
							qm_sg_addr(&sgt[sgcnt]));
			sgcnt++;
		} while (sgt[sgcnt - 1].final != 1);
		buf_hdr->addr[sgcnt] = __dma_mem_ptov(qm_fd_addr(fd));
		buf_hdr->segcount = sgcnt;
		fd_addr = buf_hdr->addr[sgcnt];
	}
	buf = odp_hdr_to_buf(buf_hdr);

	/* get input interface */
	struct pktio_entry *pktio_entry = PKTIO_ENTRY_FROM_FQ(fq);

	pkthdr = (odp_packet_hdr_t *)buf_hdr;
	pkthdr->headroom = pool->s.headroom;
	pkthdr->tailroom = pool->s.tailroom;
	/* setup and receive ODP packet */
	pkt = _odp_packet_from_buffer(buf);
	odp_pktio_set_input(pkthdr, pktio_entry->id);
	buf_set_input_queue(buf_hdr, ODP_QUEUE_INVALID);
	_odp_packet_parse(pkthdr, fd->length20, off, fd_addr);
	*user_context = (uint64_t)pkt;

	if (pktio_entry->pkt_table) {
		*(pktio_entry->pkt_table) = pkt;
		(pktio_entry->pkt_table)++;
	}

	return qman_cb_dqrr_consume;
}

/*
 * Create a Tx queue for interface
 * */
static int create_tx_fq(struct qman_fq *fq, struct fman_if *__if)
{
	int ret;
	struct qm_mcc_initfq opts;
	queue_entry_t *qentry;
	uint32_t flags = QMAN_FQ_FLAG_DYNAMIC_FQID |
			 QMAN_FQ_FLAG_TO_DCPORTAL;

	ret = qman_create_fq(0, flags, fq);
	if (ret)
		return ret;

	qentry = QENTRY_FROM_FQ(fq);
	memset(&opts, 0, sizeof(opts));
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
			QM_INITFQ_WE_CONTEXTA | QM_INITFQ_WE_CONTEXTB;
	opts.fqd.dest.channel = __if->tx_channel_id;
	opts.fqd.dest.wq = qentry->s.param.sched.prio;
	opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
	opts.fqd.context_b = 0;
	if (__if->mac_type == fman_offline && fman_ip_rev >= FMAN_V3) {
		opts.fqd.context_a.hi = 0;
		opts.fqd.context_a.lo = 0;
	} else {
		opts.fqd.context_a.hi = 0x80000000 | fman_dealloc_bufs_mask_hi;
		opts.fqd.context_a.lo = 0 | fman_dealloc_bufs_mask_lo;
	}

	ret = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	return ret;
}

/*
 * A pktio device is a Tx/Rx facility built on top of a pair of HW queues.
 * Rx queue is allocated from the default and PCD ranges allocated by USDPAA
 * to port corresponding to argument *name.
 * It works in three modes - scheduler mode, queue mode and interface mode.
 * In schedule mode, the Rx queue is under QMAN scheduler control and application
 * gets frames from this PCD queues using ODP scheduling calls.
 * In queue mode and interface mode, frames are dequeued explicitly using
 * volatile dequeue commands.
 * In queue mode, an ODP queue is set as the default input queue and it is used
 * for Rx frame.
 * In interface mode, ODP queue is not set as default queue but default queue
 * is used for Rx frame.
 */

odp_pktio_t odp_pktio_open(const char *name, odp_pool_t pool,
				const odp_pktio_param_t *param)
{
	odp_pktio_t id;
	pktio_entry_t *pktio_entry;
	uint32_t default_fqid = 0;
	int ret;
	struct fman_if *__if;
	uint32_t count = 0, first_fqid = 0, i;
	pool_entry_t *pool_t;
	struct fman_if_bpool *bpool;

	id = odp_pktio_lookup(name);
	if (id != ODP_PKTIO_INVALID) {
		/* interface is already open */
		__odp_errno = EEXIST;
		return ODP_PKTIO_INVALID;
	}

	id = alloc_lock_pktio_entry();
	if (id == ODP_PKTIO_INVALID) {
		ODP_ERR("No resources available.\n");
		return ODP_PKTIO_INVALID;
	}

	/* if successful, alloc_pktio_entry() returns with the entry locked */
	pktio_entry = get_pktio_entry(id);
	pktio_entry->s.id = id;
	pktio_entry->s.pool = pool;
	pktio_entry->s.param.in_mode = param->in_mode;
	pktio_entry->s.param.out_mode = param->out_mode;
	snprintf(pktio_entry->s.name,
		 sizeof(pktio_entry->s.name), "%s", name);

	/* get the fman interface for this device */
	__if = get_fman_if_byshmac(name);
	if (!__if)
		__if = get_fman_if_byname(name);

	if (!__if) {
		free_pktio_entry(id);
		id = ODP_PKTIO_INVALID;
		goto out;
	}


	for (i = 0; i < netcfg->num_ethports; i++) {
		if (pktio_tbl->port_info[i].fman_if == __if) {
			pktio_entry->s.__if = __if;

			/* Default fqid */
			default_fqid = pktio_tbl->port_info[i].default_fqid;
			pktio_entry->s.default_fqid = default_fqid;

			/* Number of PCD FQs*/
			count = pktio_tbl->port_info[i].count;

			/* First FQID in PCD FQs */
			first_fqid = pktio_tbl->port_info[i].first_fqid;
			pktio_entry->s.pcd_first_fqid = first_fqid;

			pktio_entry->s.rx_fq.fqid = 0;

			break;
		}
	}

	/* reserve non-dynamic default fqid */
	ret = qman_reserve_fqid(default_fqid);
	if (ret) {
		free_pktio_entry(id);
		id = ODP_PKTIO_INVALID;
	}

	/* reserve non-dynamic pcd fqid for SCHED mode only */
	if (param->in_mode == ODP_PKTIN_MODE_SCHED) {
		for (i = 0; i < count; i++) {
			ret = qman_reserve_fqid(first_fqid++);
			if (ret)
				ODP_ERR("Unable to reserve fqid %x\n", first_fqid - 1);
		}
	}

	/* set buffer pool into the port configuration	*/
	unsigned bpool_num;
	pool_t = get_pool_entry(pool_handle_to_index(pktio_entry->s.pool));
	if (pktio_tbl->port_info[i].bp_num < MAX_PORT_BPOOLS &&
		!fman_if_find_bpid(__if, pool_t->s.bpid)) {
		bpool_num = pktio_tbl->port_info[i].bp_num;
		bpool = &pktio_tbl->port_info[i].bpool[bpool_num];
		bpool->bpid = pool_t->s.bpid;

		bpool->count = pool_t->s.params.pkt.num;
		bpool->size = pool_t->s.params.pkt.len;
		list_add_tail(&bpool->node, &__if->bpool_list);

		fman_if_set_bp(__if, pktio_tbl->port_info[i].bp_num,
				pool_t->s.bpid, pool_t->s.params.pkt.len);
		pktio_tbl->port_info[i].bp_num++;
	}

out:
	return id;
}

int odp_pktin_queue_config(odp_pktio_t pktio,
			const odp_pktin_queue_param_t *param)
{
	int ret = 0, rc;
	unsigned int num_queues, i;
	uint16_t channel;
	odp_pktin_mode_t mode;
	pktio_entry_t *entry;
	queue_entry_t *qentry;
	odp_pktio_capability_t capa;
	odp_queue_t queue = ODP_QUEUE_INVALID;
	odp_pktin_queue_param_t default_param;
	odp_queue_param_t queue_param;

	if (param == NULL) {
		odp_pktin_queue_param_init(&default_param);
		param = &default_param;
	}

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		ODP_ERR("pktio entry %d does not exist\n", pktio);
		return -1;
	}
	mode = entry->s.param.in_mode;

	num_queues = param->num_queues;

	rc = odp_pktio_capability(pktio, &capa);
	if (rc) {
		ODP_DBG("pktio %s: unable to read capabilities\n",
			entry->s.name);
		return -1;
	}

	if (num_queues > capa.max_input_queues) {
		ODP_DBG("pktio %s: too many input queues\n", entry->s.name);
		return -1;
	}

	if (param->classifier_enable && param->hash_enable) {
		ODP_ERR("pktio %s: Both classifier and hashing cannot be"
				" enabled simultaneously\n", entry->s.name);
		return -1;
	}

	if (num_queues == 0 && !(param->classifier_enable)) {
		ODP_ERR("pktio %s: zero input queues\n", entry->s.name);
		return -1;
	}

	if (num_queues > 1 && !(param->hash_enable) &&
		 !(param->classifier_enable)) {
		ODP_ERR("pktio %s:  More than one input queues require either"
			"flow hashing or classifier enabled.\n",
			entry->s.name);
		return -1;
	}

	/* If re-configuring, destroy old queues */
	if (entry->s.inq_default) {
		odp_queue_destroy(entry->s.inq_default);
		entry->s.inq_default = ODP_QUEUE_INVALID;
	}

	int pktio_id = pktio_to_id(pktio);

	if (mode == ODP_PKTIN_MODE_QUEUE ||
		mode == ODP_PKTIN_MODE_SCHED) {

		memcpy(&queue_param, &param->queue_param,
			sizeof(odp_queue_param_t));
		queue_param.type = ODP_QUEUE_TYPE_PLAIN;

		if (mode == ODP_PKTIN_MODE_SCHED)
			queue_param.type = ODP_QUEUE_TYPE_SCHED;

		/* Create default queue for pktio */
		queue = odp_queue_create("default", &queue_param);
		if (queue == ODP_QUEUE_INVALID) {
			ODP_DBG("pktio %s: event queue create failed\n",
				entry->s.name);
			return -1;
		}

		qentry = queue_to_qentry(queue);
		teardown_fq(&qentry->s.fq);

		memset(&qentry->s.fq, 0, sizeof(struct qman_fq));
		memset(&qentry->s.orp_fq, 0, sizeof(struct qman_fq));

		qentry->s.type = queue_param.type;

		lock_entry(entry);
		entry->s.inq_default = queue;
		unlock_entry(entry);

		queue_lock(qentry);
		qentry->s.pktin = pktio;
		if (qentry->s.type != ODP_QUEUE_TYPE_PLAIN) {
			channel = get_next_rx_channel();
			qentry->s.fq.cb.dqrr_ctx = dqrr_cb_qm;
			qentry->s.fq.cb.ern = ern_cb;
		} else {
			qentry->s.enqueue = pktin_enqueue;
			qentry->s.dequeue = pktin_dequeue;
			qentry->s.enqueue_multi = pktin_enq_multi;
			qentry->s.dequeue_multi = pktin_deq_multi;
			channel = pchannel_vdq;
			qentry->s.fq.cb.dqrr_ctx = dqrr_cb_poll_pktin;
			qentry->s.fq.cb.ern = ern_cb;
		}
		/* create HW Rx default queue */
		ret = qman_create_fq(entry->s.default_fqid,
				QMAN_FQ_FLAG_NO_ENQUEUE,
				&qentry->s.fq);
		ret = queue_init_rx_fq(&qentry->s.fq, channel);
		if (ret < 0) {
			queue_unlock(qentry);
			return ret;
		}
		if (qentry->s.type != ODP_QUEUE_TYPE_PLAIN) {
			qman_schedule_fq(&qentry->s.fq);
			qentry->s.status = QUEUE_STATUS_SCHED;
		}
		queue_unlock(qentry);
	} else {
		lock_entry(entry);
		entry->s.inq_default = ODP_QUEUE_INVALID;
		unlock_entry(entry);
		return ret;
	}

	/* Create PCD fq for SCHED mode only */
	if (mode == ODP_PKTIN_MODE_SCHED) {
		for (i = 0; i < num_queues; i++) {
			char name[ODP_QUEUE_NAME_LEN];

			snprintf(name, sizeof(name), "odp-pktin-%i-%i",
				 pktio_id, i);

			queue_param.type = ODP_QUEUE_TYPE_SCHED;

			queue = odp_queue_create(name, &queue_param);

			if (queue == ODP_QUEUE_INVALID) {
				ODP_DBG("pktio %s: event queue create failed\n",
					entry->s.name);
				return -1;
			}

			qentry = queue_to_qentry(queue);

			teardown_fq(&qentry->s.fq);

			memset(&qentry->s.fq, 0, sizeof(struct qman_fq));
			memset(&qentry->s.orp_fq, 0, sizeof(struct qman_fq));

			qentry->s.type = ODP_QUEUE_TYPE_SCHED;

			lock_entry(entry);
			entry->s.queue[i] = queue;
			unlock_entry(entry);

			queue_lock(qentry);
			qentry->s.pktin = pktio;
			channel = get_next_rx_channel();
			qentry->s.fq.cb.dqrr_ctx = dqrr_cb_qm;
			qentry->s.fq.cb.ern = ern_cb;

			/* create HW Rx PCD queue */
			ret = qman_create_fq(entry->s.pcd_first_fqid + i,
					QMAN_FQ_FLAG_NO_ENQUEUE,
					&qentry->s.fq);
			ret = queue_init_rx_fq(&qentry->s.fq, channel);
			if (ret < 0) {
				queue_unlock(qentry);
				return ret;
			}
			qman_schedule_fq(&qentry->s.fq);
			qentry->s.status = QUEUE_STATUS_SCHED;
			queue_unlock(qentry);
		}
	}

	if (ret != 0)
		ODP_ABORT("Error: default input-Q setup for \n");

	if (pktio_fm_config(pktio, param)) {
		ODP_ERR("Pktio FM configuration: Failed\n");
		return -1;
	}
	return ret;
}

int odp_pktout_queue_config(odp_pktio_t pktio,
			const odp_pktout_queue_param_t *param)
{
	pktio_entry_t *pktio_entry;
	char name[ODP_QUEUE_NAME_LEN];
	queue_entry_t *queue_entry;
	odp_queue_t qid;
	struct fman_if *__if;
	unsigned num_queues;
	int ret, rc;
	odp_pktio_capability_t capa;
	odp_pktout_queue_param_t default_param;
	odp_queue_param_t queue_param;

	if (param == NULL) {
		odp_pktout_queue_param_init(&default_param);
		param = &default_param;
	}

	pktio_entry = get_pktio_entry(pktio);
	if (pktio_entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", pktio);
		return -1;
	}

	__if = pktio_entry->s.__if;
	num_queues = param->num_queues;

	if (num_queues == 0) {
		ODP_DBG("pktio %s: zero input queues\n", pktio_entry->s.name);
		return -1;
	}

	rc = odp_pktio_capability(pktio, &capa);
	if (rc) {
		ODP_DBG("pktio %s: unable to read capabilities\n",
			pktio_entry->s.name);
		return -1;
	}

	if (num_queues > capa.max_input_queues) {
		ODP_DBG("pktio %s: too many input queues\n", pktio_entry->s.name);
		return -1;
	}

	/* create default output queue */
	snprintf(name, sizeof(name), "%" PRIu64 "-pktio_outq_default",
						odp_pktio_to_u64(pktio));
	name[ODP_QUEUE_NAME_LEN-1] = '\0';

	memset(&queue_param, 0, sizeof(odp_queue_param_t));

	queue_param.type = ODP_QUEUE_TYPE_PLAIN;

	qid = odp_queue_create(name, &queue_param);
	if (qid == ODP_QUEUE_INVALID)
		return -1;

	pktio_entry->s.outq_default = qid;
	queue_entry = queue_to_qentry(qid);
	queue_entry->s.pktout = pktio;
	queue_entry->s.enqueue = pktout_enqueue;
	queue_entry->s.dequeue = pktout_dequeue;
	queue_entry->s.enqueue_multi = pktout_enq_multi;
	queue_entry->s.dequeue_multi = pktout_deq_multi;

	teardown_fq(&queue_entry->s.fq);

	memset(&queue_entry->s.fq, 0, sizeof(struct qman_fq));
	memset(&queue_entry->s.orp_fq, 0, sizeof(struct qman_fq));

	/* create HW Tx queue for output */
	ret = create_tx_fq(&pktio_entry->s.tx_fq, __if);
	if (ret) {
		free_pktio_entry(pktio);
		return -1;
	}
	queue_entry->s.fq = pktio_entry->s.tx_fq;

	/* get IC transfer params */
	ret = fman_if_get_ic_params(__if, &pktio_entry->s.icp);
	if (ret) {
		free_pktio_entry(pktio);
		return -1;
	}
	assert(pktio_entry->s.icp.iceof == DEFAULT_ICEOF);
	assert(pktio_entry->s.icp.iciof == DEFAULT_ICIOF);
	assert(pktio_entry->s.icp.icsz == DEFAULT_ICSZ);

	return 0;

}

int odp_pktio_mac_addr(odp_pktio_t id, void *mac_addr, int addr_size)
{
	pktio_entry_t *pktio_entry;
	pktio_entry = get_pktio_entry(id);

	if (!pktio_entry)
		return -1;

	if (addr_size < ETH_ALEN) {
		/* Output buffer too small */
		return -1;
	}

	if (pktio_entry->s.__if->mac_type == fman_offline)
		memcpy(mac_addr, pktio_loop_mac, ETH_ALEN);
	else
		memcpy(mac_addr, pktio_entry->s.__if->mac_addr.ether_addr_octet,
			ETH_ALEN);

	return ETH_ALEN;
}

uint32_t odp_pktio_mtu(odp_pktio_t id ODP_UNUSED)
{
	return FM_MAX_FRM;
}


int odp_pktio_close(odp_pktio_t id)
{

	int i, ret = 0;
	struct fm_eth_port_cfg *p_cfg = NULL;
	pktio_entry_t *pktio_entry;

	ODP_DBG("odp_pktio_finish\n");

	if (pktio_fm_deconfig(id))
		ODP_ERR("pktio_fm_deconfig: Failed\n");

	pktio_entry = get_pktio_entry(id);
	if (!pktio_entry)
		return -1;

	for (i = 0; i < netcfg->num_ethports; i++) {
		p_cfg = &netcfg->port_cfg[i];
		if (pktio_entry->s.__if == p_cfg->fman_if &&
			p_cfg->fman_if->shared_mac_info.is_shared_mac) {
			usdpaa_netcfg_enable_disable_shared_rx(p_cfg->fman_if,
								false);
		}
	}

	/* destroy rx and tx queues */
	if (pktio_entry->s.inq_default != ODP_QUEUE_INVALID) {
		ret = odp_queue_destroy(pktio_entry->s.inq_default);
		if (ret)
			return -1;

		pktio_entry->s.inq_default = ODP_QUEUE_INVALID;
	}

	if (pktio_entry->s.outq_default != ODP_QUEUE_INVALID){
		ret = odp_queue_destroy(pktio_entry->s.outq_default);
		if (ret)
			return -1;

		pktio_entry->s.outq_default = ODP_QUEUE_INVALID;
	}

	ret = free_pktio_entry(id);


	return ret;
}

int odp_pktio_start(odp_pktio_t id)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);

	if (!pktio_entry)
		return -1;

	lock_entry(pktio_entry);
	fman_if_enable_rx(pktio_entry->s.__if);
	unlock_entry(pktio_entry);

	return 0;
}

int odp_pktio_stop(odp_pktio_t id)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);

	if (!pktio_entry)
		return -1;

	lock_entry(pktio_entry);
	fman_if_disable_rx(pktio_entry->s.__if);
	unlock_entry(pktio_entry);

	return 0;
}


int odp_pktio_term_global(void)
{

	ODP_DBG("odp_pktio_term_global\n");

	pktio_entry_t *pktio_entry;
	int id;

	/* De-initialize fman */
	if (pktio_fm_term()) {
		ODP_ERR("Pktio FM term: Failed\n");
		return -1;
	}

	qman_release_pool_range(pchannel_vdq, 1);
	for (id = 1; id <= ODP_CONFIG_PKTIO_ENTRIES; ++id) {
		pktio_entry = &pktio_tbl->entries[id - 1];
		if (pktio_entry)
			odp_pktio_close(pktio_entry->s.id);
	}
	return 0;
}

int odp_pktio_capability(odp_pktio_t pktio, odp_pktio_capability_t *capa)
{
	pktio_entry_t *entry;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", pktio);
		return -1;
	}

	memset(capa, 0, sizeof(odp_pktio_capability_t));
	capa->max_input_queues  = QUEUE_MULTI_MAX;
	capa->max_output_queues = 1;

	return 0;
}

odp_pktio_t odp_pktio_lookup(const char *name)
{
	struct fman_if *__if;
	int i;

	__if = get_fman_if_byshmac(name);
	if (!__if)
		__if = get_fman_if_byname(name);
	if (!__if)
		return ODP_PKTIO_INVALID;

	for (i = 0; i < ODP_CONFIG_PKTIO_ENTRIES; i++) {
		if (pktio_tbl->entries[i].s.taken == 0)
			continue;

		if (pktio_tbl->entries[i].s.__if == __if)
			return pktio_tbl->entries[i].s.id;
	}

	return ODP_PKTIO_INVALID;
}

int odp_pktio_promisc_mode_set(odp_pktio_t id, odp_bool_t enable)
{
	pktio_entry_t *pktio_entry;
	pktio_entry = get_pktio_entry(id);

	if (!pktio_entry)
		return -1;

	lock_entry(pktio_entry);
	if (pktio_entry->s.__if->mac_type != fman_offline) {
		if (enable)
			fman_if_promiscuous_enable(pktio_entry->s.__if);
		else
			fman_if_promiscuous_disable(pktio_entry->s.__if);
	}
	pktio_entry->s.promisc = enable;
	unlock_entry(pktio_entry);

	return 0;
}

int odp_pktio_promisc_mode(odp_pktio_t id)
{
	pktio_entry_t *pktio_entry;
	pktio_entry = get_pktio_entry(id);

	if (!pktio_entry)
		return -1;
	return pktio_entry->s.promisc;
}

int odp_pktin_queue(odp_pktio_t pktio, odp_pktin_queue_t queues[], int num)
{
	pktio_entry_t *entry;
	odp_pktin_mode_t mode;
	int i;
	int num_queues;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", pktio);
		return -1;
	}
	mode = entry->s.param.in_mode;

	if (mode == ODP_PKTIN_MODE_DISABLED)
		return 0;

	if (mode != ODP_PKTIN_MODE_DIRECT)
		return -1;

	num_queues = 1;

	if (queues && num > 0)
		for (i = 0; i < num && i < num_queues; i++) {
			queues[i].fq_id = entry->s.rx_fq.fqid;
			queues[i].pktio = pktio;
		}

	return num_queues;
}

int odp_pktin_event_queue(odp_pktio_t pktio, odp_queue_t queues[], int num)
{
	pktio_entry_t *entry;
	odp_pktin_mode_t mode;
	int i;
	int num_queues;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", pktio);
		return -1;
	}
	mode = entry->s.param.in_mode;

	if (mode == ODP_PKTIN_MODE_DISABLED)
		return 0;

	if (mode != ODP_PKTIN_MODE_QUEUE &&
	    mode != ODP_PKTIN_MODE_SCHED)
		return -1;

	num_queues = 1;

	if (queues && num > 0)
		for (i = 0; i < num && i < num_queues; i++)
			queues[i] = entry->s.inq_default;

	return num_queues;
}

int odp_pktout_event_queue(odp_pktio_t pktio, odp_queue_t queues[], int num)
{
	pktio_entry_t *entry;
	odp_pktout_mode_t mode;
	int i;
	int num_queues;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", pktio);
		return -1;
	}

	mode = entry->s.param.out_mode;

	if (mode == ODP_PKTOUT_MODE_DISABLED)
		return 0;

	if (mode != ODP_PKTOUT_MODE_QUEUE)
		return -1;

	num_queues = 1;

	if (queues && num > 0)
		for (i = 0; i < num && i < num_queues; i++)
			queues[i] = entry->s.outq_default;

	return num_queues;
}

int odp_pktout_queue(odp_pktio_t pktio, odp_pktout_queue_t queues[], int num)
{
	pktio_entry_t *entry;
	odp_pktout_mode_t mode;
	int i;
	int num_queues;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", pktio);
		return -1;
	}

	mode = entry->s.param.out_mode;

	if (mode == ODP_PKTOUT_MODE_DISABLED)
		return 0;

	if (mode != ODP_PKTOUT_MODE_DIRECT)
		return -1;

	num_queues = 1;

	if (queues && num > 0)
		for (i = 0; i < num && i < num_queues; i++) {
			queues[i].outq = entry->s.outq_default;
			queues[i].pktio = pktio;
		}

	return num_queues;
}



/*
 * Receive a number of packets from a pktio device (interface mode).
 * Pktio Rx queue is initialized at first receive and volatile
 * dequeue command is executed to receive packets.
 * */
int odp_pktin_recv(odp_pktin_queue_t queue, odp_packet_t packets[], int num)
{
	unsigned pkts;
	int ret;
	pktio_entry_t *pktio_entry;
	odp_pktio_t pktio = queue.pktio;


	if (unlikely(received_sigint)) {
		odp_term_local();
		pthread_exit(NULL);
	}

	pktio_entry = get_pktio_entry(pktio);
	if(unlikely(!pktio_entry->s.rx_fq.fqid)){
		/* create HW Rx queue */
		ret = qman_create_fq(pktio_entry->s.default_fqid,
					QMAN_FQ_FLAG_NO_ENQUEUE,
					&pktio_entry->s.rx_fq);
		ret = queue_init_rx_fq(&pktio_entry->s.rx_fq, pchannel_vdq);
		if (ret < 0)
			return ret;

		pktio_entry->s.rx_fq.cb.dqrr_ctx = (void *)dqrr_cb_im;
		pktio_entry->s.rx_fq.cb.ern = ern_cb;
	}

	lock_entry(pktio_entry);
	pktio_entry->s.pkt_table = packets;
	qman_static_dequeue_add(sdqcr_vdq);
	pkts = do_volatile_deq(&pktio_entry->s.rx_fq, num, true);
	qman_static_dequeue_del(sdqcr_vdq);
	pktio_entry->s.pkt_table = NULL;
	unlock_entry(pktio_entry);

	return pkts;
}
#if 0
odp_queue_t odp_pktio_inq_getdef(odp_pktio_t id)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);

	if (pktio_entry == NULL)
		return ODP_QUEUE_INVALID;

	return pktio_entry->s.inq_default;
}

odp_queue_t odp_pktio_outq_getdef(odp_pktio_t id)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);

	if (pktio_entry == NULL)
		return ODP_QUEUE_INVALID;

	return pktio_entry->s.outq_default;
}
#endif
/*
 * Transmit a number of packets from a pktio device.
 * */
int odp_pktout_send(odp_pktout_queue_t queue, const odp_packet_t packets[],
			int num)
{
	int ret;
	int i = 0;
	odp_queue_t outq = queue.outq;
	queue_entry_t *qentry = queue_to_qentry(outq);
	odp_packet_t pkt;

	while (i < num) {
		pkt = packets[i];

		ret = pktout_enqueue(qentry,
					(odp_buffer_hdr_t *)(odp_packet_hdr(pkt)));
		if (odp_unlikely(ret))
			break; /* free the buffer */
		i++;
	} /* end while */
	return i;
}

static inline size_t odp_pkt_get_len(odp_buffer_hdr_t *buf_hdr)
{
	return ((odp_packet_hdr_t *)(buf_hdr))->frame_len;
}

static inline uint32_t odp_buf_get_bpid(odp_buffer_hdr_t *buf_hdr)
{
	return buf_hdr->handle.pool_id;
}

/* Enqueue a buffer for transmission */
int pktout_enqueue(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr)
{
	size_t len, off;
	struct qm_fd fd;
	odp_queue_t inq;
	queue_entry_t *in_qentry = NULL;
	int ret;

	len = odp_pkt_get_len(buf_hdr);
	off = GET_PRS_RESULT(buf_hdr)->eth_off +
		((odp_packet_hdr_t *)(buf_hdr))->headroom;
	inq = buf_hdr->inq;

	__config_fd(&fd, buf_hdr, off, len, qentry);

	if (inq != ODP_QUEUE_INVALID) {
		in_qentry = queue_to_qentry(inq);
	} else {
retry:
		/* pktio burst mode */
		ret = qman_enqueue(&qentry->s.fq, &fd, 0);
		if (ret) {
			cpu_spin(CPU_BACKOFF_CYCLES);
			goto retry;
		}
		return ret;
	}

	return queue_enqueue_tx_fq(&qentry->s.fq, &fd, buf_hdr, in_qentry);
}

/* no dequeue from PKTOUT queues */
odp_buffer_hdr_t *pktout_dequeue(queue_entry_t *qentry)
{
	(void)qentry;
	return NULL;
}

int pktout_enq_multi(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr[],
			int num)
{
	int nbr = 0;
	int i;

	for (i = 0; i < num; ++i)
		if (pktout_enqueue(qentry, buf_hdr[i]) == 0)
			nbr++;

	return nbr;
}

/* no dequeue from PKTOUT queues */
int pktout_deq_multi(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr[],
			int num)
{
	(void)qentry;
	(void)buf_hdr;
	(void)num;
	return 0;
}

/* no direct enqueue to PKTIN queue*/
int pktin_enqueue(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr)
{
	(void)qentry, (void)buf_hdr;
	return -1;
}

odp_buffer_hdr_t *pktin_dequeue(queue_entry_t *qentry)
{
	/* no direct dequeue from HW sched PKTIN queue */

	pktio_entry_t *pktio_entry = get_pktio_entry(qentry->s.pktin);
	assert(pktio_entry);
	odp_packet_t pkt = ODP_PACKET_INVALID;

	lock_entry(pktio_entry);
	pktio_entry->s.pkt_table = &pkt;
	qman_static_dequeue_add(sdqcr_vdq);
	assert(qentry->s.fq.cb.dqrr_ctx == dqrr_cb_poll_pktin);
	do_volatile_deq(&qentry->s.fq, 1, true);
	qman_static_dequeue_del(sdqcr_vdq);
	pktio_entry->s.pkt_table = NULL;
	unlock_entry(pktio_entry);

	if (pkt != ODP_PACKET_INVALID)
		return odp_buf_to_hdr(_odp_packet_to_buffer(pkt));

	return NULL;
}

/* no direct enqueue to PKTIN queue*/
int pktin_enq_multi(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr[], int num)
{
	(void)qentry, (void)buf_hdr, (void)num;
	return -1;
}

int pktin_deq_multi(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr[], int num)
{
	int i, ret = 0;
	for (i = 0; i < num; i++) {
		buf_hdr[ret] = pktin_dequeue(qentry);
		if (buf_hdr[ret])
			ret++;
	}
	return ret;
}

void odp_pktio_param_init(odp_pktio_param_t *params)
{
	memset(params, 0, sizeof(odp_pktio_param_t));
}

void odp_pktin_queue_param_init(odp_pktin_queue_param_t *param)
{
	memset(param, 0, sizeof(odp_pktin_queue_param_t));
	param->op_mode = ODP_PKTIO_OP_MT;
	param->num_queues = 1;
	/* no need to choose queue type since pktin mode defines it */
	odp_queue_param_init(&param->queue_param);
}

void odp_pktout_queue_param_init(odp_pktout_queue_param_t *param)
{
	memset(param, 0, sizeof(odp_pktout_queue_param_t));
	param->op_mode = ODP_PKTIO_OP_MT;
	param->num_queues = 1;
}

int odp_pktio_stats(odp_pktio_t pktio ODP_UNUSED,
			odp_pktio_stats_t *stats)
{
	/*TODO: API needs to be implemented. Currently stats are
		set to 0.*/
	memset(stats, 0, sizeof(odp_pktio_stats_t));
	return 0;
}

int odp_pktio_index(odp_pktio_t pktio)
{
	pktio_entry_t *entry = get_pktio_entry(pktio);

	if (!entry || is_free(entry))
		return -1;

	return pktio_to_id(pktio);
}

void odp_pktio_config_init(odp_pktio_config_t *config)
{
	memset(config, 0, sizeof(odp_pktio_config_t));
}

int odp_pktio_info(odp_pktio_t hdl, odp_pktio_info_t *info)
{
	pktio_entry_t *entry;

	entry = get_pktio_entry(hdl);

	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", hdl);
		return -1;
	}

	memset(info, 0, sizeof(odp_pktio_info_t));
	info->name = entry->s.name;
	/* Driver name need to be updated*/
	info->drv_name = NULL;
	info->pool = entry->s.pool;
	memcpy(&info->param, &entry->s.param, sizeof(odp_pktio_param_t));

	return 0;
}

/* Apply PCD configuration on port */
static inline int set_port_pcd(netcfg_port_info  *port_info, uint8_t pcd_support)
{
	int ret = 0;

	port_info->config_pcd = true;
	/* Set port info parse params */
	port_info->prs_param.parsingOffset = 0;
	port_info->prs_param.prsResultPrivateInfo = 0;
	port_info->prs_param.firstPrsHdr = HEADER_TYPE_ETH;

	/* Set port info pcd params */
	port_info->pcd_param.p_CcParams = NULL;
	port_info->pcd_param.pcdSupport = pcd_support;
	port_info->pcd_param.p_KgParams = &port_info->kg_param;
	port_info->pcd_param.p_PrsParams = &port_info->prs_param;

	/* FM PORT Disable */
	ret = FM_PORT_Disable(port_info->port_handle);
	if (ret != E_OK) {
		ODP_ERR("FM_PORT_Disable: Failed, Mac-idx %d\n", port_info->p_cfg->fman_if->mac_idx);
		return ret;
	}

	/* FM PORT SetPCD */
	ret = FM_PORT_SetPCD(port_info->port_handle, &port_info->pcd_param);
	if (ret != E_OK) {
		ODP_ERR("FM_PORT_SetPCD: Failed, Mac-idx %d\n", port_info->p_cfg->fman_if->mac_idx);
		return ret;
	}

	/* FM PORT Enable */
	ret = FM_PORT_Enable(port_info->port_handle);
	if (ret != E_OK) {
		ODP_ERR("FM_PORT_Enable: Failed, Mac-idx %d\n", port_info->p_cfg->fman_if->mac_idx);
		return ret;
	}

	return 0;
}

static inline struct scheme_info *get_free_scheme(netcfg_port_info  *port_info)
{
	int i = 0;

	for (i = 0; i < FMC_SCHEMES_NUM; i++) {
		if (!port_info->scheme[i].taken) {
			memset(&port_info->scheme[i], 0, sizeof(port_info->scheme[i]));
			port_info->scheme[i].taken = 1;
			return &port_info->scheme[i];
		}
	}

	return NULL;
}

/* Set scheme params for hash distribution */
static inline int set_scheme_params(struct scheme_info *scheme, netcfg_port_info  *port_info,
				    uint8_t next_engine, unsigned int num_queue, bool hash_enable)
{
	int i, j = 0, k;

	/* Memset scheme priv params */
	memset(&scheme->priv.params, 0, sizeof(scheme->priv.params));

	scheme->priv.prio = 0;
	scheme->priv.queue_count = num_queue;
	scheme->priv.qos_key_idx = -1;
	scheme->priv.params.useHash = hash_enable;
	scheme->priv.is_default = true;
	scheme->priv.params.modify = false;
	scheme->priv.params.alwaysDirect = false;
	scheme->priv.params.schemeCounter.update = 1;
	scheme->priv.params.schemeCounter.value = 0;
	scheme->priv.params.nextEngine = next_engine;
	scheme->priv.params.baseFqid = port_info->first_fqid;
	scheme->priv.params.netEnvParams.h_NetEnv = port_info->net_env_set;
	scheme->priv.params.netEnvParams.numOfDistinctionUnits = port_info->dist_units.numOfDistinctionUnits;

	scheme->priv.params.keyExtractAndHashParams.hashDistributionNumOfFqids = num_queue;
	scheme->priv.params.keyExtractAndHashParams.numOfUsedExtracts = 2 * port_info->dist_units.numOfDistinctionUnits;

	for (i = 0; i < port_info->dist_units.numOfDistinctionUnits; i++) {
		switch (port_info->dist_units.units[i].hdrs[0].hdr) {

		case HEADER_TYPE_IPv4:
			for (k = 0; k < 2; k++) {
				scheme->priv.params.keyExtractAndHashParams.extractArray[j].type = e_FM_PCD_EXTRACT_BY_HDR;
				scheme->priv.params.keyExtractAndHashParams.extractArray[j].extractByHdr.hdr = HEADER_TYPE_IPv4;
				scheme->priv.params.keyExtractAndHashParams.extractArray[j].extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
				scheme->priv.params.keyExtractAndHashParams.extractArray[j].extractByHdr.type = e_FM_PCD_EXTRACT_FULL_FIELD;
				if (k == 0)
					scheme->priv.params.keyExtractAndHashParams.extractArray[j].
							extractByHdr.extractByHdrType.fullField.ipv4 = NET_HEADER_FIELD_IPv4_SRC_IP;
				else
					scheme->priv.params.keyExtractAndHashParams.extractArray[j].
							extractByHdr.extractByHdrType.fullField.ipv4 = NET_HEADER_FIELD_IPv4_DST_IP;
				j++;
			}
			break;
		case HEADER_TYPE_IPv6:
			for (k = 0; k < 2; k++) {
				scheme->priv.params.keyExtractAndHashParams.extractArray[j].type = e_FM_PCD_EXTRACT_BY_HDR;
				scheme->priv.params.keyExtractAndHashParams.extractArray[j].extractByHdr.hdr = HEADER_TYPE_IPv6;
				scheme->priv.params.keyExtractAndHashParams.extractArray[j].extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
				scheme->priv.params.keyExtractAndHashParams.extractArray[j].extractByHdr.type = e_FM_PCD_EXTRACT_FULL_FIELD;
				if (k == 0)
					scheme->priv.params.keyExtractAndHashParams.extractArray[j].
							extractByHdr.extractByHdrType.fullField.ipv6 = NET_HEADER_FIELD_IPv6_SRC_IP;
				else
					scheme->priv.params.keyExtractAndHashParams.extractArray[j].
							extractByHdr.extractByHdrType.fullField.ipv6 = NET_HEADER_FIELD_IPv6_DST_IP;
				j++;
			}
			break;

		case HEADER_TYPE_UDP:
			for (k = 0; k < 2; k++) {
				scheme->priv.params.keyExtractAndHashParams.extractArray[j].type = e_FM_PCD_EXTRACT_BY_HDR;
				scheme->priv.params.keyExtractAndHashParams.extractArray[j].extractByHdr.hdr = HEADER_TYPE_UDP;
				scheme->priv.params.keyExtractAndHashParams.extractArray[j].extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
				scheme->priv.params.keyExtractAndHashParams.extractArray[j].extractByHdr.type = e_FM_PCD_EXTRACT_FULL_FIELD;
				if (k == 0)
					scheme->priv.params.keyExtractAndHashParams.extractArray[j].
							extractByHdr.extractByHdrType.fullField.udp = NET_HEADER_FIELD_UDP_PORT_SRC;
				else
					scheme->priv.params.keyExtractAndHashParams.extractArray[j].
							extractByHdr.extractByHdrType.fullField.udp = NET_HEADER_FIELD_UDP_PORT_DST;
				j++;
			}
			break;

		case HEADER_TYPE_TCP:
			for (k = 0; k < 2; k++) {
				scheme->priv.params.keyExtractAndHashParams.extractArray[j].type = e_FM_PCD_EXTRACT_BY_HDR;
				scheme->priv.params.keyExtractAndHashParams.extractArray[j].extractByHdr.hdr = HEADER_TYPE_TCP;
				scheme->priv.params.keyExtractAndHashParams.extractArray[j].extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
				scheme->priv.params.keyExtractAndHashParams.extractArray[j].extractByHdr.type = e_FM_PCD_EXTRACT_FULL_FIELD;
				if (k == 0)
					scheme->priv.params.keyExtractAndHashParams.extractArray[j].
							extractByHdr.extractByHdrType.fullField.tcp = NET_HEADER_FIELD_TCP_PORT_SRC;
				else
					scheme->priv.params.keyExtractAndHashParams.extractArray[j].
							extractByHdr.extractByHdrType.fullField.tcp = NET_HEADER_FIELD_TCP_PORT_DST;
				j++;
			}
			break;
		default:
			ODP_ERR("Invalid Distinction Unit\n");
		}
	}

	return 0;
}

/* Set PCD NetEnv and Scheme in port info */
static inline int set_pcd_netenv_scheme(netcfg_port_info  *port_info, const odp_pktin_queue_param_t *param)
{
	int ret = -1;
	struct scheme_info *scheme;
	uint8_t next_engine = e_FM_PCD_DONE;
	t_Handle scheme_handle = NULL, net_env_handle = NULL;
	uint32_t i = 0;

	/* Set PCD NetEnvCharacteristics */
	memset(&port_info->dist_units, 0, sizeof(port_info->dist_units));

	if (param->hash_proto.proto.ipv4 || param->hash_proto.proto.ipv4_udp || param->hash_proto.proto.ipv4_tcp)
		port_info->dist_units.units[i++].hdrs[0].hdr = HEADER_TYPE_IPv4;

	if (param->hash_proto.proto.ipv6 || param->hash_proto.proto.ipv6_udp || param->hash_proto.proto.ipv6_tcp)
		port_info->dist_units.units[i++].hdrs[0].hdr = HEADER_TYPE_IPv6;

	if (param->hash_proto.proto.ipv4_udp || param->hash_proto.proto.ipv6_udp)
		port_info->dist_units.units[i++].hdrs[0].hdr = HEADER_TYPE_UDP;

	if (param->hash_proto.proto.ipv4_tcp || param->hash_proto.proto.ipv6_tcp)
		port_info->dist_units.units[i++].hdrs[0].hdr = HEADER_TYPE_TCP;

	/* Set Default value to IPv4 */
	if (!param->hash_proto.all_bits)
		port_info->dist_units.units[i++].hdrs[0].hdr = HEADER_TYPE_IPv4;

	/* Dist units is set to i */
	port_info->dist_units.numOfDistinctionUnits = i;

	/* FM PCD NetEnvCharacteristicsSet */
	net_env_handle = FM_PCD_NetEnvCharacteristicsSet(port_info->pcd_handle, &port_info->dist_units);
	if (!net_env_handle) {
		ODP_ERR("FM_PCD_NetEnvCharacteristicsSet: Failed Mac-idx = %d\n",
			port_info->p_cfg->fman_if->mac_idx);
		return -1;
	}
	port_info->pcd_param.h_NetEnv = net_env_handle;
	port_info->net_env_set = net_env_handle;

	/* Set PCD Scheme */
	INIT_LIST_HEAD(&port_info->scheme_list);

	scheme = get_free_scheme(port_info);
	if (!scheme) {
		ODP_ERR("No free scheme available\n");
		return -1;
	}

	/* Set Scheme params */
	ret = set_scheme_params(scheme, port_info, next_engine, param->num_queues, param->hash_enable);
	if (ret) {
		ODP_ERR("Set scheme params: Failed, Mac-idx %d\n",
			port_info->p_cfg->fman_if->mac_idx);
		return ret;
	}

	/* Add scheme to the scheme list */
	list_add_tail(&scheme->scheme_node, &port_info->scheme_list);
	port_info->scheme_count++;

	scheme->priv.params.id.relativeSchemeId = port_info->p_cfg->fman_if->mac_idx - 1;
	scheme->id = port_info->p_cfg->fman_if->mac_idx - 1;

	/* FM PCD KgSchemeSet */
	scheme_handle = FM_PCD_KgSchemeSet(port_info->pcd_handle, &scheme->priv.params);
	if (!scheme_handle) {
		ODP_ERR("FM_PCD_KgSchemeSet: Failed, Mac-idx %d\n",
			port_info->p_cfg->fman_if->mac_idx);
		return -1;
	}

	scheme->handle = scheme_handle;

	port_info->kg_param.numOfSchemes = port_info->scheme_count;
	/* One scheme used per port */
	port_info->kg_param.h_Schemes[0] = scheme_handle;

	return 0;
}

static inline int set_fm_port_handle(netcfg_port_info  *port_info)
{
	t_FmPortParams	fm_port_params;

	/* FMAN mac indexes mappings */
	uint8_t mac_idx[] = {-1, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1};

	/* Memset FM port params */
	memset(&fm_port_params, 0, sizeof(fm_port_params));

	/* Set FM port params */
	fm_port_params.h_Fm = port_info->fman_handle;
	fm_port_params.portType = GET_PORT_TYPE(port_info->p_cfg->fman_if);
	fm_port_params.portId = mac_idx[port_info->p_cfg->fman_if->mac_idx];

	/* FM PORT Open */
	port_info->port_handle = FM_PORT_Open(&fm_port_params);
	if (!port_info->port_handle) {
		ODP_ERR("FM_PORT_Open: Failed, Mac-idx = %d\n",
			port_info->p_cfg->fman_if->mac_idx);
		return -1;
	}

	return 0;
}

/* Configure FM Port for pktio passed for hash distribution */
int pktio_fm_config(odp_pktio_t pktio, const odp_pktin_queue_param_t *param)
{
	pktio_entry_t *pktio_entry;
	netcfg_port_info  *port_info;
	/* PCD support for hash distribution */
	uint8_t pcd_support = e_FM_PORT_PCD_SUPPORT_PRS_AND_KG;
	int ret;

	pktio_entry = get_pktio_entry(pktio);
	port_info = pktio_get_port_info(pktio_entry->s.__if);

	/* Open FM Port and set it in port info */
	ret = set_fm_port_handle(port_info);
	if (ret) {
		ODP_ERR("Set FM Port handle: Failed, Mac-idx = %d\n",
			port_info->p_cfg->fman_if->mac_idx);
		return -1;
	}

	/* Set PCD netenv and scheme */
	ret = set_pcd_netenv_scheme(port_info, param);
	if (ret) {
		ODP_ERR("Set PCD NetEnv and Scheme: Failed, Mac-idx = %d\n",
			port_info->p_cfg->fman_if->mac_idx);
		return -1;
	}

	/* Set Port PCD */
	ret = set_port_pcd(port_info, pcd_support);
	if (ret) {
		ODP_ERR("Set Port PCD: Failed, Mac-idx = %d\n",
			port_info->p_cfg->fman_if->mac_idx);
		return -1;
	}

	return 0;
}

/* De-Configure Pktio FM */
int pktio_fm_deconfig(odp_pktio_t pktio)
{
	pktio_entry_t *pktio_entry;
	netcfg_port_info  *port_info;
	int ret;

	pktio_entry = get_pktio_entry(pktio);
	port_info = pktio_get_port_info(pktio_entry->s.__if);

	/* FM PORT Disable */
	ret = FM_PORT_Disable(port_info->port_handle);
	if (ret != E_OK) {
		ODP_ERR("FM_PORT_Disable: Failed, Mac-idx %d\n", port_info->p_cfg->fman_if->mac_idx);
		return ret;
	}

	/* FM PORT DeletePCD */
	ret = FM_PORT_DeletePCD(port_info->port_handle);
	if (ret != E_OK) {
		ODP_ERR("FM_PORT_DeletePCD: Failed, Mac-idx %d\n", port_info->p_cfg->fman_if->mac_idx);
		return ret;
	}

	/* FM PCD KgSchemeDelete */
	ret = FM_PCD_KgSchemeDelete(port_info->kg_param.h_Schemes[0]);
	if (ret != E_OK) {
		ODP_ERR("FM_PCD_KgSchemeDelete: Failed, Mac-idx %d\n", port_info->p_cfg->fman_if->mac_idx);
		return ret;
	}

	/* FM PCD NetEnvCharacteristicsDelete */
	ret = FM_PCD_NetEnvCharacteristicsDelete(port_info->net_env_set);
	if (ret != E_OK) {
		ODP_ERR("FM_PCD_NetEnvCharacteristicsDelete: Failed, Mac-idx %d\n", port_info->p_cfg->fman_if->mac_idx);
		return ret;
	}
}

/* One time configuration of FM for hash distribution */
int pktio_fm_init(void)
{
	t_Handle fman_handle;
	t_Handle pcd_handle;
	t_FmPcdParams fmPcdParams = {0};
	/* Hard-coded : fman id 0 since one fman is present in LS104x */
	int fman_id = 0, ret, i;
	struct fm_eth_port_cfg *port_cfg;
	netcfg_port_info  *port_info;

	/* FM Open */
	fman_handle = FM_Open(fman_id);
	if (!fman_handle) {
		ODP_ERR("FM_Open: Failed\n");
		return -1;
	}

	/* FM PCD Open */
	fmPcdParams.h_Fm = fman_handle;
	fmPcdParams.prsSupport = TRUE;
	fmPcdParams.kgSupport = TRUE;
	pcd_handle = FM_PCD_Open(&fmPcdParams);
	if (!pcd_handle) {
		ODP_ERR("FM_PCD_Open: Failed\n");
		FM_Close(fman_handle);
		return -1;
	}

	/* FM PCD Enable */
	ret = FM_PCD_Enable(pcd_handle);
	if (ret) {
		ODP_ERR("FM_PCD_Enable: Failed\n");
		FM_PCD_Close(pcd_handle);
		FM_Close(fman_handle);
		return -1;
	}

	/* Set fman and pcd handle in port info */
	for (i = 0; i < netcfg->num_ethports; i++) {
		port_cfg = &netcfg->port_cfg[i];
		port_info = pktio_get_port_info(port_cfg->fman_if);

		port_info->fman_handle = fman_handle;
		port_info->pcd_handle = pcd_handle;
	}

	return 0;
}

/* De-initialization of FM */
int pktio_fm_term(void)
{
	t_Handle fman_handle = NULL;
	t_Handle pcd_handle = NULL;
	int ret, i;
	struct fm_eth_port_cfg *port_cfg;
	netcfg_port_info  *port_info;

	/* Set fman and pcd handle in port info to NULL */
	for (i = 0; i < netcfg->num_ethports; i++) {
		port_cfg = &netcfg->port_cfg[i];
		port_info = pktio_get_port_info(port_cfg->fman_if);

		if (!fman_handle)
			fman_handle = port_info->fman_handle;
		if (!pcd_handle)
			pcd_handle = port_info->pcd_handle;

		port_info->fman_handle = NULL;
		port_info->pcd_handle = NULL;
	}

	/* FM PCD Disable */
	ret = FM_PCD_Disable(pcd_handle);
	if (ret) {
		ODP_ERR("FM_PCD_Disable: Failed\n");
		return -1;
	}

	/* FM PCD Close */
	FM_PCD_Close(pcd_handle);

	/* FM Close */
	FM_Close(fman_handle);

	return 0;
}

int odp_pktio_config(odp_pktio_t id ODP_UNUSED, const odp_pktio_config_t *config ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return -1;
}

void odp_pktio_print(odp_pktio_t id ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
}

int odp_pktin_recv_tmo(odp_pktin_queue_t queue ODP_UNUSED, odp_packet_t packets[] ODP_UNUSED,
						int num ODP_UNUSED, uint64_t wait ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}
int odp_pktin_recv_mq_tmo(const odp_pktin_queue_t queues[] ODP_UNUSED, unsigned num_q ODP_UNUSED,
					unsigned *from ODP_UNUSED, odp_packet_t packets[] ODP_UNUSED,
							int num ODP_UNUSED, uint64_t wait ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_pktio_link_status(odp_pktio_t id ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return -1;
}
uint64_t odp_pktin_wait_time(uint64_t nsec ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

uint64_t odp_pktin_ts_res(odp_pktio_t id ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

odp_time_t odp_pktin_ts_from_ns(odp_pktio_t id ODP_UNUSED, uint64_t ns ODP_UNUSED)
{
	odp_time_t ts = {0};
	ODP_UNIMPLEMENTED();
	return ts;
}

int odp_pktio_stats_reset(odp_pktio_t pktio ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return -1;
}
