/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/packet_io.h>
#include <odp_packet_io_internal.h>
#include <odp_packet_io_queue.h>
#include <odp/api/packet.h>
#include <odp_packet_internal.h>
#include <odp_internal.h>
#include <odp/api/spinlock.h>
#include <odp/api/shared_memory.h>
#include <odp_packet_dpaa2.h>
#include <odp_config_internal.h>
#include <odp_queue_internal.h>
#include <odp_schedule_internal.h>
#include <odp_crypto_internal.h>
#include <odp_classification_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/init.h>

#include <string.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <errno.h>
#include <dpaa2.h>
#include <dpaa2_time.h>
#include <dpaa2_dev.h>
#include <dpaa2_ethdev.h>
#include <dpaa2_sec_priv.h>
#include <dpaa2_ether.h>
#include <pthread.h>
#include <dpaa2_eth_priv.h>
#include <dpaa2_dev_priv.h>

#include <fsl_dpni.h>
#include <fsl_dpni_cmd.h>
#include <fsl_mc_sys.h>

#define ALL_BITS ((uint32_t)-1)
#define DEFAULT_DIST_TUPLE (DPAA2_FDIST_IP_SA | DPAA2_FDIST_IP_DA)

/* Actual mapped loopback device */
char loop_device[10];

/* VFIO container */
char container[8];

static pktio_table_t *pktio_tbl;

/* pktio pointer entries ( for inlines) */
void *pktio_entry_ptr[ODP_CONFIG_PKTIO_ENTRIES];

static void lock_entry(pktio_entry_t *entry)
{
	odp_spinlock_lock(&entry->s.lock);
}

static void unlock_entry(pktio_entry_t *entry)
{
	odp_spinlock_unlock(&entry->s.lock);
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

int odp_pktio_init_global(void)
{
	pktio_entry_t *pktio_entry;
	int64_t id, retcode;
	odp_shm_t shm;

	shm = odp_shm_reserve("odp_pktio_entries",
				    sizeof(pktio_table_t),
				    0, 0);

	pktio_tbl = odp_shm_addr(shm);
	if (pktio_tbl == NULL) {
		ODP_ERR("Error in allocating pktio table memory\n");
		return -1;
	}

	memset(pktio_tbl, 0, sizeof(pktio_table_t));

	odp_spinlock_init(&pktio_tbl->lock);

	for (id = 1; id <= ODP_CONFIG_PKTIO_ENTRIES; ++id) {
		pktio_entry = &pktio_tbl->entries[id - 1];

		odp_spinlock_init(&pktio_entry->s.lock);
		odp_spinlock_init(&pktio_entry->s.cls.lock);

		pktio_entry_ptr[id - 1] = pktio_entry;
	}

	/*Scan the device list for Ethernet devices*/
	retcode = odp_dpaa2_scan_device_list(DPAA2_NIC);
	if (!retcode) {
		ODP_ERR("Schedule init failed...\n");
		return -1;
	}
	return 0;
}
int odp_pktio_term_global(void)
{
	pktio_entry_t *pktio_entry;
	odp_pktio_t pktio;
	struct dpaa2_dev *ndev;
	int ret;
	int id;

	if (!pktio_tbl)
		return 0;
	for (id = 1; id <= ODP_CONFIG_PKTIO_ENTRIES; ++id) {

		pktio_entry = &pktio_tbl->entries[id - 1];
		if (!is_free(pktio_entry)) {
			pktio = (odp_pktio_t)(uintptr_t)id;
			ndev = pktio_entry->s.pkt_dpaa2.dev;
			odp_queue_t queue;
			odp_pktout_mode_t outmode;
			odp_pktin_mode_t inmode;

			ret = dpaa2_eth_stop(ndev);
			if (ret)
				ODP_ERR("Failed to stop pktio\n");

			outmode = pktio_entry->s.param.out_mode;
			lock_entry(pktio_entry);
			if (outmode == ODP_PKTOUT_MODE_QUEUE) {
				queue_entry_t *qentry;

				while (pktio_entry->s.conf_tx_queues) {
					queue = (odp_queue_t)dpaa2_dev_get_vq_handle(ndev->tx_vq[pktio_entry->s.conf_tx_queues - 1]);
					qentry = queue_to_qentry(queue);
					set_queue_entry_to_free(qentry);
					pktio_entry->s.conf_tx_queues--;
				}
			} else
				pktio_entry->s.conf_tx_queues = 0;

			inmode = pktio_entry->s.param.in_mode;

			if ((inmode == ODP_PKTIN_MODE_SCHED) ||
				(inmode == ODP_PKTIN_MODE_QUEUE)) {
				while (pktio_entry->s.conf_rx_queues) {
					ret = odp_pktio_inq_rem(pktio, pktio_entry->s.conf_rx_queues - 1);
					if (ret) {
						ODP_ERR("pktio %s: failed to remove already configured queues\n",
							pktio_entry->s.name);
						unlock_entry(pktio_entry);
						return -1;
					}
				}
			} else
				pktio_entry->s.conf_rx_queues = 0;

			unlock_entry(pktio_entry);
			odp_pktio_close(pktio);
		}
	}

	ret = odp_shm_free(odp_shm_lookup("odp_pktio_entries"));
	if (ret < 0)
		ODP_ERR("shm free failed for odp_pktio_entries");

	return ret;
}

int odp_pktio_init_local(void)
{
	return 0;
}

static void lock_entry_classifier(pktio_entry_t *entry)
{
	odp_spinlock_lock(&entry->s.lock);
	odp_spinlock_lock(&entry->s.cls.lock);
}

static void unlock_entry_classifier(pktio_entry_t *entry)
{
	odp_spinlock_unlock(&entry->s.cls.lock);
	odp_spinlock_unlock(&entry->s.lock);
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
	param->op_mode = ODP_PKTIO_OP_MT;
	param->num_queues = 1;
}

static void init_pktio_entry(pktio_entry_t *entry)
{
	set_taken(entry);
	entry->s.conf_rx_queues = 0;
	entry->s.conf_tx_queues = 0;
	memset(&entry->s.pkt_dpaa2, 0, sizeof(entry->s.pkt_dpaa2));
	/* Save pktio parameters, type is the most useful */
	//memcpy(&entry->s.params, params, sizeof(*params));
	pktio_classifier_init(entry);
}

static odp_pktio_t alloc_lock_pktio_entry(void)
{
	odp_pktio_t id;
	pktio_entry_t *entry;
	int i;

	for (i = 0; i < ODP_CONFIG_PKTIO_ENTRIES; ++i) {
		entry = &pktio_tbl->entries[i];
		if (is_free(entry)) {
			lock_entry_classifier(entry);
			if (is_free(entry)) {
				init_pktio_entry(entry);
				init_pktio_cls_rule_list(i);
				id = _odp_cast_scalar(odp_pktio_t, i + 1);
				return id; /* return with entry locked! */
			}
			unlock_entry_classifier(entry);
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

static int init_loop(pktio_entry_t *entry, odp_pktio_t id)
{
	char loopq_name[ODP_QUEUE_NAME_LEN];
	odp_queue_param_t param;

	entry->s.type = ODP_PKTIO_TYPE_LOOPBACK;
	snprintf(loopq_name, sizeof(loopq_name), "%" PRIu64 "-pktio_loopq",
		 odp_pktio_to_u64(id));
	odp_queue_param_init(&param);
	entry->s.loopq = odp_queue_create(loopq_name, &param);
	if (entry->s.loopq == ODP_QUEUE_INVALID) {
		ODP_ERR("Unable to create queue for loop device\n");
		return -1;
	}

	return 0;
}

static void odp_hash_dist(odp_pktio_t pktio,
				const odp_pktin_queue_param_t *q_param)
{
	struct dpaa2_dev *ndev;
	pktio_entry_t *pktio_entry;
	uint32_t i, dist_tuple;
	int32_t ret;
	struct queues_config *q_config;

	pktio_entry = get_pktio_entry(pktio);
	if (!pktio_entry)
		return;

	ndev = pktio_entry->s.pkt_dpaa2.dev;
	q_config = dpaa2_eth_get_queues_config(ndev);

	/* Set default hash protocol as IPv4/IPv6
	*  if no hash protocol is given by user
	*  */
	dist_tuple = DEFAULT_DIST_TUPLE;

	/* Adding support for Rx Side distribution.
	*
	* TODO: Handling of failure needs to be done while
	* configuring for multiple TCs, and failures of any in
	* between TC while configuring multiple TCs.
	*
	* Note: There is common configuration fo ipv4/ipv6 protocols.
	* When user configures ipv4 protocol, ipv6 will also be
	* enabled and vice versa.
	* Separate configurations to be provided for ipv4 and ipv6
	* protocols when support is added in MC.
	* */
	for (i = 0; i < q_config->num_tcs; i++) {
		if (q_param->hash_proto.all_bits == ALL_BITS) {
			/* All hash protocols are to be enabled */
			dist_tuple = dist_tuple |
				     DPAA2_FDIST_TCP_SP | DPAA2_FDIST_TCP_DP |
				     DPAA2_FDIST_UDP_SP | DPAA2_FDIST_UDP_DP;
		} else {
			if (q_param->hash_proto.proto.ipv4_udp ||
				q_param->hash_proto.proto.ipv6_udp)
				dist_tuple = dist_tuple | DPAA2_FDIST_UDP_SP |
						DPAA2_FDIST_UDP_DP;
			if (q_param->hash_proto.proto.ipv4_tcp ||
				q_param->hash_proto.proto.ipv6_tcp)
				dist_tuple = dist_tuple | DPAA2_FDIST_TCP_SP |
					     DPAA2_FDIST_TCP_DP;
		}

		ret = dpaa2_eth_setup_flow_distribution(ndev,
					dist_tuple,
					i,
					q_param->num_queues);

		if (ret) {
			ODP_ERR("Fail to configure RX dist\n");
			return;
		}
	}

	ODP_PRINT("Configured RX dist! 0x%X\n", dist_tuple);

	return;
}

odp_pktio_t odp_pktio_open(const char *name, odp_pool_t pool,
				const odp_pktio_param_t *param)
{
	odp_pktio_t id;
	pktio_entry_t *pktio_entry;
	struct dpaa2_dev *ndev;
	int ret, loop_dev = 0;
	pool_entry_t *phandle = (pool_entry_t *)pool;

        if (!(strcmp(name, "loop"))) {
                strcpy(container, vfio_container);
                strcpy(loop_device, "LOOP_IF_");
                strtok(container, ".");
                strcat(loop_device, strtok(NULL, "."));

                name = getenv(loop_device);
                if (!name) {
                        ODP_ERR("Unable to find loop device");
                        return ODP_PKTIO_INVALID;
                }
                loop_dev = 1;
                ODP_DBG("%s is mapped to loop device\n", name);
        }

	id = odp_pktio_lookup(name);
	if (id != ODP_PKTIO_INVALID) {
		/* interface is already open */
		__odp_errno = EEXIST;
		return ODP_PKTIO_INVALID;
	}

	ODP_DBG("Allocating dpaa2 pktio\n");

	if (strlen(name) >= IFNAMSIZ) {
		/* ioctl names limitation */
		ODP_ERR("pktio name %s is too big, limit is %d bytes\n",
			name, IFNAMSIZ);
		return ODP_PKTIO_INVALID;
	}

	ndev = odp_get_dpaa2_eth_dev(name);
	if (!ndev) {
		ODP_ERR("unable to find dpaa2_dev %s", name);
		return ODP_PKTIO_INVALID;
	}

	ret = dpaa2_eth_open(ndev);
	if (ret)
		return ODP_PKTIO_INVALID;

	/* if successful, alloc_lock_pktio_entry() returns with the entry locked */
	id = alloc_lock_pktio_entry();
	if (id == ODP_PKTIO_INVALID) {
		ODP_ERR("No resources available.\n");
		goto setup_failure;
	}

	pktio_entry = get_pktio_entry(id);
	if (!pktio_entry)
		goto setup_failure;

	if (loop_dev) {
		ret = init_loop(pktio_entry, id);
		if (ret) {
			free_pktio_entry(id);
			goto setup_failure;
		}
	}

	pktio_entry->s.pkt_dpaa2.dev = ndev;
	ndev->pktio = (uint64_t)id;
	if (param)
		memcpy(&pktio_entry->s.param, param, sizeof(odp_pktio_param_t));
	else
		odp_pktio_param_init(&pktio_entry->s.param);

	ret = dpaa2_eth_attach_bp_list(ndev, (void *)(phandle->s.int_hdl));
	if (ret < 0) {
		unlock_entry_classifier(pktio_entry);
		free_pktio_entry(id);
		ODP_ERR("Unable to init any I/O type.\n");
		goto setup_failure;
	}

	pktio_entry->s.pkt_dpaa2.pool = pool;
	snprintf(pktio_entry->s.name, IFNAMSIZ, "%s", name);
	pktio_entry->s.pktio_headroom = ODP_CONFIG_PACKET_HEADROOM;
	unlock_entry_classifier(pktio_entry);

	return id;

setup_failure:
	ret = dpaa2_eth_close(ndev);
	if (ret)
		ODP_ERR("Failed to close the device\n");
	return ODP_PKTIO_INVALID;
}

int odp_pktio_start(odp_pktio_t pktio)
{
	pktio_entry_t *entry;
	int ret;

	entry = get_pktio_entry(pktio);
	if (entry == NULL)
		return -1;
	lock_entry(entry);
	if (entry) {
		ret = start_pkt_dpaa2(&entry->s.pkt_dpaa2);
		if (DPAA2_FAILURE == ret) {
			ODP_ERR("Unable to start pktio\n");
			unlock_entry(entry);
			return -1;
		}
	}
	unlock_entry(entry);
	return 0;
}

int odp_pktio_stop(odp_pktio_t pktio)
{
	pktio_entry_t *entry;
	int ret;

	entry = get_pktio_entry(pktio);
	if (entry == NULL)
		return -1;
	lock_entry(entry);
	if (entry) {
		ret = close_pkt_dpaa2(&entry->s.pkt_dpaa2);
		if (DPAA2_FAILURE == ret) {
			ODP_ERR("Unable to stop pktio\n");
			unlock_entry(entry);
			return -1;
		}
	}
	unlock_entry(entry);
	return 0;
}

int odp_pktio_close(odp_pktio_t id)
{
	struct dpaa2_dev *ndev;
	pktio_entry_t *entry;
	struct dpaa2_dev_priv *dev_priv;
	int res = -1;

	entry = get_pktio_entry(id);
	if (entry == NULL)
		return -1;

	ndev = entry->s.pkt_dpaa2.dev;
	dev_priv = ndev->priv;

	if (!dev_priv->hw) {
		ODP_DBG("pktio already closed\n");
		return 0;
	}

	lock_entry(entry);
	if (!is_free(entry)) {
		res  = close_pkt_dpaa2(&entry->s.pkt_dpaa2);
		if (entry->s.type == ODP_PKTIO_TYPE_LOOPBACK)
			res |= odp_queue_destroy(entry->s.loopq);

		res |= free_pktio_entry(id);
	}

	res |= dpaa2_eth_close(ndev);
	if (res)
		ODP_ERR("pktio cleanup failed\n");

	/*Free allocated memories*/
	dpaa2_data_free((void *)(entry->s.priv));
	dpaa2_data_free((void *)(entry->s.cls.tc_cfg.key_cfg_iova));
	unlock_entry(entry);

	if (res != 0)
		return -1;

	return 0;
}
odp_pktio_t odp_pktio_lookup(const char *name)
{
	odp_pktio_t id = ODP_PKTIO_INVALID;
	pktio_entry_t *entry;
	int i;

	if (!(strcmp(name, "loop"))) {
		name = getenv(loop_device);
		if (!name) {
			ODP_ERR("Unable to find loop device");
			return ODP_PKTIO_INVALID;
		}
		ODP_DBG("%s is mapped to loop device\n", name);
	}

	odp_spinlock_lock(&pktio_tbl->lock);

	for (i = 1; i <= ODP_CONFIG_PKTIO_ENTRIES; ++i) {
		entry = get_pktio_entry(_odp_cast_scalar(odp_pktio_t, i));
		if (entry && is_free(entry))
			continue;

		lock_entry(entry);

		if (!is_free(entry) &&
		    strncmp(entry->s.name, name, IFNAMSIZ) == 0)
			id = _odp_cast_scalar(odp_pktio_t, i);

		unlock_entry(entry);

		if (id != ODP_PKTIO_INVALID)
			break;
	}

	odp_spinlock_unlock(&pktio_tbl->lock);

	return id;
}

extern int32_t dpaa2_eth_recv(struct dpaa2_dev *dev,
			void *vq,
			uint32_t num,
			dpaa2_mbuf_pt mbuf[]);

/**
 * Receive packets using dpaa2
 */
static inline int recv_pkt_dpaa2(odp_packet_t pkt_table[],
				unsigned len, queue_entry_t *qentry)
{
	return dpaa2_eth_recv(NULL, qentry->s.priv, len, pkt_table);
}

int odp_pktin_recv(odp_pktin_queue_t queue, odp_packet_t pkt_table[], int len)
{
	/* If ctrl+C signal is received, just exit the thread */
	if (odp_unlikely(received_sigint)) {
		if (odp_term_local() < 0)
			fprintf(stderr, "error: odp_term_local() failed.\n");
		pthread_exit(NULL);
	}

	if (!queue)
		return -1;

	return dpaa2_eth_recv(NULL, (void *)queue, len, pkt_table);
}

int odp_pktout_send(odp_pktout_queue_t queue, const odp_packet_t pkt_table[], int len)
{
	int pkts;

	pkts = dpaa2_eth_xmit(((struct dpaa2_vq *)queue)->dev, (struct dpaa2_vq *) queue, len, pkt_table);

	return pkts;
}

int odp_pktio_inq_set(odp_pktio_t id, queue_entry_t *qentry, uint8_t vq_id)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);
	struct dpaa2_dev *ndev;
	int retcode;

	if (!pktio_entry || !qentry)
		return -1;

	queue_lock(qentry);
	ndev = pktio_entry->s.pkt_dpaa2.dev;

	qentry->s.pktin = id;
	qentry->s.pktout = id;
	qentry->s.status = QUEUE_STATUS_READY;
	qentry->s.priv = ndev->rx_vq[vq_id];
	qentry->s.enqueue = queue_enq_dummy;
	qentry->s.enqueue_multi = queue_enq_multi_dummy;
	dpaa2_dev_set_vq_handle(ndev->rx_vq[vq_id], (uint64_t)qentry->s.handle);
	if (qentry->s.param.type == ODP_QUEUE_TYPE_SCHED) {
		qentry->s.dequeue = queue_deq_dummy;
		qentry->s.dequeue_multi = queue_deq_multi_dummy;
		odp_schedule_queue(qentry, qentry->s.param.sched.prio, vq_id);
		qentry->s.status = QUEUE_STATUS_SCHED;
	} else {
		qentry->s.dequeue = pktin_dequeue;
		qentry->s.dequeue_multi = pktin_deq_multi;
		retcode = dpaa2_eth_setup_rx_vq(ndev, vq_id, NULL);
		if (DPAA2_FAILURE == retcode) {
			ODP_ERR("Fail to setup RX VQ\n");
			return -1;
		}
	}
	queue_unlock(qentry);
	pktio_entry->s.conf_rx_queues += 1;

	return 0;
}

int odp_pktio_inq_rem(odp_pktio_t id, uint8_t vq_id)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);
	struct dpaa2_dev *ndev;
	queue_entry_t *qentry;
	odp_queue_t queue;
	int ret;

	if (pktio_entry == NULL)
		return -1;

	ndev = pktio_entry->s.pkt_dpaa2.dev;

	queue = (odp_queue_t)dpaa2_dev_get_vq_handle(ndev->rx_vq[vq_id]);

	qentry = queue_to_qentry(queue);
	queue_lock(qentry);

	if (qentry->s.status == QUEUE_STATUS_FREE) {
		queue_unlock(qentry);
		return -1;
	}

	qentry->s.dequeue = queue_deq_dummy;
	qentry->s.dequeue_multi = queue_deq_multi_dummy;
	qentry->s.enqueue = queue_enq_dummy;
	qentry->s.enqueue_multi = queue_enq_multi_dummy;
	qentry->s.status = QUEUE_STATUS_NOTSCHED;
	qentry->s.pktin = ODP_PKTIO_INVALID;
	qentry->s.priv = NULL;
	if (qentry->s.param.type == ODP_QUEUE_TYPE_SCHED) {
		struct dpaa2_dev_priv *dev_priv = ndev->priv;
		struct fsl_mc_io *dpni = dev_priv->hw;
		struct dpaa2_vq *vq = ndev->rx_vq[vq_id];

		if (vq->sync == ODP_SCHED_SYNC_ORDERED) {
			struct opr_cfg cfg;

			/*XXX API may return error in case setting the opr on TC rather than on a queue*/
			ret = dpni_set_opr(dpni, CMD_PRI_LOW, dev_priv->token,
						vq->tc_index, vq->flow_id, OPR_OPT_RETIRE, &cfg);
			if (ret) {
				DPAA2_ERR(ETH, "Error in queue retire: ErrorCode = %d\n",
										ret);
				return DPAA2_FAILURE;
			}
		}
		ret = odp_sub_queue_to_group(qentry->s.param.sched.group);
		if (!ret)
			odp_deaffine_group(qentry->s.param.sched.group, NULL);
	}
	qentry->s.status = QUEUE_STATUS_FREE;

	queue_unlock(qentry);
	pktio_entry->s.conf_rx_queues -= 1;

	return 0;
}

int pktout_enqueue(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr)
{
	odp_packet_t pkt = _odp_packet_from_buffer((odp_buffer_t) buf_hdr);
	int len = 1;
	int nbr;
	pktio_entry_t *pktio_entry;
	struct dpaa2_dev *ndev;

	pktio_entry = get_pktio_entry(qentry->s.pktout);
	if (pktio_entry == NULL)
		return -1;
	ndev = pktio_entry->s.pkt_dpaa2.dev;
	nbr = dpaa2_eth_xmit(ndev, qentry->s.priv, len, &pkt);

	return (nbr == len ? 0 : -1);
}

int pktout_enq_multi(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr[],
		     int num)
{
	odp_packet_t pkt_tbl[QUEUE_MULTI_MAX];
	int nbr, i;
	pktio_entry_t *pktio_entry;
	struct dpaa2_dev *ndev;

	pktio_entry = get_pktio_entry(qentry->s.pktout);
	if (pktio_entry == NULL)
		return -1;

	for (i = 0; i < num; ++i)
		pkt_tbl[i] = _odp_packet_from_buffer((odp_buffer_t) buf_hdr[i]);

	ndev = pktio_entry->s.pkt_dpaa2.dev;
	nbr = dpaa2_eth_xmit(ndev, qentry->s.priv, num, pkt_tbl);
	return nbr;
}

int pktin_enqueue(queue_entry_t *qentry,
		  odp_buffer_hdr_t *buf_hdr)
{
	odp_packet_t pkt = _odp_packet_from_buffer((odp_buffer_t)buf_hdr);
	int len = 1;
	int nbr;

	nbr = dpaa2_eth_xmit_fqid(qentry->s.priv, len, &pkt);

	return (nbr == len ? 0 : -1);
}

odp_buffer_hdr_t *pktin_dequeue(queue_entry_t *qentry)
{
	dpaa2_mbuf_pt pkt_buf[1];

	/* If ctrl+C signal is received, just exit the thread */
	if (odp_unlikely(received_sigint)) {
		if (odp_term_local() < 0)
			fprintf(stderr, "error: odp_term_local() failed.\n");
		pthread_exit(NULL);
	}

	if (recv_pkt_dpaa2(pkt_buf, 1, qentry) <= 0)
		return NULL;

	return pkt_buf[0];
}

odp_buffer_hdr_t *sec_dequeue(queue_entry_t *qentry)
{
	dpaa2_mbuf_pt pkt_buf[1];
	int pkts;
	crypto_vq_t *crypto_vq = qentry->s.priv;

	/* If ctrl+C signal is received, just exit the thread */
	if (odp_unlikely(received_sigint)) {
		if (odp_term_local() < 0)
			fprintf(stderr, "error: odp_term_local() failed.\n");
		pthread_exit(NULL);
	}
	pkts = dpaa2_sec_recv(crypto_vq->rx_vq, 1, pkt_buf);
	if (pkts <= 0)
		return NULL;

	return pkt_buf[0];
}

int sec_dequeue_multi(queue_entry_t *qentry, odp_buffer_hdr_t *pkt_buf[], int num)
{
	int pkts;
	crypto_vq_t *crypto_vq = qentry->s.priv;

	/* If ctrl+C signal is received, just exit the thread */
	if (odp_unlikely(received_sigint)) {
		if (odp_term_local() < 0)
			fprintf(stderr, "error: odp_term_local() failed.\n");
		pthread_exit(NULL);
	}
	pkts = dpaa2_sec_recv(crypto_vq->rx_vq, num, pkt_buf);

	return pkts;
}

int pktin_enq_multi(queue_entry_t *qentry,
		    odp_buffer_hdr_t *buf_hdr[],
		    int num)
{
	odp_packet_t pkt_tbl[QUEUE_MULTI_MAX];
	int nbr;
	int i;

	for (i = 0; i < num; ++i)
		pkt_tbl[i] = _odp_packet_from_buffer((odp_buffer_t)buf_hdr[i]);

	nbr = dpaa2_eth_xmit_fqid(qentry->s.priv,
				num, pkt_tbl);
	return nbr;
}

int pktin_deq_multi(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr[], int num)
{
	int32_t pkts;

	/* If ctrl+C signal is received, just exit the thread */
	if (odp_unlikely(received_sigint)) {
		if (odp_term_local() < 0)
			fprintf(stderr, "error: odp_term_local() failed.\n");
		pthread_exit(NULL);
	}
	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	pkts = recv_pkt_dpaa2(buf_hdr, num, qentry);
	if (pkts <= 0)
		goto done;
done:
	return pkts;
}

int odpfsl_pktio_mtu_set(odp_pktio_t id, unsigned mtu)
{
	pktio_entry_t *entry;

	entry = get_pktio_entry(id);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}
	unlock_entry(entry);
	return dpaa2_eth_mtu_set(entry->s.pkt_dpaa2.dev, mtu);
}

uint32_t odp_pktio_mtu(odp_pktio_t id)
{
	pktio_entry_t *entry;

	entry = get_pktio_entry(id);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}
	unlock_entry(entry);
	return dpaa2_eth_mtu_get(entry->s.pkt_dpaa2.dev);
}

int odp_pktio_promisc_mode_set(odp_pktio_t id, odp_bool_t enable)
{
	pktio_entry_t *entry;

	entry = get_pktio_entry(id);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}
	if (enable)
		dpaa2_eth_promiscuous_enable(entry->s.pkt_dpaa2.dev);
	else
		dpaa2_eth_promiscuous_disable(entry->s.pkt_dpaa2.dev);
	unlock_entry(entry);
	return 0;
}

int odp_pktio_promisc_mode(odp_pktio_t id)
{
	pktio_entry_t *entry;
	entry = get_pktio_entry(id);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}

	unlock_entry(entry);
	return dpaa2_eth_promiscuous_get(entry->s.pkt_dpaa2.dev);
}

int odpfsl_pktio_mac_addr_set(odp_pktio_t id, void *mac_addr, int addr_size)
{
	pktio_entry_t *entry;
	struct dpaa2_dev *ndev;

	if (addr_size < ETH_ADDR_LEN)
		return 0;

	entry = get_pktio_entry(id);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return 0;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}

	ndev = entry->s.pkt_dpaa2.dev;
	unlock_entry(entry);

	if (dpaa2_eth_set_mac_addr(ndev, (uint8_t *)mac_addr)
		== DPAA2_SUCCESS)
		return ETH_ADDR_LEN;
	return 0;
}


int odp_pktio_mac_addr(odp_pktio_t id, void *mac_addr, int addr_size)
{
	pktio_entry_t *entry;
	struct dpaa2_dev *ndev;
	if (addr_size < ETH_ADDR_LEN)
		return -1;

	entry = get_pktio_entry(id);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}

	ndev = entry->s.pkt_dpaa2.dev;
	unlock_entry(entry);

	if (dpaa2_eth_get_mac_addr(ndev, (uint8_t *)mac_addr)
		== DPAA2_SUCCESS)
		return ETH_ADDR_LEN;
	return -1;
}

int odp_pktio_stats(odp_pktio_t pktio,
		    odp_pktio_stats_t *stats)
{
	pktio_entry_t *entry;
	struct dpaa2_dev *ndev;
	struct fsl_mc_io *dpni;
	struct dpaa2_dev_priv *dev_priv;
	int32_t  retcode = -1;
	union dpni_statistics value;
	uint8_t	page0 = 0, page1 = 1, page2 = 2;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		printf("pktio entry %p does not exist\n", pktio);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_ERR("already freed pktio\n");
		return -1;
	}

	ndev = entry->s.pkt_dpaa2.dev;
	unlock_entry(entry);

	/*First check for the invalid parameters passed*/
	if (!ndev || (!ndev->priv)) {
		ODP_ERR("Device is NULL");
		return -1;
	}

	dev_priv = ndev->priv;
	dpni = (struct fsl_mc_io *)(dev_priv->hw);

	if (stats) {
		memset(stats, 0, sizeof(odp_pktio_stats_t));
		/*Get Counters from page_0*/
		retcode = dpni_get_statistics(dpni, CMD_PRI_LOW,
					      dev_priv->token,
					      page0, &value);
		if (retcode)
			goto error;

		/*total bytes received */
		stats->in_octets = value.page_0.ingress_all_bytes;
		/*total pkt received */
		stats->in_ucast_pkts = value.page_0.ingress_all_frames;
		/* less the multicast pkts*/
		stats->in_ucast_pkts -= value.page_0.ingress_multicast_frames;
		/* less the broadcast pkts*/
		stats->in_ucast_pkts -= value.page_0.ingress_broadcast_frames;

		/*Get Counters from page_1*/
		retcode =  dpni_get_statistics(dpni, CMD_PRI_LOW,
					       dev_priv->token,
					       page1, &value);
		if (retcode)
			goto error;
		/* Egress bytes count*/
		stats->out_octets = value.page_1.egress_all_bytes;
		/*total pkt received */
		stats->out_ucast_pkts = value.page_1.egress_all_frames;
		/* less the multicast pkts*/
		stats->out_ucast_pkts -= value.page_1.egress_multicast_frames;
		/* less the broadcast pkts*/
		stats->out_ucast_pkts -= value.page_1.egress_broadcast_frames;

		/*Get Counters from page_2*/
		retcode =  dpni_get_statistics(dpni, CMD_PRI_LOW,
					       dev_priv->token,
					       page2, &value);
		if (retcode)
			goto error;
		/* Ingress drop frame count*/
		stats->in_discards = value.page_2.ingress_nobuffer_discards;
		/* Ingress error frame count*/
		stats->in_errors = value.page_2.ingress_discarded_frames;
		/* Egress drop frame count*/
		stats->out_discards = value.page_2.egress_discarded_frames;
	}
	return retcode;
error:
	ODP_ERR("Operation not completed:Error Code = %d\n", retcode);
	return retcode;
}

int odp_pktio_stats_reset(odp_pktio_t pktio)
{
	pktio_entry_t *entry;
	struct dpaa2_dev *ndev;
	struct fsl_mc_io *dpni;
	struct dpaa2_dev_priv *dev_priv;
	int32_t  retcode;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		printf("pktio entry %p does not exist\n", pktio);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_ERR("already freed pktio\n");
		return -1;
	}

	ndev = entry->s.pkt_dpaa2.dev;
	unlock_entry(entry);

	/*First check for the invalid parameters passed*/
	if (!ndev || (!ndev->priv)) {
		ODP_ERR("Device is NULL");
		return -1;
	}

	dev_priv = ndev->priv;
	dpni = (struct fsl_mc_io *)(dev_priv->hw);

	/* Reset ingress packets */
	retcode =  dpni_reset_statistics(dpni, CMD_PRI_LOW, dev_priv->token);
	if (retcode)
		goto error;

	return retcode;
error:
	ODP_ERR("Operation not completed:Error Code = %d\n", retcode);
	return retcode;
}

int odp_pktin_queue_config(odp_pktio_t pktio,
			   const odp_pktin_queue_param_t *param)
{
	int retcode;
	uint32_t i;
	queue_entry_t *queue;
	odp_pktin_mode_t mode;
	pktio_entry_t *pktio_entry;
	odp_pktin_queue_param_t q_param;
	odp_pktio_capability_t capa;
	struct dpaa2_dev *ndev;

	if (!param)
		odp_pktin_queue_param_init(&q_param);
	else
		memcpy(&q_param, param, sizeof(odp_pktin_queue_param_t));

	pktio_entry = get_pktio_entry(pktio);
	if (!pktio_entry) {
		printf("Invalid pktio entry\n");
		return -1;
	}

	mode = pktio_entry->s.param.in_mode;

	/* Ignore the call when packet input is disabled. */
	if (mode == ODP_PKTIN_MODE_DISABLED) {
		ODP_DBG("pktio %s: in mode is disabled\n", pktio_entry->s.name);
		return 0;
	}

	ndev = pktio_entry->s.pkt_dpaa2.dev;

	if (ndev->state == DEV_ACTIVE) {
		ODP_ERR("pktio %s: not stopped\n", pktio_entry->s.name);
		return -1;
	}

	retcode = odp_pktio_capability(pktio, &capa);
	if (retcode) {
		ODP_ERR("pktio %s: unable to read capabilities\n",
			pktio_entry->s.name);
		return -1;
	}

	if (q_param.num_queues > capa.max_input_queues) {
		ODP_ERR("pktio %s: too many input queues\n", pktio_entry->s.name);
		return -1;
	}

	if (q_param.classifier_enable && q_param.hash_enable) {
		ODP_ERR("pktio %s: Both classifier and hashing cannot be"
				" enabled simultaneously\n", pktio_entry->s.name);
		return -1;
	}

	if (q_param.num_queues == 0 && !(q_param.classifier_enable)) {
		ODP_ERR("pktio %s: zero input queues\n", pktio_entry->s.name);
		return -1;
	}

	if (q_param.num_queues > 1 && !(q_param.hash_enable) &&
		 !(q_param.classifier_enable)) {
		ODP_ERR("pktio %s:  More than one input queues require either"
			"flow hashing or classifier enabled.\n",
			pktio_entry->s.name);
		return -1;
	}

	lock_entry(pktio_entry);
	/* If re-configuring, destroy old queues */
	if (pktio_entry->s.conf_rx_queues) {
		if ((mode == ODP_PKTIN_MODE_SCHED) ||
			(mode == ODP_PKTIN_MODE_QUEUE)) {

			while (pktio_entry->s.conf_rx_queues) {
				retcode = odp_pktio_inq_rem(pktio, pktio_entry->s.conf_rx_queues - 1);
				if (retcode) {
					ODP_ERR("pktio %s: failed to remove already configured queues\n",
						pktio_entry->s.name);
					unlock_entry(pktio_entry);
					return -1;
				}
			}
		} else
			pktio_entry->s.conf_rx_queues = 0;

		if (pktio_entry->s.hash_enable) {
			struct queues_config *q_config;

			q_config = dpaa2_eth_get_queues_config(ndev);
			for (i = 0; i < q_config->num_tcs; i++)
				dpaa2_eth_remove_flow_distribution(ndev, i);

			pktio_entry->s.hash_enable = FALSE;
		}
	}


	/* enable hash distribution */
	if (q_param.hash_enable && q_param.num_queues > 1) {
		pktio_entry->s.hash_enable = TRUE;
		odp_hash_dist(pktio, &q_param);
	}

	switch (mode) {
	case ODP_PKTIN_MODE_SCHED:

		q_param.queue_param.type = ODP_QUEUE_TYPE_SCHED;
	case ODP_PKTIN_MODE_QUEUE:

		for (i = 0; i < q_param.num_queues; i++) {
			queue = get_free_queue_entry();
			if (!queue) {
				ODP_ERR("pktio %s: No free queue entry available\n",
					pktio_entry->s.name);
				goto failure;
			}

			memcpy(&queue->s.param, &q_param.queue_param, sizeof(odp_queue_param_t));

			retcode = odp_pktio_inq_set(pktio, queue, i);
			if (retcode < 0) {
				ODP_ERR("\n Error in setting inq\n");
				/*unconfigure the queues in case partial configured*/
				goto failure;
			}
		}
		break;

	case ODP_PKTIN_MODE_DIRECT:
		for (i = 0; i < q_param.num_queues; i++) {
			retcode = dpaa2_eth_setup_rx_vq(ndev, i, NULL);
			if (DPAA2_FAILURE == retcode) {
				ODP_ERR("Fail to setup RX VQ\n");
				unlock_entry(pktio_entry);
				return -1;
			}

		}
		pktio_entry->s.conf_rx_queues = q_param.num_queues;

	default:
		break;
	}
	unlock_entry(pktio_entry);
	return 0;

failure:
	while (pktio_entry->s.conf_rx_queues) {
		retcode = odp_pktio_inq_rem(pktio, pktio_entry->s.conf_rx_queues - 1);
		if (retcode) {
			ODP_ERR("pktio %s: failed to remove already configured queues\n",
				pktio_entry->s.name);
			unlock_entry(pktio_entry);
			return -1;
		}
	}

	if (pktio_entry->s.hash_enable) {
		struct queues_config *q_config;

		q_config = dpaa2_eth_get_queues_config(ndev);
		for (i = 0; i < q_config->num_tcs; i++)
			dpaa2_eth_remove_flow_distribution(ndev, i);

		pktio_entry->s.hash_enable = FALSE;
	}
	unlock_entry(pktio_entry);
	return -1;
}

int odp_pktout_queue_config(odp_pktio_t pktio,
			    const odp_pktout_queue_param_t *param)
{
	queue_entry_t *qentry;
	pktio_entry_t *pktio_entry;
	odp_queue_t qid;
	odp_pktout_mode_t mode;
	odp_pktio_capability_t capa;
	struct dpaa2_dev *ndev;
	int32_t ret;
	uint32_t i = 0;
	char name[ODP_QUEUE_NAME_LEN] = {0};
	odp_pktout_queue_param_t q_default_param;

	if (!param)
		odp_pktout_queue_param_init(&q_default_param);
	else
		memcpy(&q_default_param, param, sizeof(odp_pktout_queue_param_t));

	pktio_entry = get_pktio_entry(pktio);
	if (!pktio_entry)
		return -1;

	mode = pktio_entry->s.param.out_mode;

	if (mode == ODP_PKTOUT_MODE_DISABLED ||
		mode == ODP_PKTOUT_MODE_TM)
		return 0;

	ndev = pktio_entry->s.pkt_dpaa2.dev;

	if (ndev->state == DEV_ACTIVE) {
		ODP_ERR("pktio %s: not stopped\n", pktio_entry->s.name);
		return -1;
	}

	if (q_default_param.num_queues == 0) {
		ODP_DBG("pktio %s: zero output queues\n", pktio_entry->s.name);
		return -1;
	}

	ret = odp_pktio_capability(pktio, &capa);
	if (ret) {
		ODP_DBG("pktio %s: unable to read capabilities\n",
			pktio_entry->s.name);
		return -1;
	}

	if (q_default_param.num_queues > capa.max_output_queues) {
		ODP_DBG("pktio %s: too many output queues\n", pktio_entry->s.name);
		return -1;
	}

	lock_entry(pktio_entry);
	/* If re-configuring, destroy old queues */
	if (pktio_entry->s.conf_tx_queues) {
		if (mode == ODP_PKTOUT_MODE_QUEUE) {
			odp_queue_t qid;

			while (pktio_entry->s.conf_tx_queues) {
				qid = (odp_queue_t)dpaa2_dev_get_vq_handle(ndev->tx_vq[pktio_entry->s.conf_tx_queues - 1]);
				if (!qid) {
					ODP_ERR("pktio %s: failed to remove already configured queues\n",
						pktio_entry->s.name);
					unlock_entry(pktio_entry);
					return -1;
				}
				qentry = queue_to_qentry(qid);
				set_queue_entry_to_free(qentry);
				pktio_entry->s.conf_tx_queues -= 1;
			}
		} else
			pktio_entry->s.conf_tx_queues = 0;
	}

	switch (mode) {
	case ODP_PKTOUT_MODE_QUEUE:
		for (i = 0; i < q_default_param.num_queues; i++) {
			sprintf(name, "pktio%lu_outq_%d", odp_pktio_to_u64(pktio), i);
			qentry = get_free_queue_entry();
			if (!qentry) {
				ODP_ERR("pktio %s: No free queue entry available\n",
					pktio_entry->s.name);
				goto failure;
			}

			queue_lock(qentry);
			qentry->s.pktout = pktio;

			/*Configure tx queue at underlying hardware queues*/
			qentry->s.priv = ndev->tx_vq[i];
			dpaa2_dev_set_vq_handle(ndev->tx_vq[i], (uint64_t)qentry->s.handle);

			qentry->s.enqueue = pktout_enqueue;
			qentry->s.enqueue_multi = pktout_enq_multi;
			qentry->s.status = QUEUE_STATUS_READY;
			queue_unlock(qentry);
		}

	case ODP_PKTOUT_MODE_DIRECT:
		ret = dpaa2_eth_setup_tx_vq(ndev, q_default_param.num_queues, DPAA2BUF_TX_NO_ACTION);
		if (ret == DPAA2_FAILURE) {
			ODP_ERR("pktio %s: Failed to setup queues\n", pktio_entry->s.name);
			goto failure;
		}
		pktio_entry->s.conf_tx_queues = q_default_param.num_queues;

	default:
		break;
	}
	unlock_entry(pktio_entry);
	return 0;

failure:
	/** Free queues for queue mode*/
	while (i > 0) {
		qid = (odp_queue_t)dpaa2_dev_get_vq_handle(ndev->tx_vq[--i]);
		if (!qid) {
			ODP_ERR("pktio %s: failed to remove already configured queues\n",
				pktio_entry->s.name);
			unlock_entry(pktio_entry);
			return -1;
		}
		qentry = queue_to_qentry(qid);
		set_queue_entry_to_free(qentry);
	}
	unlock_entry(pktio_entry);
	return -1;

}

int odp_pktin_queue(odp_pktio_t pktio, odp_pktin_queue_t queues[],
							int num)
{
	int32_t i = -1;
	pktio_entry_t *pktio_entry;
	struct dpaa2_dev *ndev;
	int num_queues;

	pktio_entry = get_pktio_entry(pktio);
	if (!pktio_entry)
		return -1;

	num_queues = pktio_entry->s.conf_rx_queues;
	if (!queues) {
		ODP_DBG("OUT parameter 'queues' is NULL\n");
		return num_queues;
	}

	ndev = pktio_entry->s.pkt_dpaa2.dev;
	if (pktio_entry->s.param.in_mode  == ODP_PKTIN_MODE_DIRECT) {
		for (i = 0; i < num && i < num_queues; i++) {
			queues[i] = ndev->rx_vq[i];
		}
	} else {
		ODP_ERR("pktio %s: pktio in mode is not DIRECT mode\n", pktio_entry->s.name);
		return -1;
	}

	return num_queues;
}

int odp_pktout_queue(odp_pktio_t pktio, odp_pktout_queue_t queues[],
							  int num)
{
	int32_t i = -1, num_queues;
	pktio_entry_t *pktio_entry;
	struct dpaa2_dev *ndev;

	pktio_entry = get_pktio_entry(pktio);
	if (!pktio_entry)
		return -1;

	num_queues = pktio_entry->s.conf_tx_queues;
	if (!queues) {
		ODP_DBG("OUT parameter 'queues' is NULL\n");
		return num_queues;
	}

	ndev = pktio_entry->s.pkt_dpaa2.dev;
	if (pktio_entry->s.param.out_mode == ODP_PKTOUT_MODE_DIRECT) {
		for (i = 0; i < num && i < num_queues; i++) {
			queues[i] = ndev->tx_vq[i];
		}
	} else {
		ODP_ERR("pktio %s: pktio out mode is not DIRECT mode\n", pktio_entry->s.name);
		return -1;
	}

	return num_queues;
}

int odp_pktio_capability(odp_pktio_t pktio, odp_pktio_capability_t *capa)
{
	pktio_entry_t *entry;
	struct dpaa2_dev *ndev;

	entry = get_pktio_entry(pktio);
	if (!entry) {
		ODP_DBG("pktio entry %lu does not exist\n", odp_pktio_to_u64(pktio));
		return -1;
	}

	ndev = entry->s.pkt_dpaa2.dev;

	memset(capa, 0, sizeof(odp_pktio_capability_t));
	capa->max_input_queues = ndev->num_rx_vqueues;
	capa->max_output_queues = ndev->num_tx_vqueues;
	capa->set_op.op.promisc_mode = 1;

	if (entry->s.type == ODP_PKTIO_TYPE_LOOPBACK)
		capa->loop_supported = TRUE;

	capa->config.pktin.all_bits = ALL_BITS;
	capa->config.pktout.all_bits = ALL_BITS;

	return 0;
}

int odp_pktin_event_queue(odp_pktio_t pktio, odp_queue_t queues[], int num)
{
	int32_t i = -1, num_queues;
	pktio_entry_t *pktio_entry;
	struct dpaa2_dev *ndev;

	pktio_entry = get_pktio_entry(pktio);
	if (!pktio_entry)
		return -1;

	num_queues = pktio_entry->s.conf_rx_queues;
	if (!queues) {
		ODP_DBG("OUT parameter 'queues' is NULL\n");
		return num_queues;
	}

	ndev = pktio_entry->s.pkt_dpaa2.dev;

	if ((pktio_entry->s.param.in_mode == ODP_PKTIN_MODE_QUEUE) ||
		(pktio_entry->s.param.in_mode == ODP_PKTIN_MODE_SCHED)) {
		for (i = 0; i < num && i < num_queues; i++)
			queues[i] =
			(odp_queue_t)dpaa2_dev_get_vq_handle(ndev->rx_vq[i]);
	} else {
		ODP_ERR("pktio %s: pktio in mode is not either QUEUE or SCHED mode\n", pktio_entry->s.name);
		return -1;
	}

	return num_queues;
}

int odp_pktout_event_queue(odp_pktio_t pktio, odp_queue_t queues[], int num)
{
	int32_t i = -1, num_queues;
	pktio_entry_t *pktio_entry;
	struct dpaa2_dev *ndev;

	pktio_entry = get_pktio_entry(pktio);
	if (!pktio_entry)
		return -1;

	num_queues = pktio_entry->s.conf_tx_queues;
	if (!queues) {
		ODP_DBG("OUT parameter 'queues' is NULL\n");
		return num_queues;
	}

	ndev = pktio_entry->s.pkt_dpaa2.dev;
	if (pktio_entry->s.param.out_mode == ODP_PKTOUT_MODE_QUEUE) {
		for (i = 0; i < num && i < num_queues; i++)
			queues[i] = (odp_queue_t)dpaa2_dev_get_vq_handle(ndev->tx_vq[i]);
	} else {
		ODP_ERR("pktio %s: pktio out mode is not QUEUE mode\n", pktio_entry->s.name);
		return -1;
	}
	return num_queues;
}

int odp_pktio_index(odp_pktio_t pktio)
{
	pktio_entry_t *entry = get_pktio_entry(pktio);

	if (!entry || is_free(entry))
		return -1;

	return _odp_typeval(pktio) - 1;
}

void odp_pktio_config_init(odp_pktio_config_t *config)
{
	memset(config, 0, sizeof(odp_pktio_config_t));
}

/*TODO: Currently, API is not implementing any configuration for pktio.
	only configuration is being saved.*/
int odp_pktio_config(odp_pktio_t id, const odp_pktio_config_t *config)
{
	pktio_entry_t *entry;
	odp_pktio_capability_t capa;
	odp_pktio_config_t default_config;
	int res = 0;

	entry = get_pktio_entry(id);
	if (!entry)
		return -1;

	if (!config) {
		odp_pktio_config_init(&default_config);
	} else
		memcpy(&default_config, config, sizeof(odp_pktio_config_t));

	if (odp_pktio_capability(id, &capa))
		return -1;

	/* Check config for invalid values */
	if (default_config.pktin.all_bits & ~capa.config.pktin.all_bits) {
		ODP_ERR("Unsupported input configuration option\n");
		return -1;
	}
	if (default_config.pktout.all_bits & ~capa.config.pktout.all_bits) {
		ODP_ERR("Unsupported output configuration option\n");
		return -1;
	}

	if (default_config.enable_loop && !capa.loop_supported) {
		ODP_ERR("Loopback mode not supported\n");
		return -1;
	}

	lock_entry(entry);

	/*TODO PKTIO state information is not available*/
#if 0
	if (entry->s.state == STATE_STARTED) {
		unlock_entry(entry);
		ODP_DBG("pktio %s: not stopped\n", entry->s.name);
		return -1;
	}
#endif

	memcpy(&entry->s.config, &default_config, sizeof(odp_pktio_config_t));

	unlock_entry(entry);

	return res;
}

int odp_pktio_info(odp_pktio_t id, odp_pktio_info_t *info)
{
	pktio_entry_t *entry;
	struct dpaa2_dev *dev;
	struct dpaa2_dev_priv *dev_priv;
	struct dpaa2_eth_priv *epriv;

	entry = get_pktio_entry(id);

	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return -1;
	}

	memset(info, 0, sizeof(odp_pktio_info_t));
	if (entry->s.type == ODP_PKTIO_TYPE_LOOPBACK) {
		info->name = "loop";
	} else
		info->name = entry->s.name;

	dev = entry->s.pkt_dpaa2.dev;
	dev_priv = (struct dpaa2_dev_priv *)dev->priv;
	epriv = (struct dpaa2_eth_priv *)(dev_priv->drv_priv);

	info->drv_name = (const char*)epriv->cfg.name;
	info->pool = entry->s.pkt_dpaa2.pool;
	memcpy(&info->param, &entry->s.param, sizeof(odp_pktio_param_t));

	return 0;
}

void odp_pktio_print(odp_pktio_t id)
{
	pktio_entry_t *entry;
	uint8_t addr[ETH_ADDR_LEN];
	int max_len = 512;
	char str[max_len];
	int len = 0;
	int n = max_len - 1;

	entry = get_pktio_entry(id);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return;
	}

	len += snprintf(&str[len], n - len,
			"pktio\n");
	len += snprintf(&str[len], n - len,
			"  handle       %" PRIu64 "\n", odp_pktio_to_u64(id));
	len += snprintf(&str[len], n - len,
			"  name         %s\n", entry->s.type == ODP_PKTIO_TYPE_LOOPBACK ? "loop" :
										entry->s.name);

	len += snprintf(&str[len], n - len,
			"  type         %s\n", entry->s.type == ODP_PKTIO_TYPE_SOCKET_BASIC ? "ODP_PKTIO_TYPE_SOCKET_BASIC" :
					(entry->s.type == ODP_PKTIO_TYPE_SOCKET_MMSG ? "ODP_PKTIO_TYPE_SOCKET_MMSG" :
					(entry->s.type == ODP_PKTIO_TYPE_SOCKET_MMAP ? "ODP_PKTIO_TYPE_SOCKET_MMAP" :
					(entry->s.type == ODP_PKTIO_TYPE_LOOPBACK ? "ODP_PKTIO_TYPE_LOOPBACK" :
											"UNKNOWN"))));
	/*FIXME: Interface state information is not available yet*/
#if 0
	len += snprintf(&str[len], n - len,
			"  state        %s\n",
			entry->s.state ==  STATE_STARTED ? "start" :
		       (entry->s.state ==  STATE_STOPPED ? "stop" :
		       (entry->s.state ==  STATE_OPENED ? "opened" :
							  "unknown")));
#endif
	memset(addr, 0, sizeof(addr));
	odp_pktio_mac_addr(id, addr, ETH_ADDR_LEN);
	len += snprintf(&str[len], n - len,
			"  mac          %02x:%02x:%02x:%02x:%02x:%02x\n",
			addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	len += snprintf(&str[len], n - len,
			"  mtu          %" PRIu32 "\n", odp_pktio_mtu(id));
	len += snprintf(&str[len], n - len,
			"  promisc      %s\n", entry->s.promisc ? "yes" : "no");
	str[len] = '\0';

	ODP_PRINT("\n%s\n", str);
}

int odp_pktin_recv_tmo(odp_pktin_queue_t queue, odp_packet_t packets[],
						int num, uint64_t wait)
{
	int32_t ret;
	uint64_t wait_till;

	if (!queue)
		return -1;

	if (wait)
		wait_till = dpaa2_time_get_cycles() + wait;

	do {
		ret = dpaa2_eth_recv(NULL, (void *)queue, num, packets);
		if (ret > 0 || ret < 0)
			break;
		else if (ret == 0) {
			if ((wait != ODP_PKTIN_WAIT) && (wait_till <= dpaa2_time_get_cycles()))
				break;
		}

		/* If ctrl+C signal is received, just exit the thread */
		if (odp_unlikely(received_sigint)) {
			if (odp_term_local() < 0)
				fprintf(stderr, "error: odp_term_local() failed.\n");
			pthread_exit(NULL);
		}
	} while(1);

	return ret;
}

/*TODO: Improvement for fairness of queue service levels */
int odp_pktin_recv_mq_tmo(const odp_pktin_queue_t queues[], unsigned num_q,
					unsigned *from, odp_packet_t packets[],
					int num, uint64_t wait)
{
	int32_t ret;
	unsigned i = 0;
	uint64_t wait_till;

	if (wait)
		wait_till = dpaa2_time_get_cycles() + wait;

	do {
		ret = dpaa2_eth_recv(NULL, (void *)queues[i++], num, packets);
		if (ret > 0 && from) {
			*from = i - 1;
			break;
		} else if (ret == 0) {
			if ((wait != ODP_PKTIN_WAIT) && (wait_till <= dpaa2_time_get_cycles()))
				break;
		} else
			break;
		if (i == num_q)
			i = 0;

		/* If ctrl+C signal is received, just exit the thread */
		if (odp_unlikely(received_sigint)) {
			if (odp_term_local() < 0)
				fprintf(stderr, "error: odp_term_local() failed.\n");
			pthread_exit(NULL);
		}
	} while(1);

	return ret;
}

int odp_pktio_link_status(odp_pktio_t id)
{
	pktio_entry_t *entry;
	struct dpaa2_dev *dev;
	struct dpni_link_state state;
	int ret = -1;

	entry = get_pktio_entry(id);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return -1;
	}

	if (odp_unlikely(is_free(entry))) {
		ODP_DBG("already freed pktio\n");
		return -1;
	}

	dev = entry->s.pkt_dpaa2.dev;

	ret = dpaa2_eth_get_link_info(dev, &state);

	if(!ret)
		ret = state.up;

	return ret;
}

uint64_t odp_pktin_wait_time(uint64_t nsec)
{
	return nsec;
}

uint64_t odp_pktin_ts_res(odp_pktio_t id ODP_UNUSED)
{
	/*TODO timestamp is disabled so return 0*/
	return 0;
}

odp_time_t odp_pktin_ts_from_ns(odp_pktio_t id ODP_UNUSED, uint64_t ns ODP_UNUSED)
{
	odp_time_t ts = {0};
	ODP_UNIMPLEMENTED();
	return ts;
}
