/*-
 * GPL LICENSE SUMMARY
 *
 *   Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 *   Copyright(c) 2010-2013 Intel Corporation. All rights reserved.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *   The full GNU General Public License is included in this distribution
 *   in the file called LICENSE.GPL.
 *
 *   Derived from DPDK's kni_dev.h
 */

#ifndef _KNI_DEV_H_
#define _KNI_DEV_H_

#include <linux/if.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/list.h>

#ifdef DPAA2_KNI_VHOST
#include <net/sock.h>
#endif

#include "../platform/linux-dpaa2/kni/odpfsl_kni_common.h"
#define KNI_KTHREAD_RESCHEDULE_INTERVAL 5 /* us */

/**
 * A structure describing the private information for a kni device.
 */

struct kni_dev {
	/* kni list */
	struct list_head list;

	struct net_device_stats stats;
	int status;
	uint16_t group_id;	/* Group ID of a group of KNI devices */
	unsigned core_id;	/* Core ID to bind */
	char name[DPAA2_KNI_NAMESIZE]; /* Network device name */
	struct task_struct *pthread;
	void *usrctxt; /* User space process context*/

	/* wait queue for req/resp */
	wait_queue_head_t wq;
	struct mutex sync_lock;

	/* PCI device id */
	uint16_t device_id;

	/* kni device */
	struct net_device *net_dev;
	struct net_device *lad_dev;
	struct pci_dev *pci_dev;

	/* queue for packets to be sent out */
	void *tx_q;

	/* queue for the packets received */
	void *rx_q;

	/* queue for the allocated kbufs those can be used to save sk buffs */
	void *alloc_q;

	/* free queue for the kbufs to be freed */
	void *free_q;

	/* request queue */
	void *req_q;

	/* response queue */
	void *resp_q;

	void * sync_kva;
	void *sync_va;

	void *kbuf_kva;
	void *kbuf_va;

	/* kbuf size */
	unsigned kbuf_size;

	/* synchro for request processing */
	unsigned long synchro;

#ifdef DPAA2_KNI_VHOST
	struct kni_vhost_queue* vhost_queue;
	volatile enum {
		BE_STOP = 0x1,
		BE_START = 0x2,
		BE_FINISH = 0x4,
	}vq_status;
#endif
};

#define KNI_ERR(args...) printk(KERN_INFO "KNI: Error:" args)
#define KNI_PRINT(args...) printk(KERN_INFO "KNI: " args)
#define KNI_TRACE	printk(KERN_INFO"\n%s-%d", __func__, __LINE__)
#ifdef NCS_DEBUG
	#define KNI_DBG(args...) printk(KERN_INFO "KNI: " args)
#else
	#define KNI_DBG(args...)
#endif

#ifdef DPAA2_KNI_VHOST
unsigned int
kni_poll(struct file *file, struct socket *sock, poll_table * wait);
int kni_chk_vhost_rx(struct kni_dev *kni);
int kni_vhost_init(struct kni_dev *kni);
int kni_vhost_backend_release(struct kni_dev *kni);

struct kni_vhost_queue {
	struct sock sk;
	struct socket *sock;
	int vnet_hdr_sz;
	struct kni_dev *kni;
	int sockfd;
	unsigned int flags;
	struct sk_buff* cache;
	struct odpfsl_kni_fifo* fifo;
};

#endif

#ifdef DPAA2_KNI_VHOST_DEBUG_RX
	#define KNI_DBG_RX(args...) printk(KERN_DEBUG "KNI RX: " args)
#else
	#define KNI_DBG_RX(args...)
#endif

#ifdef DPAA2_KNI_VHOST_DEBUG_TX
	#define KNI_DBG_TX(args...) printk(KERN_DEBUG "KNI TX: " args)
#else
	#define KNI_DBG_TX(args...)
#endif


#define isprint(c) ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || \
	(c >= '0' && c <= '9'))

static inline void hexdump(const unsigned char *buf, unsigned short len)
{
	char str[80], octet[10];
	int ofs, i, l;

	for (ofs = 0; ofs < len; ofs += 16) {
		sprintf(str, "%03x ", ofs);

		for (i = 0; i < 16; i++) {
			if ((i + ofs) < len)
				sprintf(octet, "%02x ", buf[ofs + i]);
			else
				strcpy(octet, "   ");

			strcat(str, octet);
		}
		strcat(str, "  ");
		l = strlen(str);

		for (i = 0; (i < 16) && ((i + ofs) < len); i++)
			str[l++] = isprint(buf[ofs + i]) ? buf[ofs + i] : '.';

		str[l] = '\0';
		printk(KERN_INFO "%s\n", str);
	}
}

#endif
