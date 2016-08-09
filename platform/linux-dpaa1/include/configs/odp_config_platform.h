/* Copyright (c) 2014, Freescale Semiconductor Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_CONFIG_PLATFORM_H_
#define ODP_CONFIG_PLATFORM_H_

/* Generic DMA memory area - packet buffers */
#define DMA_MAP_SIZE            0x2000000

/* IC offset from buffer header address */
#define DEFAULT_ICEOF		80

/* internal offset from where IC is copied to packet buffer*/
#define DEFAULT_ICIOF		32

/* IC transfer size */
#define DEFAULT_ICSZ		48

/* Frame descriptor offset as provided by FMan */
#define FD_DEFAULT_OFFSET	128

/* NIA for O/H port after the dequeue operation (fetch full frame) */
#define OH_DEQ_NIA 0x0050020C

/* Maximum transfer unit - fsl_fm_max_frm
   TODO - get it from /proc/cmdline */
#define FM_MAX_FRM		4352

/* Maximum number of buffer pools for an FMan port */
#define MAX_PORT_BPOOLS		8

/* ORP parameters - relevant for ORDERED queues */
#define ORP_WINDOW_SIZE		3
#define ORP_AUTO_ADVANCE	1
#define ORP_ACCEPT_LATE		3

/* Number of pool channels to allocate */
#define NUM_POOL_CHANNELS	4
/* Number of pool channels to allocate for named groups */
#define NUM_POOL_CHANNELS_GROUP 2

/* Disables channels scheduling for a thread when
 * returning from schedule calls */
/*#undef ODP_SCHED_FAIR*/

/* Sets DQRR_MF to 1. This releases the
 * HOLDACTIVE queue from the current portal after one
 * enqueue. This disables the use of POLL queues which
 * are based on volatile dequeue (DQRR_MF >= 3)*/
/*#undef ODP_ATOMIC_SCHED_FAIR*/

/* QMAN/BMAN slow poll params */
#define WORKER_SLOWPOLL_BUSY	4
#define WORKER_SLOWPOLL_IDLE	400

/* CAAM era */
#if defined P4080
#define SEC_ERA		RTA_SEC_ERA_2
#elif defined T1040
#define SEC_ERA		RTA_SEC_ERA_6
#elif defined LS1043
#define SEC_ERA		RTA_SEC_ERA_8
#elif defined T4240
#define SEC_ERA		RTA_SEC_ERA_6
#endif
/* Crypto IV max len supported by CAAM */
#define IV_MAX_LEN	64
/* CAAM burst number == MCFGR:BURST/FD_DEFAULT_OFFSET
 * to have output frames fd_offset = BURST/FD_DEFAULT_OFFSET */
#define CAAM_BURST_NUM_DEFAULT  2
/* QI max offset to request */
#define CAAM_QI_MAX_OFFSET	511
/* Default sharing mode - serial */
#define CAAM_DESC_SHARE_SERIAL

/* RNG device file name */
#define RNG_DEV			"/dev/hwrng"

/* Taildrop threshold (bytes) */
#define TD_THRESH               1000000

/**
 * Maximum number of crypto sessions
 */
#define ODP_CONFIG_CRYPTO_SES   256

#endif
