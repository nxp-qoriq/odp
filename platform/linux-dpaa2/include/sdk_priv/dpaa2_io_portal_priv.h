/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		dpaa2_io_portal_priv.h
 * @description		Private functions & MACRO definitions for DPAA2 Data Path I/O portal
			type Device
 */

#ifndef _DPAA2_IO_PORTAL_PRIV_H_
#define _DPAA2_IO_PORTAL_PRIV_H_

/*Standard header files*/
#include <stddef.h>
#include <pthread.h>

/*DPAA2 header files*/
#include <odp/api/std_types.h>
#include <dpaa2_common.h>
#include <dpaa2.h>
#include <dpaa2_vfio.h>
#include <dpaa2_dev.h>
#include <dpaa2_dev_priv.h>
#include <dpaa2_malloc.h>
#include <odp/api/byteorder.h>
#include <dpaa2_lock.h>
#include <odp/api/spinlock.h>
#include <odp/api/atomic.h>
#include <dpaa2_dev_intr_priv.h>

/*MC header files*/
#include <fsl_dpio.h>
#include <fsl_dpio_cmd.h>
#include <fsl_mc_sys.h>
#include <fsl_dpmng.h>
/*QBMAN header files*/
#include <fsl_qbman_portal.h>

#ifdef __cplusplus
extern "C" {
#endif
/* Macros to define feature enable/disable options */
#define LDPAA_IO_P_VENDOR_ID	6487
#define LDPAA_IO_P_MAJ_NUM	DPIO_VER_MAJOR
#define LDPAA_IO_P_MIN_NUM	DPIO_VER_MINOR
#define LDPAA_IO_P_NAME		"ldpaa-dpio"

#define SVR_LS1080A             0x87030000
#define SVR_LS2080A             0x87010000
#define SVR_LS2088A             0x87090000
#define SVR_LX2160A             0x87360000

/*QBMAN Version*/
#define QBMAN_REV_4100   0x04010000

/*Maximum number of slots available in TX ring*/
#define MAX_TX_RING_SLOTS       8

/* Number of maximum frames storage in private dqrr storage */
#define NUM_MAX_RECV_FRAMES	32

/* Maximum number of channels*/
#define MAX_SCHED_GRPS		11

/* DPIO IRQ index for VFIO */
#define VFIO_DPIO_DATA_IRQ_INDEX 0
/* Invalid DPIO Channel index */
#define DPAA2_INVALID_CHANNEL_IDX	((uint8_t)(-1))

/*
 * Structure to represent hold dqrr entry.
 */
struct dqrr {
	struct qbman_result *hold_dqrr; /**< Last DQRR Entry which is on hold for this SW portal */
	dpaa2_mbuf_pt hold_buf; /**< Last buffer which is on hold  w.r.t hold_dqrr ptr */
};

/*
 * The DPAA2 DPIO device structure.
 */
struct dpaa2_dpio_dev {
	TAILQ_ENTRY(dpaa2_dpio_dev) next; /**< Pointer to Next device instance */
	struct dqrr *dqrr_entry;
	uint32_t index; /**< Index of a instance in the list */
	odp_atomic_u16_t ref_count; /**< How many thread contexts are sharing this.*/
	struct fsl_mc_io *dpio; /** handle to DPIO portal object */
	uint16_t token;
	struct qbman_swp *sw_portal; /**< SW portal object */
	lock_t lock; /**< Mutex Lock required when Portal is shared */
	void *mc_portal; /**< MC Portal for configuring this device */
	uint64_t qbman_portal_ce_paddr; /**< Physical address of Cache Enabled Area */
	uint64_t ce_size; /**< Size of the CE region */
	uint64_t qbman_portal_ci_paddr; /**< Physical address of Cache Inhibit Area */
	uint64_t ci_size; /**< Size of the CI region */
	struct dpaa2_intr_handle *intr_handle;
	int32_t	vfio_fd; /**< File descriptor received via VFIO */
	int32_t hw_id; /**< An unique ID of this DPIO device instance */
	uint8_t ch_idx[MAX_SCHED_GRPS];	/**< channel indexes corresponding to DPCON
			  objects for static dequeue mapping */
	uint8_t ch_count;  /**< count of channels which are mapped for
			     static dequeue **/
	uint8_t	dqrr_size;
};

/* DCA related helper Macros */
#define ANY_ATOMIC_CNTXT_TO_FREE(mbuf) \
	(mbuf->atomic_cntxt == thread_io_info.dpio_dev->dqrr_entry[mbuf->index].hold_dqrr)
#define IS_HOLD_DQRR_VALID(index) (thread_io_info.dpio_dev->dqrr_entry[index].hold_dqrr != NULL)
#define MARK_HOLD_DQRR_PTR_INVALID(index)  (thread_io_info.dpio_dev->dqrr_entry[index].hold_dqrr = NULL)
#define MARK_HOLD_BUF_CNTXT_INVALID(index) \
	(thread_io_info.dpio_dev->dqrr_entry[index].hold_buf->atomic_cntxt = INVALID_CNTXT_PTR)
#define SAVE_HOLD_BUF_PTR(val, index) \
	(thread_io_info.dpio_dev->dqrr_entry[index].hold_buf = val)
#define SAVE_HOLD_DQRR_PTR(val, index) \
	(thread_io_info.dpio_dev->dqrr_entry[index].hold_dqrr = (struct qbman_result *)val)

#define GET_HOLD_DQRR_PTR(index) (thread_io_info.dpio_dev->dqrr_entry[index].hold_dqrr)
#define GET_HOLD_DQRR_IDX(index) \
	(qbman_get_dqrr_idx(thread_io_info.dpio_dev->dqrr_entry[index].hold_dqrr))

/*!
 * DPAA2 device list structure
 */
TAILQ_HEAD(dpaa2_dpio_device_list, dpaa2_dpio_dev); /*!< DPAA2 DPIO device List */
extern struct dpaa2_dpio_device_list *dpio_dev_list; /*!< Global list of DPAA2 devices. */

struct thread_io_info_t {
	struct dpaa2_dpio_dev *dpio_dev;
	struct qbman_result *dq_storage;
};
/*! Global per thread DPIO portal */
extern __thread struct thread_io_info_t thread_io_info;

/*! The globally stored DPIO for notifier */
extern struct dpaa2_dpio_dev *notif_dpio;
/* The epoll fd to be used for epolling on the notifier DPIO */
extern int notif_dpio_epollfd;
/* Global struct for soc version */
extern struct mc_soc_version mc_plat_info;
/* Helper Macro to acquire lock for IO Portal */
#define	SWP_LOCK(dpio_dev)	({					\
		if (odp_atomic_read_u16(&dpio_dev->ref_count) > 1)	\
					LOCK(dpio_dev->lock);		\
		})

/* Helper Macro to unlock IO Portal */
#define	SWP_UNLOCK(dpio_dev)	({					\
		if (odp_atomic_read_u16(&dpio_dev->ref_count) > 1)	\
					UNLOCK(dpio_dev->lock);		\
		})

int32_t dpaa2_io_portal_init(void);

int32_t dpaa2_io_portal_exit(void);

/*!
 * @details	DPIO driver probe function to initialize the device.
 *
 * @param[in]	dev - Pointer to DPAA2 device
 *
 * @param[in]	data - device specific configuration data
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_io_portal_probe(struct dpaa2_dev *dev,
			ODP_UNUSED const void *data);

/*!
 * @details	DPIO driver shutdown function to close the device.
 *
 * @param[in]	dev - Pointer to DPAA2 device
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_io_portal_close(struct dpaa2_dev *dev);

/*!
 * @details	Register the DPIO interrupt with VFIO
 *
 * @param[in]	dpio_dev - Pointer to DPIO device
 *
 * @returns	index - interrupt index
 *
 */
int dpaa2_register_dpio_interrupt(struct dpaa2_dpio_dev *dpio_dev,
	uint32_t index);

void dpaa2_affine_dpio_intr_to_respective_core(int32_t dpio_id);

void release_dpio(struct dpaa2_dpio_dev *dpio_dev);

#ifdef __cplusplus
}
#endif

#endif /* _DPAA2_IO_PORTAL_PRIV_H_ */
