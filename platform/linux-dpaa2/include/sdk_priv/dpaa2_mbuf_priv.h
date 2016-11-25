/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		dpaa2_mbuf_priv.h
 *
 * @brief		Buffer management library services for DPAA2 based applications.
 */

#ifndef _DPAA2_MBUF_PRIV_H_
#define _DPAA2_MBUF_PRIV_H_

#ifdef __cplusplus
extern "C" {
#endif

/* DPAA2 header files */
#include <odp/api/plat/sdk/common/dpaa2_cfg.h>
#include <odp/api/plat/sdk/rts/dpaa2_mbuf.h>
#include <dpaa2_mbuf_priv_ldpaa.h>
#include <odp_config_internal.h>

/* Maximum release/acquire from QBMAN */
#define DPAA2_MBUF_MAX_ACQ_REL	7

#define MAX_BPID 256

/*Macros to define operations on FD*/
#define DPAA2_SET_FD_ADDR(fd, addr) {				\
	fd->simple.addr_lo = lower_32_bits((uint64_t)addr);	\
	fd->simple.addr_hi = upper_32_bits((uint64_t)addr); }
#define DPAA2_SET_FD_LEN(fd, length)	fd->simple.len = length
#define DPAA2_SET_FD_BPID(fd, bpid)	fd->simple.bpid_offset |= bpid;
#define DPAA2_SET_FD_IVP(fd)   ((fd->simple.bpid_offset |= 0x00004000))
#define DPAA2_SET_FD_OFFSET(fd, offset)	fd->simple.bpid_offset |= (uint32_t)offset << 16;
#define DPAA2_SET_FD_INTERNAL_JD(fd, len) fd->simple.frc = (0x80000000 | (len));
#define DPAA2_SET_FD_FRC(fd, frc)	fd->simple.frc = frc;
#define DPAA2_RESET_FD_CTRL(fd)	fd->simple.ctrl = 0;

#define	DPAA2_SET_FD_ASAL(fd, asal)	(fd->simple.ctrl |= (asal << 16))
#define DPAA2_SET_FD_FLC(fd, addr)				\
	fd->simple.flc_lo = lower_32_bits((uint64_t)addr);	\
	fd->simple.flc_hi = upper_32_bits((uint64_t)addr);
#define DPAA2_SET_FLE_INTERNAL_JD(fle, len) fle->frc = (0x80000000 | (len));
#define DPAA2_SET_FLE_OFFSET(fle, offset)	(fle->fin_bpid_offset |= (uint32_t)offset << 16);
#define DPAA2_GET_FLE_ADDR(fle)					\
	(uint64_t)((((uint64_t)(fle->addr_hi)) << 32) + fle->addr_lo)
#define DPAA2_SET_FLE_ADDR(fle, addr)	\
	fle->addr_lo = lower_32_bits((uint64_t)addr);     \
	fle->addr_hi = upper_32_bits((uint64_t)addr);
#define DPAA2_SET_FLE_BPID(fle, bpid)	fle->fin_bpid_offset |= (uint64_t)bpid;
#define DPAA2_GET_FLE_BPID(fle, bpid)	(fle->fin_bpid_offset & 0x000000ff)
#define DPAA2_SET_FLE_FIN(fle)	fle->fin_bpid_offset |= (uint64_t)1<<31;
#define DPAA2_SET_FLE_SG_EXT(fle)	fle->fin_bpid_offset |= (uint64_t)1<<29;
#define DPAA2_IS_SET_FLE_SG_EXT(fle)	\
	(fle->fin_bpid_offset & ((uint64_t)1<<29))? 1 : 0
#define DPAA2_SET_FLE_IVP(fle)   ((fle->fin_bpid_offset |= 0x00004000))
#define DPAA2_SET_FD_COMPOUND_FMT(fd)	\
	fd->simple.bpid_offset |= (uint32_t)1 << 28;
#define DPAA2_GET_FD_ADDR(fd)	\
	(uint64_t)((((uint64_t)(fd->simple.addr_hi)) << 32) + fd->simple.addr_lo)
#define DPAA2_GET_FD_LEN(fd)	(fd->simple.len)
#define DPAA2_GET_FD_BPID(fd)	((fd->simple.bpid_offset & 0x00003FFF))
#define DPAA2_GET_FD_IVP(fd)   ((fd->simple.bpid_offset & 0x00004000) >> 14)
#define DPAA2_GET_FD_OFFSET(fd)	((fd->simple.bpid_offset & 0x0FFF0000) >> 16)
#define DPAA2_GET_FD_FRC(fd)	(fd->simple.frc)
#define DPAA2_GET_FD_FLC(fd)	\
	(uint64_t)((((uint64_t)(fd->simple.flc_hi)) << 32) + fd->simple.flc_lo)
#define GET_VIRT_ADDR_FROM_ZONE(addr, bz) ((addr - bz->phys_addr) + dpaa2_memzone_virt(bz))
#define GET_PHY_ADDR_FROM_ZONE(addr, bz) (bz->phys_addr + ((uintptr_t)addr - dpaa2_memzone_virt(bz)))

#define DPAA2_INLINE_MBUF_FROM_BUF(buf, meta_data_size) \
	((struct dpaa2_mbuf *)((uint64_t)buf -  meta_data_size))
#define DPAA2_BUF_FROM_INLINE_MBUF(mbuf, meta_data_size) \
	((uint8_t *)((uint64_t)mbuf + meta_data_size))

/* Refer to Table 7-3 in SEC BG */
struct qbman_fle {
	uint32_t addr_lo;
	uint32_t addr_hi;
	uint32_t length;
	/* FMT must be 00, MSB is final bit  */
	uint32_t fin_bpid_offset;
	uint32_t frc;
	uint32_t reserved[3]; /* Not used currently */
};

/*!
 * Structure representing private buffer pool list. This buffer pool list may
 * have several buffer pools
 */
struct dpaa2_bp_list {
	struct dpaa2_bp_list *next;
	uint8_t num_buf_pools;
	struct buf_pool buf_pool[DPAA2_MAX_BUF_POOLS];
};

/*!
 * @details	Initializes the buffer pool list. Within this API
 *		memory required will be allocated, dpbp will get initialized,
 *		buffer pool list will be configured
 *
 * @param[in]	bp_list_cfg - buffer pool list configuration
 *
 * @returns	buffer pool list pointer in case of success; NULL otherwise
 *
 */
struct dpaa2_bp_list *dpaa2_mbuf_create_bp_list(
		struct dpaa2_bp_list_cfg *bp_list_cfg);


/*!
 * @details	Add the buffer pool list to the global list. Also the buffer
 *		pools in the list are stored in sorted order of size.
 *
 * @param[in]	bp_list - buffer pool list
 *
 * @returns	none
 *
 */
void dpaa2_add_bp_list(
		struct dpaa2_bp_list *bp_list);


/*!
 * @details	Allocate a SG DPAA2 buffer of given size from given 'dev'.
 *
 * @param[in]	dev - DPAA2 device. Buffer will be allcoated from the pool
 *		affined to this 'dev'
 *
 * @param[in]	size - the DPAA2 buffer size required.
 *
 * @returns	dpaa2 buffer on success; NULL of failure .
 *
 */
dpaa2_mbuf_pt dpaa2_mbuf_alloc_sg(
		struct dpaa2_dev *dev,
		uint32_t size);


/*!
 * @details	Allocate SG DPAA2 buffer from given buffer pool.
 *
 * @param[in]	bpid - buffer pool id (which was filled in by DPAA2 at
 *		'dpaa2_mbuf_create_bp_list'
 *
 * @param[in]	length - if single buffer length is greater than the buffer size
 *		it may allocate SG list.
 *
 * @returns	dpaa2 buffer on success; NULL on failure.
 *
 */
dpaa2_mbuf_pt dpaa2_mbuf_alloc_sg_from_bpid(
		uint16_t bpid,
		int length);


/*!
 * @details	Make a complete copy of given DPAA2 buffer in case of SG
 *
 * @param[out]	to_buf - DPAA2 buffer on which the 'from_buffer' is copied.
 *		'to_buf' should already have the buffer frames in it, and thus
 *		no new frame from any buffer pool will be allocated inside
 *		the function.
 *
 * @param[in]	from_buf - DPAA2 buffer which needs to be copied.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise
 *
 */
int dpaa2_mbuf_sg_copy(
		dpaa2_mbuf_pt to_buf,
		dpaa2_mbuf_pt from_buf);

/* Extern declarations */
extern struct dpaa2_bp_list *g_bp_list;

#ifdef __cplusplus
}
#endif

#endif	/* _DPAA2BUF_PRIV_H_ */
