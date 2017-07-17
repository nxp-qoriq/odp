/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/std_types.h>
#include <odp/api/pool.h>
#include <odp_pool_internal.h>
#include <odp_packet_internal.h>
#include <odp_timer_internal.h>
#include <odp_align_internal.h>
#include <odp/api/shared_memory.h>
#include <odp/api/align.h>
#include <odp_internal.h>
#include <odp_config_internal.h>
#include <odp/api/hints.h>
#include <odp_debug_internal.h>
#include <odp_atomic_internal.h>

#include <string.h>
#include <stdlib.h>

/* for DPAA2 */
#include <dpaa2_mbuf.h>
#include <dpaa2_mbuf_priv.h>
#include <dpaa2_io_portal_priv.h>
#include <odp_packet_dpaa2.h>


extern int dpaa2_mbuf_pool_get_bpid(void *bplist);

#if ODP_CONFIG_POOLS > ODP_BUFFER_MAX_POOLS
#error ODP_CONFIG_POOLS > ODP_BUFFER_MAX_POOLS
#endif

typedef struct pool_table_t {
	pool_entry_t pool[ODP_CONFIG_POOLS];
} pool_table_t;

/* The pool table */
static pool_table_t *pool_tbl;

static const char SHM_DEFAULT_NAME[] = "odp_buffer_pools";

/* Pool entry pointers (for inlining) */
void *pool_entry_ptr[ODP_CONFIG_POOLS];

int odp_pool_init_global(void)
{
	uint32_t i;
	odp_shm_t shm;

	shm = odp_shm_reserve(SHM_DEFAULT_NAME,
				sizeof(pool_table_t),
				/*sizeof(pool_entry_t)*/0, 0);

	pool_tbl = odp_shm_addr(shm);

	if (pool_tbl == NULL)
		return -1;

	memset(pool_tbl, 0, sizeof(pool_table_t));

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		/* init locks */
		pool_entry_t *pool = &pool_tbl->pool[i];
		POOL_LOCK_INIT(&pool->s.lock);
		pool->s.int_hdl = NULL;
		pool->s.pool_id = i;
		pool_entry_ptr[i] = pool;
	}

	ODP_DBG("\nPool init global\n");
	ODP_DBG("  pool_entry_s size     %zu\n", sizeof(struct pool_entry_s));
	ODP_DBG("  pool_entry_t size     %zu\n", sizeof(pool_entry_t));
	ODP_DBG("  odp_buffer_hdr_t size %zu\n", sizeof(odp_buffer_hdr_t));
	ODP_DBG("\n");
	return 0;
}

int odp_pool_term_global(void)
{
	int i;
	pool_entry_t *pool;
	int ret = 0;
	int rc = 0;

	if (!pool_tbl)
		return 0;
	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool = get_pool_entry(i);

		if (pool) {
			POOL_LOCK(&pool->s.lock);
			if (pool->s.pool_shm != ODP_SHM_INVALID) {
				ODP_ERR("Not destroyed pool: %s\n", pool->s.name);
				rc = -1;
			}
			POOL_UNLOCK(&pool->s.lock);
		}
	}

	ret = odp_shm_free(odp_shm_lookup(SHM_DEFAULT_NAME));
	if (ret < 0) {
		ODP_ERR("shm free failed for %s", SHM_DEFAULT_NAME);
		rc = -1;
	}

	return rc;
}

int odp_pool_term_local(void)
{
	return 0;
}

/*
 * save the object number in the first 4 bytes of object data. All
 * other bytes are set to 0.
 */
static void
my_elem_init(void *mp ODP_UNUSED, void *arg,
	void *obj, unsigned i ODP_UNUSED)
{
	uint8_t type = (uint8_t)((uint64_t)arg);
	struct dpaa2_mbuf *mbuf = obj;
	memset(obj, 0, sizeof (struct dpaa2_mbuf));
	_odp_buffer_type_set(mbuf, type);
}

void odp_pool_param_init(odp_pool_param_t *params)
{
	memset(params, 0, sizeof(odp_pool_param_t));
}

/**
 * Pool creation
 */

odp_pool_t odp_pool_create(const char *name, odp_pool_param_t *params)
{
	pool_entry_t *pool;
	uint32_t i, tailroom = 0;
	uint64_t blk_size, buf_num;
	uint32_t seg_len = 0;
	uint32_t buf_align;

	if (params == NULL)
		return ODP_POOL_INVALID;

	/* Default size and align for timeouts */
	if (params->type == ODP_POOL_TIMEOUT) {
		params->buf.align = 0; /* tmo.__res2 */
	}

	buf_align = params->type == ODP_POOL_BUFFER ? params->buf.align : 0;

	/* Validate requested buffer alignment */
	if (buf_align > ODP_CONFIG_BUFFER_ALIGN_MAX ||
	    buf_align != ODP_ALIGN_ROUNDDOWN_POWER_2(buf_align, buf_align))
		return ODP_POOL_INVALID;

	/* Set correct alignment based on input request */
	if (buf_align == 0)
		buf_align = ODP_CACHE_LINE_SIZE;
	else if (buf_align < ODP_CONFIG_BUFFER_ALIGN_MIN)
		buf_align = ODP_CONFIG_BUFFER_ALIGN_MIN;

	/* Calculate space needed for buffer blocks and metadata */
	switch (params->type) {
	case ODP_POOL_BUFFER:
		buf_num  = params->buf.num;
		blk_size = params->buf.size;

		/* Optimize small raw buffers */
		if (blk_size > ODP_MAX_INLINE_BUF || params->buf.align != 0)
			blk_size = ODP_ALIGN_ROUNDUP(blk_size, buf_align);
		break;
	case ODP_POOL_PACKET:
		tailroom = ODP_CONFIG_PACKET_TAILROOM;
		buf_num = params->pkt.num;
		seg_len = params->pkt.seg_len <= ODP_CONFIG_PACKET_SEG_LEN_MIN ?
			ODP_CONFIG_PACKET_SEG_LEN_MIN :
			(params->pkt.seg_len <= ODP_CONFIG_PACKET_SEG_LEN_MAX ?
			 params->pkt.seg_len : ODP_CONFIG_PACKET_SEG_LEN_MAX);

		seg_len = ODP_ALIGN_ROUNDUP(
			seg_len + tailroom,
			ODP_CONFIG_BUFFER_ALIGN_MIN);

		blk_size = params->pkt.len <= seg_len ? seg_len :
			ODP_ALIGN_ROUNDUP(params->pkt.len, seg_len);

		/*todo - w.r.t WRIOP 256 byte alignment requirement
		making the buffer in multiple of 256 */
		if ((mc_plat_info.svr & 0xffff0000) == SVR_LS2080A)
			blk_size = ODP_ALIGN_ROUNDUP(blk_size, 256);
		else
			blk_size = ODP_ALIGN_ROUNDUP(blk_size, 64);

		break;
	case ODP_POOL_TIMEOUT:
		blk_size = 64;
		buf_num = params->tmo.num;
		break;

	default:
		return ODP_POOL_INVALID;
	}


	/* Find an unused buffer pool slot and iniitalize it as requested */
	for (i = 0, pool = NULL; i < ODP_CONFIG_POOLS; i++, pool = NULL) {
		pool = get_pool_entry(i);
		if (pool && pool->s.flags.all == 0)
			break;
	}
	if (!pool) {
		ODP_ERR("FREE buffer pool not available");
		return ODP_POOL_INVALID;
	}
	POOL_LOCK(&pool->s.lock);

	if (params->type == ODP_POOL_PACKET) {
		void *h_bp_list;
		struct dpaa2_bp_list_cfg bp_list_cfg;
		/* Buffer Pool allocation. ODP APs provide only one buffer pool */
		memset(&bp_list_cfg, 0, sizeof(struct dpaa2_bp_list_cfg));
		bp_list_cfg.num_buf_pools = 1;
		bp_list_cfg.buf_pool[0].num = buf_num;
		bp_list_cfg.buf_pool[0].size = blk_size;
		if ((mc_plat_info.svr & 0xffff0000) == SVR_LS2080A)
			bp_list_cfg.buf_pool[0].meta_data_size = ODP_ALIGN_ROUNDUP(sizeof(odp_packet_hdr_t)
								+ params->pkt.uarea_size, 256);
		else
			bp_list_cfg.buf_pool[0].meta_data_size = ODP_ALIGN_ROUNDUP(sizeof(odp_packet_hdr_t)
								+ params->pkt.uarea_size, 64);
		bp_list_cfg.buf_pool[0].odp_user_area = params->pkt.uarea_size;
		h_bp_list = dpaa2_mbuf_pool_list_init(&bp_list_cfg);
		if (!h_bp_list) {
			ODP_ERR("Buffer pool is not initialised\n");
			POOL_UNLOCK(&pool->s.lock);
			return ODP_POOL_INVALID;
		}
		ODP_DBG("Configuring buffer pool list %p", h_bp_list);
		ODP_DBG("bufnum = %u, size = %lu user_area = %u meta_data = %u",
				buf_num, blk_size, params->pkt.uarea_size,
				bp_list_cfg.buf_pool[0].meta_data_size);

		pool->s.bpid = dpaa2_mbuf_pool_get_bpid(h_bp_list);
		pool->s.int_hdl = h_bp_list;
	} else {
		struct dpaa2_mpool_cfg mpcfg = {0};
		mpcfg.name = name;
		mpcfg.block_size = sizeof(struct dpaa2_mbuf) + blk_size;
		mpcfg.num_global_blocks = buf_num;
		mpcfg.num_max_blocks = buf_num;
		mpcfg.alignment = buf_align;
		mpcfg.priv_data_size = sizeof(struct dpaa2_mbuf);
		pool->s.int_hdl = dpaa2_mpool_create(&mpcfg, my_elem_init,
			(void *)(uint64_t)(params->type));
		if (!pool->s.int_hdl) {
			ODP_ERR("Buffer pool is not initialised\n");
			POOL_UNLOCK(&pool->s.lock);
			return ODP_POOL_INVALID;
		}
	}
	pool->s.flags.all = 0;
	if (name == NULL) {
		pool->s.name[0] = 0;
	} else {
		strncpy(pool->s.name, name,
			ODP_POOL_NAME_LEN - 1);
		pool->s.name[ODP_POOL_NAME_LEN - 1] = 0;
		pool->s.flags.has_name = 1;
	}
	pool->s.params = *params;
	pool->s.pool_shm = NULL;
	pool->s.flags.user_supplied_shm = 0;

	POOL_UNLOCK(&pool->s.lock);

	return (odp_pool_t)pool;
}


odp_pool_t odp_pool_lookup(const char *name)
{
	uint32_t i;
	pool_entry_t *pool;

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool = get_pool_entry(i);
		if (!pool)
			continue;

		POOL_LOCK(&pool->s.lock);
		if (strcmp(name, pool->s.name) == 0) {
			/* found it */
			POOL_UNLOCK(&pool->s.lock);
			return (odp_pool_t)pool;
		}
		POOL_UNLOCK(&pool->s.lock);
	}

	return ODP_POOL_INVALID;
}

odp_pool_t odp_debug_pool_lookup(const char *name)
{
	uint32_t i;
	pool_entry_t *pool;
	struct dpaa2_bp_list *bp_list;

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool = get_pool_entry(i);
		bp_list = (struct dpaa2_bp_list *)pool->s.int_hdl;

		POOL_LOCK(&pool->s.lock);
		if (strcmp(name, bp_list->buf_pool->dpbp_node->name) == 0) {
			POOL_UNLOCK(&pool->s.lock);
			return (odp_pool_t)pool;
		}
		POOL_UNLOCK(&pool->s.lock);
	}

	return ODP_POOL_INVALID;
}

int odp_pool_info(odp_pool_t pool_hdl, odp_pool_info_t *info)
{
	pool_entry_t *pool = odp_pool_to_entry(pool_hdl);

	if (pool == NULL || info == NULL)
		return -1;

	info->name = pool->s.name;
	info->params.buf.size  = pool->s.params.buf.size;
	info->params.buf.align = pool->s.params.buf.align;
	info->params.buf.num   = pool->s.params.buf.num;
	info->params.type      = pool->s.params.type;

	return 0;
}

int odp_pool_destroy(odp_pool_t pool_hdl)
{
	pool_entry_t *pool = odp_pool_to_entry(pool_hdl);

	if (pool == NULL)
		return -1;

	POOL_LOCK(&pool->s.lock);

	if (pool->s.params.type != ODP_EVENT_PACKET) {
		dpaa2_mpool_delete((void *)pool->s.int_hdl);
	} else {
		dpaa2_mbuf_pool_list_deinit((void *)pool->s.int_hdl);
	}

	pool->s.flags.all = 0;

	POOL_UNLOCK(&pool->s.lock);

	return 0;
}

static inline odp_buffer_t buffer_alloc(odp_pool_t pool_hdl, size_t size)
{
	pool_entry_t *pool = odp_pool_to_entry(pool_hdl);

	if (pool->s.params.type == ODP_POOL_PACKET) {
		return (odp_buffer_t)odp_packet_alloc(pool_hdl, size);
	} else {
		return (odp_buffer_t)get_buf(&pool->s);
	}
}

odp_buffer_t odp_buffer_alloc(odp_pool_t pool_hdl)
{
	return buffer_alloc(pool_hdl,
		odp_pool_to_entry(pool_hdl)->s.params.buf.size);
}

void odp_buffer_free(odp_buffer_t buf)
{
	odp_buffer_hdr_t *buf_hdr = odp_buf_to_hdr(buf);
	pool_entry_t *pool = odp_buf_to_pool(buf_hdr);

	if (pool->s.params.type == ODP_POOL_PACKET)
		dpaa2_mbuf_free(buf_hdr);
	else
		ret_blk(&pool->s, buf);
	return;
}

void odp_pool_print(odp_pool_t pool_hdl)
{
	pool_entry_t *pool = odp_pool_to_entry(pool_hdl);

	if (!pool)
		return;

	ODP_PRINT("\n\n");
	ODP_PRINT("Pool Print:\n");
	ODP_PRINT("Pool id              = \t\t%d\n", pool->s.pool_id);
	ODP_PRINT("Pool Name            = \t\t%s\n", pool->s.name);

	if (pool->s.params.type == ODP_POOL_PACKET) {
		ODP_PRINT("Pool type            = \t\t%s\n", "PACKET POOL");
		ODP_PRINT("Number of packets                            = \t\t%d\n", pool->s.params.pkt.num);
		ODP_PRINT("Minimum length for each packet               = \t\t%d\n", pool->s.params.pkt.len);
		ODP_PRINT("Min pkt data bytes stored in 1st seg	      = \t\t%d\n", pool->s.params.pkt.seg_len);
		ODP_PRINT("user area size                               = \t\t%d\n", pool->s.params.pkt.uarea_size);
	} else if (pool->s.params.type == ODP_POOL_BUFFER) {
		ODP_PRINT("Pool type            = \t\t%s\n", "BUFFER POOL");
		ODP_PRINT("Number of buffers                    = \t\t%d\n", pool->s.params.buf.num);
		ODP_PRINT("Max number of bytes for each buffer  = \t\t%d\n", pool->s.params.buf.size);
		ODP_PRINT("Minimum buffer alignment in bytes    = \t\t%d\n", pool->s.params.buf.align);
	} else {
		ODP_PRINT("Pool type            = \t\t%s\n", "TIMEOUT POOL");
		ODP_PRINT("Number of timeouts                   = \t\t%d\n", pool->s.params.tmo.num);
        }
}

odp_pool_t odp_buffer_pool(odp_buffer_t buf)
{
	return (odp_pool_t)odp_buf_to_pool(buf);
}

odp_buffer_t odpfsl_buffer_from_addr(void *addr)
{
	odp_buffer_t buf;
	void *buf_addr;

	buf = (odp_buffer_t)(addr - sizeof(odp_buffer_hdr_t));
	buf_addr = odp_buffer_addr(buf);

	if (buf_addr != addr)
		return NULL;

	return buf;
}

int pool_type_is_packet(odp_pool_t pool)
{
	pool_entry_t *pool_entry = odp_pool_to_entry(pool);
	int is_packet = false;

	if (pool_entry)
		is_packet = (pool_entry->s.params.type == ODP_POOL_PACKET);

	return is_packet;
}

int odp_pool_capability(odp_pool_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_pool_capability_t));

	/* Buffer pools */
	capa->buf.max_pools = ODP_CONFIG_POOLS;
	capa->buf.max_align = ODP_CONFIG_BUFFER_ALIGN_MAX;
	capa->buf.max_size  = 0;
	capa->buf.max_num   = 0;

	/* Packet pools */
	capa->pkt.max_pools = ODP_CONFIG_POOLS;
	capa->pkt.max_len = ODP_CONFIG_PACKET_MAX_SEGS *
							ODP_CONFIG_PACKET_SEG_LEN_MIN;
	capa->pkt.max_num = 0;
	capa->pkt.min_headroom = ODP_CONFIG_PACKET_HEADROOM;
	capa->pkt.min_tailroom = ODP_CONFIG_PACKET_TAILROOM;
	capa->pkt.max_segs_per_pkt = ODP_CONFIG_PACKET_MAX_SEGS;
	capa->pkt.min_seg_len      = ODP_CONFIG_PACKET_SEG_LEN_MIN;
	capa->pkt.max_seg_len      = ODP_CONFIG_PACKET_SEG_LEN_MAX;
	capa->pkt.max_uarea_size   = 0;

	/* Timeout pools */
	capa->tmo.max_pools = ODP_CONFIG_POOLS;
	capa->tmo.max_num   = 0;

	capa->max_pools = capa->buf.max_pools + capa->pkt.max_pools
					+ capa->tmo.max_pools;
	return 0;
}
