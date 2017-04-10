/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/schedule.h>
#include <odp_schedule_internal.h>
#include <odp_buffer_internal.h>
#include <odp_packet_internal.h>
#include <odp/api/align.h>
#include <odp/api/queue.h>
#include <odp/api/shared_memory.h>
#include <odp/api/buffer.h>
#include <odp/api/pool.h>
#include <odp_internal.h>
#include <odp_config_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/thread.h>
#include <odp/api/time.h>
#include <odp/api/spinlock.h>
#include <odp/api/hints.h>
#include <odp/api/cpu.h>

#include <configs/odp_config_platform.h>
#include <odp_queue_internal.h>

#include <assert.h>

#define _ODP_SCHED_GROUP_NAMED (ODP_SCHED_GROUP_CONTROL + 1)

typedef struct {
	odp_spinlock_t grp_lock;
	struct {
		char           name[ODP_SCHED_GROUP_NAME_LEN + 1];
		uint32_t       pchannel;
		odp_thrmask_t *mask;
	} sched_grp[ODP_CONFIG_SCHED_GRPS];
	/* reference thread local structure */
	sched_local_t *sched_local_p[ODP_CONFIG_MAX_THREADS];
} sched_t;

/* Global scheduler context */
static sched_t *sched;
/* all threads that are group scheduled */
odp_thrmask_t sched_mask_all;

static inline uint64_t odp_schedule_dummy(odp_queue_t *out_queue, uint64_t wait,
				odp_buffer_t out_buf[], unsigned int max_num,
				unsigned int max_deq);
/* Receive function to have PUSH at run time */
__thread odp_sch_recv_t fn_sch_recv_pkt = odp_schedule_dummy;

#define QM_SDQCR_COUNT_UPTO3	    0x20000000

/* Thread local scheduler context */
__thread sched_local_t sched_local;

odp_thrmask_t *thread_sched_grp_mask(int index);

int odp_schedule_init_global(void)
{
	int i;
	int ret = 0;
	uint32_t pch[NUM_POOL_CHANNELS_GROUP];
	odp_shm_t shm;

	shm = odp_shm_reserve("odp_group_sched_shm",
			      sizeof(sched_t),
			      ODP_CACHE_LINE_SIZE, 0);

	sched = odp_shm_addr(shm);
	if (!sched) {
		ODP_ERR("Schedule init: Shm reserve failed.\n");
		return -1;
	}

	memset(sched, 0, sizeof(sched_t));

	odp_spinlock_init(&sched->grp_lock);

	for (i = 0; i < ODP_CONFIG_SCHED_GRPS; i++)
		sched->sched_grp[i].mask = thread_sched_grp_mask(i);

	odp_thrmask_zero(&sched_mask_all);

	ret = qman_alloc_pool_range(&pch[0],
				    NUM_POOL_CHANNELS_GROUP, 1, 0);
	if (ret != NUM_POOL_CHANNELS_GROUP) {
		ODP_ERR("Cannot allocate %d pool channels for group scheduling",
			NUM_POOL_CHANNELS_GROUP);
		return -1;
	}
	/* populate allocated channels into sched struct*/
	for (i = 0; i < NUM_POOL_CHANNELS_GROUP; i++)
		sched->sched_grp[i + _ODP_SCHED_GROUP_NAMED].pchannel = pch[i];

	return 0;
}

int odp_schedule_term_global(void)
{
	odp_shm_t grp_shm = odp_shm_lookup("odp_group_sched_shm");

	if (grp_shm == ODP_SHM_INVALID) {
		ODP_ERR("Cannot find shm \"odp_group_sched_shm\"");
		return -1;
	}

	return odp_shm_free(grp_shm);
}

int odp_schedule_init_local(uint32_t sdqcr)
{
	int i;

	for (i = 0; i < MAX_DEQ; i++) {
		sched_local.buf[i] = ODP_BUFFER_INVALID;
		sched_local.buf_ctx[i] = NULL;
	}

	sched_local.num   = 0;
	sched_local.index = 0;
	sched_local.sdqcr = sdqcr;
	sched_local.qp = NULL;
	/* NOTE - in order to be able to update SDQCR for
	other threads one needs to have a reference to the affine
	portal. However, this is currently internal to USDPAA. */
	odp_spinlock_lock(&sched->grp_lock);
	sched->sched_local_p[odp_thread_id()] = &sched_local;
	odp_spinlock_unlock(&sched->grp_lock);

#if defined (ODP_SCHED_FAIR) && defined (ODP_ATOMIC_SCHED_FAIR)
	uint32_t _sdqcr;
	_sdqcr = qman_static_dequeue_get();
	/* reset FC <=> QM_SDQCR_COUNT_EXACT1*/
	_sdqcr &= ~QM_SDQCR_COUNT_UPTO3;
	qman_static_dequeue_set(_sdqcr);
	/* forces HOLDACTIVE queue to be scheduled in another portal
	 CAUTION : this disables the use of POLL queues which require at least
	 3 entries in DQRR */
	qman_dqrr_set_maxfill(1);
#endif
	sched_local.init_done = true;

	return 0;
}

void odp_schedule_release_atomic(void)
{
	const struct qm_dqrr_entry *dqrr = NULL;

	if (sched_local.index)
		dqrr = sched_local.buf_ctx[sched_local.index - 1];

	if (dqrr) {
		qman_dca((struct qm_dqrr_entry *)dqrr, 0);
		sched_local.buf_ctx[sched_local.index - 1] = NULL;
	}
}

static int copy_bufs(odp_buffer_t out_buf[], unsigned int max)
{
	int i = 0;

	do {
		out_buf[i] = sched_local.buf[sched_local.index];
		sched_local.buf[sched_local.index] = ODP_BUFFER_INVALID;
		sched_local.index++;
		sched_local.num--;
		max--;
		i++;
	} while (sched_local.num && max);

	return i;
}

/*
 * Schedule queues
 */
static int schedule(odp_queue_t *out_queue ODP_UNUSED, odp_buffer_t out_buf[],
		    unsigned int max_num, unsigned int max_deq)
{
	int ret;

	if (sched_local.num) {
		ret = copy_bufs(out_buf, max_num);
		return ret;
	}

	sched_local.index = 0;
	qman_poll_dqrr(max_deq);
	sched_local.num = sched_local.index;
	/* reset the index for copy_bufs loop */
	sched_local.index = 0;
	if (sched_local.num) {
		ret = copy_bufs(out_buf, max_num);
		return ret;
	}

	return 0;
}

static int schedule_loop(odp_queue_t *out_queue, uint64_t wait,
			  odp_buffer_t out_buf[],
			  unsigned int max_num, unsigned int max_deq)
{
	odp_time_t next, wtime;
	int first = 1;
	int ret;

	while (1) {
		ret = schedule(out_queue, out_buf, max_num, max_deq);

		if (ret)
			break;

		if (wait == ODP_SCHED_WAIT)
			continue;

		if (wait == ODP_SCHED_NO_WAIT)
			break;

		if (first) {
			wtime = odp_time_local_from_ns(wait);
			next = odp_time_sum(odp_time_local(), wtime);
			first = 0;
			continue;
		}

		if (odp_time_cmp(next, odp_time_local()) < 0)
			break;
	}

	return ret;
}

/* This dummy Receive function will first configure the Channel to thread
 * mapping for PUSH & then reset the "fn_sch_recv_pkt" function
 * pointer to related Function
 */
static inline uint64_t odp_schedule_dummy(odp_queue_t *out_queue, uint64_t wait,
				odp_buffer_t out_buf[], unsigned int max_num,
				unsigned int max_deq)
{
	/* Enable channels scheduling for worker thread only */
	qman_static_dequeue_add(sched_local.sdqcr);
	fn_sch_recv_pkt = (void *)schedule_loop;
	return fn_sch_recv_pkt(out_queue, wait, out_buf, max_num, max_deq);
}

odp_event_t odp_schedule(odp_queue_t *out_queue, uint64_t wait)
{
	odp_buffer_t buf;
	odp_time_t next, wtime;
	int first = 1;
#ifndef ODP_SCHED_FAIR
	static __thread int sdqcr_enable;

	if (!sdqcr_enable) {
		qman_static_dequeue_add(sched_local.sdqcr);
		sdqcr_enable = 1;
	}

#else
	qman_static_dequeue_add(sched_local.sdqcr);
#endif

	while (1) {
		buf = (void *)qman_poll_odp_dqrr();

		if (buf)
			break;

		if (wait == ODP_SCHED_WAIT)
			continue;

		/* If buffer was not returned by QBMAN set it as invalid */
		buf = ODP_BUFFER_INVALID;

		if (wait == ODP_SCHED_NO_WAIT)
			break;

		if (first) {
			wtime = odp_time_local_from_ns(wait);
			next = odp_time_sum(odp_time_local(), wtime);
			first = 0;
			continue;
		}

		if (odp_time_cmp(next, odp_time_local()) < 0)
			break;
	}

#ifdef ODP_SCHED_FAIR
	qman_static_dequeue_del(sched_local.sdqcr);
#endif
	if (out_queue && (buf != ODP_BUFFER_INVALID))
		*out_queue = ((odp_buffer_hdr_t *)buf)->inq;

	return (odp_event_t)buf;
}

int odp_schedule_multi(odp_queue_t *out_queue, uint64_t wait,
			odp_event_t ev[], int num ODP_UNUSED)
{
	int ret = 0;

	ev[0] = odp_schedule(out_queue, wait);

	if ((odp_buffer_t)ev[0] != ODP_BUFFER_INVALID)
		ret = 1;

	return ret;
}

void odp_schedule_pause(void)
{
	qman_stop_dequeues();
}


void odp_schedule_resume(void)
{
	qman_start_dequeues();
}

uint64_t odp_schedule_wait_time(uint64_t ns)
{
	return ns;
}


int odp_schedule_num_prio(void)
{
	return ODP_CONFIG_SCHED_PRIOS;
}

void odp_schedule_release_ordered(void)
{
	ODP_UNIMPLEMENTED();
}

odp_schedule_group_t odp_schedule_group_lookup(const char *name)
{
	odp_schedule_group_t group = ODP_SCHED_GROUP_INVALID;
	int i;

	ODP_ASSERT(name);

	odp_spinlock_lock(&sched->grp_lock);

	for (i = _ODP_SCHED_GROUP_NAMED; i < ODP_CONFIG_SCHED_GRPS; i++) {
		if (!strcmp(name, sched->sched_grp[i].name)) {
			group = (odp_schedule_group_t)i;
			break;
		}
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return group;
}

odp_schedule_group_t odp_schedule_group_create(const char *name,
					       const odp_thrmask_t *mask)
{
	odp_schedule_group_t group = ODP_SCHED_GROUP_INVALID;
	int i;

	ODP_ASSERT(name);
	ODP_ASSERT(strlen(name) <= ODP_SCHED_GROUP_NAME_LEN);
	ODP_ASSERT(mask);
	/*TODO: mask is usually all zeros, analyze non-zero case */
	odp_spinlock_lock(&sched->grp_lock);

	for (i = _ODP_SCHED_GROUP_NAMED; i < ODP_CONFIG_SCHED_GRPS; i++)
		if (sched->sched_grp[i].name[0] == 0) {
			strcpy(sched->sched_grp[i].name, name);
			odp_thrmask_copy(sched->sched_grp[i].mask, mask);
			group = (odp_schedule_group_t)i;
			break;
		}

	odp_spinlock_unlock(&sched->grp_lock);

	return group;
}

int odp_schedule_group_join(odp_schedule_group_t group,
			    const odp_thrmask_t *mask)
{
	int ret = -1;
	int thr_id;
	int this_thr_id;
	sched_local_t *_sched_local = NULL;

	ODP_ASSERT(mask);
	if (odp_thrmask_count(mask) != 1) {
		ODP_DBG("Expecting mask corresponding to single thread");
		return -1;
	}
	/* get thread id from mask, assume single thread */
	thr_id = odp_thrmask_first(mask);
	/* get caller thread id */
	this_thr_id = odp_thread_id();

	odp_spinlock_lock(&sched->grp_lock);

	if (group < ODP_CONFIG_SCHED_GRPS &&
	    group >= _ODP_SCHED_GROUP_NAMED &&
	    sched->sched_grp[group].name[0] != 0) {
		if (odp_thrmask_isset(sched->sched_grp[group].mask, thr_id)) {
			/* consider success if already part of this group */
			ret = 0;
			goto out;
		}
		_sched_local = sched->sched_local_p[thr_id];
		if (this_thr_id != thr_id) {
			if (!_sched_local) {
				ODP_DBG("Invalid reference to local sched info");
				goto out;
			}
			/* need pointer to affine portal to continue */
			ODP_ASSERT(_sched_local->qp);
		}

		odp_thrmask_or(sched->sched_grp[group].mask,
			       sched->sched_grp[group].mask,
			       mask);
		if (this_thr_id == thr_id)
			qman_static_dequeue_del(_sched_local->sdqcr);
		else
			qman_p_static_dequeue_del(_sched_local->qp,
						  _sched_local->sdqcr);
		/* if first group to be joined by thread, clear sdqcr */
		if (!odp_thrmask_isset(&sched_mask_all, thr_id))
			_sched_local->sdqcr &= ~QM_SDQCR_CHANNELS_POOL_MASK;
		/* indicate this thread is group scheduled in global mask */
		odp_thrmask_or(&sched_mask_all, &sched_mask_all, mask);
		_sched_local->sdqcr |= QM_SDQCR_CHANNELS_POOL_CONV(
					sched->sched_grp[group].pchannel);
		if (this_thr_id != thr_id)
			qman_p_static_dequeue_add(_sched_local->qp,
						  _sched_local->sdqcr);
		else
			qman_static_dequeue_add(_sched_local->sdqcr);

		ret = 0;
	} else {
		ODP_DBG("Invalid group id");
	}

out:
	odp_spinlock_unlock(&sched->grp_lock);

	return ret;
}

int odp_schedule_group_thrmask(odp_schedule_group_t group,
			       odp_thrmask_t *thrmask)
{
	int ret = -1;

	ODP_ASSERT(thrmask);
	odp_spinlock_lock(&sched->grp_lock);

	if (group < ODP_CONFIG_SCHED_GRPS &&
	    group >= _ODP_SCHED_GROUP_NAMED &&
	    sched->sched_grp[group].name[0] != 0) {
		*thrmask = *sched->sched_grp[group].mask;
		ret = 0;
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return ret;
}

int odp_schedule_group_info(odp_schedule_group_t group,
			    odp_schedule_group_info_t *info)
{
	int ret = -1;

	odp_spinlock_lock(&sched->grp_lock);

	if (group < ODP_CONFIG_SCHED_GRPS &&
	    group >= _ODP_SCHED_GROUP_NAMED &&
	    sched->sched_grp[group].name[0] != 0) {
		info->name    =  sched->sched_grp[group].name;
		info->thrmask = *sched->sched_grp[group].mask;
		ret = 0;
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return ret;
}

int odp_schedule_group_leave(odp_schedule_group_t group,
			     const odp_thrmask_t *mask)
{
	int ret = -1;
	sched_local_t *_sched_local = NULL;
	int thr_id;
	int this_thr_id;

	ODP_ASSERT(mask);
	if (odp_thrmask_count(mask) != 1) {
		ODP_DBG("Expecting mask corresponding to single thread");
		return -1;
	}

	/* get thread_id from mask, assume single thread leave */
	thr_id = odp_thrmask_first(mask);
	/* get caller thread id */
	this_thr_id = odp_thread_id();

	odp_spinlock_lock(&sched->grp_lock);

	if (group < ODP_CONFIG_SCHED_GRPS &&
	    group >= _ODP_SCHED_GROUP_NAMED &&
	    sched->sched_grp[group].name[0] != 0) {
		if (!odp_thrmask_isset(sched->sched_grp[group].mask, thr_id)) {
			ODP_DBG("Thread not part of group");
			goto out;
		}
		odp_thrmask_t leavemask;

		_sched_local = sched->sched_local_p[thr_id];
		if (this_thr_id != thr_id) {
			if (!_sched_local) {
				ODP_DBG("Invalid reference to local sched info");
				goto out;
			}
			ODP_ASSERT(_sched_local->qp);
		}

		odp_thrmask_xor(&leavemask, mask, &sched_mask_all);
		odp_thrmask_and(sched->sched_grp[group].mask,
				sched->sched_grp[group].mask,
				&leavemask);
		if (this_thr_id != thr_id)
			qman_p_static_dequeue_del(_sched_local->qp,
						  _sched_local->sdqcr);
		else
			qman_static_dequeue_del(_sched_local->sdqcr);
		/* clear corresponding bit in sdqcr */
		_sched_local->sdqcr ^= QM_SDQCR_CHANNELS_POOL_CONV(
					sched->sched_grp[group].pchannel);
		if ((_sched_local->sdqcr & QM_SDQCR_CHANNELS_POOL_MASK) == 0) {
			/* no group membership, default to worker sdqcr */
			_sched_local->sdqcr = sdqcr_default;
			/* signal thread is no longer group scheduled */
			odp_thrmask_and(&sched_mask_all, &sched_mask_all,
					&leavemask);
		}
		if (this_thr_id != thr_id)
			qman_p_static_dequeue_add(_sched_local->qp,
						  _sched_local->sdqcr);
		else
			qman_static_dequeue_add(_sched_local->sdqcr);

		ret = 0;
	} else {
		ODP_DBG("Invalid group id");
	}

out:
	odp_spinlock_unlock(&sched->grp_lock);

	return ret;
}

void odp_schedule_prefetch(int num ODP_UNUSED)
{
        ODP_UNIMPLEMENTED();
}

int odp_schedule_group_destroy(odp_schedule_group_t group)
{
	int ret = -1;

	odp_spinlock_lock(&sched->grp_lock);
	/* TODO it is the responsibility of the caller to ensure
	there are no more threads within this group or queues
	referencing this group! */

	if (group < ODP_CONFIG_SCHED_GRPS &&
	    group >= _ODP_SCHED_GROUP_NAMED &&
	    sched->sched_grp[group].name[0] != 0) {
		odp_thrmask_zero(sched->sched_grp[group].mask);
		memset(sched->sched_grp[group].name, 0,
		       ODP_SCHED_GROUP_NAME_LEN);
		ret = 0;
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return ret;
}

int get_group_channel(odp_schedule_group_t group, uint16_t *pchannel)
{
	int ret = -1;

	ODP_ASSERT(pchannel);
	odp_spinlock_lock(&sched->grp_lock);

	if (group < ODP_CONFIG_SCHED_GRPS &&
	    group >= _ODP_SCHED_GROUP_NAMED &&
	    sched->sched_grp[group].name[0] != 0) {
		*pchannel = (uint16_t)sched->sched_grp[group].pchannel;
		ret = 0;
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return ret;
}
