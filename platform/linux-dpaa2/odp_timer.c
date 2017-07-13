/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP timer service
 *
 */

/* Check if compiler supports 16-byte atomics. GCC needs -mcx16 flag on x86 */
/* Using spin lock actually seems faster on Core2 */
#ifdef ODP_ATOMIC_U128
/* TB_NEEDS_PAD defined if sizeof(odp_buffer_t) != 8 */
#define TB_NEEDS_PAD
#define TB_SET_PAD(x) ((x).pad = 0)
#else
#define TB_SET_PAD(x) (void)(x)
#endif

/* For snprint, POSIX timers and sigevent */
#define _POSIX_C_SOURCE 200112L
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <odp/api/align.h>
#include <odp_align_internal.h>
#include <odp/api/atomic.h>
#include <odp_atomic_internal.h>
#include <odp/api/buffer.h>
#include <odp/api/pool.h>
#include <odp_pool_internal.h>
#include <odp/api/debug.h>
#include <odp_debug_internal.h>
#include <odp/api/event.h>
#include <odp/api/hints.h>
#include <odp_internal.h>
#include <odp/api/queue.h>
#include <odp/api/shared_memory.h>
#include <odp/api/spinlock.h>
#include <odp/api/std_types.h>
#include <odp/api/sync.h>
#include <odp/api/time.h>
#include <odp/api/timer.h>
#include <odp_timer_internal.h>
#include <dpaa2_timer.h>
#include <dpaa2_time.h>
#include <dpaa2.h>

#define TMO_UNUSED   ((uint64_t)0xFFFFFFFFFFFFFFFF)
/* TMO_INACTIVE is or-ed with the expiration tick to indicate an expired timer.
 * The original expiration tick (63 bits) is still available so it can be used
 * for checking the freshness of received timeouts */

#ifdef __ARM_ARCH
#define PREFETCH(ptr) __builtin_prefetch((ptr), 0, 0)
#else
#define PREFETCH(ptr) (void)(ptr)
#endif

#define ODP_TICKS_INVALID ((uint64_t)~0U)

/******************************************************************************
 * Mutual exclusion in the absence of CAS16
 *****************************************************************************/

#ifndef ODP_ATOMIC_U128
#define NUM_LOCKS 1024
static _odp_atomic_flag_t locks[NUM_LOCKS]; /* Multiple locks per cache line! */
#define IDX2LOCK(idx) (&locks[(idx) % NUM_LOCKS])
#endif

#define MAX_CORES		8	/*Number of cores*/
uint8_t core_mask[MAX_CORES] = {0};	/*Mask value for creating one manager
					thread per core*/

struct worker {
	pthread_t id;
	uint64_t ures;			/*resolution in micro seconds*/
	int cpu;
};

struct worker attr[MAX_CORES];		/*Data for each manager thread*/

static void callback_func_tim(__attribute__((unused)) struct dpaa2_timer *tim,											__attribute__((unused)) void *arg);

/******************************************************************************
 * Translation between timeout buffer and timeout header
 *****************************************************************************/

static odp_timeout_hdr_t *timeout_hdr_from_buf(odp_buffer_t buf)
{
	return (odp_timeout_hdr_t *)odp_buf_to_hdr(buf);
}

/******************************************************************************
 * odp_timer abstract datatype
 *****************************************************************************/

typedef struct tick_buf_s {
	odp_atomic_u64_t exp_tck;/* Expiration tick or TMO_xxx */
	odp_buffer_t tmo_buf;/* ODP_BUFFER_INVALID if timer not active */
#ifdef TB_NEEDS_PAD
	uint32_t pad;/* Need to be able to access padding for successful CAS */
#endif
} tick_buf_t
#ifdef ODP_ATOMIC_U128
ODP_ALIGNED(16) /* 16-byte atomic operations need properly aligned addresses */
#endif
;
#if	defined __powerpc64__ || defined __aarch64__
//TODO need to find the right solution for 32 bit arch.
ODP_STATIC_ASSERT(sizeof(tick_buf_t) == 16, "sizeof(tick_buf_t) == 16");
#endif

/*Timers data*/
struct tim_data {
	void *user_ptr;
	odp_queue_t queue;
	odp_event_t ev;
};

typedef struct dpaa2_timer odp_timer;

/*initialize the timer with queue and user_ptr*/
static void timer_init(odp_timer *tim,
		odp_queue_t _q,
		void *_up)
{
	struct tim_data *data = malloc(sizeof(struct tim_data));

	data->user_ptr = _up;
	data->queue = _q;
	data->ev = ODP_EVENT_INVALID;
	tim->arg = data;
}

/* Teardown when timer is freed */
static void timer_fini(odp_timer *tim)
{
	struct tim_data *data;

	if (!tim->arg)
		return;
	data = tim->arg;
	data->user_ptr = NULL;
	data->queue = ODP_QUEUE_INVALID;
	data->ev = ODP_EVENT_INVALID;
	free(data);
	tim->arg = NULL;
}

/******************************************************************************
 * odp_timer_pool abstract datatype
 * Inludes alloc and free timer
 *****************************************************************************/

TAILQ_HEAD(odp_timer_list, dpaa2_timer); /*!< Timer List */

typedef struct odp_timer_pool_s {
/* Put frequently accessed fields in the first cache line */
	odp_atomic_u64_t cur_tick;/* Current tick value */
	uint64_t min_rel_tck;
	uint64_t max_rel_tck;
	tick_buf_t *tick_buf;	/* Expiration tick and timeout buffer */
	odp_timer *timers;	/* pointer to timers */
	struct odp_timer_list *free_tim_list; /*!< Contains free timer objects */
	odp_atomic_u32_t high_wm;/* High watermark of allocated timers */
	odp_spinlock_t itimer_running;
	odp_spinlock_t lock;
	uint32_t num_alloc;/* Current number of allocated timers */
	uint32_t tp_idx;/* Index into timer_pool array */
	odp_timer_pool_param_t param;
	char name[ODP_TIMER_POOL_NAME_LEN];
	odp_shm_t shm;
	timer_t timerid;
} odp_timer_pool;

#define MAX_TIMER_POOLS 255 /* Leave one for ODP_TIMER_INVALID */
#define INDEX_BITS 24
static odp_atomic_u32_t num_timer_pools;
static odp_timer_pool *timer_pool[MAX_TIMER_POOLS];

static inline odp_timer_pool *handle_to_tp(odp_timer_t hdl)
{
	uint32_t tp_idx = hdl >> INDEX_BITS;
	if (odp_likely(tp_idx < MAX_TIMER_POOLS)) {
		odp_timer_pool *tp = timer_pool[tp_idx];
		if (odp_likely(tp != NULL))
			return timer_pool[tp_idx];
	}
	ODP_ABORT("Invalid timer handle %#x\n", hdl);
}

static inline uint32_t handle_to_idx(odp_timer_t hdl,
		struct odp_timer_pool_s *tp)
{
	uint32_t idx = hdl & ((1U << INDEX_BITS) - 1U);
	PREFETCH(&tp->tick_buf[idx]);
	if (odp_likely(idx < odp_atomic_load_u32(&tp->high_wm)))
		return idx;
	ODP_ABORT("Invalid timer handle %#x\n", hdl);
}

static inline odp_timer_t tp_idx_to_handle(struct odp_timer_pool_s *tp,
		uint32_t idx)
{
	ODP_ASSERT(idx < (1U << INDEX_BITS));
	return (tp->tp_idx << INDEX_BITS) | idx;
}


static odp_timer_pool *odp_timer_pool_new(
	const char *_name,
	const odp_timer_pool_param_t *param)
{
	uint32_t tp_idx = odp_atomic_fetch_add_u32(&num_timer_pools, 1);
	if (odp_unlikely(tp_idx >= MAX_TIMER_POOLS)) {
		/* Restore the previous value */
		odp_atomic_sub_u32(&num_timer_pools, 1);
		__odp_errno = ENFILE; /* Table overflow */
		return ODP_TIMER_POOL_INVALID;
	}
	size_t sz0 = ODP_ALIGN_ROUNDUP(sizeof(odp_timer_pool),
			ODP_CACHE_LINE_SIZE);
	size_t sz1 = ODP_ALIGN_ROUNDUP(sizeof(tick_buf_t) * param->num_timers,
			ODP_CACHE_LINE_SIZE);
	size_t sz2 = ODP_ALIGN_ROUNDUP(sizeof(odp_timer) * param->num_timers,
			ODP_CACHE_LINE_SIZE);
	odp_shm_t shm = odp_shm_reserve(_name, sz0 + sz1 + sz2,
			ODP_CACHE_LINE_SIZE, ODP_SHM_SW_ONLY);
	if (odp_unlikely(shm == ODP_SHM_INVALID))
		ODP_ABORT("%s: timer pool shm-alloc(%zuKB) failed\n",
			  _name, (sz0 + sz1 + sz2) / 1024);
	odp_timer_pool *tp = (odp_timer_pool *)odp_shm_addr(shm);
	odp_atomic_init_u64(&tp->cur_tick, 0);
	snprintf(tp->name, sizeof(tp->name), "%s", _name);
	tp->shm = shm;
	tp->param = *param;
	tp->min_rel_tck = odp_timer_ns_to_tick(tp, param->min_tmo);
	tp->max_rel_tck = odp_timer_ns_to_tick(tp, param->max_tmo);
	tp->num_alloc = 0;
	odp_atomic_init_u32(&tp->high_wm, 0);
	tp->tick_buf = (void *)((char *)odp_shm_addr(shm) + sz0);
	tp->timers = (void *)((char *)odp_shm_addr(shm) + sz0 + sz1);
	/* Initialize all odp_timer entries */
	uint32_t i;
	for (i = 0; i < tp->param.num_timers; i++) {
		odp_atomic_init_u64(&tp->tick_buf[i].exp_tck, TMO_UNUSED);
		tp->tick_buf[i].tmo_buf = ODP_BUFFER_INVALID;
	}
	tp->tp_idx = tp_idx;
	odp_spinlock_init(&tp->lock);
	odp_spinlock_init(&tp->itimer_running);

	/* Initialize free list */
	tp->free_tim_list = dpaa2_malloc(NULL, sizeof(struct odp_timer_list));
	TAILQ_INIT(tp->free_tim_list);
	/* Initially all objects are free */
	for (i = 0; i < param->num_timers; i++) {
		odp_timer *tim = &tp->timers[i];
		tim->index = i;
		TAILQ_INSERT_TAIL(tp->free_tim_list, tim, next);
	}

	timer_pool[tp_idx] = tp;
	return tp;
}

static void odp_timer_pool_del(odp_timer_pool *tp)
{
	odp_spinlock_lock(&tp->lock);
	timer_pool[tp->tp_idx] = NULL;
	/* Wait for itimer thread to stop running */
	odp_spinlock_lock(&tp->itimer_running);
	if (tp->num_alloc != 0) {
		/* It's a programming error to attempt to destroy a */
		/* timer pool which is still in use */
		ODP_ABORT("%s: timers in use\n", tp->name);
	}
	int rc = odp_shm_free(tp->shm);
	if (rc != 0)
		ODP_ABORT("Failed to free shared memory (%d)\n", rc);
	if (tp->free_tim_list)
		dpaa2_free(tp->free_tim_list);
}

static inline odp_timer_t timer_alloc(odp_timer_pool *tp,
				      odp_queue_t queue,
				      void *user_ptr)
{
	odp_timer_t hdl;

	odp_spinlock_lock(&tp->lock);
	if (odp_likely(tp->num_alloc < tp->param.num_timers)) {
		odp_timer *tim = TAILQ_FIRST(tp->free_tim_list);
		TAILQ_REMOVE(tp->free_tim_list, tim, next);

		tp->num_alloc++;
		/* Initialize timer */
		dpaa2_timer_init(tim);
		timer_init(tim, queue, user_ptr);
		if (odp_unlikely(tp->num_alloc >
				 odp_atomic_load_u32(&tp->high_wm)))
			/* Update high_wm last with release model to
			 * ensure timer initialization is visible */
			_odp_atomic_u32_store_mm(&tp->high_wm,
						 tp->num_alloc,
						 _ODP_MEMMODEL_RLS);
		hdl = tp_idx_to_handle(tp, tim->index);
	} else {
		__odp_errno = ENFILE; /* Reusing file table overflow */
		hdl = ODP_TIMER_INVALID;
	}
	odp_spinlock_unlock(&tp->lock);
	return hdl;
}

static inline odp_buffer_t timer_free(odp_timer_pool *tp, uint32_t idx)
{
	odp_event_t ev;
	odp_buffer_t buf;
	struct tim_data *info;
	int i;
	odp_timer *tim = &tp->timers[idx];

	if (dpaa2_timer_pending(tim)) {
		info = (struct tim_data *)tim->arg;
		ev = info->ev;
		buf = odp_buffer_from_event(ev);
	} else {
		buf = ODP_BUFFER_INVALID;
	}
	odp_spinlock_lock(&tp->lock);
	ODP_ASSERT(tp->num_alloc != 0);
	tp->num_alloc--;
	if (!tp->num_alloc) {
		for (i = 0; i < MAX_CORES; i++) {
			if (core_mask[i]) {
				pthread_cancel(attr[i].id);
				core_mask[i] = false;
			}
		}
	}

	timer_fini(tim);
	TAILQ_INSERT_HEAD(tp->free_tim_list, tim, next);

	odp_spinlock_unlock(&tp->lock);

	return buf;
}

/******************************************************************************
 * Public API functions
 * Some parameter checks and error messages
 * No modificatios of internal state
 *****************************************************************************/
odp_timer_pool_t
odp_timer_pool_create(const char *name,
		      const odp_timer_pool_param_t *param)
{
	/* Verify that buffer pool can be used for timeouts */
	/* Verify that we have a valid (non-zero) timer resolution */
	if (param->res_ns == 0) {
		__odp_errno = EINVAL;
		return ODP_TIMER_POOL_INVALID;
	}
	odp_timer_pool_t tp = odp_timer_pool_new(name, param);
	return tp;
}

void odp_timer_pool_start(void)
{
	/* Nothing to do here, timer pools will started by first timer set call */
}

void odp_timer_pool_destroy(odp_timer_pool_t tpid)
{
	odp_timer_pool_del(tpid);
}

uint64_t odp_timer_tick_to_ns(odp_timer_pool_t tpid, uint64_t ticks)
{
	return ticks * tpid->param.res_ns;
}

uint64_t odp_timer_ns_to_tick(odp_timer_pool_t tpid, uint64_t ns)
{
	return (uint64_t)(ns / tpid->param.res_ns);
}

uint64_t odp_timer_current_tick(odp_timer_pool_t tpid)
{
	return (dpaa2_time_get_cycles() / tpid->param.res_ns);
}

int odp_timer_pool_info(odp_timer_pool_t tpid,
			odp_timer_pool_info_t *buf)
{
	buf->param = tpid->param;
	buf->cur_timers = tpid->num_alloc;
	buf->hwm_timers = odp_atomic_load_u32(&tpid->high_wm);
	buf->name = tpid->name;
	return 0;
}

static void *manage(void *ptr)
{
	struct worker *attr = ptr;
	int ret;
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(attr->cpu, &cpuset);
	ODP_DBG("Thread 0x%x is affined with core %d\n",
		attr->id, attr->cpu);
	ret = pthread_setaffinity_np(attr->id, sizeof(cpu_set_t), &cpuset);
	if (ret != 0) {
		ODP_ERR("Failed to set thread affinity with core\n");
		return NULL;
	}

	/*Register the deaffine API to pthread library that will be called
	  during timer_free, when pthread_cancel will be called for this thread.*/
	pthread_cleanup_push(dpaa2_thread_cleanup_callback, NULL);

	ret = dpaa2_thread_affine_io_context(DPAA2_IO_PORTAL_ANY_FREE);
	if (ret) {
		ODP_ERR("dpaa2_thread_affine_io_context failed.\n");
		return NULL;
	}

	while (1) {
		dpaa2_timer_manage();
		dpaa2_usleep(attr->ures);
	}

	/* Although function will not be called for this thread, but required to
	   put the closing brace in macro which was opened during pthread_cleanup_push function*/
	pthread_cleanup_pop(1);
	return NULL;
}

odp_timer_t odp_timer_alloc(odp_timer_pool_t tpid,
			    odp_queue_t queue,
			    void *user_ptr)
{
	odp_timer_t hdl;

	if (odp_unlikely(queue == ODP_QUEUE_INVALID))
		ODP_ABORT("%s: Invalid queue handle\n", tpid->name);
	/* We don't care about the validity of user_ptr because we will not
	 * attempt to dereference it */

	hdl = timer_alloc(tpid, queue, user_ptr);

	if (odp_likely(hdl == ODP_TIMER_INVALID)) {
		/* Fail */
		return ODP_TIMER_INVALID;
	}
	return hdl;
}

static void callback_func_tim(__attribute__((unused)) struct dpaa2_timer *tim,
				__attribute__((unused)) void *arg)
{
	int rc;
	struct tim_data *info = (struct tim_data *)arg;

	ODP_DBG("TIMER expired\n");
	ODP_DBG("event %p enqueued on Queue handle %p\n", info->ev, info->queue);
	rc = odp_queue_enq(info->queue, info->ev);
	if (odp_unlikely(rc != 0))
		ODP_ABORT("Failed to enqueue timeout buffer (%d)\n", rc);
}

odp_event_t odp_timer_free(odp_timer_t hdl)
{
	odp_buffer_t buf;
	odp_event_t ev;
	odp_timer_pool *tp = handle_to_tp(hdl);
	int index = handle_to_idx(hdl, tp);

	buf = timer_free(tp, index);
	ev = odp_buffer_to_event(buf);
	return ev;
}

int odp_timer_set_abs(odp_timer_t hdl,
		      uint64_t abs_tck,
		      odp_event_t *tmo_ev)
{
	odp_timeout_t tmo;
	odp_timeout_hdr_t *hdr;
	odp_timer_pool *tp;
	int index;
	uint64_t cur_tick;
	unsigned lcore_id;
	odp_timer *tim;
	struct tim_data *info;
	int ret;

	tp = handle_to_tp(hdl);
	lcore_id = dpaa2_lcore_id();
	index = handle_to_idx(hdl, tp);
	tim = &tp->timers[index];
	info = tim->arg;
	if (!tmo_ev || *tmo_ev == ODP_EVENT_INVALID)
		return ODP_TIMER_NOEVENT;
	if (!core_mask[lcore_id]) {
		attr[lcore_id].ures = tp->param.res_ns / 1000;
		attr[lcore_id].cpu = lcore_id;
		ret = pthread_create(&attr[lcore_id].id, NULL,
				(void *(*)(void *))manage,
				&attr[lcore_id]);
		if (ret) {
			DPAA2_ERR(APP1, "Fail to spawn the thread %lu\n",
						attr[lcore_id].id);
			return ODP_TIMER_INVALID;
		}
		core_mask[lcore_id] = true;
	}
	cur_tick = odp_timer_current_tick(tp);
	if (odp_unlikely(abs_tck < cur_tick + tp->min_rel_tck))
		return ODP_TIMER_TOOEARLY;
	if (odp_unlikely(abs_tck > cur_tick + tp->max_rel_tck))
		return ODP_TIMER_TOOLATE;

	tmo = odp_timeout_from_event(*tmo_ev);
	hdr = (odp_timeout_hdr_t *)tmo;
	hdr->expiration = abs_tck;
	hdr->timer = hdl;
	hdr->user_ptr = info->user_ptr;

	info->ev = *tmo_ev;
	*tmo_ev = ODP_EVENT_INVALID;
	dpaa2_timer_abs_reset(tim, abs_tck * tp->param.res_ns, lcore_id,
			  callback_func_tim, info);
	return ODP_TIMER_SUCCESS;
}

int odp_timer_set_rel(odp_timer_t hdl,
		      uint64_t rel_tck,
		      odp_event_t *tmo_ev)
{
	odp_timeout_t tmo;
	odp_timeout_hdr_t *hdr;
	odp_timer_pool *tp;
	int index;
	unsigned lcore_id;
	uint64_t cur_tick;
	odp_timer *tim;
	struct tim_data *info;
	int ret;

	tp = handle_to_tp(hdl);
	lcore_id = dpaa2_lcore_id();
	index = handle_to_idx(hdl, tp);
	tim = &tp->timers[index];
	info = tim->arg;
	if (!tmo_ev || *tmo_ev == ODP_EVENT_INVALID)
		return ODP_TIMER_NOEVENT;
	if (!core_mask[lcore_id]) {
		attr[lcore_id].ures = tp->param.res_ns / 1000;
		attr[lcore_id].cpu = lcore_id;
		ret = pthread_create(&attr[lcore_id].id, NULL,
				(void *(*)(void *))manage,
				&attr[lcore_id]);
		if (ret) {
			DPAA2_ERR(APP1, "Fail to spawn the thread %lu\n",
						attr[lcore_id].id);
			return ODP_TIMER_INVALID;
		}
		core_mask[lcore_id] = true;
	}

	if (odp_unlikely(rel_tck < tp->min_rel_tck))
		return ODP_TIMER_TOOEARLY;
	if (odp_unlikely(rel_tck > tp->max_rel_tck))
		return ODP_TIMER_TOOLATE;

	cur_tick = odp_timer_current_tick(tp);
	tmo = odp_timeout_from_event(*tmo_ev);
	hdr = (odp_timeout_hdr_t *)tmo;
	hdr->expiration = cur_tick + rel_tck;
	hdr->timer = hdl;
	hdr->user_ptr = info->user_ptr;
	info->ev = *tmo_ev;

	*tmo_ev = ODP_EVENT_INVALID;
	dpaa2_timer_reset(tim, rel_tck * tp->param.res_ns, 0, lcore_id,
			  callback_func_tim, info);
	return ODP_TIMER_SUCCESS;
}

int odp_timer_cancel(odp_timer_t hdl, odp_event_t *tmo_ev)
{
	struct tim_data *info;
	odp_timer_pool *tp = handle_to_tp(hdl);
	int index = handle_to_idx(hdl, tp);
	odp_timer *timer = &tp->timers[index];

	if (dpaa2_timer_pending(timer)) {
		info = (struct tim_data *)timer->arg;
		*tmo_ev = info->ev;
		dpaa2_timer_stop(timer);
		timer->expire = ODP_TICKS_INVALID; /* Invalid expiration ticks */
		return ODP_TIMER_SUCCESS;
	} else {
		timer->expire = ODP_TICKS_INVALID; /* Invalid expiration ticks */
		ODP_DBG("Timer already expired or inactive\n");
		return ODP_TIMER_NOEVENT;
	}
}

odp_timeout_t odp_timeout_from_event(odp_event_t ev)
{
	/* This check not mandated by the API specification */
	if (odp_event_type(ev) != ODP_EVENT_TIMEOUT) {
		ODP_PRINT("Event not a timeout");
		return ODP_TIMEOUT_INVALID;
	}
	return (odp_timeout_t)timeout_hdr_from_buf(odp_buffer_from_event(ev));
}

odp_event_t odp_timeout_to_event(odp_timeout_t tmo)
{
	odp_timeout_hdr_t *tmo_hdr;
	odp_buffer_t buf;

	if (tmo == ODP_TIMEOUT_INVALID)
		return ODP_EVENT_INVALID;

	tmo_hdr = (odp_timeout_hdr_t *)tmo;
	buf = odp_hdr_to_buf(&tmo_hdr->buf_hdr);

	return odp_buffer_to_event(buf);
}

odp_timer_t odp_timeout_timer(odp_timeout_t tmo)
{
	const odp_timeout_hdr_t *hdr = (odp_timeout_hdr_t *)tmo;
	return hdr->timer;
}

uint64_t odp_timeout_tick(odp_timeout_t tmo)
{
	const odp_timeout_hdr_t *hdr = (odp_timeout_hdr_t *)tmo;
	return hdr->expiration;
}

void *odp_timeout_user_ptr(odp_timeout_t tmo)
{
	const odp_timeout_hdr_t *hdr = (odp_timeout_hdr_t *)tmo;
	return hdr->user_ptr;
}

int odp_timeout_fresh(odp_timeout_t tmo)
{
	const odp_timeout_hdr_t *hdr = (odp_timeout_hdr_t *)tmo;
	odp_timer_t tim = hdr->timer;
	odp_timer_pool *tp = handle_to_tp(tim);
	int index = handle_to_idx(tim, tp);

	odp_timer *timer = &tp->timers[index];

	return (timer->expire / tp->param.res_ns) == hdr->expiration;
}


odp_timeout_t odp_timeout_alloc(odp_pool_t pool)
{
	odp_buffer_t buf;
	pool_entry_t *p;

	buf = odp_buffer_alloc(pool);
	p = odp_pool_to_entry(pool);
	if (odp_unlikely(buf == ODP_BUFFER_INVALID))
		return ODP_TIMEOUT_INVALID;

	if (p->s.params.type == ODP_POOL_TIMEOUT) {
		_odp_buffer_type_set(buf, ODP_EVENT_TIMEOUT);
	} else {
		ODP_DBG("Pool is not TIMEOUT\n");
		return ODP_TIMEOUT_INVALID;
	}
	return odp_timeout_from_event(odp_buffer_to_event(buf));
}

void odp_timeout_free(odp_timeout_t tmo)
{
	odp_event_t ev = odp_timeout_to_event(tmo);
	odp_buffer_free(odp_buffer_from_event(ev));
}

int odp_timer_init_global(void)
{
#ifndef ODP_ATOMIC_U128
	uint32_t i;
	for (i = 0; i < NUM_LOCKS; i++)
		_odp_atomic_flag_clear(&locks[i]);
#else
	ODP_DBG("Using lock-less timer implementation\n");
#endif
	odp_atomic_init_u32(&num_timer_pools, 0);
	return 0;
}
