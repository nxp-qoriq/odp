/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP atomic operations
 */

#ifndef ODP_PLAT_ATOMIC_H_
#define ODP_PLAT_ATOMIC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <odp/api/align.h>
#include <odp/api/plat/atomic_types.h>

/** @ingroup odp_synchronizers
 *  @{
 */

/*!
 * Atomic Operations on arm
 */

#define __ATOMIC_BARRIER  __asm__ __volatile__ ("dmb st" : : : "memory")

/*!
 * General memory barrier.
 *
 * Guarantees that the LOAD and STORE operations generated before the
 * barrier occur before the LOAD and STORE operations generated after.
 */
#define odp_mb() __ATOMIC_BARRIER

/*!
 * Write memory barrier.
 *
 * Guarantees that the STORE operations generated before the barrier
 * occur before the STORE operations generated after.
 */
#define odp_wmb() odp_mb()

/*!
 * Read memory barrier.
 *
 * Guarantees that the LOAD operations generated before the barrier
 * occur before the LOAD operations generated after.
 */
#define odp_rmb() odp_mb()

static inline void
odp_atomic_init_u16(odp_atomic_u16_t *atom)
{
	atom->v = 0;
}

/*!
 * @details	Atomically read a 16-bit value from a counter.
 *
 * @param[in]	v - A pointer to the atomic counter.
 *
 * @return	The value of the counter.
 */
static inline int16_t
odp_atomic_read_u16(const odp_atomic_u16_t *atom)
{
	return atom->v;
}

/*!
 * @details	Atomically set a counter to a 16-bit value.
 *
 * @param[in]	v - A pointer to the atomic counter.
 *
 * @param[in]	new_value - The new value for the counter.
 *
 */
static inline void
odp_atomic_set_u16(odp_atomic_u16_t *atom, int16_t new_value)
{
	atom->v = new_value;
}

/*!
 * @details	Atomically add a 16-bit value to an atomic counter.
 *
 * @param[in]	v - A pointer to the atomic counter.
 *
 * @param[in]	inc - The value to be added to the counter.
 *
 */
static inline void
odp_atomic_add_u16(odp_atomic_u16_t *atom, int16_t inc)
{
	__sync_fetch_and_add(&atom->v, inc);
}

/*!
 * @details	Atomically subtract a 16-bit value from an atomic counter.
 *
 * @param[in]	v - A pointer to the atomic counter.
 *
 * @param[in]	dec - The value to be subtracted from the counter.
 *
 */
static inline void
odp_atomic_sub_u16(odp_atomic_u16_t *atom, int16_t dec)
{
	__sync_fetch_and_sub(&atom->v, dec);
}

/*!
 * @details	Atomically increment a counter by one.
 *
 * @param[in]	v - A pointer to the atomic counter.
 *
 */
static inline void
odp_atomic_inc_u16(odp_atomic_u16_t *atom)
{
	__sync_fetch_and_add(&atom->v, 1);
}

/*!
 * @details	Atomically decrement a counter by one.
 *
 * @param[in] v
 *   A pointer to the atomic counter.
 */
static inline void
odp_atomic_dec_u16(odp_atomic_u16_t *atom)
{
	__sync_fetch_and_sub(&atom->v, 1);
}

/*!
 * @details	Atomically add a 16-bit value to a counter and return the result.
 *		Atomically adds the 16-bits value (inc) to the atomic counter
 *		(v) and returns the value of v after addition.
 *
 * @param[in]	v - A pointer to the atomic counter.
 *
 * @param[in]	inc - The value to be added to the counter.
 *
 * @return	The value of v after the addition.
 *
 */

static inline int16_t
odp_atomic_add_fetch_u16(odp_atomic_u16_t *atom, int16_t inc)
{
	return __sync_add_and_fetch(&atom->v, inc);
}

/*!
 * @details	Atomically subtract a 16-bit value from a counter and return
 *		the result. Atomically subtracts the 16-bit value (inc) from
 *		the atomic counter (v) and returns the value of v after the
 *		subtraction.
 *
 * @param[in]	v - A pointer to the atomic counter.
 *
 * @param[in]	dec - The value to be subtracted from the counter.
 *
 * @return	The value of v after the subtraction.
 *
 */
static inline int16_t
odp_atomic_sub_fetch_u16(odp_atomic_u16_t *atom, int16_t dec)
{
	return __sync_sub_and_fetch(&atom->v, dec);
}

static inline
uint16_t odp_atomic_fetch_add_u16(odp_atomic_u16_t *atom, uint16_t val)
{
	return __sync_fetch_and_add(&atom->v, val);
}

static inline
uint16_t odp_atomic_fetch_sub_u16(odp_atomic_u16_t *atom, uint16_t val)
{
	return __sync_fetch_and_sub(&atom->v, val);
}

static inline
uint16_t odp_atomic_fetch_inc_u16(odp_atomic_u16_t *atom)
{
	return __sync_fetch_and_add(&atom->v, 1);
}

static inline
uint16_t odp_atomic_fetch_dec_u16(odp_atomic_u16_t *atom)
{
	return __sync_fetch_and_sub(&atom->v, 1);
}

static inline
uint16_t odp_atomic_load_u16(odp_atomic_u16_t *atom)
{
	return __atomic_load_n(&atom->v, __ATOMIC_RELAXED);
}

static inline
void odp_atomic_store_u16(odp_atomic_u16_t *atom, uint16_t val)
{
	__atomic_store_n(&atom->v, val, __ATOMIC_RELAXED);
}

/*!
 * @details	Atomically increment a 16-bit counter by one and test.
 *
 * @param[in]	v - A pointer to the atomic counter.
 *
 * @return	True if the result after the increment operation is 0;
 *		false otherwise.
 *
 */
static inline int odp_atomic_inc_and_test_u16(odp_atomic_u16_t *atom)
{
	return (__sync_add_and_fetch(&atom->v, 1) == 0);
}

/*!
 * @details	Atomically decrement a 16-bit counter by one and test.
 *
 * @param[in]	v - A pointer to the atomic counter.
 *
 * @return	True if the result after the decrement operation is 0;
 *		false otherwise.
 */
static inline int odp_atomic_dec_and_test_u16(odp_atomic_u16_t *atom)
{
	return (__sync_sub_and_fetch(&atom->v, 1) == 0);
}

/*!
 * @details	Atomically test and set a 16-bit atomic counter.
 *
 * @param[in]	v - A pointer to the atomic counter.
 *
 * @return	0 If the counter value is already set or any failure; else 1.
 *
 */
static inline int odp_atomic_test_and_set_u16(odp_atomic_u16_t *atom)
{
	return __sync_bool_compare_and_swap((volatile uint16_t *)&atom->v, 0, 1);
}

/*!
 * @details	Atomically set a 16-bit counter to 0.
 *
 * @param[in]	v - A pointer to the atomic counter.
 *
 */
static inline void odp_atomic_reset_u16(odp_atomic_u16_t *atom)
{
	atom->v = 0;
}

static inline void odp_atomic_init_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	__atomic_store_n(&atom->v, val, __ATOMIC_RELAXED);
}

static inline uint32_t odp_atomic_load_u32(odp_atomic_u32_t *atom)
{
	return __atomic_load_n(&atom->v, __ATOMIC_RELAXED);
}

static inline void odp_atomic_store_u32(odp_atomic_u32_t *atom,
					uint32_t val)
{
	__atomic_store_n(&atom->v, val, __ATOMIC_RELAXED);
}

static inline uint32_t odp_atomic_fetch_add_u32(odp_atomic_u32_t *atom,
						uint32_t val)
{
	return __atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
}

static inline void odp_atomic_add_u32(odp_atomic_u32_t *atom,
				      uint32_t val)
{
	(void)__atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
}

static inline uint32_t odp_atomic_fetch_sub_u32(odp_atomic_u32_t *atom,
						uint32_t val)
{
	return __atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
}

static inline void odp_atomic_sub_u32(odp_atomic_u32_t *atom,
				      uint32_t val)
{
	(void)__atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
}

static inline uint32_t odp_atomic_fetch_inc_u32(odp_atomic_u32_t *atom)
{
	return __atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
}

static inline void odp_atomic_inc_u32(odp_atomic_u32_t *atom)
{
	(void)__atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
}

static inline uint32_t odp_atomic_fetch_dec_u32(odp_atomic_u32_t *atom)
{
	return __atomic_fetch_sub(&atom->v, 1, __ATOMIC_RELAXED);
}

static inline void odp_atomic_dec_u32(odp_atomic_u32_t *atom)
{
	(void)__atomic_fetch_sub(&atom->v, 1, __ATOMIC_RELAXED);
}

static inline void odp_atomic_reset_u32(odp_atomic_u32_t *atom)
{
	atom->v = 0;
}

static inline int
odp_atomic_cmpset_u32(volatile uint32_t *dst, uint32_t exp, uint32_t src)
{
	return __sync_bool_compare_and_swap(dst, exp, src);
}

static inline int odp_atomic_test_and_set_u32(odp_atomic_u32_t *atom)
{
	return odp_atomic_cmpset_u32((volatile uint32_t *)&atom->v, 0, 1);
}

static inline void odp_atomic_init_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	atom->v = val;
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	__atomic_clear(&atom->lock, __ATOMIC_RELAXED);
#endif
}

static inline uint64_t odp_atomic_load_u64(odp_atomic_u64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, (void)0);
#else
	return __atomic_load_n(&atom->v, __ATOMIC_RELAXED);
#endif
}

static inline void odp_atomic_store_u64(odp_atomic_u64_t *atom,
					uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v = val);
#else
	__atomic_store_n(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

static inline uint64_t odp_atomic_fetch_add_u64(odp_atomic_u64_t *atom,
						uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, atom->v += val);
#else
	return __atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

static inline void odp_atomic_add_u64(odp_atomic_u64_t *atom, uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v += val);
#else
	(void)__atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

static inline uint64_t odp_atomic_fetch_sub_u64(odp_atomic_u64_t *atom,
						uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, atom->v -= val);
#else
	return __atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

static inline void odp_atomic_sub_u64(odp_atomic_u64_t *atom, uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v -= val);
#else
	(void)__atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

static inline uint64_t odp_atomic_fetch_inc_u64(odp_atomic_u64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, atom->v++);
#else
	return __atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
#endif
}

static inline void odp_atomic_inc_u64(odp_atomic_u64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v++);
#else
	(void)__atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
#endif
}

static inline uint64_t odp_atomic_fetch_dec_u64(odp_atomic_u64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, atom->v--);
#else
	return __atomic_fetch_sub(&atom->v, 1, __ATOMIC_RELAXED);
#endif
}

static inline void odp_atomic_dec_u64(odp_atomic_u64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v--);
#else
	(void)__atomic_fetch_sub(&atom->v, 1, __ATOMIC_RELAXED);
#endif
}

static inline uint32_t odp_atomic_load_acq_u32(odp_atomic_u32_t *atom)
{
	return __atomic_load_n(&atom->v, __ATOMIC_ACQUIRE);
}

static inline void odp_atomic_store_rel_u32(odp_atomic_u32_t *atom,
					    uint32_t val)
{
	__atomic_store_n(&atom->v, val, __ATOMIC_RELEASE);
}

static inline void odp_atomic_add_rel_u32(odp_atomic_u32_t *atom,
					  uint32_t val)
{
	(void)__atomic_fetch_add(&atom->v, val, __ATOMIC_RELEASE);
}

static inline void odp_atomic_sub_rel_u32(odp_atomic_u32_t *atom,
					  uint32_t val)
{
	(void)__atomic_fetch_sub(&atom->v, val, __ATOMIC_RELEASE);
}

static inline int odp_atomic_cas_acq_u32(odp_atomic_u32_t *atom,
					 uint32_t *old_val, uint32_t new_val)
{
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_ACQUIRE,
					   __ATOMIC_RELAXED);
}

static inline int odp_atomic_cas_rel_u32(odp_atomic_u32_t *atom,
					 uint32_t *old_val, uint32_t new_val)
{
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_RELEASE,
					   __ATOMIC_RELAXED);
}

static inline int odp_atomic_cas_acq_rel_u32(odp_atomic_u32_t *atom,
					     uint32_t *old_val,
					     uint32_t new_val)
{
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_ACQ_REL,
					   __ATOMIC_RELAXED);
}

static inline uint64_t odp_atomic_load_acq_u64(odp_atomic_u64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, (void)0);
#else
	return __atomic_load_n(&atom->v, __ATOMIC_ACQUIRE);
#endif
}

static inline void odp_atomic_store_rel_u64(odp_atomic_u64_t *atom,
					    uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v = val);
#else
	__atomic_store_n(&atom->v, val, __ATOMIC_RELEASE);
#endif
}

static inline void odp_atomic_add_rel_u64(odp_atomic_u64_t *atom, uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v += val);
#else
	(void)__atomic_fetch_add(&atom->v, val, __ATOMIC_RELEASE);
#endif
}

static inline void odp_atomic_sub_rel_u64(odp_atomic_u64_t *atom, uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v -= val);
#else
	(void)__atomic_fetch_sub(&atom->v, val, __ATOMIC_RELEASE);
#endif
}

static inline int odp_atomic_cas_acq_u64(odp_atomic_u64_t *atom,
					 uint64_t *old_val, uint64_t new_val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	int ret;
	*old_val = ATOMIC_OP(atom, ATOMIC_CAS_OP(&ret, *old_val, new_val));
	return ret;
#else
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_ACQUIRE,
					   __ATOMIC_RELAXED);
#endif
}

static inline int odp_atomic_cas_rel_u64(odp_atomic_u64_t *atom,
					 uint64_t *old_val, uint64_t new_val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	int ret;
	*old_val = ATOMIC_OP(atom, ATOMIC_CAS_OP(&ret, *old_val, new_val));
	return ret;
#else
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_RELEASE,
					   __ATOMIC_RELAXED);
#endif
}

static inline int odp_atomic_cas_acq_rel_u64(odp_atomic_u64_t *atom,
					     uint64_t *old_val,
					     uint64_t new_val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	int ret;
	*old_val = ATOMIC_OP(atom, ATOMIC_CAS_OP(&ret, *old_val, new_val));
	return ret;
#else
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_ACQ_REL,
					   __ATOMIC_RELAXED);
#endif
}

static inline int
odp_atomic_cas_u32(odp_atomic_u32_t *atom, uint32_t *old_val,
				     uint32_t new_val)
{
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_RELAXED,
					   __ATOMIC_RELAXED);
}

static inline void odp_atomic_max_u32(odp_atomic_u32_t *atom, uint32_t new_max)
{
	uint32_t old_val;

	old_val = odp_atomic_load_u32(atom);

	while (new_max > old_val) {
		if (odp_atomic_cas_u32(atom, &old_val, new_max))
			break;
	}
}

static inline void odp_atomic_min_u32(odp_atomic_u32_t *atom, uint32_t new_min)
{
	uint32_t old_val;

	old_val = odp_atomic_load_u32(atom);

	while (new_min < old_val) {
		if (odp_atomic_cas_u32(atom, &old_val, new_min))
			break;
	}
}

static inline int
odp_atomic_cas_u64(odp_atomic_u64_t *atom, uint64_t *old_val,
				     uint64_t new_val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	int ret;
	*old_val = ATOMIC_OP(atom, ATOMIC_CAS_OP(&ret, *old_val, new_val));
	return ret;
#else
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_RELAXED,
					   __ATOMIC_RELAXED);
#endif
}

static inline void odp_atomic_max_u64(odp_atomic_u64_t *atom, uint64_t new_max)
{
	uint64_t old_val;

	old_val = odp_atomic_load_u64(atom);

	while (new_max > old_val) {
		if (odp_atomic_cas_u64(atom, &old_val, new_max))
			break;
	}
}

static inline void odp_atomic_min_u64(odp_atomic_u64_t *atom, uint64_t new_min)
{
	uint64_t old_val;

	old_val = odp_atomic_load_u64(atom);

	while (new_min < old_val) {
		if (odp_atomic_cas_u64(atom, &old_val, new_min))
			break;
	}
}

static inline uint32_t odp_atomic_xchg_u32(odp_atomic_u32_t *atom,
					   uint32_t new_val)
{
	return __atomic_exchange_n(&atom->v, new_val, __ATOMIC_RELAXED);
}

static inline uint64_t odp_atomic_xchg_u64(odp_atomic_u64_t *atom,
					   uint64_t new_val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, atom->v = new_val);
#else
	return __atomic_exchange_n(&atom->v, new_val, __ATOMIC_RELAXED);
#endif
}

/**
 * @}
 */

#include <odp/api/spec/atomic.h>

#ifdef __cplusplus
}
#endif

#endif
