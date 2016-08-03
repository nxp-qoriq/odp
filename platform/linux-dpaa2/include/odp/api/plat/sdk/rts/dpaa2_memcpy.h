/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/*-
 *   Derived from DPDK's rte_memcpy.h
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _DPAA2_MEMCPY_H_
#define _DPAA2_MEMCPY_H_

/**
 * @file
 *
 * Functions for SSE implementation of memcpy().
 */

#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline void dpaa2_mov16(uint8_t *dst, const uint8_t *src)
{
	memcpy(dst, src, 16);
}
static inline void dpaa2_mov32(uint8_t *dst, const uint8_t *src)
{
	memcpy(dst, src, 32);
}
static inline void dpaa2_mov48(uint8_t *dst, const uint8_t *src)
{
	memcpy(dst, src, 48);
}
static inline void dpaa2_mov64(uint8_t *dst, const uint8_t *src)
{
	memcpy(dst, src, 64);
}
static inline void dpaa2_mov128(uint8_t *dst, const uint8_t *src)
{
	memcpy(dst, src, 128);
}


/**
 * Copy 256 bytes from one location to another using optimised SSE
 * instructions. The locations should not overlap.
 *
 * @param dst
 *   Pointer to the destination of the data.
 * @param src
 *   Pointer to the source data.
 */
static inline void
dpaa2_mov256(uint8_t *dst, const uint8_t *src)
{
	dpaa2_mov128(dst, src);
	dpaa2_mov128(dst + 128, src + 128);
}

/**
 * Copy bytes from one location to another. The locations must not overlap.
 *
 * @note This is implemented as a macro, so it's address should not be taken
 * and care is needed as parameter expressions may be evaluated multiple times.
 *
 * @param dst
 *   Pointer to the destination of the data.
 * @param src
 *   Pointer to the source data.
 * @param n
 *   Number of bytes to copy.
 * @return
 *   Pointer to the destination data.
 */
#define dpaa2_memcpy(dst, src, n)              \
	((__builtin_constant_p(n)) ?          \
	memcpy((dst), (src), (n)) :          \
	dpaa2_memcpy_func((dst), (src), (n)))

/*
 * memcpy() function used by dpaa2_memcpy macro
 */
static inline void *
dpaa2_memcpy_func(void *dst, const void *src, size_t n) __attribute__((always_inline));

static inline void *
dpaa2_memcpy_func(void *dst, const void *src, size_t n)
{
	void *ret = dst;

	/* We can't copy < 16 bytes using XMM registers so do it manually. */
	if (n < 16) {
		if (n & 0x01) {
			*(uint8_t *)dst = *(const uint8_t *)src;
			dst = (uint8_t *)dst + 1;
			src = (const uint8_t *)src + 1;
		}
		if (n & 0x02) {
			*(uint16_t *)dst = *(const uint16_t *)src;
			dst = (uint16_t *)dst + 1;
			src = (const uint16_t *)src + 1;
		}
		if (n & 0x04) {
			*(uint32_t *)dst = *(const uint32_t *)src;
			dst = (uint32_t *)dst + 1;
			src = (const uint32_t *)src + 1;
		}
		if (n & 0x08) {
			*(uint64_t *)dst = *(const uint64_t *)src;
		}
		return ret;
	}

	/* Special fast cases for <= 128 bytes */
	if (n <= 32) {
		dpaa2_mov16((uint8_t *)dst, (const uint8_t *)src);
		dpaa2_mov16((uint8_t *)dst - 16 + n, (const uint8_t *)src - 16 + n);
		return ret;
	}

	if (n <= 64) {
		dpaa2_mov32((uint8_t *)dst, (const uint8_t *)src);
		dpaa2_mov32((uint8_t *)dst - 32 + n, (const uint8_t *)src - 32 + n);
		return ret;
	}

	if (n <= 128) {
		dpaa2_mov64((uint8_t *)dst, (const uint8_t *)src);
		dpaa2_mov64((uint8_t *)dst - 64 + n, (const uint8_t *)src - 64 + n);
		return ret;
	}

	/*
	 * For large copies > 128 bytes. This combination of 256, 64 and 16 byte
	 * copies was found to be faster than doing 128 and 32 byte copies as
	 * well.
	 */
	for ( ; n >= 256; n -= 256) {
		dpaa2_mov256((uint8_t *)dst, (const uint8_t *)src);
		dst = (uint8_t *)dst + 256;
		src = (const uint8_t *)src + 256;
	}

	/*
	 * We split the remaining bytes (which will be less than 256) into
	 * 64byte (2^6) chunks.
	 * Using incrementing integers in the case labels of a switch statement
	 * enourages the compiler to use a jump table. To get incrementing
	 * integers, we shift the 2 relevant bits to the LSB position to first
	 * get decrementing integers, and then subtract.
	 */
	switch (3 - (n >> 6)) {
	case 0x00:
		dpaa2_mov64((uint8_t *)dst, (const uint8_t *)src);
		n -= 64;
		dst = (uint8_t *)dst + 64;
		src = (const uint8_t *)src + 64;      /* fallthrough */
	case 0x01:
		dpaa2_mov64((uint8_t *)dst, (const uint8_t *)src);
		n -= 64;
		dst = (uint8_t *)dst + 64;
		src = (const uint8_t *)src + 64;      /* fallthrough */
	case 0x02:
		dpaa2_mov64((uint8_t *)dst, (const uint8_t *)src);
		n -= 64;
		dst = (uint8_t *)dst + 64;
		src = (const uint8_t *)src + 64;      /* fallthrough */
	default:
		;
	}

	/*
	 * We split the remaining bytes (which will be less than 64) into
	 * 16byte (2^4) chunks, using the same switch structure as above.
	 */
	switch (3 - (n >> 4)) {
	case 0x00:
		dpaa2_mov16((uint8_t *)dst, (const uint8_t *)src);
		n -= 16;
		dst = (uint8_t *)dst + 16;
		src = (const uint8_t *)src + 16;      /* fallthrough */
	case 0x01:
		dpaa2_mov16((uint8_t *)dst, (const uint8_t *)src);
		n -= 16;
		dst = (uint8_t *)dst + 16;
		src = (const uint8_t *)src + 16;      /* fallthrough */
	case 0x02:
		dpaa2_mov16((uint8_t *)dst, (const uint8_t *)src);
		n -= 16;
		dst = (uint8_t *)dst + 16;
		src = (const uint8_t *)src + 16;      /* fallthrough */
	default:
		;
	}

	/* Copy any remaining bytes, without going beyond end of buffers */
	if (n != 0) {
		dpaa2_mov16((uint8_t *)dst - 16 + n, (const uint8_t *)src - 16 + n);
	}
	return ret;
}

#ifdef __cplusplus
}
#endif

#endif /* _DPAA2_MEMCPY_H_ */
