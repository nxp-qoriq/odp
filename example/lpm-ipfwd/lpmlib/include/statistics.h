/*
 * Copyright (C) 2015,2016 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** @file
 *
 * This file defines several statistics manipulation functions,
 */

#ifndef __STATISTICS_H__
#define __STATISTICS_H__

#include <stdint.h>

/* 32 bit statistics, single accumulator */
typedef volatile int32_t stat32_t;

/* 32 bit statistics, incrementor (number of packets) and accumulator
 *(number of bytes) pair.
 */
struct stat32_pair_t {
	stat32_t inc;
	stat32_t acc;
};

/* 64 bit statistics, single accumulator */
union stat64_t {
	volatile int64_t stat;
	struct {
		volatile uint32_t hi;
		volatile uint32_t lo;
	} words;
};

/* 64 bit statistics, incrementor (number of packets) and accumulator
 * (number of bytes) pair
 */
struct stat64_pair_t {
	union stat64_t inc;
	union stat64_t acc;
};
#endif	/* __STATISTICS_H__ */
