/**
 \file refcount.h
 \brief This file contains the prototypes used for managing refernce count
 */
/*
 * Copyright (C) 2015 - 2016 Freescale Semiconductor, Inc.
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
#ifndef LIB_COMMON_REFCOUNT_H
#define LIB_COMMON_REFCOUNT_H 1

#include <stdlib.h>
#include <statistics.h>
#include <stdbool.h>
#include <odp.h>

typedef stat32_t refcount_t;

/**
 \brief Increments the reference count
 \param[inout] count The reference counter
 \return none
 */
static inline void refcount_acquire(refcount_t *count)
{
	(*count)++;
}

/**
 \brief Decrements the reference count
 \param[inout] count The reference counter
 \return none
 */
static inline void refcount_release(refcount_t *count)
{
	(*count)--;
}

/**
 \brief Finds out if the reference count is zero
 \param[in] count The reference counter
 \return true - reference count is zero
 false -  reference count is non-zero
 */
static inline bool refcount_try_await_zero(refcount_t *count)
{
	return (*count == 0);
}

/**
 \brief Blocks till the reference count is zero
 \param[in] count The reference counter
 \return none
 */
static inline void refcount_await_zero(refcount_t *count)
{
	bool retval;

	do {
		retval = refcount_try_await_zero(count);
	} while (retval == false);
}

/**
 \brief Creates a refernce counter
 \return The reference counter
 */
refcount_t *refcount_create(void);

/**
 \brief Frees the refernce counter
 \param[in] count The reference counter
 \return none
 */
void refcount_destroy(void *count);

#endif /* ifndef LIB_COMMON_REFCOUNT_H */
