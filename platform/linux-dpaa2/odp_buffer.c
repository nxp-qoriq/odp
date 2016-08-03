/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/buffer.h>
#include <odp_pool_internal.h>
#include <odp_buffer_internal.h>
#include <odp_debug_internal.h>
#include <dpaa2_mpool_priv.h>

#include <string.h>
#include <stdio.h>


odp_buffer_t odp_buffer_from_event(odp_event_t ev)
{
	return (odp_buffer_t)ev;
}

odp_event_t odp_buffer_to_event(odp_buffer_t buf)
{
	return (odp_event_t)buf;
}

void *odp_buffer_addr(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = odp_buf_to_hdr(buf);

	return hdr->data;
}

uint32_t odp_buffer_size(odp_buffer_t buf)
{
	odp_buffer_hdr_t	*buf_hdr = odp_buf_to_hdr(buf);
	pool_entry_t		*pool = odp_buf_to_pool(buf_hdr);
	struct dpaa2_pool	*mpool;

	mpool = (struct dpaa2_pool *)pool->s.int_hdl;
	if (!mpool)
		return 0;

	return mpool->data_size - mpool->priv_data_size;
}


int _odp_buffer_type(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = odp_buf_to_hdr(buf);

	return (hdr->usr_flags & ODP_EVENT_TYPES);
}

int odp_buffer_is_valid(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = odp_buf_to_hdr(buf);
	int32_t type;

	if (buf == ODP_BUFFER_INVALID)
		return false;

	if (!(hdr->data))
		return false;

	type = _odp_buffer_type(buf);
	if (!(type & ODP_EVENT_BUFFER))
		return false;

	return true;
}


int odp_buffer_snprint(char *str, uint32_t n, odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr;
	int len = 0;

	if (!odp_buffer_is_valid(buf)) {
		ODP_PRINT("Buffer is not valid.\n");
		return len;
	}

	hdr = odp_buf_to_hdr(buf);

	len += snprintf(&str[len], n-len,
			"Buffer\n");
	len += snprintf(&str[len], n-len,
			"  Buffer type		0x%X\n", _odp_buffer_type(buf));
	len += snprintf(&str[len], n-len,
			"  pool pointer		%p\n", (struct pool_entry_s *)hdr->buf_pool);
	len += snprintf(&str[len], n-len,
			"  data addr		%p\n",        hdr->data);
	len += snprintf(&str[len], n-len,
			"  size			%u\n",        odp_buffer_size(buf));

	return len;
}


void odp_buffer_print(odp_buffer_t buf)
{
	if (_odp_buffer_type(buf) == ODP_EVENT_PACKET) {
		dpaa2_mbuf_dump_pkt(stdout, buf);
	} else {
		int max_len = 512;
		char str[max_len];
		int len;

		len = odp_buffer_snprint(str, max_len - 1, buf);
		str[len] = 0;

		ODP_PRINT("\n%s\n", str);
	}
}

int odp_buffer_alloc_multi(odp_pool_t pool_hdl ODP_UNUSED,
			   odp_buffer_t buf[] ODP_UNUSED,
			  int num ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

void odp_buffer_free_multi(const odp_buffer_t buf[] ODP_UNUSED,
			   int num ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
}
