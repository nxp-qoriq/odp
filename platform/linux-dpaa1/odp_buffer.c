/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/buffer.h>
#include <odp_pool_internal.h>
#include <odp_buffer_internal.h>
#include <odp_buffer_inlines.h>
#include <odp_debug_internal.h>

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

	return hdr->addr[0];
}


uint32_t odp_buffer_size(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = odp_buf_to_hdr(buf);

	return hdr->size;
}


int _odp_buffer_type(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = odp_buf_to_hdr(buf);

	return hdr->type;
}

int odp_buffer_is_valid(odp_buffer_t buf)
{
	return validate_buf(buf) != NULL;
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
			"  pool         %" PRIu64 "\n",
			odp_pool_to_u64(hdr->pool_hdl));
	len += snprintf(&str[len], n-len,
			"  addr         %p\n",        hdr->addr);
	len += snprintf(&str[len], n-len,
			"  size         %u\n",        hdr->size);
	len += snprintf(&str[len], n-len,
			"  ref_count    %i\n",
			odp_atomic_load_u32(&hdr->ref_count));
	len += snprintf(&str[len], n-len,
			"  type         %i\n",        hdr->type);

	return len;
}


void odp_buffer_print(odp_buffer_t buf)
{
	int max_len = 512;
	char str[max_len];
	int len;

	len = odp_buffer_snprint(str, max_len-1, buf);
	str[len] = 0;

	ODP_PRINT("\n%s\n", str);
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
