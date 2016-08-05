/* Copyright (c) 2014, Linaro Limited
 * Copyright (C) 2015-2016 Freescale Semiconductor,Inc
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp.h>
#include <odp_cunit_common.h>
#include "odp_proto_test_inp.h"
#include "proto.h"

#define SHM_PKT_POOL_SIZE	(512 * 2048 * 2)
#define SHM_PKT_POOL_BUF_SIZE	(1024 * 32)

#define SHM_COMPL_POOL_SIZE	(128 * 1024)
#define SHM_COMPL_POOL_BUF_SIZE	128

odp_suiteinfo_t proto_suites[] = {
	{ODP_PDCP_CPLANE_ENCAP, proto_suite_async_init, NULL,
		proto_suite_cplane_encap},
	{ODP_PDCP_UPLANE_ENCAP, proto_suite_async_init, NULL,
		proto_suite_uplane_encap},
	{ODP_PDCP_CPLANE_DECAP, proto_suite_async_init, NULL,
		proto_suite_cplane_decap},
	{ODP_PDCP_UPLANE_DECAP, proto_suite_async_init, NULL,
		proto_suite_uplane_decap},
	ODP_SUITE_INFO_NULL,
};

int proto_init(odp_instance_t *inst)
{
	odp_pool_param_t params;
	odp_pool_t pool;
	odp_queue_t out_queue;

	if (0 != odp_init_global(inst, NULL, NULL)) {
		fprintf(stderr, "error: odp_init_global() failed.\n");
		return -1;
	}
	if (0 != odp_init_local(*inst, ODP_THREAD_CONTROL)) {
		fprintf(stderr, "error: odp_init_local() failed.\n");
		return -1;
	}

	memset(&params, 0, sizeof(params));
	params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.num     = SHM_PKT_POOL_SIZE / SHM_PKT_POOL_BUF_SIZE;
	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet_pool", &params);

	if (ODP_POOL_INVALID == pool) {
		fprintf(stderr, "Packet pool creation failed.\n");
		return -1;
	}
	out_queue = odp_queue_create("crypto-out", NULL);
	if (ODP_QUEUE_INVALID == out_queue) {
		fprintf(stderr, "Crypto outq creation failed.\n");
		return -1;
	}

	return 0;
}

int proto_term(odp_instance_t inst)
{
	odp_pool_t pool;
	odp_queue_t out_queue;

	out_queue = odp_queue_lookup("crypto-out");
	if (ODP_QUEUE_INVALID != out_queue) {
		if (odp_queue_destroy(out_queue))
			fprintf(stderr, "Crypto outq destroy failed.\n");
	} else {
		fprintf(stderr, "Crypto outq not found.\n");
	}

	pool = odp_pool_lookup("packet_pool");
	if (ODP_POOL_INVALID != pool) {
		if (odp_pool_destroy(pool))
			fprintf(stderr, "Packet pool destroy failed.\n");
	} else {
		fprintf(stderr, "Packet pool not found.\n");
	}

	if (0 != odp_term_local()) {
		fprintf(stderr, "error: odp_term_local() failed.\n");
		return -1;
	}

	if (0 != odp_term_global(inst)) {
		fprintf(stderr, "error: odp_term_global() failed.\n");
		return -1;
	}

	return 0;
}

int proto_main(void)
{
	int ret;

	odp_cunit_register_global_init(proto_init);
	odp_cunit_register_global_term(proto_term);

	ret = odp_cunit_register(proto_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
