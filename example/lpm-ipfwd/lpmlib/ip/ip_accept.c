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

/**
 \file ip_accept.c
 \brief If packet is valid then IP packet is sent here for PREROUTING
	stage. Hooks before routing execute at this stage
 */

#include "ip_accept.h"
#include "ip_hooks.h"
#include "ip_route.h"
#include "ipsec/ipsec_init.h"
#include <odp.h>

extern struct ipsec_stack_t ipsec_stack;

enum IP_STATUS ip_accept_preparsed(odp_packet_t buf,
			enum state source)
{
	struct ip_hooks_t *hook = &ipsec_stack.ip_stack.hooks;
	return exec_hook(buf, hook, IP_HOOK_PREROUTING, &ip_accept_finish,
			source);
}

enum IP_STATUS ip_accept_finish(odp_packet_t buf,
			enum state source)
{
	int len;

	odph_ipv4hdr_t *ip_hdr = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, &len);

	if (odp_unlikely(has_options(ip_hdr))) {
		/* TODO:
		 Handle Preroute options */
	}
	return ip_route_input(buf, ip_hdr, source);
}
