/**
 \file ip_handler.h
 \brief This file is designed to encapsulate all of the p4080 translation that
 is needed to accept a new IP-classified frame, and put it into the format
 that the rest of the system expects.
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

#ifndef __IP_HANDLER_H
#define __IP_HANDLER_H
#include <odp.h>
/**
 \brief		Prepares the frame and annotations to be handled by the IP stack
		This function represents a "translation" from something that is QMan-sourced into
		something that is source-agnostic
		We increment the number of received IP datagrams, move the pointer to point to the
		start of the IP datagram, and send it to the stack
 \param[in]	ctxt	FQ Context used for accessing and updating ip stats
 \param[inout]	notes	A pointer to the annotations for this frame, as received from the queue
			manager
 \param[in]	data	A pointer to the first byte of data in the frame.
 \return	none
 */
enum IP_STATUS ip_handler(odp_packet_t pkt);

#endif	/* __IP_HANDLER_H */
