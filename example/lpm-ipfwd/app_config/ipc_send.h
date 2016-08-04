/**
 \file ipc_send.h
 \brief Basic IPfwd Config Tool defines and Data structures
 */
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
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

#include <argp.h>
#include <assert.h>
#include <string.h>

const char *argp_program_version = "argex 1.0";

#define IPC_CTRL_PARAM_BMASK_DESTIP		(1 << 0)
/**< Bit Mask for Dst IP */
#define IPC_CTRL_PARAM_BMASK_GWIP		(1 << 1)
/**< Bit Mask for Gateway IP */
#define LWE_CTRL_PARAM_BMASK_FIBCNT    (1 << 2)        /**< Bit Mask for FIB Count */
#define LWE_CTRL_PARAM_BMASK_NETMASK    (1 << 3)        /**< Bit Mask for Netmask */
#define IPC_CTRL_PARAM_MAX_IP_BIT_NO	4

/**< Mandatory Parameters needed for creating Route */
#define IPC_CTRL_ROUTE_ADD_MDTR_PARAM_MAP (IPC_CTRL_PARAM_BMASK_DESTIP | \
				IPC_CTRL_PARAM_BMASK_GWIP | \
				LWE_CTRL_PARAM_BMASK_FIBCNT | \
				LWE_CTRL_PARAM_BMASK_NETMASK)

static struct argp_option route_add_options[] = {
	{"d", 'd', "DESTIP", 0, "Destination IP", 0},
	{"g", 'g', "GWIP", 0, "Gateway IP", 0},
	{"c", 'c', "FIBCNT", 0, "Number of FIB entries", 0},
	{"n", 'n', "NETMASK", 0, "netmask length to be used by LPM", 0},
	{ 0 }
};

/**< Mandatory Parameters needed for deleting Route */
#define IPC_CTRL_ROUTE_DEL_MDTR_PARAM_MAP (IPC_CTRL_PARAM_BMASK_DESTIP)

static struct argp_option route_del_options[] = {
	{"d", 'd', "DESTIP", 0, "Destination IP", 0},
	{ 0 }
};

#define IPC_CTRL_PARAM_BMASK_ARP_IPADDR		(1 << 0)
/**< Bit Mask for ARP IP Address */
#define IPC_CTRL_PARAM_BMASK_ARP_MACADDR		(1 << 1)
/**< Bit Mask for MAC Address */
#define IPC_CTRL_PARAM_BMASK_ARP_REPLACE		(1 << 2)
/**< Bit Mask for Replace variable */
#define IPC_CTRL_PARAM_ARP_MAX_BIT_NO		3

/**< Mandatory Parameters needed for creating ARP */
#define IPC_CTRL_ARP_ADD_MDTR_PARAM_MAP (IPC_CTRL_PARAM_BMASK_ARP_IPADDR | \
				IPC_CTRL_PARAM_BMASK_ARP_MACADDR)

static struct argp_option arp_add_options[] = {
	{"s", 's', "IPADDR", 0, "IP Address", 0},
	{"m", 'm', "MACADDR", 0, "MAC Address", 0},
	{"r", 'r', "Replace", 0,
	 "Replace Exiting Entry - true/ false {Default: false}", 0},
	{ 0 }
};

/**< Mandatory Parameters needed for deleting ARP */
#define IPC_CTRL_ARP_DEL_MDTR_PARAM_MAP (IPC_CTRL_PARAM_BMASK_ARP_IPADDR)

static struct argp_option arp_del_options[] = {
	{"s", 's', "IPADDR", 0, "IP Address", 0},
	{ 0 }
};

#define IPC_CTRL_IFNUM_MIN				1
#define IPC_CTRL_IFNUM_MAX				200
static struct argp_option intf_conf_options[] = {
	{"i", 'i', "IFNUM", 0, "If Number", 0},
	{"a", 'a', "IPADDR", 0, "IP Address", 0},
	{ 0 }
};
static struct argp_option show_intf_options[] = {
	{"a", 'a', "ALL", 0, "All interfaces", 0},
	{ 0 }
};
