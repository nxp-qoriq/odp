/**
 \file ip_appconf.h
 \brief Implements a simple, fast cache for looking up IPSec tunnels.
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
#ifndef LIB_IP_APPCONF_H
#define LIB_IP_APPCONF_H

#include <ip/ip.h>
#include <stdbool.h>
#include <odp.h>
/**
 \brief	Structure for configuring an Interface
 */


struct app_ctrl_intf_conf {
	in_addr_t ip_addr;			/**< IP Address */
	int ifnum;				/**< Interface number */
#define IPC_CTRL_PARAM_BMASK_IFNAME		(1 << 0)
#define IPC_CTRL_PARAM_BMASK_IPADDR		(1 << 1)
#define IPC_CTRL_PARAM_MAX_INTF_BIT_NO		2

#define IPC_CTRL_INTF_CONF_MDTR_PARAM_MAP (IPC_CTRL_PARAM_BMASK_IFNAME)

	uint32_t bitmask;
};

struct app_ctrl_sa_algo {
	unsigned int alg_type;          /**< Algorithm selector */
	unsigned int alg_key_len;	/**< Length of the key in bytes */
#define IPC_CTRL_MAX_ALGO_KEY_LEN 48
	char alg_key[IPC_CTRL_MAX_ALGO_KEY_LEN];	/**< Key */
	char *alg_key_ptr;
};

/**< SA info structure*/
struct app_ctrl_sa_id {
	unsigned int saddr;		/**< Src IP of Tunnel end point */
	unsigned int daddr;		/**< Dest IP of Tunnel end point */
	unsigned int spi;		/**< SPI */
	bool is_esn;			/**< Extended Sequence Number */
	uint64_t seq_num;		/**< Sequence Number */
	unsigned int defgw;		/**< Default Gateway */

#define IPSEC_PROTO_ESP 50
	unsigned char proto;		/**< Protocol Type */

#define IPSEC_DIR_IN 1
#define IPSEC_DIR_OUT 2
	unsigned char dir;
};

/**< Selector info structure */
struct app_ctrl_sa_selector {
	unsigned int saddr;		/**< Src IP of Host */
	unsigned int daddr;		/**< Dest IP of Host */
};

#ifdef STATS_TBD
/**
 \brief Statistics Data
 */
struct app_ctrl_ipsec_stats {
	unsigned int decap_pkts;	/**< Decrypted pkt count */
	unsigned int encap_pkts;	/**< Encrypted pkt count */
	unsigned int decap_octets;	/**< Decrypted bytes count */
	unsigned int encap_octets;	/**< Encrypted bytes count */
	unsigned int decap_errored_pkts; /**Decrypted erroneous pkt count */
	unsigned int encap_errored_pkts; /** Encrypted erroneous pkts count */
};
#endif

/**
 \brief The Structure is used in External API - ipsecfwd_create_sa
 \details	For configuring the SA with Tunnel End Points, Host IPs,
		Authentication Algo info, and Encryption Algo info
 */
struct app_ctrl_ipsec_info {
	struct app_ctrl_sa_id id;		/**< SA Info */
	struct app_ctrl_sa_selector sel;	/**< Selector Info */
	struct app_ctrl_sa_algo aalg;		/**< Authentication Algo info */
	struct app_ctrl_sa_algo ealg;		/**< Encryption Algo info */
#ifdef STATS_TBD
	struct app_ctrl_ipsec_stats stats;
#endif
	bool hb_tunnel;
};

struct app_ctrl_ip_info {
	in_addr_t src_ipaddr;			/**<Source IP Address>*/
	in_addr_t dst_ipaddr;			/**<Destination IP Address>*/
	in_addr_t gw_ipaddr;			/**<Gateway IP Address>*/
	odph_ethaddr_t mac_addr;		/**< Mac Address */
	unsigned int all;			/**< Show all enabled interfaces */
	unsigned int replace_entry;		/**< Used for overwriting an existing ARP entry */
	struct app_ctrl_intf_conf intf_conf;	/**< Interface Configuration */
	unsigned int fib_cnt;                     /**< Count for fib entries */
	unsigned int mask;
};

/**
 \brief	Structure used for communicating with USDPAA process through
posix message queue.
 */
struct app_ctrl_op_info {

#define IPC_CTRL_CMD_STATE_IDLE 0
#define IPC_CTRL_CMD_STATE_BUSY 1
	unsigned int state;
	/**< State of Command */

#define IPC_CTRL_CMD_TYPE_SA_ADD		1
#define IPC_CTRL_CMD_TYPE_SA_DEL		2
#define IPC_CTRL_CMD_TYPE_ROUTE_ADD		3
#define IPC_CTRL_CMD_TYPE_ROUTE_DEL		4
#define IPC_CTRL_CMD_TYPE_INTF_CONF_CHNG	5
#define IPC_CTRL_CMD_TYPE_SHOW_INTF		6
#define IPC_CTRL_CMD_TYPE_ARP_ADD		7
#define IPC_CTRL_CMD_TYPE_ARP_DEL		8

	unsigned int msg_type;
	/**<Type of Request>*/

#define IPC_CTRL_RSLT_SUCCESSFULL		1
#define IPC_CTRL_RSLT_FAILURE		0
	unsigned int result;
	/**<Result - Successful, Failure>*/
	uint32_t pid;
	union {
		struct app_ctrl_ipsec_info ipsec_info;
	/**< IPsec Info structure */
		struct app_ctrl_ip_info ip_info;
	/**< IPfwd Info structure */
	};
};

extern struct app_ctrl_op_info g_sLweCtrlSaInfo;

#endif	/* LIB_IP_APPCONF_H */
