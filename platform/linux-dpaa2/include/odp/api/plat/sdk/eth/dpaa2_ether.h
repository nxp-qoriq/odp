/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/*!
 * @file	dpaa2_ether.h
 *
 * @brief	Ethernet related header and supported protocols information
 *
 * @addtogroup	DPAA2_ETH
 * @ingroup	DPAA2_DEV
 * @{
 */

/*
 * $FreeBSD: head/sys/net/ethernet.h 249925 2013-04-26 12:50:32Z glebius $
 */
#ifndef _DPAA2_ETHER_H_
#define _DPAA2_ETHER_H_

#ifdef __cplusplus
extern "C" {
#endif
#include <odp/api/std_types.h>
/*
 * Some basic Ethernet constants.
 */
#define	ETH_ADDR_LEN		6	/*!< Length of Ethernet address. */
#define	ETH_TYPE_LEN		2	/*!< Length of Ethernet type field. */
#define	ETH_CRC_LEN		4	/*!< Length of Ethernet CRC. */
#define	ETH_HDR_LEN		\
	((ETH_ADDR_LEN * 2) + ETH_TYPE_LEN) /*!< Length of Ethernet header. */
#define	ETH_MIN_LEN		64	/*!< Minimum frame len, including CRC */
#define	ETH_MAX_LEN		1518	/*!< Maximum frame len, including CRC */
#define	ETH_MTU			\
	(ETH_MAX_LEN - ETH_HDR_LEN - ETH_CRC_LEN) /*!< Ethernet MTU. */
#define	ETH_MAX_VLAN_FRAME_LEN	\
	(ETH_MAX_LEN + 4)	/*!< Maximum VLAN frame length, including CRC */
/* TODO: More Macros can be added to support multiple layer2 headers
	i.e. PPP, PPPOE etc*/
#define	ETH_MAX_JUMBO_FRAME_LEN	\
			0x2800  /*!< Maximum Jumbo frame length(10KB) including
					Headers, payload and CRC */


#define	ETH_MIN	(ETH_MIN_LEN-ETH_HDR_LEN-ETH_CRC_LEN) /*!< Minimum Data length*/
#define	ETH_MTU_JUMBO		\
	(ETH_MAX_JUMBO_FRAME_LEN - ETH_HDR_LEN - ETH_CRC_LEN)	\
						/*!< MTU for Jumbo frame*/

#define	ETH_VLAN_ENCAP_LEN	4	/*!<802.1Q VLAN encapsulation length*/
#define	ETH_MAX_VLAN_ID		4095	/*!< Maximum VLAN ID. */

#define	ETH_LOCAL_ADMIN_ADDR	0x02	/*!< Locally assigned Eth. address. */
#define	ETH_GROUP_ADDR		0x01	/*!< Multicast/Broadcast Eth. address */
#define	ETH_VLAN_HLEN (ETH_HDR_LEN + 4)	/* Total Eth + VLAN header length. */

/*
 * Ethernet CRC32 polynomials (big- and little-endian verions).
 */
#define	ETH_CRC_POLY_LE	0xedb88320	/*!< CRC polynomial for Low Endian*/
#define	ETH_CRC_POLY_BE	0x04c11db6	/*!< CRC polynomial for Big Endian*/

/*!
 * A macro to validate a length width
 */
#define	ETH_IS_VALID_LEN(foo)	\
	((foo) >= ETH_MIN_LEN && (foo) <= ETH_MAX_LEN)


/*!
 * Ethernet header: Contains the destination address, source address
 * and frame type.
 */
struct ether_hdr {
	uint8_t daddr[ETH_ADDR_LEN];	/*!< Addr bytes in transmission order */
	uint8_t saddr[ETH_ADDR_LEN];	/*!< Addr bytes in transmission order */
	uint16_t ether_type;		/*!< Frame type. */
} __attribute__((__packed__));

/*!
 * Ethernet VLAN Header.
 * Contains the 16-bit VLAN Tag Control Identifier and the Ethernet type
 * of the encapsulated frame.
 */
struct vlan_hdr {
	uint16_t vlan_tci; /*!<Priority (3) + CFI (1) + Identifier Code (12)*/
	uint16_t eth_proto;/*!<Ethernet type of encapsulated frame.*/
} __attribute__((__packed__));

/*TODO: More layer2 headers can be added i.e PPP, PPPOE etc*/

/* Ethernet frame types which are commonly used */
#define	DPAA2_ETHTYPE_IP		0x0800	/*!<IPv4 Protocol. */
#define	DPAA2_ETHTYPE_ARP	0x0806	/*!<Arp Protocol. */
#define	DPAA2_ETHTYPE_VLAN	0x8100	/*!<IEEE 802.1Q VLAN tagging. */
#define	DPAA2_ETHTYPE_VLAN_OUTER	0x88A8	/**<Stacked VLANs/QinQ,outer-tag/STAG*/
#define	DPAA2_ETHTYPE_IPV6	0x86DD	/*!<IPv6 Protocol. */
#define	DPAA2_ETHTYPE_FLOW_CTRL	0x8808	/**<Ethernet flow control */
#define	DPAA2_ETHTYPE_MACSEC	0x88E5	/**<MAC security IEEE 802.1AE */
#define	DPAA2_ETHTYPE_1588	0x88F7	/*!<802.1AS 1588 Precise Time Protocol*/
#define	DPAA2_ETHTYPE_REVARP	0x8035	/*!<Reverse addr resolution protocol*/
#define	DPAA2_ETHTYPE_PPP	0x880B	/*!<PPP (obsolete by PPPoE) */
#define	DPAA2_ETHTYPE_PPPOEDISC	0x8863	/*!<PPP Over Ethernet Discovery Stage*/
#define	DPAA2_ETHTYPE_PPPOE	0x8864	/*!<PPP Over Ethernet Session Stage */
#define	DPAA2_ETHTYPE_LOOPBACK	0x9000	/*!<Loopback: used to test interfaces*/

#define	ETH_IS_MULTICAST(addr) (*(addr) & 0x01) /*!< Macro to validate mcast*/

/*!
 * @details	Swap 6-byte source/destination MAC address
 * @param[in]	prot_eth  - ethernet header pointer
 */
static inline void eth_header_swap(struct ether_hdr *prot_eth)
{
	register uint32_t a, b, c;
	uint32_t *overlay = (uint32_t *)prot_eth;

	a = overlay[0];
	b = overlay[1];
	c = overlay[2];

#ifdef __BIG_ENDIAN
	overlay[0] = (b << 16) | (c >> 16);
	overlay[1] = (c << 16) | (a >> 16);
	overlay[2] = (a << 16) | (b >> 16);
#else
	overlay[0] = (b >> 16) | (c << 16);
	overlay[1] = (c >> 16) | (a << 16);
	overlay[2] = (a >> 16) | (b << 16);
#endif
}

#ifdef __cplusplus
}
#endif

/*! @} */
#endif /* _DPAA2_ETHER_H_ */
