/* Copyright (c) 2015 Freescale Semiconductor, Inc.
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example odp_l3fwd.h Supporting header
 */

/*********************************************************************
			Header inclusion
**********************************************************************/
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <odp.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/api/packet_io.h>
#include <odp/helper/linux.h>
#include <odp/api/spinlock.h>

/*********************************************************************
			Macro Definitions
**********************************************************************/
#define LOCK(a)      odp_spinlock_lock(a)
#define UNLOCK(a)    odp_spinlock_unlock(a)
#define LOCK_INIT(a) odp_spinlock_init(a)

/**
 * Maximum Number of Route entries in Routing database
 */
#define MAX_ENTRIES_IN_TABLE          32   /**< maximum number of data base entries */

/**
 * Maximum string Length for Generic usage
 */
#define MAX_STRING			32		/**< maximum string length */
#define MAX_MAC_STRING_SIZE		MAX_STRING	/**< maximum MAC address string size */
#define MAX_SUBNET_STRING_SIZE		MAX_STRING	/**< maximum Subnet string size */
#define MAX_INTERFACE_STRING_SIZE	MAX_STRING	/**< maximum interface string size */

/**
 * Create IPv4 address
 */
#define IPv4(a, b, c, d) ((uint32_t)(((a) & 0xff) << 24) | \
				(((b) & 0xff) << 16) | \
				(((c) & 0xff) << 8)  | \
				((d) & 0xff))

/**
 * Enabling/Disable Debug prints
 */
#define ODP_L3FWD_DEBUG		0

/**
 * Enabling/Disable Debug prints
 */
#define ODP_L3FWD_PERF_MODE	1

/**
 * Default number of flows
 */
#define ODP_MAX_FLOW_COUNT		0x100000

/**
 * Default Hash bucket number
 */
#define ODP_DEFAULT_BUCKET_COUNT	(ODP_MAX_FLOW_COUNT / 8)

/**
 * Hash calculation utility
 */
#define JHASH_GOLDEN_RATIO	0x9e3779b9
#define rot(x, k) (((x) << (k)) | ((x) >> (32 - (k))))
#define ODP_BJ3_MIX(a, b, c) \
{ \
	a -= c; a ^= rot(c, 4); c += b; \
	b -= a; b ^= rot(a, 6); a += c; \
	c -= b; c ^= rot(b, 8); b += a; \
	a -= c; a ^= rot(c, 16); c += b; \
	b -= a; b ^= rot(a, 19); a += c; \
	c -= b; c ^= rot(b, 4); b += a; \
}

/*********************************************************************
			Structure Definitions
**********************************************************************/
/**
 * Interface entry
 */
typedef struct {
	odp_pktio_t	pktio;		/**< pktio handle*/
	odph_ethaddr_t	addr;		/**< pktio MAC Address*/
	odph_ethaddr_t	next_hop_addr;	/**< Next Hop MAC Address*/
} odp_pktio_entry_t;

/**
 * Flow cache table entry
 */
typedef struct {
	void			*next;		/**< Pointer to next flow in list*/
	uint32_t		l3_src;		/**< Source IP Address*/
	uint32_t		l3_dst;		/**< Destination IP Address*/
	uint16_t		l4_sport;	/**< Source Port Number*/
	uint16_t		l4_dport;	/**< Destination Port Number*/
	uint8_t			l3_proto;	/**< IP protocol*/
	odp_pktio_entry_t	out_port;	/**< Out interface of matching flow*/
} odp_flow_entry_t;

/**
 * Flow cache table bucket
 */
typedef struct {
	odp_spinlock_t		lock;	/**< Bucket lock*/
	uint32_t		depth;	/**< Depth of bucket*/
	odp_flow_entry_t	*next;	/**< Pointer to first flow entry in bucket*/
} flow_bucket_t;

/**
 * IP address range (subnet)
 */
typedef struct ip_addr_range_s {
	uint32_t  addr;     /**< IP address */
	uint32_t  mask;     /**< mask, 1 indicates bits are valid */
} ip_addr_range_t;

/**
 * Forwarding data base entry
 */
typedef struct fwd_db_entry_s {
	struct fwd_db_entry_s *next;          /**< Next entry on list */
	char	oif[MAX_INTERFACE_STRING_SIZE];  /**< Output interface name */
	odp_pktio_t            pktio;         /**< Output interface id */
	uint8_t   src_mac[ODPH_ETHADDR_LEN];  /**< Output source MAC */
	uint8_t   dst_mac[ODPH_ETHADDR_LEN];  /**< Output destination MAC */
	ip_addr_range_t        subnet;        /**< Subnet for this router */
} fwd_db_entry_t;

/**
 * Forwarding data base global structure
 */
typedef struct fwd_db_s {
	uint32_t          index;          /**< Next available entry */
	fwd_db_entry_t   *list;           /**< List of active routes */
	fwd_db_entry_t    array[MAX_ENTRIES_IN_TABLE];  /**< Entry storage */
} fwd_db_t;

/*********************************************************************
			Global Definitions
**********************************************************************/
/**
 * Pointer to Flow cache table
 */
extern flow_bucket_t *flow_table;

/**
 * Number of buckets in hash table
 */
extern uint32_t bucket_count;

/**
 * Global pointer to fwd db
 */
extern fwd_db_t *fwd_db;

/*********************************************************************
			Function Definitions
**********************************************************************/
/*
 * Allocate and Initialize routing table with default Route entries.
 *
 */
void odp_init_routing_table(void);

/*
 * Searches flow entry in given hash bucket according to given 5-tuple information
 *
 * @param sip           Source IP Address
 * @param dip           Destination IP Address
 * @param sport         Source Port Number
 * @param dport         Destination Port Number
 * @param proto         IP protocol
 * @param bucket        Hash Bucket
 *
 * @return Matching flow entry
 */
#if ODP_L3FWD_PERF_MODE
static inline odp_flow_entry_t *odp_route_flow_lookup_in_bucket(uint32_t sip,
						uint32_t dip,
						uint16_t sport ODP_UNUSED,
						uint16_t dport ODP_UNUSED,
						uint8_t proto ODP_UNUSED,
						void *bucket)
#else
static inline odp_flow_entry_t *odp_route_flow_lookup_in_bucket(uint32_t sip,
						uint32_t dip,
						uint16_t sport,
						uint16_t dport,
						uint8_t proto,
						void *bucket)
#endif
{
	odp_flow_entry_t      *flow, *head;

	head = ((flow_bucket_t *)bucket)->next;
	for (flow = head; flow != NULL; flow = (odp_flow_entry_t *)flow->next) {
		if ((flow->l3_src == sip) && (flow->l3_dst == dip)
#if !ODP_L3FWD_PERF_MODE
			&& (flow->l4_sport == sport) && (flow->l4_dport == dport)
			&& (flow->l3_proto == proto)
#endif
		) {
			return flow;
		}
	}
	return NULL;
}

/**
 * Insert the flow into given hash bucket
 *
 * @param flow		Which is to be inserted
 * @param bucket	Target Hash Bucket
 *
 */
static inline void odp_route_flow_insert_in_bucket(odp_flow_entry_t *flow,
								void *bucket)
{
	odp_flow_entry_t *head, *temp;
	flow_bucket_t *bkt = (flow_bucket_t *)bucket;

	if (!flow) {
		EXAMPLE_ERR("Invalid flow entry passed\n");
		return;
	}

	LOCK(&bkt->lock);
	/*Check that entry already exist or not*/
	temp = odp_route_flow_lookup_in_bucket(flow->l3_src, flow->l3_dst,
						flow->l4_sport, flow->l4_dport,
						flow->l3_proto, bkt);
	if (temp) {
		UNLOCK(&bkt->lock);
		return;
	}

	if (!bkt->next) {
		bkt->next = flow;
	} else {
		head = bkt->next;
		flow->next = head;
		bkt->next = flow;
	}
	bkt->depth++;
	UNLOCK(&bkt->lock);
}

/**
 * Print Routing table information
 */
void odp_flow_table_print(void);

/*
 * Allocate and Initialize Forwarding database.
 *
 */
void init_fwd_db(void);

/**
 * Create a forwarding database entry
 *
 * String is of the format "SubNet:Intf:NextHopMAC"
 *
 * @param input  Pointer to string describing route
 *
 * @return 0 if successful else -1
 */
int create_fwd_db_entry(char *input);

/**
 * Scan FWD DB entries and resolve output queue and source MAC address
 *
 * @param intf   Interface name string
 * @param outq   Output queue for packet transmit
 * @param mac    MAC address of this interface
 */
void resolve_fwd_db(char *intf, odp_pktio_t pktio, uint8_t *mac);

/**
 * Display one fowarding database entry
 *
 * @param entry  Pointer to entry to display
 */
void dump_fwd_db_entry(fwd_db_entry_t *entry);

/**
 * Display the forwarding database
 */
void dump_fwd_db(void);

/**
 * Get the maximum bucket depth in the system
 */
uint32_t get_max_bucket_depth(void);

/**
 * Check IPv4 address against a range/subnet
 *
 * @param addr  IPv4 address to check
 * @param range Pointer to address range to check against
 *
 * @return 1 if match else 0
 */
static inline
int match_ip_range(uint32_t addr, ip_addr_range_t *range)
{
	return (range->addr == (addr & range->mask));
}

/**
 * Generate text string representing IPv4 address
 *
 * @param b    Pointer to buffer to store string
 * @param addr IPv4 address
 *
 * @return Pointer to supplied buffer
 */
static inline
char *ipv4_addr_str(char *b, uint32_t addr)
{
	sprintf(b, "%03d.%03d.%03d.%03d",
		0xFF & ((addr) >> 24),
		0xFF & ((addr) >> 16),
		0xFF & ((addr) >>  8),
		0xFF & ((addr) >>  0));
	return b;
}

/**
 * Parse text string representing an IPv4 address or subnet
 *
 * String is of the format "XXX.XXX.XXX.XXX(/W)" where
 * "XXX" is decimal value and "/W" is optional subnet length
 *
 * @param ipaddress  Pointer to IP address/subnet string to convert
 * @param addr       Pointer to return IPv4 address
 * @param mask       Pointer (optional) to return IPv4 mask
 *
 * @return 0 if successful else -1
 */
static inline
int parse_ipv4_string(char *ipaddress, uint32_t *addr, uint32_t *mask)
{
	int b[4];
	int qualifier = 32;
	int converted;

	if (strchr(ipaddress, '/')) {
		converted = sscanf(ipaddress, "%d.%d.%d.%d/%d",
				   &b[3], &b[2], &b[1], &b[0],
				   &qualifier);
		if (5 != converted)
			return -1;
	} else {
		converted = sscanf(ipaddress, "%d.%d.%d.%d",
				   &b[3], &b[2], &b[1], &b[0]);
		if (4 != converted)
			return -1;
	}

	if ((b[0] > 255) || (b[1] > 255) || (b[2] > 255) || (b[3] > 255))
		return -1;
	if (!qualifier || (qualifier > 32))
		return -1;

	*addr = b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24;
	if (mask)
		*mask = ~(0xFFFFFFFF & ((1ULL << (32 - qualifier)) - 1));

	return 0;
}

/**
 * Generate text string representing IPv4 range/subnet, output
 * in "XXX.XXX.XXX.XXX/W" format
 *
 * @param b     Pointer to buffer to store string
 * @param range Pointer to IPv4 address range
 *
 * @return Pointer to supplied buffer
 */
static inline
char *ipv4_subnet_str(char *b, ip_addr_range_t *range)
{
	int idx;
	int len;

	for (idx = 0; idx < 32; idx++)
		if (range->mask & (1 << idx))
			break;
	len = 32 - idx;

	sprintf(b, "%03d.%03d.%03d.%03d/%d",
		0xFF & ((range->addr) >> 24),
		0xFF & ((range->addr) >> 16),
		0xFF & ((range->addr) >>  8),
		0xFF & ((range->addr) >>  0),
		len);
	return b;
}

/**
 * Parse text string representing a MAC address into byte araray
 *
 * String is of the format "XX.XX.XX.XX.XX.XX" where XX is hexadecimal
 *
 * @param macaddress  Pointer to MAC address string to convert
 * @param mac         Pointer to MAC address byte array to populate
 *
 * @return 0 if successful else -1
 */
static inline
int parse_mac_string(char *macaddress, uint8_t *mac)
{
	uint8_t macwords[ODPH_ETHADDR_LEN];
	int converted;

	converted = sscanf(macaddress,
			   "%hhx.%hhx.%hhx.%hhx.%hhx.%hhx",
			   &macwords[0], &macwords[1], &macwords[2],
			   &macwords[3], &macwords[4], &macwords[5]);
	if (6 != converted)
		return -1;

	mac[0] = macwords[0];
	mac[1] = macwords[1];
	mac[2] = macwords[2];
	mac[3] = macwords[3];
	mac[4] = macwords[4];
	mac[5] = macwords[5];

	return 0;
}

/**
 * Adjust IPv4 length
 *
 * @param ip   Pointer to IPv4 header
 * @param adj  Signed adjustment value
 */
static inline
void ipv4_adjust_len(odph_ipv4hdr_t *ip, int adj)
{
	ip->tot_len = odp_cpu_to_be_16(odp_be_to_cpu_16(ip->tot_len) + adj);
}

/**
 * Find a matching forwarding database entry
 *
 * @param dst_ip  Destination IPv4 address
 *
 * @return pointer to forwarding DB entry else NULL
 */
static inline fwd_db_entry_t *find_fwd_db_entry(uint32_t dst_ip)
{
	fwd_db_entry_t *entry;

	for (entry = fwd_db->list; NULL != entry; entry = entry->next) {
		if (entry->subnet.addr == (dst_ip & entry->subnet.mask))
			break;
	}
	return entry;
}

/**
 * Generate text string representing MAC address
 *
 * @param b     Pointer to buffer to store string
 * @param mac   Pointer to MAC address
 *
 * @return Pointer to supplied buffer
 */
static inline
char *mac_addr_str(char *b, uint8_t *mac)
{
	sprintf(b, "%02X.%02X.%02X.%02X.%02X.%02X",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return b;
}
