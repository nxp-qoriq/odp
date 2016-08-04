/**
 \file neigh.h
 \brief Contains neighbour/next hop related table, data structures,
 and defines used for ARP
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
#ifndef __NEIGH_H
#define __NEIGH_H

#include <stdlib.h>
#include <pthread.h>
#include <common/refcount.h>
#include "net.h"
#include <fsl_crc64.h>
#include <odp.h>
#include <odp/helper/eth.h>

#define NEIGH_STATE_UNKNOWN	0x00
/**< Entry State - Unknown*/
#define NEIGH_STATE_NO_NEIGH	0x01				/**< Entry State - No Neighbour*/
#define NEIGH_STATE_PERMANENT	0x02				/**< Entry State - Permanent*/
#define NEIGH_STATE_PENDING	0x04				/**< Entry State - Incomplete*/
#define NEIGH_STATE_REACHABLE	0x08				/**< Entry State - Reachable*/
#define NEIGH_STATE_STALE	0x10					/**< Entry State - Stale*/
#define NEIGH_STATE_QUIESCE	0x20					/**< Entry State - Quisce*/
#define NEIGH_STATE_SOLICIT	0x40					/**< Entry State - Solicit*/
#define NEIGH_STATE_FAILED	0x80					/**< Entry State - Failed*/

#define NEIGH_TABLE_MAX_ENTRIES_2EXP	(10)
#define NEIGH_TABLE_BUCKETS_2EXP	(10)
#define NEIGH_POOL_SIZE_2EXP		(12)

#define NEIGH_TABLE_MAX_ENTRIES		(1 << NEIGH_TABLE_MAX_ENTRIES_2EXP)
/**< Maximum Number of entries in Neighbour Table*/
#define NEIGH_TABLE_ENTRIES_MASK	(NEIGH_TABLE_MAX_ENTRIES - 1)
/**< Table Mask*/
#define NEIGH_TABLE_BUCKETS		(1 << NEIGH_TABLE_BUCKETS_2EXP)
/**< Maximum number of entries in a bucket of the Table*/
#define NEIGH_TABLE_BUCKETS_MASK	(NEIGH_TABLE_BUCKETS - 1)
/**< Buckt Mask*/
#define NEIGH_POOL_SIZE			(1 << NEIGH_POOL_SIZE_2EXP)
/**< Number of Entries in the Pool*/

struct neigh_t;

/**
 \brief Configuration structure having timeout values for various timers
 */
struct neigh_config_t {
	/* Coarse Timeouts, Using MFATBU */
	uint32_t base_reachable_timeout;
	uint32_t reachable_timeout;
	/* Fine Timeouts */
	uint32_t retrans_timeout;
	uint32_t quiesce_timeout;
	uint32_t solicit_queue_len;
};

/**
 \brief Structure containing notification functions registered by Protocol handler
 */
struct neigh_func_t {
	/* Set by Protocol Handler Create Function */
	void (*solicit) (struct neigh_t *, odp_packet_t);
	void (*error_handler) (struct neigh_t *, odp_packet_t);
	/* Set by Neighbor Init Function */
	void (*full_output) (struct neigh_t *, void *, void *);
	void (*reachable_output) (struct neigh_t *, void *, void *);
	/* Set by Netdevice Init Function */
/*FIXME	void (*xmit) (struct ppac_interface *, struct qm_fd *, void *);*/
};

/**
 \brief Stats related to the Neighbor table
 */
struct neigh_stats_t {
	union stat64_t lookup_attempts;
	/**< Number of times a lookUp is attempted*/
	union stat64_t lookup_hits;
	/**< Number of times a lookUp is successful*/
	union stat64_t solicit_errors;
	/**< Number of Solicit Error occured*/
	union stat64_t protocol_errors;
	/**< Number of Protocol Erors occured*/
	stat32_t entries;
	/**< Number of Entries in the Table*/
};

/**
 \brief Neighbor Entry structure
 */
struct neigh_t {
	/* Structs - 32B */
	struct neigh_t *next;
	/**< Pointer to the next node in th eLinked List*/
	pthread_mutex_t wlock;
	/**< Lock for accessing the Entry*/
	struct neigh_table_t *nt;
	/**< Pointer to the Neighbour table*/
	odp_pktio_t pktio;		/**< Net Device Pointer*/
	struct neigh_func_t *funcs;
	/**< Pointer to the structure having the notification functions*/
	struct neigh_config_t *config;
	/**< Pointer to Config structure having timeout values for diff timers*/
	struct ll_cache_t *ll_cache;	/**< Pointer to the cache Entry*/
	void (*output) (struct neigh_t *, void *notes, void *ll_payload);
	/**< Egress handler to reach this neighbor*/
	/*struct qm_fd fd;*/		/**< frame descriptor*/

	/* Addresses - 10B */
	uint32_t proto_addr[L3_MAX_ADDR_LEN_WORDS];
	/**< IP Address*/
	odph_ethaddr_t neigh_addr;
	/**< MAC Address*/

	/* State - 10B */
	uint8_t neigh_state;
	/**< State of the Entry*/
	uint8_t solicitations_sent;
	refcount_t *refcnt;
	/* struct list_head_t	   *solicit_q; */
	/* Timers - 5B */
	uint32_t retransmit_timer;
	uint8_t retransmit_count;
};
/*} __attribute__((aligned(L1_CACHE_BYTES)));*/

/**
 \brief Neighbor Entry related functions, and data
 */
struct __neigh_func_combo_t {
	struct neigh_t neigh;			/**< Neighbor Entry structure*/
	struct neigh_func_t funcs;		/**< Structure having the notification functions*/
};

/**
 \brief Neighbour Table Bucket
 */
struct neigh_bucket_t {
	uint32_t id;			/**< Bucket Id*/
	pthread_mutex_t wlock;			/**< Lock to access th eHead of the Link List in the Bucket*/
	struct neigh_t *head;		/**< Head of the List of Neighbour Entries*/
};

/**
 \brief Neighbour Table Structure
 */
struct neigh_table_t {
	uint32_t proto_len;
	/**< Protocol Length*/
	void (*constructor) (struct neigh_t *);						/**< Contructor function called when initializing an Entry*/
	struct neigh_config_t config;								/**< Configuration structure having timeout info related to various timers*/
	struct neigh_stats_t *stats;									/**< Stats for neighbour table*/
	struct mem_cache_t *free_entries;							/**< List of Free Entries in the Table*/
	struct neigh_bucket_t buckets[NEIGH_TABLE_BUCKETS];		/**< Neighbour Table Bucket Array*/
};

typedef void (*nt_execfn_t) (struct neigh_t *);

/**
 \brief Hash function used for finding the appropriate bucket related to an IP Address
 \param[in] key IP Address
 \param[in] key_len Length of the key
 \return Bucket Id (0 - (NEIGH_TABLE_BUCKETS_MASK - 1))
 */
static inline uint32_t compute_neigh_hash(uint32_t key, uint32_t key_len ODP_UNUSED)
{
	uint64_t result;

	result = fman_crc64_init();
	result = fman_crc64_compute_32bit(key, result);
	result = fman_crc64_finish(result);
	return ((uint32_t) result) & NEIGH_TABLE_BUCKETS_MASK;
}
/** \brief		Initializes the neighbour table
 *  \param[out]	table	Neighbour table
 *  \return		On success, zero. On error, a negative
 value as per errno.h
 */
int neigh_table_init(struct neigh_table_t *table);

/**
 \brief Allocates a Neighbour Table Entry
 \param[in] nt Pointer to the Neighbour table
 \return Pointer to Neighbour Table Entry
 */
struct neigh_t *neigh_create(struct neigh_table_t *nt);

/**
 \brief Initializes the Neighbour Table Entry
 \param[in] nt Pointer to the Neighbour table
 \param[in] n Pointer to the Neighbour table Entry
 \param[in] dev Net Device Pointer
 \param[in] proto_addr IP Address
 \return Pointer to Neighbour Table Entry
 */
struct neigh_t *neigh_init(struct neigh_table_t *nt, struct neigh_t *n,
			   odp_pktio_t pktio, uint32_t *proto_addr);

/**
 \brief Updates the Neighbour Table Entry with MAC Address, and State
 \param[in] n Pointer to the Neighbour table Entry
 \param[in] lladdr Pointer to the MAC Address
 \param[in] state State for the Entry
 \return Pointer to Neighbour Table Entry
 */
struct neigh_t *neigh_update(struct neigh_t *n, const uint8_t *lladdr,
			     uint8_t state);

/**
 \brief Adds the Neighbour Table Entry into the Table
 \param[in] nt Pointer to the Neighbour table
 \param[in] new_n Pointer to the Neighbour table Entry
 \return true if addition was successful, else false
 */
bool neigh_add(struct neigh_table_t *nt, struct neigh_t *new_n);

/**
 \brief Replaces the Neighbour Table Entry with same IP Address with the new one
 \param[in] nt Pointer to the Neighbour table
 \param[in] new_n Pointer to the new Neighbour table Entry
 \return true if replacement was successful, else false
 */
bool neigh_replace(struct neigh_table_t *nt, struct neigh_t *new_n);

/**
 \brief Removes a Neighbour Table Entry
 \param[in] nt Pointer to the Neighbour table
 \param[in] key	 IP Address
 \param[in] keylen Length of the Key
 \return true if removal was successful, else false
 */
bool neigh_remove(struct neigh_table_t *nt, uint32_t key, uint32_t keylen);

/**
 \brief Prints Neighbour Table Stats
 \param[in] nt Pointer to the Neighbour table
 */
void neigh_table_print_stats(struct neigh_table_t *nt, bool print_zero);

/**
 \brief Prints Neighbour Table Entry Data
 \param[in] n Pointer to the Neighbour table entry
 */
void neigh_print_entry(struct neigh_t *n);

/**
 \brief Prints All Neighbour Table Entries calling 'neigh_print_entry iteratively'
 \param[in] nt Pointer to the Neighbour table
 */
void neigh_table_print(struct neigh_table_t *nt);

/**
 \brief Generic function used for performing action on each of the entries in the Neighbour Table
 \param[in] nt Pointer to the Neighbour table
 \param[in] execfn Function to be executed for every entry
 */
void neigh_exec_per_entry(struct neigh_table_t *nt, nt_execfn_t execfn);

/**
 \brief Looks Up for a Neighbour Table Entry gievn the IP Address
 \param[in] nt Pointer to the Neighbour table
 \param[in] key	 IP Address
 \param[in] keylen Length of the Key
 \return Pointer to the Entry if found, else NULL
 */
void neigh_table_delete(struct neigh_table_t *table);

struct neigh_t *neigh_lookup(struct neigh_table_t *nt, uint32_t key,
			     uint32_t keylen);

void neigh_reachable_output(struct neigh_t *n, void *notes, void *ll_payload);

bool __neigh_delete(struct neigh_table_t *nt, struct neigh_t **nptr);
void __neigh_free(void *n, void *ctxt);
#endif	/* __NEIGH_H */
