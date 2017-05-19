/* Copyright (c) 2015 Freescale Semiconductor, Inc.
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example odp_l3fwd_ctrl.c  ODP layer 3 forwarding application's control
 *	plane to integrate route and arp entries for destination IP.
 */

/** enable strtok */
#define _POSIX_C_SOURCE 200112L

/*********************************************************************
			Header inclusion
**********************************************************************/
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <example_debug.h>

#include <odp.h>
#include "odp_l3fwd.h"
#include <odp/api/packet_io.h>

/*********************************************************************
			Global Definitions
**********************************************************************/
/**
 * Pointer to Flow cache table
 */
flow_bucket_t *flow_table;

/**
 * bucket count. It will be updated with user argument if provided
 */
uint32_t bucket_count = ODP_DEFAULT_BUCKET_COUNT;

/**
 * Global pointer to fwd db
 */
fwd_db_t *fwd_db;

/*********************************************************************
			Function Definitions
**********************************************************************/
/**
 * Print Flow table information
 *
 */
void odp_flow_table_print(void)
{
	uint32_t i;
	uint8_t	*temp;
	odp_flow_entry_t *flow, *head;

	printf("*********************************************************************\n");
	printf("***************************** Flows *********************************\n");
	for (i = 0; i < bucket_count; i++) {
		head = flow_table[i].next;
		for (flow = head; flow != NULL; flow = (odp_flow_entry_t *)flow->next) {
			temp = (uint8_t *)&flow->l3_src;
			printf("SIP: %d.%d.%d.%d\t", *(temp + 3), *(temp + 2), *(temp + 1), *(temp + 0));
			temp = (uint8_t *)&flow->l3_dst;
			printf("DIP: %d.%d.%d.%d\t", *(temp + 3), *(temp + 2), *(temp + 1), *(temp + 0));
			printf("SPORT: %u\t", flow->l4_sport);
			printf("DPORT: %u\t", flow->l4_dport);
			printf("PROTO: %u\t", flow->l3_proto);
			printf("Output Port: %lu\t", odp_pktio_to_u64(flow->out_port.pktio));
			printf ("\n");
		}
	}
	printf("*********************************************************************\n");
}

void init_fwd_db(void)
{
	odp_shm_t shm;

	shm = odp_shm_reserve("shm_fwd_db",
			      sizeof(fwd_db_t),
			      ODP_CACHE_LINE_SIZE,
			      0);

	fwd_db = (fwd_db_t *)odp_shm_addr(shm);

	if (fwd_db == NULL) {
		EXAMPLE_ABORT("Error: shared mem alloc failed.\n");
	}
	memset(fwd_db, 0, sizeof(*fwd_db));
}

int create_fwd_db_entry(char *input)
{
	int pos = 0;
	char *local;
	char *str;
	char *save;
	char *token;
	fwd_db_entry_t *entry = &fwd_db->array[fwd_db->index];

	/* Verify we haven't run out of space */
	if (MAX_ENTRIES_IN_TABLE <= fwd_db->index)
		return -1;

	/* Make a local copy */
	local = (char *)malloc(strlen(input) + 1);
	if (NULL == local)
		return -1;
	strcpy(local, input);

	/* Setup for using "strtok_r" to search input string */
	str = local;
	save = NULL;

	/* Parse tokens separated by ':' */
	while (NULL != (token = strtok_r(str, ":", &save))) {
		str = NULL;  /* reset str for subsequent strtok_r calls */

		/* Parse token based on its position */
		switch (pos) {
		case 0:
			parse_ipv4_string(token,
					  &entry->subnet.addr,
					  &entry->subnet.mask);
			break;
		case 1:
			strncpy(entry->oif, token, MAX_INTERFACE_STRING_SIZE - 1);
			entry->oif[MAX_INTERFACE_STRING_SIZE - 1] = 0;
			break;
		case 2:
			parse_mac_string(token, entry->dst_mac);
			break;
		default:
			printf("ERROR: extra token \"%s\" at position %d\n",
			       token, pos);
			break;
		}

		/* Advance to next position */
		pos++;
	}

	/* Verify we parsed exactly the number of tokens we expected */
	if (3 != pos) {
		printf("ERROR: \"%s\" contains %d tokens, expected 3\n",
		       input,
		       pos);
		free(local);
		return -1;
	}

	/* Reset pktio to invalid */
	entry->pktio = ODP_PKTIO_INVALID;

	/* Add route to the list */
	fwd_db->index++;
	entry->next = fwd_db->list;
	fwd_db->list = entry;

	free(local);
	return 0;
}

void resolve_fwd_db(char *intf, odp_pktio_t pktio, uint8_t *mac)
{
	fwd_db_entry_t *entry;

	/* Walk the list and attempt to set output queue and MAC */
	for (entry = fwd_db->list; NULL != entry; entry = entry->next) {
		if (strcmp(intf, entry->oif))
			continue;

		entry->pktio = pktio;
		memcpy(entry->src_mac, mac, ODPH_ETHADDR_LEN);
	}
}

void dump_fwd_db_entry(fwd_db_entry_t *entry)
{
	char subnet_str[MAX_SUBNET_STRING_SIZE];
	char mac_str[MAX_MAC_STRING_SIZE];

	printf(" %s %s %s\n",
	       ipv4_subnet_str(subnet_str, &entry->subnet),
	       entry->oif,
	       mac_addr_str(mac_str, entry->dst_mac));
}

void dump_fwd_db(void)
{
	fwd_db_entry_t *entry;

	printf("\n"
	       "Routing table\n"
	       "-------------\n");

	for (entry = fwd_db->list; NULL != entry; entry = entry->next)
		dump_fwd_db_entry(entry);
}

uint32_t get_max_bucket_depth(void)
{
	flow_bucket_t *bucket;
	uint32_t i, max_depth = 0;

	/* Get the maximum bucket depth */
	for (i = 0; i < bucket_count; i++) {
		bucket = &flow_table[i];
		max_depth = max_depth > bucket->depth ?
			max_depth : bucket->depth;
	}

	return max_depth;
}

void odp_init_routing_table(void)
{
	odp_shm_t		hash_shm;
	uint32_t		i;
	flow_bucket_t		*bucket;

	/*Initialize route table for user given parameter*/
	init_fwd_db();

	/*Reserve memory for Routing hash table*/
	hash_shm = odp_shm_reserve("route_table",
			sizeof(flow_bucket_t) * bucket_count,
						ODP_CACHE_LINE_SIZE, 0);
	flow_table = (flow_bucket_t *)odp_shm_addr(hash_shm);
	if (!flow_table) {
		EXAMPLE_ABORT("Error: shared mem alloc failed.\n");
	}
	/*Inialize Locks*/
	for (i = 0; i < bucket_count; i++) {
		bucket = &flow_table[i];
		LOCK_INIT(&bucket->lock);
	}

	memset(flow_table, 0, bucket_count * sizeof(flow_bucket_t));
}
