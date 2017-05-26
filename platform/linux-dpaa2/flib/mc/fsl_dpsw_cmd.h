/* Copyright 2013-2016 Freescale Semiconductor Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * * Neither the name of the above-listed copyright holders nor the
 * names of any contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef __FSL_DPSW_CMD_H
#define __FSL_DPSW_CMD_H

/* DPSW Version */
#define DPSW_VER_MAJOR		8
#define DPSW_VER_MINOR		1

/* Command versioning */
#define DPSW_CMD_BASE_VERSION	1
#define DPSW_CMD_ID_OFFSET	4

#define DPSW_CMD(id)	((id << DPSW_CMD_ID_OFFSET) | DPSW_CMD_BASE_VERSION)

/* Command IDs */
#define DPSW_CMDID_CLOSE                        DPSW_CMD(0x800)
#define DPSW_CMDID_OPEN                         DPSW_CMD(0x802)
#define DPSW_CMDID_CREATE                       DPSW_CMD(0x902)
#define DPSW_CMDID_DESTROY                      DPSW_CMD(0x982)
#define DPSW_CMDID_GET_API_VERSION              DPSW_CMD(0xa02)

#define DPSW_CMDID_ENABLE                       DPSW_CMD(0x002)
#define DPSW_CMDID_DISABLE                      DPSW_CMD(0x003)
#define DPSW_CMDID_GET_ATTR                     DPSW_CMD(0x004)
#define DPSW_CMDID_RESET                        DPSW_CMD(0x005)
#define DPSW_CMDID_IS_ENABLED                   DPSW_CMD(0x006)

#define DPSW_CMDID_SET_IRQ_ENABLE               DPSW_CMD(0x012)
#define DPSW_CMDID_GET_IRQ_ENABLE               DPSW_CMD(0x013)
#define DPSW_CMDID_SET_IRQ_MASK                 DPSW_CMD(0x014)
#define DPSW_CMDID_GET_IRQ_MASK                 DPSW_CMD(0x015)
#define DPSW_CMDID_GET_IRQ_STATUS               DPSW_CMD(0x016)
#define DPSW_CMDID_CLEAR_IRQ_STATUS             DPSW_CMD(0x017)

#define DPSW_CMDID_SET_REFLECTION_IF            DPSW_CMD(0x022)

#define DPSW_CMDID_ADD_CUSTOM_TPID              DPSW_CMD(0x024)

#define DPSW_CMDID_REMOVE_CUSTOM_TPID           DPSW_CMD(0x026)

#define DPSW_CMDID_IF_SET_TCI                   DPSW_CMD(0x030)
#define DPSW_CMDID_IF_SET_STP                   DPSW_CMD(0x031)
#define DPSW_CMDID_IF_SET_ACCEPTED_FRAMES       DPSW_CMD(0x032)
#define DPSW_CMDID_SET_IF_ACCEPT_ALL_VLAN       DPSW_CMD(0x033)
#define DPSW_CMDID_IF_GET_COUNTER               DPSW_CMD(0x034)
#define DPSW_CMDID_IF_SET_COUNTER               DPSW_CMD(0x035)
#define DPSW_CMDID_IF_SET_TX_SELECTION          DPSW_CMD(0x036)
#define DPSW_CMDID_IF_ADD_REFLECTION            DPSW_CMD(0x037)
#define DPSW_CMDID_IF_REMOVE_REFLECTION         DPSW_CMD(0x038)
#define DPSW_CMDID_IF_SET_FLOODING_METERING     DPSW_CMD(0x039)
#define DPSW_CMDID_IF_SET_METERING              DPSW_CMD(0x03A)
#define DPSW_CMDID_IF_SET_EARLY_DROP            DPSW_CMD(0x03B)

#define DPSW_CMDID_IF_ENABLE                    DPSW_CMD(0x03D)
#define DPSW_CMDID_IF_DISABLE                   DPSW_CMD(0x03E)

#define DPSW_CMDID_IF_GET_ATTR                  DPSW_CMD(0x042)

#define DPSW_CMDID_IF_SET_MAX_FRAME_LENGTH      DPSW_CMD(0x044)
#define DPSW_CMDID_IF_GET_MAX_FRAME_LENGTH      DPSW_CMD(0x045)
#define DPSW_CMDID_IF_GET_LINK_STATE            DPSW_CMD(0x046)
#define DPSW_CMDID_IF_SET_FLOODING              DPSW_CMD(0x047)
#define DPSW_CMDID_IF_SET_BROADCAST             DPSW_CMD(0x048)
#define DPSW_CMDID_IF_SET_MULTICAST             DPSW_CMD(0x049)
#define DPSW_CMDID_IF_GET_TCI                   DPSW_CMD(0x04A)

#define DPSW_CMDID_IF_SET_LINK_CFG              DPSW_CMD(0x04C)

#define DPSW_CMDID_VLAN_ADD                     DPSW_CMD(0x060)
#define DPSW_CMDID_VLAN_ADD_IF                  DPSW_CMD(0x061)
#define DPSW_CMDID_VLAN_ADD_IF_UNTAGGED         DPSW_CMD(0x062)
#define DPSW_CMDID_VLAN_ADD_IF_FLOODING         DPSW_CMD(0x063)
#define DPSW_CMDID_VLAN_REMOVE_IF               DPSW_CMD(0x064)
#define DPSW_CMDID_VLAN_REMOVE_IF_UNTAGGED      DPSW_CMD(0x065)
#define DPSW_CMDID_VLAN_REMOVE_IF_FLOODING      DPSW_CMD(0x066)
#define DPSW_CMDID_VLAN_REMOVE                  DPSW_CMD(0x067)
#define DPSW_CMDID_VLAN_GET_IF                  DPSW_CMD(0x068)
#define DPSW_CMDID_VLAN_GET_IF_FLOODING         DPSW_CMD(0x069)
#define DPSW_CMDID_VLAN_GET_IF_UNTAGGED         DPSW_CMD(0x06A)
#define DPSW_CMDID_VLAN_GET_ATTRIBUTES          DPSW_CMD(0x06B)

#define DPSW_CMDID_FDB_GET_MULTICAST            DPSW_CMD(0x080)
#define DPSW_CMDID_FDB_GET_UNICAST              DPSW_CMD(0x081)
#define DPSW_CMDID_FDB_ADD                      DPSW_CMD(0x082)
#define DPSW_CMDID_FDB_REMOVE                   DPSW_CMD(0x083)
#define DPSW_CMDID_FDB_ADD_UNICAST              DPSW_CMD(0x084)
#define DPSW_CMDID_FDB_REMOVE_UNICAST           DPSW_CMD(0x085)
#define DPSW_CMDID_FDB_ADD_MULTICAST            DPSW_CMD(0x086)
#define DPSW_CMDID_FDB_REMOVE_MULTICAST         DPSW_CMD(0x087)
#define DPSW_CMDID_FDB_SET_LEARNING_MODE        DPSW_CMD(0x088)
#define DPSW_CMDID_FDB_GET_ATTR                 DPSW_CMD(0x089)
#define DPSW_CMDID_FDB_DUMP                     DPSW_CMD(0x08A)

#define DPSW_CMDID_ACL_ADD                      DPSW_CMD(0x090)
#define DPSW_CMDID_ACL_REMOVE                   DPSW_CMD(0x091)
#define DPSW_CMDID_ACL_ADD_ENTRY                DPSW_CMD(0x092)
#define DPSW_CMDID_ACL_REMOVE_ENTRY             DPSW_CMD(0x093)
#define DPSW_CMDID_ACL_ADD_IF                   DPSW_CMD(0x094)
#define DPSW_CMDID_ACL_REMOVE_IF                DPSW_CMD(0x095)
#define DPSW_CMDID_ACL_GET_ATTR                 DPSW_CMD(0x096)

#define DPSW_CMDID_CTRL_IF_GET_ATTR             DPSW_CMD(0x0A0)
#define DPSW_CMDID_CTRL_IF_SET_POOLS            DPSW_CMD(0x0A1)
#define DPSW_CMDID_CTRL_IF_ENABLE               DPSW_CMD(0x0A2)
#define DPSW_CMDID_CTRL_IF_DISABLE              DPSW_CMD(0x0A3)

/* Macros for accessing command fields smaller than 1byte */
#define DPSW_MASK(field)        \
	GENMASK(DPSW_##field##_SHIFT + DPSW_##field##_SIZE - 1, \
		DPSW_##field##_SHIFT)
#define dpsw_set_field(var, field, val) \
	((var) |= (((val) << DPSW_##field##_SHIFT) & DPSW_MASK(field)))
#define dpsw_get_field(var, field)      \
	(((var) & DPSW_MASK(field)) >> DPSW_##field##_SHIFT)
#define dpsw_set_bit(var, bit, val) \
	((var) |= (((uint64_t)(val) << (bit)) & GENMASK((bit), (bit))))
#define dpsw_get_bit(var, bit) \
	(((var)  >> bit) & GENMASK(0, 0))

#pragma pack(push, 1)
struct dpsw_cmd_open {
	uint32_t dpsw_id;
};

#define DPSW_COMPONENT_TYPE_SHIFT	0
#define DPSW_COMPONENT_TYPE_SIZE	4

struct dpsw_cmd_create {
	/* cmd word 0 */
	uint16_t num_ifs;
	uint8_t max_fdbs;
	uint8_t max_meters_per_if;
	/* from LSB: only the first 4 bits */
	uint8_t component_type;
	uint8_t pad[3];
	/* cmd word 1 */
	uint16_t max_vlans;
	uint16_t max_fdb_entries;
	uint16_t fdb_aging_time;
	uint16_t max_fdb_mc_groups;
	/* cmd word 2 */
	uint64_t options;
};

struct dpsw_cmd_destroy {
	uint32_t dpsw_id;
};

#define DPSW_ENABLE_SHIFT 0
#define DPSW_ENABLE_SIZE  1

struct dpsw_rsp_is_enabled {
	/* from LSB: enable:1 */
	uint8_t enabled;
};

struct dpsw_cmd_set_irq_enable {
	uint8_t enable_state;
	uint8_t pad[3];
	uint8_t irq_index;
};

struct dpsw_cmd_get_irq_enable {
	uint32_t pad;
	uint8_t irq_index;
};

struct dpsw_rsp_get_irq_enable {
	uint8_t enable_state;
};

struct dpsw_cmd_set_irq_mask {
	uint32_t mask;
	uint8_t irq_index;
};

struct dpsw_cmd_get_irq_mask {
	uint32_t pad;
	uint8_t irq_index;
};

struct dpsw_rsp_get_irq_mask {
	uint32_t mask;
};

struct dpsw_cmd_get_irq_status {
	uint32_t status;
	uint8_t irq_index;
};

struct dpsw_rsp_get_irq_status {
	uint32_t status;
};

struct dpsw_cmd_clear_irq_status {
	uint32_t status;
	uint8_t irq_index;
};

#define DPSW_COMPONENT_TYPE_SHIFT	0
#define DPSW_COMPONENT_TYPE_SIZE	4

struct dpsw_rsp_get_attr {
	/* cmd word 0 */
	uint16_t num_ifs;
	uint8_t max_fdbs;
	uint8_t num_fdbs;
	uint16_t max_vlans;
	uint16_t num_vlans;
	/* cmd word 1 */
	uint16_t max_fdb_entries;
	uint16_t fdb_aging_time;
	uint32_t dpsw_id;
	/* cmd word 2 */
	uint16_t mem_size;
	uint16_t max_fdb_mc_groups;
	uint8_t max_meters_per_if;
	/* from LSB only the ffirst 4 bits */
	uint8_t component_type;
	uint16_t pad;
	/* cmd word 3 */
	uint64_t options;
};

struct dpsw_cmd_set_reflection_if {
	uint16_t if_id;
};

struct dpsw_cmd_if_set_flooding {
	uint16_t if_id;
	/* from LSB: enable:1 */
	uint8_t enable;
};

struct dpsw_cmd_if_set_broadcast {
	uint16_t if_id;
	/* from LSB: enable:1 */
	uint8_t enable;
};

struct dpsw_cmd_if_set_multicast {
	uint16_t if_id;
	/* from LSB: enable:1 */
	uint8_t enable;
};

#define DPSW_VLAN_ID_SHIFT	0
#define DPSW_VLAN_ID_SIZE	12
#define DPSW_DEI_SHIFT		12
#define DPSW_DEI_SIZE		1
#define DPSW_PCP_SHIFT		13
#define DPSW_PCP_SIZE		3

struct dpsw_cmd_if_set_tci {
	uint16_t if_id;
	/* from LSB: VLAN_ID:12 DEI:1 PCP:3 */
	uint16_t conf;
};

struct dpsw_cmd_if_get_tci {
	uint16_t if_id;
};

struct dpsw_rsp_if_get_tci {
	uint16_t pad;
	uint16_t vlan_id;
	uint8_t dei;
	uint8_t pcp;
};

#define DPSW_STATE_SHIFT	0
#define DPSW_STATE_SIZE		4

struct dpsw_cmd_if_set_stp {
	uint16_t if_id;
	uint16_t vlan_id;
	/* only the first LSB 4 bits */
	uint8_t state;
};

#define DPSW_FRAME_TYPE_SHIFT		0
#define DPSW_FRAME_TYPE_SIZE		4
#define DPSW_UNACCEPTED_ACT_SHIFT	4
#define DPSW_UNACCEPTED_ACT_SIZE	4

struct dpsw_cmd_if_set_accepted_frames {
	uint16_t if_id;
	/* from LSB: type:4 unaccepted_act:4 */
	uint8_t unaccepted;
};

#define DPSW_ACCEPT_ALL_SHIFT	0
#define DPSW_ACCEPT_ALL_SIZE	1

struct dpsw_cmd_if_set_accept_all_vlan {
	uint16_t if_id;
	/* only the least significant bit */
	uint8_t accept_all;
};

#define DPSW_COUNTER_TYPE_SHIFT		0
#define DPSW_COUNTER_TYPE_SIZE		5

struct dpsw_cmd_if_get_counter {
	uint16_t if_id;
	/* from LSB: type:5 */
	uint8_t type;
};

struct dpsw_rsp_if_get_counter {
	uint64_t pad;
	uint64_t counter;
};


struct dpsw_cmd_if_set_counter {
	/* cmd word 0 */
	uint16_t if_id;
	/* from LSB: type:5 */
	uint8_t type;
	uint8_t pad[5];
	/* cmd word 1 */
	uint64_t counter;
};

#define DPSW_PRIORITY_SELECTOR_SHIFT	0
#define DPSW_PRIORITY_SELECTOR_SIZE	3
#define DPSW_SCHED_MODE_SHIFT		0
#define DPSW_SCHED_MODE_SIZE		4

struct dpsw_cmd_if_set_tx_selection {
	uint16_t if_id;
	/* from LSB: priority_selector:3 */
	uint8_t priority_selector;
	uint8_t pad[5];
	uint8_t tc_id[8];

	struct dpsw_tc_sched {
		uint16_t delta_bandwidth;
		uint8_t mode;
		uint8_t pad;
	} tc_sched[8];
};

#define DPSW_FILTER_SHIFT	0
#define DPSW_FILTER_SIZE	2

struct dpsw_cmd_if_reflection {
	uint16_t if_id;
	uint16_t vlan_id;
	/* only 2 bits from the LSB */
	uint8_t filter;
};

#define DPSW_MODE_SHIFT		0
#define DPSW_MODE_SIZE		4
#define DPSW_UNITS_SHIFT	4
#define DPSW_UNITS_SIZE		4

struct dpsw_cmd_if_set_flooding_metering {
	/* cmd word 0 */
	uint16_t if_id;
	uint8_t pad;
	/* from LSB: mode:4 units:4 */
	uint8_t mode_units;
	uint32_t cir;
	/* cmd word 1 */
	uint32_t eir;
	uint32_t cbs;
	/* cmd word 2 */
	uint32_t ebs;
};

struct dpsw_cmd_if_set_metering {
	/* cmd word 0 */
	uint16_t if_id;
	uint8_t tc_id;
	/* from LSB: mode:4 units:4 */
	uint8_t mode_units;
	uint32_t cir;
	/* cmd word 1 */
	uint32_t eir;
	uint32_t cbs;
	/* cmd word 2 */
	uint32_t ebs;
};

#define DPSW_EARLY_DROP_MODE_SHIFT	0
#define DPSW_EARLY_DROP_MODE_SIZE	2
#define DPSW_EARLY_DROP_UNIT_SHIFT	2
#define DPSW_EARLY_DROP_UNIT_SIZE	2

struct dpsw_prep_early_drop {
	/* from LSB: mode:2 units:2 */
	uint8_t conf;
	uint8_t pad0[3];
	uint32_t tail_drop_threshold;
	uint8_t green_drop_probability;
	uint8_t pad1[7];
	uint64_t green_max_threshold;
	uint64_t green_min_threshold;
	uint64_t pad2;
	uint8_t yellow_drop_probability;
	uint8_t pad3[7];
	uint64_t yellow_max_threshold;
	uint64_t yellow_min_threshold;
};

struct dpsw_cmd_if_set_early_drop {
	/* cmd word 0 */
	uint8_t pad0;
	uint8_t tc_id;
	uint16_t if_id;
	uint32_t pad1;
	/* cmd word 1 */
	uint64_t early_drop_iova;
};

struct dpsw_cmd_custom_tpid {
	uint16_t pad;
	uint16_t tpid;
};

struct dpsw_cmd_if {
	uint16_t if_id;
};

#define DPSW_ADMIT_UNTAGGED_SHIFT	0
#define DPSW_ADMIT_UNTAGGED_SIZE	4
#define DPSW_ENABLED_SHIFT		5
#define DPSW_ENABLED_SIZE		1
#define DPSW_ACCEPT_ALL_VLAN_SHIFT	6
#define DPSW_ACCEPT_ALL_VLAN_SIZE	1

struct dpsw_rsp_if_get_attr {
	/* cmd word 0 */
	/* from LSB: admit_untagged:4 enabled:1 accept_all_vlan:1 */
	uint8_t conf;
	uint8_t pad1;
	uint8_t num_tcs;
	uint8_t pad2;
	uint16_t qdid;
	/* cmd word 1 */
	uint32_t options;
	uint32_t pad3;
	/* cmd word 2 */
	uint32_t rate;
};

struct dpsw_cmd_if_set_max_frame_length {
	uint16_t if_id;
	uint16_t frame_length;
};

struct dpsw_cmd_if_get_max_frame_length {
	uint16_t if_id;
};

struct dpsw_rsp_if_get_max_frame_length {
	uint16_t pad;
	uint16_t frame_length;
};

struct dpsw_cmd_if_set_link_cfg {
	/* cmd word 0 */
	uint16_t if_id;
	uint8_t pad[6];
	/* cmd word 1 */
	uint32_t rate;
	uint32_t pad1;
	/* cmd word 2 */
	uint64_t options;
};

struct dpsw_cmd_if_get_link_state {
	uint16_t if_id;
};

#define DPSW_UP_SHIFT	0
#define DPSW_UP_SIZE	1

struct dpsw_rsp_if_get_link_state {
	/* cmd word 0 */
	uint32_t pad0;
	uint8_t up;
	uint8_t pad1[3];
	/* cmd word 1 */
	uint32_t rate;
	uint32_t pad2;
	/* cmd word 2 */
	uint64_t options;
};

struct dpsw_vlan_add {
	uint16_t fdb_id;
	uint16_t vlan_id;
};

struct dpsw_cmd_vlan_manage_if {
	/* cmd word 0 */
	uint16_t pad0;
	uint16_t vlan_id;
	uint32_t pad1;
	/* cmd word 1 */
	uint64_t if_id[4];
};

struct dpsw_cmd_vlan_remove {
	uint16_t pad;
	uint16_t vlan_id;
};

struct dpsw_cmd_vlan_get_attr {
	uint16_t vlan_id;
};

struct dpsw_rsp_vlan_get_attr {
	/* cmd word 0 */
	uint64_t pad;
	/* cmd word 1 */
	uint16_t fdb_id;
	uint16_t num_ifs;
	uint16_t num_untagged_ifs;
	uint16_t num_flooding_ifs;
};

struct dpsw_cmd_vlan_get_if {
	uint16_t vlan_id;
};

struct dpsw_rsp_vlan_get_if {
	/* cmd word 0 */
	uint16_t pad0;
	uint16_t num_ifs;
	uint8_t pad1[4];
	/* cmd word 1 */
	uint64_t if_id[4];
};


struct dpsw_cmd_vlan_get_if_untagged {
	uint16_t vlan_id;
};

struct dpsw_rsp_vlan_get_if_untagged {
	/* cmd word 0 */
	uint16_t pad0;
	uint16_t num_ifs;
	uint8_t pad1[4];
	/* cmd word 1 */
	uint64_t if_id[4];
};


struct dpsw_cmd_vlan_get_if_flooding {
	uint16_t vlan_id;
};

struct dpsw_rsp_vlan_get_if_flooding {
	/* cmd word 0 */
	uint16_t pad0;
	uint16_t num_ifs;
	uint8_t pad1[4];
	/* cmd word 1 */
	uint64_t if_id[4];
};

struct dpsw_cmd_fdb_add {
	uint32_t pad;
	uint16_t fdb_aging_time;
	uint16_t num_fdb_entries;
};

struct dpsw_rsp_fdb_add {
	uint16_t fdb_id;
};

struct dpsw_cmd_fdb_remove {
	uint16_t fdb_id;
};

#define DPSW_ENTRY_TYPE_SHIFT	0
#define DPSW_ENTRY_TYPE_SIZE	4

struct dpsw_cmd_fdb_add_unicast {
	/* cmd word 0 */
	uint16_t fdb_id;
	uint8_t mac_addr[6];
	/* cmd word 1 */
	uint8_t if_egress;
	uint8_t pad;
	/* only the first 4 bits from LSB */
	uint8_t type;
};

struct dpsw_cmd_fdb_get_unicast {
	uint16_t fdb_id;
	uint8_t mac_addr[6];
};

struct dpsw_rsp_fdb_get_unicast {
	uint64_t pad;
	uint16_t if_egress;
	/* only first 4 bits from LSB */
	uint8_t type;
};

struct dpsw_cmd_fdb_remove_unicast {
	/* cmd word 0 */
	uint16_t fdb_id;
	uint8_t mac_addr[6];
	/* cmd word 1 */
	uint16_t if_egress;
	/* only the first 4 bits from LSB */
	uint8_t type;
};

struct dpsw_cmd_fdb_add_multicast {
	/* cmd word 0 */
	uint16_t fdb_id;
	uint16_t num_ifs;
	/* only the first 4 bits from LSB */
	uint8_t type;
	uint8_t pad[3];
	/* cmd word 1 */
	uint8_t mac_addr[6];
	uint16_t pad2;
	/* cmd word 2 */
	uint64_t if_id[4];
};

struct dpsw_cmd_fdb_get_multicast {
	uint16_t fdb_id;
	uint8_t mac_addr[6];
};

struct dpsw_rsp_fdb_get_multicast {
	/* cmd word 0 */
	uint64_t pad0;
	/* cmd word 1 */
	uint16_t num_ifs;
	/* only the first 4 bits from LSB */
	uint8_t type;
	uint8_t pad1[5];
	/* cmd word 2 */
	uint64_t if_id[4];
};


struct dpsw_cmd_fdb_dump {
	uint16_t fdb_id;
	uint16_t pad0;
	uint32_t pad1;
	uint64_t iova_addr;
	uint32_t iova_size;
};

struct dpsw_rsp_fdb_dump {
	uint16_t num_entries;
};

#define DPSW_UNICAST(type_unicast)		(!!(type_unicast&0x10))
#define DPSW_TYPE(type_unicast)			(type_unicast&0x0f)

struct dpsw_rsp_fdb_get_offline_entry {
	/* cmd word 0 */
	uint16_t pad;
	uint8_t mac_addr[6];
	/* cmd word 1 */
	uint16_t if_info;
	uint8_t type_unicast;
	uint8_t pad2;
	uint32_t pad3;
	/* cmd word 2 */
	uint64_t if_id[4];
};

struct dpsw_cmd_fdb_remove_multicast {
	/* cmd word 0 */
	uint16_t fdb_id;
	uint16_t num_ifs;
	/* only the first 4 bits from LSB */
	uint8_t type;
	uint8_t pad[3];
	/* cmd word 1 */
	uint8_t mac_addr[6];
	uint16_t pad2;
	/* cmd word 2 */
	uint64_t if_id[4];
};

#define DPSW_LEARNING_MODE_SHIFT	0
#define DPSW_LEARNING_MODE_SIZE		4

struct dpsw_cmd_fdb_set_learning_mode {
	uint16_t fdb_id;
	/* only the first 4 bits from LSB */
	uint8_t mode;
};

struct dpsw_cmd_fdb_get_attr {
	uint16_t fdb_id;
};

struct dpsw_rsp_fdb_get_attr {
	/* cmd word 0 */
	uint16_t pad;
	uint16_t max_fdb_entries;
	uint16_t fdb_aging_time;
	uint16_t num_fdb_mc_groups;
	/* cmd word 1 */
	uint16_t max_fdb_mc_groups;
	/* only the first 4 bits from LSB */
	uint8_t learning_mode;
};

struct dpsw_cmd_acl_add {
	uint16_t pad;
	uint16_t max_entries;
};

struct dpsw_rsp_acl_add {
	uint16_t acl_id;
};

struct dpsw_cmd_acl_remove {
	uint16_t acl_id;
};

struct dpsw_prep_acl_entry {
	uint8_t match_l2_dest_mac[6];
	uint16_t match_l2_tpid;

	uint8_t match_l2_source_mac[6];
	uint16_t match_l2_vlan_id;

	uint32_t match_l3_dest_ip;
	uint32_t match_l3_source_ip;

	uint16_t match_l4_dest_port;
	uint16_t match_l4_source_port;
	uint16_t match_l2_ether_type;
	uint8_t match_l2_pcp_dei;
	uint8_t match_l3_dscp;

	uint8_t mask_l2_dest_mac[6];
	uint16_t mask_l2_tpid;

	uint8_t mask_l2_source_mac[6];
	uint16_t mask_l2_vlan_id;

	uint32_t mask_l3_dest_ip;
	uint32_t mask_l3_source_ip;

	uint16_t mask_l4_dest_port;
	uint16_t mask_l4_source_port;
	uint16_t mask_l2_ether_type;
	uint8_t mask_l2_pcp_dei;
	uint8_t mask_l3_dscp;

	uint8_t match_l3_protocol;
	uint8_t mask_l3_protocol;
};

#define DPSW_RESULT_ACTION_SHIFT	0
#define DPSW_RESULT_ACTION_SIZE		4

struct dpsw_cmd_acl_entry {
	uint16_t acl_id;
	uint16_t result_if_id;
	uint32_t precedence;
	/* from LSB only the first 4 bits */
	uint8_t result_action;
	uint8_t pad[7];
	uint64_t pad2[4];
	uint64_t key_iova;
};

struct dpsw_cmd_acl_if {
	/* cmd word 0 */
	uint16_t acl_id;
	uint16_t num_ifs;
	uint32_t pad;
	/* cmd word 1 */
	uint64_t if_id[4];
};

struct dpsw_cmd_acl_get_attr {
	uint16_t acl_id;
};

struct dpsw_rsp_acl_get_attr {
	/* cmd word 0 */
	uint64_t pad;
	/* cmd word 1 */
	uint16_t max_entries;
	uint16_t num_entries;
	uint16_t num_ifs;
};

struct dpsw_rsp_ctrl_if_get_attr {
	/* cmd word 0 */
	uint64_t pad;
	/* cmd word 1 */
	uint32_t rx_fqid;
	uint32_t rx_err_fqid;
	/* cmd word 2 */
	uint32_t tx_err_conf_fqid;
};

struct dpsw_cmd_ctrl_if_set_pools {
	uint8_t num_dpbp;
	/* from LSB: POOL0_BACKUP_POOL:1 ... POOL7_BACKUP_POOL */
	uint8_t backup_pool;
	uint16_t pad;
	uint32_t dpbp_id[8];
	uint16_t buffer_size[8];
};

struct dpsw_rsp_get_api_version {
	uint16_t version_major;
	uint16_t version_minor;
};
#pragma pack(pop)
#endif /* __FSL_DPSW_CMD_H */
