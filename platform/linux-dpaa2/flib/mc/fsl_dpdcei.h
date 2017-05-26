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
#ifndef __FSL_DPDCEI_H
#define __FSL_DPDCEI_H

/* Data Path DCE Interface API
 * Contains initialization APIs and runtime control APIs for DPDCEI
 */

struct fsl_mc_io;

/** General DPDCEI macros */

/**
 * Indicates an invalid frame queue
 */
#define DPDCEI_FQID_NOT_VALID	(uint32_t)(-1)

/**
 * enum dpdcei_engine - DCE engine block
 * @DPDCEI_ENGINE_COMPRESSION: Engine compression
 * @DPDCEI_ENGINE_DECOMPRESSION: Engine decompression
 */
enum dpdcei_engine {
	DPDCEI_ENGINE_COMPRESSION,
	DPDCEI_ENGINE_DECOMPRESSION
};

int dpdcei_open(struct fsl_mc_io *mc_io,
		uint32_t cmd_flags,
		int dpdcei_id,
		uint16_t *token);

int dpdcei_close(struct fsl_mc_io *mc_io,
		 uint32_t cmd_flags,
		 uint16_t token);

/**
 * struct dpdcei_cfg - Structure representing DPDCEI configuration
 * @engine:	compression or decompression engine to be selected
 * @priority:	Priority for the DCE hardware processing (valid values 1-8).
 */
struct dpdcei_cfg {
	enum dpdcei_engine engine;
	uint8_t priority;
};

int dpdcei_create(struct fsl_mc_io *mc_io,
		  uint16_t dprc_token,
		  uint32_t cmd_flags,
		  const struct dpdcei_cfg *cfg,
		  uint32_t *obj_id);

int dpdcei_destroy(struct fsl_mc_io *mc_io,
		   uint16_t dprc_token,
		   uint32_t cmd_flags,
		   uint32_t object_id);

int dpdcei_enable(struct fsl_mc_io *mc_io,
		  uint32_t cmd_flags,
		  uint16_t token);

int dpdcei_disable(struct fsl_mc_io *mc_io,
		   uint32_t cmd_flags,
		   uint16_t token);

int dpdcei_is_enabled(struct fsl_mc_io *mc_io,
		      uint32_t cmd_flags,
		      uint16_t token,
		      int *en);

int dpdcei_reset(struct fsl_mc_io *mc_io,
		 uint32_t cmd_flags,
		 uint16_t token);

int dpdcei_set_irq_enable(struct fsl_mc_io *mc_io,
			  uint32_t cmd_flags,
			  uint16_t token,
			  uint8_t irq_index,
			  uint8_t en);

int dpdcei_get_irq_enable(struct fsl_mc_io *mc_io,
			  uint32_t cmd_flags,
			  uint16_t token,
			  uint8_t irq_index,
			  uint8_t *en);

int dpdcei_set_irq_mask(struct fsl_mc_io *mc_io,
			uint32_t cmd_flags,
			uint16_t token,
			uint8_t irq_index,
			uint32_t mask);

int dpdcei_get_irq_mask(struct fsl_mc_io *mc_io,
			uint32_t cmd_flags,
			uint16_t token,
			uint8_t irq_index,
			uint32_t *mask);

int dpdcei_get_irq_status(struct fsl_mc_io *mc_io,
			  uint32_t cmd_flags,
			  uint16_t token,
			  uint8_t irq_index,
			  uint32_t *status);

int dpdcei_clear_irq_status(struct fsl_mc_io *mc_io,
			    uint32_t cmd_flags,
			    uint16_t token,
			    uint8_t irq_index,
			    uint32_t status);
/**
 * struct dpdcei_attr - Structure representing DPDCEI attributes
 * @id:		DPDCEI object ID
 * @engine:	DCE engine block
 */
struct dpdcei_attr {
	int id;
	enum dpdcei_engine engine;
};

int dpdcei_get_attributes(struct fsl_mc_io *mc_io,
			  uint32_t cmd_flags,
			  uint16_t token,
			  struct dpdcei_attr *attr);

/**
 * enum dpdcei_dest - DPDCEI destination types
 * @DPDCEI_DEST_NONE:	Unassigned destination; The queue is set in parked mode
 *			and does not generate FQDAN notifications;
 *			user is expected to dequeue from the queue based on
 *			polling or other user-defined method
 * @DPDCEI_DEST_DPIO:	The queue is set in schedule mode and generates FQDAN
 *			notifications to the specified DPIO; user is expected to
 *			dequeue from the queue only after notification is
 *			received
 * @DPDCEI_DEST_DPCON:	The queue is set in schedule mode and does not generate
 *			FQDAN notifications, but is connected to the specified
 *			DPCON object;
 *			user is expected to dequeue from the DPCON channel
 */
enum dpdcei_dest {
	DPDCEI_DEST_NONE = 0,
	DPDCEI_DEST_DPIO = 1,
	DPDCEI_DEST_DPCON = 2
};

/**
 * struct dpdcei_dest_cfg - Structure representing DPDCEI destination parameters
 * @dest_type:	Destination type
 * @dest_id:	Either DPIO ID or DPCON ID, depending on the destination type
 * @priority:	Priority selection within the DPIO or DPCON channel;
 *		Valid values are 0-1 or 0-7, depending on the number of
 *		priorities in that channel; not relevant for
 *		'DPDCEI_DEST_NONE' option
 */
struct dpdcei_dest_cfg {
	enum dpdcei_dest dest_type;
	int dest_id;
	uint8_t priority;
};

/** DPDCEI queue modification options */

/**
 * Select to modify the user's context associated with the queue
 */
#define DPDCEI_QUEUE_OPT_USER_CTX	0x00000001

/**
 * Select to modify the queue's destination
 */
#define DPDCEI_QUEUE_OPT_DEST		0x00000002

/**
 * struct dpdcei_rx_queue_cfg - RX queue configuration
 * @options:	Flags representing the suggested modifications to the queue;
 *		Use any combination of 'DPDCEI_QUEUE_OPT_<X>' flags
 * @user_ctx:	User context value provided in the frame descriptor of each
 *		dequeued frame; Valid only if 'DPDCEI_QUEUE_OPT_USER_CTX'
 *		is contained in 'options'
 * @dest_cfg:	Queue destination parameters;
 *		Valid only if 'DPDCEI_QUEUE_OPT_DEST' is contained in 'options'
 */
struct dpdcei_rx_queue_cfg {
	uint32_t options;
	uint64_t user_ctx;
	struct dpdcei_dest_cfg dest_cfg;
};

int dpdcei_set_rx_queue(struct fsl_mc_io *mc_io,
			uint32_t cmd_flags,
			uint16_t token,
			const struct dpdcei_rx_queue_cfg *cfg);

/**
 * struct dpdcei_rx_queue_attr - Structure representing attributes of Rx queues
 * @user_ctx:	User context value provided in the frame descriptor of each
 *		dequeued frame
 * @dest_cfg:	Queue destination configuration
 * @fqid:	Virtual FQID value to be used for dequeue operations
 */
struct dpdcei_rx_queue_attr {
	uint64_t user_ctx;
	struct dpdcei_dest_cfg dest_cfg;
	uint32_t fqid;
};

int dpdcei_get_rx_queue(struct fsl_mc_io *mc_io,
			uint32_t cmd_flags,
			uint16_t token,
			struct dpdcei_rx_queue_attr *attr);

/**
 * struct dpdcei_tx_queue_attr - Structure representing attributes of Tx queues
 * @fqid:	Virtual FQID to be used for sending frames to DCE hardware
 */
struct dpdcei_tx_queue_attr {
	uint32_t fqid;
};

int dpdcei_get_tx_queue(struct fsl_mc_io *mc_io,
			uint32_t cmd_flags,
			uint16_t token,
			struct dpdcei_tx_queue_attr *attr);

int dpdcei_get_api_version(struct fsl_mc_io *mc_io,
			   uint32_t cmd_flags,
			   uint16_t *major_ver,
			   uint16_t *minor_ver);

#endif /* __FSL_DPDCEI_H */
