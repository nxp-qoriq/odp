/**************************************************************************//**
Copyright 2013-2015 Freescale Semiconductor, Inc. All rights reserved.

@File          fsl_cmdif_client.h

@Description   AIOP to GPP cmdif API. API to be used by GPP Client.
 *//***************************************************************************/

#ifndef __FSL_CMDIF_CLIENT_H
#define __FSL_CMDIF_CLIENT_H

/*!
 * @addtogroup DPAA2_CMDIF_CLIENT
 * @ingroup DPAA2_DEV
 * @{
 */

#define CMDIF_PRI_LOW		0	/**< Low Priority */
#define CMDIF_PRI_HIGH		1	/**< High Priority */

#define CMDIF_ASYNC_CMD		0x2000
/**< Bit to be used for cmd_id to identify asynchronous commands */
#define CMDIF_NORESP_CMD	0x1000
/**< Bit to be used for commands that don't need response */



#define CMDIF_OPEN_SIZE		64  /**< cmdif_open() default size */

/**************************************************************************//**
@Description   Command interface descriptor.
*//***************************************************************************/
struct cmdif_desc {
	void *regs;
	/*!<
	 * Pointer to transport layer device for sending commands;
	 * On GPP the user should pass DPAA2 device
	 * On AIOP the user should pass dpci_id as known by GPP SW context
	 * Must be set by the user
	 */
	void *dev;
	/*!<
	 * Opaque handle for the use of the command interface;
	 * user should not modify it.
	 */
};

/**************************************************************************//**
@Description	Command callback

User provides this function. Driver invokes it for all asynchronous commands
that had been sent through cidesc.

@Param[in]	async_ctx   User context that was setup during cmdif_open()
@Param[in]	err         Error as returned by server
@Param[in]	cmd_id      Id of command
@Param[in]	size        Size of the data.
		On the AIOP side use PRC_GET_SEGMENT_LENGTH() to determine the
		size of presented data.
@Param[in]	data        Data of the command.
		On the AIOP side it is the pointer to segment presentation
		address; use fdma_modify_default_segment_data() if needed.
		On GPP side it should be virtual address that belongs
		to current SW context.
@Return		DPAA2_SUCCESS on success; error code, otherwise.
@Cautions	Please make sure to modify only size bytes of the data.
		Automatic expansion of the buffer is not available.
 *//***************************************************************************/
typedef int (cmdif_cb_t)(void *async_ctx,
			int err,
			uint16_t cmd_id,
			uint32_t size,
			void *data);

/**************************************************************************//**
@Function	cmdif_open

@Description	Open command interface device for the specified module

@Param[in]	cidesc		Command interface descriptor, cmdif device will
		be returned inside this descriptor.
		Sharing of the same cidesc by multiple threads requires locks
		outside CMDIF API, as an alternative each thread can open it's
		own session by calling cmdif_open().
		Only cidesc.regs must be set by user see struct cmdif_desc.
@Param[in]	module_name	Module name, up to 8 characters.
@Param[in]	instance_id	Instance id which will be passed to #open_cb_t
@Param[in]	data		8 bytes aligned buffer for internal use of the
		command interface.
		This address should be accessible by Server and Client.
		This buffer can be freed only after cmdif_close().
		On AIOP, set data as NULL.
@Param[in]	size		Size of the data buffer. If the size is not
				enough cmdif_open() will return -ENOMEM.
				By default, set it to #CMDIF_OPEN_SIZE bytes.

@Return		DPAA2_SUCCESS on success; error code, otherwise.
 *//***************************************************************************/
int cmdif_open(struct cmdif_desc *cidesc,
		const char *module_name,
		uint8_t instance_id,
		void *data,
		uint32_t size);

/**************************************************************************//**
@Function	cmdif_close

@Description	Close this command interface device and free this instance entry
		on the Server.

It's not yet supported by the AIOP client.

@Param[in]	cidesc   Command interface descriptor which was setup by
		cmdif_open().

@Return		DPAA2_SUCCESS on success; error code, otherwise.
 *//***************************************************************************/
int cmdif_close(struct cmdif_desc *cidesc);

/**************************************************************************//**
@Function	cmdif_send

@Description	Send command to the module device that was created during
		cmdif_open().

		This function may be activated in synchronous and asynchronous
		mode.

@Param[in]	cidesc     Command interface descriptor which was setup by
		cmdif_open().
@Param[in]	cmd_id     Id which represent command on the module that was
		registered on Server; Application may use bits 11-0.
@Param[in]	size       Size of the data including extra 16 bytes for
		cmdif_cb_t in case of CMDIF_ASYNC_CMD.
@Param[in]	priority   High or low priority queue.
@Param[in]	data       Data of the command or buffer allocated by user which
		will be used inside command.
		This address should be accessible by Server and Client.
		It should be virtual address that belongs to current SW context.
		In case of asynchronous command last 16 bytes must be reserved
		for cmdif usage.
		On GPP it must be from Write-Back Cacheable and
		Outer Shareable memory.
@Param[in]	async_cb	Callback to be called on response of
		asynchronous command.
@Param[in]	async_ctx	Context to be received with asynchronous
		command response inside async_cb().

@Return		DPAA2_SUCCESS on success; error code, otherwise.
 *//***************************************************************************/
int cmdif_send(struct cmdif_desc *cidesc,
		uint16_t cmd_id,
		uint32_t size,
		int priority,
		uint64_t data,
		cmdif_cb_t *async_cb,
		void *async_ctx);

/**************************************************************************//**
@Function	cmdif_resp_read

@Description	Check the response queue for new responses,
		de-queue and activate the callback function for each response

This function is not blocking; if nothing was found it will return error code.
Note, this functionality is not relevant for AIOP client.

@Param[in]	cidesc   Command interface descriptor which was setup by
		cmdif_open().
@Param[in]	priority  High or low priority queue to be checked.

@Return		DPAA2_SUCCESS on success;
		error code, if no responses have been found.
 *//***************************************************************************/
int cmdif_resp_read(struct cmdif_desc *cidesc, int priority);

/*! @} */

#endif /* __FSL_CMDIF_CLIENT_H */
