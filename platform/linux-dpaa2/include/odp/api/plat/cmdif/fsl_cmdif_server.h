/*
 * Copyright 2013-2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 */

/**
 * @file
 *
 * AIOP to GPP cmdif API. API to be used by GPP Server.
 */

#ifndef __FSL_CMDIF_SERVER_H
#define __FSL_CMDIF_SERVER_H

/** @addtogroup odpfsl_cmdif ODPFSL CMDIF
 *  @{
 */

#define CMDIF_SESSION_OPEN_SIZE		64
/**< cmdif_session_open() default size */

struct cmdif_desc;

/**************************************************************************//**
Open callback
User provides this function.
Server invokes it when it gets open instance command.

@param[in]	instance_id - Instance id to be specified by client
		on cmdif_open().
@param[out]	dev         - device handle.

@return		Handle to instance object, or NULL for Failure.
 *//***************************************************************************/
typedef int (open_cb_t)(uint8_t instance_id, void **dev);

/**************************************************************************//**
De-init callback
User provides this function.
Driver invokes it when it gets close instance command.

@param[in]	dev - A handle of the device.

@return		0 on success; error code, otherwise.
 *//***************************************************************************/
typedef int (close_cb_t)(void *dev);

/**************************************************************************//**
Control callback
User provides this function. Driver invokes it for all runtime commands

@param[in]	dev -  A handle of the device which was returned after
		module open callback
@param[in]	cmd -  Id of command
@param[in]	size - Size of the data.
		On the AIOP side use PRC_GET_SEGMENT_LENGTH() to determine the
		size of presented data.
@param[in]	data - Data of the command.
		AIOP server will pass here address to the start of presentation
		segment - physical address is the same as virtual.
		On AIOP use fdma_modify_default_segment_data() if needed.
		On GPP, it should be virtual address that belongs
		to current SW context.
@return		0 on success; error code, otherwise.
 *//***************************************************************************/
typedef int (ctrl_cb_t)(void *dev, uint16_t cmd, uint32_t size, void *data);

/**************************************************************************//**
Function pointers to be supplied during module registration
 *//***************************************************************************/
struct cmdif_module_ops {
	open_cb_t  *open_cb;
	/**< Open callback to be activated after client calls cmdif_open() */
	close_cb_t *close_cb;
	/**< Close callback to be activated after client calls cmdif_close() */
	ctrl_cb_t  *ctrl_cb;
	/**< Control callback to be activated on each command */
};

/**************************************************************************//**
Registration of a module to the server.
For AIOP, use this API during AIOP boot.
Each module needs to register to the command interface by
supplying the following:

@param[in]	module_name - Module name, it should be a valid string of
		up to 8 characters.
@param[in]	ops -         A structure with 3 callbacks described above
		for open, close and control
@return		0 on success; error code, otherwise.
 *//***************************************************************************/
int cmdif_register_module(const char *module_name,
			struct cmdif_module_ops *ops);

/**************************************************************************//**
Cancel the registration of a module on the server and free the module id
acquired during registration.
For AIOP, use this API during AIOP boot.

@param[in]	module_name - Module name, up to 8 characters.

@return		0 on success; error code, otherwise.
 *//***************************************************************************/
int cmdif_unregister_module(const char *module_name);

/**************************************************************************//**
Open session on server and notify client about it.
This functionality is relevant only for GPP.

@param[in]	cidesc   - Already open connection descriptor towards the
		second side
@param[in]	m_name   - Name of the module as registered
		by cmdif_register_module()
@param[in]	inst_id  - Instance id which will be passed to #open_cb_t
@param[in]	size     - Size of v_data buffer.
		By default, set it to #CMDIF_SESSION_OPEN_SIZE bytes.
@param[in]	v_data   - 8 byte aligned buffer allocated by user. If not NULL
		this buffer will carry all the information of this session.
		The buffer can be freed after cmdif_session_close().
@param[in]	send_dev - Transport device to be used for server (ODP device).
		Device used for send and receive of frame descriptor.
@param[out]	auth_id  - Session id as returned by server.

@return		0 on success; error code, otherwise.
 *//***************************************************************************/
int cmdif_session_open(struct cmdif_desc *cidesc,
		const char *m_name,
		uint8_t inst_id,
		uint32_t size,
		void *v_data,
		void *send_dev,
		uint16_t *auth_id);

/**************************************************************************//**
Close session on server and notify client about it.
This functionality is relevant only for GPP but it's not yet supported
by the GPP server.

@param[in]	cidesc   - Already open connection descriptor towards
		second side
@param[in]	size     - Size of v_data buffer
@param[in]	auth_id  - Session id as returned by server.
@param[in]	v_data   - Buffer allocated by user. If not NULL this buffer
		will carry all the information of this session.
@param[in]	send_dev - Transport device used for server (ODP device).
		Device used for send and receive of frame descriptor.

@return		0 on success; error code, otherwise.
 *//***************************************************************************/
int cmdif_session_close(struct cmdif_desc *cidesc,
			uint16_t auth_id,
			uint32_t size,
			void *v_data,
			void *send_dev);

/**************************************************************************//**
Server callback to be called on every frame command.
This functionality is relevant only for GPP.

@param[in]	pr       - Priority
@param[in]	send_dev - Device used for send and receive of frame descriptor

@return		0 on success; error code, otherwise.
 *//***************************************************************************/
int cmdif_srv_cb(int pr, void *send_dev);

/**
 * @}
 */

#endif /* __FSL_CMDIF_SERVER_H */
