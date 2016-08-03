/*
 * Copyright (c) 2014-2015 Freescale Semiconductor, Inc. All rights reserved.
 */

#include <stdlib.h>
#include <errno.h>
#include <odp/api/std_types.h>
#include <dpaa2_mpool.h>
#include <odp/api/atomic.h>
#include <dpaa2_aiop.h>
#include <dpaa2_aiop_priv.h>
#include <dpaa2_log.h>
#include <dpaa2_time.h>
#include <fsl_cmdif_flib_s.h>
#include <fsl_cmdif_client.h>
#include <string.h>
#include <cmdif.h>

/*
 * This is server handle. it is set using cmdif_srv_allocate().
 */
void *srv;
odp_atomic_u16_t module_count;

static int gpp_cmdif_srv_init(void)
{
	int     err = 0;

	srv = cmdif_srv_allocate((void * (*)(int))(malloc),
		(void * (*)(int))(malloc));
	if (srv == NULL)
		return -ENOMEM;

	/* TODO add anything else you might need for server */
	return err;
}

static void gpp_cmdif_srv_free(void)
{
	cmdif_srv_deallocate(srv, free);

	/* TODO add anything else you might need for server */
}

int cmdif_register_module(const char *m_name, struct cmdif_module_ops *ops)
{
	int ret;

	/* Place here lock if required */

	if (odp_atomic_add_fetch_u16(&module_count, 1) == 1) {
		ret = gpp_cmdif_srv_init();
		if (ret != 0) {
			DPAA2_ERR(CMD, "CMDIF server Initalization failed");
			return ret;
		}

		ret = cmdif_srv_register(srv, m_name, ops);
		if (ret != 0)
			gpp_cmdif_srv_free();
		return ret;
	}

	return cmdif_srv_register(srv, m_name, ops);
}

int cmdif_unregister_module(const char *m_name)
{
	int ret;

	/* Place here lock if required */

	ret = cmdif_srv_unregister(srv, m_name);

	if (odp_atomic_sub_fetch_u16(&module_count, 1) == 0)
		gpp_cmdif_srv_free();

	return ret;
}

int cmdif_srv_cb(int pr, void *send_dev)
{
	int     err = 0;
	struct  cmdif_fd cfd_out;
	struct  cmdif_fd cfd;
	uint8_t send_resp = 0;
	int pkt_rcvd;

	if (srv == NULL)
		return -ENODEV;

	pkt_rcvd = receive_fd(&cfd, pr, send_dev);
	if (pkt_rcvd < 0) {
		DPAA2_ERR(APP1, "Error calling receive_fd");
		return DPAA2_FAILURE;
	}

	if (pkt_rcvd == 0)
		return -ENODATA;

	/* Call ctrl cb; if no perm cfd_out will be invalid */
	err = cmdif_srv_cmd(srv, &cfd, 0, &cfd_out, &send_resp);
	/* don't bother to send response in order not to overload
	 * response queue, it might be intentional attack */
	if (err) {
		if (err == -EPERM)
			DPAA2_ERR(CMD, "Got command with invalid auth_id");
		else if (err == -EINVAL)
			DPAA2_ERR(CMD, "Invalid parameters for cmdif_srv_cmd");
		return err;
	}
	if (send_resp)
		err = send_fd(&cfd_out, pr, send_dev);

	return err;
}

int cmdif_session_open(struct cmdif_desc *cidesc,
		const char *m_name,
		uint8_t inst_id,
		uint32_t size,
		void *v_data,
		void *send_dev,
		uint16_t *auth_id)
{
	int      err = 0;
	uint32_t dpci_id = get_aiop_dev_id((struct dpaa2_dev *)(send_dev));

	/* Place here lock if required */

	/*Call open_cb , Store dev */
	err = cmdif_srv_open(srv, m_name, inst_id, dpci_id, size, v_data,
			auth_id);
	if (err)
		return err;

	/*Send information to AIOP */
	err = cmdif_send(cidesc, CMD_ID_NOTIFY_OPEN, size, CMDIF_PRI_LOW,
			(uint64_t)(v_data), NULL, NULL);

	return err;
}

int cmdif_session_close(struct cmdif_desc *cidesc,
			uint16_t auth_id,
			uint32_t size,
			void *v_data,
			void *send_dev)
{
	int      err = 0;
	uint32_t dpci_id = get_aiop_dev_id((struct dpaa2_dev *)(send_dev));

	/* Place here lock if required */

	/*Call close_cb , place dpci_id, auth_id inside p_data */
	err = cmdif_srv_close(srv, auth_id, dpci_id, size, v_data);
	if (err)
		return err;

	/*Send information to AIOP */
	err = cmdif_send(cidesc, CMD_ID_NOTIFY_CLOSE, size, CMDIF_PRI_LOW,
			(uint64_t)(v_data), NULL, NULL);

	return err;
}
