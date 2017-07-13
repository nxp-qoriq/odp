/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/*!
 * @file dpaa2_dev_notif.c
 *
 * @brief	DPAA2 notifier module. Using this module user can receive
 *	notifications to know that a packet is received on a particular
 *	queue of a device
 *
 */

/* System Header Files */
#include <sys/epoll.h>

/* DPAA2 header files */
#include <dpaa2_dev_priv.h>
#include <dpaa2_mbuf_priv.h>
#include <dpaa2_io_portal_priv.h>
#include <dpaa2_dev_notif_priv.h>
#include <dpaa2_dev_notif.h>

/* QBMAN header files */
#include <fsl_qbman_portal.h>

int dpaa2_dev_process_notifications(int timeout)
{
	struct qbman_swp *swp = notif_dpio->sw_portal;
	const struct qbman_result *dqrr_entry;
	struct notif_cnxt *notifier_context;
	uint64_t user_context;
	struct epoll_event events[1];
	int nfds = 0;
	uint32_t status;
	ssize_t nbytes;

	DPAA2_TRACE(NOTIFIER);

	nfds = epoll_wait(notif_dpio_epollfd, events, 1, timeout);
	/* epoll returned error */
	if (nfds < 0) {
		DPAA2_ERR(NOTIFIER, "epoll_wait returns with fail");
		return DPAA2_FAILURE;
	} else if (nfds == 0) {
		/* epoll_wait timeout */
		return DPAA2_SUCCESS;
	}

	status = qbman_swp_interrupt_read_status(swp);
	if (!status)
		return DPAA2_FAILURE;

	/* Overloading user_context to read dummy value */
	nbytes = read(notif_dpio->intr_handle[VFIO_DPIO_DATA_IRQ_INDEX].fd,
		&user_context, sizeof(uint64_t));
	if (!nbytes)
		return DPAA2_FAILURE;

	/* Recieve the Notifications */
	while (TRUE) {
		dqrr_entry = qbman_swp_dqrr_next(swp);
		if (!dqrr_entry) {
			DPAA2_INFO(NOTIFIER, "No FQDAN/CDAN delivered");
			break;
		}
		/* Check if FQDAN/CDAN is received */
		if (!qbman_result_is_FQDAN(dqrr_entry) &&
			!qbman_result_is_CDAN(dqrr_entry)) {
			qbman_swp_dqrr_consume(swp, dqrr_entry);
			DPAA2_INFO(NOTIFIER, "No FQDAN/CDAN delivered");
			break;
		}
		/* Get the CNTX from the FQDAN/CDAN */
		notifier_context = (struct notif_cnxt *)
				qbman_result_SCN_ctx(dqrr_entry);
		user_context = notifier_context->user_cnxt;
		if (notifier_context->cb) {
			notifier_context->cb(user_context);
		} else {
			nbytes = write(notifier_context->eventfd,
				&user_context, sizeof(uint64_t));
			if (!nbytes)
				DPAA2_WARN(NOTIFIER, "No Info is written to event FD\n ");
		}

		/* Consume the entry. */
		qbman_swp_dqrr_consume(swp, dqrr_entry);
		DPAA2_INFO(NOTIFIER, "Notification received");
	}

	/* Clear the status and mark it as non-inhibitted to
	 * re-enable the interrupt on the portal */
	qbman_swp_interrupt_clear_status(swp, status);
	qbman_swp_interrupt_set_inhibit(swp, 0);
	return DPAA2_SUCCESS;
}

int dpaa2_dev_vq_enable_notifications(
		struct dpaa2_dev *dev,
		void *vq)
{
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	int id = dev_priv->fn_get_vqid(vq);

	DPAA2_TRACE(NOTIFIER);

	if (dev->dev_type != DPAA2_CONC)
		return qbman_swp_fq_schedule(
			thread_io_info.dpio_dev->sw_portal, id);
	else
		return qbman_swp_CDAN_enable(
			thread_io_info.dpio_dev->sw_portal, id);

	return DPAA2_SUCCESS;
}
