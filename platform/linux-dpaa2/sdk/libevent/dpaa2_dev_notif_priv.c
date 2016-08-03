/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/*!
 * @file	dpaa2_dev_notif_priv.c
 *
 * @brief	DPAA2 event notifier module private API's
 *
 */

/* DPAA2 Header files */
#include <sys/eventfd.h>
#include <dpaa2_queue.h>
#include <dpaa2_dev.h>
#include <dpaa2_dev_notif.h>
#include <dpaa2_dev_notif_priv.h>

struct notif_cnxt_list g_notif_cnxt_list;

int dpaa2_notif_init(void)
{
	DPAA2_TRACE(NOTIFIER);

	/* Initialize the Notifier context List */
	TAILQ_INIT(&g_notif_cnxt_list);

	return DPAA2_SUCCESS;
}


int dpaa2_reg_with_notifier(
		uint64_t user_context,
		dpaa2_notification_callback_t cb,
		int *efd,
		uint64_t *notifier_context)
{
	struct notif_cnxt *new_notif_cnxt = malloc(sizeof(struct notif_cnxt));

	DPAA2_TRACE(NOTIFIER);

	if (!new_notif_cnxt) {
		DPAA2_ERR(NOTIFIER, "Memory unavailable");
		return -ENOMEM;
	}

	new_notif_cnxt->user_cnxt = user_context;
	if (cb) {
		new_notif_cnxt->cb = cb;
	} else {
		/* Add a new link to the g_dev_vq */
		new_notif_cnxt->eventfd = eventfd(0, 0);
		if (new_notif_cnxt->eventfd == -1) {
			DPAA2_ERR(NOTIFIER, "Unable to create eventfd");
			free(new_notif_cnxt);
			return DPAA2_FAILURE;
		}
		if (!new_notif_cnxt->user_cnxt)
			new_notif_cnxt->user_cnxt = DEFAULT_USER_CONTEXT;
	}

	/* Add to the dev-vq List */
	TAILQ_INSERT_HEAD(&g_notif_cnxt_list, new_notif_cnxt, next);

	*efd = new_notif_cnxt->eventfd;
	*notifier_context = (uint64_t)(new_notif_cnxt);
	return DPAA2_SUCCESS;
}


void dpaa2_notif_close(void)
{
	struct notif_cnxt *p_notif_cnxt, *p_temp_notif_cnxt;

	DPAA2_TRACE(NOTIFIER);

	p_notif_cnxt = TAILQ_FIRST(&g_notif_cnxt_list);
	while (p_notif_cnxt) {
		p_temp_notif_cnxt = TAILQ_NEXT(p_notif_cnxt, next);
		dpaa2_free(p_notif_cnxt);
		p_notif_cnxt = p_temp_notif_cnxt;
	}

}
