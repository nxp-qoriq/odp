/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/*!
 * @file	dpaa2_dev_intr_priv.c
 *
 * @brief	DPAA2 interrupt event module private API's.
 *
 */

/* System Header Files */
#include<sys/eventfd.h>

/* DPAA2 header files */
#include <dpaa2_dev_intr_priv.h>

#define IRQ_SET_BUF_LEN  (sizeof(struct vfio_irq_set) + sizeof(int))

int dpaa2_get_interrupt_info(int dev_vfio_fd,
		struct vfio_device_info *device_info,
		struct dpaa2_intr_handle **intr_handle)
{
	struct vfio_irq_info irq_info = { .argsz = sizeof(irq_info) };
	uint32_t i;
	int ret;

/* TODO - Change NOTIFIER to EVENT at all the places */
	DPAA2_TRACE(NOTIFIER);

	if (device_info->num_irqs == 0) {
		DPAA2_INFO(NOTIFIER, "No IRQ for device fd: %d", dev_vfio_fd);
		return DPAA2_SUCCESS;
	}

	*intr_handle = dpaa2_calloc(NULL, device_info->num_irqs,
		sizeof(struct dpaa2_intr_handle), 0);

	/* Get the IRQ INFO from VFIO for all the interrupts */
	for (i = 0; i < device_info->num_irqs; i++) {
		irq_info.index = i;
		ret = ioctl(dev_vfio_fd, VFIO_DEVICE_GET_IRQ_INFO, &irq_info);
		if (ret < 0) {
			DPAA2_ERR(NOTIFIER, "Failed to get IRQ info from VFIO, "
				"ret code: %d", ret);
			dpaa2_free(*intr_handle);
			return DPAA2_FAILURE;
		}

		/* Set the dpaa2_intr_handle */
		(*intr_handle[i]).fd = 0;
		(*intr_handle[i]).flags = irq_info.flags;
	}

	return DPAA2_SUCCESS;
}


int dpaa2_register_interrupt(int dev_vfio_fd,
		struct dpaa2_intr_handle *intr_handle,
		uint32_t index)
{
	struct vfio_irq_set *irq_set;
	char irq_set_buf[IRQ_SET_BUF_LEN];
	int *fd_ptr, ret;
	int fd;

	DPAA2_TRACE(NOTIFIER);

	if (intr_handle->flags & DPAA2_INTR_REGISTERED) {
		DPAA2_INFO(NOTIFIER, "Interrupt already registered");
		return DPAA2_SUCCESS;
	}

	/* Prepare vfio_irq_set structure and SET the IRQ in VFIO */
	/* Give the eventfd to VFIO */
	fd = eventfd(0, 0);
	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = sizeof(irq_set_buf);
	irq_set->count = 1;
	irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = index;
	irq_set->start = 0;
	fd_ptr = (int *)&irq_set->data;
	*fd_ptr = fd;

	ret = ioctl(dev_vfio_fd, VFIO_DEVICE_SET_IRQS, irq_set);
	if (ret < 0) {
		DPAA2_ERR(NOTIFIER, "Unable to set IRQ in VFIO, ret code: %d",
			ret);
		return DPAA2_FAILURE;
	}

	/* Set the FD and update the flags */
	intr_handle->fd = fd;
	intr_handle->flags |= DPAA2_INTR_REGISTERED;
	return DPAA2_SUCCESS;
}


int dpaa2_enable_interrupt(int dev_vfio_fd,
		struct dpaa2_intr_handle *intr_handle,
		uint32_t index)
{
	struct vfio_irq_set *irq_set;
	char irq_set_buf[IRQ_SET_BUF_LEN];
	int *data_ptr, ret;

	DPAA2_TRACE(NOTIFIER);

	/* Prepare vfio_irq_set structure to enable the interrupt
	   and SET the IRQ in VFIO */
	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = sizeof(irq_set_buf);
	irq_set->count = 1;
	irq_set->flags = VFIO_IRQ_SET_ACTION_UNMASK | VFIO_IRQ_SET_DATA_BOOL;
	irq_set->index = index;
	irq_set->start = 0;
	data_ptr = (int *)&irq_set->data;
	*data_ptr = 1;

	ret = ioctl(dev_vfio_fd, VFIO_DEVICE_SET_IRQS, irq_set);
	if (ret < 0) {
		DPAA2_ERR(NOTIFIER, "Unable to set IRQ in VFIO, ret code: %d",
			ret);
		return DPAA2_FAILURE;
	}
	/* Update the flag in our structure */
	intr_handle->flags |= DPAA2_INTR_ENABLED;

	return DPAA2_SUCCESS;
}

int dpaa2_disable_interrupt(int dev_vfio_fd,
		struct dpaa2_intr_handle *intr_handle,
		uint32_t index)
{
	struct vfio_irq_set *irq_set;
	char irq_set_buf[IRQ_SET_BUF_LEN];
	int *data_ptr, ret;

	DPAA2_TRACE(NOTIFIER);

	/* Prepare vfio_irq_set structure to disable the interrupt
	   and SET the IRQ in VFIO */
	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = sizeof(irq_set_buf);
	irq_set->count = 1;
	irq_set->flags = VFIO_IRQ_SET_ACTION_MASK | VFIO_IRQ_SET_DATA_BOOL;
	irq_set->index = index;
	irq_set->start = 0;
	data_ptr = (int *)&irq_set->data;
	*data_ptr = 1;

	ret = ioctl(dev_vfio_fd, VFIO_DEVICE_SET_IRQS, irq_set);
	if (ret < 0) {
		DPAA2_ERR(NOTIFIER, "Unable to set IRQ in VFIO, ret code: %d",
			ret);
		return DPAA2_FAILURE;
	}
	/* Update the flag in our structure */
	intr_handle->flags &= ~DPAA2_INTR_ENABLED;

	return DPAA2_SUCCESS;
}
