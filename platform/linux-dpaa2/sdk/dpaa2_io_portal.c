/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 *
 */

/*!
 * @file	dpaa2_io_portal_ldpaa.c
 *
 * @brief	Data Path I/O portal driver implementation. It contains initialization of
 *		Input/Output context required for DPAA2 device framework based application.
 *
 */

/* System Header Files */
#include <sys/epoll.h>

/*DPAA2 header files*/
#include "dpaa2_io_portal_priv.h"
#include <dpaa2_internal.h>
#include <dpaa2_vfio.h>

#include <odp/api/cpu.h>

#if defined(BUILD_LS2085) || defined(BUILD_LS2080) || \
	defined(BUILD_LS2088) || defined(BUILD_LS1088)
#define NUM_HOST_CPUS 8
#elif defined(BUILD_LX2160)
#define NUM_HOST_CPUS 16
#endif

#define NUM_DPIO_REGIONS	2
/* DPIO devices list */
struct dpaa2_dpio_device_list *dpio_dev_list; /*!< DPIO device list */
uint32_t io_space_count;

/* The DPIO reserved for notifier */
struct dpaa2_dpio_dev *notif_dpio;
/* The epoll fd to be used for epolling on the notifier DPIO */
int notif_dpio_epollfd;

/*!< I/O handle for this thread, for the use of DPAA2 framework.
 * This is duplicated as will be used frequently
 */
__thread struct thread_io_info_t thread_io_info;
static int32_t dpaa2_configure_stashing(void);

struct dpaa2_driver io_p_driver = {
	.name			=	LDPAA_IO_P_NAME,
	.vendor_id		=	LDPAA_IO_P_VENDOR_ID,
	.major			=	LDPAA_IO_P_MAJ_NUM,
	.minor			=	LDPAA_IO_P_MIN_NUM,
	.dev_type		=	DPAA2_IO_CNTXT,
	.dev_probe		=	dpaa2_io_portal_probe,
	.dev_shutdown		=	dpaa2_io_portal_close
};

int32_t dpaa2_io_portal_init(void)
{
	/*Register Ethernet driver to DPAA2 device framework*/
	dpaa2_register_driver(&io_p_driver);
	return DPAA2_SUCCESS;
}

int32_t dpaa2_io_portal_exit(void)
{
	/*Unregister Ethernet driver to DPAA2 device framework*/
	dpaa2_unregister_driver(&io_p_driver);
	return DPAA2_SUCCESS;
}

static int dpaa2_dpio_intr_init(struct dpaa2_dpio_dev *dpio_dev)
{
	struct epoll_event epoll_ev;
	int eventfd, dpio_epollfd;
	int ret;
	int threshold = 0x3, timeout = 0xFF;

	dpio_epollfd = epoll_create(1);
	ret = dpaa2_register_dpio_interrupt(dpio_dev,
		VFIO_DPIO_DATA_IRQ_INDEX);
	if (ret != DPAA2_SUCCESS) {
		DPAA2_ERR(FW, "Interrupt registeration failed");
		return DPAA2_FAILURE;
	}

	if (getenv("ODP_INTR_THRESHOLD"))
		threshold = atoi(getenv("ODP_INTR_THRESHOLD"));

	if (getenv("ODP_INTR_TIMEOUT"))
		sscanf(getenv("ODP_INTR_TIMEOUT"), "%x", &timeout);

	qbman_swp_interrupt_set_trigger(dpio_dev->sw_portal,
		QBMAN_SWP_INTERRUPT_DQRI);
	qbman_swp_interrupt_clear_status(dpio_dev->sw_portal,
		0xffffffff);
	qbman_swp_interrupt_set_inhibit(dpio_dev->sw_portal, 0);
	qbman_swp_dqrr_thrshld_write(dpio_dev->sw_portal, threshold);
	qbman_swp_intr_timeout_write(dpio_dev->sw_portal, timeout);
	DPAA2_DBG(DPIO, "DPIO_ID = %d, INTR: DQRR Threshold value =%d\n",
			dpio_dev->hw_id, qbman_swp_dqrr_thrshld_read_status(dpio_dev->sw_portal));
	DPAA2_DBG(DPIO, "DPIO_ID = %d, INTR: Timeout value =        %d\n", dpio_dev->hw_id,
			qbman_swp_intr_timeout_read_status(dpio_dev->sw_portal));

	eventfd = dpio_dev->intr_handle[VFIO_DPIO_DATA_IRQ_INDEX].fd;
	epoll_ev.events = EPOLLIN | EPOLLPRI | EPOLLET;
	epoll_ev.data.fd = eventfd;

	ret = epoll_ctl(dpio_epollfd, EPOLL_CTL_ADD, eventfd, &epoll_ev);
	if (ret < 0) {
		DPAA2_ERR(FW, "epoll_ctl failed");
		return DPAA2_FAILURE;
	}
	dpio_dev->intr_handle[VFIO_DPIO_DATA_IRQ_INDEX].poll_fd = dpio_epollfd;

	return DPAA2_SUCCESS;
}

/* Initializer funciton for DPIO device */
int32_t dpaa2_io_portal_probe(ODP_UNUSED struct dpaa2_dev *dev,
			const void *data)
{
	/* Probe function is responsible to initialize the DPIO devices.
	 * It does followings
	 * 1. Open & Enable the DPIO device
	 * 2. Allocated required resources.
	 */
	struct vfio_region_info reg_info = {
					.argsz = sizeof(reg_info) };
	struct dpaa2_dpio_dev *dpio_dev;
	const struct dpaa2_dev_priv *dev_priv = (const struct dpaa2_dev_priv *) data;
	struct vfio_device_info *obj_info =
		(struct vfio_device_info *)dev_priv->drv_priv;
	struct qbman_swp_desc p_des;
	struct dpio_attr attr;

	if (obj_info->num_regions < NUM_DPIO_REGIONS) {
		DPAA2_ERR(FW, "ERROR, Not sufficient number "
					"of DPIO regions.\n");
		return DPAA2_FAILURE;
	}

	DPAA2_INFO(FW, "Initializing DPIO DEVICE.\n");
	/* Allocate Device List first, If not already done */
	if (!dpio_dev_list) {
		dpio_dev_list = dpaa2_malloc(NULL,
				sizeof(struct dpaa2_dpio_device_list));
		if (NULL == dpio_dev_list) {
			DPAA2_ERR(FW, "ERROR, No Memory for DPIO list\n");
			return DPAA2_FAILURE;
		}
		/* Initialize the DPIO List */
		TAILQ_INIT(dpio_dev_list);
	}
	/* Allocate DPIO device object */
	dpio_dev = dpaa2_calloc(NULL, 1, sizeof(struct dpaa2_dpio_dev), 0);
	if (!dpio_dev) {
		DPAA2_ERR(FW, "ERROR, No Memory for DPIO Device\n");
		return DPAA2_FAILURE;
	}
	DPAA2_INFO(FW, "\t Allocated DPIO [%p]\n", dpio_dev);
	dpio_dev->dpio = NULL;
	dpio_dev->vfio_fd = dev_priv->vfio_fd;
	dpio_dev->hw_id = dev_priv->hw_id;
	memset(&dpio_dev->ch_idx, DPAA2_INVALID_CHANNEL_IDX, sizeof(uint8_t) * MAX_SCHED_GRPS);
	odp_atomic_init_u16(&dpio_dev->ref_count);
	/* Using single portal  for all devices */
	dpio_dev->mc_portal = dev_priv->mc_portal;

	DPAA2_INFO(FW, "\t MC_portal [%p]\n", dpio_dev->mc_portal);
	LOCK_INIT(dpio_dev->lock, NULL);
	/* Get SW portals regions */
	reg_info.index = 0;
	if (ioctl(dpio_dev->vfio_fd, VFIO_DEVICE_GET_REGION_INFO,
							&reg_info)) {
		DPAA2_ERR(FW, "VFIO_DEVICE_FSL_MC_GET_REGION_INFO failed\n");
		goto free_dpio;
	}
	DPAA2_INFO(FW, "\t CE Region Offset = %llx\n", reg_info.offset);
	DPAA2_INFO(FW, "\t CE Region Size = %llx\n", reg_info.size);
	dpio_dev->ce_size = reg_info.size;
	dpio_dev->qbman_portal_ce_paddr = (uint64_t)mmap(NULL, reg_info.size,
				PROT_WRITE | PROT_READ, MAP_SHARED,
				dpio_dev->vfio_fd, reg_info.offset);

#if defined(BUILD_LS2085) || defined(BUILD_LS2080)
	/* Create Mapping for QBMan Cache Enabled area. This is a fix for
	   SMMU fault for DQRR statshing transaction. */
	if (vfio_dmamap_mem_region(dpio_dev->qbman_portal_ce_paddr,
				reg_info.offset,
				reg_info.size)) {
		DPAA2_ERR(FW, "DMAMAP for Portal CE area failed.\n");
		goto free_dpio;
	}
#endif

	reg_info.index = 1;
	if (ioctl(dpio_dev->vfio_fd, VFIO_DEVICE_GET_REGION_INFO,
					&reg_info)) {
		DPAA2_ERR(FW, "VFIO_DEVICE_FSL_MC_GET_REGION_INFO failed\n");
		goto free_dpio;
	}
	DPAA2_INFO(FW, "\t CI Region Offset = %llx\n", reg_info.offset);
	DPAA2_INFO(FW, "\t CI Region Size = %llx\n", reg_info.size);
	dpio_dev->ci_size = reg_info.size;
	dpio_dev->qbman_portal_ci_paddr =  (uint64_t)mmap(NULL, reg_info.size,
				PROT_WRITE | PROT_READ, MAP_SHARED,
				dpio_dev->vfio_fd, reg_info.offset);

	/* Get the interrupts for DPIO device */
	if (dpaa2_get_interrupt_info(dpio_dev->vfio_fd, obj_info,
		&(dpio_dev->intr_handle)) != DPAA2_SUCCESS) {
		DPAA2_ERR(FW, "Unable to get interrupt information\n");
		goto free_dpio;
	};

	/* Initialize the IO space sw portal */
	dpio_dev->dpio = dpaa2_malloc(NULL, sizeof(struct fsl_mc_io));
	if (!dpio_dev->dpio) {
		DPAA2_ERR(FW, "Memory allocation failure\n");
		goto free_dpio;
	}
	DPAA2_INFO(FW, "\t Allocated  DPIO[%p]\n", dpio_dev->dpio);
	dpio_dev->dpio->regs = dpio_dev->mc_portal;
	if (dpio_open(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->hw_id,
			&(dpio_dev->token))) {
		DPAA2_ERR(FW, "Failed to allocate IO space\n");
		goto free_res;
	}
	if (dpio_enable(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->token)) {
		DPAA2_ERR(FW, "DPIO failed to Enable\n");
		dpio_close(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->token);
		goto free_res;
	}
	if (dpio_get_attributes(dpio_dev->dpio, CMD_PRI_LOW,
			dpio_dev->token, &attr)) {
		DPAA2_ERR(FW, "DPIO Get attribute failed\n");
		dpio_disable(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->token);
		dpio_close(dpio_dev->dpio, CMD_PRI_LOW,  dpio_dev->token);
		goto free_res;
	}
	/* The following condition must not be TRUE */
	if (dpio_dev->hw_id != attr.id)
		DPAA2_WARN(FW, "DPIO IDs are different. VFIO vs MC API\n");

	DPAA2_INFO(FW, "DPIO ID %d\n", attr.id);
	DPAA2_INFO(FW, "Qbman Portal ID %d\n", attr.qbman_portal_id);
	DPAA2_INFO(FW, "Portal CE addr 0x%"PRIx64"\n", attr.qbman_portal_ce_offset);
	DPAA2_INFO(FW, "Portal CI addr 0x%"PRIx64"\n", attr.qbman_portal_ci_offset);
	/* Configure & setup SW portal */
	p_des.block = NULL;
	p_des.idx = attr.qbman_portal_id;
	p_des.cena_bar = (void *)(dpio_dev->qbman_portal_ce_paddr);
	p_des.cinh_bar = (void *)(dpio_dev->qbman_portal_ci_paddr);
	p_des.irq = -1;
	DPAA2_INFO(FW, "Portal CE addr 0x%p\n", p_des.cena_bar);
	DPAA2_INFO(FW, "Portal CI addr 0x%p\n", p_des.cinh_bar);
	p_des.qman_version = attr.qbman_version;
	dpio_dev->sw_portal = qbman_swp_init(&p_des);
	if (dpio_dev->sw_portal == NULL) {
		DPAA2_ERR(FW, "QBMan SW Portal Init failed\n");
		dpio_close(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->token);
		goto free_res;
	}
	if ((p_des.qman_version & 0xFFFF0000) < QBMAN_REV_4100)
		dpio_dev->dqrr_size = 4;
	else
		dpio_dev->dqrr_size = 8;
	/*Allocate space to hold dqrr entries*/
	dpio_dev->dqrr_entry = dpaa2_calloc(NULL, dpio_dev->dqrr_size,
					sizeof(struct dqrr), 0);
	if (!dpio_dev->dqrr_entry) {
		DPAA2_ERR(FW, "ERROR, No Memory for DQRR entries\n");
		goto free_res;
	}
	DPAA2_INFO(FW, "\t DPIO[%d]  ", dpio_dev->hw_id);
	DPAA2_INFO(FW, "QBMan SW Portal 0x%p\n", dpio_dev->sw_portal);

	if(dev_priv->flags & DPAA2_ENABLE_INTERRUPTS) {
		if (dpaa2_dpio_intr_init(dpio_dev) != DPAA2_SUCCESS) {
			DPAA2_ERR(FW, "Interrupt registration failed for dpio");
			goto free_dqrr;
		}
	}

	io_space_count++;
	dpio_dev->index = io_space_count;
	/* Add device to DPAA2 DPIO device List */
	TAILQ_INSERT_HEAD(dpio_dev_list, dpio_dev, next);

	DPAA2_INFO(FW, "\t Allocated DPIO Device %d\n", io_space_count);
	return DPAA2_SUCCESS;
free_dqrr:
	dpaa2_free(dpio_dev->dqrr_entry);
free_res:
	if (dpio_dev->sw_portal)
		qbman_swp_finish(dpio_dev->sw_portal);
	dpaa2_free(dpio_dev->dpio);
free_dpio:
	LOCK_DESTROY(dpio_dev->lock);
	dpaa2_free(dpio_dev->intr_handle);
	dpaa2_free(dpio_dev);
	return DPAA2_FAILURE;
}


void release_dpio(struct dpaa2_dpio_dev *dpio_dev)
{
	int ret;

	SWP_LOCK(dpio_dev);
	if (dpio_dev->sw_portal)
		qbman_swp_finish(dpio_dev->sw_portal);

	if (dpio_dev->dpio) {
		DPAA2_INFO(FW, "Closing DPIO object %p\n", dpio_dev->dpio);

		ret = dpio_disable(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->token);
		if (ret)
			DPAA2_ERR(FW, "Error in Disabling DPIO "
				"device %p  Error %d\n", dpio_dev, ret);
		ret = dpio_reset(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->token);
		if (ret)
			DPAA2_ERR(FW, "Error in Resetting DPIO "
				"device %p  Error %d\n", dpio_dev, ret);
		ret = dpio_close(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->token);
		if (ret)
			DPAA2_ERR(FW, "Error in Closing DPIO "
				"device %p  Error %d\n", dpio_dev, ret);
		dpaa2_free(dpio_dev->dpio);
	}
	if (dpio_dev->dqrr_entry) {
		dpaa2_free(dpio_dev->dqrr_entry);
	}
	SWP_UNLOCK(dpio_dev);
	dpaa2_free(dpio_dev);

}

/* DPIO device cleanup fucntion */
int32_t dpaa2_io_portal_close(ODP_UNUSED struct dpaa2_dev *dev)
{
	/*Function is reverse of dpaa2_io_portal_probe.
	 * 1. RESET & Close the DPIO device
	 * 2. Free the allocated resources.
	 */
	if (dpio_dev_list) {
		struct dpaa2_dpio_dev *dpio_dev = NULL, *tmp;

		dpio_dev = TAILQ_FIRST(dpio_dev_list);
		while (dpio_dev) {
			DPAA2_INFO(FW, "RELEASING DPIO device %p\n", dpio_dev);
			tmp = TAILQ_NEXT(dpio_dev, next);
			release_dpio(dpio_dev);
			dpio_dev = tmp;
		}
		dpaa2_free(dpio_dev_list);
		dpio_dev_list = NULL;
	}
	/* Handle cleanup for notifier specific DPIO */
	if (notif_dpio) {
		release_dpio(notif_dpio);
		notif_dpio = NULL;
	}

	return DPAA2_SUCCESS;
}

void dpaa2_affine_dpio_intr_to_respective_core(int32_t dpio_id)
{
#define STRING_LEN	28
#define COMMAND_LEN	50
	uint32_t cpu_mask = 1;
	int ret;
	size_t len = 0;
	char *temp = NULL, *token = NULL;
	char string[STRING_LEN], command[COMMAND_LEN];
	FILE *file;

	snprintf(string, STRING_LEN, "dpio.%d", dpio_id);
	file = fopen("/proc/interrupts", "r");
	if (!file) {
		DPAA2_WARN(FW, "Failed to open /proc/interrupts file\n");
		return;
	}
	while (getline(&temp, &len, file) != -1) {
		if ((strstr(temp, string)) != NULL) {
			token = strtok(temp, ":");
			break;
		}
	}

	if (!token) {
		DPAA2_WARN(FW, "Failed to get interrupt id for dpio.%d\n", dpio_id);
		if (temp)
			free(temp);
		fclose(file);
		return;
	}

	cpu_mask = cpu_mask << sched_getcpu();
	snprintf(command, COMMAND_LEN, "echo %X > /proc/irq/%s/smp_affinity", cpu_mask, token);
	ret = system(command);
	if (ret < 0)
		DPAA2_WARN(FW, "Failed to affine the interrupts on respective core\n");
	else {
		DPAA2_DBG(FW, " %s command is executed\n", command);
	}
	free(temp);
	fclose(file);
}

void dpaa2_write_all_intr_fd(void)
{
	struct dpaa2_dpio_dev *dpio_dev = NULL;

	TAILQ_FOREACH(dpio_dev, dpio_dev_list, next) {
		uint64_t  i = 1;
		write(dpio_dev->intr_handle[0].fd, &i, sizeof(uint64_t));
	}
}

/*!
 * @details	This function must be invoked by each IO thread of application
 *		once.  This function will affine a thread to a given IO context.
 *		If an application wish to share a IO context between multiple
 *		threads, same IO context shall be passed for all required
 *		threads.
 *
 * @param[in]	io_index - An index value of IO context. Range is 1 to
 *		total IO context count. or DPAA2_IO_PORTAL_ANY_FREE to be
 *		choosed by the underlying API.
 *
 * @returns     DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_thread_affine_io_context(uint32_t io_index)
{

	struct dpaa2_dpio_dev *dpio_dev = NULL;
	uint32_t ret;

	if (thread_io_info.dpio_dev) {
		DPAA2_NOTE(FW, "io_index %d  thread alread affined to =%d",
				io_index, thread_io_info.dpio_dev->index);
		return DPAA2_SUCCESS;
	}

	if (io_index == DPAA2_IO_PORTAL_ANY_FREE) {
		int dpio_avbl = 0;

		/* Get any unused DPIO dev handle from list */
		TAILQ_FOREACH(dpio_dev, dpio_dev_list, next) {
		DPAA2_DBG(FW, "cpu %d io_index %d dpio index %d - dpio =%p/%d",
				odp_cpu_id(), io_index, dpio_dev ? dpio_dev->index : 0xff,
				thread_io_info.dpio_dev,
				odp_atomic_read_u16(&dpio_dev->ref_count));
		if (dpio_dev && odp_atomic_test_and_set_u16(&dpio_dev->ref_count)) {
			dpio_avbl = 1;
			break;
			}
		}
		if (!dpio_avbl) {
			DPAA2_ERR(FW, "No free portal available");
			return DPAA2_FAILURE;
		}
	} else {
		/* Index value must lie in range (1 - io_space_count.resource_count) */
		if ((io_index <= 0) || (io_index > io_space_count)) {
			DPAA2_ERR(FW, "\tInvalid IO index- %d (ip_space_count = %d)\n",
						io_index, io_space_count);
			return DPAA2_FAILURE;
		}
		/* Get DPIO dev handle from list using index */
		TAILQ_FOREACH(dpio_dev, dpio_dev_list, next) {
			if (dpio_dev && (dpio_dev->index == io_index))
				break;
		}
		/* Increment reference count */
		odp_atomic_inc_u16(&dpio_dev->ref_count);
	}
	if (!dpio_dev) {
		DPAA2_ERR(FW, "\tdpio_dev not found or not available\n");
		return DPAA2_FAILURE;
	}

	/* Populate the thread_io_info structure */
	thread_io_info.dpio_dev = dpio_dev;
	thread_io_info.dq_storage = dpaa2_data_malloc(NULL,
		NUM_MAX_RECV_FRAMES * sizeof(struct qbman_result),
		ODP_CACHE_LINE_SIZE);
	if (!thread_io_info.dq_storage) {
		DPAA2_ERR(FW, "Memory allocation failure");
		return DPAA2_FAILURE;
	}
	ret = dpaa2_configure_stashing();
	if (ret) {
		DPAA2_ERR(FW, "dpaa2_configure_stashing failed");
		return DPAA2_FAILURE;
	}
	DPAA2_DBG(FW, "io_index %d affined with dpio index %d - dpio =%p",
			io_index, dpio_dev->index, thread_io_info.dpio_dev);
	if ((dpio_dev->intr_handle[VFIO_DPIO_DATA_IRQ_INDEX].flags) & DPAA2_INTR_ENABLED)
		dpaa2_affine_dpio_intr_to_respective_core(dpio_dev->hw_id);

	return DPAA2_SUCCESS;
}

static int32_t dpaa2_configure_stashing(void)
{
	int8_t sdest;
	int32_t cpu_id, ret;
	struct dpaa2_dpio_dev *dpio_dev = NULL;

	dpio_dev = thread_io_info.dpio_dev;
	if (!dpio_dev) {
		DPAA2_ERR(FW, "\tdpio_dev not found. Stashing cannot be set\n");
		return DPAA2_FAILURE;
	}

	/* Set the Stashing Destination */
	cpu_id = sched_getcpu();/* change it to odp_cpu_id(), when dpaa2 is deprecreted*/;
	if (cpu_id < 0) {
		DPAA2_ERR(FW, "\tGetting CPU Index failed\n");
		return DPAA2_FAILURE;
	}

	/* In case of running ODP on the Virtual Machine the Stashing
	 * Destination gets set in the H/W w.r.t. the Virtual CPU ID's.
	 * As a W.A. environment variable HOST_START_CPU tells which the
	 * offset of the host start core of the Virtual Machine threads.
	 */
	if (getenv("HOST_START_CPU")) {
		cpu_id += atoi(getenv("HOST_START_CPU"));
		cpu_id = cpu_id % NUM_HOST_CPUS;
	}

	/* Set the STASH Destination depending on Current CPU ID.
	   Valid values of SDEST are 4,5,6,7. Where,
	   CPU 0-1 will have SDEST 4
	   CPU 2-3 will have SDEST 5.....and so on.
	*/
	DPAA2_CORE_CLUSTER_GET(sdest, cpu_id);
	DPAA2_INFO(FW, "%s: Portal= %d  CPU= %u SDEST= %d\n",
			__func__, dpio_dev->index, cpu_id, sdest);

	ret = dpio_set_stashing_destination(dpio_dev->dpio, CMD_PRI_LOW,
						dpio_dev->token, sdest);
	if (ret) {
		DPAA2_ERR(FW, "%s: %d ERROR in Setting SDEST\n", __func__, ret);
		return DPAA2_FAILURE;
	}
	return DPAA2_SUCCESS;
}

/*!
 * @details	Stop the already active IO thread & de-affine IO context from
 *		current thread. This function must be invoked before exiting
 *		from thread if, it has initially called
 *		dpaa2_thread_affine_io_context().
 *
 * @returns     Not applicable.
 *
 */
void dpaa2_thread_deaffine_io_context(void)
{
	struct dpaa2_dpio_dev *dpio_dev;

	/* Get DPIO portal for this thread context */
	dpio_dev = thread_io_info.dpio_dev;
	if ((dpio_dev == NULL) ||
			(odp_atomic_read_u16(&dpio_dev->ref_count) == 0))
		return;
	/* Decrement reference count */
	odp_atomic_dec_u16(&dpio_dev->ref_count);
	/* Unset the thread_io_info structure */
	dpaa2_data_free(thread_io_info.dq_storage);
	thread_io_info.dq_storage = NULL;
	thread_io_info.dpio_dev = NULL;
}

uint32_t dpaa2_get_io_context_count(void)
{
	return io_space_count;
}


int dpaa2_register_dpio_interrupt(struct dpaa2_dpio_dev *dpio_dev,
		uint32_t index)
{
	return dpaa2_register_interrupt(dpio_dev->vfio_fd,
		&(dpio_dev->intr_handle[index]), index);
}
