/*
 * Copyright (c) 2014-2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/*!
 * @file	dpaa2_ldpaa.c
 *
 * @brief	Layerscape DPAA specific DPAA2 framework functionalities.
 *
 */
#include <odp/api/std_types.h>
#include <fsl_dprc.h>
#include <fsl_dpio.h>
#include <fsl_dpmcp.h>

#include <pthread.h>
#include <fsl_qbman_portal.h>
#include <dpaa2.h>
#include <dpaa2_vfio.h>
#include <dpaa2_internal.h>
#include <dpaa2_dev_priv.h>
#include <dpaa2_malloc.h>
#include <dpaa2_mbuf_priv_ldpaa.h>
#include <dpaa2_io_portal_priv.h>
#include <dpaa2_dev_notif_priv.h>
#include <dpaa2_hwq_priv.h>

#include "eal_hugepages.h"
#include <dpaa2_memory.h>
#include <dpaa2_memconfig.h>
#include <dirent.h>
#include <string.h>
#include <odp/api/hints.h>

/***** Macros ********/

/***** Global Variables ********/
extern struct vfio_group vfio_groups[VFIO_MAX_GRP];
extern int container_device_fd;

/*!
 * A variable to store thread specific configuration / Settings.
 * This shall be defined per thread.
*/

/* MC Portals */
uint32_t mcp_id;
void *(*mcp_ptr_list);

#define MC_PORTALS_BASE_PADDR   ((phys_addr_t)0x00080C000000ULL)
#define MC_PORTAL_STRIDE        0x10000
#define MC_PORTAL_SIZE	64
#define MC_PORTAL_ID_TO_PADDR(portal_id) \
	(MC_PORTALS_BASE_PADDR + (portal_id) * MC_PORTAL_STRIDE)
/* Common MC Portal */
#define MC_PORTAL_INDEX		0

void *get_mc_portal(uint32_t idx)
{
	uint64_t mc_portal_paddr;
	int64_t v_addr;

	mc_portal_paddr = MC_PORTAL_ID_TO_PADDR(idx);
	DPAA2_INFO(FW, "MC [%d] has PHY_ADD = 0x%"PRIx64"\n", idx, mc_portal_paddr);
	v_addr = (uint64_t)mmap(NULL, MC_PORTAL_SIZE,
		PROT_WRITE | PROT_READ, MAP_SHARED,
		container_device_fd, mc_portal_paddr);
	if (v_addr == -1)
		return NULL;

	DPAA2_INFO(FW, "MC [%d] has VIR_ADD = 0x%"PRIx64"\n", idx, v_addr);
	return (void *)v_addr;
}

enum dpaa2_dev_type mc_to_dpaa2_dev_type(const char *dev_name)
{
	if (!strcmp(dev_name, "dpni"))
		return DPAA2_NIC;
	if (!strcmp(dev_name, "dpsw"))
		return DPAA2_SW;
	if (!strcmp(dev_name, "dpcon"))
		return DPAA2_CONC;
	if (!strcmp(dev_name, "dpci"))
		return DPAA2_AIOP_CI;
	if (!strcmp(dev_name, "dpseci"))
		return DPAA2_SEC;
	if (!strcmp(dev_name, "dpio"))
		return DPAA2_IO_CNTXT;

	/* Will add More cases */
	return DPAA2_MAX_DEV;
}


static struct dpaa2_driver *get_device_driver(const char *dev_name)
{

	enum dpaa2_dev_type dev_type =
		mc_to_dpaa2_dev_type(dev_name);

	if (dev_type == DPAA2_MAX_DEV)
		return NULL;

	return dpaa2_driver_list[dev_type];

}

/* Following function shall fetch total available list of MC devices
 * from VFIO container & populate private list of devices and other
 * data structures
 */
static int32_t dpaa2_dev_init_all(struct dpaa2_init_cfg *cfg)
{

	struct vfio_device *vdev;
	struct vfio_device_info device_info = { .argsz = sizeof(device_info) };
	struct vfio_group *group = &vfio_groups[0];
	char *temp_obj, *mcp_obj, *dev_name;
	const char *object_type;
	int32_t ret, object_id, i, dev_fd;
	DIR *d;
	struct dirent *dir;
	char path[VFIO_PATH_MAX];
	int64_t v_addr;

	sprintf(path, "/sys/kernel/iommu_groups/%d/devices", group->groupid);

	DPAA2_INFO(FW, "\t Devices path = %s\n", path);

	d = opendir(path);
	if (!d) {
		DPAA2_ERR(FW, "\t Unable to open directory %s\n", path);
		return DPAA2_FAILURE;
	}

	/*Counting the number of devices in a group and getting the mcp ID*/
	ndev_count = 0;
	mcp_obj = NULL;
	while ((dir = readdir(d)) != NULL) {
		if (dir->d_type == DT_LNK) {
			ndev_count++;
			if (!strncmp("dpmcp", dir->d_name, 5)) {
				if (mcp_obj)
					dpaa2_free(mcp_obj);
				mcp_obj = dpaa2_malloc(NULL, sizeof(dir->d_name));
				if (!mcp_obj) {
					DPAA2_ERR(FW, "\t Unable to allocate memory\n");
					closedir(d);
					return DPAA2_FAILURE;
				}
				strcpy(mcp_obj, dir->d_name);
				temp_obj = strtok(dir->d_name, ".");
				temp_obj = strtok(NULL, ".");
				sscanf(temp_obj, "%d", &mcp_id);
			}
		}
	}
	closedir(d);

	if (!mcp_obj) {
		DPAA2_ERR(FW, "\t MCP Object not Found\n");
		return DPAA2_FAILURE;
	}
	DPAA2_INFO(FW, "\t Total devices in conatiner = %d, MCP ID = %d\n",
			ndev_count, mcp_id);
	/* Allocate the memory depends upon number of objects in a group*/
	group->vfio_device = (struct vfio_device *) dpaa2_malloc(NULL,
				ndev_count * sizeof(struct vfio_device));

	if (!(group->vfio_device)) {
		DPAA2_ERR(FW, "\t Unable to allocate memory\n");
		dpaa2_free(mcp_obj);
		return DPAA2_FAILURE;
	}

	/* Initialize the Device List */
	TAILQ_INIT(&device_list);

	/* Allocate memory for MC Portal list */
	mcp_ptr_list = dpaa2_malloc(NULL, sizeof(void *) * 1);
	if (!mcp_ptr_list) {
		DPAA2_ERR(FW, "NO Memory!\n");
		dpaa2_free(mcp_obj);
		goto FAILURE;
	}

	v_addr = vfio_map_mcp_obj(group, mcp_obj);
	dpaa2_free(mcp_obj);
	if (v_addr == (int64_t) MAP_FAILED) {
		DPAA2_ERR(FW, "Error mapping region (errno = %d)\n", errno);
		goto FAILURE;
	}

	DPAA2_INFO(FW, "MC  has VIR_ADD = 0x%"PRIx64"\n", v_addr);

	mcp_ptr_list[0] = (void *)v_addr;


	d = opendir(path);
	if (!d) {
		DPAA2_ERR(FW, "\t Directory %s not able to open\n", path);
		goto FAILURE;
	}

	i = 0;
	/* Parsing each object and initiating them*/
	while ((dir = readdir(d)) != NULL) {
		if (dir->d_type != DT_LNK)
			continue;
		if (!strncmp("dprc", dir->d_name, 4) || !strncmp("dpmcp", dir->d_name, 5))
			continue;
		dev_name = dpaa2_malloc(NULL, sizeof(dir->d_name));
		if (!dev_name) {
			DPAA2_ERR(FW, "\t Unable to allocate memory\n");
			goto FAILURE;
		}
		strcpy(dev_name, dir->d_name);
		object_type = strtok(dir->d_name, ".");
		temp_obj = strtok(NULL, ".");
		sscanf(temp_obj, "%d", &object_id);
		DPAA2_INFO(FW, "Parsing Device = %s\n", dev_name);

		/* getting the device fd*/
		dev_fd = ioctl(group->fd, VFIO_GROUP_GET_DEVICE_FD, dev_name);
		if (dev_fd < 0) {
			DPAA2_ERR(FW, "\tvfio: error getting device %s fd from group %d\n",
				dev_name, group->fd);
			dpaa2_free(dev_name);
			goto FAILURE;
		}
		dpaa2_free(dev_name);
		DPAA2_INFO(FW, "\tAdding device at index %d", group->object_index);
		vdev = &group->vfio_device[group->object_index++];
		vdev->fd = dev_fd;
		vdev->index = i;
		i++;
		/* Get Device inofrmation */
		if (ioctl(vdev->fd, VFIO_DEVICE_GET_INFO, &device_info)) {
			DPAA2_ERR(FW, "VFIO_DEVICE_FSL_MC_GET_INFO failed");
			goto FAILURE;
		}
		DPAA2_INFO(FW, "\tDevice Type %s, ID %d",
				object_type, object_id);
		DPAA2_INFO(FW, "\tnum_regions %d num_irqs %d",
				device_info.num_regions, device_info.num_irqs);


		/* Alloc a dpaa2_dev struct and add to device table */
		if (!strcmp(object_type, "dpbp")) {
			/* Call Buffer pool APIs to intialize pools */
			DPAA2_INFO(FW, "Initializing DPBP DEVICE.\n");
			if (dpaa2_mbuf_dpbp_init((uint64_t)mcp_ptr_list[MC_PORTAL_INDEX],
				object_id)) {
				DPAA2_ERR(FW, "DPBP Initialization Failed\n");
				goto FAILURE;
			}

		} else if (!strcmp(object_type, "dpio")) {

			struct dpaa2_driver *drv;
			struct dpaa2_dev_priv dev_priv;

			/* Get the Matching driver for this device */
			DPAA2_INFO(FW, "Initializing DEVICE[%s].\n", object_type);
			drv = get_device_driver(object_type);
			if (NULL == drv) {
				DPAA2_WARN(FW, "No Device driver for [%s]\n",
							object_type);
				continue;
			}

			dev_priv.vfio_fd = vdev->fd;
			dev_priv.hw_id = object_id;
			/* Using single portal  for all devices */
			dev_priv.mc_portal = mcp_ptr_list[MC_PORTAL_INDEX];
			dev_priv.flags = cfg->flags;
			/* Pass VFIO object attributes that may be used by DPIO driver.
			   The driver will overrite private data pointer to its own
			   data structure pointer, if required.
			 */
			dev_priv.drv_priv = (void *)&device_info;
			/* Now prob the DPIO device. DPIO portal driver will alocate its own
			   device strcuture & maintain same in seperate DPIO device list */
			DPAA2_INFO(FW, "Probing DPIO device.\n");
			if (drv->dev_probe(NULL, (void *)&dev_priv)) {
				DPAA2_WARN(FW, "Device [%s] Probe Failed.\n", object_type);
				continue;
			}

		} else if (!strcmp(object_type, "dpni") ||
				!strcmp(object_type, "dpci") ||
				!strcmp(object_type, "dpseci") ||
				!strcmp(object_type, "dpcon")) {

			struct dpaa2_driver *drv;
			struct dpaa2_dev *dev;
			struct dpaa2_dev_priv *dev_priv;

			/* Get the Matching driver for this device */
			DPAA2_INFO(FW, "Initializing DEVICE[%s].\n", object_type);
			drv = get_device_driver(object_type);
			if (NULL == drv) {
				DPAA2_WARN(FW, "No Device driver for [%s]\n",
							object_type);
				continue;
			}

			/* Allocate DPAA2 device object */
			dev = dpaa2_malloc(NULL, sizeof(struct dpaa2_dev));
			if (!dev) {
				DPAA2_ERR(FW, " NO memory for DEVICE.\n");
				goto FAILURE;
			}
			dev_priv = dpaa2_malloc(NULL, sizeof(struct dpaa2_dev_priv));
			if (!dev_priv) {
				dpaa2_free(dev);
				DPAA2_ERR(FW, "No memory for device priv.\n");
				goto FAILURE;
			}
			dev->state = DEV_INACTIVE;
			dev->dev_type =
				mc_to_dpaa2_dev_type(object_type);

			/* Fill VFIO data. This shall be required in
			   device driver probe function for xxx_open API.
			*/
			dev_priv->vfio_fd = vdev->fd;
			dev_priv->hw_id = object_id;
			dev_priv->bp_list = NULL;
			/* Using single portal  for all devices */
			dev_priv->mc_portal = mcp_ptr_list[MC_PORTAL_INDEX];
			/* Pass VFIO object attributes that may be used by device driver.
			   The driver will overrite private data pointer to its own
			   data structure pointer, if required.
			 */
			dev_priv->drv_priv = (void *)&device_info;
			dev->priv = (void *)dev_priv;
			dev_priv->flags = cfg->flags;

			/* Initialize function pointers to dummy ones.
			 The device driver shall overwrite them with
			 required one */
			dev_priv->fn_dev_cfg = dpaa2_dummy_dev_fn;
			dev_priv->fn_get_vqid = dpaa2_dummy_vq_fn;
			/* Now prob the device */
			DPAA2_INFO(FW, "Probing device.\n");
			ret = drv->dev_probe(dev, cfg);
			if (ret != DPAA2_SUCCESS) {
				dpaa2_free(dev_priv);
				dpaa2_free(dev);
				if (ret == DPAA2_DEV_CONSUMED)
					/* In case device is condumed, don't ERR */
					DPAA2_INFO(FQ, "Device consumed");
				else
					DPAA2_WARN(FW, "Device Probe Failed.\n");
				continue;
			}
			/* Add device to DPAA2 device List */
			TAILQ_INSERT_HEAD(&device_list, dev, next);
		} else {
			/* Handle all other devices */
			DPAA2_INFO(FW, "Unsupported Device Type '%s'\n",
					object_type);
			group->object_index--;
			i--;
			close(dev_fd);
		}
		/* End IF */
	}
	closedir(d);
	return DPAA2_SUCCESS;

FAILURE:
	dpaa2_free(group->vfio_device);
	group->vfio_device = NULL;
	return DPAA2_FAILURE;
}

int32_t dpaa2_dev_shutdown(ODP_UNUSED struct dpaa2_dev *dev)
{
	DPAA2_INFO(FW, "Device is closed successfully\n");
	return DPAA2_SUCCESS;
}

/*!
 * @details	Initialize the Network Application Development Kit Layer (DPAA2).
 *		This function must be the first function invoked by an
 *		application and is to be executed once.
 *
 * @param[in]	arg - A pointer to dpaa2_init_cfg structure.
 *
 * @returns     DPAA2_SUCCESS in case of successfull intialization of
 *		DPAA2 Layer; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_platform_init(struct dpaa2_init_cfg *cfg)
{
	/* Do when we have valid VFIO container */
	if (cfg->vfio_container) {
		/* Find and Configure VFIO container / groups for this applicaton context */
		if (setup_vfio_grp(cfg->vfio_container))
			return DPAA2_FAILURE;

		/* Now scan & populate List of devices assigned to our container */
		if (dpaa2_dev_init_all(cfg))
			return DPAA2_FAILURE;
	}
	return DPAA2_SUCCESS;
}


/*!
 * @details	Do Clean up and exit for in context of a given application. This
 *		function must be invoked by an application before exiting.
 *
 * @returns     Not applicable.
 *
 */
void dpaa2_platform_exit(void)
{
	struct dpaa2_dev *dev;
	struct dpaa2_driver *drv;
	uint16_t mc_token, retcode;
	struct dpaa2_dev_priv *priv;
	struct fsl_mc_io mc_handle;

	/* Doing gracefull shutdown of all devices & release all resources */
	/* Need to handle cleanup for DPIO devices.
	   Get the Matching driver for this device */
	drv = get_device_driver("dpio");
	if (NULL != drv)
		drv->dev_shutdown(NULL);

	/* Handle cleanup of all other devices */
	dev = TAILQ_FIRST(&device_list);
	while (dev) {
		struct dpaa2_dev *dev_tmp;
		/* shutdown the device */
		DPAA2_INFO(FW, "RELEASING NIC %p\n", dev);
		drv = dpaa2_driver_list[dev->dev_type];
		drv->dev_shutdown(dev);
		/* Free unused memory */
		priv = (struct dpaa2_dev_priv *) dev->priv;
		close(priv->vfio_fd);
		dpaa2_free(dev->priv);
		dev_tmp = TAILQ_NEXT(dev, next);
		dpaa2_free(dev);
		dev = dev_tmp;
	}
	/* Close all the dpbp objects */
	dpaa2_mbuf_dpbp_close_all();
	/* Close all the frame queue objects */
	dpaa2_hwq_close_all();

	if (mcp_ptr_list) {
		mc_handle.regs = (void *) mcp_ptr_list[MC_PORTAL_INDEX];
		retcode = dpmcp_open(&mc_handle, CMD_PRI_LOW, mcp_id, &mc_token);
		if (retcode != 0)
			DPAA2_ERR(ETH, "Error in open MCP"
					" device: ErrorCode = %d\n", retcode);
		/* Resetting the device*/
		retcode = dpmcp_reset(&mc_handle, CMD_PRI_LOW, mc_token);
		if (retcode != 0)
			DPAA2_ERR(ETH, "Error in Resetting the MCP"
					" device: ErrorCode = %d\n", retcode);
		/*Close the device at underlying layer*/
		retcode = dpmcp_close(&mc_handle, CMD_PRI_LOW, mc_token);
		if (retcode != 0)
			DPAA2_ERR(ETH, "Error in closing the MCP"
					" device: ErrorCode = %d\n", retcode);

		dpaa2_free(mcp_ptr_list);
	}

	/* UNSET the container & Close Opened File descriptors */
	destroy_vfio_group(&vfio_groups[0]);
}

void dpaa2_dump_platform_device(void *device)
{
	/* Not Used for now*/
	device = device;

}

int32_t dpaa2_dev_affine_conc_list(struct dpaa2_dev *conc_dev ODP_UNUSED)
{
	DPAA2_INFO(EAL, "NOT supported for LDPAA\n");
	return DPAA2_SUCCESS;
}

int32_t dpaa2_dev_deaffine_conc_list(struct dpaa2_dev *conc_dev ODP_UNUSED)
{
	DPAA2_INFO(EAL, "NOT supported for LDPAA\n");
	return DPAA2_SUCCESS;
}
