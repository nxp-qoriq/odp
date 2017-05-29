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
#include <pthread.h>
#include <dpaa2.h>
#include <dpaa2_vfio.h>
#include <dpaa2_internal.h>
#include <dpaa2_dev_priv.h>
#include <dpaa2_malloc.h>
#include <dpaa2_dev_notif_priv.h>

#include "eal_hugepages.h"
#include <dpaa2_memory.h>
#include <dpaa2_memconfig.h>
#include <dirent.h>
#include <string.h>

/***** Macros ********/

/***** Global Variables ********/

/* Number of VFIO containers & groups with in */
struct vfio_group vfio_groups[VFIO_MAX_GRP];
struct vfio_container vfio_containers[VFIO_MAX_CONTAINERS];
int container_device_fd;
uint32_t *msi_intr_vaddr;

static int vfio_connect_container(struct vfio_group *vfio_group)
{
	struct vfio_container *container;
	int i, fd, ret;

	/* Try connecting to vfio container already created */
	for (i = 0; i < VFIO_MAX_CONTAINERS; i++) {
		container = &vfio_containers[i];
		if (!ioctl(vfio_group->fd, VFIO_GROUP_SET_CONTAINER, &container->fd)) {
			DPAA2_ERR(FW, "Container pre-exists with FD[0x%x]"
					" for this group\n", container->fd);
			vfio_group->container = container;
			return DPAA2_SUCCESS;
		}
	}

	/* Opens main vfio file descriptor which represents the "container" */
	fd = open("/dev/vfio/vfio", O_RDWR);
	if (fd < 0) {
		DPAA2_ERR(FW, "vfio: error opening VFIO Container\n");
		return DPAA2_FAILURE;
	}
	ret = ioctl(fd, VFIO_GET_API_VERSION);
	if (ret != VFIO_API_VERSION) {
		close(fd);
		return DPAA2_FAILURE;
	}
	/* Check whether support for SMMU type IOMMU prresent or not */
	if (ioctl(fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU)) {
		/* Connect group to container */
		if (ioctl(vfio_group->fd, VFIO_GROUP_SET_CONTAINER, &fd)) {
			DPAA2_ERR(FW, "VFIO_GROUP_SET_CONTAINER failed.\n");
			close(fd);
			return DPAA2_FAILURE;
		}
		/* Initialize SMMU */
		if (ioctl(fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU)) {
			DPAA2_ERR(FW, "VFIO_SET_IOMMU failed.\n");
			close(fd);
			return DPAA2_FAILURE;
		}
		DPAA2_INFO(FW, "VFIO_TYPE1_IOMMU Supported\n");
	} else {
		DPAA2_ERR(FW, "vfio error: No supported IOMMU\n");
		close(fd);
		return DPAA2_FAILURE;
	}


	/* Configure the Container private data structure */
	container = NULL;
	for (i = 0; i < VFIO_MAX_CONTAINERS; i++) {
		if (vfio_containers[i].used)
			continue;
		DPAA2_INFO(FW, "Found unused container at index %d\n", i);
		container = &vfio_containers[i];
	}
	if (!container) {
		DPAA2_ERR(FW, "vfio error: No Free Container Found\n");
		close(fd);
		return DPAA2_FAILURE;
	}
	container->used = 1;
	container->fd = fd;
	container->group_list[container->index] = vfio_group;
	DPAA2_INFO(FW, "Assigning Group to index group_list[%d]\n", container->index);

	vfio_group->container = container;
	container->index++;
	return DPAA2_SUCCESS;
}


static void vfio_disconnect_container(struct vfio_group *group)
{
	struct vfio_container *container = group->container;

	if (!container) {
		DPAA2_WARN(FW, "Invalid container");
		return;
	}

	/*TODO: Below Command always failed with error code -16. For current
		use cases, there is no need to unset the container. But in future,
		if the application will trying to re-initialize the container resources
		without killing itself, then there may be need for this command*/
	if (ioctl(group->fd, VFIO_GROUP_UNSET_CONTAINER, &container->fd)) {
		DPAA2_DBG(FW, "UNSET Container API Failed with ERRNO = %d\n", errno);
	}

	group->container = NULL;

	close(container->fd);
}


/* TODO - The below two API's are provided as a W.A.. as VFIO currently
   does not add the mapping of the interrupt region to SMMU. This should
   be removed once the support is added in the Kernel.
*/
static void vfio_unmap_irq_region(struct vfio_group *group)
{
	int ret;
	struct vfio_iommu_type1_dma_unmap unmap = {
		.argsz = sizeof(unmap),
		.flags = 0,
		.iova = 0x6030000,
		.size = 0x1000,
	};

	ret = ioctl(group->container->fd, VFIO_IOMMU_UNMAP_DMA, &unmap);
	if (ret)
		DPAA2_ERR(FW, "Error in vfio_dma_unmap (errno = %d)", errno);
}

static int vfio_map_irq_region(struct vfio_group *group)
{
	int ret;
	unsigned long *vaddr = NULL;
	struct vfio_iommu_type1_dma_map map = {
		.argsz = sizeof(map),
		.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
		.vaddr = 0x6030000,
		.iova = 0x6030000,
		.size = 0x1000,
	};

	vaddr = (unsigned long *) mmap(NULL, 0x1000, PROT_WRITE |
		PROT_READ, MAP_SHARED, container_device_fd, 0x6030000);
	if (vaddr == MAP_FAILED) {
		DPAA2_ERR(FW, "Error mapping GITS region (errno = %d)", errno);
		return -errno;
	}

	msi_intr_vaddr = (uint32_t *)((char *)(vaddr) + 64);
	map.vaddr = (unsigned long)vaddr;
	ret = ioctl(group->container->fd, VFIO_IOMMU_MAP_DMA, &map);
	if (ret == 0)
		return DPAA2_SUCCESS;

	DPAA2_ERR(FW, "vfio_map_irq_region fails (errno = %d)", errno);
	return -errno;
}

int32_t vfio_dmamap_mem_region(uint64_t vaddr,
				uint64_t iova,
				uint64_t size)
{
	struct vfio_group *group;
	struct vfio_iommu_type1_dma_map dma_map = {
		.argsz = sizeof(dma_map),
		.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
	};

	dma_map.vaddr = vaddr;
	dma_map.size = size;
	dma_map.iova = iova;

	/* SET DMA MAP for IOMMU */
	group = &vfio_groups[0];
	if (ioctl(group->container->fd, VFIO_IOMMU_MAP_DMA, &dma_map)) {
		DPAA2_ERR(FW, "SWP: VFIO_IOMMU_MAP_DMA API Error %d.\n", errno);
		return DPAA2_FAILURE;
	}
	return DPAA2_SUCCESS;
}

static int32_t setup_dmamap(void)
{
	int ret;
	struct vfio_group *group;
	struct vfio_iommu_type1_dma_map dma_map = {
		.argsz = sizeof(dma_map),
		.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
	};

	int i;
	const struct dpaa2_memseg *memseg;
	char *temp = NULL;
	FILE *file;
	size_t len = 0;

	for (i = 0; i < DPAA2_MAX_MEMSEG; i++) {
		memseg = dpaa2_eal_get_physmem_layout();
		if (memseg == NULL) {
			DPAA2_ERR(FW, "Cannot get physical layout\n");
			return -1;
		}

		if (memseg[i].addr == NULL && memseg[i].len == 0) {
			DPAA2_INFO(FW, "No more valid memsegs\n");
			break;
		}

		dma_map.vaddr = (uint64_t)memseg[i].addr;
		dma_map.size = memseg[i].len;

		/* SET DMA MAP for IOMMU */
		group = &vfio_groups[0];

		DPAA2_INFO(FW, "Initial SHM Virtual ADDR %llX\n", dma_map.vaddr);
		DPAA2_INFO(FW, "DMA size 0x%llx\n", dma_map.size);
		dma_map.iova = (uint64_t)(DPAA2_VADDR_TO_IOVA(dma_map.vaddr));
		ret = ioctl(group->container->fd, VFIO_IOMMU_MAP_DMA, &dma_map);
		if (ret) {
			DPAA2_ERR(FW, "VFIO_IOMMU_MAP_DMA API Error %d.\n", errno);
			return DPAA2_FAILURE;
		}
		DPAA2_INFO(FW, "-----> dma_map.vaddr = 0x%llX\n", dma_map.vaddr);
	}

	file = fopen("/proc/version", "r");
	if (!file) {
		DPAA2_ERR(FW, "Failed to open /proc/version\n");
		free(temp);
		return DPAA2_FAILURE;
	}

	if (getline(&temp, &len, file) == -1) {
		DPAA2_ERR(FW, "Failed to read from /proc/version\n");
		goto err;
	}

	if ((strstr(temp, "Linux version 4.1")) ||
		(strstr(temp, "Linux version 4.4"))) {
		ret = vfio_map_irq_region(group);
		if (ret) {
			DPAA2_ERR(FW, "Unable to map IRQ region\n");
			goto err;
		}
	}
	return DPAA2_SUCCESS;

err:
	free(temp);
	fclose(file);
	return DPAA2_FAILURE;
}

void destroy_dmamap(void)
{
	int ret;
	struct vfio_group *group;
	struct vfio_iommu_type1_dma_unmap dma_unmap = {
		.argsz = sizeof(dma_unmap),
		.flags = 0,
	};

	int i;
	const struct dpaa2_memseg *memseg;

	for (i = 0; i < DPAA2_MAX_MEMSEG; i++) {
		memseg = dpaa2_eal_get_physmem_layout();
		if (memseg == NULL) {
			DPAA2_ERR(FW, "Cannot get physical layout\n");
			return;
		}

		if (memseg[i].addr == NULL && memseg[i].len == 0) {
			DPAA2_INFO(FW, "No more valid memsegs\n");
			break;
		}

		dma_unmap.iova = (uint64_t)memseg[i].addr;
		dma_unmap.size = memseg[i].len;

		group = &vfio_groups[0];
		DPAA2_INFO(FW, "\nDMA-UNMAP IOVA ADDR %llX\n", dma_unmap.iova);
		DPAA2_INFO(FW, "DMA-UNMAP size 0x%llx\n", dma_unmap.size);

		ret = ioctl(group->container->fd, VFIO_IOMMU_UNMAP_DMA, &dma_unmap);
		if (ret)
			DPAA2_ERR(FW, "VFIO_IOMMU_UNMAP_DMA API Error %d.\n", errno);
	}

	vfio_unmap_irq_region(group);

}

static int vfio_set_group(struct vfio_group *group, int groupid)
{
	char path[VFIO_PATH_MAX];
	struct vfio_group_status status = { .argsz = sizeof(status) };

	/* Open the VFIO file corresponding to the IOMMU group */
	snprintf(path, sizeof(path), "/dev/vfio/%d", groupid);

	group->fd = open(path, O_RDWR);
	if (group->fd < 0) {
		DPAA2_ERR(FW, "vfio: error opening %s\n", path);
		return DPAA2_FAILURE;
	}
	DPAA2_INFO(FW, "vfio: Open FD[0x%X] for IOMMU group = %s\n",
		group->fd, path);

	/* Test & Verify that group is VIABLE & AVAILABLE */
	if (ioctl(group->fd, VFIO_GROUP_GET_STATUS, &status)) {
		goto fail;
	}
	if (!(status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		goto fail;
	}
	/* Since Group is VIABLE, Store the groupid */
	group->groupid = groupid;

	/* Now connect this IOMMU group to given container */
	if (vfio_connect_container(group)) {
		goto fail;
	}
	return DPAA2_SUCCESS;
fail:
	close(group->fd);
	return DPAA2_FAILURE;
}

static void vfio_put_group(struct vfio_group *group)
{
	vfio_disconnect_container(group);
	if (group->fd)
		close(group->fd);
}

int32_t setup_vfio_grp(char  *vfio_container)
{

	char path[VFIO_PATH_MAX];
	char iommu_group_path[VFIO_PATH_MAX], *group_name;
	struct vfio_group *group = NULL;
	struct stat st;
	int groupid;
	int ret, len, i;

	/* Check whether LS-Container exists or not */
	sprintf(path, "/sys/bus/fsl-mc/devices/%s", vfio_container);
	DPAA2_INFO(FW, "\tcontainer device path = %s\n", path);
	if (stat(path, &st) < 0) {
		DPAA2_ERR(FW, "vfio: LS-container device does not exists\n");
		return DPAA2_FAILURE;
	}

	/* DPRC container exists. NOw checkout the IOMMU Group */
	strncat(path, "/iommu_group", sizeof(path) - strlen(path) - 1);

	len = readlink(path, iommu_group_path, VFIO_PATH_MAX);
	if (len == -1) {
		DPAA2_ERR(FW, "\tvfio: error no iommu_group for device\n");
		DPAA2_ERR(FW, "\t%s: len = %d, errno = %d\n", path, len, errno);
		return DPAA2_FAILURE;
	}

	iommu_group_path[len] = 0;
	group_name = basename(iommu_group_path);
	DPAA2_INFO(FW, "vfio: IOMMU group_name = %s\n", group_name)
		;
	if (sscanf(group_name, "%d", &groupid) != 1) {
		DPAA2_ERR(FW, "vfio: error reading %s: %m\n", path);
		return DPAA2_FAILURE;
	}

	DPAA2_INFO(FW, "vfio: IOMMU group_id = %d\n", groupid);

	/* Check if group already exists */
	for (i = 0; i < VFIO_MAX_GRP; i++) {
		group = &vfio_groups[i];
		if (group->groupid == groupid) {
			DPAA2_WARN(FW, "groupid already exists %d\n", groupid);
			return DPAA2_SUCCESS;
		}
	}

	if (DPAA2_SUCCESS != vfio_set_group(group, groupid)) {
		DPAA2_ERR(FW, "group setup failure - %d\n", groupid);
		return DPAA2_FAILURE;
	}

	/* Get Device information */
	ret = ioctl(group->fd, VFIO_GROUP_GET_DEVICE_FD, vfio_container);
	if (ret < 0) {
		DPAA2_ERR(FW, "\tvfio: error getting device %s fd from group %d\n",
			vfio_container, group->groupid);
		goto fail;
	}
	container_device_fd = ret;
	DPAA2_INFO(FW, "vfio: Container FD is [0x%X]n", container_device_fd);

	/* Set up SMMU */
	if (setup_dmamap()) {
		goto fail;
	}

	return DPAA2_SUCCESS;
fail:
	vfio_put_group(group);
	return DPAA2_FAILURE;
};

void destroy_vfio_group(struct vfio_group *group)
{
	/* Remove DMAMAP Settings */
	if (group->container)
		destroy_dmamap();

	vfio_put_group(group);

	if (group->vfio_device)
		dpaa2_free(group->vfio_device);
}


int64_t vfio_map_mcp_obj(struct vfio_group *group, char *mcp_obj)
{
	int64_t v_addr = (int64_t)MAP_FAILED;
	int32_t ret, mc_fd;

	struct vfio_device_info d_info = { .argsz = sizeof(d_info) };
	struct vfio_region_info reg_info = { .argsz = sizeof(reg_info) };

	DPAA2_INFO(FW, "\t MCP object = %s\n", mcp_obj);

	/* getting the mcp object's fd*/
	mc_fd = ioctl(group->fd, VFIO_GROUP_GET_DEVICE_FD, mcp_obj);
	if (mc_fd < 0) {
		DPAA2_ERR(FW, "\tvfio: error getting device %s fd from group %d\n",
				mcp_obj, group->fd);
		return v_addr;
	}

	/* getting device info*/
	ret = ioctl(mc_fd, VFIO_DEVICE_GET_INFO, &d_info);
	if (ret < 0) {
		DPAA2_ERR(FW, "\tvfio: error getting DEVICE_INFO\n");
		goto MC_FAILURE;
	}

	/* getting device region info*/
	ret = ioctl(mc_fd, VFIO_DEVICE_GET_REGION_INFO, &reg_info);
	if (ret < 0) {
		DPAA2_ERR(FW, "\tvfio: error getting REGION_INFO\n");
		goto MC_FAILURE;
	}

	DPAA2_INFO(FW, "region offset = %llx  , region size = %llx\n",
			reg_info.offset, reg_info.size);

	v_addr = (uint64_t)mmap(NULL, reg_info.size,
		PROT_WRITE | PROT_READ, MAP_SHARED,
		mc_fd, reg_info.offset);

MC_FAILURE:
	close(mc_fd);

	return v_addr;
}
