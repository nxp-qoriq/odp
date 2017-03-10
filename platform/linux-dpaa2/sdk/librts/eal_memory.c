/*   Derived from DPDK's eal_memory.h
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*   BSD LICENSE
 *
 *   Copyright(c) 2013 6WIND.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of 6WIND S.A. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <odp/api/std_types.h>
#include <dpaa2_log.h>
#include <dpaa2_common.h>
#include <dpaa2_memory.h>
#include <dpaa2_memzone.h>
#include <dpaa2_memconfig.h>
#include <dpaa2_string_fns.h>
#include <dpaa2_internal.h>
#include <odp_debug_internal.h>

/*FIXME */
#include <eal_internal_cfg.h>
#include "eal_filesystem.h"
#include "eal_hugepages.h"

#include <dpaa2_mpool.h>

#define DPAA2_DEFAULT_DATA_MEM_SIZE	(32 * 1024 * 1024)	/*32 MB*/

/**
 * @file
 * Huge page mapping under linux
 *
 * To reserve a big contiguous amount of memory, we use the hugepage
 * feature of linux. For that, we need to have hugetlbfs mounted. This
 * code will create many files in this directory (one per page) and
 * map them in virtual memory. For each page, we will retrieve its
 * physical address and remap it in order to have a virtual contiguous
 * zone as well as a physical contiguous zone.
 */

static uint64_t baseaddr_offset;
struct hugepage_file *hugepage;
int nr_hugefiles;

/*
 * For each hugepage in hugepg_tbl, fill the physaddr value. We find
 * it by browsing the /proc/self/pagemap special file.
 */
static int
find_physaddrs(struct hugepage_file *hugepg_tbl, struct hugepage_info *hpi)
{
	unsigned i;
	phys_addr_t addr;

	for (i = 0; i < hpi->num_pages; i++) {
		addr = dpaa2_mem_virt2phy(hugepg_tbl[i].orig_va);
		if (addr == DPAA2_BAD_PHYS_ADDR)
			return -1;
		hugepg_tbl[i].physaddr = addr;
	}
	return 0;
}

/*
 * Try to mmap *size bytes in /dev/zero. If it is succesful, return the
 * pointer to the mmap'd area and keep *size unmodified. Else, retry
 * with a smaller zone: decrease *size by hugepage_sz until it reaches
 * 0. In this case, return NULL. Note: this function returns an address
 * which is a multiple of hugepage size.
 */
static void *
get_virtual_area(size_t *size, size_t hugepage_sz)
{
	void *addr;
	int fd;
	long aligned_addr;

	if (internal_config.base_virtaddr != 0) {
		addr = (void *) (uintptr_t) (internal_config.base_virtaddr +
				baseaddr_offset);
	} else
		addr = NULL;

	DPAA2_INFO(MEMZONE, "Ask a virtual area of 0x%zx bytes", *size);

	fd = open("/dev/zero", O_RDONLY);
	if (fd < 0) {
		DPAA2_ERR(MEMZONE, "Cannot open /dev/zero\n");
		return NULL;
	}
	do {
		addr = mmap(addr,
				(*size) + hugepage_sz, PROT_READ, MAP_PRIVATE, fd, 0);
		if (addr == MAP_FAILED)
			*size -= hugepage_sz;
	} while (addr == MAP_FAILED && *size > 0);

	if (addr == MAP_FAILED) {
		close(fd);
		DPAA2_INFO(MEMZONE, "Cannot get a virtual area\n");
		return NULL;
	}

	munmap(addr, (*size) + hugepage_sz);
	close(fd);

	/* align addr to a huge page size boundary */
	aligned_addr = (long)addr;
	aligned_addr += (hugepage_sz - 1);
	aligned_addr &= (~(hugepage_sz - 1));
	addr = (void *)(aligned_addr);

	DPAA2_INFO(MEMZONE, "Virtual area found at %p (size = 0x%zx)\n",
		addr, *size);

	/* increment offset */
	baseaddr_offset += *size;

	return addr;
}

/*
 * Mmap all hugepages of hugepage table: it first open a file in
 * hugetlbfs, then mmap() hugepage_sz data in it. If orig is set, the
 * virtual address is stored in hugepg_tbl[i].orig_va, else it is stored
 * in hugepg_tbl[i].final_va. The second mapping (when orig is 0) tries to
 * map continguous physical blocks in contiguous virtual blocks.
 */
static int
map_all_hugepages(struct hugepage_file *hugepg_tbl,
		struct hugepage_info *hpi, int orig)
{
	int fd;
	unsigned i;
	void *virtaddr;
	void *vma_addr = NULL;
	size_t vma_len = 0;

#ifdef DPAA2_EAL_SINGLE_FILE_SEGMENTS
	DPAA2_SET_USED(vma_len);
#endif

	for (i = 0; i < hpi->num_pages; i++) {
		size_t hugepage_sz = hpi->hugepage_sz;

		if (orig) {
			hugepg_tbl[i].file_id = i;
			hugepg_tbl[i].size = hugepage_sz;
#ifdef DPAA2_EAL_SINGLE_FILE_SEGMENTS
			eal_get_hugefile_temp_path(hugepg_tbl[i].filepath,
					sizeof(hugepg_tbl[i].filepath), hpi->hugedir,
					hugepg_tbl[i].file_id);
#else
			eal_get_hugefile_path(hugepg_tbl[i].filepath,
					sizeof(hugepg_tbl[i].filepath), hpi->hugedir,
					hugepg_tbl[i].file_id);
#endif
			hugepg_tbl[i].filepath[sizeof(hugepg_tbl[i].filepath) - 1] = '\0';
		}
#ifndef CONFIG_64BIT
		/* for 32-bit systems, don't remap 1G pages, just reuse original
		 * map address as final map address.
		 */
		else if (hugepage_sz == DPAA2_PGSIZE_1G) {
			hugepg_tbl[i].final_va = hugepg_tbl[i].orig_va;
			hugepg_tbl[i].orig_va = NULL;
			continue;
		}
#endif

#ifndef DPAA2_EAL_SINGLE_FILE_SEGMENTS
		else if (vma_len == 0) {
			unsigned j, num_pages;

			/* reserve a virtual area for next contiguous
			 * physical block: count the number of
			 * contiguous physical pages. */
			for (j = i+1; j < hpi->num_pages ; j++) {
				if (hugepg_tbl[j].physaddr !=
				    hugepg_tbl[j-1].physaddr + hugepage_sz)
					break;
			}
			num_pages = j - i;
			vma_len = num_pages * hugepage_sz;

			/* get the biggest virtual memory area up to
			 * vma_len. If it fails, vma_addr is NULL, so
			 * let the kernel provide the address. */
			vma_addr = get_virtual_area(&vma_len, hpi->hugepage_sz);
			if (vma_addr == NULL)
				vma_len = hugepage_sz;
		}
#endif

		/* try to create hugepage file */
		fd = open(hugepg_tbl[i].filepath, O_CREAT | O_RDWR, 0755);

		if (fd < 0) {
			DPAA2_ERR(MEMZONE, "%s(): open failed: %s\n", __func__,
					strerror(errno));
			return -1;
		}

		virtaddr = mmap(vma_addr, hugepage_sz, PROT_READ | PROT_WRITE,
				MAP_SHARED, fd, 0);
		if (virtaddr == MAP_FAILED) {
			DPAA2_ERR(MEMZONE, "%s(): mmap failed: %s\n", __func__,
					strerror(errno));
			close(fd);
			return -1;
		}

		if (orig) {
			hugepg_tbl[i].orig_va = virtaddr;
			memset(virtaddr, 0, hugepage_sz);
		} else {
			hugepg_tbl[i].final_va = virtaddr;
		}

		/* set shared flock on the file. */
		if (flock(fd, LOCK_SH | LOCK_NB) == -1) {
			DPAA2_ERR(MEMZONE, "%s(): Locking file failed:%s \n",
				__func__, strerror(errno));
			close(fd);
			return -1;
		}

		close(fd);

		vma_addr = (char *)vma_addr + hugepage_sz;
		vma_len -= hugepage_sz;
	}
	return 0;
}

#ifdef DPAA2_EAL_SINGLE_FILE_SEGMENTS

/*
 * Remaps all hugepages into single file segments
 */
static int
remap_all_hugepages(struct hugepage_file *hugepg_tbl, struct hugepage_info *hpi)
{
	int fd;
	unsigned i = 0, j, num_pages, page_idx = 0;
	void *vma_addr = NULL, *old_addr = NULL, *page_addr = NULL;
	size_t vma_len = 0;
	size_t hugepage_sz = hpi->hugepage_sz;
	size_t total_size, offset;
	char filepath[MAX_HUGEPAGE_PATH];
	phys_addr_t physaddr;
	int socket;

	while (i < hpi->num_pages) {

#ifndef CONFIG_64BIT
		/* for 32-bit systems, don't remap 1G pages, just reuse original
		 * map address as final map address.
		 */
		if (hugepage_sz == DPAA2_PGSIZE_1G) {
			hugepg_tbl[i].final_va = hugepg_tbl[i].orig_va;
			hugepg_tbl[i].orig_va = NULL;
			i++;
			continue;
		}
#endif

		/* reserve a virtual area for next contiguous
		 * physical block: count the number of
		 * contiguous physical pages. */
		for (j = i+1; j < hpi->num_pages; j++) {
			if (hugepg_tbl[j].physaddr != hugepg_tbl[j-1].physaddr + hugepage_sz)
				break;
		}
		num_pages = j - i;
		vma_len = num_pages * hugepage_sz;

		/* get the biggest virtual memory area up to
		 * vma_len. If it fails, vma_addr is NULL, so
		 * let the kernel provide the address. */
		vma_addr = get_virtual_area(&vma_len, hpi->hugepage_sz);

		/* If we can't find a big enough virtual area, work out how many pages
		 * we are going to get */
		if (vma_addr == NULL)
			j = i + 1;
		else if (vma_len != num_pages * hugepage_sz) {
			num_pages = vma_len / hugepage_sz;
			j = i + num_pages;

		}

		hugepg_tbl[page_idx].file_id = page_idx;
		eal_get_hugefile_path(filepath,
				sizeof(filepath),
				hpi->hugedir,
				hugepg_tbl[page_idx].file_id);

		/* try to create hugepage file */
		fd = open(filepath, O_CREAT | O_RDWR, 0755);
		if (fd < 0) {
			DPAA2_ERR(MEMZONE, "%s(): open failed: %s\n", __func__, strerror(errno));

			return -1;
		}

		total_size = 0;
		for (; i < j; i++) {

			/* unmap current segment */
			if (total_size > 0)
				munmap(vma_addr, total_size);

			/* unmap original page */
			munmap(hugepg_tbl[i].orig_va, hugepage_sz);
			unlink(hugepg_tbl[i].filepath);

			total_size += hugepage_sz;

			old_addr = vma_addr;

			/* map new, bigger segment */
			vma_addr = mmap(vma_addr, total_size,
					PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

			if (vma_addr == MAP_FAILED || vma_addr != old_addr) {
				DPAA2_ERR(MEMZONE, "%s(): mmap failed: %s\n", __func__, strerror(errno));
				close(fd);
				return -1;
			}

			/* touch the page. this is needed because kernel postpones mapping
			 * creation until the first page fault. with this, we pin down
			 * the page and it is marked as used and gets into process' pagemap.
			 */
			for (offset = 0; offset < total_size; offset += hugepage_sz)
				*((volatile uint8_t *) DPAA2_PTR_ADD(vma_addr, offset));
		}

		/* set shared flock on the file. */
		if (flock(fd, LOCK_SH | LOCK_NB) == -1) {
			DPAA2_ERR(MEMZONE, "%s(): Locking file failed:%s \n",
				__func__, strerror(errno));
			close(fd);
			return -1;
		}

		dpaa2_snprintf(hugepg_tbl[page_idx].filepath, MAX_HUGEPAGE_PATH, "%s",
				filepath);

		physaddr = dpaa2_mem_virt2phy(vma_addr);

		if (physaddr == DPAA2_BAD_PHYS_ADDR)
			return -1;

		hugepg_tbl[page_idx].final_va = vma_addr;

		hugepg_tbl[page_idx].physaddr = physaddr;

		hugepg_tbl[page_idx].repeated = num_pages;

		close(fd);

		/* verify the memory segment - that is, check that every VA corresponds
		 * to the physical address we expect to see
		 */
		for (offset = 0; offset < vma_len; offset += hugepage_sz) {
			uint64_t expected_physaddr;

			expected_physaddr = hugepg_tbl[page_idx].physaddr + offset;
			page_addr = DPAA2_PTR_ADD(vma_addr, offset);
			physaddr = dpaa2_mem_virt2phy(page_addr);

			if (physaddr != expected_physaddr) {
				DPAA2_ERR(MEMZONE, "Segment sanity check failed: wrong physaddr "
						"at %p (offset 0x%" PRIx64 ": 0x%" PRIx64
						" (expected 0x%" PRIx64 ")\n",
						page_addr, offset, physaddr, expected_physaddr);
				return -1;
			}
		}

		/* zero out the whole segment */
		memset(hugepg_tbl[page_idx].final_va, 0, total_size);

		page_idx++;
	}

	/* zero out the rest */
	memset(&hugepg_tbl[page_idx], 0, (hpi->num_pages - page_idx) * sizeof(struct hugepage_file));
	return page_idx;
}
#else/* DPAA2_EAL_SINGLE_FILE_SEGMENTS=n */

/* Unmap all hugepages from original mapping */
static int
unmap_all_hugepages_orig(struct hugepage_file *hugepg_tbl, struct hugepage_info *hpi)
{
	unsigned i;
	for (i = 0; i < hpi->num_pages; i++) {
		if (hugepg_tbl[i].orig_va) {
			munmap(hugepg_tbl[i].orig_va, hpi->hugepage_sz);
			hugepg_tbl[i].orig_va = NULL;
		}
	}
	return 0;
}
#endif /* DPAA2_EAL_SINGLE_FILE_SEGMENTS */

/*
 * Sort the hugepg_tbl by physical address (lower addresses first). We
 * use a slow algorithm, but we won't have millions of pages, and this
 * is only done at init time.
 */
static int
sort_by_physaddr(struct hugepage_file *hugepg_tbl, struct hugepage_info *hpi)
{
	unsigned i, j;
	int smallest_idx;
	uint64_t smallest_addr;
	struct hugepage_file tmp;

	for (i = 0; i < hpi->num_pages; i++) {
		smallest_addr = 0;
		smallest_idx = -1;

		/*
		 * browse all entries starting at 'i', and find the
		 * entry with the smallest addr
		 */
		for (j = i; j < hpi->num_pages; j++) {

			if (smallest_addr == 0 ||
			    hugepg_tbl[j].physaddr < smallest_addr) {
				smallest_addr = hugepg_tbl[j].physaddr;
				smallest_idx = j;
			}
		}

		/* should not happen */
		if (smallest_idx == -1) {
			DPAA2_ERR(MEMZONE, "%s(): error in physaddr sorting\n", __func__);
			return -1;
		}

		/* swap the 2 entries in the table */
		memcpy(&tmp, &hugepg_tbl[smallest_idx], sizeof(struct hugepage_file));
		memcpy(&hugepg_tbl[smallest_idx], &hugepg_tbl[i],
				sizeof(struct hugepage_file));
		memcpy(&hugepg_tbl[i], &tmp, sizeof(struct hugepage_file));
	}
	return 0;
}

/*
 * Uses mmap to create a shared memory area for storage of data
 * Used in this file to store the hugepage file map on disk
 */
static void *
create_shared_memory(const char *filename, const size_t mem_size)
{
	void *retval;
	int fd = open(filename, O_CREAT | O_RDWR, 0666);
	if (fd < 0)
		return NULL;
	if (ftruncate(fd, mem_size) < 0) {
		close(fd);
		return NULL;
	}
	retval = mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	return retval;
}

/*
 * this copies *active* hugepages from one hugepage table to another.
 * destination is typically the shared memory.
 */
static int
copy_hugepages_to_shared_mem(struct hugepage_file *dst, int dest_size,
		const struct hugepage_file *src, int src_size)
{
	int src_pos, dst_pos = 0;

	for (src_pos = 0; src_pos < src_size; src_pos++) {
		if (src[src_pos].final_va != NULL) {
			/* error on overflow attempt */
			if (dst_pos == dest_size)
				return -1;
			memcpy(&dst[dst_pos], &src[src_pos], sizeof(struct hugepage_file));
			dst_pos++;
		}
	}
	return 0;
}

/*
 * unmaps hugepages that are not going to be used. since we originally allocate
 * ALL hugepages (not just those we need), additional unmapping needs to be done.
 */
static int
unmap_unneeded_hugepages(struct hugepage_file *hugepg_tbl,
		struct hugepage_info *hpi,
		unsigned num_hp_info)
{
	unsigned size;
	int page, nrpages = 0;

	/* get total number of hugepages */
	for (size = 0; size < num_hp_info; size++)
		nrpages += internal_config.hugepage_info[size].num_pages;

	for (size = 0; size < num_hp_info; size++) {
		unsigned pages_found = 0;

		/* traverse until we have unmapped all the unused pages */
		for (page = 0; page < nrpages; page++) {
			struct hugepage_file *hp = &hugepg_tbl[page];

#ifdef DPAA2_EAL_SINGLE_FILE_SEGMENTS
			/* if this page was already cleared */
			if (hp->final_va == NULL)
				continue;
#endif

			/* find a page that matches the criteria */
			if ((hp->size == hpi[size].hugepage_sz)) {

				/* if we skipped enough pages, unmap the rest */
				if (pages_found == hpi[size].num_pages) {
					uint64_t unmap_len;

#ifdef DPAA2_EAL_SINGLE_FILE_SEGMENTS
					unmap_len = hp->size * hp->repeated;
#else
					unmap_len = hp->size;
#endif

					/* get start addr and len of the remaining segment */
					munmap(hp->final_va, (size_t) unmap_len);

					hp->final_va = NULL;
					if (unlink(hp->filepath) == -1) {
						DPAA2_ERR(MEMZONE, "%s(): Removing %s failed: %s\n",
								__func__, hp->filepath, strerror(errno));
						return -1;
					}
				}
#ifdef DPAA2_EAL_SINGLE_FILE_SEGMENTS
				/* else, check how much do we need to map */
				else {
					int nr_pg_left =
							hpi[size].num_pages - pages_found;

					/* if we need enough memory to fit into the segment */
					if (hp->repeated <= nr_pg_left) {
						pages_found += hp->repeated;
					}
					/* truncate the segment */
					else {
						uint64_t final_size = nr_pg_left * hp->size;
						uint64_t seg_size = hp->repeated * hp->size;

						void *unmap_va = DPAA2_PTR_ADD(hp->final_va,
								final_size);
						int fd;

						munmap(unmap_va, seg_size - final_size);

						fd = open(hp->filepath, O_RDWR);
						if (fd < 0) {
							DPAA2_ERR(MEMZONE, "Cannot open %s: %s\n",
									hp->filepath, strerror(errno));
							return -1;
						}
						if (ftruncate(fd, final_size) < 0) {
							DPAA2_ERR(MEMZONE, "Cannot truncate %s: %s\n",
									hp->filepath, strerror(errno));
							return -1;
						}
						close(fd);

						pages_found += nr_pg_left;
						hp->repeated = nr_pg_left;
					}
				}
#else
				/* else, lock the page and skip */
				else
					pages_found++;
#endif

			} /* match page */
		} /* foreach page */
	} /* foreach pagesize */

	return 0;
}

/*
 * This function is a NUMA-aware equivalent of calc_num_pages.
 * It takes in the list of hugepage sizes and the
 * number of pages thereof, and calculates the best number of
 * pages of each size to fulfill the request for <memory> ram
 */
static int
calc_num_pages_per_socket(uint64_t memory,
		struct hugepage_info *hp_info,
		struct hugepage_info *hp_used,
		unsigned num_hp_info)
{
	unsigned j, i = 0;
	unsigned requested, available;
	int total_num_pages = 0;
	uint64_t remaining_mem, cur_mem;
	uint64_t total_mem = internal_config.memory;

	if (num_hp_info == 0)
		return -1;

		/* skips if the memory on specific socket wasn't requested */
	for (i = 0; i < num_hp_info && memory != 0; i++) {
		hp_used[i].hugedir = hp_info[i].hugedir;
		hp_used[i].num_pages = DPAA2_MIN(memory/hp_info[i].hugepage_sz,
				hp_info[i].num_pages);

		cur_mem = hp_used[i].num_pages * hp_used[i].hugepage_sz;

		memory -= cur_mem;
		total_mem -= cur_mem;

		total_num_pages += hp_used[i].num_pages;

		/* check if we have met all memory requests */
		if (memory == 0)
			break;

		/* check if we have any more pages left at this size, if so
		 * move on to next size */
		if (hp_used[i].num_pages == hp_info[i].num_pages)
			continue;
		/* At this point we know that there are more pages available that are
		 * bigger than the memory we want, so lets see if we can get enough
		 * from other page sizes.
		 */
		remaining_mem = 0;
		for (j = i+1; j < num_hp_info; j++)
			remaining_mem += hp_info[j].hugepage_sz *
			hp_info[j].num_pages;

		/* is there enough other memory, if not allocate another page and quit */
		if (remaining_mem < memory) {
			cur_mem = DPAA2_MIN(memory, hp_info[i].hugepage_sz);
			memory -= cur_mem;
			total_mem -= cur_mem;
			hp_used[i].num_pages++;
			total_num_pages++;
			break; /* we are done with this socket*/
		}
	}
	/* if we didn't satisfy all memory requirements per socket */
	if (memory > 0) {
		/* to prevent icc errors */
		requested = (unsigned) (internal_config.max_mem /
				0x100000);
		available = requested -
				((unsigned) (memory / 0x100000));
		DPAA2_NOTE(MEMZONE, "Not enough memory available ! "
				"Requested: %uMB, available: %uMB\n",
				requested, available);
		return -1;
	}

	/* if we didn't satisfy total memory requirements */
	if (total_mem > 0) {
		requested = (unsigned) (internal_config.memory / 0x100000);
		available = requested - (unsigned) (total_mem / 0x100000);
		DPAA2_NOTE(MEMZONE, "Not enough memory available! Requested: %uMB,"
				" available: %uMB\n", requested, available);
		return -1;
	}
	return total_num_pages;
}

static inline size_t
eal_get_hugepage_mem_size(void)
{
	uint64_t size = 0;
	unsigned i;

	for (i = 0; i < internal_config.num_hugepage_sizes; i++) {
		struct hugepage_info *hpi = &internal_config.hugepage_info[i];
		/*if (hpi->hugedir != NULL) */{
			size += hpi->hugepage_sz * hpi->num_pages;
		}
	}

	return (size < SIZE_MAX) ? (size_t)(size) : SIZE_MAX;
}

/*
 * Prepare physical memory mapping: fill configuration structure with
 * these infos, return 0 on success.
 *  1. map N huge pages in separate files in hugetlbfs
 *  2. find associated physical addr
 *  3. sort all huge pages by physical address
 *  4. remap these N huge pages in the correct order
 *  5. unmap the first mapping
 *  6. fill memsegs in configuration with contiguous zones
 */
static int
dpaa2_eal_hugepage_init(struct dpaa2_init_cfg *cfg)
{
	struct dpaa2_mem_config *mcfg;
	struct hugepage_file *tmp_hp = NULL;
	struct hugepage_info used_hp[MAX_HUGEPAGE_SIZES];
	uint64_t memory;
	unsigned hp_offset;
	int i, j, new_memseg;
	int nr_hugepages = 0;
	void *addr;
#ifdef DPAA2_EAL_SINGLE_FILE_SEGMENTS
	int new_pages_count[MAX_HUGEPAGE_SIZES];
#endif

	memset(used_hp, 0, sizeof(used_hp));

	/* get pointer to global configuration */
	mcfg = dpaa2_eal_get_configuration()->mem_config;

	/* hugetlbfs can be disabled */
	if (internal_config.no_hugetlbfs) {
		if(!internal_config.memory) {
			addr = malloc(DPAA2_DEFAULT_DATA_MEM_SIZE);
			internal_config.memory = DPAA2_DEFAULT_DATA_MEM_SIZE;
			/* At init time, all memory is free memory */
			internal_config.free_memory = DPAA2_DEFAULT_DATA_MEM_SIZE;
		} else
			addr = malloc(internal_config.memory);
		mcfg->memseg[0].phys_addr = (phys_addr_t)(uintptr_t)addr;
		mcfg->memseg[0].addr = addr;
		mcfg->memseg[0].len = internal_config.memory;
		return 0;
	}

	/* calculate total number of hugepages available.*/
	for (i = 0; i < (int) internal_config.num_hugepage_sizes; i++) {
		/* meanwhile, also initialize used_hp hugepage sizes in used_hp */
		used_hp[i].hugepage_sz = internal_config.hugepage_info[i].hugepage_sz;
		nr_hugepages += internal_config.hugepage_info[i].num_pages;
	}

	/*
	 * allocate a memory area for hugepage table.
	 * this isn't shared memory yet. due to the fact that we need some
	 * processing done on these pages, shared memory will be created
	 * at a later stage.
	 */
	tmp_hp = malloc(nr_hugepages * sizeof(struct hugepage_file));
	if (tmp_hp == NULL)
		goto fail;

	memset(tmp_hp, 0, nr_hugepages * sizeof(struct hugepage_file));

	hp_offset = 0; /* where we start the current page size entries */

	/* map all hugepages and sort them */
	for (i = 0; i < (int)internal_config.num_hugepage_sizes; i++) {
		struct hugepage_info *hpi;

		/*
		 * we don't yet mark hugepages as used at this stage, so
		 * we just map all hugepages available to the system
		 * all hugepages are still located on socket 0
		 */
		hpi = &internal_config.hugepage_info[i];

		if (hpi->num_pages == 0)
			continue;

		/* map all hugepages available */
		if (map_all_hugepages(&tmp_hp[hp_offset], hpi, 1) < 0) {
			DPAA2_DBG(MEMZONE, "Failed to mmap %u MB hugepages\n",
					(unsigned)(hpi->hugepage_sz / 0x100000));
			goto fail;
		}

		/* find physical addresses and sockets for each hugepage */
		if (find_physaddrs(&tmp_hp[hp_offset], hpi) < 0) {
			DPAA2_DBG(MEMZONE, "Failed to find phys addr for %u MB pages\n",
					(unsigned)(hpi->hugepage_sz / 0x100000));
			goto fail;
		}

		if (sort_by_physaddr(&tmp_hp[hp_offset], hpi) < 0)
			goto fail;

#ifdef DPAA2_EAL_SINGLE_FILE_SEGMENTS
		/* remap all hugepages into single file segments */
		new_pages_count[i] = remap_all_hugepages(&tmp_hp[hp_offset], hpi);
		if (new_pages_count[i] < 0) {
			DPAA2_DBG(MEMZONE, "Failed to remap %u MB pages\n",
					(unsigned)(hpi->hugepage_sz / 0x100000));
			goto fail;
		}

		/* we have processed a num of hugepages of this size, so inc offset */
		hp_offset += new_pages_count[i];
#else
		/* remap all hugepages */
		if (map_all_hugepages(&tmp_hp[hp_offset], hpi, 0) < 0) {
			DPAA2_DBG(MEMZONE, "Failed to remap %u MB pages\n",
					(unsigned)(hpi->hugepage_sz / 0x100000));
			goto fail;
		}

		/* unmap original mappings */
		if (unmap_all_hugepages_orig(&tmp_hp[hp_offset], hpi) < 0)
			goto fail;

		/* we have processed a num of hugepages of this size, so inc offset */
		hp_offset += hpi->num_pages;
#endif
	}

#ifdef DPAA2_EAL_SINGLE_FILE_SEGMENTS
	nr_hugefiles = 0;
	for (i = 0; i < (int) internal_config.num_hugepage_sizes; i++) {
		nr_hugefiles += new_pages_count[i];
	}
#else
	nr_hugefiles = nr_hugepages;
#endif


	/* clean out the numbers of pages */
	for (i = 0; i < (int) internal_config.num_hugepage_sizes; i++)
		internal_config.hugepage_info[i].num_pages = 0;

	/* get hugepages for each socket */
	for (i = 0; i < nr_hugefiles; i++) {
		/* find a hugepage info with right size and increment num_pages */
		for (j = 0; j < (int) internal_config.num_hugepage_sizes; j++) {
			if (tmp_hp[i].size ==
					internal_config.hugepage_info[j].hugepage_sz) {
#ifdef DPAA2_EAL_SINGLE_FILE_SEGMENTS
					internal_config.hugepage_info[j].num_pages +=
						tmp_hp[i].repeated;
#else
				internal_config.hugepage_info[j].num_pages++;
#endif
			}
		}
	}

	memory = eal_get_hugepage_mem_size();

	/*if enough huge pages are not available as desired by app */
	if (cfg->data_mem_size > memory) {
		DPAA2_ERR(MEMZONE,
			 "Requesting %lu size, avaialable only %lu\n",
			cfg->data_mem_size, eal_get_hugepage_mem_size());
		goto fail;
	}

	/*FIXME  */
	if(!cfg->data_mem_size) {
		internal_config.max_mem = memory;
		internal_config.memory = memory;
		/* At init time, all memory is free memory */
		internal_config.free_memory = memory;
	} else
		internal_config.max_mem = cfg->data_mem_size;

	/* make a copy of max_mem, needed for number of pages calculation */
	memory = internal_config.max_mem;

	/* calculate final number of pages */
	nr_hugepages = calc_num_pages_per_socket(memory,
			internal_config.hugepage_info, used_hp,
			internal_config.num_hugepage_sizes);

	/* error if not enough memory available */
	if (nr_hugepages <= 0)
		goto fail;

	/* reporting in! */
	for (i = 0; i < (int) internal_config.num_hugepage_sizes; i++) {
		if (used_hp[i].num_pages > 0) {
			DPAA2_INFO(MEMZONE,
				"Requesting %u pages of size %uMB\n",
				used_hp[i].num_pages,
				(unsigned)(used_hp[i].hugepage_sz / 0x100000));
		}
	}

	/* create shared memory */
	hugepage = create_shared_memory(eal_hugepage_info_path(),
			nr_hugefiles * sizeof(struct hugepage_file));

	if (hugepage == NULL) {
		DPAA2_ERR(MEMZONE, "Failed to create shared memory!\n");
		goto fail;
	}
	memset(hugepage, 0, nr_hugefiles * sizeof(struct hugepage_file));

	/*
	 * unmap pages that we won't need (looks at used_hp).
	 * also, sets final_va to NULL on pages that were unmapped.
	 */
	if (unmap_unneeded_hugepages(tmp_hp, used_hp,
			internal_config.num_hugepage_sizes) < 0) {
		DPAA2_ERR(MEMZONE, "Unmapping and locking hugepages failed!\n");
		goto fail;
	}

	/*
	 * copy stuff from malloc'd hugepage* to the actual shared memory.
	 * this procedure only copies those hugepages that have final_va
	 * not NULL. has overflow protection.
	 */
	if (copy_hugepages_to_shared_mem(hugepage, nr_hugefiles,
			tmp_hp, nr_hugefiles) < 0) {
		DPAA2_ERR(MEMZONE, "Copying tables to shared memory failed!\n");
		goto fail;
	}

	/* free the temporary hugepage table */
	free(tmp_hp);
	tmp_hp = NULL;

	/* find earliest free memseg - this is needed because in case of IVSHMEM,
	 * segments might have already been initialized */
	for (j = 0; j < DPAA2_MAX_MEMSEG; j++)
		if (mcfg->memseg[j].addr == NULL) {
			/* move to previous segment and exit loop */
			j--;
			break;
		}

	for (i = 0; i < nr_hugefiles; i++) {
		new_memseg = 0;

		/* if this is a new section, create a new memseg */
		if (i == 0)
			new_memseg = 1;
		else if (hugepage[i].size != hugepage[i-1].size)
			new_memseg = 1;
		else if ((hugepage[i].physaddr - hugepage[i-1].physaddr) !=
		    hugepage[i].size)
			new_memseg = 1;
		else if (((unsigned long)hugepage[i].final_va -
		    (unsigned long)hugepage[i-1].final_va) != hugepage[i].size)
			new_memseg = 1;

		if (new_memseg) {

			if (j == DPAA2_MAX_MEMSEG)
				break;
			j += 1;

			mcfg->memseg[j].phys_addr = hugepage[i].physaddr;
			mcfg->memseg[j].addr = hugepage[i].final_va;
#ifdef DPAA2_EAL_SINGLE_FILE_SEGMENTS
			mcfg->memseg[j].len = hugepage[i].size * hugepage[i].repeated;
#else
			mcfg->memseg[j].len = hugepage[i].size;
#endif
			mcfg->memseg[j].hugepage_sz = hugepage[i].size;
		}
		/* continuation of previous memseg */
		else {
			mcfg->memseg[j].len += mcfg->memseg[j].hugepage_sz;
		}
		hugepage[i].memseg_id = j;
	}

	if (i < nr_hugefiles) {
		DPAA2_ERR(MEMZONE, "Can only reserve %d pages "
			"from %d requested\n"
			"Current %s=%d is not enough\n"
			"Please either increase it or request less amount "
			"of memory.\n",
			i, nr_hugefiles, DPAA2_STR(CONFIG_DPAA2_MAX_MEMSEG),
			DPAA2_MAX_MEMSEG);
		return (-ENOMEM);
	}

	return 0;

fail:
	if (tmp_hp)
		free(tmp_hp);
	return -1;
}


int
dpaa2_eal_hugepage_exit(void)
{
	int i;

	if (!hugepage)
		return 0;
	for (i = 0; (i < nr_hugefiles); i++) {

		/* Already Unmapped, then continue*/
		if (hugepage[i].final_va == 0)
			continue;

		mprotect(hugepage[i].final_va, (size_t) hugepage[i].size, PROT_NONE);

		/* Unmap the hugepage from the final va*/
		munmap(hugepage[i].final_va, hugepage[i].size);
		hugepage[i].final_va = NULL;

		/* Unlinking the hugefile*/
		if (unlink(hugepage[i].filepath) == -1) {
			DPAA2_ERR(MEMZONE, "%s(): Removing %s failed: %s\n",
						__func__, hugepage[i].filepath,
						strerror(errno));
			return -1;
		}
	}

	/* Clear the hugepage table*/
	memset(hugepage, 0, nr_hugefiles * sizeof(struct hugepage_file));
	munmap(hugepage, nr_hugefiles * sizeof(struct hugepage_file));

	return 0;
}

int
dpaa2_eal_memory_exit(void)
{
	struct dpaa2_mem_config *mcfg;
	struct dpaa2_memseg *memseg;
	struct dpaa2_memseg *free_memseg;
	struct malloc_heap *malloc_heaps;
	struct dpaa2_tailq_head *dpaa2_tailq_head;

	mcfg = dpaa2_eal_get_configuration()->mem_config;
	memseg = mcfg->memseg;
	malloc_heaps = mcfg->malloc_heaps;
	dpaa2_tailq_head = mcfg->tailq_head;
	free_memseg = mcfg->free_memseg;

	RWLOCK_RLOCK(mcfg->mlock);

	memset(memseg, 0, sizeof(*memseg));
	memset(malloc_heaps, 0, sizeof(*malloc_heaps));
	memset(dpaa2_tailq_head, 0, sizeof(*dpaa2_tailq_head));
	memset(free_memseg, 0, sizeof(*free_memseg));

	RWLOCK_RUNLOCK(mcfg->mlock);

	return 0;
}

/* init memory subsystem */
int
dpaa2_eal_memory_init(struct dpaa2_init_cfg *cfg)
{
	int i, retval;
	struct dpaa2_mem_config *mcfg;

	DPAA2_INFO(MEMZONE, "Setting up memory...\n");

	retval = dpaa2_eal_hugepage_init(cfg);
	if (retval < 0) {
		DPAA2_ERR(MEMZONE, "error in hugepage init");
		return -1;
	}

	mcfg = dpaa2_eal_get_configuration()->mem_config;
	for (i = 0; i < DPAA2_MAX_HEAPS; i++)
		odp_spinlock_init(&(mcfg->malloc_heaps[i].lock));

	return 0;
}
