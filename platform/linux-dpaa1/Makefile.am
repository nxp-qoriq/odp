#include $(top_srcdir)/Makefile.inc
include $(top_srcdir)/platform/Makefile.inc
include $(top_srcdir)/platform/@with_platform@/Makefile.inc


if BUILD_LS1043
SOC=LS1043
PLAT_CFLAGS = -D$(SOC)
FMD_CFLAGS = -D$(SOC) -DNCSW_LINUX
QBMAN_CFLAGS = -DCONFIG_ARM64
FMLIB = fm-arm64a53
USDPAA_LIB_PATH = lib_arm64
LIB_PATH = lib
SPEC_CFLAGS =
endif
if BUILD_LS1046
SOC=LS1046
PLAT_CFLAGS = -D$(SOC)
FMD_CFLAGS = -DLS1043 -DNCSW_LINUX
QBMAN_CFLAGS = -DCONFIG_ARM64
FMLIB = fm-arm64a72
USDPAA_LIB_PATH = lib_arm64
LIB_PATH = lib
SPEC_CFLAGS =
endif
if P4_SOC
SOC=P4080
PLAT_CFLAGS = -D$(SOC)
FMD_CFLAGS = -D$(SOC) -DNCSW_LINUX
QBMAN_CFLAGS =
FMLIB = fm-ppce500mc
USDPAA_LIB_PATH = lib_powerpc
LIB_PATH = lib
SPEC_CFLAGS =
endif
if T1_SOC
SOC=T1040
PLAT_CFLAGS = -D$(SOC)
FMD_CFLAGS = -DFMAN_V3L -DNCSW_LINUX
QBMAN_CFLAGS =
FMLIB = fm-ppc64e5500-fmv3l
USDPAA_LIB_PATH = lib_powerpc64
LIB_PATH = lib64
SPEC_CFLAGS = -m64 -mhard-float -mcpu=e5500
endif
if T4_SOC
SOC=T4240
PLAT_CFLAGS = -D$(SOC)
FMD_CFLAGS = -DFMAN_V3H -DNCSW_LINUX
QBMAN_CFLAGS =
FMLIB = fm-ppc64e6500
USDPAA_LIB_PATH = lib_powerpc64
LIB_PATH = lib64
SPEC_CFLAGS = -m64 -mhard-float -mcpu=e6500
endif

AM_CFLAGS +=  $(PLAT_CFLAGS)
AM_CFLAGS +=  -D_GNU_SOURCE $(SPEC_CFLAGS)
AM_CFLAGS +=  $(QBMAN_CFLAGS) $(FMD_CFLAGS)
AM_CFLAGS += -std=gnu99
AM_CFLAGS +=  -I$(srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include/odp
AM_CFLAGS +=  -I$(top_srcdir)/helper/include

AM_CFLAGS +=  -I$(srcdir)/../linux-generic/include
AM_CFLAGS +=  -I$(srcdir)/../linux-generic/include/api
AM_CFLAGS +=  -I$(srcdir)/../linux-generic/arch/@ARCH_DIR@/

AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa1/include/odp/api/plat/sdk/
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa1/include/odp/api/plat/sdk/usdpaa
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa1/include/odp/api/plat/sdk/usdpaa/usdpaa
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa1/include/odp/api/plat/sdk/usdpaa/fsl_sec
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa1/include/odp/api/plat/sdk/usdpaa/syscfg
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa1/flib/include/
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa1/flib/rta

AM_CFLAGS += -Wno-cast-qual -Wno-pointer-arith

if SDK_INSTALL_PATH_
AM_CFLAGS    += -I$(SDK_INSTALL_PATH)/usr/include/fmd
AM_CFLAGS    += -I$(SDK_INSTALL_PATH)/usr/include/fmd/Peripherals
AM_CFLAGS    += -I$(SDK_INSTALL_PATH)/usr/include/fmd/integrations
AM_LDFLAGS   += -L$(SDK_INSTALL_PATH)/usr/$(LIB_PATH)
else
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa1/flib/include/fmd
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa1/flib/include/fmd/Peripherals
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa1/flib/include/fmd/integrations
#if little endian is being compiled
AM_LDFLAGS += -L$(PWD)/flib/le
#else
#AM_CFLAGS += -mbig-endian
#AM_LDFLAGS += -L$(PWD)/flib/be
#endif
endif #SDK_INSTALL_PATH_

LIBS = -lxml2 -lz -lm -l$(FMLIB)

include_HEADERS = \
		  $(top_srcdir)/include/odp.h \
		  $(top_srcdir)/include/odp_api.h

odpapiincludedir= $(includedir)/odp/api
odpapiinclude_HEADERS = \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/align.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/atomic.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/barrier.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/buffer.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/byteorder.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/classification.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/compiler.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/cpu.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/cpumask.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/crypto.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/debug.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/errno.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/event.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/hash.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/hints.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/init.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/packet_flags.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/packet.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/packet_io.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/packet_io_stats.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/pool.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/queue.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/random.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/rwlock.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/rwlock_recursive.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/schedule.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/schedule_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/shared_memory.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/spinlock.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/spinlock_recursive.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/std_clib.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/std_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/sync.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/system_info.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/thread.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/thrmask.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/ticketlock.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/time.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/timer.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/traffic_mngr.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/visibility_begin.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/visibility_end.h \
		  $(top_srcdir)/platform/linux-generic/arch/@ARCH_DIR@/odp/api/cpu_arch.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/version.h

odpapiplatincludedir= $(includedir)/odp/api/plat
odpapiplatinclude_HEADERS = \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/atomic_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/barrier_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/buffer_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/byteorder_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/classification_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/cpumask_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/crypto_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/event_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/init_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/packet_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/packet_io_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/pool_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/queue_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/rwlock_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/rwlock_recursive_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/schedule_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/shared_memory_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/spinlock_recursive_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/spinlock_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/strong_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/thread_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/thrmask_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/ticketlock_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/time_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/timer_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/traffic_mngr_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/version_types.h

noinst_HEADERS = \
		  ${top_srcdir}/platform/linux-generic/include/odp_align_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_atomic_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_buffer_inlines.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_buffer_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_datamodel.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_inlines.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_config_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_crypto_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_debug_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_forward_typedefs_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_name_table_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_io_ipc_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_io_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_io_ring_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_io_queue.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_socket.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_tap.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_pkt_queue_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_pool_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_posix_extensions.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_queue_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_sorted_list_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_schedule_if.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_schedule_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_schedule_ordered_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_shm_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_timer_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_timer_wheel_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_traffic_mngr_internal.h \
		  ${top_srcdir}/platform/linux-generic/Makefile.inc

__LIB__libodp_linux_la_SOURCES = \
			   ../linux-generic/odp_barrier.c \
			   odp_buffer.c \
			   odp_buffer_pool_bman.c \
			   odp_classification.c \
			   odp_cpumask.c \
                           odp_system_info.c \
			   odp_cpumask_task.c \
			   odp_crypto.c \
			   odp_ipsec.c \
			   ../linux-generic/odp_errno.c \
			   ../linux-generic/odp_hash.c \
			   ../linux-generic/odp_event.c \
			   odp_init.c \
			   ../linux-generic/odp_impl.c \
			   odp_packet.c \
			   odp_packet_flags.c \
			   odp_packet_io.c \
			   odp_pool.c \
			   odp_queue.c \
			   ../linux-generic/odp_rwlock.c \
			   ../linux-generic/odp_rwlock_recursive.c \
			   odp_schedule.c \
			   odp_shared_memory.c \
			   ../linux-generic/odp_spinlock.c \
			   ../linux-generic/odp_spinlock_recursive.c \
			   odp_thread.c \
			   ../linux-generic/odp_thrmask.c \
			   ../linux-generic/odp_ticketlock.c \
			   ../linux-generic/odp_atomic.c \
			   odp_time.c \
			   odp_timer.c \
			   ../linux-generic/odp_version.c \
			   ../linux-generic/odp_weak.c \
			   arch/linux/odp_time_cycles.c \
			   arch/linux/odp_cpu_cycles.c \
			   sdk/qbman/bman_driver.c \
			   sdk/qbman/qman_driver.c \
			   sdk/qbman/dpa_alloc.c \
			   sdk/qbman/bman_high.c \
			   sdk/qbman/qman_high.c \
			   sdk/qbman/qman_utility.c \
			   sdk/qbman/dpa_sys.c \
			   sdk/fman/memac.c \
			   sdk/fman/fman.c \
			   sdk/dma_mem/allocator.c \
			   sdk/dma_mem/map.c \
			   sdk/dma_mem/setup.c \
			   sdk/process/process.c \
			   sdk/of/of.c \
			   sdk/syscfg/usdpaa_netcfg_layer.c \
			   sdk/syscfg/fmc_netcfg_parser.c

EXTRA_DIST = \
		arch/linux/odp_time_cycles.c \
		arch/linux/odp_cpu_cycles.c \
		arch/mips64/odp_time_cycles.c \
		arch/x86/odp_time_cycles.c

customscriptsdir=${exec_prefix}/odp/scripts
dist_customscripts_SCRIPTS = \
	$(top_srcdir)/platform/linux-dpaa1/scripts/*

custompcddir=${exec_prefix}/odp/pcd
dist_custompcd_SCRIPTS = \
	$(top_srcdir)/platform/linux-dpaa1/pcd/*
