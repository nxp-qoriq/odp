
include $(top_srcdir)/platform/Makefile.inc
include Makefile.inc

AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/aiop
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa2/kni
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa2/include
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-generic/include
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/notify
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/main
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/cmdif
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/eth
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/rts
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/common

AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa2/include/sdk_priv

AM_CFLAGS += -D_LITTLE_ENDIAN
AM_CFLAGS +=  -I$(srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/helper/include

#DPAA2_LIBS = -static
LIBS += $(DPAA2_LIBS)
AM_LDFLAGS += -L$(top_srcdir)/lib

if BUILD_LS2085
DPAA2_CFLAGS += -DBUILD_LS2085
endif
if BUILD_LS2080
DPAA2_CFLAGS += -DBUILD_LS2080
endif
if BUILD_LS2088
DPAA2_CFLAGS += -DBUILD_LS2088
endif
if BUILD_LS1088
DPAA2_CFLAGS += -DBUILD_LS1088
endif
if BUILD_LX2160
DPAA2_CFLAGS += -DBUILD_LX2160
endif

SUBDIRS = flib .

include_HEADERS = \
		  $(top_srcdir)/include/odp.h \
		  $(top_srcdir)/include/odp_api.h

odpincludedir= $(includedir)/odp/api
odpinclude_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/align.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/atomic.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/barrier.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/buffer.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/byteorder.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/classification.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/compiler.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/cpu.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/cpumask.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/crypto.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/ipsec.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/debug.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/errno.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/event.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/hash.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/hints.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/init.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/packet_flags.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/packet.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/packet_io.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/packet_io_stats.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/pool.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/queue.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/random.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/rwlock.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/rwlock_recursive.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/schedule.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/schedule_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/shared_memory.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/spinlock.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/spinlock_recursive.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/std_clib.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/std_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/sync.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/system_info.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/thread.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/thrmask.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/ticketlock.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/time.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/timer.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/traffic_mngr.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/version.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/visibility_begin.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/visibility_end.h

sdkincludecommondir= $(includedir)/odp/api/plat/sdk/common
sdkincludecommon_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/common/dpaa2_cfg.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/common/dpaa2_common.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/common/dpaa2_lock.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/common/dpaa2_queue.h

sdkincludemaindir= $(includedir)/odp/api/plat/sdk/main
sdkincludemain_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/main/dpaa2.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/main/dpaa2_dev.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/main/eal_filesystem.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/main/eal_hugepages.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/main/eal_internal_cfg.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/main/dpaa2_hwq.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/main/dpaa2_internal.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/main/dpaa2_vfio.h

sdkincludenotifydir= $(includedir)/odp/api/plat/sdk/notify
sdkincludenotify_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/notify/dpaa2_dev_notif.h

sdkincludertsdir= $(includedir)/odp/api/plat/sdk/rts
sdkincluderts_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/rts/dpaa2_timer.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/rts/dpaa2_time.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/rts/dpaa2_string_fns.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/rts/dpaa2_random.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/rts/dpaa2_mpool.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/rts/dpaa2_memzone.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/rts/dpaa2_memory.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/rts/dpaa2_memcpy.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/rts/dpaa2_mbuf.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/rts/dpaa2_malloc.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/rts/dpaa2_log.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/rts/dpaa2_hexdump.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/rts/dpaa2_debug.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/rts/malloc_elem.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/rts/malloc_heap.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/rts/dpaa2_malloc_heap.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/rts/dpaa2_mbuf_support.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/rts/dpaa2_memconfig.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/rts/dpaa2_tailq.h

sdkincludecmdifdir= $(includedir)/odp/api/plat/sdk/cmdif
sdkincludecmdif_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/cmdif/shbp.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/cmdif/cmdif.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/cmdif/fsl_shbp.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/cmdif/cmdif_srv_flib.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/cmdif/cmdif_client_flib.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/cmdif/fsl_cmdif_flib_fd.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/cmdif/fsl_cmdif_flib_s.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/cmdif/fsl_cmdif_server.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/cmdif/fsl_cmdif_client.h

sdkincludeaiopdir= $(includedir)/odp/api/plat/sdk/aiop
sdkincludeaiop_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/aiop/dpaa2_aiop.h


sdkincludeethdir= $(includedir)/odp/api/plat/sdk/eth
sdkincludeeth_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/eth/dpaa2_eth_ldpaa_qbman.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/eth/dpaa2_ether.h

odpplatincludedir= $(includedir)/odp/api/plat
odpplatinclude_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/atomic_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/barrier_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/buffer_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/byteorder_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/classification_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/cpumask_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/crypto_pdcp_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/crypto_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/event_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/init_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/packet_annot.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/packet_io_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/packet_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/pool_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/queue_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/rwlock_recursive_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/rwlock_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/schedule_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/shared_memory_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/spinlock_recursive_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/spinlock_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/strong_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/thread_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/thrmask_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/ticketlock_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/timer_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/time_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/traffic_mngr_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/api/plat/version_types.h

odpplatcmdifincludedir= $(includedir)/odp/api/plat/cmdif
odpplatcmdifinclude_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/cmdif/fsl_cmdif_client.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/cmdif/fsl_cmdif_server.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/cmdif/odpfsl_cidev.h

odpplatkniincludedir= $(includedir)/odp/api/plat/kni
odpplatkniinclude_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/kni/odpfsl_kni_api.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/kni/odpfsl_kni_mbuf.h

odpplatmallocincludedir= $(includedir)/odp/api/plat/malloc
odpplatmallocinclude_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/malloc/odpfsl_data_malloc.h

odpplatcountersincludedir= $(includedir)/odp/api/plat/counters
odpplatcountersinclude_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/counters/counters_v7.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/counters/counters_v8.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/counters/counters.h

odpapiincludedir= $(includedir)/odp/api/spec
odpapiinclude_HEADERS = \
		  $(top_srcdir)/include/odp/api/spec/crypto_pdcp.h 
noinst_HEADERS = \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_align_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_atomic_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_buffer_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_pool_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_traffic_mngr_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_posix_extensions.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_classification_datamodel.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_classification_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_crypto_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_ipsec_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_debug_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_packet_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_packet_io_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_packet_io_queue.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_packet_dpaa2.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_queue_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_schedule_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_timer_internal.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/eth/dpaa2_vq.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/eth/dpaa2_eth_ldpaa_annot.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/api/plat/sdk/eth/dpaa2_ethdev.h \
		  ${top_srcdir}/platform/linux-dpaa2/Makefile.inc


__LIB__libodp_linux_la_LIBADD = $(top_srcdir)/platform/linux-dpaa2/flib/libflib.la

__LIB__libodp_linux_la_SOURCES = \
			   ../linux-generic/odp_barrier.c \
			   odp_buffer.c \
			   odp_classification.c \
			   ../linux-generic/odp_cpu.c \
			   ../linux-generic/odp_cpumask.c \
			   odp_cpumask_task.c \
			   ../linux-generic/odp_errno.c \
			   odp_event.c \
			   odp_init.c \
			   odp_dpaa2_debug.c \
			   odp_crypto.c \
			   odp_ipsec.c \
			   ../linux-generic/odp_impl.c \
			   odp_packet.c \
			   odp_packet_io.c \
			   odp_packet_dpaa2.c \
			   odp_pool.c \
			   odp_queue.c \
			   odp_traffic_mngr.c \
			   ../linux-generic/odp_rwlock.c \
			   ../linux-generic/odp_rwlock_recursive.c \
			   odp_schedule.c \
			   odp_shared_memory.c \
			   ../linux-generic/odp_spinlock.c \
			   ../linux-generic/odp_spinlock_recursive.c \
			   odp_system_info.c \
			   odp_thread.c \
			   ../linux-generic/odp_thrmask.c \
			   ../linux-generic/odp_ticketlock.c \
			   ../linux-dpaa2/odp_time.c \
			   odp_timer.c \
			   ../linux-generic/odp_version.c \
			   ../linux-generic/odp_weak.c \
			   ../linux-generic/odp_atomic.c \
			   ../linux-generic/odp_hash.c \
			   malloc/odpfsl_data_malloc.c \
			   sdk/dpaa2_dev.c \
			   sdk/dpaa2_ldpaa.c \
			   sdk/dpaa2_ldpaa_vfio.c \
			   sdk/trace.c \
			   sdk/dpaa2_main.c \
			   sdk/dpaa2_io_portal.c \
			   sdk/dpaa2_sec_ldpaa.c \
			   sdk/dpaa2_ethdev_ldpaa.c \
			   sdk/dpaa2_ethdev_priv_ldpaa.c \
			   sdk/dpaa2_eth_ldpaa.c \
			   sdk/dpaa2_conc_ldpaa.c \
			   sdk/dpaa2_mbuf_priv_ldpaa.c \
			   sdk/dpaa2_mbuf_ldpaa.c \
			   sdk/dpaa2_mbuf.c \
			   sdk/dpaa2_hwq.c \
			   sdk/librts/eal_hugepage_info.c \
			   sdk/librts/eal_memory.c \
			   sdk/librts/eal_common_memory.c \
			   sdk/librts/eal_common_memzone.c \
			   sdk/librts/dpaa2_time.c \
			   sdk/librts/dpaa2_timer.c \
			   sdk/librts/malloc_elem.c \
			   sdk/librts/malloc_heap.c \
			   sdk/librts/dpaa2_malloc.c \
			   sdk/librts/eal_debug.c \
			   sdk/librts/eal_common_log.c \
			   sdk/librts/eal_common_hexdump.c \
			   sdk/librts/eal_log.c \
			   sdk/librts/dpaa2_mpool.c \
			   sdk/libevent/dpaa2_dev_notif_priv.c \
			   sdk/libevent/dpaa2_dev_notif.c \
			   sdk/libevent/dpaa2_dev_intr_priv.c \
			   sdk/libaiop/dpaa2_aiop.c \
			   arch/@ARCH_DIR@/odp_cpu_cycles.c \
			   kni/odpfsl_kni.c \
			   kni/odpfsl_kni_api.c \
			   sdk/libcmdif/cmdif_client_flib.c \
			   sdk/libcmdif/cmdif_client_gpp.c \
			   sdk/libcmdif/cmdif_srv_flib.c \
			   sdk/libcmdif/cmdif_srv_gpp.c \
			   sdk/libcmdif/shbp.c \
			   cmdif/odpfsl_cidev.c
