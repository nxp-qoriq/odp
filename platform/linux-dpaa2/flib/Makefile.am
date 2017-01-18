AM_CFLAGS += -I$(top_srcdir)/platform/linux-dpaa2/flib/mc
AM_CFLAGS += -I$(top_srcdir)/platform/linux-dpaa2/flib/qbman/include
AM_CFLAGS += -Wno-error

noinst_LTLIBRARIES = libflib.la
nodist_libflib_la_SOURCES = mc/dprc.c \
	mc/dprtc.c \
	mc/dpaiop.c \
	mc/dpkg.c \
	mc/dpdcei.c \
	mc/dpdmai.c \
	mc/dpmac.c \
	mc/dpmcp.c \
	mc/dpbp.c \
	mc/dpio.c \
	mc/dpni.c \
	mc/dpsw.c \
	mc/dpci.c \
	mc/dpcon.c \
	mc/dpseci.c \
	mc/dpmng.c \
	mc/dpdmux.c \
	mc/mc_sys.c \
	qbman/driver/qbman_portal.c \
	qbman/driver/qbman_debug.c
