# Copyright (c) 2014, Linaro Limited
# Copyright (c) 2014, Freescale Semiconductor, Inc.
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause

# DPAA2_CFLAGS should match flags used to build DPAA2 libraries

#overwrite some top level compiler options - required by DPAA2
DPAA2_CFLAGS = -Wno-cast-qual -Wno-pointer-arith
DPAA2_CFLAGS += -D_GNU_SOURCE
#DPAA2_CFLAGS += -DODP_USE_PHYS_IOVA

PLAT_CFLAGS = $(DPAA2_CFLAGS)
PLAT_CFLAGS += -I$(top_srcdir)/platform/linux-dpaa2/flib/qbman/include/drivers/
PLAT_CFLAGS += -I$(top_srcdir)/platform/linux-dpaa2/flib/qbman/include
PLAT_CFLAGS += -I$(top_srcdir)/platform/linux-dpaa2/flib/qbman/driver/
PLAT_CFLAGS += -I$(top_srcdir)/platform/linux-dpaa2/flib/mc/
PLAT_CFLAGS += -I$(top_srcdir)/platform/linux-dpaa2/flib/rta/sec/rta/include/


AM_CFLAGS += $(PLAT_CFLAGS)

#these FLAGS are needed by yocto build
