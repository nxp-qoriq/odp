#/**************************************************************************
# *Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#
# Makefile config for the ARM perf counter kernel driver module
#
#
PWD=$(shell pwd)
XPWD=$(shell pwd)
ifdef KERNEL_CFG_PATH
include $(KERNEL_CFG_PATH)/.config
else
include $(KERNEL_PATH)/.config
endif

CC      = $(CROSS_COMPILE)gcc
AR      = $(CROSS_COMPILE)ar
LD      = $(CROSS_COMPILE)ld

ifeq ($(ARCH), aarch64)
	ARCH = arm64
endif
EXTRA_CFLAGS += -DCONFIG_LDPAA

export KBUILD_EXTRA_SYMBOLS

obj-m += odpfsl_perfcounters.o
odpfsl_perfcounters-y := perf_counters.o

all:
	make ARCH=$(ARCH) -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make ARCH=$(ARCH) -C $(KERNEL_PATH) M=$(PWD) clean
	rm -rf *.o *.ko *.mod.c modules.order Modules.symvers

distclean: clean

install:
	@echo "Installing..."
