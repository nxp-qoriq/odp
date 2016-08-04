#/**************************************************************************
# *Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#
# Makefile config for the ODP KNI kernel driver module
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

export KBUILD_EXTRA_SYMBOLS

ifeq ($(ARCH), powerpc)
EXTRA_CFLAGS := -mno-spe -mspe=no -mabi=no-spe
EXTRA_CFLAGS += -DCONFIG_QORIQ
else
ifeq ($(ARCH), aarch64)
	ARCH = arm64
endif
EXTRA_CFLAGS += -DCONFIG_LDPAA
endif

#MODULE_CFLAGS += -DNCS_DEBUG
#MODULE_CFLAGS += -DDPAA2_KNI_VHOST

obj-m += odpfsl_kni.o
odpfsl_kni-y :=  kni_net.o kni_misc.o

all:
	make ARCH=$(ARCH) -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make ARCH=$(ARCH) -C $(KERNEL_PATH) M=$(PWD) clean
	rm -rf *.o *.ko *.mod.c modules.order Modules.symvers

distclean: clean

install:
	@echo "Installing..."
