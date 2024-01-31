# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for CVIP platform driver
#

ifdef CONFIG_CVIP_PLT
obj-$(CONFIG_CVIP_PLT)	        += cvip_plt.o cvip_plt_property.o cvip_plt_scpi.o cvip_plt_crc_opto.o cvip_plt_pci.o
obj-$(CONFIG_COMMON_CLK_SCPI) += cvip_plt_fclk.o

ccflags-y += -I $(srctree)/include/linux/cvip
ccflags-y += -I $(srctree)/drivers/firmware
ccflags-y += -I $(srctree)/drivers/staging/android/ion
ccflags-y += -I $(srctree)/drivers/staging/android/uapi
endif
