#
# File: rsbac/adf/pm/Makefile
#
# Makefile for the Linux rsbac pm decision module.
#
# Author and (c) 1999-2003 Amon Ott
#

ifeq ($(PATCHLEVEL),4)

O_TARGET := pm.o
obj-y    := pm_syscalls.o
# decisions only in non-maint mode
ifneq ($(CONFIG_RSBAC_MAINT),y)
obj-y += pm_main.o
endif
include $(TOPDIR)/Rules.make

else

obj-y    := pm_syscalls.o
# decisions only in non-maint mode
ifneq ($(CONFIG_RSBAC_MAINT),y)
obj-y += pm_main.o
endif

endif

