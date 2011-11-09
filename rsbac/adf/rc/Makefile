#
# File: rsbac/adf/rc/Makefile
#
# Makefile for the Linux rsbac rc decision module.
#
# Author and (c) 1999-2003 Amon Ott
#

ifeq ($(PATCHLEVEL),4)

O_TARGET := rc.o
obj-y    := rc_syscalls.o
# decisions only in non-maint mode
ifneq ($(CONFIG_RSBAC_MAINT),y)
obj-y += rc_main.o
endif
include $(TOPDIR)/Rules.make

else
# 2.6.x
obj-y    := rc_syscalls.o
# decisions only in non-maint mode
ifneq ($(CONFIG_RSBAC_MAINT),y)
obj-y += rc_main.o
endif

endif
