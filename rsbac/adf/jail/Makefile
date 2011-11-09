#
# File: rsbac/adf/jail/Makefile
#
# Makefile for the Linux rsbac jail decision module.
#
# Author and (c) 1999-2003 Amon Ott
#

ifeq ($(PATCHLEVEL),4)
O_TARGET := jail.o
obj-y   := jail_syscalls.o
# decisions only in non-maint mode
ifneq ($(CONFIG_RSBAC_MAINT),y)
obj-y += jail_main.o
endif
include $(TOPDIR)/Rules.make

else
# 2.6.x
obj-y   := jail_syscalls.o
# decisions only in non-maint mode
ifneq ($(CONFIG_RSBAC_MAINT),y)
obj-y += jail_main.o
endif

endif

