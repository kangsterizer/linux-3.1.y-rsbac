#
# File: rsbac/adf/auth/Makefile
#
# Makefile for the Linux rsbac auth decision module.
#
# Author and (c) 1999-2003 Amon Ott
#

ifeq ($(PATCHLEVEL),4)

O_TARGET := acl.o
obj-y    := acl_syscalls.o
# decisions only in non-maint mode
ifneq ($(CONFIG_RSBAC_MAINT),y)
obj-y += acl_main.o
endif
include $(TOPDIR)/Rules.make

else
# 2.6.x

obj-y    := acl_syscalls.o
# decisions only in non-maint mode
ifneq ($(CONFIG_RSBAC_MAINT),y)
obj-y += acl_main.o
endif

endif

