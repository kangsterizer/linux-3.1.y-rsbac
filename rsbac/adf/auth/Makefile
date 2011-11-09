#
# File: rsbac/adf/auth/Makefile
#
# Makefile for the Linux rsbac auth decision module.
#
# Author and (c) 1999-2003 Amon Ott
#

ifeq ($(PATCHLEVEL),4)
O_TARGET := auth.o
obj-y   := auth_syscalls.o
# decisions only in non-maint mode
ifneq ($(CONFIG_RSBAC_MAINT),y)
obj-y += auth_main.o
endif
include $(TOPDIR)/Rules.make

else

obj-y   := auth_syscalls.o
# decisions only in non-maint mode
ifneq ($(CONFIG_RSBAC_MAINT),y)
obj-y += auth_main.o
endif

endif

