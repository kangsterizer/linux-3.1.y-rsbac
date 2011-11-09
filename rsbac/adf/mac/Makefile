#
# File: rsbac/adf/mac/Makefile
#
# Makefile for the Linux rsbac mac decision module.
#
# Author and (c) 1999-2003 Amon Ott
#

ifeq ($(PATCHLEVEL),4)

O_TARGET := mac.o
obj-y    := mac_syscalls.o
# decisions only in non-maint mode
ifneq ($(CONFIG_RSBAC_MAINT),y)
obj-y += mac_main.o
endif
include $(TOPDIR)/Rules.make

else

obj-y    := mac_syscalls.o
# decisions only in non-maint mode
ifneq ($(CONFIG_RSBAC_MAINT),y)
obj-y += mac_main.o
endif

endif

