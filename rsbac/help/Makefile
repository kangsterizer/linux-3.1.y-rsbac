#
# Makefile for the Rule Set Based Access Control helpers.
#
# Author and (c) 1999 Amon Ott
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (ie not a .c file).
#
# Note 2! The CFLAGS definition is now in the main makefile...

ifeq ($(PATCHLEVEL),4)

O_TARGET := help.o
obj-y	    := syscalls.o helpers.o getname.o debug.o rkmem.o net_getname.o
export-objs += helpers.o getname.o debug.o rkmem.o net_getname.o

obj-$(CONFIG_RSBAC_PM) += pm_getname.o
obj-$(CONFIG_RSBAC_RC) += rc_getname.o
obj-$(CONFIG_RSBAC_ACL) += acl_getname.o
obj-$(CONFIG_RSBAC_PAX) += pax_getname.o
obj-$(CONFIG_RSBAC_CAP_LOG_MISSING) += cap_getname.o
obj-$(CONFIG_RSBAC_JAIL_LOG_MISSING) += jail_getname.o
obj-$(CONFIG_RSBAC_NET_OBJ) += net_helpers.o

include $(TOPDIR)/Rules.make

else
# 2.6.x

obj-y := syscalls.o helpers.o getname.o debug.o rkmem.o net_getname.o
#lsm.o

obj-$(CONFIG_RSBAC_PM) += pm_getname.o
obj-$(CONFIG_RSBAC_RC) += rc_getname.o
obj-$(CONFIG_RSBAC_ACL) += acl_getname.o
obj-$(CONFIG_RSBAC_PAX) += pax_getname.o
obj-$(CONFIG_RSBAC_CAP_LOG_MISSING) += cap_getname.o
obj-$(CONFIG_RSBAC_JAIL_LOG_MISSING) += jail_getname.o
obj-$(CONFIG_RSBAC_NET_OBJ) += net_helpers.o

endif
