#
# File: rsbac/data_structures/Makefile
#
# Makefile for the RSBAC data structures.
#
# Author and (c) 1999-2004 Amon Ott
#

ifeq ($(PATCHLEVEL),4)

O_TARGET := data_structures.o
obj-y += aci_data_structures.o gen_lists.o
export-objs += aci_data_structures.o gen_lists.o

# Adding policy dependent data structures

obj-$(CONFIG_RSBAC_MAC) += mac_data_structures.o
obj-$(CONFIG_RSBAC_PM) += pm_data_structures.o
obj-$(CONFIG_RSBAC_RC) += rc_data_structures.o
obj-$(CONFIG_RSBAC_AUTH) += auth_data_structures.o
obj-$(CONFIG_RSBAC_ACL) += acl_data_structures.o
obj-$(CONFIG_RSBAC_UM) += um_data_structures.o

include $(TOPDIR)/Rules.make

else
# 2.6.x
obj-y += aci_data_structures.o gen_lists.o

# Adding policy dependent data structures

obj-$(CONFIG_RSBAC_MAC) += mac_data_structures.o
obj-$(CONFIG_RSBAC_PM) += pm_data_structures.o
obj-$(CONFIG_RSBAC_RC) += rc_data_structures.o
obj-$(CONFIG_RSBAC_AUTH) += auth_data_structures.o
obj-$(CONFIG_RSBAC_ACL) += acl_data_structures.o
obj-$(CONFIG_RSBAC_UM) += um_data_structures.o

endif

