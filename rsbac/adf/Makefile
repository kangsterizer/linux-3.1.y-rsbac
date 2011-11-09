#
# File: rsbac/adf/Makefile
#
# Makefile for the Linux RSBAC Access Control Decision Facility (ADF)
#
# Author and (c) 1999-2005 Amon Ott
#

#TOPDIR := ../..

ifeq ($(PATCHLEVEL),4)

O_TARGET := adf.o

obj-y   := adf_main.o
export-objs += adf_main.o

ifeq ($(CONFIG_RSBAC_DEBUG),y)
obj-y   += adf_check.o
endif

# Adding policies
subdir-$(CONFIG_RSBAC_MAC) += mac
obj-$(CONFIG_RSBAC_MAC) += mac/mac.o

subdir-$(CONFIG_RSBAC_PM) += pm
obj-$(CONFIG_RSBAC_PM) += pm/pm.o

ifneq ($(CONFIG_RSBAC_MAINT),y)
subdir-$(CONFIG_RSBAC_DAZ) += daz
obj-$(CONFIG_RSBAC_DAZ) += daz/daz.o
endif

ifneq ($(CONFIG_RSBAC_MAINT),y)
subdir-$(CONFIG_RSBAC_FF) += ff
obj-$(CONFIG_RSBAC_FF) += ff/ff.o
endif

subdir-$(CONFIG_RSBAC_RC) += rc
obj-$(CONFIG_RSBAC_RC) += rc/rc.o

subdir-$(CONFIG_RSBAC_AUTH) += auth
obj-$(CONFIG_RSBAC_AUTH) += auth/auth.o

subdir-$(CONFIG_RSBAC_ACL) += acl
obj-$(CONFIG_RSBAC_ACL) += acl/acl.o

ifneq ($(CONFIG_RSBAC_MAINT),y)
subdir-$(CONFIG_RSBAC_CAP) += cap
obj-$(CONFIG_RSBAC_CAP) += cap/cap.o
endif

subdir-$(CONFIG_RSBAC_JAIL) += jail
obj-$(CONFIG_RSBAC_JAIL) += jail/jail.o

subdir-$(CONFIG_RSBAC_PAX) += pax
obj-$(CONFIG_RSBAC_PAX) += pax/pax.o

ifneq ($(CONFIG_RSBAC_MAINT),y)
subdir-$(CONFIG_RSBAC_RES) += res
obj-$(CONFIG_RSBAC_RES) += res/res.o
endif

subdir-$(CONFIG_RSBAC_REG) += reg
obj-$(CONFIG_RSBAC_REG) += reg/reg.o
subdir-m += reg

ALL_SUB_DIRS := mac fc sim pm ms ff rc auth reg acl cap jail res

include $(TOPDIR)/Rules.make

else
# 2.6.x

obj-y   := adf_main.o

ifeq ($(CONFIG_RSBAC_DEBUG),y)
obj-y   += adf_check.o
endif

# Adding policies
subdir-$(CONFIG_RSBAC_MAC) += mac
obj-$(CONFIG_RSBAC_MAC) += mac/

subdir-$(CONFIG_RSBAC_PM) += pm
obj-$(CONFIG_RSBAC_PM) += pm/

ifneq ($(CONFIG_RSBAC_MAINT),y)
subdir-$(CONFIG_RSBAC_DAZ) += daz
obj-$(CONFIG_RSBAC_DAZ) += daz/
endif

ifneq ($(CONFIG_RSBAC_MAINT),y)
subdir-$(CONFIG_RSBAC_FF) += ff
obj-$(CONFIG_RSBAC_FF) += ff/
endif

subdir-$(CONFIG_RSBAC_RC) += rc
obj-$(CONFIG_RSBAC_RC) += rc/

subdir-$(CONFIG_RSBAC_AUTH) += auth
obj-$(CONFIG_RSBAC_AUTH) += auth/

subdir-$(CONFIG_RSBAC_ACL) += acl
obj-$(CONFIG_RSBAC_ACL) += acl/

ifneq ($(CONFIG_RSBAC_MAINT),y)
subdir-$(CONFIG_RSBAC_CAP) += cap
obj-$(CONFIG_RSBAC_CAP) += cap/
endif

subdir-$(CONFIG_RSBAC_JAIL) += jail
obj-$(CONFIG_RSBAC_JAIL) += jail/

subdir-$(CONFIG_RSBAC_PAX) += pax
obj-$(CONFIG_RSBAC_PAX) += pax/

ifneq ($(CONFIG_RSBAC_MAINT),y)
subdir-$(CONFIG_RSBAC_RES) += res
obj-$(CONFIG_RSBAC_RES) += res/
endif

subdir-$(CONFIG_RSBAC_REG) += reg
obj-$(CONFIG_RSBAC_REG) += reg/
ifeq ($(CONFIG_RSBAC_REG_SAMPLES),y)
subdir-m += reg
endif

endif

