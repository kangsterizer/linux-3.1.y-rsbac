#
# File: rsbac/adf/daz/Makefile
#
# Makefile for the Linux rsbac DAZ decision module.
#
# Author and (c) 1999-2004 Amon Ott
#

ifeq ($(PATCHLEVEL),4)

O_TARGET := daz.o
obj-y    := daz_main.o dazuko_xp.o
export-objs := daz_main.o
include $(TOPDIR)/Rules.make

else
# 2.6.x
obj-y    := daz_main.o dazuko_xp.o

endif
