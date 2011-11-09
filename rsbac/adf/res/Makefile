#
# File: rsbac/adf/RES/Makefile
#
# Makefile for the Linux rsbac RES decision module.
#
# Author and (c) 1999-2003 Amon Ott
#

ifeq ($(PATCHLEVEL),4)

O_TARGET := res.o
obj-y    := res_main.o
include $(TOPDIR)/Rules.make

else
# 2.6.x
obj-y    := res_main.o

endif
