#
# File: rsbac/adf/ff/Makefile
#
# Makefile for the Linux rsbac ff decision module.
#
# Author and (c) 1999-2003 Amon Ott
#

ifeq ($(PATCHLEVEL),4)
O_TARGET := ff.o
obj-y    := ff_main.o
include $(TOPDIR)/Rules.make

else
# 2.6.x
obj-y    := ff_main.o

endif

