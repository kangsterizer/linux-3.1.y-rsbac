#
# File: rsbac/adf/cap/Makefile
#
# Makefile for the Linux rsbac cap decision module.
#
# Author and (c) 1999-2003 Amon Ott
#

ifeq ($(PATCHLEVEL),4)
O_TARGET := cap.o
obj-y    := cap_main.o
include $(TOPDIR)/Rules.make

else

# 2.6.x
obj-y    := cap_main.o
endif

