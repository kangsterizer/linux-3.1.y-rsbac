#
# File: rsbac/adf/pax/Makefile
#
# Makefile for the Linux rsbac pax decision module.
#
# Author and (c) 1999-2004 Amon Ott
#

ifeq ($(PATCHLEVEL),4)
O_TARGET := pax.o
obj-y    := pax_main.o
include $(TOPDIR)/Rules.make

else

# 2.6.x
obj-y    := pax_main.o
endif

