#
# File: rsbac/adf/reg/Makefile
#
# Makefile for the Linux rsbac REG / registration of decision modules
#
# Author and (c) 1999-2010 Amon Ott
#

obj-y  := reg_main.o
ifeq ($(CONFIG_RSBAC_REG_SAMPLES),y)
obj-m    += reg_sample1.o reg_sample3.o kproc_hide.o modules_off.o
endif

