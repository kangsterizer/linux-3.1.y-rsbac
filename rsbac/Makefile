#
# Main Makefile for the Rule Set Based Access Control subsystem.
#
# Author and (c) 1999-2001 Amon Ott
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (ie not a .c file).
#
# Note 2! The CFLAGS definitions are now in the main makefile...

ifeq ($(TOPDIR),)
TOPDIR=..
endif


ifeq ($(PATCHLEVEL),4)

O_TARGET     := rsbac.o
subdir-y     := help data_structures adf
subdir-m     := adf
obj-y        := $(join $(subdir-y),$(subdir-y:%=/%.o))

include $(TOPDIR)/Rules.make

else
#2.6.x

obj-y     := help/ data_structures/ adf/
obj-m     := adf/

endif

clean:	Makefile
	rm -f `find . -name '*.o' -print`

