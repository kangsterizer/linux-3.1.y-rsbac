/*
 * RSBAC REG decision module kproc_hide.
 *
 * Originally written for a Linux Journal as LSM sample module.
 * Rewriten for RSBAC by Michal Purzynski <albeiro@rsbac.org>
 *
 * Copyright (C) 2002 Greg Kroah-Hartman <greg@kroah.com>
 *
 * Prevents any programs running with egid == 0 if a specific USB device
 * is not present in the system.  Yes, it can be gotten around, but is a
 * nice starting point for people to play with, and learn the LSM interface.
 *
 * See http://www.linuxjournal.com/article.php?sid=6279 for more information about this code.
 *
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the License.
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/usb.h>
#include <rsbac/types.h>
#include <rsbac/reg.h>
#include <rsbac/adf.h>
#include <rsbac/aci.h>
#include <rsbac/getname.h>
#include <rsbac/error.h>
#include <rsbac/proc_fs.h>
#include <linux/usb.h>
#include <linux/moduleparam.h>

MODULE_AUTHOR("Michal Purzynski");
MODULE_DESCRIPTION("RSBAC REG root_plug decision module");
MODULE_LICENSE("GPL");

#ifdef CONFIG_USB
/* default is a generic type of usb to serial converter */
static int vendor_id = 0x0557;
static int product_id = 0x2008;

module_param(vendor_id, uint, 0400);
module_param(product_id, uint, 0400);
#endif

static long handle = 999999;

/**** Decision Functions ****/

static int request_func (enum  rsbac_adf_request_t	request,
			rsbac_pid_t			owner_pid,
			enum  rsbac_target_t		target,
			union rsbac_target_id_t		tid,
			enum  rsbac_attribute_t		attr,
			union rsbac_attribute_value_t	attr_val,
			rsbac_uid_t			owner)
{
	struct usb_device *dev = NULL;
#ifdef CONFIG_USB 
	dev = usb_find_device(vendor_id, product_id);
#endif

	if (!dev) {

		switch (request) {
			case R_CHANGE_OWNER:
			case R_CHANGE_GROUP:
			case R_CLONE:
				switch (target) {
					case T_PROCESS:
						switch (attr) {
							case A_owner:
								switch (attr_val.owner) {
									case 0:
										return NOT_GRANTED;
									default:
										return DO_NOT_CARE;
								}
							default:
								return DO_NOT_CARE;
						}
					default:
						return DO_NOT_CARE;
				}
			default:
				return DO_NOT_CARE;
		}
	}
	
	return DO_NOT_CARE;
}

/**** Init ****/

int init_module(void)
{
	struct rsbac_reg_entry_t entry;

	rsbac_printk(KERN_INFO "RSBAC REG decision module root_plug: Initializing.\n");

	/* clearing registration entries */
	memset(&entry, 0, sizeof(entry));

	strcpy(entry.name, "RSBAC REG root_plug ADF module");
	rsbac_printk(KERN_INFO "RSBAC REG decision module root_plug: REG Version: %u, Name: %s, Handle: %li\n",
			RSBAC_REG_VERSION, entry.name, handle);

	entry.handle = handle;
	entry.request_func = request_func;
	entry.switch_on = TRUE;

	rsbac_printk(KERN_INFO "RSBAC REG decision module root_plug: Registering to ADF.\n");

	if(rsbac_reg_register(RSBAC_REG_VERSION, entry) < 0) {
		rsbac_printk(KERN_WARNING "RSBAC REG decision module sample 1: Registering failed. Unloading.\n");
		return -ENOEXEC;
	}

	rsbac_printk(KERN_INFO "RSBAC REG decision module root_plug: Loaded.\n");

	return 0;
}

void cleanup_module(void)
{
	rsbac_printk(KERN_INFO "RSBAC REG decision module root_plug: Unregistering.\n");
	
	if(rsbac_reg_unregister(handle))
	{
		rsbac_printk(KERN_ERR "RSBAC REG decision module root_plug: Unregistering failed - beware of possible system failure!\n");
	}
	
	rsbac_printk(KERN_INFO "RSBAC REG decision module root_plug: Unloaded.\n");
}

