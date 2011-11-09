/*
 *   RSBAC REG decision module kproc_hide. Disabling kernel modules support.
 *   
 *   Author and (c) 2004 Michal Purzynski <albeiro@rsbac.org>
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <rsbac/types.h>
#include <rsbac/reg.h>
#include <rsbac/adf.h>
#include <rsbac/aci.h>
#include <rsbac/getname.h>
#include <rsbac/error.h>
#include <rsbac/proc_fs.h>
#include <linux/namei.h>

MODULE_AUTHOR("Michal Purzynski");
MODULE_DESCRIPTION("RSBAC REG modules_off decision module");
MODULE_LICENSE("GPL");

static long handle = 9999991;

static rsbac_inode_nr_t inode_nr = 0;
static kdev_t device_nr = 0;

/**** Decision Functions ****/

static int request_func (enum rsbac_adf_request_t	request,
			rsbac_pid_t			owner_pid,
			enum  rsbac_target_t		target,
			union rsbac_target_id_t		tid,
			enum  rsbac_attribute_t		attr,
			union rsbac_attribute_value_t	attr_val,
			rsbac_uid_t			owner)
{
	switch (request) {
		case R_ADD_TO_KERNEL:
		case R_REMOVE_FROM_KERNEL:
			return NOT_GRANTED;
		case R_GET_STATUS_DATA:
			switch (target) {
				case T_FILE:
					if (tid.file.device == device_nr && tid.file.inode == inode_nr)
					return NOT_GRANTED;
				default:
					return DO_NOT_CARE;
			}
		default:
			return DO_NOT_CARE;
	}
}

/**** Init ****/

int init_module(void)
{

	struct rsbac_reg_entry_t entry;
	struct nameidata nd;

	path_lookup("/proc/modules", 0, &nd);
	device_nr = nd.path.dentry->d_sb->s_dev;
	inode_nr = nd.path.dentry->d_inode->i_ino;
	path_put(&nd.path);

	rsbac_printk(KERN_INFO "RSBAC REG decision module modules_off: Initializing.\n");

	/* clearing registration entries */
	memset(&entry, 0, sizeof(entry));

	strcpy(entry.name, "RSBAC REG modules_off ADF module");
	rsbac_printk(KERN_INFO "RSBAC REG decision module modules_off: REG Version: %u, Name: %s, Handle: %li\n",RSBAC_REG_VERSION, entry.name, handle);

	entry.handle = handle;
	entry.request_func = request_func;
	entry.switch_on = TRUE;

	rsbac_printk(KERN_INFO "RSBAC REG decision module modules_off: Registering to ADF.\n");

	if(rsbac_reg_register(RSBAC_REG_VERSION, entry) < 0)
	{
		rsbac_printk(KERN_WARNING "RSBAC REG decision module sample 1: Registering failed. Unloading.\n");
		return -ENOEXEC;
	}

	rsbac_printk(KERN_INFO "RSBAC REG decision module modules_off: Loaded.\n");

	return 0;
}

void cleanup_module(void)
{
	rsbac_printk(KERN_INFO "RSBAC REG decision module modules_off: Unregistering.\n");

	if(rsbac_reg_unregister(handle))
	{
		rsbac_printk(KERN_ERR "RSBAC REG decision module modules_off: Unregistering failed - beware of possible system failure!\n");
	}
	
	rsbac_printk(KERN_INFO "RSBAC REG decision module modules_off: Unloaded.\n");
}

