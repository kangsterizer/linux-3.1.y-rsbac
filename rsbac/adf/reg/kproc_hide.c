/*
 * RSBAC REG decision module kproc_hide. Hiding kernel processes.
 *
 * Author and (c) 2004 Michal Purzynski <albeiro@rsbac.org>
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <rsbac/types.h>
#include <rsbac/reg.h>
#include <rsbac/adf.h>
#include <rsbac/aci.h>
#include <rsbac/getname.h>
#include <rsbac/error.h>
#include <rsbac/proc_fs.h>

MODULE_AUTHOR("Michal Purzynski");
MODULE_DESCRIPTION("RSBAC REG kproc_hide decision module");
MODULE_LICENSE("GPL");

static long handle = 9999992;

/**** Helper Functions ****/

/**********************************************************************
Description:  Checks if process is a kernel process.
Parameters:   Pid of checking process.
Return value: 1 if is, 0 otherwise.
**********************************************************************/

int is_kproc(struct pid *pid)
{
	struct task_struct *tid_task;

	tid_task = pid_task(pid, PIDTYPE_PID);

	if (tid_task->mm == NULL)
		return 1;
	else
		return 0;
}

/**** Decision Functions ****/

static int request_func(enum rsbac_adf_request_t	request,
			rsbac_pid_t			owner_pid,
			enum rsbac_target_t 		target,
			union rsbac_target_id_t		tid,
			enum rsbac_attribute_t		attr,
			union rsbac_attribute_value_t	attr_val,
			rsbac_uid_t 			owner)
{  

	switch (request) {
		case R_GET_STATUS_DATA:
			switch (target) {
				case T_PROCESS:
					if (is_kproc(tid.process))
					return NOT_GRANTED;
				default:
					return DO_NOT_CARE;
			}
		default:
			return DO_NOT_CARE;
	}
	
/*
	if (request == R_GET_STATUS_DATA && target == T_PROCESS && is_kproc(tid.process))
		return NOT_GRANTED;
	else
		return GRANTED;
*/
}

/**** Init ****/

int init_module(void)
{
	struct rsbac_reg_entry_t entry;

	rsbac_printk(KERN_INFO "RSBAC REG decision module kproc_hide: Initializing.\n");

	/* clearing registration entries */
	memset(&entry, 0, sizeof(entry));

	strcpy(entry.name, "RSBAC REG kproc_hide ADF module");
	rsbac_printk(KERN_INFO "RSBAC REG decision module kproc_hide: REG Version: %u, Name: %s, Handle: %li\n",
								RSBAC_REG_VERSION, entry.name, handle);

	entry.handle = handle;
	entry.request_func = request_func;
	entry.switch_on = TRUE;
	rsbac_printk(KERN_INFO "RSBAC REG decision module kproc_hide: Registering to ADF.\n");
	
	if(rsbac_reg_register(RSBAC_REG_VERSION, entry) < 0) {
		rsbac_printk(KERN_WARNING "RSBAC REG decision module sample 1: Registering failed. Unloading.\n");
		return -ENOEXEC;
	}

	rsbac_printk(KERN_INFO "RSBAC REG decision module kproc_hide: Loaded.\n");

	return 0;
}

void cleanup_module(void)
{
	rsbac_printk(KERN_INFO "RSBAC REG decision module kproc_hide: Unregistering.\n");
	
	if(rsbac_reg_unregister(handle))
	{
		rsbac_printk(KERN_ERR "RSBAC REG decision module kproc_hide: Unregistering failed - beware of possible system failure!\n");
	}
	
	rsbac_printk(KERN_INFO "RSBAC REG decision module kproc_hide: Unloaded.\n");
}

