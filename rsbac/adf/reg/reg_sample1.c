/*
 * RSBAC REG decision module sample 1
 *
 * Author and (c) 1999-2009 Amon Ott <ao@rsbac.org>
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <rsbac/types.h>
#include <rsbac/reg.h>
#include <rsbac/adf.h>
#include <rsbac/aci.h>
#include <rsbac/getname.h>
#include <rsbac/error.h>
#include <rsbac/proc_fs.h>

static u_long nr_request_calls = 0;
static u_long nr_set_attr_calls = 0;
static u_long nr_need_overwrite_calls = 0;
static u_long nr_system_calls = 0;
static void * system_call_arg = NULL;

MODULE_AUTHOR("Amon Ott");
MODULE_DESCRIPTION("RSBAC REG sample decision module 1");
MODULE_LICENSE("GPL");

static char * name = NULL;
static char * syscall_name = NULL;
static long handle = 123456;
static long syscall_registration_handle = 654321;
static long syscall_dispatcher_handle = 1;

module_param(name, charp, 0000);
MODULE_PARM_DESC(name, "Name");
module_param(syscall_name, charp, 0000);
MODULE_PARM_DESC(syscall_name, "Syscall name");
module_param(handle, long, S_IRUSR);
MODULE_PARM_DESC(handle, "Handle");
module_param(syscall_registration_handle, long, S_IRUSR);
MODULE_PARM_DESC(syscall_registration_handle, "Syscall registration handle");
module_param(syscall_dispatcher_handle, long, S_IRUSR);
MODULE_PARM_DESC(syscall_dispatcher_handle, "Syscall dispatcher");


/* PROC functions */

#if defined(CONFIG_RSBAC_PROC)
#define PROC_NAME "reg_sample1"

static struct proc_dir_entry * reg_sample_proc_p;

static int
reg_sample_proc_show(struct seq_file *m, void *v)
{
  union rsbac_target_id_t       rsbac_target_id;
  union rsbac_attribute_value_t rsbac_attribute_value;

  if (!rsbac_is_initialized())
    return -ENOSYS;

  rsbac_target_id.scd = ST_rsbac;
  rsbac_attribute_value.dummy = 0;
  if (!rsbac_adf_request(R_GET_STATUS_DATA,
                         task_pid(current),
                         T_SCD,
                         rsbac_target_id,
                         A_none,
                         rsbac_attribute_value))
    {
      return -EPERM;
    }
  seq_puts(m, "RSBAC REG decision module sample 1\n----------------------------------\n");
  seq_printf(m, "%lu calls to request function.\n",
                 nr_request_calls);
  seq_printf(m, "%lu calls to set_attr function.\n",
                 nr_set_attr_calls);
  seq_printf(m, "%lu calls to need_overwrite function.\n",
                 nr_need_overwrite_calls);
  seq_printf(m, "%lu calls to system_call function %lu, last arg was %p.\n",
                 nr_system_calls,
                 syscall_dispatcher_handle,
                 system_call_arg);
  return 0;
}

static int reg_sample_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, reg_sample_proc_show, NULL);
}

static const struct file_operations reg_sample_proc_fops = {
       .owner          = THIS_MODULE,
       .open           = reg_sample_proc_open,
       .read           = seq_read,
       .llseek         = seq_lseek,
       .release        = single_release,
};

#endif /* CONFIG_RSBAC_PROC */

/**** Decision Functions ****/

static  int request_func  ( enum  rsbac_adf_request_t     request,
                                  rsbac_pid_t             owner_pid,
                            enum  rsbac_target_t          target,
                            union rsbac_target_id_t       tid,
                            enum  rsbac_attribute_t       attr,
                            union rsbac_attribute_value_t attr_val,
                            rsbac_uid_t                   owner)
  {
    /* count call, but not for SEARCH request */
    if(request != R_SEARCH)
      nr_request_calls++;
    return GRANTED;
  }

static  int set_attr_func ( enum  rsbac_adf_request_t     request,
                                  rsbac_pid_t             owner_pid,
                            enum  rsbac_target_t          target,
                            union rsbac_target_id_t       tid,
                            enum  rsbac_target_t          new_target,
                            union rsbac_target_id_t       new_tid,
                            enum  rsbac_attribute_t       attr,
                            union rsbac_attribute_value_t attr_val,
                            rsbac_uid_t                   owner)
  {
    /* count call, but not for SEARCH request */
    if(request != R_SEARCH)
      nr_set_attr_calls++;
    return 0;
  }

static rsbac_boolean_t need_overwrite_func (struct dentry * dentry_p)
  {
    nr_need_overwrite_calls++;
    return FALSE;
  }

static int syscall_func (void * arg)
  {
    nr_system_calls++;
    system_call_arg = arg;
    return nr_system_calls;
  }

/**** Init ****/

int init_module(void)
{
  struct rsbac_reg_entry_t entry;
  struct rsbac_reg_syscall_entry_t syscall_entry;

  if(!handle)
    handle = 123456;
  if(!syscall_registration_handle)
    syscall_registration_handle = 654321;
  if(!syscall_dispatcher_handle)
    syscall_dispatcher_handle = 1;

  rsbac_printk(KERN_INFO "RSBAC REG decision module sample 1: Initializing.\n");

  /* clearing registration entries */
  memset(&entry, 0, sizeof(entry));
  memset(&syscall_entry, 0, sizeof(syscall_entry));

  if(name)
    {
      strncpy(entry.name, name, RSBAC_REG_NAME_LEN);
      entry.name[RSBAC_REG_NAME_LEN] = 0;
    }
  else
    strcpy(entry.name, "RSBAC REG sample 1 ADF module");
  rsbac_printk(KERN_INFO "RSBAC REG decision module sample 1: REG Version: %u, Name: %s, Handle: %li\n",
         RSBAC_REG_VERSION, entry.name, handle);

  entry.handle = handle;
  entry.request_func = request_func;
  entry.set_attr_func = set_attr_func;
  entry.need_overwrite_func = need_overwrite_func;
  entry.switch_on = TRUE;
  rsbac_printk(KERN_INFO "RSBAC REG decision module sample 1: Registering to ADF.\n");
  if(rsbac_reg_register(RSBAC_REG_VERSION, entry) < 0)
    {
      rsbac_printk(KERN_WARNING "RSBAC REG decision module sample 1: Registering failed. Unloading.\n");
      return -ENOEXEC;
    }

  if(syscall_name)
    {
      strncpy(syscall_entry.name, syscall_name, RSBAC_REG_NAME_LEN);
      syscall_entry.name[RSBAC_REG_NAME_LEN] = 0;
    }
  else
    strcpy(syscall_entry.name, "RSBAC REG sample 1 syscall");
  rsbac_printk(KERN_INFO "RSBAC REG decision module sample 1: REG Version: %u, Name: %s, Dispatcher Handle: %li\n",
         RSBAC_REG_VERSION, syscall_entry.name, syscall_dispatcher_handle);

  syscall_entry.registration_handle = syscall_registration_handle;
  syscall_entry.dispatcher_handle = syscall_dispatcher_handle;
  syscall_entry.syscall_func = syscall_func;
  rsbac_printk(KERN_INFO "RSBAC REG decision module sample 1: Registering syscall.\n");
  syscall_registration_handle = rsbac_reg_register_syscall(RSBAC_REG_VERSION, syscall_entry);
  if(syscall_registration_handle < 0)
    {
      rsbac_printk(KERN_WARNING "RSBAC REG decision module sample 1: Registering syscall failed. Unloading.\n");
      if(rsbac_reg_unregister(handle))
        {
          rsbac_printk(KERN_ERR "RSBAC REG decision module sample 1: Unregistering failed - beware of possible system failure!\n");
        }
      return -ENOEXEC;
    }

  #if defined(CONFIG_RSBAC_PROC)
  reg_sample_proc_p = proc_create(PROC_NAME,  S_IFREG | S_IRUGO, proc_rsbac_root_p, &reg_sample_proc_fops);
  if(!reg_sample_proc_p)
    {
      rsbac_printk(KERN_WARNING "%s: Not loaded due to failed proc entry registering.\n", name);
      if(rsbac_reg_unregister(handle))
        {
          rsbac_printk(KERN_ERR "RSBAC REG decision module sample 1: Unregistering failed - beware of possible system failure!\n");
        }
      if(rsbac_reg_unregister_syscall(syscall_registration_handle))
        {
          rsbac_printk(KERN_ERR "RSBAC REG decision module sample 1: Unregistering syscall failed - beware of possible system failure!\n");
        }
      return -ENOEXEC;
    }
  #endif 

  rsbac_printk(KERN_INFO "RSBAC REG decision module sample 1: Loaded.\n");

  return 0;
}

void cleanup_module(void)
{
  rsbac_printk(KERN_INFO "RSBAC REG decision module sample 1: Unregistering.\n");
  #if defined(CONFIG_RSBAC_PROC)
  remove_proc_entry(PROC_NAME, proc_rsbac_root_p);
  #endif 
  if(rsbac_reg_unregister_syscall(syscall_registration_handle))
    {
      rsbac_printk(KERN_ERR "RSBAC REG decision module sample 1: Unregistering syscall failed - beware of possible system failure!\n");
    }
  if(rsbac_reg_unregister(handle))
    {
      rsbac_printk(KERN_ERR "RSBAC REG decision module sample 1: Unregistering failed - beware of possible system failure!\n");
    }
  rsbac_printk(KERN_INFO "RSBAC REG decision module sample 1: Unloaded.\n");
}
