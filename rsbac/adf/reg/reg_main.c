/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of the Access Control Decision     */
/* Facility (ADF) - REG / Decision Module Registration */
/* File: rsbac/adf/reg/main.c                        */
/*                                                   */
/* Author and (c) 1999-2011: Amon Ott <ao@rsbac.org> */
/*                                                   */
/* Last modified: 12/Jul/2011                        */
/*************************************************** */

#include <linux/types.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <asm/uaccess.h>
#include <linux/seq_file.h>
#include <rsbac/types.h>
#include <rsbac/reg.h>
#include <rsbac/reg_main.h>
#include <rsbac/aci.h>
#include <rsbac/aci_data_structures.h>
#include <rsbac/adf.h>
#include <rsbac/adf_main.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/getname.h>
#include <rsbac/proc_fs.h>
#include <rsbac/rkmem.h>

/************************************************* */
/*           Global Variables                      */
/************************************************* */

static struct rsbac_reg_list_head_t     list_head;
static struct rsbac_reg_sc_list_head_t  sc_list_head;

/************************************************* */
/*           Internal functions                    */
/************************************************* */

static void reg_read_lock(void)
  {
    spin_lock(&list_head.lock);
    while(list_head.readers < 0)
      {
        spin_unlock(&list_head.lock);
        spin_lock(&list_head.lock);
      }
    list_head.readers++;
    spin_unlock(&list_head.lock);
  }

static void reg_read_unlock(void)
  {
    spin_lock(&list_head.lock);
    list_head.readers--;
    spin_unlock(&list_head.lock);
  }

static void reg_write_lock(void)
  {
    spin_lock(&list_head.lock);
    while(list_head.readers != 0)
      {
        spin_unlock(&list_head.lock);
        spin_lock(&list_head.lock);
      }
    list_head.readers = -1;
    spin_unlock(&list_head.lock);
  }

static void reg_write_unlock(void)
  {
    spin_lock(&list_head.lock);
    list_head.readers = 0;
    spin_unlock(&list_head.lock);
  }

static void reg_sc_read_lock(void)
  {
    spin_lock(&sc_list_head.lock);
    while(sc_list_head.readers < 0)
      {
        spin_unlock(&sc_list_head.lock);
        spin_lock(&sc_list_head.lock);
      }
    sc_list_head.readers++;
    spin_unlock(&sc_list_head.lock);
  }

static void reg_sc_read_unlock(void)
  {
    spin_lock(&sc_list_head.lock);
    sc_list_head.readers--;
    spin_unlock(&sc_list_head.lock);
  }

static void reg_sc_write_lock(void)
  {
    spin_lock(&sc_list_head.lock);
    while(sc_list_head.readers != 0)
      {
        spin_unlock(&sc_list_head.lock);
        spin_lock(&sc_list_head.lock);
      }
    sc_list_head.readers = -1;
    spin_unlock(&sc_list_head.lock);
  }

static void reg_sc_write_unlock(void)
  {
    spin_lock(&sc_list_head.lock);
    sc_list_head.readers = 0;
    spin_unlock(&sc_list_head.lock);
  }

/* lookup_item() */
static struct rsbac_reg_list_item_t * lookup_item(rsbac_reg_handle_t handle)
  {
    struct rsbac_reg_list_item_t  * curr = list_head.curr;

    /* is the current item the one we look for? yes -> return, else search */
    if (curr && (curr->entry.handle == handle))
      return (curr);

    curr = list_head.head;
    while (curr && (curr->entry.handle != handle))
      curr = curr->next;
    if (curr)
      list_head.curr=curr;
    return (curr);
  };

/* lookup_sc_item_reg() */
static struct rsbac_reg_sc_list_item_t * lookup_sc_item_reg(rsbac_reg_handle_t handle)
  {
    struct rsbac_reg_sc_list_item_t  * curr = sc_list_head.curr;

    /* is the current item the one we look for? yes -> return, else search */
    if (curr && (curr->entry.registration_handle == handle))
      return (curr);

    curr = sc_list_head.head;
    while (curr && (curr->entry.registration_handle != handle))
      curr = curr->next;
    if (curr)
      sc_list_head.curr=curr;
    return (curr);
  };

/* lookup_sc_item_dis() */
static struct rsbac_reg_sc_list_item_t * lookup_sc_item_dis(rsbac_reg_handle_t handle)
  {
    struct rsbac_reg_sc_list_item_t  * curr = sc_list_head.curr;

    /* is the current item the one we look for? yes -> return, else search */
    if (curr && (curr->entry.dispatcher_handle == handle))
      return (curr);

    curr = sc_list_head.head;
    while (curr && (curr->entry.dispatcher_handle != handle))
      curr = curr->next;
    if (curr)
      sc_list_head.curr=curr;
    return (curr);
  };

static struct rsbac_reg_list_item_t* 
         add_item(struct rsbac_reg_entry_t entry)
    {
      struct rsbac_reg_list_item_t * new_item_p = NULL;

      if ( !(new_item_p = (struct rsbac_reg_list_item_t *)
                 rsbac_kmalloc(sizeof(*new_item_p))) )
        return(NULL);
      new_item_p->entry.handle = entry.handle;
      strncpy(new_item_p->entry.name, entry.name, RSBAC_REG_NAME_LEN);
      new_item_p->entry.name[RSBAC_REG_NAME_LEN] = 0;
      new_item_p->entry.request_func = entry.request_func;
      new_item_p->entry.set_attr_func = entry.set_attr_func;
      new_item_p->entry.need_overwrite_func = entry.need_overwrite_func;
      new_item_p->entry.write_func = entry.write_func;
      new_item_p->entry.mount_func = entry.mount_func;
      new_item_p->entry.umount_func = entry.umount_func;
      new_item_p->entry.check_func = entry.check_func;
      new_item_p->entry.switch_on = entry.switch_on;
      
      if (!list_head.head)
        {
          list_head.head=new_item_p;
          list_head.tail=new_item_p;
          list_head.curr=new_item_p;
          list_head.count = 1;
          new_item_p->prev=NULL;
          new_item_p->next=NULL;          
        }  
      else
        {
          new_item_p->prev=list_head.tail;
          new_item_p->next=NULL;
          list_head.tail->next=new_item_p;
          list_head.tail=new_item_p;
          list_head.curr=new_item_p;
          list_head.count++;
        };
      return(new_item_p);
    };

static struct rsbac_reg_sc_list_item_t* 
         add_sc_item(struct rsbac_reg_syscall_entry_t entry)
    {
      struct rsbac_reg_sc_list_item_t * new_item_p = NULL;

      if ( !(new_item_p = (struct rsbac_reg_sc_list_item_t *)
                 rsbac_kmalloc(sizeof(*new_item_p))) )
        return(NULL);
      new_item_p->entry.registration_handle = entry.registration_handle;
      new_item_p->entry.dispatcher_handle = entry.dispatcher_handle;
      strncpy(new_item_p->entry.name, entry.name, RSBAC_REG_NAME_LEN);
      new_item_p->entry.name[RSBAC_REG_NAME_LEN] = 0;
      new_item_p->entry.syscall_func = entry.syscall_func;
      
      if (!sc_list_head.head)
        {
          sc_list_head.head=new_item_p;
          sc_list_head.tail=new_item_p;
          sc_list_head.curr=new_item_p;
          sc_list_head.count = 1;
          new_item_p->prev=NULL;
          new_item_p->next=NULL;          
        }  
      else
        {
          new_item_p->prev=sc_list_head.tail;
          new_item_p->next=NULL;
          sc_list_head.tail->next=new_item_p;
          sc_list_head.tail=new_item_p;
          sc_list_head.curr=new_item_p;
          sc_list_head.count++;
        };
      return(new_item_p);
    };

static void remove_item(rsbac_reg_handle_t handle)
    {
      struct rsbac_reg_list_item_t * item_p;
    
      /* first we must locate the item. */
      if ( (item_p = lookup_item(handle)) )
        { /* ok, item was found */
          if ( (list_head.head == item_p) )
             { /* item is head */
               if ( (list_head.tail == item_p) )
                 { /* item is head and tail = only item -> list will be empty*/
                   list_head.head = NULL;
                   list_head.tail = NULL;
                 }
               else
                 { /* item is head, but not tail -> next item becomes head */
                   item_p->next->prev = NULL;
                   list_head.head = item_p->next;
                 };
             }
          else
             { /* item is not head */
               if ( (list_head.tail == item_p) )
                 { /*item is not head, but tail -> previous item becomes tail*/
                   item_p->prev->next = NULL;
                   list_head.tail = item_p->prev;
                 }
               else
                 { /* item is neither head nor tail -> item is cut out */
                   item_p->prev->next = item_p->next;
                   item_p->next->prev = item_p->prev;
                 };
             };
             
          /* curr is no longer valid -> reset */
          list_head.curr=NULL;
          /* adjust counter */
          list_head.count--;
          /* now we can remove the item from memory */
          rsbac_kfree(item_p);    
        };  /* end of if: item was found */
    }; /* end of remove_item() */

static void remove_sc_item(rsbac_reg_handle_t handle)
    {
      struct rsbac_reg_sc_list_item_t * item_p;
    
      /* first we must locate the item. */
      if ( (item_p = lookup_sc_item_reg(handle)) )
        { /* ok, item was found */
          if ( (sc_list_head.head == item_p) )
             { /* item is head */
               if ( (sc_list_head.tail == item_p) )
                 { /* item is head and tail = only item -> sc_list will be empty*/
                   sc_list_head.head = NULL;
                   sc_list_head.tail = NULL;
                 }
               else
                 { /* item is head, but not tail -> next item becomes head */
                   item_p->next->prev = NULL;
                   sc_list_head.head = item_p->next;
                 };
             }
          else
             { /* item is not head */
               if ( (sc_list_head.tail == item_p) )
                 { /*item is not head, but tail -> previous item becomes tail*/
                   item_p->prev->next = NULL;
                   sc_list_head.tail = item_p->prev;
                 }
               else
                 { /* item is neither head nor tail -> item is cut out */
                   item_p->prev->next = item_p->next;
                   item_p->next->prev = item_p->prev;
                 };
             };
             
          /* curr is no longer valid -> reset */
          sc_list_head.curr=NULL;
          /* adjust counter */
          sc_list_head.count--;
          /* now we can remove the item from memory */
          rsbac_kfree(item_p);    
        };  /* end of if: item was found */
    }; /* end of remove_item() */


/************************************************* */
/*           PROC support                          */
/************************************************* */

#if defined(CONFIG_RSBAC_PROC) && defined(CONFIG_PROC_FS)
static int
reg_modules_proc_show(struct seq_file *m, void *v)
{
  union rsbac_target_id_t           rsbac_target_id;
  union rsbac_attribute_value_t     rsbac_attribute_value;
  struct rsbac_reg_list_item_t    * item_p;
  struct rsbac_reg_sc_list_item_t * sc_item_p;

  if (!rsbac_is_initialized())
    return (-ENOSYS);

#ifdef CONFIG_RSBAC_DEBUG
  if (rsbac_debug_aef)
    {
      rsbac_printk(KERN_DEBUG "reg_modules_proc_info(): calling ADF\n");
    }
#endif
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

  seq_printf(m, "RSBAC REG registered decision modules\n-------------------------------------\n");

  reg_read_lock();
  item_p=list_head.head;
  while(item_p)
    {
      if(item_p->entry.name[0] == 0)
        seq_printf(m, "(no name)\n");
      else
        seq_printf(m, "%s\n",
                       item_p->entry.name);
      item_p = item_p->next;
    }
  reg_read_unlock();

  seq_printf(m, "\n %i module entries used.\n",
                 list_head.count);
  seq_printf(m, "\nRSBAC REG registered system calls\n---------------------------------\n");

  reg_sc_read_lock();
  sc_item_p=sc_list_head.head;
  while(sc_item_p)
    {
      if(sc_item_p->entry.name[0] == 0)
        seq_printf(m, "%u: (no name)\n",
                       sc_item_p->entry.dispatcher_handle);
      else
        seq_printf(m, "%u: %s\n",
                       sc_item_p->entry.dispatcher_handle,
                       sc_item_p->entry.name);
      sc_item_p = sc_item_p->next;
    }
  reg_sc_read_unlock();

  seq_printf(m, "\n %i syscall entries used.\n",
                 sc_list_head.count);
  return 0;
}

static int reg_modules_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, reg_modules_proc_show, NULL);
}

static const struct file_operations reg_modules_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= reg_modules_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static struct proc_dir_entry *reg_modules;

#endif /* PROC */

/************************************************* */
/*          Externally visible functions           */
/************************************************* */

#ifdef CONFIG_RSBAC_INIT_DELAY
void rsbac_reg_init(void)
#else
void __init rsbac_reg_init(void)
#endif
  {
    if (rsbac_is_initialized())
      {
        rsbac_printk(KERN_WARNING "rsbac_reg_init(): RSBAC already initialized\n");
        return;
      }
    /* init data structures */
    rsbac_printk(KERN_INFO "rsbac_reg_init(): Initializing RSBAC: REG module and syscall registration\n");

    spin_lock_init(&list_head.lock);
    list_head.readers = 0;
    list_head.head = NULL;
    list_head.tail = NULL;
    list_head.curr = NULL;
    list_head.count = 0;
    spin_lock_init(&sc_list_head.lock);
    sc_list_head.readers = 0;
    sc_list_head.head = NULL;
    sc_list_head.tail = NULL;
    sc_list_head.curr = NULL;
    sc_list_head.count = 0;

    /* init proc entry */
    #if defined(CONFIG_RSBAC_PROC) && defined(CONFIG_PROC_FS)
    {
      reg_modules = proc_create(RSBAC_REG_PROC_NAME,
                                      S_IFREG | S_IRUGO,
                                      proc_rsbac_root_p, &reg_modules_proc_fops);
    }
    #endif
  }


inline enum rsbac_adf_req_ret_t
   rsbac_adf_request_reg (enum  rsbac_adf_request_t     request,
                                rsbac_pid_t             caller_pid,
                          enum  rsbac_target_t          target,
                          union rsbac_target_id_t       tid,
                          enum  rsbac_attribute_t       attr,
                          union rsbac_attribute_value_t attr_val,
                                rsbac_uid_t             owner)
  {
    enum   rsbac_adf_req_ret_t        result = DO_NOT_CARE;
    struct rsbac_reg_list_item_t    * item_p;

    reg_read_lock();
    item_p=list_head.head;
    while(item_p)
      {
        if(   item_p->entry.request_func
        #ifdef CONFIG_RSBAC_SWITCH_REG
           && item_p->entry.switch_on
        #endif
          )
          result = adf_and_plus(result,
                                item_p->entry.request_func (request,
                                                            caller_pid,
                                                            target,
                                                            tid,
                                                            attr,
                                                            attr_val,
                                                            owner) );
        item_p=item_p->next;
      }
    reg_read_unlock();
    return result;
  }

inline int rsbac_adf_set_attr_reg(
                      enum  rsbac_adf_request_t     request,
                            rsbac_pid_t             caller_pid,
                      enum  rsbac_target_t          target,
                      union rsbac_target_id_t       tid,
                      enum  rsbac_target_t          new_target,
                      union rsbac_target_id_t       new_tid,
                      enum  rsbac_attribute_t       attr,
                      union rsbac_attribute_value_t attr_val,
                            rsbac_uid_t             owner)
  {
    int error = 0;
    int suberror;
    struct rsbac_reg_list_item_t    * item_p;

    reg_read_lock();
    item_p=list_head.head;
    while(item_p)
      {
        if(   item_p->entry.set_attr_func
        #ifdef CONFIG_RSBAC_SWITCH_REG
           && item_p->entry.switch_on
        #endif
          )
          {
            suberror = item_p->entry.set_attr_func (request,
                                                    caller_pid,
                                                    target,
                                                    tid,
                                                    new_target,
                                                    new_tid,
                                                    attr,
                                                    attr_val,
                                                    owner);
            if(suberror)
              error = suberror;
          }
        item_p = item_p->next;
      }
    reg_read_unlock();
    return error;
  }


#ifdef CONFIG_RSBAC_SECDEL
inline rsbac_boolean_t rsbac_need_overwrite_reg(struct dentry * dentry_p)
  {
    rsbac_boolean_t need_overwrite = FALSE;
    struct rsbac_reg_list_item_t    * item_p;

    reg_read_lock();
    item_p=list_head.head;
    while(item_p)
      {
        if(   item_p->entry.need_overwrite_func
        #ifdef CONFIG_RSBAC_SWITCH_REG
           && item_p->entry.switch_on
        #endif
          )
          if(!need_overwrite)
            need_overwrite = item_p->entry.need_overwrite_func(dentry_p);
        item_p=item_p->next;
      }
    reg_read_unlock();
    return need_overwrite;
  }
#endif

/* mounting and umounting */
inline int rsbac_mount_reg(kdev_t kdev)
  {
    int error = 0;
    int suberror;
    struct rsbac_reg_list_item_t    * item_p;

    reg_read_lock();
    item_p=list_head.head;
    while(item_p)
      {
        if(   item_p->entry.mount_func
          )
          {
            suberror = item_p->entry.mount_func(kdev);
            if(suberror < 0)
              error = suberror;
          }
        item_p=item_p->next;
      }
    reg_read_unlock();
    return error;
  }

inline int rsbac_umount_reg(kdev_t kdev)
  {
    int error = 0;
    int suberror;
    struct rsbac_reg_list_item_t    * item_p;

    reg_read_lock();
    item_p=list_head.head;
    while(item_p)
      {
        if(   item_p->entry.umount_func
          )
          {
            suberror = item_p->entry.umount_func(kdev);
            if(suberror < 0)
              error = suberror;
          }
        item_p=item_p->next;
      }
    reg_read_unlock();
    return error;
  }

#if defined(CONFIG_RSBAC_AUTO_WRITE)
inline int rsbac_write_reg(void)
  {
    int count = 0;
    int subcount = 0;
    struct rsbac_reg_list_item_t    * item_p;

    reg_read_lock();
    item_p=list_head.head;
    while(item_p)
      {
        if(item_p->entry.write_func)
          {
            subcount = item_p->entry.write_func(FALSE);
            if(subcount > 0)
              {
                count += subcount;
              }
            else
            if(subcount < 0)
              {
                if(subcount != -RSBAC_ENOTWRITABLE)
                  {
                    rsbac_printk(KERN_WARNING
                           "rsbac_write_reg(): write_func() for REG module %s returned error %i\n",
                           item_p->entry.name, subcount);
                  }
              }
          }
        item_p=item_p->next;
      }
    reg_read_unlock();
#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_write)
      {
        rsbac_printk(KERN_DEBUG "rsbac_write_reg(): %u lists written.\n",
               count);
      }
#endif
    return count;
  }
#endif /* CONFIG_RSBAC_AUTO_WRITE */

/* Status checking */
inline int rsbac_check_reg(int correct, int check_inode)
  {
    int error = 0;
    int suberror;
    struct rsbac_reg_list_item_t    * item_p;

    reg_read_lock();
    item_p=list_head.head;
    while(item_p)
      {
        if(   item_p->entry.check_func
          )
          {
            suberror = item_p->entry.check_func(correct, check_inode);
            if(suberror < 0)
              error = suberror;
          }
        item_p=item_p->next;
      }
    reg_read_unlock();
    return error;
  }


/*
 * Register an ADF decision module
 * Returns given positive handle or negative error code
 */

EXPORT_SYMBOL(rsbac_reg_register);

rsbac_reg_handle_t rsbac_reg_register(        rsbac_version_t    version,
                                       struct rsbac_reg_entry_t  entry)
  {
    if(version != RSBAC_REG_VERSION)
      return(-RSBAC_EINVALIDVERSION);

    /* check entry */
    if(   (   !entry.request_func
           && !entry.set_attr_func
           && !entry.need_overwrite_func
           && !entry.write_func
           && !entry.mount_func
           && !entry.umount_func
          )
       || (entry.handle <= 0)
      )
      return -RSBAC_EINVALIDVALUE;

    reg_write_lock();
    if(lookup_item(entry.handle))
      {
        rsbac_printk(KERN_INFO "rsbac_reg_register: Handle in use, registering failed: %s.\n",
               entry.name);
        entry.handle = -RSBAC_EEXISTS;
      }
    else
      {
        if(!add_item(entry))
          {
            entry.name[RSBAC_REG_NAME_LEN] = 0;
            rsbac_printk(KERN_INFO "rsbac_reg_register: registering failed for %s.\n",
                   entry.name);
            entry.handle = -RSBAC_ECOULDNOTADDITEM;
          }
#ifdef CONFIG_RSBAC_DEBUG
        else
          if(rsbac_debug_reg)
            {
              rsbac_printk(KERN_DEBUG "rsbac_reg_register: module %s registered.\n",
                     entry.name);
            }
#endif
      }
    reg_write_unlock();
    return entry.handle;
  }

/*
 * Switch module on or off - for 'normal' modules this is done by general
 * function. This is a dummy, if module switching is disabled.
 */

EXPORT_SYMBOL(rsbac_reg_switch);

int rsbac_reg_switch (rsbac_reg_handle_t handle, rsbac_boolean_t value)
  {
#ifdef CONFIG_RSBAC_SWITCH_REG
    struct rsbac_reg_list_item_t    * item_p;
           int err=0;

    if((value != FALSE) && (value != TRUE))
      return -RSBAC_EINVALIDVALUE;
    reg_read_lock();
    item_p = lookup_item(handle);
    if(item_p)
      {
        item_p->entry.switch_on = value;
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_reg)
          {
            rsbac_printk(KERN_DEBUG "rsbac_reg_switch: module %s switched to %i.\n",
                   item_p->entry.name,
                   value);
          }
#endif
      }
    else
      err = -RSBAC_EINVALIDTARGET;
    reg_read_unlock();
    return err;
#else
    return(-RSBAC_EINVALIDTARGET);
#endif
  };

/*
 * Unregister an ADF decision module
 * Returns 0 on success or negative error code. Be careful not to unregister
 * modules you did not register yourself.
 */

EXPORT_SYMBOL(rsbac_reg_unregister);

int rsbac_reg_unregister(rsbac_reg_handle_t handle)
  {
    int    err=0;

    if(handle <= 0)
      return -RSBAC_EINVALIDVALUE;

    reg_write_lock();
    if(lookup_item(handle))
      {
        remove_item(handle);
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_reg)
          {
            rsbac_printk(KERN_DEBUG "rsbac_reg_unregister: module unregistered.\n");
          }
#endif
      }
    else
      {
        err = -RSBAC_EINVALIDTARGET;
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_reg)
          {
            rsbac_printk(KERN_DEBUG "rsbac_reg_unregister: module unregistering failed.\n");
          }
#endif
      }
    reg_write_unlock();
    return err;
  }


/*
 * Register a system call
 * Returns given positive handle or negative error code
 */

EXPORT_SYMBOL(rsbac_reg_register_syscall);

rsbac_reg_handle_t rsbac_reg_register_syscall(       rsbac_version_t            version,
                                              struct rsbac_reg_syscall_entry_t  entry)
  {
    if(version != RSBAC_REG_VERSION)
      return(-RSBAC_EINVALIDVERSION);

    /* check entry */
    if(   !entry.syscall_func
       || (entry.registration_handle <= 0)
       || (entry.dispatcher_handle <= 0)
      )
      return -RSBAC_EINVALIDVALUE;

    reg_sc_write_lock();
    if(lookup_sc_item_reg(entry.registration_handle))
      {
        rsbac_printk(KERN_INFO "rsbac_reg_register_syscall: Registration handle in use, registering failed: %s.\n",
               entry.name);
        entry.registration_handle = -RSBAC_EEXISTS;
      }
    else
    if(lookup_sc_item_dis(entry.dispatcher_handle))
      {
        rsbac_printk(KERN_INFO "rsbac_reg_register_syscall: Dispatcher handle in use, registering failed: %s.\n",
               entry.name);
        entry.registration_handle = -RSBAC_EEXISTS;
      }
    else
      {
        entry.name[RSBAC_REG_NAME_LEN] = 0;
        if(!add_sc_item(entry))
          {
            rsbac_printk(KERN_INFO "rsbac_reg_register_syscall: registering failed for %s.\n",
                   entry.name);
            entry.registration_handle = -RSBAC_ECOULDNOTADDITEM;
          }
#ifdef CONFIG_RSBAC_DEBUG
        else
          if(rsbac_debug_reg)
            {
              rsbac_printk(KERN_DEBUG "rsbac_reg_register_syscall: syscall %s registered.\n",
                     entry.name);
            }
#endif
      }
    reg_sc_write_unlock();
    return entry.registration_handle;
  }

/*
 * Unregister a system call
 * Returns 0 on success or negative error code. Be careful not to unregister
 * syscalls you did not register yourself.
 */

EXPORT_SYMBOL(rsbac_reg_unregister_syscall);

int rsbac_reg_unregister_syscall(rsbac_reg_handle_t handle)
  {
    int    err=0;

    if(handle <= 0)
      return -RSBAC_EINVALIDVALUE;

    reg_sc_write_lock();
    if(lookup_sc_item_reg(handle))
      {
        remove_sc_item(handle);
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_reg)
          {
            rsbac_printk(KERN_DEBUG "rsbac_reg_unregister_syscall: syscall unregistered.\n");
          }
#endif
      }
    else
      {
        err = -RSBAC_EINVALIDTARGET;
        rsbac_printk(KERN_INFO "rsbac_reg_unregister_syscall: syscall unregistering failed for invalid handle!\n");
      }
    reg_sc_write_unlock();
    return err;
  }

int rsbac_reg_syscall(rsbac_reg_handle_t handle,
                      void * arg)
  {
    int err = 0;
    struct rsbac_reg_sc_list_item_t    * item_p;

    reg_sc_read_lock();
    item_p=lookup_sc_item_dis(handle);
    if(item_p && item_p->entry.syscall_func)
      {
        err = item_p->entry.syscall_func(arg);
      }
    else
      {
        err = -RSBAC_EINVALIDTARGET;
      }
    reg_sc_read_unlock();
    return err;
  }
  
/* end of rsbac/adf/reg/reg_main.c */
