/*********************************** */
/* Rule Set Based Access Control     */
/* Author and (c) 1999-2011:         */
/*   Amon Ott <ao@rsbac.org>         */
/* Getname functions for JAIL module */
/* Last modified: 12/Jul/2011        */
/*********************************** */

#include <rsbac/getname.h>
#include <rsbac/jail_getname.h>
#include <rsbac/helpers.h>
#include <rsbac/error.h>

#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/sched.h>
#include <rsbac/debug.h>
#include <rsbac/aci.h>
#include <rsbac/rkmem.h>
#else
#include <string.h>
#endif

#ifdef __KERNEL__
#ifdef CONFIG_RSBAC_JAIL_LOG_MISSING
void rsbac_jail_log_missing_cap(int cap)
  {
    char * tmp;
    union rsbac_target_id_t       i_tid;
    union rsbac_attribute_value_t i_attr_val1;

    i_tid.process = task_pid(current);
    if (rsbac_get_attr(SW_JAIL,
                       T_PROCESS,
                       i_tid,
                       A_jail_max_caps,
                       &i_attr_val1,
                       FALSE))
      {
        rsbac_ds_get_error("rsbac_jail_log_missing_cap()", A_jail_max_caps);
      }
    else
      {
        if(!((i_attr_val1.jail_max_caps.cap[0] & (1 << cap)) || (i_attr_val1.jail_max_caps.cap[1] & (1 << cap))))
          {
            tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
            if(tmp)
              {
                get_cap_name(tmp, cap);
                rsbac_printk(KERN_DEBUG
                             "capable(): pid %u(%.15s), uid %u: missing jail_max_cap %s!\n",
                             current->pid, current->comm,
                             current_uid(),
                             tmp);
                  rsbac_kfree(tmp);
              }
          }
      }
  }
#endif
#endif
