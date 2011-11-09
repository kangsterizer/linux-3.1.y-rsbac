/******************************************* */
/* Rule Set Based Access Control             */
/*                                           */
/* Author and (c) 1999-2011:                 */
/*   Amon Ott <ao@rsbac.org>                 */
/*                                           */
/* Debug and logging functions for all parts */
/*                                           */
/* Last modified: 12/Jul/2011                */
/******************************************* */
 
#include <asm/uaccess.h>
#include <rsbac/types.h>
#include <rsbac/aci.h>
#include <rsbac/aci_data_structures.h>
#include <rsbac/debug.h>
#include <rsbac/error.h>
#include <rsbac/proc_fs.h>
#include <rsbac/getname.h>
#include <rsbac/net_getname.h>
#include <rsbac/adf.h>
#include <rsbac/rkmem.h>
#if defined(CONFIG_RSBAC_DAZ)
#include <rsbac/daz.h>
#endif
#include <linux/init.h>
#include <linux/module.h>
#include <linux/console.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/moduleparam.h>
#include <linux/syscalls.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/seq_file.h>

extern u_int rsbac_list_rcu_rate;

unsigned long int rsbac_flags;

/* Boolean debug switch for NO_WRITE (global) */
int  rsbac_debug_no_write = 0;

static rsbac_boolean_t debug_initialized = FALSE;

#ifdef CONFIG_RSBAC_FD_CACHE
rsbac_time_t rsbac_fd_cache_ttl = CONFIG_RSBAC_FD_CACHE_TTL;
u_int rsbac_fd_cache_disable = 0;
#endif

#if defined(CONFIG_RSBAC_AUTO_WRITE) && (CONFIG_RSBAC_AUTO_WRITE > 0)
rsbac_time_t rsbac_list_check_interval = CONFIG_RSBAC_LIST_CHECK_INTERVAL;
#endif

#ifdef CONFIG_RSBAC_DEBUG
/* Boolean debug switch for data structures */
int  rsbac_debug_ds = 0;

/* Boolean debug switch for writing of data structures */
int  rsbac_debug_write = 0;

/* Boolean debug switch for AEF */
EXPORT_SYMBOL(rsbac_debug_aef);
int  rsbac_debug_aef = 0;

/* Boolean debug switch for stack debugging */
int  rsbac_debug_stack = 0;

/* Boolean debug switch for generic lists */
int  rsbac_debug_lists = 0;

#ifdef CONFIG_RSBAC_NET
int rsbac_debug_ds_net = 0;
int rsbac_debug_adf_net = 0;
int rsbac_debug_aef_net = 0;
#endif

#if defined(CONFIG_RSBAC_MAC)
/* Boolean debug switch for MAC data structures */
int  rsbac_debug_ds_mac = 0;
/* Boolean debug switch for MAC syscalls / AEF */
int  rsbac_debug_aef_mac = 0;
/* Boolean debug switch for MAC decisions / ADF */
int  rsbac_debug_adf_mac = 0;
#endif

#if defined(CONFIG_RSBAC_PM) || defined(CONFIG_RSBAC_PM_MAINT)
/* Boolean debug switch for PM data structures */
int  rsbac_debug_ds_pm = 0;
/* Boolean debug switch for PM syscalls / AEF */
int  rsbac_debug_aef_pm = 0;
/* Boolean debug switch for PM decisions / ADF */
int  rsbac_debug_adf_pm = 0;
#endif

#if defined(CONFIG_RSBAC_DAZ)
/* Boolean debug switch for DAZ decisions / ADF */
int  rsbac_debug_adf_daz = 0;
#endif

#if defined(CONFIG_RSBAC_RC) || defined(CONFIG_RSBAC_RC_MAINT)
/* Boolean debug switch for RC data structures */
int  rsbac_debug_ds_rc = 0;
/* Boolean debug switch for RC syscalls / AEF */
int  rsbac_debug_aef_rc = 0;
/* Boolean debug switch for RC decisions / ADF */
int  rsbac_debug_adf_rc = 0;
#endif

#if defined(CONFIG_RSBAC_AUTH) || defined(CONFIG_RSBAC_AUTH_MAINT)
/* Boolean debug switch for AUTH data structures */
int  rsbac_debug_ds_auth = 0;
/* Boolean debug switch for AUTH syscalls / AEF */
int  rsbac_debug_aef_auth = 0;
/* Boolean debug switch for AUTH decisions / ADF */
int  rsbac_debug_adf_auth = 0;
#endif

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
/* Boolean debug switch for REG */
int  rsbac_debug_reg = 0;
#endif

#if defined(CONFIG_RSBAC_ACL) || defined(CONFIG_RSBAC_ACL_MAINT)
/* Boolean debug switch for ACL data structures */
int  rsbac_debug_ds_acl = 0;
/* Boolean debug switch for ACL syscalls / AEF */
int  rsbac_debug_aef_acl = 0;
/* Boolean debug switch for ACL decisions / ADF */
int  rsbac_debug_adf_acl = 0;
#endif

#if defined(CONFIG_RSBAC_JAIL)
/* Boolean debug switch for JAIL syscalls / AEF */
int  rsbac_debug_aef_jail = 0;
/* Boolean debug switch for JAIL decisions / ADF */
int  rsbac_debug_adf_jail = 0;
#endif

#if defined(CONFIG_RSBAC_PAX)
/* Boolean debug switch for PAX decisions / ADF */
int  rsbac_debug_adf_pax = 0;
#endif

#if defined(CONFIG_RSBAC_UM)
/* Boolean debug switch for UM data structures */
int  rsbac_debug_ds_um = 0;
/* Boolean debug switch for UM syscalls / AEF */
int  rsbac_debug_aef_um = 0;
/* Boolean debug switch for UM decisions / ADF */
int  rsbac_debug_adf_um = 0;
#endif

#if defined(CONFIG_RSBAC_AUTO_WRITE) && (CONFIG_RSBAC_AUTO_WRITE > 0)
  int  rsbac_debug_auto = 0;
#endif

#endif /* DEBUG */

#if defined(CONFIG_RSBAC_UM_EXCL)
int  rsbac_um_no_excl = 0;
#endif

#if defined(CONFIG_RSBAC_RC_LEARN)
int  rsbac_rc_learn = 0;
#endif

#if defined(CONFIG_RSBAC_AUTH) || defined(CONFIG_RSBAC_AUTH_MAINT)
/* Boolean switch for AUTH init: set may_setuid for /bin/login */
int  rsbac_auth_enable_login = 0;
#if defined(CONFIG_RSBAC_AUTH_LEARN)
int  rsbac_auth_learn = 0;
#endif
#endif

#if defined(CONFIG_RSBAC_CAP_LEARN)
int  rsbac_cap_learn = 0;
#endif

#if defined(CONFIG_RSBAC_ACL_LEARN)
int  rsbac_acl_learn_fd = 0;
#endif

/* Suppress default list creation for complete restore */
int  rsbac_no_defaults = 0;

static rsbac_list_handle_t log_levels_handle = NULL;

#ifdef CONFIG_RSBAC_SOFTMODE
/* Boolean switch for RSBAC soft mode */
int  rsbac_softmode = 0;
int  rsbac_softmode_prohibit = 0;
#ifdef CONFIG_RSBAC_SOFTMODE_IND
int  rsbac_ind_softmode[SW_NONE] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0};
#endif
#endif

int rsbac_list_recover = 0;

#ifdef CONFIG_RSBAC_FREEZE
int rsbac_freeze = 0;
#endif

#if defined(CONFIG_RSBAC_CAP_PROC_HIDE)
int rsbac_cap_process_hiding = 0;
#endif
#ifdef CONFIG_RSBAC_CAP_LOG_MISSING
int rsbac_cap_log_missing = 0;
#endif
#ifdef CONFIG_RSBAC_JAIL_LOG_MISSING
int rsbac_jail_log_missing = 0;
#endif

#ifdef CONFIG_RSBAC_ALLOW_DAC_DISABLE_FULL
/* Boolean switch for disabling Linux DAC */
int  rsbac_dac_disable = 0;

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_dac_is_disabled);
#endif
int rsbac_dac_is_disabled(void)
  {
    return rsbac_dac_disable;
  }
#endif

static u_int log_seq = 0;

/* Boolean switch for no syslog option*/
#ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
int  rsbac_nosyslog = 0;
#endif

#ifdef CONFIG_RSBAC_SYSLOG_RATE
static u_int rsbac_syslog_rate = CONFIG_RSBAC_SYSLOG_RATE_DEF;
static u_int syslog_count = 0;
#endif

/* Boolean switch for delayed init option*/
#ifdef CONFIG_RSBAC_INIT_DELAY
int  rsbac_no_delay_init = 0;
kdev_t rsbac_delayed_root = RSBAC_MKDEV(0,0);
#endif

/* Array of Boolean debug switches for ADF */
int  rsbac_debug_adf_default = 1;
rsbac_log_entry_t  rsbac_log_levels[R_NONE+1];

rsbac_boolean_t rsbac_debug_adf_dirty = FALSE;

/* variables for rsbac_logging */
#if defined(CONFIG_RSBAC_RMSG)
#include <linux/poll.h>
#include <linux/smp.h>
DECLARE_WAIT_QUEUE_HEAD(rlog_wait);
struct rsbac_log_list_head_t log_list_head = {NULL, NULL, 0, 0};
static u_int rsbac_rmsg_maxentries = CONFIG_RSBAC_RMSG_MAXENTRIES;
#if defined(CONFIG_RSBAC_LOG_REMOTE)
struct rsbac_log_list_head_t remote_log_list_head = {NULL, NULL, 0, 0};
static DECLARE_WAIT_QUEUE_HEAD(rsbaclogd_wait);
static u_int rsbac_log_remote_maxentries = CONFIG_RSBAC_LOG_REMOTE_MAXENTRIES;
#ifndef CONFIG_RSBAC_LOG_REMOTE_SYNC
static struct timer_list rsbac_log_remote_timer;
u_int rsbac_log_remote_interval = CONFIG_RSBAC_LOG_INTERVAL;
#endif
rsbac_pid_t rsbaclogd_pid=0;
#define REMOTE_SEND_BUF_LEN 1024
static __u16 rsbac_log_remote_port = 0;
static __u32 rsbac_log_remote_addr = 0;
static char rsbac_log_remote_addr_string[RSBAC_MAXNAMELEN] = CONFIG_RSBAC_LOG_REMOTE_ADDR;
#endif

#endif /* RMSG */

#ifdef CONFIG_RSBAC_SYSLOG_RATE
static struct timer_list rsbac_syslog_rate_timer;
#endif

void  rsbac_adf_log_switch(rsbac_adf_request_int_t request,
                           enum rsbac_target_t target,
                           rsbac_enum_t value)
  {
    if(   (request < R_NONE)
       && (target <= T_NONE)
       && (value <= LL_full)
      )
      {
        rsbac_log_levels[request][target] = value;
        if(log_levels_handle)
          rsbac_list_add(log_levels_handle, &request, rsbac_log_levels[request]);
      }
  };

int rsbac_get_adf_log(rsbac_adf_request_int_t request,
                      enum rsbac_target_t target,
                      u_int * value_p)
  {
    if(   (request < R_NONE)
       && (target <= T_NONE)
      )
      {
        *value_p = rsbac_log_levels[request][target];
        return 0;
      }
    else
      return -RSBAC_EINVALIDVALUE;
  }

static int R_INIT rsbac_flags_setup(char * line)
{
	rsbac_flags = simple_strtoul(line, NULL, 0);
	rsbac_flags_set(rsbac_flags);
	return 1;
}
__setup("rsbac_flags=", rsbac_flags_setup);

//  module_param(rsbac_no_defaults, bool, S_IRUGO);
  static int R_INIT no_defaults_setup(char *line)
    {
      rsbac_no_defaults = 1;
      return 1;
    }
__setup("rsbac_no_defaults", no_defaults_setup);

  #if defined(CONFIG_RSBAC_UM_EXCL)
  static int R_INIT um_no_excl_setup(char *line)
    {
      rsbac_um_no_excl = 1;
      return 1;
    }
  __setup("rsbac_um_no_excl", um_no_excl_setup);
  #endif
  #if defined(CONFIG_RSBAC_DAZ_CACHE)
  /* RSBAC: DAZ - set cache ttl */
//    module_param(rsbac_daz_ttl,
//                 int,
//                 S_IRUGO);
  static int R_INIT daz_ttl_setup(char *line)
    {
      rsbac_daz_set_ttl(simple_strtoul(line, NULL, 0));
      return 1;
    }
  __setup("rsbac_daz_ttl=", daz_ttl_setup);
  #endif
  #if defined(CONFIG_RSBAC_RC_LEARN)
  static int R_INIT rc_learn_setup(char *line)
    {
      rsbac_rc_learn = 1;
      rsbac_debug_adf_rc = 1;
      return 1;
    }
  __setup("rsbac_rc_learn", rc_learn_setup);
  #endif
  #if defined(CONFIG_RSBAC_AUTH) || defined(CONFIG_RSBAC_AUTH_MAINT)
  /* RSBAC: AUTH - set auth_may_setuid for /bin/login? */
//    module_param(rsbac_auth_enable_login, int, S_IRUGO);
  static int R_INIT auth_enable_login_setup(char *line)
    {
      rsbac_auth_enable_login = 1;
      return 1;
    }
  __setup("rsbac_auth_enable_login", auth_enable_login_setup);
    #if defined(CONFIG_RSBAC_AUTH_LEARN)
  static int R_INIT auth_learn_setup(char *line)
    {
      rsbac_auth_learn = 1;
      return 1;
    }
  __setup("rsbac_auth_learn", auth_learn_setup);
    #endif
  #endif
  #if defined(CONFIG_RSBAC_CAP_LEARN)
  static int R_INIT cap_learn_setup(char *line)
    {
      rsbac_cap_learn = 1;
      return 1;
    }
  __setup("rsbac_cap_learn", cap_learn_setup);
  #endif
  #if defined(CONFIG_RSBAC_ACL_LEARN)
  /* learn all target types */
  static int R_INIT acl_learn_setup(char *line)
    {
      rsbac_acl_learn_fd = 1;
      return 1;
    }
  __setup("rsbac_acl_learn", acl_learn_setup);
  static int R_INIT acl_learn_fd_setup(char *line)
    {
      rsbac_acl_learn_fd = 1;
      return 1;
    }
  __setup("rsbac_acl_learn_fd", acl_learn_fd_setup);
  #endif
  #if defined(CONFIG_RSBAC_RC_LEARN) || defined(CONFIG_RSBAC_AUTH_LEARN) || defined(CONFIG_RSBAC_ACL_LEARN) || defined(CONFIG_RSBAC_CAP_LEARN)
  static int R_INIT learn_all_setup(char *line)
    {
  #if defined(CONFIG_RSBAC_RC_LEARN)
      rsbac_rc_learn = 1;
      rsbac_debug_adf_rc = 1;
  #endif
  #if defined(CONFIG_RSBAC_AUTH_LEARN)
      rsbac_auth_learn = 1;
  #endif
  #if defined(CONFIG_RSBAC_ACL_LEARN)
      rsbac_acl_learn_fd = 1;
  #endif
  #if defined(CONFIG_RSBAC_CAP_LEARN)
      rsbac_cap_learn = 1;
  #endif
      return 1;
    }
  __setup("rsbac_learn_all", learn_all_setup);
  #endif

  #if defined(CONFIG_RSBAC_SOFTMODE)
  /* RSBAC: softmode on? */
//    module_param(rsbac_softmode_once, bool, S_IRUGO);
//    module_param(rsbac_softmode, bool, S_IRUGO);
  static int R_INIT softmode_setup(char *line)
    {
      rsbac_softmode = 1;
      return 1;
    }
  __setup("rsbac_softmode", softmode_setup);
  static int R_INIT softmode_once_setup(char *line)
    {
      rsbac_softmode = 1;
      rsbac_softmode_prohibit = 1;
      return 1;
    }
  __setup("rsbac_softmode_once", softmode_once_setup);
//    module_param(rsbac_softmode_never, bool, S_IRUGO);
  static int R_INIT softmode_never_setup(char *line)
    {
      rsbac_softmode_prohibit = 1;
      return 1;
    }
  __setup("rsbac_softmode_never", softmode_never_setup);

    #if defined(CONFIG_RSBAC_SOFTMODE_IND)
    /* RSBAC: softmode on for a module? */
//    module_param_named(rsbac_softmode_mac, rsbac_ind_softmode[MAC], bool, S_IRUGO);
  static int R_INIT softmode_mac_setup(char *line)
    {
      rsbac_ind_softmode[SW_MAC] = 1;
      return 1;
    }
  __setup("rsbac_softmode_mac", softmode_mac_setup);
//    module_param_named(rsbac_softmode_pm, rsbac_ind_softmode[SW_PM], bool, S_IRUGO);
  static int R_INIT softmode_pm_setup(char *line)
    {
      rsbac_ind_softmode[SW_PM] = 1;
      return 1;
    }
  __setup("rsbac_softmode_pm", softmode_pm_setup);
//    module_param_named(rsbac_softmode_daz, rsbac_ind_softmode[SW_DAZ], bool, S_IRUGO);
  static int R_INIT softmode_daz_setup(char *line)
    {
      rsbac_ind_softmode[SW_DAZ] = 1;
      return 1;
    }
  __setup("rsbac_softmode_daz", softmode_daz_setup);
//    module_param_named(rsbac_softmode_ff, rsbac_ind_softmode[SW_FF], bool, S_IRUGO);
  static int R_INIT softmode_ff_setup(char *line)
    {
      rsbac_ind_softmode[SW_FF] = 1;
      return 1;
    }
  __setup("rsbac_softmode_ff", softmode_ff_setup);
//    module_param_named(rsbac_softmode_rc, rsbac_ind_softmode[SW_RC], bool, S_IRUGO);
  static int R_INIT softmode_rc_setup(char *line)
    {
      rsbac_ind_softmode[SW_RC] = 1;
      return 1;
    }
  __setup("rsbac_softmode_rc", softmode_rc_setup);
//    module_param_named(rsbac_softmode_auth, rsbac_ind_softmode[SW_AUTH], bool, S_IRUGO);
  static int R_INIT softmode_auth_setup(char *line)
    {
      rsbac_ind_softmode[SW_AUTH] = 1;
      return 1;
    }
  __setup("rsbac_softmode_auth", softmode_auth_setup);
//    module_param_named(rsbac_softmode_reg, rsbac_ind_softmode[SW_REG], bool, S_IRUGO);
  static int R_INIT softmode_reg_setup(char *line)
    {
      rsbac_ind_softmode[SW_REG] = 1;
      return 1;
    }
  __setup("rsbac_softmode_reg", softmode_reg_setup);
//    module_param_named(rsbac_softmode_acl, rsbac_ind_softmode[SW_ACL], bool, S_IRUGO);
  static int R_INIT softmode_acl_setup(char *line)
    {
      rsbac_ind_softmode[SW_ACL] = 1;
      return 1;
    }
  __setup("rsbac_softmode_acl", softmode_acl_setup);
//    module_param_named(rsbac_softmode_cap, rsbac_ind_softmode[SW_CAP], bool, S_IRUGO);
  static int R_INIT softmode_cap_setup(char *line)
    {
      rsbac_ind_softmode[SW_CAP] = 1;
      return 1;
    }
  __setup("rsbac_softmode_cap", softmode_cap_setup);
//    module_param_named(rsbac_softmode_jail, rsbac_ind_softmode[SW_JAIL], bool, S_IRUGO);
  static int R_INIT softmode_jail_setup(char *line)
    {
      rsbac_ind_softmode[SW_JAIL] = 1;
      return 1;
    }
  __setup("rsbac_softmode_jail", softmode_jail_setup);
//    module_param_named(rsbac_softmode_res, rsbac_ind_softmode[SW_RES], bool, S_IRUGO);
  static int R_INIT softmode_res_setup(char *line)
    {
      rsbac_ind_softmode[SW_RES] = 1;
      return 1;
    }
  __setup("rsbac_softmode_res", softmode_res_setup);
    #endif
    #endif

    #if defined(CONFIG_RSBAC_CAP_PROC_HIDE)
    /* RSBAC: hide processes? */
//    module_param(rsbac_cap_process_hiding, bool, S_IRUGO);
  static int R_INIT cap_process_hiding_setup(char *line)
    {
      rsbac_cap_process_hiding = 1;
      return 1;
    }
  __setup("rsbac_cap_process_hiding", cap_process_hiding_setup);
    #endif
    #ifdef CONFIG_RSBAC_CAP_LOG_MISSING
    /* RSBAC: log missing caps? */
//    module_param(rsbac_cap_log_missing, bool, S_IRUGO);
  static int R_INIT cap_log_missing_setup(char *line)
    {
      rsbac_cap_log_missing = 1;
      return 1;
    }
  __setup("rsbac_cap_log_missing", cap_log_missing_setup);
    #endif
    #ifdef CONFIG_RSBAC_JAIL_LOG_MISSING
    /* RSBAC: log missing jail caps? */
//    module_param(rsbac_jail_log_missing, bool, S_IRUGO);
  static int R_INIT jail_log_missing_setup(char *line)
    {
      rsbac_jail_log_missing = 1;
      return 1;
    }
  __setup("rsbac_jail_log_missing", jail_log_missing_setup);
    #endif
    #if defined(CONFIG_RSBAC_FREEZE)
    /* RSBAC: freeze config? */
//    module_param(rsbac_freeze, bool, S_IRUGO);
  static int R_INIT freeze_setup(char *line)
    {
      rsbac_freeze = 1;
      return 1;
    }
  __setup("rsbac_freeze", freeze_setup);
    #endif
    /* RSBAC: recover lists? */
//    module_param(rsbac_list_recover, bool, S_IRUGO);
  static int R_INIT list_recover_setup(char *line)
    {
      rsbac_list_recover = 1;
      return 1;
    }
  __setup("rsbac_list_recover", list_recover_setup);
  static int R_INIT list_rcu_rate_setup(char *line)
    {
      rsbac_list_rcu_rate = simple_strtoul(line, NULL, 0);
      if (rsbac_list_rcu_rate < 1)
        rsbac_list_rcu_rate = 1;
      else
      if (rsbac_list_rcu_rate > 100000)
        rsbac_list_rcu_rate = 100000;
      return 1;
    }
  __setup("rsbac_list_rcu_rate=", list_rcu_rate_setup);
    #ifdef CONFIG_RSBAC_ALLOW_DAC_DISABLE_FULL
    /* RSBAC: disable Linux DAC? */
//    module_param(rsbac_dac_disable, bool, S_IRUGO);
  static int R_INIT dac_disable_setup(char *line)
    {
      rsbac_dac_disable = 1;
      return 1;
    }
  __setup("rsbac_dac_disable", dac_disable_setup);
    #endif
    #ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
//    module_param(rsbac_nosyslog, bool, S_IRUGO);
  static int R_INIT nosyslog_setup(char *line)
    {
      rsbac_nosyslog = 1;
      return 1;
    }
  __setup("rsbac_nosyslog", nosyslog_setup);
//    module_param_named(rsbac_no_syslog, rsbac_nosyslog, bool, S_IRUGO);
  static int R_INIT no_syslog_setup(char *line)
    {
      rsbac_nosyslog = 1;
      return 1;
    }
  __setup("rsbac_no_syslog", no_syslog_setup);
    #endif
    #if defined(CONFIG_RSBAC_RMSG)
  static int R_INIT rmsg_maxentries_setup(char *line)
    {
      rsbac_rmsg_maxentries = simple_strtoul(line, NULL, 0);
      return 1;
    }
  __setup("rsbac_rmsg_maxentries=", rmsg_maxentries_setup);
    #endif
    #if defined(CONFIG_RSBAC_LOG_REMOTE)
//    module_param_string(rsbac_log_remote_addr,
//                        rsbac_log_remote_addr_string,
//                        sizeof(rsbac_log_remote_addr_string),
//                        S_IRUGO);
  static int R_INIT log_remote_addr_setup(char *line)
    {
      strncpy(rsbac_log_remote_addr_string, line, RSBAC_MAXNAMELEN - 1);
      rsbac_log_remote_addr_string[RSBAC_MAXNAMELEN - 1]=0;
      return 1;
    }
  __setup("rsbac_log_remote_addr=", log_remote_addr_setup);
//    module_param(rsbac_log_remote_port,
//                 int,
//                 S_IRUGO);
  static int R_INIT log_remote_port_setup(char *line)
    {
      __u16 tmp_port;

      tmp_port = simple_strtoul(line, NULL, 0);
      rsbac_log_remote_port = htons(tmp_port);
      return 1;
    }
  __setup("rsbac_log_remote_port=", log_remote_port_setup);
  static int R_INIT log_remote_maxentries_setup(char *line)
    {
      rsbac_log_remote_maxentries = simple_strtoul(line, NULL, 0);
      return 1;
    }
  __setup("rsbac_log_remote_maxentries=", log_remote_maxentries_setup);
    #endif
    #ifdef CONFIG_RSBAC_INIT_DELAY
//    module_param(rsbac_no_delay_init, bool, S_IRUGO);
  static int R_INIT no_delay_init_setup(char *line)
    {
      rsbac_no_delay_init = 1;
      return 1;
    }
  __setup("rsbac_no_delay_init", no_delay_init_setup);
//    module_param_named(rsbac_no_init_delay, rsbac_no_delay_init, bool, S_IRUGO);
  static int R_INIT no_init_delay_setup(char *line)
    {
      rsbac_no_delay_init = 1;
      return 1;
    }
  __setup("rsbac_no_init_delay", no_init_delay_setup);
    char rsbac_delayed_root_str[20] = "";
//    module_param_string(rsbac_delayed_root,
//                        rsbac_delayed_root_str,
//                        sizeof(rsbac_delayed_root_str),
//                        S_IRUGO);
  static int R_INIT delayed_root_setup(char *line)
    {
      strncpy(rsbac_delayed_root_str, line, 19);
      rsbac_delayed_root_str[19]=0;
      return 1;
    }
  __setup("rsbac_delayed_root=", delayed_root_setup);
    #endif
    #ifdef CONFIG_RSBAC_SYSLOG_RATE
//    module_param(rsbac_syslog_rate,
//                 int,
//                 S_IRUGO);
  static int R_INIT syslog_rate_setup(char *line)
    {
      rsbac_syslog_rate = simple_strtoul(line, NULL, 0);
      return 1;
    }
  __setup("rsbac_syslog_rate=", syslog_rate_setup);
    #endif
#ifdef CONFIG_RSBAC_FD_CACHE
//    module_param(rsbac_fd_cache_ttl,
//                 int,
//                 S_IRUGO);
  static int R_INIT fd_cache_ttl_setup(char *line)
    {
      rsbac_fd_cache_ttl = simple_strtoul(line, NULL, 0);
      return 1;
    }
  __setup("rsbac_fd_cache_ttl=", fd_cache_ttl_setup);
//    module_param(rsbac_fd_cache_disable, bool, S_IRUGO);
  static int R_INIT fd_cache_disable_setup(char *line)
    {
      rsbac_fd_cache_disable = 1;
      return 1;
    }
  __setup("rsbac_fd_cache_disable", fd_cache_disable_setup);
#endif
#if defined(CONFIG_RSBAC_AUTO_WRITE) && (CONFIG_RSBAC_AUTO_WRITE > 0)
//    module_param(rsbac_list_check_interval,
//                 int,
//                 S_IRUGO);
  static int R_INIT list_check_interval_setup(char *line)
    {
      rsbac_list_check_interval = simple_strtoul(line, NULL, 0);
      return 1;
    }
  __setup("rsbac_list_check_interval=", list_check_interval_setup);
#endif

#ifdef CONFIG_RSBAC_DEBUG
    #ifdef CONFIG_RSBAC_NET
    /* RSBAC: debug for net data structures? */
//    module_param(rsbac_debug_ds_net, bool, S_IRUGO);
  static int R_INIT debug_ds_net_setup(char *line)
    {
      rsbac_debug_ds_net = 1;
      return 1;
    }
  __setup("rsbac_debug_ds_net", debug_ds_net_setup);
    /* RSBAC: debug for net syscalls/AEF? */
//    module_param(rsbac_debug_aef_net, bool, S_IRUGO);
  static int R_INIT debug_aef_net_setup(char *line)
    {
      rsbac_debug_aef_net = 1;
      return 1;
    }
  __setup("rsbac_debug_aef_net", debug_aef_net_setup);
    /* RSBAC: debug for net decisions/ADF? */
//    module_param(rsbac_debug_adf_net, bool, S_IRUGO);
  static int R_INIT debug_adf_net_setup(char *line)
    {
      rsbac_debug_adf_net = 1;
      return 1;
    }
  __setup("rsbac_debug_adf_net", debug_adf_net_setup);
    #endif

    #if defined(CONFIG_RSBAC_MAC)
//    module_param(rsbac_debug_ds_mac, bool, S_IRUGO);
  static int R_INIT debug_ds_mac_setup(char *line)
    {
      rsbac_debug_ds_mac = 1;
      return 1;
    }
  __setup("rsbac_debug_ds_mac", debug_ds_mac_setup);
//    module_param(rsbac_debug_aef_mac, bool, S_IRUGO);
  static int R_INIT debug_aef_mac_setup(char *line)
    {
      rsbac_debug_aef_mac = 1;
      return 1;
    }
  __setup("rsbac_debug_aef_mac", debug_aef_mac_setup);
//    module_param(rsbac_debug_adf_mac, bool, S_IRUGO);
  static int R_INIT debug_adf_mac_setup(char *line)
    {
      rsbac_debug_adf_mac = 1;
      return 1;
    }
  __setup("rsbac_debug_adf_mac", debug_adf_mac_setup);
  #if defined(CONFIG_RSBAC_SWITCH_MAC) && defined(RSBAC_SWITCH_BOOT_OFF)
//    module_param(rsbac_switch_off_mac, bool, S_IRUGO);
  static int R_INIT switch_off_mac_setup(char *line)
    {
      rsbac_switch_mac = 0;
      return 1;
    }
  __setup("rsbac_switch_off_mac", switch_off_mac_setup);
  #endif
    #endif
    #if defined(CONFIG_RSBAC_PM) || defined(CONFIG_RSBAC_PM_MAINT)
//    module_param(rsbac_debug_ds_pm, bool, S_IRUGO);
  static int R_INIT debug_ds_pm_setup(char *line)
    {
      rsbac_debug_ds_pm = 1;
      return 1;
    }
  __setup("rsbac_debug_ds_pm", debug_ds_pm_setup);
//    module_param(rsbac_debug_aef_pm, bool, S_IRUGO);
  static int R_INIT debug_aef_pm_setup(char *line)
    {
      rsbac_debug_aef_pm = 1;
      return 1;
    }
  __setup("rsbac_debug_aef_pm", debug_aef_pm_setup);
//    module_param(rsbac_debug_adf_pm, bool, S_IRUGO);
  static int R_INIT debug_adf_pm_setup(char *line)
    {
      rsbac_debug_adf_pm = 1;
      return 1;
    }
  __setup("rsbac_debug_adf_pm", debug_adf_pm_setup);
  #if defined(CONFIG_RSBAC_SWITCH_PM) && defined(RSBAC_SWITCH_BOOT_OFF)
//    module_param(rsbac_switch_off_mac, bool, S_IRUGO);
  static int R_INIT switch_off_pm_setup(char *line)
    {
      rsbac_switch_pm = 0;
      return 1;
    }
  __setup("rsbac_switch_off_pm", switch_off_pm_setup);
  #endif
    #endif
    #if defined(CONFIG_RSBAC_DAZ)
//    module_param(rsbac_debug_adf_daz, bool, S_IRUGO);
  static int R_INIT debug_adf_daz_setup(char *line)
    {
      rsbac_debug_adf_daz = 1;
      return 1;
    }
  __setup("rsbac_debug_adf_daz", debug_adf_daz_setup);
  #if defined(CONFIG_RSBAC_SWITCH_DAZ) && defined(RSBAC_SWITCH_BOOT_OFF)
//    module_param(rsbac_switch_off_mac, bool, S_IRUGO);
  static int R_INIT switch_off_daz_setup(char *line)
    {
      rsbac_switch_daz = 0;
      return 1;
    }
  __setup("rsbac_switch_off_daz", switch_off_daz_setup);
  #endif
    #endif
    #if defined(CONFIG_RSBAC_RC) || defined(CONFIG_RSBAC_RC_MAINT)
//    module_param(rsbac_debug_ds_rc, bool, S_IRUGO);
  static int R_INIT debug_ds_rc_setup(char *line)
    {
      rsbac_debug_ds_rc = 1;
      return 1;
    }
  __setup("rsbac_debug_ds_rc", debug_ds_rc_setup);
//    module_param(rsbac_debug_aef_rc, bool, S_IRUGO);
  static int R_INIT debug_aef_rc_setup(char *line)
    {
      rsbac_debug_aef_rc = 1;
      return 1;
    }
  __setup("rsbac_debug_aef_rc", debug_aef_rc_setup);
//    module_param(rsbac_debug_adf_rc, bool, S_IRUGO);
  static int R_INIT debug_adf_rc_setup(char *line)
    {
      rsbac_debug_adf_rc = 1;
      return 1;
    }
  __setup("rsbac_debug_adf_rc", debug_adf_rc_setup);
  #if defined(CONFIG_RSBAC_SWITCH_RC) && defined(RSBAC_SWITCH_BOOT_OFF)
//    module_param(rsbac_switch_off_rc, bool, S_IRUGO);
  static int R_INIT switch_off_rc_setup(char *line)
    {
      rsbac_switch_rc = 0;
      return 1;
    }
  __setup("rsbac_switch_off_rc", switch_off_rc_setup);
  #endif
    #endif
    #if defined(CONFIG_RSBAC_AUTH) || defined(CONFIG_RSBAC_AUTH_MAINT)
//    module_param(rsbac_debug_ds_auth, bool, S_IRUGO);
  static int R_INIT debug_ds_auth_setup(char *line)
    {
      rsbac_debug_ds_auth = 1;
      return 1;
    }
  __setup("rsbac_debug_ds_auth", debug_ds_auth_setup);
//    module_param(rsbac_debug_aef_auth, bool, S_IRUGO);
  static int R_INIT debug_aef_auth_setup(char *line)
    {
      rsbac_debug_aef_auth = 1;
      return 1;
    }
  __setup("rsbac_debug_aef_auth", debug_aef_auth_setup);
//    module_param(rsbac_debug_adf_auth, bool, S_IRUGO);
  static int R_INIT debug_adf_auth_setup(char *line)
    {
      rsbac_debug_adf_auth = 1;
      return 1;
    }
  __setup("rsbac_debug_adf_auth", debug_adf_auth_setup);
  #if defined(CONFIG_RSBAC_SWITCH_AUTH) && defined(RSBAC_SWITCH_BOOT_OFF)
//    module_param(rsbac_switch_off_auth, bool, S_IRUGO);
  static int R_INIT switch_off_auth_setup(char *line)
    {
      rsbac_switch_auth = 0;
      return 1;
    }
  __setup("rsbac_switch_off_auth", switch_off_auth_setup);
  #endif
    #endif
    #if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
//    module_param(rsbac_debug_reg, bool, S_IRUGO);
  static int R_INIT debug_reg_setup(char *line)
    {
      rsbac_debug_reg = 1;
      return 1;
    }
  __setup("rsbac_debug_reg", debug_reg_setup);
    #endif
    #if defined(CONFIG_RSBAC_ACL) || defined(CONFIG_RSBAC_ACL_MAINT)
//    module_param(rsbac_debug_ds_acl, bool, S_IRUGO);
  static int R_INIT debug_ds_acl_setup(char *line)
    {
      rsbac_debug_ds_acl = 1;
      return 1;
    }
  __setup("rsbac_debug_ds_acl", debug_ds_acl_setup);
//    module_param(rsbac_debug_aef_acl, bool, S_IRUGO);
  static int R_INIT debug_aef_acl_setup(char *line)
    {
      rsbac_debug_aef_acl = 1;
      return 1;
    }
  __setup("rsbac_debug_aef_acl", debug_aef_acl_setup);
//    module_param(rsbac_debug_adf_acl, bool, S_IRUGO);
  static int R_INIT debug_adf_acl_setup(char *line)
    {
      rsbac_debug_adf_acl = 1;
      return 1;
    }
  __setup("rsbac_debug_adf_acl", debug_adf_acl_setup);
  #if defined(CONFIG_RSBAC_SWITCH_ACL) && defined(RSBAC_SWITCH_BOOT_OFF)
//    module_param(rsbac_switch_off_acl, bool, S_IRUGO);
  static int R_INIT switch_off_acl_setup(char *line)
    {
      rsbac_switch_acl = 0;
      return 1;
    }
  __setup("rsbac_switch_off_acl", switch_off_acl_setup);
  #endif
    #endif
    #if defined(CONFIG_RSBAC_JAIL)
//    module_param(rsbac_debug_aef_jail, bool, S_IRUGO);
  static int R_INIT debug_aef_jail_setup(char *line)
    {
      rsbac_debug_aef_jail = 1;
      return 1;
    }
  __setup("rsbac_debug_aef_jail", debug_aef_jail_setup);
//    module_param(rsbac_debug_adf_jail, bool, S_IRUGO);
  static int R_INIT debug_adf_jail_setup(char *line)
    {
      rsbac_debug_adf_jail = 1;
      return 1;
    }
  __setup("rsbac_debug_adf_jail", debug_adf_jail_setup);
  #if defined(CONFIG_RSBAC_SWITCH_JAIL) && defined(RSBAC_SWITCH_BOOT_OFF)
//    module_param(rsbac_switch_off_jail, bool, S_IRUGO);
  static int R_INIT switch_off_jail_setup(char *line)
    {
      rsbac_switch_jail = 0;
      return 1;
    }
  __setup("rsbac_switch_off_jail", switch_off_jail_setup);
  #endif
    #endif
    #if defined(CONFIG_RSBAC_PAX)
//    module_param(rsbac_debug_adf_pax, bool, S_IRUGO);
  static int R_INIT debug_adf_pax_setup(char *line)
    {
      rsbac_debug_adf_pax = 1;
      return 1;
    }
  __setup("rsbac_debug_adf_pax", debug_adf_pax_setup);
  #if defined(CONFIG_RSBAC_SWITCH_PAX) && defined(RSBAC_SWITCH_BOOT_OFF)
//    module_param(rsbac_switch_off_pax, bool, S_IRUGO);
  static int R_INIT switch_off_pax_setup(char *line)
    {
      rsbac_switch_pax = 0;
      return 1;
    }
  __setup("rsbac_switch_off_pax", switch_off_pax_setup);
  #endif
    #endif
  #if defined(CONFIG_RSBAC_SWITCH_FF) && defined(RSBAC_SWITCH_BOOT_OFF)
//    module_param(rsbac_switch_off_ff, bool, S_IRUGO);
  static int R_INIT switch_off_ff_setup(char *line)
    {
      rsbac_switch_ff = 0;
      return 1;
    }
  __setup("rsbac_switch_off_ff", switch_off_ff_setup);
  #endif
  #if defined(CONFIG_RSBAC_SWITCH_RES) && defined(RSBAC_SWITCH_BOOT_OFF)
//    module_param(rsbac_switch_off_res, bool, S_IRUGO);
  static int R_INIT switch_off_res_setup(char *line)
    {
      rsbac_switch_res = 0;
      return 1;
    }
  __setup("rsbac_switch_off_res", switch_off_res_setup);
  #endif
  #if defined(CONFIG_RSBAC_SWITCH_CAP) && defined(RSBAC_SWITCH_BOOT_OFF)
//    module_param(rsbac_switch_off_cap, bool, S_IRUGO);
  static int R_INIT switch_off_cap_setup(char *line)
    {
      rsbac_switch_cap = 0;
      return 1;
    }
  __setup("rsbac_switch_off_cap", switch_off_cap_setup);
  #endif
    #if defined(CONFIG_RSBAC_UM)
//    module_param(rsbac_debug_ds_um, bool, S_IRUGO);
  static int R_INIT debug_ds_um_setup(char *line)
    {
      rsbac_debug_ds_um = 1;
      return 1;
    }
  __setup("rsbac_debug_ds_um", debug_ds_um_setup);
//    module_param(rsbac_debug_aef_um, bool, S_IRUGO);
  static int R_INIT debug_aef_um_setup(char *line)
    {
      rsbac_debug_aef_um = 1;
      return 1;
    }
  __setup("rsbac_debug_aef_um", debug_aef_um_setup);
//    module_param(rsbac_debug_adf_um, bool, S_IRUGO);
  static int R_INIT debug_adf_um_setup(char *line)
    {
      rsbac_debug_adf_um = 1;
      return 1;
    }
  __setup("rsbac_debug_adf_um", debug_adf_um_setup);
    #endif
    #if defined(CONFIG_RSBAC_AUTO_WRITE) && (CONFIG_RSBAC_AUTO_WRITE > 0)
//    module_param(rsbac_debug_auto, bool, S_IRUGO);
  static int R_INIT debug_auto_setup(char *line)
    {
      rsbac_debug_auto = 1;
      return 1;
    }
  __setup("rsbac_debug_auto", debug_auto_setup);
    #endif
    /* RSBAC: debug_lists */
//    module_param(rsbac_debug_lists, bool, S_IRUGO);
  static int R_INIT debug_lists_setup(char *line)
    {
      rsbac_debug_lists = 1;
      return 1;
    }
  __setup("rsbac_debug_lists", debug_lists_setup);
    /* RSBAC: debug_stack */
//    module_param(rsbac_debug_stack, bool, S_IRUGO);
  static int R_INIT debug_stack_setup(char *line)
    {
      rsbac_debug_stack = 1;
      return 1;
    }
  __setup("rsbac_debug_stack", debug_stack_setup);
    /* RSBAC: debug for data structures? */
//    module_param(rsbac_debug_ds, bool, S_IRUGO);
  static int R_INIT debug_ds_setup(char *line)
    {
      rsbac_debug_ds = 1;
      return 1;
    }
  __setup("rsbac_debug_ds", debug_ds_setup);
    /* RSBAC: debug for writing of data structures? */
//    module_param(rsbac_debug_write, bool, S_IRUGO);
  static int R_INIT debug_write_setup(char *line)
    {
      rsbac_debug_write = 1;
      return 1;
    }
  __setup("rsbac_debug_write", debug_write_setup);
    /* RSBAC: debug for AEF? */
//    module_param(rsbac_debug_aef, bool, S_IRUGO);
  static int R_INIT debug_aef_setup(char *line)
    {
      rsbac_debug_aef = 1;
      return 1;
    }
  __setup("rsbac_debug_aef", debug_aef_setup);
    /* RSBAC: debug_no_write for ds */
//    module_param(rsbac_debug_no_write, bool, S_IRUGO);
  static int R_INIT debug_no_write_setup(char *line)
    {
      rsbac_debug_no_write = 1;
      return 1;
    }
  __setup("rsbac_debug_no_write", debug_no_write_setup);
    /* RSBAC: debug default for ADF */
//    module_param(rsbac_debug_adf_default, int, S_IRUGO);
  static int R_INIT debug_adf_default_setup(char *line)
    {
      rsbac_debug_adf_default = 1;
      return 1;
    }
  __setup("rsbac_debug_adf_default", debug_adf_default_setup);
#endif /* DEBUG */

#if defined(CONFIG_RSBAC_RMSG)
static DEFINE_SPINLOCK(rsbac_log_lock);

#if defined(CONFIG_RSBAC_LOG_REMOTE)
static DEFINE_SPINLOCK(rsbac_log_remote_lock);
#endif

/*
 * Commands to do_syslog:
 *
 * 	0 -- Close the log.  Currently a NOP.
 * 	1 -- Open the log. Currently a NOP.
 * 	2 -- Read from the log.
 * 	3 -- Read all messages remaining in the ring buffer.
 * 	4 -- Read and clear all messages remaining in the ring buffer
 * 	5 -- Clear ring buffer.
 *	9 -- Return number of unread characters in the log buffer
 */
int rsbac_log(int type, char * buf, int len)
{
	unsigned long count;
	int do_clear = 0;
	int error = 0;
	char * k_buf;

        union rsbac_target_id_t       rsbac_target_id;
        union rsbac_attribute_value_t rsbac_attribute_value;
	struct rsbac_log_list_item_t * log_item;

        /* RSBAC */
        rsbac_target_id.scd = ST_rsbac_log;
        rsbac_attribute_value.dummy = 0;
        if ((type == 4) || (type == 5))
          {
#ifdef CONFIG_RSBAC_DEBUG
            if (rsbac_debug_aef)
              {
                rsbac_printk(KERN_DEBUG "rsbac_log(): function %u, calling ADF for MODIFY_SYSTEM_DATA\n", type);
              }
#endif
            if (!rsbac_adf_request(R_MODIFY_SYSTEM_DATA,
                                   task_pid(current),
                                   T_SCD,
                                   rsbac_target_id,
                                   A_none,
                                   rsbac_attribute_value))
              {
                error = -EPERM;
                goto out;
              }
          }
        else
        if(type >= 1)
          {
#ifdef CONFIG_RSBAC_DEBUG
            if (rsbac_debug_aef)
              {
                rsbac_printk(KERN_DEBUG "rsbac_log(): function %u, calling ADF for GET_STATUS_DATA\n", type);
              }
#endif
            if (!rsbac_adf_request(R_GET_STATUS_DATA,
                                   task_pid(current),
                                   T_SCD,
                                   rsbac_target_id,
                                   A_none,
                                   rsbac_attribute_value))
              {
                error = -EPERM;
                goto out;
              }
          }

	switch (type) {
	case 0:		/* Close log */
		break;
	case 1:		/* Open log */
		break;
	case 2:		/* Read from log */
		error = -EINVAL;
		if (!buf || len < 0)
			goto out;
		error = 0;
		if (!len)
			goto out;
		error = access_ok(VERIFY_WRITE,buf,len);
		if (!error)
			goto out;
		error = wait_event_interruptible(rlog_wait, log_list_head.count);
		if (error)
			goto out;
		if (len > RSBAC_LOG_MAXREADBUF)
			len = RSBAC_LOG_MAXREADBUF;
		k_buf = rsbac_kmalloc(len);
		count = 0;
		spin_lock(&rsbac_log_lock);
		log_item = log_list_head.head;
		while (log_item && (count + log_item->size < len)) {
			memcpy(k_buf + count, log_item->buffer, log_item->size);
			count += log_item->size;
			log_item = log_item->next;
			kfree(log_list_head.head);
			log_list_head.head = log_item;
			if(!log_item)
				log_list_head.tail = NULL;
			log_list_head.count--;
		}
		spin_unlock(&rsbac_log_lock);
		error = copy_to_user(buf, k_buf, count);
		if (!error)
			error = count;
		rsbac_kfree(k_buf);
		break;
	case 4:		/* Read/clear last kernel messages */
		do_clear = 1; 
		/* FALL THRU */
	case 3:		/* Read last kernel messages */
		error = -EINVAL;
		if (!buf || len < 0)
			goto out;
		error = 0;
		if (!len)
			goto out;
		error = access_ok(VERIFY_WRITE,buf,len);
		if (!error)
			goto out;
		if (len > RSBAC_LOG_MAXREADBUF)
			len = RSBAC_LOG_MAXREADBUF;
		k_buf = rsbac_kmalloc(len);
		count = 0;
		spin_lock(&rsbac_log_lock);
		log_item = log_list_head.head;
		while (log_item && (count + log_item->size < len)) {
			memcpy(k_buf + count, log_item->buffer, log_item->size);
			count += log_item->size;
			log_item = log_item->next;
			if(do_clear) {
				kfree(log_list_head.head);
				log_list_head.head = log_item;
				if(!log_item)
					log_list_head.tail = NULL;
				log_list_head.count--;
			}
		}
		spin_unlock(&rsbac_log_lock);
		error = copy_to_user(buf, k_buf, count);
		if (!error)
			error = count;
		rsbac_kfree(k_buf);
		break;
	case 5:		/* Clear ring buffer */
		spin_lock(&rsbac_log_lock);
		log_item = log_list_head.head;
		while (log_item) {
			log_item = log_item->next;
			kfree(log_list_head.head);
			log_list_head.head = log_item;
		}
		log_list_head.tail = NULL;
		log_list_head.count = 0;
		spin_unlock(&rsbac_log_lock);
		error = 0;
		break;
	case 9:		/* Number of chars in the log buffer */
		error = 0;
		spin_lock(&rsbac_log_lock);
		log_item = log_list_head.head;
		while (log_item) {
			error += log_item->size;
			log_item = log_item->next;
		}
		spin_unlock(&rsbac_log_lock);
		break;
	default:
		error = -EINVAL;
		break;
	}
out:
	return error;
}
#endif /* RMSG */

#ifdef CONFIG_RSBAC_SYSLOG_RATE
static void syslog_rate_reset(u_long dummy)
  {
    if(syslog_count > rsbac_syslog_rate)
      printk(KERN_INFO "syslog_rate_reset: resetting syslog_count at %u, next message is %u\n",
             syslog_count, log_seq);
    syslog_count = 0;
    mod_timer(&rsbac_syslog_rate_timer, jiffies + HZ);
  }
#endif

EXPORT_SYMBOL(rsbac_printk);
int rsbac_printk(const char *fmt, ...)
{
	va_list args;
	int printed_len;
        char * buf;
#if defined(CONFIG_RSBAC_RMSG)
	struct rsbac_log_list_item_t * log_item;
#endif

	if (rsbac_is_initialized())
		buf = rsbac_kmalloc(RSBAC_LOG_MAXLINE);
	else
		buf = kmalloc(RSBAC_LOG_MAXLINE, GFP_ATOMIC);
	if (!buf)
		return -ENOMEM;
	/* Emit the output into the buffer */
	va_start(args, fmt);
	printed_len = vsnprintf(buf + 11, RSBAC_LOG_MAXLINE - 14, fmt, args);
	va_end(args);
	if(printed_len < 4) {
		kfree(buf);
		return printed_len;
	}
	buf[0] = '<';
	buf[1] = buf[12];
	buf[2] = '>';
	sprintf(buf + 3, "%010u", log_seq++);
	buf[13] = '|';
	/* Terminate string */
	buf[printed_len + 11] = 0;

	/* copy to printk */
#ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
	if (!rsbac_nosyslog)
#endif
	{
#ifdef CONFIG_RSBAC_SYSLOG_RATE
		syslog_count++;
		if(syslog_count < rsbac_syslog_rate)
#endif
			printk("%s", buf);
#ifdef CONFIG_RSBAC_SYSLOG_RATE
		else
			if(syslog_count == rsbac_syslog_rate)
				printk(KERN_INFO "rsbac_printk: Applying syslog rate limit at count %u, message %u!\n",
					syslog_count, log_seq - 1);
#endif
	}
	/* Buffer is ready, now link into log list */
#if defined(CONFIG_RSBAC_RMSG)
	if (rsbac_is_initialized())
		log_item = rsbac_kmalloc(sizeof(*log_item) + printed_len + 12);
	else
		log_item = kmalloc(sizeof(*log_item) + printed_len + 12, GFP_ATOMIC);
	if(log_item) {
		memcpy(log_item->buffer, buf, printed_len + 11);
		log_item->size = printed_len + 11;
		log_item->next = NULL;
		spin_lock(&rsbac_log_lock);
		if (log_list_head.tail) {
			log_list_head.tail->next = log_item;
		} else {
			log_list_head.head = log_item;
		}
		log_list_head.tail = log_item;
		log_list_head.count++;
		while(log_list_head.count > rsbac_rmsg_maxentries) {
			log_item = log_list_head.head;
			log_list_head.head = log_item->next;
			log_list_head.count--;
			log_list_head.lost++;
			kfree(log_item);
		}
		spin_unlock(&rsbac_log_lock);
		wake_up_interruptible(&rlog_wait);
	}
#endif

#if defined(CONFIG_RSBAC_LOG_REMOTE)
	/* Link into remote log list */
	if (rsbac_is_initialized())
		log_item = rsbac_kmalloc(sizeof(*log_item) + printed_len + 12);
	else
		log_item = kmalloc(sizeof(*log_item) + printed_len + 12, GFP_ATOMIC);
	if(log_item) {
		memcpy(log_item->buffer, buf, printed_len + 11);
		log_item->size = printed_len + 11;
		log_item->next = NULL;
		spin_lock(&rsbac_log_remote_lock);
		if (remote_log_list_head.tail) {
			remote_log_list_head.tail->next = log_item;
		} else {
			remote_log_list_head.head = log_item;
		}
		remote_log_list_head.tail = log_item;
		remote_log_list_head.count++;
		while(remote_log_list_head.count > rsbac_log_remote_maxentries) {
			log_item = remote_log_list_head.head;
			remote_log_list_head.head = log_item->next;
			remote_log_list_head.count--;
			remote_log_list_head.lost++;
			kfree(log_item);
		}
		spin_unlock(&rsbac_log_remote_lock);
#ifdef CONFIG_RSBAC_LOG_REMOTE_SYNC
		wake_up_interruptible(&rsbaclogd_wait);
#endif
	}
#endif

	kfree(buf);
	return printed_len;
}

#if defined(CONFIG_RSBAC_RMSG)
#if defined(CONFIG_RSBAC_PROC)
static int rmsg_open(struct inode * inode, struct file * file)
{
	return rsbac_log(1,NULL,0);
}

static int rmsg_release(struct inode * inode, struct file * file)
{
	(void) rsbac_log(0,NULL,0);
	return 0;
}

static ssize_t rmsg_read(struct file * file, char * buf,
			 size_t count, loff_t *ppos)
{
	return rsbac_log(2,buf,count);
}

static unsigned int rmsg_poll(struct file *file, poll_table * wait)
{
	poll_wait(file, &rlog_wait, wait);
	if (rsbac_log(9, 0, 0))
		return POLLIN | POLLRDNORM;
	return 0;
}

static struct file_operations rmsg_proc_fops = {
	.read = rmsg_read,
	.poll = rmsg_poll,	/* rmsg_poll */
	.open = rmsg_open,
	.release = rmsg_release
};

static struct proc_dir_entry *rmsg;

#endif /* PROC */
#endif /* RMSG */

#if defined(CONFIG_RSBAC_PROC)
#ifndef PROC_BLOCK_SIZE
#define PROC_BLOCK_SIZE	(3*1024)  /* 4K page size but our output routines use some slack for overruns */
#endif

static int
log_levels_proc_show(struct seq_file *m, void *v)
{
  int i,j;
  char * name;
  char * name2;

  union rsbac_target_id_t       rsbac_target_id;
  union rsbac_attribute_value_t rsbac_attribute_value;

  if (!rsbac_is_initialized())
    return (-ENOSYS);

#ifdef CONFIG_RSBAC_DEBUG
  if (rsbac_debug_aef)
    {
      rsbac_printk(KERN_DEBUG "log_levels_proc_info(): calling ADF\n");
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

  name = rsbac_kmalloc(RSBAC_MAXNAMELEN);
  if(!name)
    return -ENOMEM;
  name2 = rsbac_kmalloc(RSBAC_MAXNAMELEN);
  if(!name2)
    {
      rsbac_kfree(name);
      return -ENOMEM;
    }
    
  seq_printf(m, "RSBAC Log Levels\n----------------\n");
  seq_printf(m, "Name\t\t\tFILE\tDIR\tFIFO\tSYMLINK\tDEV\tIPC\tSCD\tUSER\tPROCESS\tNETDEV\tNETTEMP\tNETOBJ\tNETT_NT\tNONE\n");

  for (i = 0; i<R_NONE; i++)
    {
      seq_printf(m, "%-23s",
                     get_request_name(name, i));
      for(j = 0; j<=T_NONE; j++)
        {
          if(j != T_FD)
            seq_printf(m, "\t%u",
                           rsbac_log_levels[i][j]);
        }
      seq_printf(m, "\n");
    }

  rsbac_kfree(name);
  rsbac_kfree(name2);

  return 0;
}

static ssize_t log_levels_proc_write(struct file * file, const char __user * buf,
                                     size_t count, loff_t *ppos)
{
    ssize_t err;
    char * k_buf;
    char * p;
    unsigned int log_level;
    char rname[RSBAC_MAXNAMELEN];
    int i,j;

    union rsbac_target_id_t       rsbac_target_id;
    union rsbac_attribute_value_t rsbac_attribute_value;

    if(count > PROC_BLOCK_SIZE) {
	return(-EOVERFLOW);
    }

    if (!(k_buf = (char *) __get_free_page(GFP_KERNEL)))
      return(-ENOMEM);
    err = copy_from_user(k_buf, buf, count);
    if(err < 0)
      return err;

  err = count;
  if(count < 15 || strncmp("log_levels", k_buf, 10))
    {
      goto out;
    }
  if (!rsbac_is_initialized())
    {
      err = -ENOSYS;
      goto out;
    }

    /*
     * Usage: echo "log_levels request #N" > /proc/rsbac_info/log_levels
     *   to set log level for request to given value
     */
    for(i=0; i<R_NONE; i++)
      {
        get_request_name(rname,i);
        if(!strncmp(rname, k_buf + 11, strlen(rname))) 
          {
#ifdef CONFIG_RSBAC_DEBUG
            if (rsbac_debug_aef)
              {
                rsbac_printk(KERN_DEBUG "log_levels_proc_write(): calling ADF\n");
              }
#endif
            rsbac_target_id.dummy = 0;
            rsbac_attribute_value.request = i;
            if (!rsbac_adf_request(R_SWITCH_LOG,
                                   task_pid(current),
                                   T_NONE,
                                   rsbac_target_id,
                                   A_request,
                                   rsbac_attribute_value))
              {
                err = -EPERM;
                goto out;
              }
	    p = k_buf + 11 + strlen(rname)+1;

            if( *p == '\0' )
              goto out;

            log_level = simple_strtoul(p, NULL, 0);
            /* only accept 0 or 1 */
            if(   (log_level == LL_none)
               || (log_level == LL_denied)
               || (log_level == LL_full)
              )
              {
                rsbac_printk(KERN_INFO
                       "log_levels_proc_write(): setting %s log level for all target types to %u\n",
                       rname, log_level);
                for(j = 0; j<=T_NONE; j++)
                  {
                    rsbac_log_levels[i][j] = log_level;
                  }
                err = count;
                goto out;
              }
            else
              {
                rsbac_printk(KERN_INFO
                       "log_levels_proc_write(): rejecting invalid log level (should be %u, %u or %u)\n",
                       LL_none, LL_denied, LL_full);
                goto out;
              }
          }
      }

out:
  free_page((ulong) k_buf);
  return(err);
  }

static int log_levels_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, log_levels_proc_show, NULL);
}

static const struct file_operations log_levels_proc_fops = {
       .owner          = THIS_MODULE,
       .open           = log_levels_proc_open,
       .read           = seq_read,
       .write          = log_levels_proc_write,
       .llseek         = seq_lseek,
       .release        = single_release,
};

static struct proc_dir_entry *log_levels;

static int
debug_proc_show(struct seq_file *m, void *v)
{
  union rsbac_target_id_t       rsbac_target_id;
  union rsbac_attribute_value_t rsbac_attribute_value;

  if (!rsbac_is_initialized())
    return (-ENOSYS);

#ifdef CONFIG_RSBAC_DEBUG
  if (rsbac_debug_aef)
      rsbac_printk(KERN_DEBUG "debug_proc_info(): calling ADF\n");
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
  seq_printf(m, "RSBAC Debug Settings\n--------------------\n");

#ifdef CONFIG_RSBAC_SOFTMODE
  seq_printf(m, "rsbac_softmode is %i\n",
                 rsbac_softmode);
  seq_printf(m, "rsbac_softmode_prohibit is %i\n",
                 rsbac_softmode_prohibit);
#ifdef CONFIG_RSBAC_SOFTMODE_IND
#ifdef CONFIG_RSBAC_MAC
  seq_printf(m, "rsbac_ind_softmode[MAC] is %i\n",
                 rsbac_ind_softmode[SW_MAC]);
#endif
#ifdef CONFIG_RSBAC_PM
  seq_printf(m, "rsbac_ind_softmode[PM] is %i\n",
                 rsbac_ind_softmode[SW_PM]);
#endif
#ifdef CONFIG_RSBAC_DAZ
  seq_printf(m, "rsbac_ind_softmode[DAZ] is %i\n",
                 rsbac_ind_softmode[SW_DAZ]);
#endif
#ifdef CONFIG_RSBAC_FF
  seq_printf(m, "rsbac_ind_softmode[FF] is %i\n",
                 rsbac_ind_softmode[SW_FF]);
#endif
#ifdef CONFIG_RSBAC_RC
  seq_printf(m, "rsbac_ind_softmode[RC] is %i\n",
                 rsbac_ind_softmode[SW_RC]);
#endif
#ifdef CONFIG_RSBAC_AUTH
  seq_printf(m, "rsbac_ind_softmode[AUTH] is %i\n",
                 rsbac_ind_softmode[SW_AUTH]);
#endif
#ifdef CONFIG_RSBAC_REG
  seq_printf(m, "rsbac_ind_softmode[REG] is %i\n",
                 rsbac_ind_softmode[SW_REG]);
#endif
#ifdef CONFIG_RSBAC_ACL
  seq_printf(m, "rsbac_ind_softmode[ACL] is %i\n",
                 rsbac_ind_softmode[SW_ACL]);
#endif
#ifdef CONFIG_RSBAC_CAP
  seq_printf(m, "rsbac_ind_softmode[CAP] is %i\n",
                 rsbac_ind_softmode[SW_CAP]);
#endif
#ifdef CONFIG_RSBAC_JAIL
  seq_printf(m, "rsbac_ind_softmode[JAIL] is %i\n",
                 rsbac_ind_softmode[SW_JAIL]);
#endif
#ifdef CONFIG_RSBAC_RES
  seq_printf(m, "rsbac_ind_softmode[RES] is %i\n",
                 rsbac_ind_softmode[SW_RES]);
#endif
#endif
#endif
#ifdef CONFIG_RSBAC_FREEZE
  seq_printf(m, "rsbac_freeze is %i\n",
                 rsbac_freeze);
#endif
  seq_printf(m, "rsbac_list_recover is %i (read-only)\n",
                 rsbac_list_recover);
  seq_printf(m, "rsbac_list_rcu_rate is %u\n",
                 rsbac_list_rcu_rate);
#if defined(CONFIG_RSBAC_DAZ_CACHE)
  /* RSBAC: DAZ - set cache ttl */
  seq_printf(m, "rsbac_daz_ttl is %u\n",
                 rsbac_daz_get_ttl());
#endif
#ifdef CONFIG_RSBAC_CAP_PROC_HIDE
  seq_printf(m, "rsbac_cap_process_hiding is %i\n",
                 rsbac_cap_process_hiding);
#endif
#ifdef CONFIG_RSBAC_CAP_LOG_MISSING
  seq_printf(m, "rsbac_cap_log_missing is %i\n",
                 rsbac_cap_log_missing);
#endif
#ifdef CONFIG_RSBAC_JAIL_LOG_MISSING
  seq_printf(m, "rsbac_jail_log_missing is %i\n",
                 rsbac_jail_log_missing);
#endif

#ifdef CONFIG_RSBAC_ALLOW_DAC_DISABLE_FULL
  seq_printf(m, "rsbac_dac_disable is %i\n",
                 rsbac_dac_disable);
#endif

#ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
  seq_printf(m, "rsbac_nosyslog is %i\n",
                 rsbac_nosyslog);
#endif

#ifdef CONFIG_RSBAC_SYSLOG_RATE
  seq_printf(m, "rsbac_syslog_rate is %u\n",
                 rsbac_syslog_rate);
#endif

#ifdef CONFIG_RSBAC_FD_CACHE
  if (!rsbac_fd_cache_disable)
    seq_printf(m, "rsbac_fd_cache_ttl is %u\n",
                   rsbac_fd_cache_ttl);
#endif
#if defined(CONFIG_RSBAC_AUTO_WRITE) && (CONFIG_RSBAC_AUTO_WRITE > 0)
  seq_printf(m, "rsbac_list_check_interval is %u\n",
                 rsbac_list_check_interval);
#endif

#if defined(CONFIG_RSBAC_LOG_REMOTE)
#if defined(CONFIG_RSBAC_LOG_REMOTE_TCP)
  seq_printf(m, "rsbac_log_remote_addr (TCP) is %u.%u.%u.%u\n",
                 NIPQUAD(rsbac_log_remote_addr));
#else
  seq_printf(m, "rsbac_log_remote_addr (UDP) is %u.%u.%u.%u\n",
                 NIPQUAD(rsbac_log_remote_addr));
#endif
  seq_printf(m, "rsbac_log_remote_port is %u\n",
                 ntohs(rsbac_log_remote_port));
#endif

#ifdef CONFIG_RSBAC_INIT_DELAY
  seq_printf(m, "rsbac_no_delay_init is %i\n",
                 rsbac_no_delay_init);
  seq_printf(m, "rsbac_delayed_root is %02u:%02u\n",
                 RSBAC_MAJOR(rsbac_delayed_root), RSBAC_MINOR(rsbac_delayed_root));
#endif

#if defined(CONFIG_RSBAC_UM_EXCL)
  seq_printf(m, "rsbac_um_no_excl is %i\n",
                 rsbac_um_no_excl);
#endif

#if defined(CONFIG_RSBAC_RC_LEARN)
  seq_printf(m, "rsbac_rc_learn is %i\n",
                 rsbac_rc_learn);
#endif

#if defined(CONFIG_RSBAC_AUTH)
  seq_printf(m, "rsbac_auth_enable_login is %i\n",
                 rsbac_auth_enable_login);

#if defined(CONFIG_RSBAC_AUTH_LEARN)
  seq_printf(m, "rsbac_auth_learn is %i\n",
                 rsbac_auth_learn);
#endif
#endif

#if defined(CONFIG_RSBAC_CAP_LEARN)
  seq_printf(m, "rsbac_cap_learn is %i\n",
                 rsbac_cap_learn);
#endif

#if defined(CONFIG_RSBAC_ACL_LEARN)
  seq_printf(m, "rsbac_acl_learn_fd is %i\n",
                 rsbac_acl_learn_fd);
#endif

  seq_printf(m, "rsbac_no_defaults is %i\n",
                 rsbac_no_defaults);
#ifdef CONFIG_RSBAC_DEBUG
  seq_printf(m, "rsbac_debug_write is %i\n",
                 rsbac_debug_write);
  seq_printf(m, "rsbac_debug_stack is %i\n",
                 rsbac_debug_stack);
  seq_printf(m, "rsbac_debug_lists is %i\n",
                 rsbac_debug_lists);
  seq_printf(m, "rsbac_debug_ds is %i\n",
                 rsbac_debug_ds);
  seq_printf(m, "rsbac_debug_aef is %i\n",
                 rsbac_debug_aef);
  seq_printf(m, "rsbac_debug_no_write is %i\n",
                 rsbac_debug_no_write);

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
/* Boolean debug switch for REG */
  seq_printf(m, "rsbac_debug_reg is %i\n",
                 rsbac_debug_reg);
#endif

#if defined(CONFIG_RSBAC_NET)
/* Boolean debug switch for NET data structures */
  seq_printf(m, "rsbac_debug_ds_net is %i\n",
                 rsbac_debug_ds_net);
/* Boolean debug switch for NET syscalls / AEF */
  seq_printf(m, "rsbac_debug_aef_net is %i\n",
                 rsbac_debug_aef_net);
/* Boolean debug switch for NET decisions / ADF */
  seq_printf(m, "rsbac_debug_adf_net is %i\n",
                 rsbac_debug_adf_net);
#endif

#if defined(CONFIG_RSBAC_MAC)
/* Boolean debug switch for MAC data structures */
  seq_printf(m, "rsbac_debug_ds_mac is %i\n",
                 rsbac_debug_ds_mac);
/* Boolean debug switch for MAC syscalls / AEF */
  seq_printf(m, "rsbac_debug_aef_mac is %i\n",
                 rsbac_debug_aef_mac);
/* Boolean debug switch for MAC decisions / ADF */
  seq_printf(m, "rsbac_debug_adf_mac is %i\n",
                 rsbac_debug_adf_mac);
#endif

#if defined(CONFIG_RSBAC_PM) || defined(CONFIG_RSBAC_PM_MAINT)
/* Boolean debug switch for PM data structures */
  seq_printf(m, "rsbac_debug_ds_pm is %i\n",
                 rsbac_debug_ds_pm);
/* Boolean debug switch for PM syscalls / AEF */
  seq_printf(m, "rsbac_debug_aef_pm is %i\n",
                 rsbac_debug_aef_pm);
/* Boolean debug switch for PM decisions / ADF */
  seq_printf(m, "rsbac_debug_adf_pm is %i\n",
                 rsbac_debug_adf_pm);
#endif

#if defined(CONFIG_RSBAC_DAZ)
/* Boolean debug switch for DAZ decisions / ADF */
  seq_printf(m, "rsbac_debug_adf_daz is %i\n",
                 rsbac_debug_adf_daz);
#endif

#if defined(CONFIG_RSBAC_RC) || defined(CONFIG_RSBAC_RC_MAINT)
/* Boolean debug switch for RC data structures */
  seq_printf(m, "rsbac_debug_ds_rc is %i\n",
                 rsbac_debug_ds_rc);
/* Boolean debug switch for RC syscalls / AEF */
  seq_printf(m, "rsbac_debug_aef_rc is %i\n",
                 rsbac_debug_aef_rc);
/* Boolean debug switch for RC decisions / ADF */
  seq_printf(m, "rsbac_debug_adf_rc is %i\n",
                 rsbac_debug_adf_rc);
#endif

#if defined(CONFIG_RSBAC_AUTH)
/* Boolean debug switch for AUTH data structures */
  seq_printf(m, "rsbac_debug_ds_auth is %i\n",
                 rsbac_debug_ds_auth);

/* Boolean debug switch for AUTH syscalls / AEF */
  seq_printf(m, "rsbac_debug_aef_auth is %i\n",
                 rsbac_debug_aef_auth);

/* Boolean debug switch for AUTH decisions / ADF */
  seq_printf(m, "rsbac_debug_adf_auth is %i\n",
                 rsbac_debug_adf_auth);
#endif

#if defined(CONFIG_RSBAC_ACL)
/* Boolean debug switch for ACL data structures */
  seq_printf(m, "rsbac_debug_ds_acl is %i\n",
                 rsbac_debug_ds_acl);

/* Boolean debug switch for ACL syscalls / AEF */
  seq_printf(m, "rsbac_debug_aef_acl is %i\n",
                 rsbac_debug_aef_acl);

/* Boolean debug switch for ACL decisions / ADF */
  seq_printf(m, "rsbac_debug_adf_acl is %i\n",
                 rsbac_debug_adf_acl);
#endif

#if defined(CONFIG_RSBAC_JAIL)
/* Boolean debug switch for JAIL syscalls / AEF */
  seq_printf(m, "rsbac_debug_aef_jail is %i\n",
                 rsbac_debug_aef_jail);
/* Boolean debug switch for JAIL decisions / ADF */
  seq_printf(m, "rsbac_debug_adf_jail is %i\n",
                 rsbac_debug_adf_jail);
#endif
#if defined(CONFIG_RSBAC_PAX)
/* Boolean debug switch for PAX decisions / ADF */
  seq_printf(m, "rsbac_debug_adf_pax is %i\n",
                 rsbac_debug_adf_pax);
#endif
#if defined(CONFIG_RSBAC_UM)
/* Boolean debug switch for UM data structures */
  seq_printf(m, "rsbac_debug_ds_um is %i\n",
                 rsbac_debug_ds_um);
/* Boolean debug switch for UM syscalls / AEF */
  seq_printf(m, "rsbac_debug_aef_um is %i\n",
                 rsbac_debug_aef_um);
/* Boolean debug switch for UM decisions / ADF */
  seq_printf(m, "rsbac_debug_adf_um is %i\n",
                 rsbac_debug_adf_um);
#endif

#if defined(CONFIG_RSBAC_AUTO_WRITE) && (CONFIG_RSBAC_AUTO_WRITE > 0)
  seq_printf(m, "rsbac_debug_auto is %i\n",
                 rsbac_debug_auto);
#endif /* CONFIG_RSBAC_AUTO_WRITE > 0 */
#endif /* DEBUG */

#if defined(CONFIG_RSBAC_RMSG)
  seq_printf(m, "rsbac_rmsg_maxentries is %u\n",
                 rsbac_rmsg_maxentries);
  seq_printf(m, "%u messages in log buffer, %lu messages lost, sequence is %u\n",
                 log_list_head.count, log_list_head.lost, log_seq);
#if defined(CONFIG_RSBAC_LOG_REMOTE)
  seq_printf(m, "rsbac_log_remote_maxentries is %u\n",
                 rsbac_log_remote_maxentries);
  seq_printf(m, "%u messages in remote log buffer, %lu messages lost\n",
                 remote_log_list_head.count, remote_log_list_head.lost);
#endif
#endif

  return 0;
}

static ssize_t debug_proc_write(struct file * file, const char __user * buf, size_t count, loff_t *ppos)
{
    ssize_t err;
    char * k_buf;
    char * p;
    unsigned int debug_level;
#ifdef CONFIG_RSBAC_SOFTMODE_IND
    enum rsbac_switch_target_t sw_target;
#endif

    union rsbac_target_id_t       rsbac_target_id;
    union rsbac_attribute_value_t rsbac_attribute_value;

    if(count > PROC_BLOCK_SIZE) {
	return(-EOVERFLOW);
    }
    if(count < 10)
      return -EINVAL;

    if (!(k_buf = (char *) __get_free_page(GFP_KERNEL)))
      return(-ENOMEM);
    err = copy_from_user(k_buf, buf, count);
    if(err < 0)
      return err;

  err = count;

  if(!strncmp("debug", k_buf, 5) || !strncmp("rsbac", k_buf, 5))
    {
      p = k_buf + 6;
    }
  else
  if(!strncmp("rsbac_debug", k_buf, 11))
    {
      p = k_buf + 12;
    }
  else
    goto out;

  if (!rsbac_is_initialized())
    {
      err = -ENOSYS;
      goto out;
    }
    if(count < 10)
      return -EINVAL;


#ifdef CONFIG_RSBAC_SOFTMODE
#ifdef CONFIG_RSBAC_SOFTMODE_IND
/* Boolean switch for RSBAC individual soft mode */
    /*
     * Usage: echo "debug ind_softmode modname #N" > /proc/rsbac_info/debug
     *   to set rsbac_ind_softmode[module] to given value
     */
    if(!strncmp("ind_softmode", k_buf + 6, 12)) 
      {
        char tmp[20];

	p += 13;

        if( *p == '\0' )
          goto out;

        sw_target = get_switch_target_nr(p);
        if(sw_target == SW_NONE)
          goto out;
        get_switch_target_name(tmp, sw_target);
        p += strlen(tmp)+1;
        if( *p == '\0' )
          goto out;
        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            if(debug_level && rsbac_softmode_prohibit)
              {
                rsbac_printk(KERN_WARNING
                             "debug_proc_write(): setting of softmode prohibited!\n");
                err = -EPERM;
                goto out;
              }
#if defined(CONFIG_RSBAC_DEBUG)
            if (rsbac_debug_aef)
              {
                rsbac_printk(KERN_DEBUG "debug_proc_write(): calling ADF for switching\n");
              }
#endif
            rsbac_target_id.dummy = 0;
            rsbac_attribute_value.switch_target = sw_target;
            if (!rsbac_adf_request(R_SWITCH_MODULE,
                                   task_pid(current),
                                   T_NONE,
                                   rsbac_target_id,
                                   A_switch_target,
                                   rsbac_attribute_value))
              {
                err = -EPERM;
                goto out;
              }
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_ind_softmode[%s] to %u\n",
                   tmp,
                   debug_level);
            rsbac_ind_softmode[sw_target] = debug_level;
            err = count;
            goto out;
          }
        else
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): rejecting invalid ind_softmode value (should be 0 or 1)\n");
            err = -EINVAL;
            goto out;
          }
      }
#endif

/* Boolean switch for RSBAC soft mode prohibit */
    /*
     * Usage: echo "debug softmode_prohibit #N" > /proc/rsbac_info/debug
     *   to set rsbac_softmode to given value
     */
    if(!strncmp("softmode_prohibit", k_buf + 6, 17)) 
      {
	p += 18;

        if( *p == '\0' )
          goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            if(!debug_level && rsbac_softmode_prohibit)
              {
                rsbac_printk(KERN_WARNING
                             "debug_proc_write(): setting of softmode prohibited!\n");
                err = -EPERM;
                goto out;
              }
#if defined(CONFIG_RSBAC_DEBUG)
            if (rsbac_debug_aef)
              {
                rsbac_printk(KERN_DEBUG "debug_proc_write(): calling ADF for softmode\n");
              }
#endif
            rsbac_target_id.dummy = 0;
            rsbac_attribute_value.switch_target = SW_SOFTMODE;
            if (!rsbac_adf_request(R_SWITCH_MODULE,
                                   task_pid(current),
                                   T_NONE,
                                   rsbac_target_id,
                                   A_switch_target,
                                   rsbac_attribute_value))
              {
                err = -EPERM;
                goto out;
              }
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_softmode_prohibit to %u\n",
                   debug_level);
            rsbac_softmode_prohibit = debug_level;
            err = count;
            goto out;
          }
        else
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): rejecting invalid softmode_prohibit value (should be 0 or 1)\n");
            err = -EINVAL;
            goto out;
          }
      }
/* Boolean switch for RSBAC soft mode */
    /*
     * Usage: echo "debug softmode #N" > /proc/rsbac_info/debug
     *   to set rsbac_softmode to given value
     */
    if(!strncmp("softmode", k_buf + 6, 8)) 
      {
	p += 9;

        if( *p == '\0' )
          goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            if(debug_level && rsbac_softmode_prohibit)
              {
                rsbac_printk(KERN_WARNING
                             "debug_proc_write(): setting of softmode prohibited!\n");
                err = -EPERM;
                goto out;
              }
#if defined(CONFIG_RSBAC_DEBUG)
            if (rsbac_debug_aef)
              {
                rsbac_printk(KERN_DEBUG "debug_proc_write(): calling ADF for softmode\n");
              }
#endif
            rsbac_target_id.dummy = 0;
            rsbac_attribute_value.switch_target = SW_SOFTMODE;
            if (!rsbac_adf_request(R_SWITCH_MODULE,
                                   task_pid(current),
                                   T_NONE,
                                   rsbac_target_id,
                                   A_switch_target,
                                   rsbac_attribute_value))
              {
                err = -EPERM;
                goto out;
              }
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_softmode to %u\n",
                   debug_level);
            rsbac_softmode = debug_level;
            err = count;
            goto out;
          }
        else
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): rejecting invalid softmode value (should be 0 or 1)\n");
            err = -EINVAL;
            goto out;
          }
      }
#endif

#ifdef CONFIG_RSBAC_ALLOW_DAC_DISABLE_FULL
/* Boolean switch for disabling Linux DAC */
    /*
     * Usage: echo "debug dac_disable #N" > /proc/rsbac_info/debug
     *   to set dac_disable to given value
     */
    if(!strncmp("dac_disable", k_buf + 6, 11)) 
      {
	p += 12;

        if( *p == '\0' )
          goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
#if defined(CONFIG_RSBAC_DEBUG)
            if (rsbac_debug_aef)
              {
                rsbac_printk(KERN_DEBUG "debug_proc_write(): calling ADF for dac_disable\n");
              }
#endif
            rsbac_target_id.dummy = 0;
            rsbac_attribute_value.dummy = 0;
            if (!rsbac_adf_request(R_MODIFY_PERMISSIONS_DATA,
                                   task_pid(current),
                                   T_NONE,
                                   rsbac_target_id,
                                   A_none,
                                   rsbac_attribute_value))
              {
                err = -EPERM;
                goto out;
              }
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_dac_disable to %u\n",
                   debug_level);
            rsbac_dac_disable = debug_level;
            err = count;
            goto out;
          }
        else
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): rejecting invalid dac_disabled value (should be 0 or 1)\n");
            err = -EINVAL;
            goto out;
          }
      }
#endif

#ifdef CONFIG_RSBAC_FREEZE
/* Boolean switch to enable freezing */
    /*
     * Usage: echo "debug freeze #N" > /proc/rsbac_info/debug
     *   to set freeze to given value
     */
    if(!strncmp("freeze", k_buf + 6, 6)) 
      {
	p += 7;

        if( *p == '\0' )
          goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            if(!debug_level && rsbac_freeze)
              {
                rsbac_printk(KERN_WARNING
                             "debug_proc_write(): RSBAC configuration frozen, no administration allowed!\n");
                err = -EPERM;
                goto out;
              }

#if defined(CONFIG_RSBAC_DEBUG)
            if (rsbac_debug_aef)
              {
                rsbac_printk(KERN_DEBUG "debug_proc_write(): calling ADF for freeze\n");
              }
#endif
            rsbac_target_id.dummy = 0;
            rsbac_attribute_value.switch_target = SW_FREEZE;
            if (!rsbac_adf_request(R_SWITCH_MODULE,
                                   task_pid(current),
                                   T_NONE,
                                   rsbac_target_id,
                                   A_switch_target,
                                   rsbac_attribute_value))
              {
                err = -EPERM;
                goto out;
              }
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_freeze to %u\n",
                   debug_level);
            rsbac_freeze = debug_level;
            err = count;
            goto out;
          }
        else
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): rejecting invalid freeze value (should be 0 or 1)\n");
            err = -EINVAL;
            goto out;
          }
      }
#endif

/* Set list rcu rate limit */
    /*
     * Usage: echo "debug list_rcu_rate #n" > /proc/rsbac_info/debug
     *   to set rate limit to given value
     */
    if(!strncmp("list_rcu_rate", k_buf + 6, 13)) 
      {
        u_int tmp_rate;

	p += 14;
        if( *p == '\0' )
          goto out;

        tmp_rate = simple_strtoul(p, NULL, 0);
        if (tmp_rate < 100)
          tmp_rate = 100;
        else
        if (tmp_rate > 100000)
          tmp_rate = 100000;

#if defined(CONFIG_RSBAC_DEBUG)
            if (rsbac_debug_aef)
              {
                rsbac_printk(KERN_DEBUG "debug_proc_write(): calling ADF for list_rcu_rate\n");
              }
#endif
            rsbac_target_id.scd = ST_rsbac;
            rsbac_attribute_value.dummy = 0;
            if (!rsbac_adf_request(R_MODIFY_SYSTEM_DATA,
                                   task_pid(current),
                                   T_SCD,
                                   rsbac_target_id,
                                   A_none,
                                   rsbac_attribute_value))
              {
                err = -EPERM;
                goto out;
              }
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_list_rcu_rate to %u\n",
                   tmp_rate);
            rsbac_list_rcu_rate = tmp_rate;
            err = count;
            goto out;
      }

#ifdef CONFIG_RSBAC_DAZ_CACHE
/* Set DAZ cache ttl */
    /*
     * Usage: echo "debug daz_ttl #n" > /proc/rsbac_info/debug
     *   to set daz cache ttl to given value
     */
    if(!strncmp("daz_ttl", k_buf + 6, 7)) 
      {
        rsbac_time_t tmp_ttl;
#ifndef CONFIG_RSBAC_MAINT
        union rsbac_target_id_t       i_tid;
        union rsbac_attribute_value_t i_attr_val1;
#endif

	p += 8;
        if( *p == '\0' )
          goto out;

        tmp_ttl = simple_strtoul(p, NULL, 0);
#if defined(CONFIG_RSBAC_DEBUG)
            if (rsbac_debug_aef)
              {
                rsbac_printk(KERN_DEBUG "debug_proc_write(): calling ADF for daz_ttl\n");
              }
#endif
#ifndef CONFIG_RSBAC_MAINT
        /* Security Officer? */
        i_tid.user = current_uid();
        if (rsbac_get_attr(SW_DAZ,
                           T_USER,
                           i_tid,
                           A_daz_role,
                           &i_attr_val1,
                           TRUE))
          {
            rsbac_printk(KERN_WARNING
                         "debug_proc_write(): rsbac_get_attr() returned error!\n");
            return -EPERM;
          }
        /* if not sec_officer or admin, deny */
        if (i_attr_val1.system_role != SR_security_officer)
          #ifdef CONFIG_RSBAC_SOFTMODE
          if(   !rsbac_softmode
          #ifdef CONFIG_RSBAC_SOFTMODE_IND
             && !rsbac_ind_softmode[SW_DAZ]
          #endif
            )
          #endif
          return -EPERM;
#endif
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_daz_ttl to %u\n",
                   tmp_ttl);
            rsbac_daz_set_ttl(tmp_ttl);
            err = count;
            goto out;
      }
#endif

#if defined(CONFIG_RSBAC_LOG_REMOTE)
/* Set remote address for remote logging */
    /*
     * Usage: echo "debug log_remote_addr a.b.c.d" > /proc/rsbac_info/debug
     *   to set log_remote_addr to given value
     */
    if(!strncmp("log_remote_addr", k_buf + 6, 15)) 
      {
        __u32 tmp_addr;
        char * tmp;

	p += 16;
        if( *p == '\0' )
          goto out;

        tmp=p;
        while(*tmp)
          {
            if(   (*tmp != '.')
               && (   (*tmp < '0')
                   || (*tmp > '9')
                  )
              )
              {
                *tmp = 0;
                break;
              }
            tmp++;
          }
        err = rsbac_net_str_to_inet(p, &tmp_addr);
        if(!err)
          {
#if defined(CONFIG_RSBAC_DEBUG)
            if (rsbac_debug_aef)
              {
                rsbac_printk(KERN_DEBUG "debug_proc_write(): calling ADF for remote_log_addr\n");
              }
#endif
            rsbac_target_id.scd = ST_rsbac_remote_log;
            rsbac_attribute_value.dummy = 0;
            if (!rsbac_adf_request(R_MODIFY_SYSTEM_DATA,
                                   task_pid(current),
                                   T_SCD,
                                   rsbac_target_id,
                                   A_none,
                                   rsbac_attribute_value))
              {
                err = -EPERM;
                goto out;
              }
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_log_remote_addr to %u.%u.%u.%u\n",
                   NIPQUAD(tmp_addr));
            rsbac_log_remote_addr = tmp_addr;
            err = count;
            goto out;
          }
        else
          {
            char * tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

            if(tmp)
              {
                get_error_name(tmp, err);
                rsbac_printk(KERN_INFO
                             "debug_proc_write(): converting remote socket address %s failed with error %s, exiting!\n",
                             p,
                             tmp);
                rsbac_kfree(tmp);
              }
            err = -EINVAL;
            goto out;
          }
      }
/* Set remote port for remote logging */
    /*
     * Usage: echo "debug log_remote_port #n" > /proc/rsbac_info/debug
     *   to set log_remote_port to given value
     */
    if(!strncmp("log_remote_port", k_buf + 6, 15)) 
      {
        __u16 tmp_port;

	p += 16;
        if( *p == '\0' )
          goto out;

        tmp_port = simple_strtoul(p, NULL, 0);
#if defined(CONFIG_RSBAC_DEBUG)
            if (rsbac_debug_aef)
              {
                rsbac_printk(KERN_DEBUG "debug_proc_write(): calling ADF for remote_log_port\n");
              }
#endif
            rsbac_target_id.scd = ST_rsbac_remote_log;
            rsbac_attribute_value.dummy = 0;
            if (!rsbac_adf_request(R_MODIFY_SYSTEM_DATA,
                                   task_pid(current),
                                   T_SCD,
                                   rsbac_target_id,
                                   A_none,
                                   rsbac_attribute_value))
              {
                err = -EPERM;
                goto out;
              }
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_log_remote_port to %u\n",
                   tmp_port);
            rsbac_log_remote_port = htons(tmp_port);
            err = count;
            goto out;
      }
#endif

#ifdef CONFIG_RSBAC_SYSLOG_RATE
/* Set syslog rate limit */
    /*
     * Usage: echo "debug syslog_rate #n" > /proc/rsbac_info/debug
     *   to set rate limit to given value
     */
    if(!strncmp("syslog_rate", k_buf + 6, 11)) 
      {
        u_int tmp_rate;

	p += 12;
        if( *p == '\0' )
          goto out;

        tmp_rate = simple_strtoul(p, NULL, 0);
#if defined(CONFIG_RSBAC_DEBUG)
            if (rsbac_debug_aef)
              {
                rsbac_printk(KERN_DEBUG "debug_proc_write(): calling ADF for syslog_rate\n");
              }
#endif
            rsbac_target_id.scd = ST_rsbac;
            rsbac_attribute_value.dummy = 0;
            if (!rsbac_adf_request(R_MODIFY_SYSTEM_DATA,
                                   task_pid(current),
                                   T_SCD,
                                   rsbac_target_id,
                                   A_none,
                                   rsbac_attribute_value))
              {
                err = -EPERM;
                goto out;
              }
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_syslog_rate to %u\n",
                   tmp_rate);
            rsbac_syslog_rate = tmp_rate;
            err = count;
            goto out;
      }
#endif

#ifdef CONFIG_RSBAC_FD_CACHE
/* Set fd_cache_ttl */
    /*
     * Usage: echo "debug fd_cache_ttl #n" > /proc/rsbac_info/debug
     *   to set ttl to given value
     */
    if(!strncmp("fd_cache_ttl", k_buf + 6, 12)) 
      {
        u_int tmp_ttl;

	p += 13;
        if( *p == '\0' )
          goto out;

        tmp_ttl = simple_strtoul(p, NULL, 0);
#if defined(CONFIG_RSBAC_DEBUG)
            if (rsbac_debug_aef)
              {
                rsbac_printk(KERN_DEBUG "debug_proc_write(): calling ADF for fd_cache_ttl\n");
              }
#endif
            rsbac_target_id.scd = ST_rsbac;
            rsbac_attribute_value.dummy = 0;
            if (!rsbac_adf_request(R_MODIFY_SYSTEM_DATA,
                                   task_pid(current),
                                   T_SCD,
                                   rsbac_target_id,
                                   A_none,
                                   rsbac_attribute_value))
              {
                err = -EPERM;
                goto out;
              }
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_fd_cache_ttl to %u\n",
                   tmp_ttl);
            rsbac_fd_cache_ttl = tmp_ttl;
            err = count;
            goto out;
      }
#endif

#if defined(CONFIG_RSBAC_AUTO_WRITE) && (CONFIG_RSBAC_AUTO_WRITE > 0)
/* Set rsbac_list_check_interval */
    /*
     * Usage: echo "debug list_check_interval #n" > /proc/rsbac_info/debug
     *   to set ttl to given value
     */
    if(!strncmp("list_check_interval", k_buf + 6, 19)) 
      {
        u_int tmp_ttl;

	p += 20;
        if( *p == '\0' )
          goto out;

        tmp_ttl = simple_strtoul(p, NULL, 0);
#if defined(CONFIG_RSBAC_DEBUG)
            if (rsbac_debug_aef)
              {
                rsbac_printk(KERN_DEBUG "debug_proc_write(): calling ADF for list_check_interval\n");
              }
#endif
            rsbac_target_id.scd = ST_rsbac;
            rsbac_attribute_value.dummy = 0;
            if (!rsbac_adf_request(R_MODIFY_SYSTEM_DATA,
                                   task_pid(current),
                                   T_SCD,
                                   rsbac_target_id,
                                   A_none,
                                   rsbac_attribute_value))
              {
                err = -EPERM;
                goto out;
              }
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_list_check_interval to %u\n",
                   tmp_ttl);
            rsbac_list_check_interval = tmp_ttl;
            err = count;
            goto out;
      }
#endif

#ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
/* Boolean switch for disabling logging to syslog */
    /*
     * Usage: echo "debug nosyslog #N" > /proc/rsbac_info/debug
     *   to set rsbac_nosyslog to given value
     */
    if(!strncmp("nosyslog", k_buf + 6, 8)) 
      {
	p += 9;

        if( *p == '\0' )
          goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
#if defined(CONFIG_RSBAC_DEBUG)
            if (rsbac_debug_aef)
              {
                rsbac_printk(KERN_DEBUG "debug_proc_write(): calling ADF for nosyslog\n");
              }
#endif
            rsbac_target_id.dummy = 0;
            rsbac_attribute_value.dummy = 0;
            if (!rsbac_adf_request(R_SWITCH_LOG,
                                   task_pid(current),
                                   T_NONE,
                                   rsbac_target_id,
                                   A_none,
                                   rsbac_attribute_value))
              {
                err = -EPERM;
                goto out;
              }
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_nosyslog to %u\n",
                   debug_level);
            rsbac_nosyslog = debug_level;
            err = count;
            goto out;
          }
        else
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): rejecting invalid nosyslog value (should be 0 or 1)\n");
            err = -EINVAL;
            goto out;
          }
      }
#endif

#ifdef CONFIG_RSBAC_RMSG
/* Set rsbac log messages limit */
    /*
     * Usage: echo "debug rmsg_maxentries #n" > /proc/rsbac_info/debug
     *   to set limit to given value
     */
    if(!strncmp("rmsg_maxentries", k_buf + 6, 15)) 
      {
        u_int tmp_rate;

	p += 16;
        if( *p == '\0' )
          goto out;

        tmp_rate = simple_strtoul(p, NULL, 0);
#if defined(CONFIG_RSBAC_DEBUG)
            if (rsbac_debug_aef)
              {
                rsbac_printk(KERN_DEBUG "debug_proc_write(): calling ADF for rmsg_maxentries\n");
              }
#endif
            rsbac_target_id.scd = ST_rsbac;
            rsbac_attribute_value.dummy = 0;
            if (!rsbac_adf_request(R_MODIFY_SYSTEM_DATA,
                                   task_pid(current),
                                   T_SCD,
                                   rsbac_target_id,
                                   A_none,
                                   rsbac_attribute_value))
              {
                err = -EPERM;
                goto out;
              }
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rmsg_maxentries to %u\n",
                   tmp_rate);
            rsbac_rmsg_maxentries = tmp_rate;
            err = count;
            goto out;
      }
#endif

#ifdef CONFIG_RSBAC_LOG_REMOTE
/* Set rsbac remote log messages limit */
    /*
     * Usage: echo "debug log_remote_maxentries #n" > /proc/rsbac_info/debug
     *   to set limit to given value
     */
    if(!strncmp("log_remote_maxentries", k_buf + 6, 21)) 
      {
        u_int tmp_rate;

	p += 22;
        if( *p == '\0' )
          goto out;

        tmp_rate = simple_strtoul(p, NULL, 0);
#if defined(CONFIG_RSBAC_DEBUG)
            if (rsbac_debug_aef)
              {
                rsbac_printk(KERN_DEBUG "debug_proc_write(): calling ADF for log_remote_maxentries\n");
              }
#endif
            rsbac_target_id.scd = ST_rsbac;
            rsbac_attribute_value.dummy = 0;
            if (!rsbac_adf_request(R_MODIFY_SYSTEM_DATA,
                                   task_pid(current),
                                   T_SCD,
                                   rsbac_target_id,
                                   A_none,
                                   rsbac_attribute_value))
              {
                err = -EPERM;
                goto out;
              }
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting log_remote_maxentries to %u\n",
                   tmp_rate);
            rsbac_log_remote_maxentries = tmp_rate;
            err = count;
            goto out;
      }
#endif

#if defined(CONFIG_RSBAC_RC_LEARN)
/* Boolean switch for RC learning mode */
    /*
     * Usage: echo "debug rc_learn #N" > /proc/rsbac_info/debug
     *   to set rsbac_rc_learn to given value
     */
    if(!strncmp("rc_learn", k_buf + 6, 8)) 
      {
	p += 9;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_target_id.dummy = 0;
            rsbac_attribute_value.rc_learn = debug_level;
            if (!rsbac_adf_request(R_MODIFY_ATTRIBUTE,
                                   task_pid(current),
                                   T_NONE,
                                   rsbac_target_id,
                                   A_rc_learn,
                                   rsbac_attribute_value))
              {
                err = -EPERM;
                goto out;
              }
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_rc_learn to %u\n",
                   debug_level);
            rsbac_rc_learn = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
#endif

#if defined(CONFIG_RSBAC_AUTH_LEARN)
/* Boolean switch for AUTH learning mode */
    /*
     * Usage: echo "debug auth_learn #N" > /proc/rsbac_info/debug
     *   to set rsbac_auth_learn to given value
     */
    if(!strncmp("auth_learn", k_buf + 6, 10)) 
      {
	p += 11;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_target_id.dummy = 0;
            rsbac_attribute_value.auth_learn = debug_level;
            if (!rsbac_adf_request(R_MODIFY_ATTRIBUTE,
                                   task_pid(current),
                                   T_NONE,
                                   rsbac_target_id,
                                   A_auth_learn,
                                   rsbac_attribute_value))
              {
                err = -EPERM;
                goto out;
              }
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_auth_learn to %u\n",
                   debug_level);
            rsbac_auth_learn = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
#endif

#if defined(CONFIG_RSBAC_CAP_LEARN)
/* Boolean switch for CAP learning mode */
    /*
     * Usage: echo "debug cap_learn #N" > /proc/rsbac_info/debug
     *   to set rsbac_cap_learn to given value
     */
    if(!strncmp("cap_learn", k_buf + 6, 9)) 
      {
	p += 10;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_target_id.dummy = 0;
            rsbac_attribute_value.cap_learn = debug_level;
            if (!rsbac_adf_request(R_MODIFY_ATTRIBUTE,
                                   task_pid(current),
                                   T_NONE,
                                   rsbac_target_id,
                                   A_cap_learn,
                                   rsbac_attribute_value))
              {
                err = -EPERM;
                goto out;
              }
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_cap_learn to %u\n",
                   debug_level);
            rsbac_cap_learn = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
#endif

#ifdef CONFIG_RSBAC_CAP_LOG_MISSING
/* Boolean switch for CAP logging of missing caps */
    /*
     * Usage: echo "debug cap_log_missing #N" > /proc/rsbac_info/debug
     *   to set rsbac_cap_log_missing to given value
     */
    if(!strncmp("cap_log_missing", k_buf + 6, 15)) 
      {
	p += 16;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_target_id.scd = ST_rsbac;
            rsbac_attribute_value.dummy = 0;
            if (!rsbac_adf_request(R_MODIFY_SYSTEM_DATA,
                                   task_pid(current),
                                   T_SCD,
                                   rsbac_target_id,
                                   A_none,
                                   rsbac_attribute_value))
              {
                err = -EPERM;
                goto out;
              }
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_cap_log_missing to %u\n",
                   debug_level);
            rsbac_cap_log_missing = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
#endif

#ifdef CONFIG_RSBAC_JAIL_LOG_MISSING
/* Boolean switch for JAIL logging of missing caps */
    /*
     * Usage: echo "debug jail_log_missing #N" > /proc/rsbac_info/debug
     *   to set rsbac_jail_log_missing to given value
     */
    if(!strncmp("jail_log_missing", k_buf + 6, 16)) 
      {
	p += 17;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_target_id.scd = ST_rsbac;
            rsbac_attribute_value.dummy = 0;
            if (!rsbac_adf_request(R_MODIFY_SYSTEM_DATA,
                                   task_pid(current),
                                   T_SCD,
                                   rsbac_target_id,
                                   A_none,
                                   rsbac_attribute_value))
              {
                err = -EPERM;
                goto out;
              }
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_jail_log_missing to %u\n",
                   debug_level);
            rsbac_jail_log_missing = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
#endif


#if defined(CONFIG_RSBAC_ACL_LEARN)
/* Boolean switch for ACL FD learning mode */
    /*
     * Usage: echo "debug acl_learn_fd #N" > /proc/rsbac_info/debug
     *   to set rsbac_acl_learn_fd to given value
     */
    if(!strncmp("acl_learn_fd", k_buf + 6, 12)) 
      {
	p += 13;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            /* use default acls */
            rsbac_target_id.file.device = RSBAC_ZERO_DEV;
            rsbac_target_id.file.inode = 0;
            rsbac_target_id.file.dentry_p = NULL;
            rsbac_attribute_value.acl_learn = debug_level;

            if (!rsbac_adf_request(R_MODIFY_ATTRIBUTE,
                                   task_pid(current),
                                   T_FILE,
                                   rsbac_target_id,
                                   A_acl_learn,
                                   rsbac_attribute_value))
              {
                err = -EPERM;
                goto out;
              }
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_acl_learn_fd to %u\n",
                   debug_level);
            rsbac_acl_learn_fd = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
#endif

#if defined(CONFIG_RSBAC_DEBUG)
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "debug_proc_write(): calling ADF\n");
      }
    rsbac_target_id.scd = ST_rsbac;
    rsbac_attribute_value.dummy = 0;
    if (!rsbac_adf_request(R_MODIFY_SYSTEM_DATA,
                           task_pid(current),
                           T_SCD,
                           rsbac_target_id,
                           A_none,
                           rsbac_attribute_value))
      {
        err = -EPERM;
        goto out;
      }

#if defined(CONFIG_RSBAC_NET)
/* Boolean debug switch for NET data structures */
    /*
     * Usage: echo "debug ds_net #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_ds_net to given value
     */
    if(!strncmp("ds_net", k_buf + 6, 6)) 
      {
	p += 7;

        if( *p == '\0' )
          goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_ds_net to %u\n",
                   debug_level);
            rsbac_debug_ds_net = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
/* Boolean debug switch for NET syscalls / AEF */
    /*
     * Usage: echo "debug aef_net #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_aef_net to given value
     */
    if(!strncmp("aef_net", k_buf + 6, 7)) 
      {
	p += 8;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_aef_net to %u\n",
                   debug_level);
            rsbac_debug_aef_net = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }

/* Boolean debug switch for NET decisions / ADF */
    /*
     * Usage: echo "debug adf_net #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_adf_net to given value
     */
    if(!strncmp("adf_net", k_buf + 6, 7)) 
      {
	p += 8;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_adf_net to %u\n",
                   debug_level);
            rsbac_debug_adf_net = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
#endif

#if defined(CONFIG_RSBAC_MAC)
/* Boolean debug switch for MAC data structures */
    /*
     * Usage: echo "debug ds_mac #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_ds_mac to given value
     */
    if(!strncmp("ds_mac", k_buf + 6, 6)) 
      {
	p += 7;

        if( *p == '\0' )
          goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_ds_mac to %u\n",
                   debug_level);
            rsbac_debug_ds_mac = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
/* Boolean debug switch for MAC syscalls / AEF */
    /*
     * Usage: echo "debug aef_mac #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_aef_mac to given value
     */
    if(!strncmp("aef_mac", k_buf + 6, 7)) 
      {
	p += 8;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_aef_mac to %u\n",
                   debug_level);
            rsbac_debug_aef_mac = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }

/* Boolean debug switch for MAC decisions / ADF */
    /*
     * Usage: echo "debug adf_mac #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_adf_mac to given value
     */
    if(!strncmp("adf_mac", k_buf + 6, 7)) 
      {
	p += 8;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_adf_mac to %u\n",
                   debug_level);
            rsbac_debug_adf_mac = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
#endif

#if defined(CONFIG_RSBAC_PM) || defined(CONFIG_RSBAC_PM_MAINT)
/* Boolean debug switch for PM data structures */
    /*
     * Usage: echo "debug ds_pm #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_ds_pm to given value
     */
    if(!strncmp("ds_pm", k_buf + 6, 5)) 
      {
	p += 6;

        if( *p == '\0' )
          goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_ds_pm to %u\n",
                   debug_level);
            rsbac_debug_ds_pm = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
/* Boolean debug switch for PM syscalls / AEF */
    /*
     * Usage: echo "debug aef_pm #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_aef_pm to given value
     */
    if(!strncmp("aef_pm", k_buf + 6, 6)) 
      {
	p += 7;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_aef_pm to %u\n",
                   debug_level);
            rsbac_debug_aef_pm = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }

/* Boolean debug switch for PM decisions / ADF */
    /*
     * Usage: echo "debug adf_pm #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_adf_pm to given value
     */
    if(!strncmp("adf_pm", k_buf + 6, 6)) 
      {
	p += 7;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_adf_pm to %u\n",
                   debug_level);
            rsbac_debug_adf_pm = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
#endif

#if defined(CONFIG_RSBAC_DAZ)
/* Boolean debug switch for DAZ decisions / ADF */
    /*
     * Usage: echo "debug adf_daz #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_adf_daz to given value
     */
    if(!strncmp("adf_daz", k_buf + 6, 7)) 
      {
	p += 8;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_adf_daz to %u\n",
                   debug_level);
            rsbac_debug_adf_daz = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
#endif

#if defined(CONFIG_RSBAC_RC) || defined(CONFIG_RSBAC_RC_MAINT)
/* Boolean debug switch for RC data structures */
    /*
     * Usage: echo "debug ds_rc #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_ds_rc to given value
     */
    if(!strncmp("ds_rc", k_buf + 6, 5)) 
      {
	p += 6;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_ds_rc to %u\n",
                   debug_level);
            rsbac_debug_ds_rc = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
/* Boolean debug switch for RC syscalls / AEF */
    /*
     * Usage: echo "debug aef_rc #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_aef_rc to given value
     */
    if(!strncmp("aef_rc", k_buf + 6, 6)) 
      {
	p += 7;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_aef_rc to %u\n",
                   debug_level);
            rsbac_debug_aef_rc = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }

/* Boolean debug switch for RC decisions / ADF */
    /*
     * Usage: echo "debug adf_rc #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_adf_rc to given value
     */
    if(!strncmp("adf_rc", k_buf + 6, 6)) 
      {
	p += 7;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_adf_rc to %u\n",
                   debug_level);
            rsbac_debug_adf_rc = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
#endif

#if defined(CONFIG_RSBAC_AUTH)
/* Boolean debug switch for AUTH data structures */
    /*
     * Usage: echo "debug ds_auth #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_ds_auth to given value
     */
    if(!strncmp("ds_auth", k_buf + 6, 7)) 
      {
	p += 8;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_ds_auth to %u\n",
                   debug_level);
            rsbac_debug_ds_auth = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
/* Boolean debug switch for AUTH syscalls / AEF */
    /*
     * Usage: echo "debug aef_auth #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_aef_auth to given value
     */
    if(!strncmp("aef_auth", k_buf + 6, 8)) 
      {
	p += 9;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_aef_auth to %u\n",
                   debug_level);
            rsbac_debug_aef_auth = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }

/* Boolean debug switch for AUTH decisions / ADF */
    /*
     * Usage: echo "debug adf_auth #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_adf_auth to given value
     */
    if(!strncmp("adf_auth", k_buf + 6, 8)) 
      {
	p += 9;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_adf_auth to %u\n",
                   debug_level);
            rsbac_debug_adf_auth = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }

#endif

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
/* Boolean debug switch for REG */
    /*
     * Usage: echo "debug reg #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_reg to given value
     */
    if(!strncmp("reg", k_buf + 6, 3)) 
      {
	p += 3;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_reg to %u\n",
                   debug_level);
            rsbac_debug_reg = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
#endif

#if defined(CONFIG_RSBAC_ACL)
/* Boolean debug switch for ACL data structures */
    /*
     * Usage: echo "debug ds_acl #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_ds_acl to given value
     */
    if(!strncmp("ds_acl", k_buf + 6, 6)) 
      {
	p += 7;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_ds_acl to %u\n",
                   debug_level);
            rsbac_debug_ds_acl = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
/* Boolean debug switch for ACL syscalls / AEF */
    /*
     * Usage: echo "debug aef_acl #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_aef_acl to given value
     */
    if(!strncmp("aef_acl", k_buf + 6, 7)) 
      {
	p += 8;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_aef_acl to %u\n",
                   debug_level);
            rsbac_debug_aef_acl = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }

/* Boolean debug switch for ACL decisions / ADF */
    /*
     * Usage: echo "debug adf_acl #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_adf_acl to given value
     */
    if(!strncmp("adf_acl", k_buf + 6, 7)) 
      {
	p += 8;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_adf_acl to %u\n",
                   debug_level);
            rsbac_debug_adf_acl = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
#endif

#if defined(CONFIG_RSBAC_JAIL)
/* Boolean debug switch for JAIL syscalls / AEF */
    /*
     * Usage: echo "debug aef_jail #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_aef_jail to given value
     */
    if(!strncmp("aef_jail", k_buf + 6, 8)) 
      {
	p += 9;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_aef_jail to %u\n",
                   debug_level);
            rsbac_debug_aef_jail = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }

/* Boolean debug switch for JAIL decisions / ADF */
    /*
     * Usage: echo "debug adf_jail #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_adf_jail to given value
     */
    if(!strncmp("adf_jail", k_buf + 6, 8)) 
      {
	p += 9;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_adf_jail to %u\n",
                   debug_level);
            rsbac_debug_adf_jail = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
#endif

#if defined(CONFIG_RSBAC_PAX)
/* Boolean debug switch for PAX decisions / ADF */
    /*
     * Usage: echo "debug adf_pax #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_adf_pax to given value
     */
    if(!strncmp("adf_pax", k_buf + 6, 7)) 
      {
	p += 8;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_adf_pax to %u\n",
                   debug_level);
            rsbac_debug_adf_pax = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
#endif

#if defined(CONFIG_RSBAC_UM)
/* Boolean debug switch for UM data structures */
    /*
     * Usage: echo "debug ds_um #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_ds_um to given value
     */
    if(!strncmp("ds_um", k_buf + 6, 5)) 
      {
	p += 6;

        if( *p == '\0' )
          goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_ds_um to %u\n",
                   debug_level);
            rsbac_debug_ds_um = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
/* Boolean debug switch for UM syscalls / AEF */
    /*
     * Usage: echo "debug aef_um #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_aef_um to given value
     */
    if(!strncmp("aef_um", k_buf + 6, 6)) 
      {
	p += 7;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_aef_um to %u\n",
                   debug_level);
            rsbac_debug_aef_um = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }

/* Boolean debug switch for UM decisions / ADF */
    /*
     * Usage: echo "debug adf_um #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_adf_um to given value
     */
    if(!strncmp("adf_um", k_buf + 6, 6)) 
      {
	p += 7;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_adf_um to %u\n",
                   debug_level);
            rsbac_debug_adf_um = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
#endif

    /*
     * Usage: echo "debug ds #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_ds to given value
     */
    if(!strncmp("ds", k_buf + 6, 2)) 
      {
	p += 3;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_ds to %u\n",
                   debug_level);
            rsbac_debug_ds = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }

    /*
     * Usage: echo "debug write #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_write to given value
     */
    if(!strncmp("write", k_buf + 6, 5)) 
      {
	p += 6;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_write to %u\n",
                   debug_level);
            rsbac_debug_write = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }

    /*
     * Usage: echo "debug stack #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_stack to given value
     */
    if(!strncmp("stack", k_buf + 6, 5)) 
      {
	p += 6;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_stack to %u\n",
                   debug_level);
            rsbac_debug_stack = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }

    /*
     * Usage: echo "debug lists #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_lists to given value
     */
    if(!strncmp("lists", k_buf + 6, 5)) 
      {
	p += 6;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_lists to %u\n",
                   debug_level);
            rsbac_debug_lists = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }

    /* Boolean debug switch for AEF */
    /*
     * Usage: echo "debug aef #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_aef to given value
     */
    if(!strncmp("aef", k_buf + 6, 3)) 
      {
	p += 4;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_aef to %u\n",
                   debug_level);
            rsbac_debug_aef = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }

/* Boolean debug switch for NO_WRITE */
    /*
     * Usage: echo "debug no_write #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_no_write to given value
     */
    if(!strncmp("no_write", k_buf + 6, 8)) 
      {
	p += 9;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_no_write to %u\n",
                   debug_level);
            rsbac_debug_no_write = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }

#if defined(CONFIG_RSBAC_AUTO_WRITE) && (CONFIG_RSBAC_AUTO_WRITE > 0)
    /*
     * Usage: echo "debug auto #N" > /proc/rsbac_info/debug
     *   to set rsbac_debug_auto to given value
     */
    if(!strncmp("auto", k_buf + 6, 4)) 
      {
	p += 5;

        if( *p == '\0' )
            goto out;

        debug_level = simple_strtoul(p, NULL, 0);
        /* only accept 0 or 1 */
        if(!debug_level || (debug_level == 1))
          {
            rsbac_printk(KERN_INFO
                   "debug_proc_write(): setting rsbac_debug_auto to %u\n",
                   debug_level);
            rsbac_debug_auto = debug_level;
            err = count;
            goto out;
          }
        else
          {
            goto out_inv;
          }
      }
#endif /* CONFIG_RSBAC_AUTO_WRITE > 0 */
#endif /* DEBUG */

out:
  free_page((ulong) k_buf);
  return(err);

out_inv:
    rsbac_printk(KERN_INFO
                 "debug_proc_write(): rejecting invalid debug level (should be 0 or 1)\n");
    err = -EINVAL;
    goto out;
  }

static int debug_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, debug_proc_show, NULL);
}

static const struct file_operations debug_proc_fops = {
       .owner          = THIS_MODULE,
       .open           = debug_proc_open,
       .read           = seq_read,
       .write          = debug_proc_write,
       .llseek         = seq_lseek,
       .release        = single_release,
};

static struct proc_dir_entry *debug;
#endif /* defined(CONFIG_RSBAC_PROC) */

#if defined(CONFIG_RSBAC_LOG_REMOTE)

#ifndef CONFIG_RSBAC_LOG_REMOTE_SYNC
/* rsbac kernel timer for auto-write */
static void wakeup_rsbaclogd(u_long dummy)
  {
    wake_up(&rsbaclogd_wait);
  }
#endif

/* rsbac kernel daemon for remote logging */
static int rsbaclogd(void * dummy)
  {
    struct task_struct *tsk = current;
    int err;
    int sock_fd;
    struct rsbac_log_list_item_t * log_item;
    struct sockaddr_in addr;
    char * tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
    mm_segment_t oldfs;

    rsbac_printk(KERN_INFO "rsbaclogd(): Initializing.\n");

#ifdef CONFIG_RSBAC_DEBUG
    rsbac_printk(KERN_DEBUG "rsbaclogd(): Setting auto timer.\n");
#endif
#ifndef CONFIG_RSBAC_LOG_REMOTE_SYNC
    init_timer(&rsbac_log_remote_timer);
    rsbac_log_remote_timer.function = wakeup_rsbaclogd;
    rsbac_log_remote_timer.data = 0;
    rsbac_log_remote_timer.expires = jiffies + rsbac_log_remote_interval;
    add_timer(&rsbac_log_remote_timer);
#endif
    interruptible_sleep_on(&rsbaclogd_wait);

    /* create a socket */
#ifndef CONFIG_RSBAC_LOG_REMOTE_TCP
    sock_fd = sys_socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sock_fd < 0)
      {
        rsbac_printk(KERN_WARNING
               "rsbaclogd(): creating local log socket failed with error %s, exiting!\n",
               get_error_name(tmp, sock_fd));
        rsbaclogd_pid = 0;
        return -RSBAC_EWRITEFAILED;
      }
    /* bind local address */
    addr.sin_family = PF_INET;
    addr.sin_port = htons(CONFIG_RSBAC_LOG_LOCAL_PORT);
    err = rsbac_net_str_to_inet(CONFIG_RSBAC_LOG_LOCAL_ADDR,
                                &addr.sin_addr.s_addr);
    if(err < 0)
      {
        rsbac_printk(KERN_WARNING
               "rsbaclogd(): converting local socket address %s failed with error %s, exiting!\n",
               CONFIG_RSBAC_LOG_LOCAL_ADDR,
               get_error_name(tmp, err));
        sys_close(sock_fd);
        rsbaclogd_pid = 0;
        return -RSBAC_EINVALIDVALUE;
      }
    /* change data segment - sys_bind reads address from user space */
    oldfs = get_fs();
    set_fs(KERNEL_DS);
    err = sys_bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr));
    set_fs(oldfs);
    if(err < 0)
      {
        rsbac_printk(KERN_WARNING
               "rsbaclogd(): binding local socket address %u.%u.%u.%u:%u failed with error %s, exiting!\n",
               NIPQUAD(addr.sin_addr.s_addr),
               CONFIG_RSBAC_LOG_LOCAL_PORT,
               get_error_name(tmp, err));
        sys_close(sock_fd);
        rsbaclogd_pid = 0;
        return -RSBAC_EWRITEFAILED;
      }
#endif /* ifndef CONFIG_RSBAC_LOG_REMOTE_TCP */
#ifdef CONFIG_RSBAC_DEBUG
    if(rsbac_debug_stack)
      {
        unsigned long * n = (unsigned long *) (current+1);

        while (!*n)
          n++;
	rsbac_printk(KERN_DEBUG "rsbaclogd: free stack: %lu\n",
	       (unsigned long) n - (unsigned long)(current+1));
      }
#endif
    for(;;)
      {
        /* wait */
#ifndef CONFIG_RSBAC_LOG_REMOTE_SYNC
        /* set new timer (only, if not woken up by rsbac_printk()) */
        mod_timer(&rsbac_log_remote_timer, jiffies + rsbac_log_remote_interval);
#endif
        interruptible_sleep_on(&rsbaclogd_wait);
#ifdef CONFIG_PM
	if (try_to_freeze())
	    continue;
	/* sleep */
#endif

	/* Unblock all signals. */
	flush_signals(tsk);
	spin_lock_irq(&tsk->sighand->siglock);
	flush_signal_handlers(tsk, 1);
	sigemptyset(&tsk->blocked);
	recalc_sigpending();
	spin_unlock_irq(&tsk->sighand->siglock);

        /* Do nothing without remote address */
        if(!rsbac_log_remote_addr || !rsbac_log_remote_port || !remote_log_list_head.head)
          continue;


#ifdef CONFIG_RSBAC_LOG_REMOTE_TCP
        sock_fd = sys_socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(sock_fd < 0)
          {
            rsbac_printk(KERN_WARNING
                   "rsbaclogd(): creating local log socket failed with error %s, exiting!\n",
                   get_error_name(tmp, sock_fd));
            continue;
          }
        /* bind local address */
        addr.sin_family = PF_INET;
        addr.sin_port = htons(CONFIG_RSBAC_LOG_LOCAL_PORT);
        err = rsbac_net_str_to_inet(CONFIG_RSBAC_LOG_LOCAL_ADDR,
                                    &addr.sin_addr.s_addr);
        if(err < 0)
          {
            rsbac_printk(KERN_WARNING
                   "rsbaclogd(): converting local socket address %s failed with error %s, exiting!\n",
                   CONFIG_RSBAC_LOG_LOCAL_ADDR,
                   get_error_name(tmp, err));
            sys_close(sock_fd);
            continue;
          }
        /* change data segment - sys_bind reads address from user space */
        oldfs = get_fs();
        set_fs(KERNEL_DS);
        err = sys_bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr));
        set_fs(oldfs);
        if(err < 0)
          {
            rsbac_printk(KERN_WARNING
                   "rsbaclogd(): binding local socket address %u.%u.%u.%u:%u failed with error %s, exiting!\n",
                   NIPQUAD(addr.sin_addr.s_addr),
                   CONFIG_RSBAC_LOG_LOCAL_PORT,
                   get_error_name(tmp, err));
            sys_close(sock_fd);
            continue;
          }
        /* Target address might have changed */
        addr.sin_family = PF_INET;
        addr.sin_port = rsbac_log_remote_port;
        addr.sin_addr.s_addr = rsbac_log_remote_addr;
        /* connect to remote socket */
        oldfs = get_fs();
        set_fs(KERNEL_DS);
        err = sys_connect(sock_fd,
                         (struct sockaddr *)&addr,
                         sizeof(addr));
        set_fs(oldfs);
        if(err < 0)
          {
            printk(KERN_WARNING
                   "rsbaclogd(): connecting to remote TCP address %u.%u.%u.%u:%u failed with error %s, exiting!\n",
                   NIPQUAD(addr.sin_addr.s_addr),
                   ntohs(addr.sin_port),
                   get_error_name(tmp, err));
            sys_close(sock_fd);
            continue;
          }
#else
        /* Target address might have changed */
        addr.sin_family = PF_INET;
        addr.sin_port = rsbac_log_remote_port;
        addr.sin_addr.s_addr = rsbac_log_remote_addr;
#endif
	while(remote_log_list_head.head)
	  {
            spin_lock(&rsbac_log_remote_lock);
	    log_item = remote_log_list_head.head;
	    remote_log_list_head.head = log_item->next;
	    if(!remote_log_list_head.head)
		remote_log_list_head.tail = NULL;
	    remote_log_list_head.count--;
            spin_unlock(&rsbac_log_remote_lock);

#ifdef CONFIG_RSBAC_LOG_REMOTE_TCP
            oldfs = get_fs();
            set_fs(KERNEL_DS);
            err = sys_send(sock_fd,
                           log_item->buffer,
                           log_item->size,
                           0);
            set_fs(oldfs);
#else
            /* change data segment - sys_sendto reads data and address from user space */
            oldfs = get_fs();
            set_fs(KERNEL_DS);
            err = sys_sendto(sock_fd,
                             log_item->buffer,
                             log_item->size,
                             MSG_DONTWAIT,
                             (struct sockaddr *)&addr,
                             sizeof(addr));
            set_fs(oldfs);
#endif
            if(   (err < log_item->size)
//               && (err != -EPERM)
              )
              {
                if((err < 0) && (err != -EAGAIN))
                  printk(KERN_WARNING
                       "rsbaclogd(): sending to remote socket address %u.%u.%u.%u:%u failed with error %i!\n",
                       NIPQUAD(addr.sin_addr.s_addr),
                       ntohs(addr.sin_port),
                       err);
		/* Restore log item to beginning of the list */
                spin_lock(&rsbac_log_remote_lock);
		log_item->next = remote_log_list_head.head;
	        remote_log_list_head.head = log_item;
	        if(!remote_log_list_head.tail)
		  remote_log_list_head.tail = log_item;
		remote_log_list_head.count++;
                spin_unlock(&rsbac_log_remote_lock);
                break;
              }
	    else {
		kfree(log_item);
	    }
          }
#ifdef CONFIG_RSBAC_LOG_REMOTE_TCP
        sys_close(sock_fd);
#endif
      }
    return 0;
  }
#endif

static int ll_conv(
	void * old_desc,
	void * old_data,
	void * new_desc,
	void * new_data)
  {
    rsbac_log_entry_t     * new_aci = new_data;
    rsbac_old_log_entry_t * old_aci = old_data;
    int i;

    memcpy(new_desc, old_desc, sizeof(rsbac_adf_request_int_t));
    for(i=0; i < T_NONE - 1; i++)
      (*new_aci)[i] = (*old_aci)[i];
    (*new_aci)[T_NONE - 1] = LL_denied;
    (*new_aci)[T_NONE] = (*old_aci)[T_NONE - 1];
    return 0;
  }

static int ll_old_conv(
	void * old_desc,
	void * old_data,
	void * new_desc,
	void * new_data)
  {
    rsbac_log_entry_t     * new_aci = new_data;
    rsbac_old_log_entry_t * old_aci = old_data;
    int i;

    memcpy(new_desc, old_desc, sizeof(rsbac_adf_request_int_t));
    for(i=0; i < T_NONE - 2; i++)
      (*new_aci)[i] = (*old_aci)[i];
    (*new_aci)[T_NONE - 1] = LL_denied;
    (*new_aci)[T_NONE - 2] = LL_denied;
    (*new_aci)[T_NONE] = (*old_aci)[T_NONE - 1];
    return 0;
  }

rsbac_list_conv_function_t * ll_get_conv(rsbac_version_t old_version)
  {
    switch(old_version)
      {
        case RSBAC_LOG_LEVEL_OLD_VERSION:
          return ll_conv;
        case RSBAC_LOG_LEVEL_OLD_OLD_VERSION:
          return ll_old_conv;
        default:
          return NULL;
      }
  }


/********************************/
/*             Init             */
/********************************/

#ifdef CONFIG_RSBAC_INIT_DELAY
inline void rsbac_init_debug(void)
#else
inline void __init rsbac_init_debug(void)
#endif
  {
    int i;
#if defined(CONFIG_RSBAC_LOG_REMOTE)
    struct task_struct * rsbaclogd_thread;
#endif

    if (!debug_initialized)
      {
        struct rsbac_list_info_t * info_p;
        int tmperr;
        rsbac_enum_t * def_data_p;

        rsbac_printk(KERN_INFO "rsbac_init_debug(): Initializing\n");
        info_p = rsbac_kmalloc(sizeof(*info_p));
        if(!info_p)
          {
            memset(rsbac_log_levels, LL_denied, sizeof(rsbac_log_levels));
            return;
          }
        def_data_p = rsbac_kmalloc(sizeof(rsbac_log_entry_t));
        if(!def_data_p)
          {
            memset(rsbac_log_levels, LL_denied, sizeof(rsbac_log_levels));
            rsbac_kfree(info_p);
            return;
          }
        /* register log_levels list */
        for(i=0; i<=T_NONE; i++)
          def_data_p[i] = LL_denied;
        info_p->version = RSBAC_LOG_LEVEL_VERSION;
        info_p->key = RSBAC_LOG_LEVEL_KEY;
        info_p->desc_size = sizeof(rsbac_adf_request_int_t);
        info_p->data_size = sizeof(rsbac_log_entry_t);
        info_p->max_age = 0;
        tmperr = rsbac_list_register(RSBAC_LIST_VERSION,
                                     &log_levels_handle,
                                     info_p,
                                     RSBAC_LIST_PERSIST | RSBAC_LIST_DEF_DATA,
                                     NULL,
                                     ll_get_conv,
                                     def_data_p,
                                     RSBAC_LOG_LEVEL_LIST_NAME,
                                     RSBAC_AUTO_DEV);
        rsbac_kfree(info_p);
        rsbac_kfree(def_data_p);
        if(tmperr)
          {
            char * tmp;

            tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
            if(tmp)
              {
                rsbac_printk(KERN_WARNING
                       "rsbac_init_debug(): registering log levels list ll failed with error %s!\n",
                       get_error_name(tmp, tmperr));
                rsbac_kfree(tmp);
              }
            memset(rsbac_log_levels, LL_denied, sizeof(rsbac_log_levels));
          }
        else
          {
            rsbac_adf_request_int_t req;

            for(req = 0; req < R_NONE; req++)
              rsbac_list_get_data(log_levels_handle, &req, rsbac_log_levels[req]);
          }

        #if defined(CONFIG_RSBAC_PROC)
	log_levels = proc_create("log_levels", S_IFREG | S_IRUGO | S_IWUGO, proc_rsbac_root_p, &log_levels_proc_fops);

	debug = proc_create("debug", S_IFREG | S_IRUGO | S_IWUGO, proc_rsbac_root_p, &debug_proc_fops);

        #if defined(CONFIG_RSBAC_RMSG)
	rmsg = proc_create("rmsg", S_IFREG | S_IRUGO, proc_rsbac_root_p, &rmsg_proc_fops);
        #endif
        #endif

        #if defined(CONFIG_RSBAC_LOG_REMOTE)
        /* Start rsbac logging thread for auto write */
        if(!rsbac_log_remote_port)
          rsbac_log_remote_port = htons(CONFIG_RSBAC_LOG_REMOTE_PORT);
        tmperr = rsbac_net_str_to_inet(rsbac_log_remote_addr_string,
                                    &rsbac_log_remote_addr);
        if(tmperr < 0)
          {
            char * tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

            if(tmp)
              {
                get_error_name(tmp, tmperr);
                rsbac_printk(KERN_WARNING
                             "rsbac_init_debug(): converting remote socket address %s failed with error %s, exiting!\n",
                             rsbac_log_remote_addr_string,
                             tmp);
                rsbac_log_remote_addr = 0;
                rsbac_kfree(tmp);
              }
          }
	rsbaclogd_thread = kthread_create(rsbaclogd, NULL, "rsbaclogd");
	wake_up_process(rsbaclogd_thread);
        rsbac_printk(KERN_INFO "rsbac_init_debug(): Started rsbaclogd thread with pid %u\n",
               rsbaclogd_pid);
        #endif

        #ifdef CONFIG_RSBAC_SYSLOG_RATE
        init_timer(&rsbac_syslog_rate_timer);
        rsbac_syslog_rate_timer.function = syslog_rate_reset;
        rsbac_syslog_rate_timer.data = 0;
        rsbac_syslog_rate_timer.expires = jiffies + HZ;
        add_timer(&rsbac_syslog_rate_timer);
        #endif

        debug_initialized = TRUE;
      }

    #ifdef CONFIG_RSBAC_SOFTMODE
    if(rsbac_softmode)
      rsbac_printk(KERN_DEBUG "rsbac_softmode is set\n");
    if(rsbac_softmode_prohibit)
      rsbac_printk(KERN_DEBUG "rsbac_softmode_prohibit is set\n");
    #endif
    #ifdef CONFIG_RSBAC_FREEZE
    if(rsbac_freeze)
      rsbac_printk(KERN_DEBUG "rsbac_freeze is set\n");
    #endif
    if(rsbac_list_recover)
      rsbac_printk(KERN_DEBUG "rsbac_list_recover is set\n");
    #if defined(CONFIG_RSBAC_UM_EXCL)
    if(rsbac_um_no_excl)
      rsbac_printk(KERN_DEBUG "rsbac_um_no_excl is set\n");
    #endif
    #if defined(CONFIG_RSBAC_DAZ_CACHE)
    rsbac_printk(KERN_DEBUG "rsbac_daz_ttl is %u\n",
                 rsbac_daz_get_ttl());
    #endif
    #if defined(CONFIG_RSBAC_RC_LEARN)
    if(rsbac_rc_learn)
      rsbac_printk(KERN_DEBUG "rsbac_rc_learn is set\n");
    #endif
    #if defined(CONFIG_RSBAC_AUTH_LEARN)
    if(rsbac_auth_learn)
      rsbac_printk(KERN_DEBUG "rsbac_auth_learn is set\n");
    #endif
    #if defined(CONFIG_RSBAC_CAP_LEARN)
    if(rsbac_cap_learn)
      rsbac_printk(KERN_DEBUG "rsbac_cap_learn is set\n");
    #endif
    #if defined(CONFIG_RSBAC_ACL_LEARN)
    if(rsbac_acl_learn_fd)
      rsbac_printk(KERN_DEBUG "rsbac_acl_learn_fd is set\n");
    #endif
    #ifdef CONFIG_RSBAC_CAP_PROC_HIDE
    if(rsbac_cap_process_hiding)
      rsbac_printk(KERN_DEBUG "rsbac_cap_process_hiding is set\n");
    #endif
    #ifdef CONFIG_RSBAC_CAP_LOG_MISSING
    if(rsbac_cap_log_missing)
      rsbac_printk(KERN_DEBUG "rsbac_cap_log_missing is set\n");
    #endif
    #ifdef CONFIG_RSBAC_JAIL_LOG_MISSING
    if(rsbac_jail_log_missing)
      rsbac_printk(KERN_DEBUG "rsbac_jail_log_missing is set\n");
    #endif
    #ifdef CONFIG_RSBAC_ALLOW_DAC_DISABLE_FULL
    if(rsbac_dac_disable)
      rsbac_printk(KERN_DEBUG "rsbac_dac_disable is set\n");
    #endif
    #ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
    if(rsbac_nosyslog)
      rsbac_printk(KERN_DEBUG "rsbac_nosyslog is set\n");
    #endif
    #ifdef CONFIG_RSBAC_SYSLOG_RATE
    if(rsbac_syslog_rate != CONFIG_RSBAC_SYSLOG_RATE_DEF)
      rsbac_printk(KERN_DEBUG "rsbac_syslog_rate is %u\n",
                   rsbac_syslog_rate);
    #endif
#ifdef CONFIG_RSBAC_FD_CACHE
    if(rsbac_fd_cache_disable) {
      rsbac_printk(KERN_DEBUG "rsbac_fd_cache_disable is %u\n",
                   rsbac_fd_cache_disable);
    } else {
      if(rsbac_fd_cache_ttl != CONFIG_RSBAC_FD_CACHE_TTL)
        rsbac_printk(KERN_DEBUG "rsbac_fd_cache_ttl is %u\n",
                     rsbac_fd_cache_ttl);
    }
#endif
#if defined(CONFIG_RSBAC_AUTO_WRITE) && (CONFIG_RSBAC_AUTO_WRITE > 0)
    if(rsbac_list_check_interval != CONFIG_RSBAC_LIST_CHECK_INTERVAL)
      rsbac_printk(KERN_DEBUG "rsbac_list_check_interval is %u\n",
                   rsbac_list_check_interval);
#endif
    #ifdef CONFIG_RSBAC_INIT_DELAY
    if(rsbac_no_delay_init)
      rsbac_printk(KERN_DEBUG "rsbac_no_delay_init is set\n");
    if(rsbac_delayed_root_str[0])
      rsbac_printk(KERN_DEBUG "rsbac_delayed_root is %s\n",
             rsbac_delayed_root_str);
    #endif
    if(rsbac_no_defaults)
      rsbac_printk(KERN_DEBUG "rsbac_no_defaults is set\n");

#if defined(CONFIG_RSBAC_DEBUG)
    if(rsbac_debug_ds)
      rsbac_printk(KERN_DEBUG "rsbac_debug_ds is set\n");
    if(rsbac_debug_write)
      rsbac_printk(KERN_DEBUG "rsbac_debug_write is set\n");
    if(rsbac_debug_no_write)
      rsbac_printk(KERN_DEBUG "rsbac_debug_no_write is set\n");
    if(rsbac_debug_stack)
      rsbac_printk(KERN_DEBUG "rsbac_debug_stack is set\n");
    if(rsbac_debug_lists)
      rsbac_printk(KERN_DEBUG "rsbac_debug_lists is set\n");
    if(rsbac_debug_aef)
      rsbac_printk(KERN_DEBUG "rsbac_debug_aef is set\n");
    if(rsbac_debug_adf_default != 1)
      rsbac_printk(KERN_DEBUG "rsbac_debug_adf_default is set to %i\n",
             rsbac_debug_adf_default);

    #if defined(CONFIG_RSBAC_REG)
    if(rsbac_debug_reg)
      rsbac_printk(KERN_DEBUG "rsbac_debug_reg is set\n");
    #endif

    #if defined(CONFIG_RSBAC_NET)
    if(rsbac_debug_ds_net)
      rsbac_printk(KERN_DEBUG "rsbac_debug_ds_net is set\n");
    if(rsbac_debug_aef_net)
      rsbac_printk(KERN_DEBUG "rsbac_debug_aef_net is set\n");
    if(rsbac_debug_adf_net)
      rsbac_printk(KERN_DEBUG "rsbac_debug_adf_net is set\n");
    #endif

    #if defined(CONFIG_RSBAC_MAC)
    if(rsbac_debug_ds_mac)
      rsbac_printk(KERN_DEBUG "rsbac_debug_ds_mac is set\n");
    if(rsbac_debug_aef_mac)
      rsbac_printk(KERN_DEBUG "rsbac_debug_aef_mac is set\n");
    if(rsbac_debug_adf_mac)
      rsbac_printk(KERN_DEBUG "rsbac_debug_adf_mac is set\n");
    #endif

    #if defined(CONFIG_RSBAC_PM)
    if(rsbac_debug_ds_pm)
      rsbac_printk(KERN_DEBUG "rsbac_debug_ds_pm is set\n");
    if(rsbac_debug_aef_pm)
      rsbac_printk(KERN_DEBUG "rsbac_debug_aef_pm is set\n");
    if(rsbac_debug_adf_pm)
      rsbac_printk(KERN_DEBUG "rsbac_debug_adf_pm is set\n");
    #endif

    #if defined(CONFIG_RSBAC_DAZ)
    if(rsbac_debug_adf_daz)
      rsbac_printk(KERN_DEBUG "rsbac_debug_adf_daz is set\n");
    #endif

    #if defined(CONFIG_RSBAC_RC)
    if(rsbac_debug_ds_rc)
      rsbac_printk(KERN_DEBUG "rsbac_debug_ds_rc is set\n");
    if(rsbac_debug_aef_rc)
      rsbac_printk(KERN_DEBUG "rsbac_debug_aef_rc is set\n");
    if(rsbac_debug_adf_rc)
      rsbac_printk(KERN_DEBUG "rsbac_debug_adf_rc is set\n");
    #endif

    #if defined(CONFIG_RSBAC_AUTH)
    if(rsbac_debug_ds_auth)
      rsbac_printk(KERN_DEBUG "rsbac_debug_ds_auth is set\n");
    if(rsbac_debug_aef_auth)
      rsbac_printk(KERN_DEBUG "rsbac_debug_aef_auth is set\n");
    if(rsbac_debug_adf_auth)
      rsbac_printk(KERN_DEBUG "rsbac_debug_adf_auth is set\n");
    #endif

    #if defined(CONFIG_RSBAC_ACL)
    if(rsbac_debug_ds_acl)
      rsbac_printk(KERN_DEBUG "rsbac_debug_ds_acl is set\n");
    if(rsbac_debug_aef_acl)
      rsbac_printk(KERN_DEBUG "rsbac_debug_aef_acl is set\n");
    if(rsbac_debug_adf_acl)
      rsbac_printk(KERN_DEBUG "rsbac_debug_adf_acl is set\n");
    #endif

    #if defined(CONFIG_RSBAC_JAIL)
    if(rsbac_debug_aef_jail)
      rsbac_printk(KERN_DEBUG "rsbac_debug_aef_jail is set\n");
    if(rsbac_debug_adf_jail)
      rsbac_printk(KERN_DEBUG "rsbac_debug_adf_jail is set\n");
    #endif

    #if defined(CONFIG_RSBAC_PAX)
    if(rsbac_debug_adf_pax)
      rsbac_printk(KERN_DEBUG "rsbac_debug_adf_pax is set\n");
    #endif

    #if defined(CONFIG_RSBAC_UM)
    if(rsbac_debug_ds_um)
      rsbac_printk(KERN_DEBUG "rsbac_debug_ds_um is set\n");
    if(rsbac_debug_aef_um)
      rsbac_printk(KERN_DEBUG "rsbac_debug_aef_um is set\n");
    if(rsbac_debug_adf_um)
      rsbac_printk(KERN_DEBUG "rsbac_debug_adf_um is set\n");
    #endif

    #if defined(CONFIG_RSBAC_AUTO_WRITE) && (CONFIG_RSBAC_AUTO_WRITE > 0)
    if(rsbac_debug_auto)
      rsbac_printk(KERN_DEBUG "rsbac_debug_auto is set\n");
    #endif
#endif /* DEBUG */

  }

