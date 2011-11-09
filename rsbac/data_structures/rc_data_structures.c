/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of RC data structures              */
/* Author and (C) 1999-2011: Amon Ott <ao@rsbac.org> */
/*                                                   */
/* Last modified: 12/Jul/2011                        */
/*************************************************** */

#include <linux/string.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <asm/uaccess.h>
#include <rsbac/aci_data_structures.h>
#include <rsbac/rc_types.h>
#include <rsbac/rc_data_structures.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/fs.h>
#include <rsbac/adf.h>
#include <rsbac/acl.h>
#include <rsbac/getname.h>
#include <rsbac/rc_getname.h>
#include <rsbac/proc_fs.h>
#include <rsbac/rkmem.h>
#include <rsbac/request_groups.h>
#include <linux/seq_file.h>
#include <linux/module.h>

/************************************************************************** */
/*                          Global Variables                                */
/************************************************************************** */

/* The following global variables are needed for access to RC data.         */

static rsbac_list_handle_t role_handle = NULL;
static rsbac_list_handle_t role_rc_handle = NULL;
static rsbac_list_handle_t role_adr_handle = NULL;
static rsbac_list_handle_t role_asr_handle = NULL;
static rsbac_list_handle_t role_dfdc_handle = NULL;
static rsbac_list_handle_t role_tcfd_handle = NULL;
static rsbac_list_handle_t role_tcdv_handle = NULL;
static rsbac_list_handle_t role_tcus_handle = NULL;
static rsbac_list_handle_t role_tcpr_handle = NULL;
static rsbac_list_handle_t role_tcip_handle = NULL;
static rsbac_list_handle_t role_tcsc_handle = NULL;
static rsbac_list_handle_t role_tcgr_handle = NULL;
static rsbac_list_handle_t role_tcnd_handle = NULL;
static rsbac_list_handle_t role_tcnt_handle = NULL;
static rsbac_list_handle_t role_tcno_handle = NULL;

static rsbac_list_handle_t type_fd_handle = NULL;
static rsbac_list_handle_t type_dev_handle = NULL;
static rsbac_list_handle_t type_ipc_handle = NULL;
static rsbac_list_handle_t type_user_handle = NULL;
static rsbac_list_handle_t type_process_handle = NULL;
static rsbac_list_handle_t type_group_handle = NULL;
static rsbac_list_handle_t type_netdev_handle = NULL;
static rsbac_list_handle_t type_nettemp_handle = NULL;
static rsbac_list_handle_t type_netobj_handle = NULL;

/**************************************************/
/*       Declarations of external functions       */
/**************************************************/

/**************************************************/
/*       Declarations of internal functions       */
/**************************************************/

/* As some function use later defined functions, we declare those here.   */

/************************************************* */
/*               Internal Help functions           */
/************************************************* */

/* nr_hashes is always 2^n, no matter what the macros say */
static u_int nr_role_hashes = RSBAC_RC_NR_ROLE_LISTS;
static u_int role_hash(void * desc, __u32 nr_hashes)
{
	return (*((rsbac_rc_role_id_t *) desc) & (nr_hashes - 1));
}

static u_int nr_type_hashes = RSBAC_RC_NR_TYPE_LISTS;
static u_int type_hash(void * desc, __u32 nr_hashes)
{
	return (*((rsbac_rc_type_id_t *) desc) & (nr_hashes - 1));
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static int role_conv(
#else
static int __init role_conv(
#endif
				   void *old_desc,
				   void *old_data,
				   void *new_desc, void *new_data)
{
	struct rsbac_rc_role_entry_t *new = new_data;
	struct rsbac_rc_old_role_entry_t *old = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_rc_role_id_t));
	new->admin_type = old->admin_type;
	memcpy(new->name, old->name, RSBAC_RC_NAME_LEN);
	new->def_fd_create_type = old->def_fd_create_type;
	new->def_user_create_type = old->def_user_create_type;
	new->def_process_create_type = old->def_process_create_type;
	new->def_process_chown_type = old->def_process_chown_type;
	new->def_process_execute_type = old->def_process_execute_type;
	new->def_ipc_create_type = old->def_ipc_create_type;
	new->def_group_create_type = RSBAC_RC_GENERAL_TYPE;
	new->def_unixsock_create_type = RC_type_use_fd;
	new->boot_role = old->boot_role;
	new->req_reauth = old->req_reauth;
	return 0;
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static int old_role_conv(
#else
static int __init old_role_conv(
#endif
				   void *old_desc,
				   void *old_data,
				   void *new_desc, void *new_data)
{
	struct rsbac_rc_role_entry_t *new = new_data;
	struct rsbac_rc_old_role_entry_t *old = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_rc_role_id_t));
	new->admin_type = old->admin_type;
	memcpy(new->name, old->name, RSBAC_RC_NAME_LEN);
	new->def_fd_create_type = old->def_fd_create_type;
	new->def_user_create_type = old->def_user_create_type;
	new->def_process_create_type = old->def_process_create_type;
	new->def_process_chown_type = old->def_process_chown_type;
	new->def_process_execute_type = old->def_process_execute_type;
	new->def_ipc_create_type = old->def_ipc_create_type;
	new->def_group_create_type = RSBAC_RC_GENERAL_TYPE;
	new->def_unixsock_create_type = RC_type_use_fd;
	new->boot_role = old->boot_role;
	new->req_reauth = FALSE;
	return 0;
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static int old_old_role_conv(
#else
static int __init old_old_role_conv(
#endif
				       void *old_desc,
				       void *old_data,
				       void *new_desc, void *new_data)
{
	struct rsbac_rc_role_entry_t *new = new_data;
	struct rsbac_rc_old_role_entry_t *old = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_rc_role_id_t));
	new->admin_type = old->admin_type;
	memcpy(new->name, old->name, RSBAC_RC_NAME_LEN);
	new->def_fd_create_type = old->def_fd_create_type;
	new->def_user_create_type = old->def_user_create_type;
	new->def_process_create_type = old->def_process_create_type;
	new->def_process_chown_type = old->def_process_chown_type;
	new->def_process_execute_type = old->def_process_execute_type;
	new->def_ipc_create_type = old->def_ipc_create_type;
	new->def_group_create_type = RSBAC_RC_GENERAL_TYPE;
	new->def_unixsock_create_type = RC_type_use_fd;
	new->boot_role = old->boot_role;
	new->req_reauth = FALSE;
	return 0;
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static int old_old_old_role_conv(
#else
static int __init old_old_old_role_conv(
#endif
					   void *old_desc,
					   void *old_data,
					   void *new_desc, void *new_data)
{
	struct rsbac_rc_role_entry_t *new = new_data;
	struct rsbac_rc_old_role_entry_t *old = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_rc_role_id_t));
	new->admin_type = old->admin_type;
	memcpy(new->name, old->name, RSBAC_RC_NAME_LEN);
	new->def_fd_create_type = old->def_fd_create_type;
	new->def_user_create_type = RSBAC_RC_GENERAL_TYPE;
	new->def_process_create_type = old->def_process_create_type;
	new->def_process_chown_type = old->def_process_chown_type;
	new->def_process_execute_type = old->def_process_execute_type;
	new->def_ipc_create_type = old->def_ipc_create_type;
	new->def_group_create_type = RSBAC_RC_GENERAL_TYPE;
	new->def_unixsock_create_type = RC_type_use_fd;
	new->boot_role = FALSE;
	new->req_reauth = FALSE;
	return 0;
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static rsbac_list_conv_function_t *role_get_conv(rsbac_version_t
						 old_version)
#else
static rsbac_list_conv_function_t *__init role_get_conv(rsbac_version_t
							old_version)
#endif
{
	switch (old_version) {
	case RSBAC_RC_ROLE_OLD_LIST_VERSION:
		return role_conv;
	case RSBAC_RC_ROLE_OLD_OLD_LIST_VERSION:
		return old_role_conv;
	case RSBAC_RC_ROLE_OLD_OLD_OLD_LIST_VERSION:
		return old_old_role_conv;
	case RSBAC_RC_ROLE_OLD_OLD_OLD_OLD_LIST_VERSION:
		return old_old_old_role_conv;
	default:
		return NULL;
	}
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static int tc_subconv(
#else
static int __init tc_subconv(
#endif
				    void *old_desc,
				    void *old_data,
				    void *new_desc, void *new_data)
{
	rsbac_rc_rights_vector_t *new = new_data;
	rsbac_rc_rights_vector_t *old = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_rc_type_id_t));
	*new = (*old & RSBAC_ALL_REQUEST_VECTOR)
	    | ((*old & ~(RSBAC_ALL_REQUEST_VECTOR)) <<
	       (RSBAC_RC_SPECIAL_RIGHT_BASE -
		RSBAC_RC_OLD_SPECIAL_RIGHT_BASE));
	return 0;
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static rsbac_list_conv_function_t *tcfd_get_subconv(rsbac_version_t
						    old_version)
#else
static rsbac_list_conv_function_t *__init tcfd_get_subconv(rsbac_version_t
							   old_version)
#endif
{
	switch (old_version) {
	case RSBAC_RC_ROLE_TCFD_OLD_LIST_VERSION:
		return tc_subconv;
	default:
		return NULL;
	}
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static int tc_conv(
#else
static int __init tc_conv(
#endif
				 void *old_desc,
				 void *old_data,
				 void *new_desc, void *new_data)
{
	memcpy(new_desc, old_desc, sizeof(rsbac_rc_role_id_t));
	return 0;
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static rsbac_list_conv_function_t *tcfd_get_conv(rsbac_version_t
						 old_version)
#else
static rsbac_list_conv_function_t *__init tcfd_get_conv(rsbac_version_t
							old_version)
#endif
{
	switch (old_version) {
	case RSBAC_RC_ROLE_TCFD_OLD_LIST_VERSION:
		return tc_conv;
	default:
		return NULL;
	}
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static int rsbac_rc_role_compare_data(void *data1, void *data2)
#else
static int __init rsbac_rc_role_compare_data(void *data1, void *data2)
#endif
{
	struct rsbac_rc_role_entry_t *role = data1;

	if (!data1)
		return 1;
	if (role->boot_role)
		return 0;
	else
		return 1;
}

/************************************************* */
/*               proc functions                    */
/************************************************* */

#if defined(CONFIG_RSBAC_PROC)
static int
stats_rc_proc_show(struct seq_file *m, void *v)
{
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "stats_rc_proc_info(): RSBAC not initialized\n");
		return (-RSBAC_ENOTINITIALIZED);
	}
	rsbac_pr_debug(aef_rc, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	seq_printf(m, "RC Status\n---------\n");
	seq_printf(m,
		    "Role entry size is %Zd, %lu entries used\n",
		    sizeof(struct rsbac_rc_role_entry_t),
		    rsbac_list_count(role_handle));
	seq_printf(m,
		    "Used type entries: fd: %lu, dev: %lu, ipc: %lu, user: %lu, process: %lu, group: %lu, netdev: %lu, nettemp: %lu, netobj: %lu\n",
		    rsbac_list_count(type_fd_handle),
		    rsbac_list_count(type_dev_handle),
		    rsbac_list_count(type_ipc_handle),
		    rsbac_list_count(type_user_handle),
		    rsbac_list_count(type_process_handle),
		    rsbac_list_count(type_group_handle),
		    rsbac_list_count(type_netdev_handle),
		    rsbac_list_count(type_nettemp_handle),
		    rsbac_list_count(type_netobj_handle));
	return 0;
}

static int stats_rc_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, stats_rc_proc_show, NULL);
}

static const struct file_operations stats_rc_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= stats_rc_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static struct proc_dir_entry *stats_rc;

#endif				/* CONFIG_PROC_FS && CONFIG_RSBAC_PROC */

/************************************************* */
/*               Init functions                    */
/************************************************* */

/* All functions return 0, if no error occurred, and a negative error code  */
/* otherwise. The error codes are defined in rsbac/error.h.                 */

/************************************************************************** */
/* Initialization of all RC data structures. After this call, all RC data   */
/* is kept in memory for performance reasons, but is written to disk on     */
/* every change.    */

/* There can be no access to aci data structures before init.               */

#ifdef CONFIG_RSBAC_INIT_DELAY
static void registration_error(int err, char *listname)
#else
static void __init registration_error(int err, char *listname)
#endif
{
	if (err) {
		char *tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

		if (tmp) {
			rsbac_printk(KERN_WARNING "rsbac_init_rc(): Registering RC %s list failed with error %s\n",
				     listname, get_error_name(tmp, err));
			rsbac_kfree(tmp);
		}
	}
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static void create_def_roles(void)
#else
static void __init create_def_roles(void)
#endif
{
	rsbac_rc_role_id_t role;
	rsbac_rc_type_id_t type;
	rsbac_rc_rights_vector_t rights;
	struct rsbac_rc_role_entry_t gen_entry =
	    RSBAC_RC_GENERAL_ROLE_ENTRY;
	struct rsbac_rc_role_entry_t ra_entry =
	    RSBAC_RC_ROLE_ADMIN_ROLE_ENTRY;
	struct rsbac_rc_role_entry_t sa_entry =
	    RSBAC_RC_SYSTEM_ADMIN_ROLE_ENTRY;

	rsbac_printk(KERN_WARNING "rsbac_init_rc(): no RC roles read, generating default role entries!\n");

	role = RSBAC_RC_GENERAL_ROLE;
	if (!rsbac_list_add(role_handle, &role, &gen_entry)) {
		if (!rsbac_list_lol_add
		    (role_tcfd_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    (RSBAC_READ_WRITE_REQUEST_VECTOR |
			     RSBAC_EXECUTE_REQUEST_VECTOR)
			    & RSBAC_FD_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcfd_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcdv_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    RSBAC_READ_WRITE_REQUEST_VECTOR &
			    RSBAC_DEV_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcdv_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcus_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    RSBAC_REQUEST_VECTOR(R_SEARCH) |
			    RSBAC_REQUEST_VECTOR(R_CHANGE_OWNER) |
			    RSBAC_REQUEST_VECTOR
			    (R_GET_STATUS_DATA);
			rsbac_list_lol_subadd(role_tcus_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcpr_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    RSBAC_READ_WRITE_REQUEST_VECTOR &
			    RSBAC_PROCESS_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcpr_handle,
					      &role, &type,
					      &rights);
			type = CONFIG_RSBAC_RC_KERNEL_PROCESS_TYPE;
			rights =
			    RSBAC_READ_REQUEST_VECTOR &
			    RSBAC_PROCESS_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcpr_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcip_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    RSBAC_READ_WRITE_REQUEST_VECTOR &
			    RSBAC_IPC_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcip_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcgr_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    RSBAC_REQUEST_VECTOR(R_SEARCH) |
			    RSBAC_REQUEST_VECTOR
			    (R_GET_STATUS_DATA);
			rsbac_list_lol_subadd(role_tcgr_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcnd_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    RSBAC_READ_WRITE_REQUEST_VECTOR &
			    RSBAC_NETDEV_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcnd_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcno_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    RSBAC_READ_WRITE_REQUEST_VECTOR &
			    RSBAC_NETOBJ_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcno_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcsc_handle, &role, NULL)) {
#ifdef CONFIG_RSBAC_USER_MOD_IOPERM
			type = ST_ioports;
			rights =
			    RSBAC_RC_RIGHTS_VECTOR
			    (R_MODIFY_PERMISSIONS_DATA);
			rsbac_list_lol_subadd(role_tcsc_handle,
					      &role, &type,
					      &rights);
#endif
			type = ST_rlimit;
			rights =
			    RSBAC_RC_RIGHTS_VECTOR
			    (R_GET_STATUS_DATA)
			    |
			    RSBAC_RC_RIGHTS_VECTOR
			    (R_MODIFY_SYSTEM_DATA);
			rsbac_list_lol_subadd(role_tcsc_handle,
					      &role, &type,
					      &rights);
			type = ST_other;
			rights =
			    RSBAC_RC_RIGHTS_VECTOR(R_MAP_EXEC);
			rsbac_list_lol_subadd(role_tcsc_handle,
					      &role, &type,
					      &rights);
			type = ST_network;
			rights =
			    RSBAC_RC_RIGHTS_VECTOR
			    (R_GET_STATUS_DATA);
			rsbac_list_lol_subadd(role_tcsc_handle,
					      &role, &type,
					      &rights);
		}
	}
	role = RSBAC_RC_ROLE_ADMIN_ROLE;
	if (!rsbac_list_add(role_handle, &role, &ra_entry)) {
		if (!rsbac_list_lol_add
		    (role_tcfd_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights = ((RSBAC_READ_WRITE_REQUEST_VECTOR
				   | RSBAC_EXECUTE_REQUEST_VECTOR
				   | RSBAC_SECURITY_REQUEST_VECTOR)
				  & RSBAC_FD_REQUEST_VECTOR) |
			    RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcfd_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SEC_TYPE;
			rsbac_list_lol_subadd(role_tcfd_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SYS_TYPE;
			rights =
			    (RSBAC_READ_REQUEST_VECTOR &
			     RSBAC_FD_REQUEST_VECTOR)
			    | RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcfd_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcdv_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    ((RSBAC_READ_WRITE_REQUEST_VECTOR |
			      RSBAC_SECURITY_REQUEST_VECTOR)
			     & RSBAC_DEV_REQUEST_VECTOR) |
			    RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcdv_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SEC_TYPE;
			rights =
			    ((RSBAC_READ_WRITE_REQUEST_VECTOR |
			      RSBAC_SECURITY_REQUEST_VECTOR)
			     & RSBAC_DEV_REQUEST_VECTOR) |
			    RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcdv_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcus_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    ((RSBAC_READ_WRITE_REQUEST_VECTOR |
			      RSBAC_SECURITY_REQUEST_VECTOR |
			      RSBAC_REQUEST_VECTOR(R_AUTHENTICATE))
			     & RSBAC_USER_REQUEST_VECTOR) |
			    RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcus_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SYS_TYPE;
			rights =
			    ((RSBAC_READ_WRITE_REQUEST_VECTOR |
			      RSBAC_SECURITY_REQUEST_VECTOR |
			      RSBAC_REQUEST_VECTOR(R_AUTHENTICATE))
			     & RSBAC_USER_REQUEST_VECTOR) |
			    RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcus_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SEC_TYPE;
			rights =
			    ((RSBAC_READ_WRITE_REQUEST_VECTOR |
			      RSBAC_SECURITY_REQUEST_VECTOR |
			      RSBAC_REQUEST_VECTOR(R_AUTHENTICATE))
			     & RSBAC_USER_REQUEST_VECTOR) |
			    RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcus_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcpr_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    ((RSBAC_READ_WRITE_REQUEST_VECTOR |
			      RSBAC_SECURITY_REQUEST_VECTOR)
			     & RSBAC_PROCESS_REQUEST_VECTOR) |
			    RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcpr_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SEC_TYPE;
			rights =
			    ((RSBAC_READ_WRITE_REQUEST_VECTOR |
			      RSBAC_SECURITY_REQUEST_VECTOR)
			     & RSBAC_PROCESS_REQUEST_VECTOR) |
			    RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcpr_handle,
					      &role, &type,
					      &rights);
			type = CONFIG_RSBAC_RC_KERNEL_PROCESS_TYPE;
			rights =
			    ((RSBAC_READ_WRITE_REQUEST_VECTOR |
			      RSBAC_SECURITY_REQUEST_VECTOR)
			     & RSBAC_PROCESS_REQUEST_VECTOR) |
			    RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcpr_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcip_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    ((RSBAC_READ_WRITE_REQUEST_VECTOR |
			      RSBAC_SECURITY_REQUEST_VECTOR)
			     & RSBAC_IPC_REQUEST_VECTOR) |
			    RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcip_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SEC_TYPE;
			rights =
			    ((RSBAC_READ_WRITE_REQUEST_VECTOR |
			      RSBAC_SECURITY_REQUEST_VECTOR)
			     & RSBAC_IPC_REQUEST_VECTOR) |
			    RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcip_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcgr_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    ((RSBAC_READ_WRITE_REQUEST_VECTOR |
			      RSBAC_SECURITY_REQUEST_VECTOR)
			     & RSBAC_GROUP_REQUEST_VECTOR) |
			    RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcgr_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcnd_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    ((RSBAC_REQUEST_VECTOR
			      (R_GET_STATUS_DATA) |
			      RSBAC_SECURITY_REQUEST_VECTOR)
			     & RSBAC_NETDEV_REQUEST_VECTOR) |
			    RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcnd_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SEC_TYPE;
			rsbac_list_lol_subadd(role_tcnd_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SYS_TYPE;
			rsbac_list_lol_subadd(role_tcnd_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcnt_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    ((RSBAC_READ_WRITE_REQUEST_VECTOR |
			      RSBAC_SECURITY_REQUEST_VECTOR)
			     & RSBAC_NETTEMP_REQUEST_VECTOR) |
			    RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcnt_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SEC_TYPE;
			rights =
			    ((RSBAC_READ_WRITE_REQUEST_VECTOR |
			      RSBAC_SECURITY_REQUEST_VECTOR)
			     & RSBAC_NETTEMP_REQUEST_VECTOR) |
			    RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcnt_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcno_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    ((RSBAC_READ_WRITE_REQUEST_VECTOR |
			      RSBAC_SECURITY_REQUEST_VECTOR)
			     & RSBAC_NETOBJ_REQUEST_VECTOR) |
			    RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcno_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcsc_handle, &role, NULL)) {
#ifdef CONFIG_RSBAC_USER_MOD_IOPERM
			type = ST_ioports;
			rights =
			    RSBAC_RC_RIGHTS_VECTOR
			    (R_MODIFY_PERMISSIONS_DATA)
			    | RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcsc_handle,
					      &role, &type,
					      &rights);
#endif
			type = ST_rlimit;
			rights =
			    RSBAC_SCD_REQUEST_VECTOR |
			    RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcsc_handle,
					      &role, &type,
					      &rights);
			type = ST_rsbac;
			rights =
			    RSBAC_SCD_REQUEST_VECTOR |
			    RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcsc_handle,
					      &role, &type,
					      &rights);
			type = ST_rsbac_log;
			rights =
			    RSBAC_SCD_REQUEST_VECTOR |
			    RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcsc_handle,
					      &role, &type,
					      &rights);
			type = ST_other;
			rights = RSBAC_RC_RIGHTS_VECTOR(R_MAP_EXEC)
			    |
			    RSBAC_RC_RIGHTS_VECTOR
			    (R_MODIFY_PERMISSIONS_DATA)
			    | RSBAC_RC_RIGHTS_VECTOR(R_SWITCH_LOG)
			    |
			    RSBAC_RC_RIGHTS_VECTOR(R_SWITCH_MODULE)
			    | RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcsc_handle,
					      &role, &type,
					      &rights);
			type = ST_network;
			rights =
			    RSBAC_RC_RIGHTS_VECTOR
			    (R_GET_STATUS_DATA)
			    | RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcsc_handle,
					      &role, &type,
					      &rights);
			type = ST_firewall;
			rights =
			    RSBAC_RC_RIGHTS_VECTOR
			    (R_GET_STATUS_DATA)
			    | RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcsc_handle,
					      &role, &type,
					      &rights);
			type = RST_auth_administration;
			rights =
			    RSBAC_SCD_REQUEST_VECTOR |
			    RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcsc_handle,
					      &role, &type,
					      &rights);
			type = ST_sysfs;
			rights =
			    RSBAC_RC_RIGHTS_VECTOR
			    (R_GET_STATUS_DATA)
			    | RSBAC_RC_SPECIAL_RIGHTS_VECTOR;
			rsbac_list_lol_subadd(role_tcsc_handle,
					      &role, &type,
					      &rights);
		}
	}
	role = RSBAC_RC_SYSTEM_ADMIN_ROLE;
	if (!rsbac_list_add(role_handle, &role, &sa_entry)) {
		if (!rsbac_list_lol_add
		    (role_tcfd_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights = (RSBAC_READ_WRITE_REQUEST_VECTOR
				  | RSBAC_EXECUTE_REQUEST_VECTOR
				  | RSBAC_SYSTEM_REQUEST_VECTOR)
			    & RSBAC_FD_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcfd_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SYS_TYPE;
			rsbac_list_lol_subadd(role_tcfd_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcdv_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    (RSBAC_READ_WRITE_REQUEST_VECTOR |
			     RSBAC_SYSTEM_REQUEST_VECTOR) &
			    RSBAC_DEV_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcdv_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SYS_TYPE;
			rights =
			    (RSBAC_READ_WRITE_REQUEST_VECTOR |
			     RSBAC_SYSTEM_REQUEST_VECTOR) &
			    RSBAC_DEV_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcdv_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcus_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    RSBAC_REQUEST_VECTOR(R_CHANGE_OWNER) |
			    RSBAC_REQUEST_VECTOR(R_SEARCH) |
			    RSBAC_REQUEST_VECTOR(R_GET_STATUS_DATA) |
			    RSBAC_REQUEST_VECTOR(R_AUTHENTICATE);
			rsbac_list_lol_subadd(role_tcus_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SYS_TYPE;
			rights =
			    RSBAC_REQUEST_VECTOR(R_SEARCH) |
			    RSBAC_REQUEST_VECTOR(R_GET_STATUS_DATA) |
			    RSBAC_REQUEST_VECTOR(R_AUTHENTICATE);
			rsbac_list_lol_subadd(role_tcus_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SEC_TYPE;
			rights =
			    RSBAC_REQUEST_VECTOR(R_SEARCH) |
			    RSBAC_REQUEST_VECTOR(R_AUTHENTICATE);
			rsbac_list_lol_subadd(role_tcus_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcpr_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    (RSBAC_READ_WRITE_REQUEST_VECTOR |
			     RSBAC_REQUEST_VECTOR(R_CONNECT) |
			     RSBAC_REQUEST_VECTOR(R_SEND) |
			     RSBAC_REQUEST_VECTOR(R_RECEIVE) |
			     RSBAC_SYSTEM_REQUEST_VECTOR) &
			    RSBAC_PROCESS_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcpr_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SYS_TYPE;
			rights =
			    (RSBAC_READ_WRITE_REQUEST_VECTOR |
			     RSBAC_SYSTEM_REQUEST_VECTOR) &
			    RSBAC_PROCESS_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcpr_handle,
					      &role, &type,
					      &rights);
			type = CONFIG_RSBAC_RC_KERNEL_PROCESS_TYPE;
			rights =
			    (RSBAC_READ_WRITE_REQUEST_VECTOR |
			     RSBAC_SYSTEM_REQUEST_VECTOR) &
			    RSBAC_PROCESS_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcpr_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcip_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    (RSBAC_READ_WRITE_REQUEST_VECTOR |
			     RSBAC_SYSTEM_REQUEST_VECTOR) &
			    RSBAC_IPC_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcip_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SYS_TYPE;
			rights =
			    (RSBAC_READ_WRITE_REQUEST_VECTOR |
			     RSBAC_SYSTEM_REQUEST_VECTOR) &
			    RSBAC_IPC_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcip_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcgr_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    RSBAC_REQUEST_VECTOR(R_SEARCH) |
			    RSBAC_REQUEST_VECTOR(R_GET_STATUS_DATA) |
			    RSBAC_REQUEST_VECTOR(R_READ);
			rsbac_list_lol_subadd(role_tcgr_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcnd_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    (RSBAC_READ_WRITE_REQUEST_VECTOR |
			     RSBAC_SYSTEM_REQUEST_VECTOR) &
			    RSBAC_NETDEV_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcnd_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcnt_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    (RSBAC_READ_REQUEST_VECTOR) &
			    RSBAC_NETTEMP_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcnt_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcno_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    (RSBAC_READ_WRITE_REQUEST_VECTOR |
			     RSBAC_SYSTEM_REQUEST_VECTOR) &
			    RSBAC_NETOBJ_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcno_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcsc_handle, &role, NULL)) {
			rights =
			    RSBAC_SCD_REQUEST_VECTOR &
			    (RSBAC_SYSTEM_REQUEST_VECTOR |
			     RSBAC_READ_WRITE_REQUEST_VECTOR);
			for (type = ST_time_strucs;
			     type <= ST_rsbac; type++) {
				rsbac_list_lol_subadd
				    (role_tcsc_handle, &role,
				     &type, &rights);
			}
			for (type = ST_network; type < ST_none;
			     type++) {
				rsbac_list_lol_subadd
				    (role_tcsc_handle, &role,
				     &type, &rights);
			}
			type = ST_other;
			rights =
			    RSBAC_RC_RIGHTS_VECTOR(R_ADD_TO_KERNEL)
			    | RSBAC_RC_RIGHTS_VECTOR(R_MAP_EXEC)
			    |
			    RSBAC_RC_RIGHTS_VECTOR
			    (R_MODIFY_SYSTEM_DATA)
			    | RSBAC_RC_RIGHTS_VECTOR(R_MOUNT)
			    |
			    RSBAC_RC_RIGHTS_VECTOR
			    (R_REMOVE_FROM_KERNEL)
			    | RSBAC_RC_RIGHTS_VECTOR(R_UMOUNT)
			    | RSBAC_RC_RIGHTS_VECTOR(R_SHUTDOWN);
			rsbac_list_lol_subadd(role_tcsc_handle,
					      &role, &type,
					      &rights);
		}
	}
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static void create_def_roles2(void)
#else
static void __init create_def_roles2(void)
#endif
{
	rsbac_rc_role_id_t role;
	rsbac_rc_type_id_t type;
	rsbac_rc_rights_vector_t rights;
	struct rsbac_rc_role_entry_t au_entry =
	    RSBAC_RC_AUDITOR_ROLE_ENTRY;
	struct rsbac_rc_role_entry_t bo_entry =
	    RSBAC_RC_BOOT_ROLE_ENTRY;

	rsbac_printk(KERN_WARNING "rsbac_init_rc(): no RC roles read, generating default role entries!\n");

	role = RSBAC_RC_AUDITOR_ROLE;
	if (!rsbac_list_add(role_handle, &role, &au_entry)) {
		if (!rsbac_list_lol_add
		    (role_tcfd_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    (RSBAC_READ_WRITE_REQUEST_VECTOR |
			     RSBAC_EXECUTE_REQUEST_VECTOR)
			    & RSBAC_FD_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcfd_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcdv_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    RSBAC_READ_WRITE_REQUEST_VECTOR &
			    RSBAC_DEV_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcdv_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcus_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    RSBAC_REQUEST_VECTOR(R_CHANGE_OWNER) |
			    RSBAC_REQUEST_VECTOR(R_SEARCH) |
			    RSBAC_REQUEST_VECTOR
			    (R_GET_STATUS_DATA);
			rsbac_list_lol_subadd(role_tcus_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcgr_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    RSBAC_REQUEST_VECTOR(R_SEARCH) |
			    RSBAC_REQUEST_VECTOR
			    (R_GET_STATUS_DATA);
			rsbac_list_lol_subadd(role_tcgr_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcpr_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    RSBAC_READ_WRITE_REQUEST_VECTOR &
			    RSBAC_PROCESS_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcpr_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcip_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    RSBAC_READ_WRITE_REQUEST_VECTOR &
			    RSBAC_IPC_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcip_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcnd_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    RSBAC_READ_WRITE_REQUEST_VECTOR &
			    RSBAC_NETDEV_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcnd_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcno_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    RSBAC_READ_WRITE_REQUEST_VECTOR &
			    RSBAC_NETOBJ_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcno_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcsc_handle, &role, NULL)) {
#ifdef CONFIG_RSBAC_USER_MOD_IOPERM
			type = ST_ioports;
			rights =
			    RSBAC_RC_RIGHTS_VECTOR
			    (R_MODIFY_PERMISSIONS_DATA);
			rsbac_list_lol_subadd(role_tcsc_handle,
					      &role, &type,
					      &rights);
#endif
			type = ST_rlimit;
			rights =
			    RSBAC_RC_RIGHTS_VECTOR
			    (R_GET_STATUS_DATA)
			    |
			    RSBAC_RC_RIGHTS_VECTOR
			    (R_MODIFY_SYSTEM_DATA);
			rsbac_list_lol_subadd(role_tcsc_handle,
					      &role, &type,
					      &rights);
			type = ST_rsbac_log;
			rights =
			    RSBAC_RC_RIGHTS_VECTOR
			    (R_GET_STATUS_DATA)
			    |
			    RSBAC_RC_RIGHTS_VECTOR
			    (R_MODIFY_SYSTEM_DATA);
			rsbac_list_lol_subadd(role_tcsc_handle,
					      &role, &type,
					      &rights);
			type = ST_other;
			rights =
			    RSBAC_RC_RIGHTS_VECTOR(R_MAP_EXEC);
			rsbac_list_lol_subadd(role_tcsc_handle,
					      &role, &type,
					      &rights);
			type = ST_network;
			rights =
			    RSBAC_RC_RIGHTS_VECTOR
			    (R_GET_STATUS_DATA);
			rsbac_list_lol_subadd(role_tcsc_handle,
					      &role, &type,
					      &rights);
		}
	}
	role = RSBAC_RC_BOOT_ROLE;
	if (!rsbac_list_add(role_handle, &role, &bo_entry)) {
		if (!rsbac_list_lol_add
		    (role_tcfd_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights = (RSBAC_READ_WRITE_REQUEST_VECTOR
				  | RSBAC_EXECUTE_REQUEST_VECTOR
				  | RSBAC_SYSTEM_REQUEST_VECTOR)
			    & RSBAC_FD_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcfd_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SYS_TYPE;
			rsbac_list_lol_subadd(role_tcfd_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcdv_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    (RSBAC_READ_WRITE_REQUEST_VECTOR |
			     RSBAC_SYSTEM_REQUEST_VECTOR) &
			    RSBAC_DEV_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcdv_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SYS_TYPE;
			rights =
			    (RSBAC_READ_WRITE_REQUEST_VECTOR |
			     RSBAC_SYSTEM_REQUEST_VECTOR) &
			    RSBAC_DEV_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcdv_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcus_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    (RSBAC_READ_REQUEST_VECTOR |
			     RSBAC_REQUEST_VECTOR(R_CHANGE_OWNER) |
			     RSBAC_SYSTEM_REQUEST_VECTOR |
			     RSBAC_REQUEST_VECTOR(R_AUTHENTICATE)) &
			    RSBAC_USER_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcus_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SEC_TYPE;
			rights =
			    RSBAC_REQUEST_VECTOR(R_SEARCH) |
		            RSBAC_REQUEST_VECTOR(R_CHANGE_OWNER) |
			    RSBAC_REQUEST_VECTOR(R_AUTHENTICATE);
			rsbac_list_lol_subadd(role_tcus_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SYS_TYPE;
			rights =
			    (RSBAC_READ_REQUEST_VECTOR |
			     RSBAC_SYSTEM_REQUEST_VECTOR) &
			    RSBAC_USER_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcus_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcpr_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    (RSBAC_READ_WRITE_REQUEST_VECTOR |
			     RSBAC_SYSTEM_REQUEST_VECTOR) &
			    RSBAC_PROCESS_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcpr_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SYS_TYPE;
			rights =
			    (RSBAC_READ_WRITE_REQUEST_VECTOR |
			     RSBAC_SYSTEM_REQUEST_VECTOR) &
			    RSBAC_PROCESS_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcpr_handle,
					      &role, &type,
					      &rights);
			type = CONFIG_RSBAC_RC_KERNEL_PROCESS_TYPE;
			rights =
			    (RSBAC_READ_WRITE_REQUEST_VECTOR |
			     RSBAC_SYSTEM_REQUEST_VECTOR) &
			    RSBAC_PROCESS_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcpr_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcip_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    (RSBAC_READ_WRITE_REQUEST_VECTOR |
			     RSBAC_SYSTEM_REQUEST_VECTOR) &
			    RSBAC_IPC_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcip_handle,
					      &role, &type,
					      &rights);
			type = RSBAC_RC_SYS_TYPE;
			rights =
			    (RSBAC_READ_WRITE_REQUEST_VECTOR |
			     RSBAC_SYSTEM_REQUEST_VECTOR) &
			    RSBAC_IPC_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcip_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcnd_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    (RSBAC_READ_WRITE_REQUEST_VECTOR |
			     RSBAC_SYSTEM_REQUEST_VECTOR) &
			    RSBAC_NETDEV_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcnd_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcnt_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    (RSBAC_READ_REQUEST_VECTOR) &
			    RSBAC_NETTEMP_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcnt_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcno_handle, &role, NULL)) {
			type = RSBAC_RC_GENERAL_TYPE;
			rights =
			    (RSBAC_READ_WRITE_REQUEST_VECTOR |
			     RSBAC_SYSTEM_REQUEST_VECTOR) &
			    RSBAC_NETOBJ_REQUEST_VECTOR;
			rsbac_list_lol_subadd(role_tcno_handle,
					      &role, &type,
					      &rights);
		}
		if (!rsbac_list_lol_add
		    (role_tcsc_handle, &role, NULL)) {
			rights =
			    RSBAC_SCD_REQUEST_VECTOR &
			    (RSBAC_SYSTEM_REQUEST_VECTOR |
			     RSBAC_READ_WRITE_REQUEST_VECTOR);
			for (type = ST_time_strucs;
			     type <= ST_rsbac; type++) {
				rsbac_list_lol_subadd
				    (role_tcsc_handle, &role,
				     &type, &rights);
			}
			for (type = ST_network; type < ST_none;
			     type++) {
				rsbac_list_lol_subadd
				    (role_tcsc_handle, &role,
				     &type, &rights);
			}
			type = ST_other;
			rights =
			    RSBAC_RC_RIGHTS_VECTOR(R_ADD_TO_KERNEL)
			    | RSBAC_RC_RIGHTS_VECTOR(R_MAP_EXEC)
			    |
			    RSBAC_RC_RIGHTS_VECTOR
			    (R_MODIFY_SYSTEM_DATA)
			    | RSBAC_RC_RIGHTS_VECTOR(R_MOUNT)
			    |
			    RSBAC_RC_RIGHTS_VECTOR
			    (R_REMOVE_FROM_KERNEL)
			    | RSBAC_RC_RIGHTS_VECTOR(R_UMOUNT)
			    | RSBAC_RC_RIGHTS_VECTOR(R_SHUTDOWN);
			rsbac_list_lol_subadd(role_tcsc_handle,
					      &role, &type,
					      &rights);
		}
	}
}

#ifdef CONFIG_RSBAC_INIT_DELAY
int rsbac_init_rc(void)
#else
int __init rsbac_init_rc(void)
#endif
{
	int err = 0;
	struct rsbac_list_lol_info_t lol_info;
	struct rsbac_list_info_t list_info;
	rsbac_rc_rights_vector_t def_tc = RSBAC_RC_DEFAULT_RIGHTS_VECTOR;

	if (rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_init_rc(): RSBAC already initialized\n");
		return -RSBAC_EREINIT;
	}

	/* init data structures */
	rsbac_printk(KERN_INFO "rsbac_init_rc(): Initializing RSBAC: RC subsystem\n");
	rsbac_pr_debug(stack, "free stack: %lu\n", rsbac_stack_free_space());

	list_info.version = RSBAC_RC_ROLE_LIST_VERSION;
	list_info.key = RSBAC_RC_LIST_KEY;
	list_info.desc_size = sizeof(rsbac_rc_role_id_t);
	list_info.data_size = sizeof(struct rsbac_rc_role_entry_t);
	list_info.max_age = 0;
	err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
				  &role_handle, &list_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				  RSBAC_LIST_BACKUP |
#endif
				  RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				  RSBAC_LIST_REPLICATE | RSBAC_LIST_AUTO_HASH_RESIZE,
				  NULL, role_get_conv,
				  NULL, RSBAC_RC_ROLE_FILENAME,
				  RSBAC_AUTO_DEV,
				  nr_role_hashes,
				  (nr_role_hashes > 1) ? role_hash : NULL,
				  NULL);
	if (err) {
		registration_error(err, "role");
	}

	lol_info.version = RSBAC_RC_ROLE_RC_LIST_VERSION;
	lol_info.key = RSBAC_RC_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_rc_role_id_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_rc_role_id_t);
	lol_info.subdata_size = 0;
	lol_info.max_age = 0;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &role_rc_handle, &lol_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				      RSBAC_LIST_REPLICATE |
				      RSBAC_LIST_DEF_DATA |
				      RSBAC_LIST_AUTO_HASH_RESIZE,
				      NULL,
				      NULL, NULL, NULL,
				      NULL, NULL,
				      RSBAC_RC_ROLE_RC_FILENAME,
				      RSBAC_AUTO_DEV,
				      nr_role_hashes,
				      (nr_role_hashes > 1) ? role_hash : NULL,
				      NULL);
	if (err) {
		registration_error(err, "role compatibilities");
	}
	lol_info.version = RSBAC_RC_ROLE_ADR_LIST_VERSION;
	lol_info.key = RSBAC_RC_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_rc_role_id_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_rc_role_id_t);
	lol_info.subdata_size = 0;
	lol_info.max_age = 0;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &role_adr_handle, &lol_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				      RSBAC_LIST_REPLICATE |
				      RSBAC_LIST_DEF_DATA |
				      RSBAC_LIST_AUTO_HASH_RESIZE,
				      NULL,
				      NULL, NULL, NULL,
				      NULL, NULL,
				      RSBAC_RC_ROLE_ADR_FILENAME,
				      RSBAC_AUTO_DEV,
				      nr_role_hashes,
				      (nr_role_hashes > 1) ? role_hash : NULL,
				      NULL);
	if (err) {
		registration_error(err, "admin roles");
	}
	lol_info.version = RSBAC_RC_ROLE_ASR_LIST_VERSION;
	lol_info.key = RSBAC_RC_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_rc_role_id_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_rc_role_id_t);
	lol_info.subdata_size = 0;
	lol_info.max_age = 0;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &role_asr_handle, &lol_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				      RSBAC_LIST_REPLICATE |
				      RSBAC_LIST_DEF_DATA |
				      RSBAC_LIST_AUTO_HASH_RESIZE,
				      NULL,
				      NULL, NULL, NULL,
				      NULL, NULL,
				      RSBAC_RC_ROLE_ASR_FILENAME,
				      RSBAC_AUTO_DEV,
				      nr_role_hashes,
				      (nr_role_hashes > 1) ? role_hash : NULL,
				      NULL);
	if (err) {
		registration_error(err, "assign roles");
	}
	lol_info.version = RSBAC_RC_ROLE_DFDC_LIST_VERSION;
	lol_info.key = RSBAC_RC_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_rc_role_id_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_rc_type_id_t);
	lol_info.subdata_size = sizeof(rsbac_rc_type_id_t);
	lol_info.max_age = 0;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &role_dfdc_handle, &lol_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				      RSBAC_LIST_REPLICATE |
				      RSBAC_LIST_DEF_DATA |
				      RSBAC_LIST_AUTO_HASH_RESIZE,
				      NULL,
				      NULL, NULL, NULL,
				      NULL, NULL,
				      RSBAC_RC_ROLE_DFDC_FILENAME,
				      RSBAC_AUTO_DEV,
				      nr_role_hashes,
				      (nr_role_hashes > 1) ? role_hash : NULL,
				      NULL);
	if (err) {
		registration_error(err, "Role default FD create types");
	}
	lol_info.version = RSBAC_RC_ROLE_TCFD_LIST_VERSION;
	lol_info.key = RSBAC_RC_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_rc_role_id_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_rc_type_id_t);
	lol_info.subdata_size = sizeof(rsbac_rc_rights_vector_t);
	lol_info.max_age = 0;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &role_tcfd_handle, &lol_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				      RSBAC_LIST_REPLICATE |
				      RSBAC_LIST_DEF_DATA |
				      RSBAC_LIST_DEF_SUBDATA |
				      RSBAC_LIST_AUTO_HASH_RESIZE,
				      NULL,
				      NULL,
				      tcfd_get_conv, tcfd_get_subconv,
				      NULL, &def_tc,
				      RSBAC_RC_ROLE_TCFD_FILENAME,
				      RSBAC_AUTO_DEV,
				      nr_role_hashes,
				      (nr_role_hashes > 1) ? role_hash : NULL,
				      NULL);
	if (err) {
		registration_error(err, "Role FD type compatibilities");
	}
	lol_info.version = RSBAC_RC_ROLE_TCDV_LIST_VERSION;
	lol_info.key = RSBAC_RC_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_rc_role_id_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_rc_type_id_t);
	lol_info.subdata_size = sizeof(rsbac_rc_rights_vector_t);
	lol_info.max_age = 0;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &role_tcdv_handle, &lol_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				      RSBAC_LIST_REPLICATE |
				      RSBAC_LIST_DEF_DATA |
				      RSBAC_LIST_DEF_SUBDATA |
				      RSBAC_LIST_AUTO_HASH_RESIZE,
				      NULL,
				      NULL,
				      tcfd_get_conv, tcfd_get_subconv,
				      NULL, &def_tc,
				      RSBAC_RC_ROLE_TCDV_FILENAME,
				      RSBAC_AUTO_DEV,
				      nr_role_hashes,
				      (nr_role_hashes > 1) ? role_hash : NULL,
				      NULL);
	if (err) {
		registration_error(err, "Role DEV type compatibilities");
	}
	lol_info.version = RSBAC_RC_ROLE_TCUS_LIST_VERSION;
	lol_info.key = RSBAC_RC_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_rc_role_id_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_rc_type_id_t);
	lol_info.subdata_size = sizeof(rsbac_rc_rights_vector_t);
	lol_info.max_age = 0;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &role_tcus_handle, &lol_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				      RSBAC_LIST_REPLICATE |
				      RSBAC_LIST_DEF_DATA |
				      RSBAC_LIST_DEF_SUBDATA |
				      RSBAC_LIST_AUTO_HASH_RESIZE,
				      NULL,
				      NULL,
				      tcfd_get_conv, tcfd_get_subconv,
				      NULL, &def_tc,
				      RSBAC_RC_ROLE_TCUS_FILENAME,
				      RSBAC_AUTO_DEV,
				      nr_role_hashes,
				      (nr_role_hashes > 1) ? role_hash : NULL,
				      NULL);
	if (err) {
		registration_error(err, "Role User type compatibilities");
	}
	lol_info.version = RSBAC_RC_ROLE_TCPR_LIST_VERSION;
	lol_info.key = RSBAC_RC_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_rc_role_id_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_rc_type_id_t);
	lol_info.subdata_size = sizeof(rsbac_rc_rights_vector_t);
	lol_info.max_age = 0;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &role_tcpr_handle, &lol_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				      RSBAC_LIST_REPLICATE |
				      RSBAC_LIST_DEF_DATA |
				      RSBAC_LIST_DEF_SUBDATA |
				      RSBAC_LIST_AUTO_HASH_RESIZE,
				      NULL,
				      NULL,
				      tcfd_get_conv, tcfd_get_subconv,
				      NULL, &def_tc,
				      RSBAC_RC_ROLE_TCPR_FILENAME,
				      RSBAC_AUTO_DEV,
				      nr_role_hashes,
				      (nr_role_hashes > 1) ? role_hash : NULL,
				      NULL);
	if (err) {
		registration_error(err,
				   "Role Process type compatibilities");
	}
	lol_info.version = RSBAC_RC_ROLE_TCIP_LIST_VERSION;
	lol_info.key = RSBAC_RC_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_rc_role_id_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_rc_type_id_t);
	lol_info.subdata_size = sizeof(rsbac_rc_rights_vector_t);
	lol_info.max_age = 0;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &role_tcip_handle, &lol_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				      RSBAC_LIST_REPLICATE |
				      RSBAC_LIST_DEF_DATA |
				      RSBAC_LIST_DEF_SUBDATA |
				      RSBAC_LIST_AUTO_HASH_RESIZE,
				      NULL,
				      NULL,
				      tcfd_get_conv, tcfd_get_subconv,
				      NULL, &def_tc,
				      RSBAC_RC_ROLE_TCIP_FILENAME,
				      RSBAC_AUTO_DEV,
				      nr_role_hashes,
				      (nr_role_hashes > 1) ? role_hash : NULL,
				      NULL);
	if (err) {
		registration_error(err, "Role IPC type compatibilities");
	}
	lol_info.version = RSBAC_RC_ROLE_TCSC_LIST_VERSION;
	lol_info.key = RSBAC_RC_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_rc_role_id_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_rc_type_id_t);
	lol_info.subdata_size = sizeof(rsbac_rc_rights_vector_t);
	lol_info.max_age = 0;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &role_tcsc_handle, &lol_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				      RSBAC_LIST_REPLICATE |
				      RSBAC_LIST_DEF_DATA |
				      RSBAC_LIST_DEF_SUBDATA |
				      RSBAC_LIST_AUTO_HASH_RESIZE,
				      NULL,
				      NULL,
				      tcfd_get_conv, tcfd_get_subconv,
				      NULL, &def_tc,
				      RSBAC_RC_ROLE_TCSC_FILENAME,
				      RSBAC_AUTO_DEV,
				      nr_role_hashes,
				      (nr_role_hashes > 1) ? role_hash : NULL,
				      NULL);
	if (err) {
		registration_error(err, "Role SCD type compatibilities");
	}
	lol_info.version = RSBAC_RC_ROLE_TCGR_LIST_VERSION;
	lol_info.key = RSBAC_RC_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_rc_role_id_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_rc_type_id_t);
	lol_info.subdata_size = sizeof(rsbac_rc_rights_vector_t);
	lol_info.max_age = 0;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &role_tcgr_handle, &lol_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				      RSBAC_LIST_REPLICATE |
				      RSBAC_LIST_DEF_DATA |
				      RSBAC_LIST_DEF_SUBDATA |
				      RSBAC_LIST_AUTO_HASH_RESIZE,
				      NULL,
				      NULL,
				      tcfd_get_conv, tcfd_get_subconv,
				      NULL, &def_tc,
				      RSBAC_RC_ROLE_TCGR_FILENAME,
				      RSBAC_AUTO_DEV,
				      nr_role_hashes,
				      (nr_role_hashes > 1) ? role_hash : NULL,
				      NULL);
	if (err) {
		registration_error(err, "Role Group type compatibilities");
	}
	lol_info.version = RSBAC_RC_ROLE_TCND_LIST_VERSION;
	lol_info.key = RSBAC_RC_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_rc_role_id_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_rc_type_id_t);
	lol_info.subdata_size = sizeof(rsbac_rc_rights_vector_t);
	lol_info.max_age = 0;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &role_tcnd_handle, &lol_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				      RSBAC_LIST_REPLICATE |
				      RSBAC_LIST_DEF_DATA |
				      RSBAC_LIST_DEF_SUBDATA |
				      RSBAC_LIST_AUTO_HASH_RESIZE,
				      NULL,
				      NULL,
				      tcfd_get_conv, tcfd_get_subconv,
				      NULL, &def_tc,
				      RSBAC_RC_ROLE_TCND_FILENAME,
				      RSBAC_AUTO_DEV,
				      nr_role_hashes,
				      (nr_role_hashes > 1) ? role_hash : NULL,
				      NULL);
	if (err) {
		registration_error(err,
				   "Role NETDEV type compatibilities");
	}
	lol_info.version = RSBAC_RC_ROLE_TCNT_LIST_VERSION;
	lol_info.key = RSBAC_RC_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_rc_role_id_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_rc_type_id_t);
	lol_info.subdata_size = sizeof(rsbac_rc_rights_vector_t);
	lol_info.max_age = 0;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &role_tcnt_handle, &lol_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				      RSBAC_LIST_REPLICATE |
				      RSBAC_LIST_DEF_DATA |
				      RSBAC_LIST_DEF_SUBDATA |
				      RSBAC_LIST_AUTO_HASH_RESIZE,
				      NULL,
				      NULL,
				      tcfd_get_conv, tcfd_get_subconv,
				      NULL, &def_tc,
				      RSBAC_RC_ROLE_TCNT_FILENAME,
				      RSBAC_AUTO_DEV,
				      nr_role_hashes,
				      (nr_role_hashes > 1) ? role_hash : NULL,
				      NULL);
	if (err) {
		registration_error(err,
				   "Role NETTEMP type compatibilities");
	}
	lol_info.version = RSBAC_RC_ROLE_TCNO_LIST_VERSION;
	lol_info.key = RSBAC_RC_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_rc_role_id_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_rc_type_id_t);
	lol_info.subdata_size = sizeof(rsbac_rc_rights_vector_t);
	lol_info.max_age = 0;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &role_tcno_handle, &lol_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				      RSBAC_LIST_REPLICATE |
				      RSBAC_LIST_DEF_DATA |
				      RSBAC_LIST_DEF_SUBDATA |
				      RSBAC_LIST_AUTO_HASH_RESIZE,
				      NULL,
				      NULL,
				      tcfd_get_conv, tcfd_get_subconv,
				      NULL, &def_tc,
				      RSBAC_RC_ROLE_TCNO_FILENAME,
				      RSBAC_AUTO_DEV,
				      nr_role_hashes,
				      (nr_role_hashes > 1) ? role_hash : NULL,
				      NULL);
	if (err) {
		registration_error(err,
				   "Role NETOBJ type compatibilities");
	}

	/* Create default role settings, if none there */
	if (!rsbac_no_defaults && !rsbac_list_count(role_handle)) {
		create_def_roles();
		create_def_roles2();
	}

	list_info.version = RSBAC_RC_TYPE_FD_LIST_VERSION;
	list_info.key = RSBAC_RC_LIST_KEY;
	list_info.desc_size = sizeof(rsbac_rc_type_id_t);
	list_info.data_size = sizeof(struct rsbac_rc_type_fd_entry_t);
	list_info.max_age = 0;
	err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
				  &type_fd_handle, &list_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				  RSBAC_LIST_BACKUP |
#endif
				  RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				  RSBAC_LIST_REPLICATE |
				  RSBAC_LIST_AUTO_HASH_RESIZE,
				  NULL, NULL, NULL,
				  RSBAC_RC_TYPE_FD_FILENAME,
				  RSBAC_AUTO_DEV,
				  nr_type_hashes,
				  (nr_type_hashes > 1) ? type_hash : NULL,
				  NULL);
	if (err) {
		registration_error(err, "type FD");
	}
	if (!rsbac_no_defaults && !rsbac_list_count(type_fd_handle)) {
		rsbac_rc_type_id_t type;
		struct rsbac_rc_type_fd_entry_t entry;

		type = RSBAC_RC_GENERAL_TYPE;
		strcpy(entry.name, "General FD");
		entry.need_secdel = 0;
		rsbac_list_add(type_fd_handle, &type, &entry);
		type = RSBAC_RC_SEC_TYPE;
		strcpy(entry.name, "Security FD");
		entry.need_secdel = 0;
		rsbac_list_add(type_fd_handle, &type, &entry);
		type = RSBAC_RC_SYS_TYPE;
		strcpy(entry.name, "System FD");
		entry.need_secdel = 0;
		rsbac_list_add(type_fd_handle, &type, &entry);
	}
	list_info.version = RSBAC_RC_TYPE_DEV_LIST_VERSION;
	list_info.key = RSBAC_RC_LIST_KEY;
	list_info.desc_size = sizeof(rsbac_rc_type_id_t);
	list_info.data_size = RSBAC_RC_NAME_LEN;
	list_info.max_age = 0;
	err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
				  &type_dev_handle, &list_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				  RSBAC_LIST_BACKUP |
#endif
				  RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				  RSBAC_LIST_REPLICATE |
				  RSBAC_LIST_AUTO_HASH_RESIZE,
				  NULL, NULL, NULL,
				  RSBAC_RC_TYPE_DEV_FILENAME,
				  RSBAC_AUTO_DEV,
				  nr_type_hashes,
				  (nr_type_hashes > 1) ? type_hash : NULL,
				  NULL);
	if (err) {
		registration_error(err, "type DEV");
	}
	if (!rsbac_no_defaults && !rsbac_list_count(type_dev_handle)) {
		rsbac_rc_type_id_t type;
		char name[RSBAC_RC_NAME_LEN];

		type = RSBAC_RC_GENERAL_TYPE;
		strcpy(name, "General Device");
		rsbac_list_add(type_dev_handle, &type, name);
		type = RSBAC_RC_SEC_TYPE;
		strcpy(name, "Security Device");
		rsbac_list_add(type_dev_handle, &type, name);
		type = RSBAC_RC_SYS_TYPE;
		strcpy(name, "System Device");
		rsbac_list_add(type_dev_handle, &type, &name);
	}
	list_info.version = RSBAC_RC_TYPE_IPC_LIST_VERSION;
	list_info.key = RSBAC_RC_LIST_KEY;
	list_info.desc_size = sizeof(rsbac_rc_type_id_t);
	list_info.data_size = RSBAC_RC_NAME_LEN;
	list_info.max_age = 0;
	err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
				  &type_ipc_handle, &list_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				  RSBAC_LIST_BACKUP |
#endif
				  RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				  RSBAC_LIST_REPLICATE |
				  RSBAC_LIST_AUTO_HASH_RESIZE,
				  NULL, NULL, NULL,
				  RSBAC_RC_TYPE_IPC_FILENAME,
				  RSBAC_AUTO_DEV,
				  nr_type_hashes,
				  (nr_type_hashes > 1) ? type_hash : NULL,
				  NULL);
	if (err) {
		registration_error(err, "type IPC");
	}
	if (!rsbac_no_defaults && !rsbac_list_count(type_ipc_handle)) {
		rsbac_rc_type_id_t type;
		char name[RSBAC_RC_NAME_LEN];

		type = RSBAC_RC_GENERAL_TYPE;
		strcpy(name, "General IPC");
		rsbac_list_add(type_ipc_handle, &type, name);
		type = RSBAC_RC_SEC_TYPE;
		strcpy(name, "Security IPC");
		rsbac_list_add(type_ipc_handle, &type, name);
		type = RSBAC_RC_SYS_TYPE;
		strcpy(name, "System IPC");
		rsbac_list_add(type_ipc_handle, &type, &name);
	}
	list_info.version = RSBAC_RC_TYPE_USER_LIST_VERSION;
	list_info.key = RSBAC_RC_LIST_KEY;
	list_info.desc_size = sizeof(rsbac_rc_type_id_t);
	list_info.data_size = RSBAC_RC_NAME_LEN;
	list_info.max_age = 0;
	err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
				  &type_user_handle, &list_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				  RSBAC_LIST_BACKUP |
#endif
				  RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				  RSBAC_LIST_REPLICATE |
				  RSBAC_LIST_AUTO_HASH_RESIZE,
				  NULL, NULL, NULL,
				  RSBAC_RC_TYPE_USER_FILENAME,
				  RSBAC_AUTO_DEV,
				  nr_type_hashes,
				  (nr_type_hashes > 1) ? type_hash : NULL,
				  NULL);
	if (err) {
		registration_error(err, "type USER");
	}
	if (!rsbac_no_defaults && !rsbac_list_count(type_user_handle)) {
		rsbac_rc_type_id_t type;
		char name[RSBAC_RC_NAME_LEN];

		type = RSBAC_RC_GENERAL_TYPE;
		strcpy(name, "General User");
		rsbac_list_add(type_user_handle, &type, name);
		type = RSBAC_RC_SEC_TYPE;
		strcpy(name, "Security User");
		rsbac_list_add(type_user_handle, &type, name);
		type = RSBAC_RC_SYS_TYPE;
		strcpy(name, "System User");
		rsbac_list_add(type_user_handle, &type, &name);
	}
	list_info.version = RSBAC_RC_TYPE_PROCESS_LIST_VERSION;
	list_info.key = RSBAC_RC_LIST_KEY;
	list_info.desc_size = sizeof(rsbac_rc_type_id_t);
	list_info.data_size = RSBAC_RC_NAME_LEN;
	list_info.max_age = 0;
	err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
				  &type_process_handle, &list_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				  RSBAC_LIST_BACKUP |
#endif
				  RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				  RSBAC_LIST_REPLICATE |
				  RSBAC_LIST_AUTO_HASH_RESIZE,
				  NULL, NULL, NULL,
				  RSBAC_RC_TYPE_PROCESS_FILENAME,
				  RSBAC_AUTO_DEV,
				  nr_type_hashes,
				  (nr_type_hashes > 1) ? type_hash : NULL,
				  NULL);
	if (err) {
		registration_error(err, "type PROCESS");
	}
	if (!rsbac_no_defaults && !rsbac_list_count(type_process_handle)) {
		rsbac_rc_type_id_t type;
		char name[RSBAC_RC_NAME_LEN];

		type = RSBAC_RC_GENERAL_TYPE;
		strcpy(name, "General Process");
		rsbac_list_add(type_process_handle, &type, name);
		type = RSBAC_RC_SEC_TYPE;
		strcpy(name, "Security Proc");
		rsbac_list_add(type_process_handle, &type, name);
		type = RSBAC_RC_SYS_TYPE;
		strcpy(name, "System Process");
		rsbac_list_add(type_process_handle, &type, &name);
	}
	if (!rsbac_no_defaults) {
		rsbac_rc_type_id_t type =
		    CONFIG_RSBAC_RC_KERNEL_PROCESS_TYPE;

		if (!rsbac_list_exist(type_process_handle, &type)) {
			char name[RSBAC_RC_NAME_LEN];
			rsbac_rc_role_id_t *role_array;
			u_long count;
			rsbac_rc_rights_vector_t rights;

			strcpy(name, "Kernel Process");
			rsbac_list_add(type_process_handle, &type, &name);

			/* Set type compatibilities for the new type for all roles */
			rights = RSBAC_READ_WRITE_REQUEST_VECTOR
			    & RSBAC_PROCESS_REQUEST_VECTOR;

			count =
			    rsbac_list_lol_get_all_desc(role_tcpr_handle,
							(void **)
							&role_array);
			if (count > 0) {
				u_int i;

				for (i = 0; i < count; i++) {
					if (!rsbac_list_lol_subexist
					    (role_tcpr_handle,
					     &role_array[i], &type))
						rsbac_list_lol_subadd
						    (role_tcpr_handle,
						     &role_array[i], &type,
						     &rights);
				}
				rsbac_kfree(role_array);
			}
		}
	}
	list_info.version = RSBAC_RC_TYPE_GROUP_LIST_VERSION;
	list_info.key = RSBAC_RC_LIST_KEY;
	list_info.desc_size = sizeof(rsbac_rc_type_id_t);
	list_info.data_size = RSBAC_RC_NAME_LEN;
	list_info.max_age = 0;
	err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
				  &type_group_handle, &list_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				  RSBAC_LIST_BACKUP |
#endif
				  RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				  RSBAC_LIST_REPLICATE |
				  RSBAC_LIST_AUTO_HASH_RESIZE,
				  NULL, NULL, NULL,
				  RSBAC_RC_TYPE_GROUP_FILENAME,
				  RSBAC_AUTO_DEV,
				  nr_type_hashes,
				  (nr_type_hashes > 1) ? type_hash : NULL,
				  NULL);
	if (err) {
		registration_error(err, "type GROUP");
	}
	if (!rsbac_no_defaults && !rsbac_list_count(type_group_handle)) {
		rsbac_rc_type_id_t type;
		char name[RSBAC_RC_NAME_LEN];

		type = RSBAC_RC_GENERAL_TYPE;
		strcpy(name, "General Group");
		rsbac_list_add(type_group_handle, &type, name);
	}
	list_info.version = RSBAC_RC_TYPE_NETDEV_LIST_VERSION;
	list_info.key = RSBAC_RC_LIST_KEY;
	list_info.desc_size = sizeof(rsbac_rc_type_id_t);
	list_info.data_size = RSBAC_RC_NAME_LEN;
	list_info.max_age = 0;
	err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
				  &type_netdev_handle, &list_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				  RSBAC_LIST_BACKUP |
#endif
				  RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				  RSBAC_LIST_REPLICATE |
				  RSBAC_LIST_AUTO_HASH_RESIZE,
				  NULL, NULL, NULL,
				  RSBAC_RC_TYPE_NETDEV_FILENAME,
				  RSBAC_AUTO_DEV,
				  nr_type_hashes,
				  (nr_type_hashes > 1) ? type_hash : NULL,
				  NULL);
	if (err) {
		registration_error(err, "type NETDEV");
	}
	if (!rsbac_no_defaults && !rsbac_list_count(type_netdev_handle)) {
		rsbac_rc_type_id_t type;
		char name[RSBAC_RC_NAME_LEN];

		type = RSBAC_RC_GENERAL_TYPE;
		strcpy(name, "General NETDEV");
		rsbac_list_add(type_netdev_handle, &type, name);
		type = RSBAC_RC_SEC_TYPE;
		strcpy(name, "Security NETDEV");
		rsbac_list_add(type_netdev_handle, &type, name);
		type = RSBAC_RC_SYS_TYPE;
		strcpy(name, "System NETDEV");
		rsbac_list_add(type_netdev_handle, &type, &name);
	}
	list_info.version = RSBAC_RC_TYPE_NETTEMP_LIST_VERSION;
	list_info.key = RSBAC_RC_LIST_KEY;
	list_info.desc_size = sizeof(rsbac_rc_type_id_t);
	list_info.data_size = RSBAC_RC_NAME_LEN;
	list_info.max_age = 0;
	err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
				  &type_nettemp_handle, &list_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				  RSBAC_LIST_BACKUP |
#endif
				  RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				  RSBAC_LIST_REPLICATE |
				  RSBAC_LIST_AUTO_HASH_RESIZE,
				  NULL, NULL, NULL,
				  RSBAC_RC_TYPE_NETTEMP_FILENAME,
				  RSBAC_AUTO_DEV,
				  nr_type_hashes,
				  (nr_type_hashes > 1) ? type_hash : NULL,
				  NULL);
	if (err) {
		registration_error(err, "type NETTEMP");
	}
	if (!rsbac_no_defaults && !rsbac_list_count(type_nettemp_handle)) {
		rsbac_rc_type_id_t type;
		char name[RSBAC_RC_NAME_LEN];

		type = RSBAC_RC_GENERAL_TYPE;
		strcpy(name, "General NETTEMP");
		rsbac_list_add(type_nettemp_handle, &type, name);
		type = RSBAC_RC_SEC_TYPE;
		strcpy(name, "Securit NETTEMP");
		rsbac_list_add(type_nettemp_handle, &type, name);
		type = RSBAC_RC_SYS_TYPE;
		strcpy(name, "System NETTEMP");
		rsbac_list_add(type_nettemp_handle, &type, &name);
	}
	list_info.version = RSBAC_RC_TYPE_NETOBJ_LIST_VERSION;
	list_info.key = RSBAC_RC_LIST_KEY;
	list_info.desc_size = sizeof(rsbac_rc_type_id_t);
	list_info.data_size = RSBAC_RC_NAME_LEN;
	list_info.max_age = 0;
	err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
				  &type_netobj_handle, &list_info,
#if defined(CONFIG_RSBAC_RC_BACKUP)
				  RSBAC_LIST_BACKUP |
#endif
				  RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
				  RSBAC_LIST_REPLICATE |
				  RSBAC_LIST_AUTO_HASH_RESIZE,
				  NULL, NULL, NULL,
				  RSBAC_RC_TYPE_NETOBJ_FILENAME,
				  RSBAC_AUTO_DEV,
				  nr_type_hashes,
				  (nr_type_hashes > 1) ? type_hash : NULL,
				  NULL);
	if (err) {
		registration_error(err, "type NETOBJ");
	}
	if (!rsbac_no_defaults && !rsbac_list_count(type_netobj_handle)) {
		rsbac_rc_type_id_t type;
		char name[RSBAC_RC_NAME_LEN];

		type = RSBAC_RC_GENERAL_TYPE;
		strcpy(name, "General NETOBJ");
		rsbac_list_add(type_netobj_handle, &type, name);
		type = RSBAC_RC_SEC_TYPE;
		strcpy(name, "Security NETOBJ");
		rsbac_list_add(type_netobj_handle, &type, name);
		type = RSBAC_RC_SYS_TYPE;
		strcpy(name, "System NETOBJ");
		rsbac_list_add(type_netobj_handle, &type, &name);
	}
	rsbac_pr_debug(stack, "free stack before adding proc entry: %lu\n",
		       rsbac_stack_free_space());
#if defined(CONFIG_RSBAC_PROC)
	stats_rc = proc_create("stats_rc",
					S_IFREG | S_IRUGO,
					proc_rsbac_root_p, &stats_rc_proc_fops);
#endif
	rsbac_pr_debug(stack, "final free stack: %lu\n",
		       rsbac_stack_free_space());
	rsbac_pr_debug(ds_rc, "Ready.\n");
	return (err);
}

/***************************************************/
/* We also need some status information...         */

int rsbac_stats_rc(void)
{
	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_stats_rc(): RSBAC not initialized\n");
		return (-RSBAC_ENOTINITIALIZED);
	}

	rsbac_printk(KERN_INFO "Role entry size is %u, %lu entries used\n",
		     sizeof(struct rsbac_rc_role_entry_t),
		     rsbac_list_count(role_handle));

	rsbac_printk(KERN_INFO "Used type entries: fd: %lu, dev: %lu, ipc: %lu, user: %lu, process: %lu, group: %lu, netdev: %lu, nettemp: %lu, netobj: %lu\n",
		     rsbac_list_count(type_fd_handle),
		     rsbac_list_count(type_dev_handle),
		     rsbac_list_count(type_ipc_handle),
		     rsbac_list_count(type_user_handle),
		     rsbac_list_count(type_process_handle),
		     rsbac_list_count(type_group_handle),
		     rsbac_list_count(type_netdev_handle),
		     rsbac_list_count(type_nettemp_handle),
		     rsbac_list_count(type_netobj_handle));
	return 0;
}

/************************************************* */
/*               Access functions                  */
/************************************************* */

/* Find the boot role */
#ifdef CONFIG_RSBAC_INIT_DELAY
int rsbac_rc_get_boot_role(rsbac_rc_role_id_t * role_p)
#else
int __init rsbac_rc_get_boot_role(rsbac_rc_role_id_t * role_p)
#endif
{
	/* Try to find role marked as boot role */
	if (rsbac_list_get_desc(role_handle,
				role_p, role_p, rsbac_rc_role_compare_data)
	    ) {			/* none found */
		return -RSBAC_ENOTFOUND;
	}
	return 0;
}

/* Checking whether role exists */
rsbac_boolean_t rsbac_rc_role_exists(rsbac_list_ta_number_t ta_number,
				     rsbac_rc_role_id_t role)
{
	return rsbac_ta_list_exist(ta_number, role_handle, &role);
}

rsbac_boolean_t rsbac_rc_type_exists(rsbac_list_ta_number_t ta_number,
				     enum rsbac_target_t target,
				     rsbac_rc_type_id_t type)
{
	switch (target) {
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_FD:
		return rsbac_ta_list_exist(ta_number, type_fd_handle,
					   &type);
	case T_DEV:
		return rsbac_ta_list_exist(ta_number, type_dev_handle,
					   &type);
	case T_IPC:
		return rsbac_ta_list_exist(ta_number, type_ipc_handle,
					   &type);
	case T_USER:
		return rsbac_ta_list_exist(ta_number, type_user_handle,
					   &type);
	case T_PROCESS:
		return rsbac_ta_list_exist(ta_number, type_process_handle,
					   &type);
	case T_NETDEV:
		return rsbac_ta_list_exist(ta_number, type_netdev_handle,
					   &type);
	case T_NETTEMP:
		return rsbac_ta_list_exist(ta_number, type_nettemp_handle,
					   &type);
	case T_NETOBJ:
		return rsbac_ta_list_exist(ta_number, type_netobj_handle,
					   &type);
	case T_SCD:
		if (type < ST_none)
			return TRUE;
		else
			return FALSE;
	default:
		return FALSE;
	}
}

/* Invalid parameter combinations return an error. */

int rsbac_rc_copy_role(rsbac_list_ta_number_t ta_number,
		       rsbac_rc_role_id_t from_role,
		       rsbac_rc_role_id_t to_role)
{
	struct rsbac_rc_role_entry_t entry;
	rsbac_rc_role_id_t *role_array;
	char *item_array;
	long count;
	u_long i;
	int err;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_rc_copy_role(): RSBAC not initialized\n");
		return (-RSBAC_ENOTINITIALIZED);
	}
	if ((from_role > RC_role_max_value)
	    || (to_role > RC_role_max_value)
	    || (to_role == from_role)
	    )
		return (-RSBAC_EINVALIDTARGET);

	/* copy */
	err =
	    rsbac_ta_list_get_data_ttl(ta_number, role_handle, NULL,
				       &from_role, &entry);
	if (err)
		return err;
	err =
	    rsbac_ta_list_add_ttl(ta_number, role_handle, 0, &to_role,
				  &entry);
	if (err)
		return err;

	rsbac_ta_list_lol_remove(ta_number, role_rc_handle, &to_role);
	count =
	    rsbac_ta_list_lol_get_all_subdesc_ttl(ta_number,
						  role_rc_handle,
						  &from_role,
						  (void **) &role_array,
						  NULL);
	if (count > 0) {
		for (i = 0; i < count; i++)
			rsbac_ta_list_lol_subadd_ttl(ta_number,
						     role_rc_handle, 0,
						     &to_role,
						     &role_array[i], 0);
		rsbac_kfree(role_array);
	}
	rsbac_ta_list_lol_remove(ta_number, role_adr_handle, &to_role);
	count =
	    rsbac_ta_list_lol_get_all_subdesc_ttl(ta_number,
						  role_adr_handle,
						  &from_role,
						  (void **) &role_array,
						  NULL);
	if (count > 0) {
		for (i = 0; i < count; i++)
			rsbac_ta_list_lol_subadd_ttl(ta_number,
						     role_adr_handle, 0,
						     &to_role,
						     &role_array[i], 0);
		rsbac_kfree(role_array);
	}
	rsbac_ta_list_lol_remove(ta_number, role_asr_handle, &to_role);
	count =
	    rsbac_ta_list_lol_get_all_subdesc_ttl(ta_number,
						  role_asr_handle,
						  &from_role,
						  (void **) &role_array,
						  NULL);
	if (count > 0) {
		for (i = 0; i < count; i++)
			rsbac_ta_list_lol_subadd_ttl(ta_number,
						     role_asr_handle, 0,
						     &to_role,
						     &role_array[i], 0);
		rsbac_kfree(role_array);
	}
	rsbac_ta_list_lol_remove(ta_number, role_dfdc_handle, &to_role);
	count =
	    rsbac_ta_list_lol_get_all_subitems_ttl(ta_number,
						   role_dfdc_handle,
						   &from_role,
						   (void **) &item_array,
						   NULL);
	if (count > 0) {
		char *tmp = item_array;
		int size =
		    rsbac_list_lol_get_subitem_size(role_dfdc_handle);

		for (i = 0; i < count; i++) {
			rsbac_ta_list_lol_subadd_ttl(ta_number,
						     role_dfdc_handle, 0,
						     &to_role, tmp,
						     tmp +
						     sizeof
						     (rsbac_rc_role_id_t));
			tmp += size;
		}
		rsbac_kfree(item_array);
	}
	rsbac_ta_list_lol_remove(ta_number, role_tcfd_handle, &to_role);
	count =
	    rsbac_ta_list_lol_get_all_subitems_ttl(ta_number,
						   role_tcfd_handle,
						   &from_role,
						   (void **) &item_array,
						   NULL);
	if (count > 0) {
		char *tmp = item_array;
		int size =
		    rsbac_list_lol_get_subitem_size(role_tcfd_handle);

		for (i = 0; i < count; i++) {
			rsbac_ta_list_lol_subadd_ttl(ta_number,
						     role_tcfd_handle, 0,
						     &to_role, tmp,
						     tmp +
						     sizeof
						     (rsbac_rc_role_id_t));
			tmp += size;
		}
		rsbac_kfree(item_array);
	}
	rsbac_ta_list_lol_remove(ta_number, role_tcdv_handle, &to_role);
	count =
	    rsbac_ta_list_lol_get_all_subitems_ttl(ta_number,
						   role_tcdv_handle,
						   &from_role,
						   (void **) &item_array,
						   NULL);
	if (count > 0) {
		char *tmp = item_array;
		int size =
		    rsbac_list_lol_get_subitem_size(role_tcdv_handle);

		for (i = 0; i < count; i++) {
			rsbac_ta_list_lol_subadd_ttl(ta_number,
						     role_tcdv_handle, 0,
						     &to_role, tmp,
						     tmp +
						     sizeof
						     (rsbac_rc_role_id_t));
			tmp += size;
		}
		rsbac_kfree(item_array);
	}
	rsbac_ta_list_lol_remove(ta_number, role_tcus_handle, &to_role);
	count =
	    rsbac_ta_list_lol_get_all_subitems_ttl(ta_number,
						   role_tcus_handle,
						   &from_role,
						   (void **) &item_array,
						   NULL);
	if (count > 0) {
		char *tmp = item_array;
		int size =
		    rsbac_list_lol_get_subitem_size(role_tcus_handle);

		for (i = 0; i < count; i++) {
			rsbac_ta_list_lol_subadd_ttl(ta_number,
						     role_tcus_handle, 0,
						     &to_role, tmp,
						     tmp +
						     sizeof
						     (rsbac_rc_role_id_t));
			tmp += size;
		}
		rsbac_kfree(item_array);
	}
	rsbac_ta_list_lol_remove(ta_number, role_tcpr_handle, &to_role);
	count =
	    rsbac_ta_list_lol_get_all_subitems_ttl(ta_number,
						   role_tcpr_handle,
						   &from_role,
						   (void **) &item_array,
						   NULL);
	if (count > 0) {
		char *tmp = item_array;
		int size =
		    rsbac_list_lol_get_subitem_size(role_tcpr_handle);

		for (i = 0; i < count; i++) {
			rsbac_ta_list_lol_subadd_ttl(ta_number,
						     role_tcpr_handle, 0,
						     &to_role, tmp,
						     tmp +
						     sizeof
						     (rsbac_rc_role_id_t));
			tmp += size;
		}
		rsbac_kfree(item_array);
	}
	rsbac_ta_list_lol_remove(ta_number, role_tcip_handle, &to_role);
	count =
	    rsbac_ta_list_lol_get_all_subitems_ttl(ta_number,
						   role_tcip_handle,
						   &from_role,
						   (void **) &item_array,
						   NULL);
	if (count > 0) {
		char *tmp = item_array;
		int size =
		    rsbac_list_lol_get_subitem_size(role_tcip_handle);

		for (i = 0; i < count; i++) {
			rsbac_ta_list_lol_subadd_ttl(ta_number,
						     role_tcip_handle, 0,
						     &to_role, tmp,
						     tmp +
						     sizeof
						     (rsbac_rc_role_id_t));
			tmp += size;
		}
		rsbac_kfree(item_array);
	}
	rsbac_ta_list_lol_remove(ta_number, role_tcsc_handle, &to_role);
	count =
	    rsbac_ta_list_lol_get_all_subitems_ttl(ta_number,
						   role_tcsc_handle,
						   &from_role,
						   (void **) &item_array,
						   NULL);
	if (count > 0) {
		char *tmp = item_array;
		int size =
		    rsbac_list_lol_get_subitem_size(role_tcsc_handle);

		for (i = 0; i < count; i++) {
			rsbac_ta_list_lol_subadd_ttl(ta_number,
						     role_tcsc_handle, 0,
						     &to_role, tmp,
						     tmp +
						     sizeof
						     (rsbac_rc_role_id_t));
			tmp += size;
		}
		rsbac_kfree(item_array);
	}
	rsbac_ta_list_lol_remove(ta_number, role_tcgr_handle, &to_role);
	count =
	    rsbac_ta_list_lol_get_all_subitems_ttl(ta_number,
						   role_tcgr_handle,
						   &from_role,
						   (void **) &item_array,
						   NULL);
	if (count > 0) {
		char *tmp = item_array;
		int size =
		    rsbac_list_lol_get_subitem_size(role_tcgr_handle);

		for (i = 0; i < count; i++) {
			rsbac_ta_list_lol_subadd_ttl(ta_number,
						     role_tcgr_handle, 0,
						     &to_role, tmp,
						     tmp +
						     sizeof
						     (rsbac_rc_role_id_t));
			tmp += size;
		}
		rsbac_kfree(item_array);
	}
	rsbac_ta_list_lol_remove(ta_number, role_tcnd_handle, &to_role);
	count =
	    rsbac_ta_list_lol_get_all_subitems_ttl(ta_number,
						   role_tcnd_handle,
						   &from_role,
						   (void **) &item_array,
						   NULL);
	if (count > 0) {
		char *tmp = item_array;
		int size =
		    rsbac_list_lol_get_subitem_size(role_tcnd_handle);

		for (i = 0; i < count; i++) {
			rsbac_ta_list_lol_subadd_ttl(ta_number,
						     role_tcnd_handle, 0,
						     &to_role, tmp,
						     tmp +
						     sizeof
						     (rsbac_rc_role_id_t));
			tmp += size;
		}
		rsbac_kfree(item_array);
	}
	rsbac_ta_list_lol_remove(ta_number, role_tcnt_handle, &to_role);
	count =
	    rsbac_ta_list_lol_get_all_subitems_ttl(ta_number,
						   role_tcnt_handle,
						   &from_role,
						   (void **) &item_array,
						   NULL);
	if (count > 0) {
		char *tmp = item_array;
		int size =
		    rsbac_list_lol_get_subitem_size(role_tcnt_handle);

		for (i = 0; i < count; i++) {
			rsbac_ta_list_lol_subadd_ttl(ta_number,
						     role_tcnt_handle, 0,
						     &to_role, tmp,
						     tmp +
						     sizeof
						     (rsbac_rc_role_id_t));
			tmp += size;
		}
		rsbac_kfree(item_array);
	}
	rsbac_ta_list_lol_remove(ta_number, role_tcno_handle, &to_role);
	count =
	    rsbac_ta_list_lol_get_all_subitems_ttl(ta_number,
						   role_tcno_handle,
						   &from_role,
						   (void **) &item_array,
						   NULL);
	if (count > 0) {
		char *tmp = item_array;
		int size =
		    rsbac_list_lol_get_subitem_size(role_tcno_handle);

		for (i = 0; i < count; i++) {
			rsbac_ta_list_lol_subadd_ttl(ta_number,
						     role_tcno_handle, 0,
						     &to_role, tmp,
						     tmp +
						     sizeof
						     (rsbac_rc_role_id_t));
			tmp += size;
		}
		rsbac_kfree(item_array);
	}
	return 0;
}

int rsbac_rc_copy_type(rsbac_list_ta_number_t ta_number,
		       enum rsbac_target_t target,
		       rsbac_rc_type_id_t from_type,
		       rsbac_rc_type_id_t to_type)
{
	rsbac_rc_role_id_t *role_array;
	rsbac_list_handle_t i_type_handle = NULL;
	rsbac_list_handle_t i_comp_handle = NULL;
	struct rsbac_rc_type_fd_entry_t type_fd_entry;
	char type_name[RSBAC_RC_NAME_LEN];
	long count;
	rsbac_time_t ttl;
	u_long i;
	int err;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_rc_copy_type(): RSBAC not initialized\n");
		return (-RSBAC_ENOTINITIALIZED);
	}
	if ((from_type > RC_type_max_value)
	    || (to_type > RC_type_max_value)
	    || (to_type == from_type)
	    )
		return (-RSBAC_EINVALIDTARGET);

	switch (target) {
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_FD:
		i_type_handle = type_fd_handle;
		i_comp_handle = role_tcfd_handle;
		break;
	case T_DEV:
		i_type_handle = type_dev_handle;
		i_comp_handle = role_tcdv_handle;
		break;
	case T_USER:
		i_type_handle = type_user_handle;
		i_comp_handle = role_tcus_handle;
		break;
	case T_PROCESS:
		i_type_handle = type_process_handle;
		i_comp_handle = role_tcpr_handle;
		break;
	case T_IPC:
		i_type_handle = type_ipc_handle;
		i_comp_handle = role_tcip_handle;
		break;
	case T_GROUP:
		i_type_handle = type_group_handle;
		i_comp_handle = role_tcgr_handle;
		break;
	case T_NETDEV:
		i_type_handle = type_netdev_handle;
		i_comp_handle = role_tcnd_handle;
		break;
	case T_NETTEMP:
		i_type_handle = type_nettemp_handle;
		i_comp_handle = role_tcnt_handle;
		break;
	case T_NETOBJ:
		i_type_handle = type_netobj_handle;
		i_comp_handle = role_tcno_handle;
		break;

	default:
		return -RSBAC_EINVALIDTARGET;
	}

	/* copy */
	if (i_type_handle == type_fd_handle) {
		err =
		    rsbac_ta_list_get_data_ttl(ta_number, i_type_handle,
					       &ttl, &from_type,
					       &type_fd_entry);
		if (err)
			return err;
		err =
		    rsbac_ta_list_add_ttl(ta_number, i_type_handle, ttl,
					  &to_type, &type_fd_entry);
		if (err)
			return err;
	} else {
		err =
		    rsbac_ta_list_get_data_ttl(ta_number, i_type_handle,
					       NULL, &from_type,
					       &type_name);
		if (err)
			return err;
		err =
		    rsbac_ta_list_add_ttl(ta_number, i_type_handle, 0,
					  &to_type, &type_name);
		if (err)
			return err;
	}

	err =
	    rsbac_ta_list_lol_subremove_from_all(ta_number, i_comp_handle,
						 &to_type);
	if (err)
		return err;

	count = rsbac_ta_list_get_all_desc(ta_number, role_handle,
					   (void **) &role_array);
	if (count > 0) {
		rsbac_rc_rights_vector_t rights;

		for (i = 0; i < count; i++) {
			err = rsbac_ta_list_lol_get_subdata_ttl(ta_number,
								i_comp_handle,
								&ttl,
								&role_array
								[i],
								&from_type,
								&rights);
			if (!err)
				err =
				    rsbac_ta_list_lol_subadd_ttl(ta_number,
								 i_comp_handle,
								 ttl,
								 &role_array
								 [i],
								 &to_type,
								 &rights);
		}
		rsbac_kfree(role_array);
	}
	return 0;
}


/* Getting values */
int rsbac_rc_get_item(rsbac_list_ta_number_t ta_number,
		      enum rsbac_rc_target_t target,
		      union rsbac_rc_target_id_t tid,
		      union rsbac_rc_target_id_t subtid,
		      enum rsbac_rc_item_t item,
		      union rsbac_rc_item_value_t *value_p,
		      rsbac_time_t * ttl_p)
{
	int err = 0;
	struct rsbac_rc_role_entry_t role_entry;
	struct rsbac_rc_type_fd_entry_t type_fd_entry;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_rc_get_item(): RSBAC not initialized\n");
		return (-RSBAC_ENOTINITIALIZED);
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_rc_get_item(): called from interrupt!\n");
	}
	if (ttl_p)
		*ttl_p = 0;
	switch (target) {
	case RT_ROLE:
		if (tid.role > RC_role_max_value)
			return (-RSBAC_EINVALIDTARGET);
/*
		rsbac_pr_debug(ds_rc, "getting role item value\n");
*/
		switch (item) {
		case RI_role_comp:
			if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							       role_rc_handle,
							       ttl_p,
							       &tid.role,
							       &subtid.
							       role, NULL))
				value_p->comp = TRUE;
			else
				value_p->comp = FALSE;
			return 0;
		case RI_admin_roles:
			if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							       role_adr_handle,
							       ttl_p,
							       &tid.role,
							       &subtid.
							       role, NULL))
				value_p->comp = TRUE;
			else
				value_p->comp = FALSE;
			return 0;
		case RI_assign_roles:
			if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							       role_asr_handle,
							       ttl_p,
							       &tid.role,
							       &subtid.
							       role, NULL))
				value_p->comp = TRUE;
			else
				value_p->comp = FALSE;
			return 0;
		case RI_type_comp_fd:
			if (rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							      role_tcfd_handle,
							      ttl_p,
							      &tid.role,
							      &subtid.type,
							      &value_p->
							      rights)) {
				value_p->rights =
				    RSBAC_RC_DEFAULT_RIGHTS_VECTOR;
				if (ttl_p)
					*ttl_p = 0;
			}
			return 0;
		case RI_type_comp_dev:
			if (rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							      role_tcdv_handle,
							      ttl_p,
							      &tid.role,
							      &subtid.type,
							      &value_p->
							      rights)) {
				value_p->rights =
				    RSBAC_RC_DEFAULT_RIGHTS_VECTOR;
				if (ttl_p)
					*ttl_p = 0;
			}
			return 0;
		case RI_type_comp_user:
			if (rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							      role_tcus_handle,
							      ttl_p,
							      &tid.role,
							      &subtid.type,
							      &value_p->
							      rights)) {
				value_p->rights =
				    RSBAC_RC_DEFAULT_RIGHTS_VECTOR;
				if (ttl_p)
					*ttl_p = 0;
			}
			return 0;
		case RI_type_comp_process:
			if (rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							      role_tcpr_handle,
							      ttl_p,
							      &tid.role,
							      &subtid.type,
							      &value_p->
							      rights)) {
				value_p->rights =
				    RSBAC_RC_DEFAULT_RIGHTS_VECTOR;
				if (ttl_p)
					*ttl_p = 0;
			}
			return 0;
		case RI_type_comp_ipc:
			if (rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							      role_tcip_handle,
							      ttl_p,
							      &tid.role,
							      &subtid.type,
							      &value_p->
							      rights)) {
				value_p->rights =
				    RSBAC_RC_DEFAULT_RIGHTS_VECTOR;
				if (ttl_p)
					*ttl_p = 0;
			}
			return 0;
		case RI_type_comp_scd:
			if (rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							      role_tcsc_handle,
							      ttl_p,
							      &tid.role,
							      &subtid.type,
							      &value_p->
							      rights)) {
				value_p->rights =
				    RSBAC_RC_DEFAULT_RIGHTS_VECTOR;
				if (ttl_p)
					*ttl_p = 0;
			}
			return 0;
		case RI_type_comp_group:
			if (rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							      role_tcgr_handle,
							      ttl_p,
							      &tid.role,
							      &subtid.type,
							      &value_p->
							      rights)) {
				value_p->rights =
				    RSBAC_RC_DEFAULT_RIGHTS_VECTOR;
				if (ttl_p)
					*ttl_p = 0;
			}
			return 0;
		case RI_type_comp_netdev:
			if (rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							      role_tcnd_handle,
							      ttl_p,
							      &tid.role,
							      &subtid.type,
							      &value_p->
							      rights)) {
				value_p->rights =
				    RSBAC_RC_DEFAULT_RIGHTS_VECTOR;
				if (ttl_p)
					*ttl_p = 0;
			}
			return 0;
		case RI_type_comp_nettemp:
			if (rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							      role_tcnt_handle,
							      ttl_p,
							      &tid.role,
							      &subtid.type,
							      &value_p->
							      rights)) {
				value_p->rights =
				    RSBAC_RC_DEFAULT_RIGHTS_VECTOR;
				if (ttl_p)
					*ttl_p = 0;
			}
			return 0;
		case RI_type_comp_netobj:
			if (rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							      role_tcno_handle,
							      ttl_p,
							      &tid.role,
							      &subtid.type,
							      &value_p->
							      rights)) {
				value_p->rights =
				    RSBAC_RC_DEFAULT_RIGHTS_VECTOR;
				if (ttl_p)
					*ttl_p = 0;
			}
			return 0;
		case RI_admin_type:
			if (!
			    (err =
			     rsbac_ta_list_get_data_ttl(ta_number,
							role_handle, NULL,
							&tid.role,
							&role_entry)))
				value_p->admin_type =
				    role_entry.admin_type;
			return err;
		case RI_name:
			if (!
			    (err =
			     rsbac_ta_list_get_data_ttl(ta_number,
							role_handle, NULL,
							&tid.role,
							&role_entry))) {
				strncpy(value_p->name, role_entry.name,
					RSBAC_RC_NAME_LEN - 1);
				value_p->name[RSBAC_RC_NAME_LEN - 1] =
				    (char) 0;
			}
			return err;
		case RI_def_fd_create_type:
			if (!
			    (err =
			     rsbac_ta_list_get_data_ttl(ta_number,
							role_handle, NULL,
							&tid.role,
							&role_entry)))
				value_p->type_id =
				    role_entry.def_fd_create_type;
			return err;
		case RI_def_fd_ind_create_type:
			return rsbac_ta_list_lol_get_subdata_ttl(ta_number,
								 role_dfdc_handle,
								 ttl_p,
								 &tid.role,
								 &subtid.
								 type,
								 &value_p->
								 type_id);
		case RI_def_user_create_type:
			if (!
			    (err =
			     rsbac_ta_list_get_data_ttl(ta_number,
							role_handle, NULL,
							&tid.role,
							&role_entry)))
				value_p->type_id =
				    role_entry.def_user_create_type;
			return err;
		case RI_def_process_create_type:
			if (!
			    (err =
			     rsbac_ta_list_get_data_ttl(ta_number,
							role_handle, NULL,
							&tid.role,
							&role_entry)))
				value_p->type_id =
				    role_entry.def_process_create_type;
			return err;
		case RI_def_process_chown_type:
			if (!
			    (err =
			     rsbac_ta_list_get_data_ttl(ta_number,
							role_handle, NULL,
							&tid.role,
							&role_entry)))
				value_p->type_id =
				    role_entry.def_process_chown_type;
			return err;
		case RI_def_process_execute_type:
			if (!
			    (err =
			     rsbac_ta_list_get_data_ttl(ta_number,
							role_handle, NULL,
							&tid.role,
							&role_entry)))
				value_p->type_id =
				    role_entry.def_process_execute_type;
			return err;
		case RI_def_ipc_create_type:
			if (!
			    (err =
			     rsbac_ta_list_get_data_ttl(ta_number,
							role_handle, NULL,
							&tid.role,
							&role_entry)))
				value_p->type_id =
				    role_entry.def_ipc_create_type;
			return err;
		case RI_def_group_create_type:
			if (!
			    (err =
			     rsbac_ta_list_get_data_ttl(ta_number,
							role_handle, NULL,
							&tid.role,
							&role_entry)))
				value_p->type_id =
				    role_entry.def_group_create_type;
			return err;
		case RI_def_unixsock_create_type:
			if (!
			    (err =
			     rsbac_ta_list_get_data_ttl(ta_number,
							role_handle, NULL,
							&tid.role,
							&role_entry)))
				value_p->type_id =
				    role_entry.def_unixsock_create_type;
			return err;
		case RI_boot_role:
			if (!
			    (err =
			     rsbac_ta_list_get_data_ttl(ta_number,
							role_handle, NULL,
							&tid.role,
							&role_entry)))
				value_p->boot_role = role_entry.boot_role;
			return err;
		case RI_req_reauth:
			if (!
			    (err =
			     rsbac_ta_list_get_data_ttl(ta_number,
							role_handle, NULL,
							&tid.role,
							&role_entry)))
				value_p->req_reauth =
				    role_entry.req_reauth;
			return err;
		default:
			return -RSBAC_EINVALIDATTR;
		}
		/* return */
		return (err);
		break;

	case RT_TYPE:
		if (tid.type > RC_type_max_value)
			return (-RSBAC_EINVALIDTARGET);
/*
 		rsbac_pr_debug(ds_rc, "getting type item value\n");
*/
		switch (item) {
		case RI_type_fd_name:
			if (!
			    (err =
			     rsbac_ta_list_get_data_ttl(ta_number,
							type_fd_handle,
							NULL, &tid.type,
							&type_fd_entry))) {
				strncpy(value_p->name, type_fd_entry.name,
					RSBAC_RC_NAME_LEN - 1);
				value_p->name[RSBAC_RC_NAME_LEN - 1] =
				    (char) 0;
			}
			return err;
		case RI_type_fd_need_secdel:
			if (!
			    (err =
			     rsbac_ta_list_get_data_ttl(ta_number,
							type_fd_handle,
							NULL, &tid.type,
							&type_fd_entry))) {
				value_p->need_secdel =
				    type_fd_entry.need_secdel;
			}
			return err;
		case RI_type_dev_name:
			return rsbac_ta_list_get_data_ttl(ta_number,
							  type_dev_handle,
							  NULL, &tid.type,
							  value_p->name);
		case RI_type_ipc_name:
			return rsbac_ta_list_get_data_ttl(ta_number,
							  type_ipc_handle,
							  NULL, &tid.type,
							  value_p->name);
		case RI_type_user_name:
			return rsbac_ta_list_get_data_ttl(ta_number,
							  type_user_handle,
							  NULL, &tid.type,
							  value_p->name);
		case RI_type_process_name:
			return rsbac_ta_list_get_data_ttl(ta_number,
							  type_process_handle,
							  NULL, &tid.type,
							  value_p->name);
		case RI_type_group_name:
			return rsbac_ta_list_get_data_ttl(ta_number,
							  type_group_handle,
							  NULL, &tid.type,
							  value_p->name);
		case RI_type_netdev_name:
			return rsbac_ta_list_get_data_ttl(ta_number,
							  type_netdev_handle,
							  NULL, &tid.type,
							  value_p->name);
		case RI_type_nettemp_name:
			return rsbac_ta_list_get_data_ttl(ta_number,
							  type_nettemp_handle,
							  NULL, &tid.type,
							  value_p->name);
		case RI_type_netobj_name:
			return rsbac_ta_list_get_data_ttl(ta_number,
							  type_netobj_handle,
							  NULL, &tid.type,
							  value_p->name);
		case RI_type_scd_name:
			{
				char *tmp;

				tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
				if (!tmp)
					err = -RSBAC_ENOMEM;
				else {
					get_rc_scd_type_name(tmp,
							     tid.type);
					strncpy(value_p->name, tmp,
						RSBAC_RC_NAME_LEN - 1);
					value_p->name[RSBAC_RC_NAME_LEN -
						      1] = (char) 0;
					rsbac_kfree(tmp);
				}
				break;
			}
		default:
			err = -RSBAC_EINVALIDATTR;
		}
		/* and return */
		return (err);
		break;

		/* switch target: no valid target */
	default:
		err = -RSBAC_EINVALIDTARGET;
	}
	return err;
}				/* end of rsbac_rc_get_item() */

/* Checking role's compatibility */
rsbac_boolean_t rsbac_rc_check_comp(rsbac_rc_role_id_t role,
				    union rsbac_rc_target_id_t subtid,
				    enum rsbac_rc_item_t item,
				    enum rsbac_rc_special_rights_t right)
{
	rsbac_rc_rights_vector_t rights_vector;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_rc_check_comp(): RSBAC not initialized\n");
		return (-RSBAC_ENOTINITIALIZED);
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_rc_check_comp(): called from interrupt!\n");
	}
	if (role > RC_role_max_value)
		return FALSE;
/*
	rsbac_pr_debug(ds_rc, "checking role compatibility\n");
*/
	switch (item) {
	case RI_role_comp:
		return rsbac_list_lol_subexist(role_rc_handle, &role,
					       &subtid.role);
	case RI_admin_roles:
		return rsbac_list_lol_subexist(role_adr_handle, &role,
					       &subtid.role);
	case RI_assign_roles:
		return rsbac_list_lol_subexist(role_asr_handle, &role,
					       &subtid.role);
	case RI_type_comp_fd:
		if (!rsbac_list_lol_get_subdata
		    (role_tcfd_handle, &role, &subtid.type, &rights_vector)
		    && (rights_vector & RSBAC_RC_RIGHTS_VECTOR(right))
		    )
			return TRUE;
		else
			return FALSE;
	case RI_type_comp_dev:
		if (!rsbac_list_lol_get_subdata
		    (role_tcdv_handle, &role, &subtid.type, &rights_vector)
		    && (rights_vector & RSBAC_RC_RIGHTS_VECTOR(right))
		    )
			return TRUE;
		else
			return FALSE;
	case RI_type_comp_user:
		if (!rsbac_list_lol_get_subdata
		    (role_tcus_handle, &role, &subtid.type, &rights_vector)
		    && (rights_vector & RSBAC_RC_RIGHTS_VECTOR(right))
		    )
			return TRUE;
		else
			return FALSE;
	case RI_type_comp_process:
		if (!rsbac_list_lol_get_subdata
		    (role_tcpr_handle, &role, &subtid.type, &rights_vector)
		    && (rights_vector & RSBAC_RC_RIGHTS_VECTOR(right))
		    )
			return TRUE;
		else
			return FALSE;
	case RI_type_comp_ipc:
		if (!rsbac_list_lol_get_subdata
		    (role_tcip_handle, &role, &subtid.type, &rights_vector)
		    && (rights_vector & RSBAC_RC_RIGHTS_VECTOR(right))
		    )
			return TRUE;
		else
			return FALSE;
	case RI_type_comp_scd:
		if (!rsbac_list_lol_get_subdata
		    (role_tcsc_handle, &role, &subtid.type, &rights_vector)
		    && (rights_vector & RSBAC_RC_RIGHTS_VECTOR(right))
		    )
			return TRUE;
		else
			return FALSE;
	case RI_type_comp_group:
		if (!rsbac_list_lol_get_subdata
		    (role_tcgr_handle, &role, &subtid.type, &rights_vector)
		    && (rights_vector & RSBAC_RC_RIGHTS_VECTOR(right))
		    )
			return TRUE;
		else
			return FALSE;
	case RI_type_comp_netdev:
		if (!rsbac_list_lol_get_subdata
		    (role_tcnd_handle, &role, &subtid.type, &rights_vector)
		    && (rights_vector & RSBAC_RC_RIGHTS_VECTOR(right))
		    )
			return TRUE;
		else
			return FALSE;
	case RI_type_comp_nettemp:
		if (!rsbac_list_lol_get_subdata
		    (role_tcnt_handle, &role, &subtid.type, &rights_vector)
		    && (rights_vector & RSBAC_RC_RIGHTS_VECTOR(right))
		    )
			return TRUE;
		else
			return FALSE;
	case RI_type_comp_netobj:
		if (!rsbac_list_lol_get_subdata
		    (role_tcno_handle, &role, &subtid.type, &rights_vector)
		    && (rights_vector & RSBAC_RC_RIGHTS_VECTOR(right))
		    )
			return TRUE;
		else
			return FALSE;

	default:
		rsbac_printk(KERN_WARNING "rsbac_rc_check_comp(): called for invalid item %u\n",
			     item);
		return FALSE;
	}
}				/* end of rsbac_rc_check_comp() */

/* Get list of defined items. Returns number or negative error.
 * item is to distinguish type targets, use RI_type_xx_name */
int rsbac_rc_get_list(rsbac_list_ta_number_t ta_number,
		      enum rsbac_rc_target_t target,
		      union rsbac_rc_target_id_t tid,
		      enum rsbac_rc_item_t item,
		      __u32 ** array_pp, rsbac_time_t ** ttl_array_pp)
{
	int res;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_rc_get_list(): RSBAC not initialized\n");
		return (-RSBAC_ENOTINITIALIZED);
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_rc_get_list(): called from interrupt!\n");
	}
	if (ttl_array_pp)
		*ttl_array_pp = NULL;
	switch (target) {
	case RT_ROLE:
/*
		rsbac_pr_debug(ds_rc, "getting role list\n");
*/
		switch (item) {
		case RI_name:
			if (array_pp)
				return
				    rsbac_ta_list_get_all_desc(ta_number,
							       role_handle,
							       (void **)
							       array_pp);
			else
				return rsbac_ta_list_count(ta_number,
							   role_handle);
		case RI_role_comp:
			if (array_pp)
				res =
				    rsbac_ta_list_lol_get_all_subdesc_ttl
				    (ta_number, role_rc_handle, &tid.role,
				     (void **) array_pp, ttl_array_pp);
			else
				res =
				    rsbac_ta_list_lol_subcount(ta_number,
							       role_rc_handle,
							       &tid.role);
			if (res == -RSBAC_ENOTFOUND)
				return 0;
			else
				return res;
		case RI_admin_roles:
			if (array_pp)
				res =
				    rsbac_ta_list_lol_get_all_subdesc_ttl
				    (ta_number, role_adr_handle, &tid.role,
				     (void **) array_pp, ttl_array_pp);
			else
				res =
				    rsbac_ta_list_lol_subcount(ta_number,
							       role_adr_handle,
							       &tid.role);
			if (res == -RSBAC_ENOTFOUND)
				return 0;
			else
				return res;
		case RI_assign_roles:
			if (array_pp)
				res =
				    rsbac_ta_list_lol_get_all_subdesc_ttl
				    (ta_number, role_asr_handle, &tid.role,
				     (void **) array_pp, ttl_array_pp);
			else
				res =
				    rsbac_ta_list_lol_subcount(ta_number,
							       role_asr_handle,
							       &tid.role);
			if (res == -RSBAC_ENOTFOUND)
				return 0;
			else
				return res;
		case RI_def_fd_ind_create_type:
			if (array_pp)
				return
				    rsbac_ta_list_lol_get_all_subdesc_ttl
				    (ta_number, role_dfdc_handle,
				     &tid.role, (void **) array_pp,
				     ttl_array_pp);
			else
				return
				    rsbac_ta_list_lol_subcount(ta_number,
							       role_dfdc_handle,
							       &tid.role);
		case RI_type_comp_fd:
			if (array_pp)
				return
				    rsbac_ta_list_lol_get_all_subdesc_ttl
				    (ta_number, role_tcfd_handle,
				     &tid.role, (void **) array_pp,
				     ttl_array_pp);
			else
				return
				    rsbac_ta_list_lol_subcount(ta_number,
							       role_tcfd_handle,
							       &tid.role);
		case RI_type_comp_dev:
			if (array_pp)
				return
				    rsbac_ta_list_lol_get_all_subdesc_ttl
				    (ta_number, role_tcdv_handle,
				     &tid.role, (void **) array_pp,
				     ttl_array_pp);
			else
				return
				    rsbac_ta_list_lol_subcount(ta_number,
							       role_tcdv_handle,
							       &tid.role);
		case RI_type_comp_user:
			if (array_pp)
				return
				    rsbac_ta_list_lol_get_all_subdesc_ttl
				    (ta_number, role_tcus_handle,
				     &tid.role, (void **) array_pp,
				     ttl_array_pp);
			else
				return
				    rsbac_ta_list_lol_subcount(ta_number,
							       role_tcus_handle,
							       &tid.role);
		case RI_type_comp_process:
			if (array_pp)
				return
				    rsbac_ta_list_lol_get_all_subdesc_ttl
				    (ta_number, role_tcpr_handle,
				     &tid.role, (void **) array_pp,
				     ttl_array_pp);
			else
				return
				    rsbac_ta_list_lol_subcount(ta_number,
							       role_tcpr_handle,
							       &tid.role);
		case RI_type_comp_ipc:
			if (array_pp)
				return
				    rsbac_ta_list_lol_get_all_subdesc_ttl
				    (ta_number, role_tcip_handle,
				     &tid.role, (void **) array_pp,
				     ttl_array_pp);
			else
				return
				    rsbac_ta_list_lol_subcount(ta_number,
							       role_tcip_handle,
							       &tid.role);
		case RI_type_comp_scd:
			if (array_pp)
				return
				    rsbac_ta_list_lol_get_all_subdesc_ttl
				    (ta_number, role_tcsc_handle,
				     &tid.role, (void **) array_pp,
				     ttl_array_pp);
			else
				return
				    rsbac_ta_list_lol_subcount(ta_number,
							       role_tcsc_handle,
							       &tid.role);
		case RI_type_comp_group:
			if (array_pp)
				return
				    rsbac_ta_list_lol_get_all_subdesc_ttl
				    (ta_number, role_tcgr_handle,
				     &tid.role, (void **) array_pp,
				     ttl_array_pp);
			else
				return
				    rsbac_ta_list_lol_subcount(ta_number,
							       role_tcgr_handle,
							       &tid.role);
		case RI_type_comp_netdev:
			if (array_pp)
				return
				    rsbac_ta_list_lol_get_all_subdesc_ttl
				    (ta_number, role_tcnd_handle,
				     &tid.role, (void **) array_pp,
				     ttl_array_pp);
			else
				return
				    rsbac_ta_list_lol_subcount(ta_number,
							       role_tcnd_handle,
							       &tid.role);
		case RI_type_comp_nettemp:
			if (array_pp)
				return
				    rsbac_ta_list_lol_get_all_subdesc_ttl
				    (ta_number, role_tcnt_handle,
				     &tid.role, (void **) array_pp,
				     ttl_array_pp);
			else
				return
				    rsbac_ta_list_lol_subcount(ta_number,
							       role_tcnt_handle,
							       &tid.role);
		case RI_type_comp_netobj:
			if (array_pp)
				return
				    rsbac_ta_list_lol_get_all_subdesc_ttl
				    (ta_number, role_tcno_handle,
				     &tid.role, (void **) array_pp,
				     ttl_array_pp);
			else
				return
				    rsbac_ta_list_lol_subcount(ta_number,
							       role_tcno_handle,
							       &tid.role);

		default:
			return -RSBAC_EINVALIDATTR;
		}

	case RT_TYPE:
/*
		rsbac_pr_debug(ds_rc, "getting type item value\n");
*/
		switch (item) {
		case RI_type_fd_name:
		case RI_type_fd_need_secdel:
			if (array_pp)
				return
				    rsbac_ta_list_get_all_desc(ta_number,
							       type_fd_handle,
							       (void **)
							       array_pp);
			else
				return rsbac_ta_list_count(ta_number,
							   type_fd_handle);
		case RI_type_dev_name:
			if (array_pp)
				return
				    rsbac_ta_list_get_all_desc(ta_number,
							       type_dev_handle,
							       (void **)
							       array_pp);
			else
				return rsbac_ta_list_count(ta_number,
							   type_dev_handle);
		case RI_type_ipc_name:
			if (array_pp)
				return
				    rsbac_ta_list_get_all_desc(ta_number,
							       type_ipc_handle,
							       (void **)
							       array_pp);
			else
				return rsbac_ta_list_count(ta_number,
							   type_ipc_handle);
		case RI_type_user_name:
			if (array_pp)
				return
				    rsbac_ta_list_get_all_desc(ta_number,
							       type_user_handle,
							       (void **)
							       array_pp);
			else
				return rsbac_ta_list_count(ta_number,
							   type_user_handle);
		case RI_type_process_name:
			if (array_pp)
				return
				    rsbac_ta_list_get_all_desc(ta_number,
							       type_process_handle,
							       (void **)
							       array_pp);
			else
				return rsbac_ta_list_count(ta_number,
							   type_process_handle);
		case RI_type_group_name:
			if (array_pp)
				return
				    rsbac_ta_list_get_all_desc(ta_number,
							       type_group_handle,
							       (void **)
							       array_pp);
			else
				return rsbac_ta_list_count(ta_number,
							   type_group_handle);
		case RI_type_netdev_name:
			if (array_pp)
				return
				    rsbac_ta_list_get_all_desc(ta_number,
							       type_netdev_handle,
							       (void **)
							       array_pp);
			else
				return rsbac_ta_list_count(ta_number,
							   type_netdev_handle);
		case RI_type_nettemp_name:
			if (array_pp)
				return
				    rsbac_ta_list_get_all_desc(ta_number,
							       type_nettemp_handle,
							       (void **)
							       array_pp);
			else
				return rsbac_ta_list_count(ta_number,
							   type_nettemp_handle);
		case RI_type_netobj_name:
			if (array_pp)
				return
				    rsbac_ta_list_get_all_desc(ta_number,
							       type_netobj_handle,
							       (void **)
							       array_pp);
			else
				return rsbac_ta_list_count(ta_number,
							   type_netobj_handle);

		default:
			return -RSBAC_EINVALIDATTR;
		}

	default:
		return -RSBAC_EINVALIDTARGET;
	}
}				/* end of rsbac_rc_get_list() */


/* Setting values */
int rsbac_rc_set_item(rsbac_list_ta_number_t ta_number,
		      enum rsbac_rc_target_t target,
		      union rsbac_rc_target_id_t tid,
		      union rsbac_rc_target_id_t subtid,
		      enum rsbac_rc_item_t item,
		      union rsbac_rc_item_value_t value, rsbac_time_t ttl)
{
	int err = 0;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_rc_set_item(): RSBAC not initialized\n");
		return (-RSBAC_ENOTINITIALIZED);
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_rc_set_item(): called from interrupt!\n");
	}
	switch (target) {
	case RT_ROLE:
		if (tid.role > RC_role_max_value)
			return (-RSBAC_EINVALIDTARGET);
		if ((item != RI_name)
		    && !rsbac_ta_list_exist(ta_number, role_handle,
					    &tid.role)
		    )
			return (-RSBAC_EINVALIDTARGET);
		rsbac_pr_debug(ds_rc, "Setting role item value\n");
		switch (item) {
		case RI_role_comp:
			if (value.comp) {
				return
				    rsbac_ta_list_lol_subadd_ttl(ta_number,
								 role_rc_handle,
								 ttl,
								 &tid.role,
								 &subtid.
								 role,
								 NULL);
			} else {
				rsbac_ta_list_lol_subremove(ta_number,
							    role_rc_handle,
							    &tid.role,
							    &subtid.role);
				return 0;
			}
		case RI_admin_roles:
			if (value.comp) {
				return
				    rsbac_ta_list_lol_subadd_ttl(ta_number,
								 role_adr_handle,
								 ttl,
								 &tid.role,
								 &subtid.
								 role,
								 NULL);
			} else {
				rsbac_ta_list_lol_subremove(ta_number,
							    role_adr_handle,
							    &tid.role,
							    &subtid.role);
				return 0;
			}
		case RI_assign_roles:
			if (value.comp) {
				return
				    rsbac_ta_list_lol_subadd_ttl(ta_number,
								 role_asr_handle,
								 ttl,
								 &tid.role,
								 &subtid.
								 role,
								 NULL);
			} else {
				rsbac_ta_list_lol_subremove(ta_number,
							    role_asr_handle,
							    &tid.role,
							    &subtid.role);
				return 0;
			}
		case RI_type_comp_fd:
			if (!rsbac_ta_list_exist
			    (ta_number, type_fd_handle, &subtid.type))
				return -RSBAC_EINVALIDVALUE;
			return rsbac_ta_list_lol_subadd_ttl(ta_number,
							    role_tcfd_handle,
							    ttl,
							    &tid.role,
							    &subtid.type,
							    &value.rights);
		case RI_type_comp_dev:
			if (!rsbac_ta_list_exist
			    (ta_number, type_dev_handle, &subtid.type))
				return -RSBAC_EINVALIDVALUE;
			return rsbac_ta_list_lol_subadd_ttl(ta_number,
							    role_tcdv_handle,
							    ttl,
							    &tid.role,
							    &subtid.type,
							    &value.rights);
		case RI_type_comp_user:
			if (!rsbac_ta_list_exist
			    (ta_number, type_user_handle, &subtid.type))
				return -RSBAC_EINVALIDVALUE;
			return rsbac_ta_list_lol_subadd_ttl(ta_number,
							    role_tcus_handle,
							    ttl,
							    &tid.role,
							    &subtid.type,
							    &value.rights);
		case RI_type_comp_process:
			if (!rsbac_ta_list_exist
			    (ta_number, type_process_handle, &subtid.type))
				return -RSBAC_EINVALIDVALUE;
			return rsbac_ta_list_lol_subadd_ttl(ta_number,
							    role_tcpr_handle,
							    ttl,
							    &tid.role,
							    &subtid.type,
							    &value.rights);
		case RI_type_comp_ipc:
			if (!rsbac_ta_list_exist
			    (ta_number, type_ipc_handle, &subtid.type))
				return -RSBAC_EINVALIDVALUE;
			return rsbac_ta_list_lol_subadd_ttl(ta_number,
							    role_tcip_handle,
							    ttl,
							    &tid.role,
							    &subtid.type,
							    &value.rights);
		case RI_type_comp_scd:
			if ((subtid.type >= ST_none)
			    && (subtid.type < RST_min)
			    )
				return -RSBAC_EINVALIDVALUE;
			if (subtid.type >= RST_none)
				return -RSBAC_EINVALIDVALUE;
			return rsbac_ta_list_lol_subadd_ttl(ta_number,
							    role_tcsc_handle,
							    ttl,
							    &tid.role,
							    &subtid.type,
							    &value.rights);
		case RI_type_comp_group:
			if (!rsbac_ta_list_exist
			    (ta_number, type_group_handle, &subtid.type))
				return -RSBAC_EINVALIDVALUE;
			return rsbac_ta_list_lol_subadd_ttl(ta_number,
							    role_tcgr_handle,
							    ttl,
							    &tid.role,
							    &subtid.type,
							    &value.rights);
		case RI_type_comp_netdev:
			if (!rsbac_ta_list_exist
			    (ta_number, type_netdev_handle, &subtid.type))
				return -RSBAC_EINVALIDVALUE;
			return rsbac_ta_list_lol_subadd_ttl(ta_number,
							    role_tcnd_handle,
							    ttl,
							    &tid.role,
							    &subtid.type,
							    &value.rights);
		case RI_type_comp_nettemp:
			if (!rsbac_ta_list_exist
			    (ta_number, type_nettemp_handle, &subtid.type))
				return -RSBAC_EINVALIDVALUE;
			return rsbac_ta_list_lol_subadd_ttl(ta_number,
							    role_tcnt_handle,
							    ttl,
							    &tid.role,
							    &subtid.type,
							    &value.rights);
		case RI_type_comp_netobj:
			if (!rsbac_ta_list_exist
			    (ta_number, type_netobj_handle, &subtid.type))
				return -RSBAC_EINVALIDVALUE;
			return rsbac_ta_list_lol_subadd_ttl(ta_number,
							    role_tcno_handle,
							    ttl,
							    &tid.role,
							    &subtid.type,
							    &value.rights);
		case RI_admin_type:
			{
				struct rsbac_rc_role_entry_t entry;

				err =
				    rsbac_ta_list_get_data_ttl(ta_number,
							       role_handle,
							       NULL,
							       &tid.role,
							       &entry);
				if (err)
					return err;
				entry.admin_type = value.admin_type;
				return rsbac_ta_list_add_ttl(ta_number,
							     role_handle,
							     0, &tid.role,
							     &entry);
			}
		case RI_name:
			{
				struct rsbac_rc_role_entry_t entry;

				/* no empty names */
				if (!value.name[0])
					return -RSBAC_EINVALIDVALUE;
				/* create, if necessary, and set name */
				memset(&entry, 0,
				       sizeof(struct
					      rsbac_rc_role_entry_t));
				rsbac_ta_list_get_data_ttl(ta_number,
							   role_handle,
							   NULL, &tid.role,
							   &entry);
				strncpy(entry.name, value.name,
					RSBAC_RC_NAME_LEN - 1);
				entry.name[RSBAC_RC_NAME_LEN - 1] = 0;
				return rsbac_ta_list_add_ttl(ta_number,
							     role_handle,
							     0, &tid.role,
							     &entry);
			}
		case RI_remove_role:
			if (!tid.role)
				return -RSBAC_EINVALIDVALUE;
			/* remove role compat. */
			rsbac_ta_list_lol_remove(ta_number, role_rc_handle,
						 &tid.role);
			/* remove from other roles' role compat */
			rsbac_ta_list_lol_subremove_from_all(ta_number,
							     role_rc_handle,
							     &tid.role);

			/* remove admin roles */
			rsbac_ta_list_lol_remove(ta_number,
						 role_adr_handle,
						 &tid.role);
			/* remove from other roles' admin roles */
			rsbac_ta_list_lol_subremove_from_all(ta_number,
							     role_adr_handle,
							     &tid.role);

			/* remove assign roles */
			rsbac_ta_list_lol_remove(ta_number,
						 role_asr_handle,
						 &tid.role);
			/* remove from other roles' assign roles */
			rsbac_ta_list_lol_subremove_from_all(ta_number,
							     role_asr_handle,
							     &tid.role);

			/* remove def_fd_ind_create_type */
			rsbac_ta_list_lol_remove(ta_number,
						 role_dfdc_handle,
						 &tid.role);

			/* remove type compatibilities */
			rsbac_ta_list_lol_remove(ta_number,
						 role_tcfd_handle,
						 &tid.role);
			rsbac_ta_list_lol_remove(ta_number,
						 role_tcdv_handle,
						 &tid.role);
			rsbac_ta_list_lol_remove(ta_number,
						 role_tcus_handle,
						 &tid.role);
			rsbac_ta_list_lol_remove(ta_number,
						 role_tcpr_handle,
						 &tid.role);
			rsbac_ta_list_lol_remove(ta_number,
						 role_tcip_handle,
						 &tid.role);
			rsbac_ta_list_lol_remove(ta_number,
						 role_tcsc_handle,
						 &tid.role);
			rsbac_ta_list_lol_remove(ta_number,
						 role_tcgr_handle,
						 &tid.role);
			rsbac_ta_list_lol_remove(ta_number,
						 role_tcnd_handle,
						 &tid.role);
			rsbac_ta_list_lol_remove(ta_number,
						 role_tcnt_handle,
						 &tid.role);
			rsbac_ta_list_lol_remove(ta_number,
						 role_tcno_handle,
						 &tid.role);

#ifdef CONFIG_RSBAC_ACL
			/* remove ACL entries */
			{
				struct rsbac_acl_entry_desc_t desc;

				desc.subj_type = ACLS_ROLE;
				desc.subj_id = tid.role;
				rsbac_acl_remove_subject(ta_number, desc);
			}
#endif

			return rsbac_ta_list_remove(ta_number, role_handle,
						    &tid.role);

		case RI_def_fd_create_type:
			{
				struct rsbac_rc_role_entry_t entry;

				if ((value.type_id <= RC_type_max_value)
				    && !rsbac_ta_list_exist(ta_number,
							    type_fd_handle,
							    &value.type_id)
				    )
					return -RSBAC_EINVALIDVALUE;
				if ((value.type_id > RC_type_max_value)
				    && (value.type_id <
					RC_type_min_special)
				    )
					return -RSBAC_EINVALIDVALUE;
				err =
				    rsbac_ta_list_get_data_ttl(ta_number,
							       role_handle,
							       NULL,
							       &tid.role,
							       &entry);
				if (err)
					return err;
				entry.def_fd_create_type = value.type_id;
				return rsbac_ta_list_add_ttl(ta_number,
							     role_handle,
							     0, &tid.role,
							     &entry);
			}
		case RI_def_fd_ind_create_type:
			if ((value.type_id <= RC_type_max_value)
			    && !rsbac_ta_list_exist(ta_number,
						    type_fd_handle,
						    &value.type_id)
			    )
				return -RSBAC_EINVALIDVALUE;
			if ((value.type_id > RC_type_max_value)
			    && (value.type_id < RC_type_min_special)
			    )
				return -RSBAC_EINVALIDVALUE;
			return rsbac_ta_list_lol_subadd_ttl(ta_number,
							    role_dfdc_handle,
							    ttl,
							    &tid.role,
							    &subtid.type,
							    &value.
							    type_id);
		case RI_def_fd_ind_create_type_remove:
			return rsbac_ta_list_lol_subremove(ta_number,
							   role_dfdc_handle,
							   &tid.role,
							   &subtid.type);

		case RI_def_user_create_type:
			{
				struct rsbac_rc_role_entry_t entry;

				if ((value.type_id <= RC_type_max_value)
				    && !rsbac_ta_list_exist(ta_number,
							    type_user_handle,
							    &value.type_id)
				    )
					return -RSBAC_EINVALIDVALUE;
				if ((value.type_id > RC_type_max_value)
				    && (value.type_id <
					RC_type_min_special)
				    )
					return -RSBAC_EINVALIDVALUE;
				err =
				    rsbac_ta_list_get_data_ttl(ta_number,
							       role_handle,
							       NULL,
							       &tid.role,
							       &entry);
				if (err)
					return err;
				entry.def_user_create_type = value.type_id;
				return rsbac_ta_list_add_ttl(ta_number,
							     role_handle,
							     0, &tid.role,
							     &entry);
			}
		case RI_def_process_create_type:
			{
				struct rsbac_rc_role_entry_t entry;

				if ((value.type_id <= RC_type_max_value)
				    && !rsbac_ta_list_exist(ta_number,
							    type_process_handle,
							    &value.type_id)
				    )
					return -RSBAC_EINVALIDVALUE;
				if ((value.type_id > RC_type_max_value)
				    && (value.type_id <
					RC_type_min_special)
				    )
					return -RSBAC_EINVALIDVALUE;
				err =
				    rsbac_ta_list_get_data_ttl(ta_number,
							       role_handle,
							       NULL,
							       &tid.role,
							       &entry);
				if (err)
					return err;
				entry.def_process_create_type =
				    value.type_id;
				return rsbac_ta_list_add_ttl(ta_number,
							     role_handle,
							     0, &tid.role,
							     &entry);
			}
		case RI_def_process_chown_type:
			{
				struct rsbac_rc_role_entry_t entry;

				if ((value.type_id <= RC_type_max_value)
				    && !rsbac_ta_list_exist(ta_number,
							    type_process_handle,
							    &value.type_id)
				    )
					return -RSBAC_EINVALIDVALUE;
				if ((value.type_id > RC_type_max_value)
				    && (value.type_id <
					RC_type_min_special)
				    )
					return -RSBAC_EINVALIDVALUE;
				err =
				    rsbac_ta_list_get_data_ttl(ta_number,
							       role_handle,
							       NULL,
							       &tid.role,
							       &entry);
				if (err)
					return err;
				entry.def_process_chown_type =
				    value.type_id;
				return rsbac_ta_list_add_ttl(ta_number,
							     role_handle,
							     0, &tid.role,
							     &entry);
			}
		case RI_def_process_execute_type:
			{
				struct rsbac_rc_role_entry_t entry;

				if ((value.type_id <= RC_type_max_value)
				    && !rsbac_ta_list_exist(ta_number,
							    type_process_handle,
							    &value.type_id)
				    )
					return -RSBAC_EINVALIDVALUE;
				if ((value.type_id > RC_type_max_value)
				    && (value.type_id <
					RC_type_min_special)
				    )
					return -RSBAC_EINVALIDVALUE;
				err =
				    rsbac_ta_list_get_data_ttl(ta_number,
							       role_handle,
							       NULL,
							       &tid.role,
							       &entry);
				if (err)
					return err;
				entry.def_process_execute_type =
				    value.type_id;
				return rsbac_ta_list_add_ttl(ta_number,
							     role_handle,
							     0, &tid.role,
							     &entry);
			}
		case RI_def_ipc_create_type:
			{
				struct rsbac_rc_role_entry_t entry;

				if ((value.type_id <= RC_type_max_value)
				    && !rsbac_ta_list_exist(ta_number,
							    type_ipc_handle,
							    &value.type_id)
				    )
					return -RSBAC_EINVALIDVALUE;
				if ((value.type_id > RC_type_max_value)
				    && (value.type_id <
					RC_type_min_special)
				    )
					return -RSBAC_EINVALIDVALUE;
				err =
				    rsbac_ta_list_get_data_ttl(ta_number,
							       role_handle,
							       NULL,
							       &tid.role,
							       &entry);
				if (err)
					return err;
				entry.def_ipc_create_type = value.type_id;
				return rsbac_ta_list_add_ttl(ta_number,
							     role_handle,
							     0, &tid.role,
							     &entry);
			}
		case RI_def_group_create_type:
			{
				struct rsbac_rc_role_entry_t entry;

				if ((value.type_id <= RC_type_max_value)
				    && !rsbac_ta_list_exist(ta_number,
							    type_group_handle,
							    &value.type_id)
				    )
					return -RSBAC_EINVALIDVALUE;
				if ((value.type_id > RC_type_max_value)
				    && (value.type_id <
					RC_type_min_special)
				    )
					return -RSBAC_EINVALIDVALUE;
				err =
				    rsbac_ta_list_get_data_ttl(ta_number,
							       role_handle,
							       NULL,
							       &tid.role,
							       &entry);
				if (err)
					return err;
				entry.def_group_create_type =
				    value.type_id;
				return rsbac_ta_list_add_ttl(ta_number,
							     role_handle,
							     0, &tid.role,
							     &entry);
			}
		case RI_def_unixsock_create_type:
			{
				struct rsbac_rc_role_entry_t entry;

				if ((value.type_id <= RC_type_max_value)
				    && !rsbac_ta_list_exist(ta_number,
							    type_fd_handle,
							    &value.type_id)
				    )
					return -RSBAC_EINVALIDVALUE;
				if ((value.type_id > RC_type_max_value)
				    && (value.type_id <
					RC_type_min_special)
				    )
					return -RSBAC_EINVALIDVALUE;
				err =
				    rsbac_ta_list_get_data_ttl(ta_number,
							       role_handle,
							       NULL,
							       &tid.role,
							       &entry);
				if (err)
					return err;
				entry.def_unixsock_create_type =
				    value.type_id;
				return rsbac_ta_list_add_ttl(ta_number,
							     role_handle,
							     0, &tid.role,
							     &entry);
			}
		case RI_boot_role:
			{
				struct rsbac_rc_role_entry_t entry;

				err =
				    rsbac_ta_list_get_data_ttl(ta_number,
							       role_handle,
							       NULL,
							       &tid.role,
							       &entry);
				if (err)
					return err;
				entry.boot_role = value.boot_role;
				return rsbac_ta_list_add_ttl(ta_number,
							     role_handle,
							     0, &tid.role,
							     &entry);
			}
		case RI_req_reauth:
			{
				struct rsbac_rc_role_entry_t entry;

				err =
				    rsbac_ta_list_get_data_ttl(ta_number,
							       role_handle,
							       NULL,
							       &tid.role,
							       &entry);
				if (err)
					return err;
				entry.req_reauth = value.req_reauth;
//				printk(KERN_WARNING "entry %u value %u\n",
//				       entry.req_reauth, value.req_reauth);
				return rsbac_ta_list_add_ttl(ta_number,
							     role_handle,
							     0, &tid.role,
							     &entry);
			}

		default:
			return -RSBAC_EINVALIDATTR;
		}

	case RT_TYPE:
		if (tid.type > RC_type_max_value)
			return (-RSBAC_EINVALIDTARGET);
		rsbac_pr_debug(ds_rc, "Setting type item value\n");
		switch (item) {
		case RI_type_fd_name:
			{
				struct rsbac_rc_type_fd_entry_t entry;

				/* no empty names */
				if (!value.name[0])
					return -RSBAC_EINVALIDVALUE;
				/* create, if necessary, and set name */
				memset(&entry, 0,
				       sizeof(struct
					      rsbac_rc_type_fd_entry_t));
				rsbac_ta_list_get_data_ttl(ta_number,
							   type_fd_handle,
							   NULL, &tid.type,
							   &entry);
				strncpy(entry.name, value.name,
					RSBAC_RC_NAME_LEN - 1);
				entry.name[RSBAC_RC_NAME_LEN - 1] = 0;
				return rsbac_ta_list_add_ttl(ta_number,
							     type_fd_handle,
							     0, &tid.type,
							     &entry);
			}
		case RI_type_fd_need_secdel:
			{
				struct rsbac_rc_type_fd_entry_t entry;

				err =
				    rsbac_ta_list_get_data_ttl(ta_number,
							       type_fd_handle,
							       NULL,
							       &tid.type,
							       &entry);
				if (err)
					return err;
				entry.need_secdel = value.need_secdel;
				return rsbac_ta_list_add_ttl(ta_number,
							     type_fd_handle,
							     0, &tid.type,
							     &entry);
			}
		case RI_type_dev_name:
			/* no empty names */
			if (!value.name[0])
				return -RSBAC_EINVALIDVALUE;
			/* create, if necessary, and set name */
			value.name[RSBAC_RC_NAME_LEN - 1] = 0;
			return rsbac_ta_list_add_ttl(ta_number,
						     type_dev_handle, 0,
						     &tid.type,
						     &value.name);
		case RI_type_ipc_name:
			/* no empty names */
			if (!value.name[0])
				return -RSBAC_EINVALIDVALUE;
			/* create, if necessary, and set name */
			value.name[RSBAC_RC_NAME_LEN - 1] = 0;
			return rsbac_ta_list_add_ttl(ta_number,
						     type_ipc_handle, 0,
						     &tid.type,
						     &value.name);
		case RI_type_user_name:
			/* no empty names */
			if (!value.name[0])
				return -RSBAC_EINVALIDVALUE;
			/* create, if necessary, and set name */
			value.name[RSBAC_RC_NAME_LEN - 1] = 0;
			return rsbac_ta_list_add_ttl(ta_number,
						     type_user_handle, 0,
						     &tid.type,
						     &value.name);
		case RI_type_process_name:
			/* no empty names */
			if (!value.name[0])
				return -RSBAC_EINVALIDVALUE;
			/* create, if necessary, and set name */
			value.name[RSBAC_RC_NAME_LEN - 1] = 0;
			return rsbac_ta_list_add_ttl(ta_number,
						     type_process_handle,
						     0, &tid.type,
						     &value.name);
		case RI_type_group_name:
			/* no empty names */
			if (!value.name[0])
				return -RSBAC_EINVALIDVALUE;
			/* create, if necessary, and set name */
			value.name[RSBAC_RC_NAME_LEN - 1] = 0;
			return rsbac_ta_list_add_ttl(ta_number,
						     type_group_handle, 0,
						     &tid.type,
						     &value.name);
		case RI_type_netdev_name:
			/* no empty names */
			if (!value.name[0])
				return -RSBAC_EINVALIDVALUE;
			/* create, if necessary, and set name */
			value.name[RSBAC_RC_NAME_LEN - 1] = 0;
			return rsbac_ta_list_add_ttl(ta_number,
						     type_netdev_handle, 0,
						     &tid.type,
						     &value.name);
		case RI_type_nettemp_name:
			/* no empty names */
			if (!value.name[0])
				return -RSBAC_EINVALIDVALUE;
			/* create, if necessary, and set name */
			value.name[RSBAC_RC_NAME_LEN - 1] = 0;
			return rsbac_ta_list_add_ttl(ta_number,
						     type_nettemp_handle,
						     0, &tid.type,
						     &value.name);
		case RI_type_netobj_name:
			/* no empty names */
			if (!value.name[0])
				return -RSBAC_EINVALIDVALUE;
			/* create, if necessary, and set name */
			value.name[RSBAC_RC_NAME_LEN - 1] = 0;
			return rsbac_ta_list_add_ttl(ta_number,
						     type_netobj_handle, 0,
						     &tid.type,
						     &value.name);

		case RI_type_fd_remove:
			if (!tid.type)
				return -RSBAC_EINVALIDVALUE;
			rsbac_ta_list_lol_subremove_from_all(ta_number,
							     role_tcfd_handle,
							     &tid.type);
			rsbac_ta_list_lol_subremove_from_all(ta_number,
							     role_dfdc_handle,
							     &tid.type);
			return rsbac_ta_list_remove(ta_number,
						    type_fd_handle,
						    &tid.type);
		case RI_type_dev_remove:
			if (!tid.type)
				return -RSBAC_EINVALIDVALUE;
			rsbac_ta_list_lol_subremove_from_all(ta_number,
							     role_tcdv_handle,
							     &tid.type);
			return rsbac_ta_list_remove(ta_number,
						    type_dev_handle,
						    &tid.type);
		case RI_type_user_remove:
			if (!tid.type)
				return -RSBAC_EINVALIDVALUE;
			rsbac_ta_list_lol_subremove_from_all(ta_number,
							     role_tcus_handle,
							     &tid.type);
			return rsbac_ta_list_remove(ta_number,
						    type_user_handle,
						    &tid.type);
		case RI_type_process_remove:
			if (!tid.type)
				return -RSBAC_EINVALIDVALUE;
			rsbac_ta_list_lol_subremove_from_all(ta_number,
							     role_tcpr_handle,
							     &tid.type);
			return rsbac_ta_list_remove(ta_number,
						    type_process_handle,
						    &tid.type);
		case RI_type_ipc_remove:
			if (!tid.type)
				return -RSBAC_EINVALIDVALUE;
			rsbac_ta_list_lol_subremove_from_all(ta_number,
							     role_tcip_handle,
							     &tid.type);
			return rsbac_ta_list_remove(ta_number,
						    type_ipc_handle,
						    &tid.type);
		case RI_type_group_remove:
			if (!tid.type)
				return -RSBAC_EINVALIDVALUE;
			rsbac_ta_list_lol_subremove_from_all(ta_number,
							     role_tcgr_handle,
							     &tid.type);
			return rsbac_ta_list_remove(ta_number,
						    type_group_handle,
						    &tid.type);
		case RI_type_netdev_remove:
			if (!tid.type)
				return -RSBAC_EINVALIDVALUE;
			rsbac_ta_list_lol_subremove_from_all(ta_number,
							     role_tcnd_handle,
							     &tid.type);
			return rsbac_ta_list_remove(ta_number,
						    type_netdev_handle,
						    &tid.type);
		case RI_type_nettemp_remove:
			if (!tid.type)
				return -RSBAC_EINVALIDVALUE;
			rsbac_ta_list_lol_subremove_from_all(ta_number,
							     role_tcnt_handle,
							     &tid.type);
			return rsbac_ta_list_remove(ta_number,
						    type_nettemp_handle,
						    &tid.type);
		case RI_type_netobj_remove:
			if (!tid.type)
				return -RSBAC_EINVALIDVALUE;
			rsbac_ta_list_lol_subremove_from_all(ta_number,
							     role_tcno_handle,
							     &tid.type);
			return rsbac_ta_list_remove(ta_number,
						    type_netobj_handle,
						    &tid.type);

		default:
			return -RSBAC_EINVALIDATTR;
		}

		/* switch target: no valid target */
	default:
		return -RSBAC_EINVALIDTARGET;
	}
}
