/**************************************************** */
/* Rule Set Based Access Control                      */
/* Implementation of the Access Control Decision      */
/* Facility (ADF) - Authorization module              */
/* File: rsbac/adf/jail/jail_main.c                   */
/*                                                    */
/* Author and (c) 1999-2011: Amon Ott <ao@rsbac.org>  */
/*                                                    */
/* Last modified: 17/Oct/2011                         */
/**************************************************** */

#include <linux/string.h>
#include <rsbac/types.h>
#include <rsbac/aci.h>
#include <rsbac/adf_main.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/getname.h>
#include <rsbac/network.h>
#include <rsbac/debug.h>
#include <rsbac/jail.h>

/************************************************* */
/*           Global Variables                      */
/************************************************* */

/************************************************* */
/*          Internal Help functions                */
/************************************************* */

static inline rsbac_boolean_t jail_dev_tty(struct rsbac_dev_desc_t dev)
{
	if (dev.type != D_char)
		return FALSE;
	if (((dev.major >= 2)
	     && (dev.major <= 4)
	    )
	    || ((dev.major >= 128)
		&& (dev.major <= 143)
	    )
	    )
		return TRUE;
	else
		return FALSE;
}

static rsbac_jail_id_t
jail_get_id(enum rsbac_target_t target, union rsbac_target_id_t tid)
{
	int err;
	union rsbac_attribute_value_t i_attr_val1;

	if ((err = rsbac_get_attr(SW_JAIL,
				  target,
				  tid, A_jail_id, &i_attr_val1, TRUE))) {
		rsbac_ds_get_error("jail_get_id()", A_jail_id);
		return 0;
	} else
		return i_attr_val1.jail_id;
}

static rsbac_jail_id_t jail_get_id_process(rsbac_pid_t pid)
{
	int err;
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val1;

	i_tid.process = pid;
	if ((err = rsbac_get_attr(SW_JAIL, T_PROCESS,
				  i_tid, A_jail_id, &i_attr_val1, TRUE))) {
		rsbac_ds_get_error("jail_get_id_process()", A_jail_id);
		return 0;
	} else
		return i_attr_val1.jail_id;
}

static inline rsbac_jail_id_t jail_get_parent_process(rsbac_pid_t pid)
{
	int err;
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val1;

	i_tid.process = pid;
	if ((err = rsbac_get_attr(SW_JAIL, T_PROCESS,
				  i_tid, A_jail_parent, &i_attr_val1, TRUE))) {
		rsbac_ds_get_error("jail_get_parent_process()", A_jail_parent);
		return 0;
	} else
		return i_attr_val1.jail_parent;
}

#if defined(CONFIG_RSBAC_NET_OBJ)
static inline rsbac_jail_ip_t jail_get_ip_process(rsbac_pid_t pid)
{
	int err;
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val1;

	i_tid.process = pid;
	if ((err = rsbac_get_attr(SW_JAIL, T_PROCESS,
				  i_tid, A_jail_ip, &i_attr_val1, TRUE))) {
		rsbac_ds_get_error("jail_get_ip_process()", A_jail_ip);
		return 0;
	} else
		return i_attr_val1.jail_ip;
}
#endif

static rsbac_jail_flags_t jail_get_flags_process(rsbac_pid_t pid)
{
	int err;
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val1;

	i_tid.process = pid;
	if ((err = rsbac_get_attr(SW_JAIL, T_PROCESS, i_tid,
				  A_jail_flags, &i_attr_val1, TRUE))) {
		rsbac_ds_get_error("jail_get_flags_process()",
				   A_jail_flags);
		return 0;
	} else
		return i_attr_val1.jail_flags;
}

static inline rsbac_jail_scd_vector_t jail_get_scd_get_process(rsbac_pid_t pid)
{
	int err;
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val1;

	i_tid.process = pid;
	if ((err = rsbac_get_attr(SW_JAIL, T_PROCESS, i_tid,
				  A_jail_scd_get, &i_attr_val1, TRUE))) {
		rsbac_ds_get_error("jail_get_scd_get_process()",
				   A_jail_scd_get);
		return 0;
	} else
		return i_attr_val1.jail_scd_get;
}

static inline rsbac_jail_scd_vector_t jail_get_scd_modify_process(rsbac_pid_t pid)
{
	int err;
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val1;

	i_tid.process = pid;
	if ((err = rsbac_get_attr(SW_JAIL, T_PROCESS, i_tid,
				  A_jail_scd_modify,
				  &i_attr_val1, TRUE))) {
		rsbac_ds_get_error("jail_get_scd_modify_process()",
				   A_jail_scd_modify);
		return 0;
	} else
		return i_attr_val1.jail_scd_modify;
}

static enum rsbac_adf_req_ret_t
jail_check_sysrole(rsbac_uid_t owner,
		enum rsbac_system_role_t role)
{
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val1;

	i_tid.user = owner;
	if (rsbac_get_attr(SW_JAIL, T_USER, i_tid,
			   A_jail_role, &i_attr_val1, TRUE)) {
		rsbac_ds_get_error("jail_check_sysrole()", A_jail_role);
		return (NOT_GRANTED);
	}
	/* if correct role, then grant */
	if (i_attr_val1.system_role == role)
		return (GRANTED);
	else
		return (NOT_GRANTED);
}

#if defined(CONFIG_RSBAC_NET_OBJ)
enum rsbac_adf_req_ret_t
jail_check_ip(rsbac_pid_t pid, union rsbac_target_id_t tid)
{
	rsbac_jail_ip_t jail_ip;
	rsbac_jail_flags_t jail_flags;

	if (!tid.netobj.sock_p) {
		rsbac_printk(KERN_WARNING
			     "jail_check_ip(): NULL sock_p!\n");
		return NOT_GRANTED;
	}
	if (!tid.netobj.sock_p->ops) {
		return DO_NOT_CARE;
	}
	switch (tid.netobj.sock_p->ops->family) {
	case AF_UNIX:
		return DO_NOT_CARE;

	case AF_INET:
		switch (tid.netobj.sock_p->type) {
		case SOCK_STREAM:
		case SOCK_DGRAM:
		case SOCK_RDM:
			jail_ip = jail_get_ip_process(pid);
			if (jail_ip == INADDR_ANY)
				return GRANTED;
			jail_flags = jail_get_flags_process(pid);
			if (tid.netobj.local_addr) {
				struct sockaddr_in *addr =
				    tid.netobj.local_addr;

				if ((jail_ip == addr->sin_addr.s_addr)
					|| (
						(jail_flags &
						JAIL_allow_inet_localhost)
						&& (addr->sin_addr.s_addr ==
						RSBAC_JAIL_LOCALHOST)
					)
#if defined(CONFIG_RSBAC_JAIL_NET_ADJUST)
					|| (
						(jail_flags &
						JAIL_auto_adjust_inet_any)
						&& (addr->sin_addr.s_addr ==
						INADDR_ANY)
					)
#endif
				    )
					return GRANTED;
				else {
					rsbac_pr_debug(adf_jail, "local_addr does not match jail_ip -> NOT_GRANTED!\n");
					return NOT_GRANTED;
				}
			} else if ((tid.netobj.remote_addr)
				   && (jail_flags &
				       JAIL_allow_inet_localhost)
				   &&
				   (((struct sockaddr_in *) tid.netobj.
				     remote_addr)->sin_addr.s_addr ==
				    RSBAC_JAIL_LOCALHOST)
			    )
				return GRANTED;
			else {
				if (((jail_ip ==
				      inet_sk(tid.netobj.sock_p->sk)->
				      inet_rcv_saddr)
				     && (jail_ip ==
					 inet_sk(tid.netobj.sock_p->sk)->
					 inet_saddr)
				    )
				    || (
					    (jail_flags &
					     JAIL_allow_inet_localhost)
					    &&
					    ((inet_sk(tid.netobj.sock_p->sk)->
					      inet_saddr == RSBAC_JAIL_LOCALHOST)
				    || (
					     inet_sk(tid.netobj.sock_p->sk)->
					     inet_daddr == RSBAC_JAIL_LOCALHOST)
				     )
				     )
#if defined(CONFIG_RSBAC_JAIL_NET_ADJUST)
				    || (
					    (jail_flags &
					     JAIL_auto_adjust_inet_any)
					    && (inet_sk(tid.netobj.sock_p->sk)->
						    inet_rcv_saddr == INADDR_ANY)
					    && (inet_sk(tid.netobj.sock_p->sk)->
						    inet_saddr == INADDR_ANY)
				    )
#endif
				    )
					return GRANTED;
				else {
					rsbac_pr_debug(adf_jail, "sk->inet_rcv_saddr or sk->inet_saddr does not match jail_ip -> NOT_GRANTED!\n");
					return NOT_GRANTED;
				}
			}

		case SOCK_RAW:
			if (jail_get_flags_process(pid) &
			    JAIL_allow_inet_raw)
				return GRANTED;
			else {
				rsbac_pr_debug(adf_jail, "network type is raw  and allow_inet_raw is not set -> NOT_GRANTED!\n");
				return NOT_GRANTED;
			}

		default:
			rsbac_pr_debug(adf_jail, "network type not STREAM, DGRAM, RDM or RAW -> NOT_GRANTED!\n");
			return NOT_GRANTED;
		}

	case AF_NETLINK:
		if (jail_get_flags_process(pid) &
		    (JAIL_allow_all_net_family | JAIL_allow_netlink))
			return GRANTED;
		else {
			rsbac_pr_debug(adf_jail, "network family is NETLINK and neither allow_netlink nor allow_all_net_family is set -> NOT_GRANTED!\n");
			return NOT_GRANTED;
		}

	default:
		if (jail_get_flags_process(pid) &
		    JAIL_allow_all_net_family)
			return GRANTED;
		else {
			rsbac_pr_debug(adf_jail, "network family not UNIX or INET and allow_all_net_family not set -> NOT_GRANTED!\n");
			return NOT_GRANTED;
		}
	}
}
#endif

/************************************************* */
/*          Externally visible functions           */
/************************************************* */

enum rsbac_adf_req_ret_t
rsbac_adf_request_jail(enum rsbac_adf_request_t request,
		       rsbac_pid_t caller_pid,
		       enum rsbac_target_t target,
		       union rsbac_target_id_t tid,
		       enum rsbac_attribute_t attr,
		       union rsbac_attribute_value_t attr_val,
		       rsbac_uid_t owner)
{
	rsbac_jail_id_t jail_id;
	rsbac_jail_id_t jail_id_object;
	rsbac_jail_flags_t jail_flags;

	switch(target) {
	case T_DEV:
		switch(request) {
		case R_SEND:
			if (jail_get_id_process(caller_pid))
				return NOT_GRANTED;
			else
				return GRANTED;
		case R_APPEND_OPEN:
		case R_WRITE_OPEN:
			if (jail_get_id_process(caller_pid)) {
				jail_flags =
				    jail_get_flags_process(caller_pid);
				if (!(jail_flags & JAIL_allow_dev_write))
					return NOT_GRANTED;
				else if (jail_dev_tty(tid.dev)
					 && !(jail_flags &
					      JAIL_allow_tty_open)
				    )
					return NOT_GRANTED;
				else
					return GRANTED;
			} else
				return GRANTED;
		case R_READ_OPEN:
			if (jail_get_id_process(caller_pid)) {
				jail_flags =
				    jail_get_flags_process(caller_pid);
				if (!(jail_flags & JAIL_allow_dev_read))
					return NOT_GRANTED;
				else if (jail_dev_tty(tid.dev)
					 && !(jail_flags &
					      JAIL_allow_tty_open)
				    )
					return NOT_GRANTED;
				else
					return GRANTED;
			} else
				return GRANTED;
		case R_READ_WRITE_OPEN:
			if (jail_get_id_process(caller_pid)) {
				jail_flags =
				    jail_get_flags_process(caller_pid);
				if (!(jail_flags & JAIL_allow_dev_read)
				    || !(jail_flags & JAIL_allow_dev_write)
				    )
					return NOT_GRANTED;
				else if (jail_dev_tty(tid.dev)
					 && !(jail_flags &
					      JAIL_allow_tty_open)
				    )
					return NOT_GRANTED;
				else
					return GRANTED;
			} else
				return GRANTED;
		case R_GET_STATUS_DATA:
			if (jail_get_id_process(caller_pid)
			    && !(jail_get_flags_process(caller_pid) &
				 JAIL_allow_dev_get_status)
			    )
				return NOT_GRANTED;
			else
				return GRANTED;
		case R_MODIFY_SYSTEM_DATA:
			if (jail_get_id_process(caller_pid)
			    && !(jail_get_flags_process(caller_pid) &
				 JAIL_allow_dev_mod_system)
			    )
				return NOT_GRANTED;
			else
				return GRANTED;
		case R_READ:
			if (jail_get_id_process(caller_pid)
			    && !(jail_get_flags_process(caller_pid) &
				 JAIL_allow_dev_read)
			    )
				return NOT_GRANTED;
			else
				return GRANTED;
		case R_WRITE:
			if (jail_get_id_process(caller_pid)
			    && !(jail_get_flags_process(caller_pid) &
				 JAIL_allow_dev_write)
			    )
				return NOT_GRANTED;
			else
				return GRANTED;
		default:
			return DO_NOT_CARE;
		}
	case T_DIR:
		switch(request) {
		case R_CREATE:
			if (!jail_get_id_process(caller_pid))
				return GRANTED;
			/* no mknod for devices or suid/sgid */
			if ((attr == A_create_data)
			    && (S_ISCHR(attr_val.create_data.mode)
				|| S_ISBLK(attr_val.create_data.mode)
				|| ((attr_val.create_data.mode & (S_ISUID | S_ISGID))
				    && !(jail_get_flags_process(caller_pid) & JAIL_allow_suid_files)
				   )
			    )
			    )
				return NOT_GRANTED;
			else
				return GRANTED;
		case R_MODIFY_PERMISSIONS_DATA:
			if (jail_get_id_process(caller_pid)
			    && (attr == A_mode)
			    && (attr_val.mode & (S_ISUID | S_ISGID))
			    && !(jail_get_flags_process(caller_pid) & JAIL_allow_suid_files)
			    )
				return NOT_GRANTED;
			else
				return GRANTED;
		default:
			return DO_NOT_CARE;
		}
	case T_FILE:
		switch(request) {
		case R_ADD_TO_KERNEL:
		case R_REMOVE_FROM_KERNEL:
			if (jail_get_id_process(caller_pid))
				return NOT_GRANTED;
			else
				return GRANTED;
		case R_MOUNT:
		case R_UMOUNT:
			if (!jail_get_id_process(caller_pid)
			    || (jail_get_flags_process(caller_pid) & JAIL_allow_mount)
			   )
				return GRANTED;
			else
				return NOT_GRANTED;
		case R_MODIFY_PERMISSIONS_DATA:
			if (jail_get_id_process(caller_pid)
			    && (attr == A_mode)
			    && (attr_val.mode & (S_ISUID | S_ISGID))
			    && !(jail_get_flags_process(caller_pid) & JAIL_allow_suid_files)
			    )
				return NOT_GRANTED;
			else
				return GRANTED;
		default:
			return DO_NOT_CARE;
		}
	case T_PROCESS:
		switch(request) {
		case R_GET_STATUS_DATA:
		case R_SEND_SIGNAL:
		case R_MODIFY_SYSTEM_DATA:
		case R_TRACE:
			jail_id = jail_get_id_process(caller_pid);
			if (!jail_id
			    || (jail_id == jail_get_id(target, tid))
			    )
				return GRANTED;
			else
				return NOT_GRANTED;
	        case R_MODIFY_ATTRIBUTE:
			switch (attr) {
			case A_jail_id:
			case A_jail_ip:
	 		case A_jail_flags:
			case A_jail_max_caps:
			case A_jail_parent:
			case A_jail_scd_get:
			case A_jail_scd_modify:
			/* All attributes (remove target!) */
			case A_none:
				if (jail_get_id_process(caller_pid))
					return NOT_GRANTED;

				/* Security Officer? */
				return jail_check_sysrole(owner,
							  SR_security_officer);
			default:
				return DO_NOT_CARE;
			}
	        case R_READ_ATTRIBUTE:
			switch (attr) {
			case A_jail_id:
			case A_jail_ip:
	 		case A_jail_flags:
			case A_jail_max_caps:
			case A_jail_parent:
			case A_jail_scd_get:
			case A_jail_scd_modify:
			/* All attributes (remove target!) */
			case A_none:
				if (jail_get_id_process(caller_pid))
					return NOT_GRANTED;

				/* Security Officer? */
				if (jail_check_sysrole(owner, SR_administrator) ==
				    NOT_GRANTED)
					return jail_check_sysrole(owner,
								  SR_security_officer);
				else
					return GRANTED;
			default:
				return (DO_NOT_CARE);
			}
		default:
			return DO_NOT_CARE;
		}
	case T_UNIXSOCK:
		switch(request) {
		case R_SEND:
		case R_CONNECT:
		case R_LISTEN:
		case R_ACCEPT:
		case R_RECEIVE:
#ifdef CONFIG_RSBAC_RW
		case R_READ:
		case R_WRITE:
#endif
		case R_BIND:
			jail_id = jail_get_id_process(caller_pid);
			if (!jail_id)
				return GRANTED;
			if (attr == A_process) {
				union rsbac_target_id_t i_tid;
				rsbac_jail_id_t jail_id_parent;

				i_tid.process = attr_val.process;
				jail_id_parent = jail_get_parent_process(caller_pid);
				if((jail_id != (jail_id_object = jail_get_id(T_PROCESS, i_tid)))
				   && !((jail_flags = jail_get_flags_process(caller_pid)) & JAIL_allow_external_ipc)
				   && (!(jail_flags & JAIL_allow_parent_ipc)
				        || (jail_id_object != jail_id_parent)
				      )
				   && (!(jail_flags & JAIL_allow_ipc_to_syslog)
				        || (jail_id_object != rsbac_jail_syslog_jail_id)
				      )
				   && (!(jail_get_flags_process(attr_val.process) & JAIL_allow_parent_ipc)
				        || (jail_get_parent_process(attr_val.process) != jail_id)
				      )
				  ) {
					rsbac_pr_debug(adf_jail,
						"process jail %u does not match partner process jail %u, parent jail is %u -> NOT_GRANTED!\n",
						jail_id, jail_id_object, jail_id_parent);
					return NOT_GRANTED;
				}
			} else {
				if(!(jail_get_flags_process(caller_pid) & JAIL_allow_external_ipc)) {
					rsbac_pr_debug(adf_jail,
						"process jail is %u, no allow_ipc and partner process unknown -> NOT_GRANTED!\n",
						jail_id);
					return NOT_GRANTED;
				}
			}
			return GRANTED;
		default:
			return DO_NOT_CARE;
		}
#ifdef CONFIG_RSBAC_NET_OBJ
	case T_NETOBJ:
		switch(request) {
		case R_SEND:
		case R_RECEIVE:
		case R_CONNECT:
		case R_LISTEN:
		case R_ACCEPT:
		case R_GET_PERMISSIONS_DATA:
		case R_MODIFY_PERMISSIONS_DATA:
		case R_GET_STATUS_DATA:
		case R_READ:
		case R_WRITE:
		case R_BIND:
			if (!jail_get_id_process(caller_pid))
				return GRANTED;
			return (jail_check_ip(caller_pid, tid));
		case R_CREATE:
			if (!jail_get_id_process(caller_pid))
				return GRANTED;
			if (!tid.netobj.sock_p) {
				rsbac_printk(KERN_WARNING "rsbac_adf_request_jail(): NULL sock_p on CREATE!\n");
				return NOT_GRANTED;
			}
			if (!tid.netobj.sock_p->ops) {
				return DO_NOT_CARE;
			}
			switch (tid.netobj.sock_p->ops->family) {
			case AF_UNIX:
				return (GRANTED);

			case AF_INET:
				switch (tid.netobj.sock_p->type) {
				case SOCK_STREAM:
				case SOCK_DGRAM:
				case SOCK_RDM:
					if (tid.netobj.sock_p->sk
					    && (tid.netobj.sock_p->sk->
						sk_protocol == IPPROTO_RAW)
					    ) {
						jail_flags =
						    jail_get_flags_process
						    (caller_pid);
						if (jail_flags &
						    JAIL_allow_inet_raw)
							return (GRANTED);
						else
							return NOT_GRANTED;
					} else
						return GRANTED;

				case SOCK_RAW:
					jail_flags =
					    jail_get_flags_process
					    (caller_pid);
					if (jail_flags &
					    JAIL_allow_inet_raw)
						return (GRANTED);
					else
						return NOT_GRANTED;

				default:
					return (NOT_GRANTED);
				}

			case AF_NETLINK:
				jail_flags = jail_get_flags_process(caller_pid);
				if (jail_flags &
				    (JAIL_allow_all_net_family | JAIL_allow_netlink))
					return GRANTED;
				else {
					rsbac_pr_debug(adf_jail, "network family is NETLINK and neither allow_netlink nor allow_all_net_family is set -> NOT_GRANTED!\n");
					return NOT_GRANTED;
				}
			default:
				jail_flags = jail_get_flags_process(caller_pid);
				if (jail_flags & JAIL_allow_all_net_family)
					return GRANTED;
				else
					return NOT_GRANTED;
			}
		default:
			return DO_NOT_CARE;
		}
#endif				/* NET_OBJ */
	case T_IPC:
		switch(request) {
		case R_ALTER:
		case R_APPEND_OPEN:
		case R_WRITE_OPEN:
		case R_READ_OPEN:
		case R_READ_WRITE_OPEN:
		case R_DELETE:
		case R_MODIFY_PERMISSIONS_DATA:
		case R_GET_STATUS_DATA:
			jail_id = jail_get_id_process(caller_pid);
			if (!jail_id
			    || (jail_id == (jail_id_object = jail_get_id(target, tid)))
			    || ((jail_flags = jail_get_flags_process(caller_pid)) &
				JAIL_allow_external_ipc)
			    || ((jail_flags & JAIL_allow_parent_ipc)
			    	&& (jail_get_parent_process(caller_pid) == jail_id_object)
			    	)
			    || ((jail_flags & JAIL_allow_ipc_to_syslog)
			    	&& (rsbac_jail_syslog_jail_id == jail_id_object)
			    	)
			    )
				return GRANTED;
			else {
				rsbac_pr_debug(adf_jail,
					"process jail %u does not match IPC object jail %u -> NOT_GRANTED!\n",
					jail_id, jail_id_object);
				return NOT_GRANTED;
			}
		case R_CREATE:
			return GRANTED;
	        case R_MODIFY_ATTRIBUTE:
			switch (attr) {
			case A_jail_id:
			/* All attributes (remove target!) */
			case A_none:
				if (jail_get_id_process(caller_pid))
					return NOT_GRANTED;

				/* Security Officer? */
				return jail_check_sysrole(owner,
							  SR_security_officer);
			default:
				return DO_NOT_CARE;
			}
	        case R_READ_ATTRIBUTE:
			switch (attr) {
			case A_jail_id:
			/* All attributes (remove target!) */
			case A_none:
				if (jail_get_id_process(caller_pid))
					return NOT_GRANTED;

				/* Security Officer? */
				if (jail_check_sysrole(owner, SR_administrator) ==
				    NOT_GRANTED)
					return jail_check_sysrole(owner,
								  SR_security_officer);
				else
					return GRANTED;
			default:
				return (DO_NOT_CARE);
			}
		default:
			jail_id = jail_get_id_process(caller_pid);
			if (!jail_id)
				return GRANTED;
			if((jail_flags = jail_get_flags_process(caller_pid)) &
					JAIL_allow_external_ipc)
				return GRANTED;
			jail_id_object = jail_get_id(target, tid);
			if((jail_flags & JAIL_allow_parent_ipc)
			   && (jail_get_parent_process(caller_pid) == jail_id_object))
				return GRANTED;
			if((attr == A_process)
				&& (jail_get_flags_process(attr_val.process) & JAIL_allow_parent_ipc)
				&& (jail_get_parent_process(attr_val.process) == jail_id))
				return GRANTED;
			if((jail_flags & JAIL_allow_ipc_to_syslog)
			   && (rsbac_jail_syslog_jail_id == jail_id_object))
				return GRANTED;
			if(jail_id != jail_id_object) {
				rsbac_pr_debug(adf_jail,
					"process jail %u does not match IPC object jail %u -> NOT_GRANTED!\n",
					jail_id, jail_id_object);
				return NOT_GRANTED;
			}
			if (attr == A_process) {
				union rsbac_target_id_t i_tid;
				rsbac_jail_id_t jail_id_parent;

				i_tid.process = attr_val.process;
				jail_id_parent = jail_get_parent_process(caller_pid);
				if((jail_id != (jail_id_object = jail_get_id(T_PROCESS, i_tid)))
				   && !(jail_flags & JAIL_allow_external_ipc)
				   && (!(jail_flags & JAIL_allow_parent_ipc)
				        || (jail_id_object != jail_id_parent)
				      )
				  ) {
					rsbac_pr_debug(adf_jail,
						"process jail %u does not match partner process jail %u, parent jail is %u -> NOT_GRANTED!\n",
						jail_id, jail_id_object, jail_id_parent);
					return NOT_GRANTED;
				}
			}
			return GRANTED;
		}
	case T_FIFO:
	case T_SYMLINK:
		switch(request) {
		case R_MODIFY_PERMISSIONS_DATA:
			if (jail_get_id_process(caller_pid)
			    && (attr == A_mode)
			    && (attr_val.mode & (S_ISUID | S_ISGID))
			    && !(jail_get_flags_process(caller_pid) & JAIL_allow_suid_files)
			    )
				return NOT_GRANTED;
			else
				return GRANTED;
		default:
			return DO_NOT_CARE;
		}
	case T_SCD:
		switch(request) {
		case R_MODIFY_PERMISSIONS_DATA:
			if (jail_get_id_process(caller_pid))
				return NOT_GRANTED;
			else
				return GRANTED;
		case R_GET_STATUS_DATA:
			if (jail_get_id_process(caller_pid)) {
				if (jail_get_scd_get_process(caller_pid) &
				    RSBAC_SCD_VECTOR(tid.scd))
					return GRANTED;
				else
					return NOT_GRANTED;
			} else
				return GRANTED;
		case R_MODIFY_SYSTEM_DATA:
			if (jail_get_id_process(caller_pid)) {
				if (jail_get_scd_modify_process(caller_pid)
				    & RSBAC_SCD_VECTOR(tid.scd))
					return (GRANTED);
				else
					return NOT_GRANTED;
			} else
				return GRANTED;
		default:
			return DO_NOT_CARE;
		}
	case T_NONE:
		switch(request) {
		case R_ADD_TO_KERNEL:
		case R_REMOVE_FROM_KERNEL:
		case R_SHUTDOWN:
			if (jail_get_id_process(caller_pid))
				return NOT_GRANTED;
			else
				return GRANTED;
		case R_SWITCH_LOG:
			if (jail_get_id_process(caller_pid))
				return NOT_GRANTED;
			/* test owner's fc_role */
			return jail_check_sysrole(owner,
						  SR_security_officer);
		case R_SWITCH_MODULE:
			/* we need the switch_target */
			if (attr != A_switch_target)
				return NOT_GRANTED;
			/* do not care for other modules */
			if ((attr_val.switch_target != SW_JAIL)
#ifdef CONFIG_RSBAC_SOFTMODE
			    && (attr_val.switch_target != SW_SOFTMODE)
#endif
#ifdef CONFIG_RSBAC_FREEZE
			    && (attr_val.switch_target != SW_FREEZE)
#endif
			    )
				return (DO_NOT_CARE);
			if (jail_get_id_process(caller_pid))
				return NOT_GRANTED;
			/* test owner's fc_role */
			return jail_check_sysrole(owner,
						  SR_security_officer);
#ifdef CONFIG_RSBAC_ALLOW_DAC_DISABLE
		/* switching Linux DAC */
		case R_MODIFY_PERMISSIONS_DATA:
			if (jail_get_id_process(caller_pid))
				return NOT_GRANTED;
			else
				return GRANTED;
#endif
		default:
			return DO_NOT_CARE;
		}
	case T_NETDEV:
		switch(request) {
#ifdef CONFIG_RSBAC_JAIL_NET_DEV_PROT
		case R_MODIFY_SYSTEM_DATA:
		case R_BIND:
			if (jail_get_id_process(caller_pid))
				return NOT_GRANTED;
			else
				return GRANTED;
#endif
		default:
			return DO_NOT_CARE;
		}

#if defined(CONFIG_RSBAC_NET_OBJ)
	case T_NETTEMP:
		switch(request) {
		case R_CREATE:
		case R_DELETE:
		case R_WRITE:
			if (jail_get_id_process(caller_pid))
				return NOT_GRANTED;
			return jail_check_sysrole(owner, SR_security_officer);
		case R_READ:
			if (jail_get_id_process(caller_pid))
				return NOT_GRANTED;
			if (jail_check_sysrole(owner, SR_security_officer)
			    == GRANTED)
				return GRANTED;
			return jail_check_sysrole(owner, SR_administrator);
		default:
			return DO_NOT_CARE;
		}
#endif

	case T_USER:
		switch(request) {
	        case R_MODIFY_ATTRIBUTE:
			switch (attr) {
			case A_system_role:
			case A_jail_role:
			/* All attributes (remove target!) */
			case A_none:
				if (jail_get_id_process(caller_pid))
					return NOT_GRANTED;

				/* Security Officer? */
				return jail_check_sysrole(owner,
							  SR_security_officer);
			default:
				return DO_NOT_CARE;
			}
	        case R_READ_ATTRIBUTE:
			switch (attr) {
			case A_system_role:
			case A_jail_role:
			/* All attributes (remove target!) */
			case A_none:
				if (jail_get_id_process(caller_pid))
					return NOT_GRANTED;

				/* Security Officer? */
				if (jail_check_sysrole(owner, SR_administrator) ==
				    NOT_GRANTED)
					return jail_check_sysrole(owner,
								  SR_security_officer);
				else
					return GRANTED;
			default:
				return (DO_NOT_CARE);
			}
		default:
			return DO_NOT_CARE;
		}

	/* all other cases are unknown */
	default:
		return DO_NOT_CARE;
	}
}

/*****************************************************************************/
/* If the request returned granted and the operation is performed,           */
/* the following function can be called by the AEF to get all aci set        */
/* correctly. For write accesses that are performed fully within the kernel, */
/* this is usually not done to prevent extra calls, including R_CLOSE for    */
/* cleaning up.                                                              */
/* The second instance of target specification is the new target, if one has */
/* been created, otherwise its values are ignored.                           */
/* On success, 0 is returned, and an error from rsbac/error.h otherwise.     */

int rsbac_adf_set_attr_jail(enum rsbac_adf_request_t request,
			    rsbac_pid_t caller_pid,
			    enum rsbac_target_t target,
			    union rsbac_target_id_t tid,
			    enum rsbac_target_t new_target,
			    union rsbac_target_id_t new_tid,
			    enum rsbac_attribute_t attr,
			    union rsbac_attribute_value_t attr_val,
			    rsbac_uid_t owner)
{
#ifdef CONFIG_RSBAC_JAIL_NET_ADJUST
	int err;
#endif
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val1;
	union rsbac_attribute_value_t i_attr_val2;

	switch (request) {
	case R_CHANGE_OWNER:
		switch (target) {
		case T_PROCESS:
			/* Adjust Linux caps */
			i_tid.process = caller_pid;
#ifdef CONFIG_RSBAC_SOFTMODE
			if (!rsbac_softmode)
#endif
			{
				if (rsbac_get_attr(SW_JAIL,
						   T_PROCESS,
						   i_tid,
						   A_jail_max_caps,
						   &i_attr_val1, FALSE)) {
					rsbac_ds_get_error
					    ("rsbac_adf_set_attr_jail()",
					     A_jail_max_caps);
				} else {
					struct cred *override_cred;

					override_cred = prepare_creds();
					if (!override_cred)
						return -ENOMEM;
					override_cred->cap_permitted.cap[0] &= i_attr_val1.jail_max_caps.cap[0];
					override_cred->cap_effective.cap[0] &= i_attr_val1.jail_max_caps.cap[0];
					override_cred->cap_inheritable.cap[0] &= i_attr_val1.jail_max_caps.cap[0];
					override_cred->cap_permitted.cap[1] &= i_attr_val1.jail_max_caps.cap[1];
					override_cred->cap_effective.cap[1] &= i_attr_val1.jail_max_caps.cap[1];
					override_cred->cap_inheritable.cap[1] &= i_attr_val1.jail_max_caps.cap[1];
					commit_creds(override_cred);
				}
			}
			return 0;

		/* all other cases are unknown */
		default:
			return 0;
		}

	case R_CLONE:
		if (target == T_PROCESS) {
			union rsbac_attribute_value_t i_attr_val3;
			union rsbac_attribute_value_t i_attr_val4;
			union rsbac_attribute_value_t i_attr_val5;
			union rsbac_attribute_value_t i_attr_val6;

			/* Get jail_id from first process */
			if (rsbac_get_attr(SW_JAIL,
					   T_PROCESS,
					   tid,
					   A_jail_id,
					   &i_attr_val1, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_jail()",
				     A_jail_id);
				return (-RSBAC_EREADFAILED);
			}
			/* Do not copy anything, if not jailed - defaults are fine */
			if(!i_attr_val1.jail_id)
			  return 0;
			/* Get jail_ip from first process */
			if (rsbac_get_attr(SW_JAIL,
					   T_PROCESS,
					   tid,
					   A_jail_ip,
					   &i_attr_val2, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_jail()",
				     A_jail_ip);
				return (-RSBAC_EREADFAILED);
			}
			/* Get jail_flags from first process */
			if (rsbac_get_attr(SW_JAIL,
					   T_PROCESS,
					   tid,
					   A_jail_flags,
					   &i_attr_val3, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_jail()",
				     A_jail_flags);
				return (-RSBAC_EREADFAILED);
			}
			/* Get jail_max_caps from first process */
			if (rsbac_get_attr(SW_JAIL,
					   T_PROCESS,
					   tid,
					   A_jail_max_caps,
					   &i_attr_val4, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_jail()",
				     A_jail_max_caps);
				return (-RSBAC_EREADFAILED);
			}
			/* Get jail_scd_get from first process */
			if (rsbac_get_attr(SW_JAIL,
					   T_PROCESS,
					   tid,
					   A_jail_scd_get,
					   &i_attr_val5, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_jail()",
				     A_jail_scd_get);
				return (-RSBAC_EREADFAILED);
			}
			/* Get jail_scd_modify from first process */
			if (rsbac_get_attr(SW_JAIL,
					   T_PROCESS,
					   tid,
					   A_jail_scd_modify,
					   &i_attr_val6, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_jail()",
				     A_jail_scd_modify);
				return (-RSBAC_EREADFAILED);
			}
			/* Set jail_id for new process */
			if (rsbac_set_attr(SW_JAIL,
					   T_PROCESS,
					   new_tid,
					   A_jail_id, i_attr_val1)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_jail()",
				     A_jail_id);
				return (-RSBAC_EWRITEFAILED);
			}
			/* Set jail_ip for new process */
			if (rsbac_set_attr(SW_JAIL,
					   T_PROCESS,
					   new_tid,
					   A_jail_ip, i_attr_val2)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_jail()",
				     A_jail_ip);
				return (-RSBAC_EWRITEFAILED);
			}
			/* Set jail_flags for new process */
			if (rsbac_set_attr(SW_JAIL,
					   T_PROCESS,
					   new_tid,
					   A_jail_flags, i_attr_val3)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_jail()",
				     A_jail_flags);
				return (-RSBAC_EWRITEFAILED);
			}
			/* Set jail_max_caps for new process */
			if (rsbac_set_attr(SW_JAIL,
					   T_PROCESS,
					   new_tid,
					   A_jail_max_caps, i_attr_val4)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_jail()",
				     A_jail_max_caps);
				return (-RSBAC_EWRITEFAILED);
			}
			/* Set jail_scd_get for new process */
			if (rsbac_set_attr(SW_JAIL,
					   T_PROCESS,
					   new_tid,
					   A_jail_scd_get, i_attr_val5)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_jail()",
				     A_jail_scd_get);
				return (-RSBAC_EWRITEFAILED);
			}
			/* Set jail_scd_modify for new process */
			if (rsbac_set_attr(SW_JAIL,
					   T_PROCESS,
					   new_tid,
					   A_jail_scd_modify,
					   i_attr_val6)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_jail()",
				     A_jail_scd_modify);
				return (-RSBAC_EWRITEFAILED);
			}
			return 0;
		} else
			return 0;

	case R_EXECUTE:
		switch (target) {
		case T_FILE:
			/* Adjust Linux caps */
			i_tid.process = caller_pid;
#ifdef CONFIG_RSBAC_SOFTMODE
			if (!rsbac_softmode)
#endif
			{
				if (rsbac_get_attr(SW_JAIL,
						   T_PROCESS,
						   i_tid,
						   A_jail_max_caps,
						   &i_attr_val1, FALSE)) {
					rsbac_ds_get_error
					    ("rsbac_adf_set_attr_jail()",
					     A_jail_max_caps);
				} else {
					struct cred *override_cred;

					override_cred = prepare_creds();
					if (!override_cred)
						return -ENOMEM;
					override_cred->cap_permitted.cap[0] &= i_attr_val1.jail_max_caps.cap[0];
					override_cred->cap_effective.cap[0] &= i_attr_val1.jail_max_caps.cap[0];
					override_cred->cap_inheritable.cap[0] &= i_attr_val1.jail_max_caps.cap[0];
					override_cred->cap_permitted.cap[1] &= i_attr_val1.jail_max_caps.cap[1];
					override_cred->cap_effective.cap[1] &= i_attr_val1.jail_max_caps.cap[1];
					override_cred->cap_inheritable.cap[1] &= i_attr_val1.jail_max_caps.cap[1];
					commit_creds(override_cred);
				}
			}
			return 0;

		/* all other cases are unknown */
		default:
			return 0;
		}

	case R_CREATE:
		switch (target) {
			case T_IPC:
				/* Get jail_id from process */
				i_tid.process = caller_pid;
				if (rsbac_get_attr(SW_JAIL,
						   T_PROCESS,
						   i_tid,
						   A_jail_id,
						   &i_attr_val1, FALSE)) {
					rsbac_ds_get_error
					    ("rsbac_adf_set_attr_jail()",
					     A_jail_id);
					return -RSBAC_EREADFAILED;
				}
				if (i_attr_val1.jail_id) {
					/* Set jail_id for new IPC */
					if (rsbac_set_attr(SW_JAIL,
							   T_IPC,
							   tid, A_jail_id, i_attr_val1)) {
						rsbac_ds_set_error
						    ("rsbac_adf_set_attr_jail()",
						     A_jail_id);
						return -RSBAC_EWRITEFAILED;
					}
				}
				return 0;

#ifdef CONFIG_RSBAC_JAIL_NET_ADJUST
			case T_NETOBJ:
				if (!tid.netobj.sock_p) {
					rsbac_printk(KERN_WARNING
						     "rsbac_adf_set_attr_jail(): NULL sock_p!\n");
					return 0;
				}
				if (!tid.netobj.sock_p->ops) {
					return 0;
				}
				switch (tid.netobj.sock_p->ops->family) {
				case AF_INET:
					i_tid.process = caller_pid;
					if ((err = rsbac_get_attr(SW_JAIL,
								  T_PROCESS,
								  i_tid,
								  A_jail_ip,
								  &i_attr_val1, TRUE))) {
						rsbac_ds_get_error
						    ("rsbac_adf_set_attr_jail()",
						     A_jail_ip);
						return -RSBAC_EREADFAILED;
					}
					if (i_attr_val1.jail_ip == INADDR_ANY)
						return 0;
					if ((err = rsbac_get_attr(SW_JAIL,
								  T_PROCESS,
								  i_tid,
								  A_jail_flags,
								  &i_attr_val2, TRUE))) {
						rsbac_ds_get_error
						    ("rsbac_adf_set_attr_jail()",
						     A_jail_flags);
						return -RSBAC_EREADFAILED;
					}
					if (i_attr_val2.
					    jail_flags & JAIL_auto_adjust_inet_any) {
						inet_sk(tid.netobj.sock_p->sk)->inet_rcv_saddr =
						    i_attr_val1.jail_ip;
						inet_sk(tid.netobj.sock_p->sk)->inet_saddr =
						    i_attr_val1.jail_ip;
					}
					return 0;

				default:
					break;
				}
#endif

			default:
				return 0;
		}

	case R_BIND:
		switch (target) {
			case T_IPC:
				/* Get jail_id from process */
				i_tid.process = caller_pid;
				if (rsbac_get_attr(SW_JAIL,
						   T_PROCESS,
						   i_tid,
						   A_jail_id,
						   &i_attr_val1, FALSE)) {
					rsbac_ds_get_error
					    ("rsbac_adf_set_attr_jail()",
					     A_jail_id);
					return -RSBAC_EREADFAILED;
				}
				if (i_attr_val1.jail_id) {
					/* Set jail_id for new IPC */
					if (rsbac_set_attr(SW_JAIL,
							   T_IPC,
							   tid, A_jail_id, i_attr_val1)) {
						rsbac_ds_set_error
						    ("rsbac_adf_set_attr_jail()",
						     A_jail_id);
						return -RSBAC_EWRITEFAILED;
					}
				}
				return 0;

#ifdef CONFIG_RSBAC_JAIL_NET_ADJUST
			case T_NETOBJ:
				if (!tid.netobj.sock_p) {
					rsbac_printk(KERN_WARNING
						     "rsbac_adf_set_attr_jail(): NULL sock_p!\n");
					return 0;
				}
				if (!tid.netobj.sock_p->ops) {
					return 0;
				}
				switch (tid.netobj.sock_p->ops->family) {
				case AF_INET:
					i_tid.process = caller_pid;
					if ((err = rsbac_get_attr(SW_JAIL,
								  T_PROCESS,
								  i_tid,
								  A_jail_ip,
								  &i_attr_val1, TRUE))) {
						rsbac_ds_get_error
						    ("rsbac_adf_set_attr_jail()",
						     A_jail_ip);
						return -RSBAC_EREADFAILED;
					}
					if (i_attr_val1.jail_ip == INADDR_ANY)
						return 0;
					if ((err = rsbac_get_attr(SW_JAIL,
								  T_PROCESS,
								  i_tid,
								  A_jail_flags,
								  &i_attr_val2, TRUE))) {
						rsbac_ds_get_error
						    ("rsbac_adf_set_attr_jail()",
						     A_jail_flags);
						return -RSBAC_EREADFAILED;
					}
					if (i_attr_val2.
					    jail_flags & JAIL_auto_adjust_inet_any) {
						inet_sk(tid.netobj.sock_p->sk)->inet_rcv_saddr =
						    i_attr_val1.jail_ip;
						inet_sk(tid.netobj.sock_p->sk)->inet_saddr =
						    i_attr_val1.jail_ip;
					}
					return 0;

				default:
					break;
				}
#endif
			default:
				return 0;
		}

	case R_CONNECT:
		switch (target) {
			case T_IPC:
				if (new_target != T_IPC)
					return 0;
				/* Get jail_id from old IPC */
				i_tid.process = caller_pid;
				if (rsbac_get_attr(SW_JAIL,
						   T_IPC,
						   tid,
						   A_jail_id,
						   &i_attr_val1, FALSE)) {
					rsbac_ds_get_error
					    ("rsbac_adf_set_attr_jail()",
					     A_jail_id);
					return -RSBAC_EREADFAILED;
				}
				if (i_attr_val1.jail_id) {
					/* Set jail_id for new IPC */
					if (rsbac_set_attr(SW_JAIL,
							   T_IPC,
							   new_tid, A_jail_id, i_attr_val1)) {
						rsbac_ds_set_error
						    ("rsbac_adf_set_attr_jail()",
						     A_jail_id);
						return -RSBAC_EWRITEFAILED;
					}
				}
				return 0;

			default:
				return 0;
		}

	default:
		return 0;
	}

	return 0;
}
