/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of the Access Control Decision     */
/* Facility (ADF) - Role Compatibility               */
/* File: rsbac/adf/rc/main.c                         */
/*                                                   */
/* Author and (c) 1999-2011: Amon Ott <ao@rsbac.org> */
/*                                                   */
/* Last modified: 21/Nov/2011                        */
/*************************************************** */

#include <linux/string.h>
#include <rsbac/types.h>
#include <rsbac/aci.h>
#include <rsbac/adf_main.h>
#include <rsbac/rc.h>
#include <rsbac/error.h>
#include <rsbac/debug.h>
#include <rsbac/helpers.h>
#include <rsbac/getname.h>
#include <rsbac/rc_getname.h>
#include <rsbac/rkmem.h>
#include <rsbac/network.h>
#include <rsbac/rc_types.h>
#include <rsbac/lists.h>

#if defined(CONFIG_RSBAC_RC_LEARN)
#ifdef CONFIG_RSBAC_RC_LEARN_TA
rsbac_list_ta_number_t rc_learn_ta = CONFIG_RSBAC_RC_LEARN_TA;
#else
rsbac_list_ta_number_t rc_learn_ta = 0;
#endif
#endif

/************************************************* */
/*          Internal Help functions                */
/************************************************* */

static enum rsbac_adf_req_ret_t
check_comp_rc(enum rsbac_target_t target,
	      union rsbac_target_id_t tid,
	      enum rsbac_adf_request_t request, rsbac_pid_t caller_pid)
{
	int err;
	union rsbac_target_id_t i_tid;
	enum rsbac_attribute_t i_attr;
	union rsbac_attribute_value_t i_attr_val1;
	union rsbac_attribute_value_t i_attr_val2;

	union rsbac_rc_target_id_t i_rc_subtid;
	enum rsbac_rc_item_t i_rc_item;

	/* get rc_role from process */
	i_tid.process = caller_pid;
	if ((err = rsbac_get_attr(SW_RC,
				  T_PROCESS,
				  i_tid,
				  A_rc_role, &i_attr_val1, TRUE))) {
		rsbac_pr_get_error(A_rc_role);
		return NOT_GRANTED;
	}
	switch (target) {
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_UNIXSOCK:
		i_rc_item = RI_type_comp_fd;
		i_attr = A_rc_type_fd;
		break;
	case T_DEV:
		i_rc_item = RI_type_comp_dev;
		i_attr = A_rc_type;
		break;
	case T_USER:
		i_rc_item = RI_type_comp_user;
		i_attr = A_rc_type;
		break;
	case T_PROCESS:
		i_rc_item = RI_type_comp_process;
		i_attr = A_rc_type;
		break;
	case T_IPC:
		i_rc_item = RI_type_comp_ipc;
		i_attr = A_rc_type;
		break;
#if defined(CONFIG_RSBAC_RC_UM_PROT)
	case T_GROUP:
		i_rc_item = RI_type_comp_group;
		i_attr = A_rc_type;
		break;
#endif
#if defined(CONFIG_RSBAC_RC_NET_DEV_PROT)
	case T_NETDEV:
		i_rc_item = RI_type_comp_netdev;
		i_attr = A_rc_type;
		break;
#endif
#if defined(CONFIG_RSBAC_RC_NET_OBJ_PROT)
	case T_NETTEMP:
		i_rc_item = RI_type_comp_nettemp;
		i_attr = A_rc_type_nt;
		break;
	case T_NETOBJ:
		i_rc_item = RI_type_comp_netobj;
		if (rsbac_net_remote_request(request))
			i_attr = A_remote_rc_type;
		else
			i_attr = A_local_rc_type;
		break;
#endif
	default:
		rsbac_printk(KERN_WARNING "check_comp_rc(): invalid target %i!\n",
			     target);
		return NOT_GRANTED;
	}

	/* get rc_type[_fd|_nt] from target */
	if ((err = rsbac_get_attr(SW_RC,
				  target,
				  tid, i_attr, &i_attr_val2, TRUE))) {
		rsbac_pr_get_error(i_attr);
		return NOT_GRANTED;
	}

	/* get type_comp_xxx of role */
	i_rc_subtid.type = i_attr_val2.rc_type;
	if (rsbac_rc_check_comp(i_attr_val1.rc_role,
				i_rc_subtid, i_rc_item, request))
		return GRANTED;
	else {
#ifdef CONFIG_RSBAC_DEBUG
		if (rsbac_debug_adf_rc) {
			char *tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

			if (tmp) {
				char *tmp2 =
				    rsbac_kmalloc(RSBAC_MAXNAMELEN);
				if (tmp2) {
#if defined(CONFIG_RSBAC_RC_LEARN)
					if (rsbac_rc_learn) {
						union rsbac_rc_target_id_t i_rc_tid;
						union rsbac_rc_item_value_t i_rc_value;

						i_rc_tid.role = i_attr_val1.rc_role;
#ifdef CONFIG_RSBAC_RC_LEARN_TA
						if (!rsbac_list_ta_exist(rc_learn_ta))
							rsbac_list_ta_begin(CONFIG_RSBAC_LIST_TRANS_MAX_TTL,
									&rc_learn_ta,
									RSBAC_ALL_USERS,
									RSBAC_RC_LEARN_TA_NAME,
									NULL);
#endif
						err = rsbac_rc_get_item (rc_learn_ta,
									RT_ROLE,
									i_rc_tid,
									i_rc_subtid,
									i_rc_item,
									&i_rc_value,
									NULL);
						if (!err) {
							i_rc_value.rights |= RSBAC_RC_RIGHTS_VECTOR(request);
							err = rsbac_rc_set_item (rc_learn_ta,
										RT_ROLE,
										i_rc_tid,
										i_rc_subtid,
										i_rc_item,
										i_rc_value,
										RSBAC_LIST_TTL_KEEP);
							if (!err) {
#ifdef CONFIG_RSBAC_LOG_PSEUDO
								u_int pseudo = 0;
								union rsbac_attribute_value_t i_attr_val3;

				          /* Get owner's logging pseudo */
						        	i_tid.user = current_uid();
				        			if (!rsbac_get_attr(SW_GEN,T_USER,i_tid,A_pseudo,&i_attr_val3,FALSE)) {
					        			pseudo = i_attr_val3.pseudo;
								}
								if (pseudo) {
									rsbac_printk(KERN_INFO "check_comp_rc(): learning mode: pid %u (%.15s), pseudo %u, rc_role %u, %s rc_type %u, right %s added to transaction %u!\n",
										     pid_nr(caller_pid),
										     current->comm,
										     pseudo,
										     i_attr_val1.rc_role,
										     get_target_name_only
										     (tmp, target),
										     i_attr_val2.rc_type,
										     get_rc_special_right_name
											     (tmp2, request),
										     rc_learn_ta);
								} else
#endif
								rsbac_printk(KERN_INFO "check_comp_rc(): learning mode: pid %u (%.15s), owner %u, rc_role %u, %s rc_type %u, right %s added to transaction %u!\n",
									     pid_nr(caller_pid),
									     current->comm,
									     current_uid(),
									     i_attr_val1.rc_role,
									     get_target_name_only
										     (tmp, target),
									     i_attr_val2.rc_type,
									     get_rc_special_right_name
										     (tmp2, request),
									     rc_learn_ta);
								rsbac_kfree(tmp2);
								rsbac_kfree(tmp);
								return GRANTED;
							}
						}
					}
#endif
					{
#ifdef CONFIG_RSBAC_LOG_PSEUDO
						u_int pseudo = 0;
						union rsbac_attribute_value_t i_attr_val3;

				          /* Get owner's logging pseudo */
				        	i_tid.user = current_uid();
				        	if (!rsbac_get_attr(SW_GEN,T_USER,i_tid,A_pseudo,&i_attr_val3,FALSE)) {
					        	pseudo = i_attr_val3.pseudo;
						}
						if (pseudo) {
							rsbac_pr_debug(adf_rc, "pid %u (%.15s), pseudo %u, rc_role %u, %s rc_type %u, request %s -> NOT_GRANTED!\n",
								     pid_nr(caller_pid),
								     current->comm,
								     pseudo,
								     i_attr_val1.rc_role,
								     get_target_name_only
								     (tmp, target),
								     i_attr_val2.rc_type,
								     get_rc_special_right_name
									     (tmp2, request));
						} else
#endif
						rsbac_pr_debug(adf_rc, "pid %u (%.15s), owner %u, rc_role %u, %s rc_type %u, request %s -> NOT_GRANTED!\n",
							     pid_nr(caller_pid),
							     current->comm,
							     current_uid(),
							     i_attr_val1.rc_role,
							     get_target_name_only
								     (tmp, target),
							     i_attr_val2.rc_type,
							     get_rc_special_right_name
								     (tmp2, request));
					}
					rsbac_kfree(tmp2);
				}
				rsbac_kfree(tmp);
			}
		}
#endif
		return NOT_GRANTED;
	}
}

static enum rsbac_adf_req_ret_t
check_comp_rc_scd(enum rsbac_rc_scd_type_t scd_type,
		  enum rsbac_adf_request_t request, rsbac_pid_t caller_pid)
{
	int err;
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val1;

	union rsbac_rc_target_id_t i_rc_subtid;

	/* get rc_role from process */
	i_tid.process = caller_pid;
	if ((err = rsbac_get_attr(SW_RC,
				  T_PROCESS,
				  i_tid,
				  A_rc_role, &i_attr_val1, TRUE))) {
		rsbac_pr_get_error(A_rc_role);
		return NOT_GRANTED;
	}
	/* get type_comp_scd of role */
	i_rc_subtid.type = scd_type;
	if (rsbac_rc_check_comp(i_attr_val1.rc_role,
				i_rc_subtid, RI_type_comp_scd, request)) {
		return GRANTED;
	} else {
#if defined(CONFIG_RSBAC_RC_LEARN) || defined(CONFIG_RSBAC_DEBUG)
		char tmp[RSBAC_MAXNAMELEN];
#endif

#if defined(CONFIG_RSBAC_RC_LEARN)
		if (rsbac_rc_learn) {
			union rsbac_rc_target_id_t i_rc_tid;
			union rsbac_rc_item_value_t i_rc_value;

			i_rc_tid.role = i_attr_val1.rc_role;
#ifdef CONFIG_RSBAC_RC_LEARN_TA
			if (!rsbac_list_ta_exist(rc_learn_ta))
				rsbac_list_ta_begin(CONFIG_RSBAC_LIST_TRANS_MAX_TTL,
						&rc_learn_ta,
						RSBAC_ALL_USERS,
						RSBAC_RC_LEARN_TA_NAME,
						NULL);
#endif
			err = rsbac_rc_get_item (rc_learn_ta,
						RT_ROLE,
						i_rc_tid,
						i_rc_subtid,
						RI_type_comp_scd,
						&i_rc_value,
						NULL);
			if (!err) {
				i_rc_value.rights |= RSBAC_RC_RIGHTS_VECTOR(request);
				err = rsbac_rc_set_item (rc_learn_ta,
							RT_ROLE,
							i_rc_tid,
							i_rc_subtid,
							RI_type_comp_scd,
							i_rc_value,
							RSBAC_LIST_TTL_KEEP);
				if (!err) {
#ifdef CONFIG_RSBAC_LOG_PSEUDO
					u_int pseudo = 0;
					union rsbac_attribute_value_t i_attr_val3;

	        /* Get owner's logging pseudo */
				        i_tid.user = current_uid();
				        if (!rsbac_get_attr(SW_GEN,T_USER,i_tid,A_pseudo,&i_attr_val3,FALSE)) {
					        pseudo = i_attr_val3.pseudo;
					}
					if (pseudo) {
						rsbac_printk(KERN_INFO "check_comp_rc_scd(): learning mode: pid %u (%.15s), pseudo %u, rc_role %i, scd_type %i, right %s added to transaction %u!\n",
							       pid_nr(caller_pid), current->comm, pseudo,
							       i_attr_val1.rc_role, scd_type,
							       get_request_name(tmp, request),
							       rc_learn_ta);
					} else
#endif
					rsbac_printk(KERN_INFO "check_comp_rc_scd(): learning mode: pid %u (%.15s), owner %u, rc_role %i, scd_type %i, right %s added to transaction %u!\n",
						       pid_nr(caller_pid), current->comm, current_uid(),
						       i_attr_val1.rc_role, scd_type,
						       get_request_name(tmp, request),
						       rc_learn_ta);
					return GRANTED;
				}
			}
		}
#endif
		{
#ifdef CONFIG_RSBAC_LOG_PSEUDO
		u_int pseudo = 0;
		union rsbac_attribute_value_t i_attr_val3;

	        /* Get owner's logging pseudo */
	        i_tid.user = current_uid();
	        if (!rsbac_get_attr(SW_GEN,T_USER,i_tid,A_pseudo,&i_attr_val3,FALSE)) {
		        pseudo = i_attr_val3.pseudo;
		}
		if (pseudo) {
			rsbac_pr_debug(adf_rc, "pid %u (%.15s), pseudo %u, rc_role %i, scd_type %i, request %s -> NOT_GRANTED!\n",
				       pid_nr(caller_pid), current->comm, pseudo,
				       i_attr_val1.rc_role, scd_type,
				       get_request_name(tmp, request));
		} else
#endif
		rsbac_pr_debug(adf_rc, "pid %u (%.15s), owner %u, rc_role %i, scd_type %i, request %s -> NOT_GRANTED!\n",
			       pid_nr(caller_pid), current->comm, current_uid(),
			       i_attr_val1.rc_role, scd_type,
			       get_request_name(tmp, request));
		return NOT_GRANTED;
		}
	}
}

static enum rsbac_adf_req_ret_t
rc_check_create(
	rsbac_pid_t caller_pid,
	enum rsbac_target_t target,
	union rsbac_rc_target_id_t tid,
	union rsbac_rc_target_id_t subtid,
	enum rsbac_rc_item_t item)
{
	if (rsbac_rc_check_comp(tid.role, subtid, item, R_CREATE))
		return GRANTED;
	else {
		char tmp[RSBAC_MAXNAMELEN];

#if defined(CONFIG_RSBAC_RC_LEARN)
		if (rsbac_rc_learn) {
			union rsbac_rc_item_value_t i_rc_value;
			int err;

#ifdef CONFIG_RSBAC_RC_LEARN_TA
			if (!rsbac_list_ta_exist(rc_learn_ta))
				rsbac_list_ta_begin(CONFIG_RSBAC_LIST_TRANS_MAX_TTL,
						&rc_learn_ta,
						RSBAC_ALL_USERS,
						RSBAC_RC_LEARN_TA_NAME,
						NULL);
#endif
			err = rsbac_rc_get_item (rc_learn_ta,
						RT_ROLE,
						tid,
						subtid,
						item,
						&i_rc_value,
						NULL);
			if (!err) {
				i_rc_value.rights |= RSBAC_RC_RIGHTS_VECTOR(R_CREATE);
				err = rsbac_rc_set_item (rc_learn_ta,
							RT_ROLE,
							tid,
							subtid,
							item,
							i_rc_value,
							RSBAC_LIST_TTL_KEEP);
				if (!err) {
#ifdef CONFIG_RSBAC_LOG_PSEUDO
					u_int pseudo = 0;
					union rsbac_target_id_t i_tid;
					union rsbac_attribute_value_t i_attr_val3;

				          /* Get owner's logging pseudo */
			        	i_tid.user = current_uid();
	        			if (!rsbac_get_attr(SW_GEN,T_USER,i_tid,A_pseudo,&i_attr_val3,FALSE)) {
		        			pseudo = i_attr_val3.pseudo;
					}
					if (pseudo) {
						rsbac_printk(KERN_INFO "rc_check_create(): learning mode: pid %u (%.15s), pseudo %u, rc_role %u, %s rc_type %u, right CREATE added to transaction %u!\n",
							     pid_nr(caller_pid),
							     current->comm,
							     pseudo,
							     tid.role,
							     get_target_name_only
							     (tmp, target),
							     subtid.type,
							     rc_learn_ta);
					} else
#endif
					rsbac_printk(KERN_INFO "rc_check_create(): learning mode: pid %u (%.15s), owner %u, rc_role %u, %s rc_type %u, right CREATE added to transaction %u!\n",
						     pid_nr(caller_pid),
						     current->comm,
						     current_uid(),
						     tid.role,
						     get_target_name_only
							     (tmp, target),
						     subtid.type,
						     rc_learn_ta);
					return GRANTED;
				}
			}
		}
#endif
		rsbac_printk(KERN_WARNING "rc_check_create(): rc_role %i has no CREATE right on its %s def_create_type %i -> NOT_GRANTED!\n",
			     tid.role,
			     get_target_name_only (tmp, target),
			     subtid.type);
		return NOT_GRANTED;
	}
}

/* exported for rc_syscalls.c */
int rsbac_rc_test_admin_roles(rsbac_rc_role_id_t t_role,
			      rsbac_boolean_t modify)
{
	int err;
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val1;
	union rsbac_rc_target_id_t i_rc_subtid;

	if (t_role > RC_role_max_value)
		return -RSBAC_EINVALIDVALUE;
	/* get rc_role of process */
	i_tid.process = task_pid(current);
	if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
				  i_tid, A_rc_role, &i_attr_val1, TRUE))) {
		rsbac_pr_get_error(A_rc_role);
		return -RSBAC_EREADFAILED;
	}

	i_rc_subtid.role = t_role;
	/* read_only? -> assign_roles membership is enough */
	if (!modify) {
		if (rsbac_rc_check_comp(i_attr_val1.rc_role,
					i_rc_subtid,
					RI_assign_roles, R_NONE))
			return 0;
		/* fall through */
	}
	/* check admin_roles of role */
	if (rsbac_rc_check_comp(i_attr_val1.rc_role,
				i_rc_subtid, RI_admin_roles, R_NONE))
		return 0;

	rsbac_pr_debug(adf_rc, 
			"rsbac_rc_test_admin_roles(): role %u not in admin roles of role %u, pid %u, user %u!\n",
			t_role,
			i_attr_val1.rc_role,
			current->pid,
			current_uid());
	return -EPERM;
}

/* exported for rc_syscalls.c */
int rsbac_rc_test_assign_roles(enum rsbac_target_t target,
			       union rsbac_target_id_t tid,
			       enum rsbac_attribute_t attr,
			       rsbac_rc_role_id_t t_role)
{
	int err;
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val1;
	union rsbac_attribute_value_t i_attr_val2;
	union rsbac_rc_target_id_t i_rc_subtid;

	if (target >= T_NONE)
		return -RSBAC_EINVALIDVALUE;
	/* get rc_role of process */
	i_tid.process = task_pid(current);
	if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
				  i_tid, A_rc_role, &i_attr_val1, TRUE))) {
		rsbac_pr_get_error(A_rc_role);
		return -RSBAC_EREADFAILED;
	}
	/* get old role of target */
	if ((err = rsbac_get_attr(SW_RC,
				  target,
				  tid, attr, &i_attr_val2, TRUE))) {
		rsbac_pr_get_error(attr);
		return -RSBAC_EREADFAILED;
	}

	i_rc_subtid.role = i_attr_val2.rc_role;
	if (!rsbac_rc_check_comp(i_attr_val1.rc_role,
				 i_rc_subtid, RI_assign_roles, R_NONE)) {
                rsbac_pr_debug(adf_rc, 
                               "rsbac_rc_test_assign_roles(): old role %u not in assign roles of role %u, pid %u, user %u!\n",
                               i_attr_val2.rc_role,
                               i_attr_val1.rc_role,
                               current->pid,
                               current_uid());
		return -EPERM;
	}
	i_rc_subtid.role = t_role;
	if (!rsbac_rc_check_comp(i_attr_val1.rc_role,
				 i_rc_subtid,
				 RI_assign_roles, R_NONE)) {
                rsbac_pr_debug(adf_rc, 
       	                       "rsbac_rc_test_assign_roles(): new role %u not in assign roles of role %u, pid %u, user %u!\n",
               	               t_role,
                       	       i_attr_val1.rc_role,
                               current->pid,
       	                       current_uid());
		return -EPERM;
	}
	return 0;
}

enum rsbac_adf_req_ret_t
rsbac_rc_check_type_comp(enum rsbac_target_t target,
			 rsbac_rc_type_id_t type,
			 enum rsbac_adf_request_t request,
			 rsbac_pid_t caller_pid)
{
	int err;
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val1;

	union rsbac_rc_target_id_t i_rc_subtid;
	enum rsbac_rc_item_t i_rc_item;

	if (!caller_pid)
		caller_pid = task_pid(current);
	/*
	 * we don't care about tried assignments of special type values,
	 * but deny other accesses to those
	 */
	if (type > RC_type_max_value) {
		if (request == RCR_ASSIGN)
			return GRANTED;
		else
			return NOT_GRANTED;
	}

	/* get rc_role from process */
	i_tid.process = caller_pid;
	if ((err = rsbac_get_attr(SW_RC,
				  T_PROCESS,
				  i_tid,
				  A_rc_role, &i_attr_val1, FALSE))) {
		rsbac_pr_get_error(A_rc_role);
		return NOT_GRANTED;
	}
	switch (target) {
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_UNIXSOCK:
	case T_FD:
		i_rc_item = RI_type_comp_fd;
		break;
	case T_DEV:
		i_rc_item = RI_type_comp_dev;
		break;
	case T_USER:
		i_rc_item = RI_type_comp_user;
		break;
	case T_PROCESS:
		i_rc_item = RI_type_comp_process;
		break;
	case T_IPC:
		i_rc_item = RI_type_comp_ipc;
		break;
#if defined(CONFIG_RSBAC_RC_UM_PROT)
	case T_GROUP:
		i_rc_item = RI_type_comp_group;
		break;
#endif
#if defined(CONFIG_RSBAC_RC_NET_DEV_PROT)
	case T_NETDEV:
		i_rc_item = RI_type_comp_netdev;
		break;
#endif
#if defined(CONFIG_RSBAC_RC_NET_OBJ_PROT)
	case T_NETTEMP:
		i_rc_item = RI_type_comp_nettemp;
		break;
	case T_NETOBJ:
		i_rc_item = RI_type_comp_netobj;
		break;
#endif

	default:
		rsbac_printk(KERN_WARNING "rsbac_rc_check_type_comp(): invalid target %i!\n",
			     target);
		return NOT_GRANTED;
	}
	/* check type_comp_xxx of role */
	i_rc_subtid.type = type;
	if (rsbac_rc_check_comp(i_attr_val1.rc_role,
				i_rc_subtid, i_rc_item, request))
		return GRANTED;
	else {
#ifdef CONFIG_RSBAC_DEBUG
		char tmp[RSBAC_MAXNAMELEN];
		rsbac_pr_debug(adf_rc, "rc_role is %i, rc_type is %i, request is %s -> NOT_GRANTED!\n",
			       i_attr_val1.rc_role, type,
			       get_rc_special_right_name(tmp, request));
#endif
		return NOT_GRANTED;
	}
}

/* exported for rc_syscalls.c */
int rsbac_rc_test_role_admin(rsbac_boolean_t modify)
{
	int err;
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val1;
	union rsbac_rc_target_id_t i_rc_tid;
	union rsbac_rc_item_value_t i_rc_item_val1;

	/* get rc_role of process */
	i_tid.process = task_pid(current);
	if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
				  i_tid, A_rc_role, &i_attr_val1, TRUE))) {
		rsbac_pr_get_error(A_rc_role);
		return -RSBAC_EREADFAILED;
	}

	/* get admin_type of role */
	i_rc_tid.role = i_attr_val1.rc_role;
	if ((err = rsbac_rc_get_item(0, RT_ROLE, i_rc_tid, i_rc_tid,	/* dummy */
				     RI_admin_type,
				     &i_rc_item_val1, NULL))) {
		rsbac_rc_pr_get_error(RI_admin_type);
		return -RSBAC_EREADFAILED;
	}

	/* allow, if RC_role_admin or (read_only and RC_system_admin) */
	if ((i_rc_item_val1.admin_type == RC_role_admin)
	    || (!modify && (i_rc_item_val1.admin_type == RC_system_admin)
	    )
	    )
		return 0;
	else
		return -EPERM;
}

/************************************************* */
/*          Externally visible functions           */
/************************************************* */

inline enum rsbac_adf_req_ret_t
rsbac_adf_request_rc(enum rsbac_adf_request_t request,
		     rsbac_pid_t caller_pid,
		     enum rsbac_target_t target,
		     union rsbac_target_id_t tid,
		     enum rsbac_attribute_t attr,
		     union rsbac_attribute_value_t attr_val,
		     rsbac_uid_t owner)
{
	int err;
	enum rsbac_adf_req_ret_t result = DO_NOT_CARE;
	union rsbac_attribute_value_t i_attr_val1;
	union rsbac_rc_target_id_t i_rc_tid;
	union rsbac_rc_target_id_t i_rc_subtid;
	union rsbac_rc_item_value_t i_rc_item_val1;
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val2;

	switch (request) {
	case R_SEARCH:
		switch (target) {
		case T_DIR:
		case T_FILE:
		case T_SYMLINK:
		case T_FIFO:
                case T_UNIXSOCK:
		case T_DEV:
#if defined(CONFIG_RSBAC_RC_NET_OBJ_PROT)
		case T_NETOBJ:
#endif
#if defined(CONFIG_RSBAC_RC_UM_PROT)
		case T_USER:
		case T_GROUP:
#endif
			return check_comp_rc
				(target, tid, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_CLOSE:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_UNIXSOCK:
		case T_DEV:
		case T_IPC:
#if defined(CONFIG_RSBAC_RC_NET_OBJ_PROT)
		case T_NETOBJ:
#endif
			return check_comp_rc
				(target, tid, request, caller_pid);

		default:
			return DO_NOT_CARE;
		}

	case R_GET_STATUS_DATA:
		switch (target) {
		case T_SCD:
			return check_comp_rc_scd
				(tid.scd, request, caller_pid);
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
		case T_UNIXSOCK:
		case T_IPC:
		case T_PROCESS:
		case T_DEV:
#if defined(CONFIG_RSBAC_RC_UM_PROT)
		case T_USER:
		case T_GROUP:
#endif
			return check_comp_rc
				(target, tid, request, caller_pid);

#if defined(CONFIG_RSBAC_RC_NET_DEV_PROT)
		case T_NETDEV:
			return check_comp_rc
				(target, tid, request, caller_pid);
#endif
#if defined(CONFIG_RSBAC_RC_NET_OBJ_PROT)
		case T_NETOBJ:
			return check_comp_rc
				(target, tid, request, caller_pid);
#endif

		default:
			return DO_NOT_CARE;
		}

	case R_SEND:
		switch (target) {
		case T_DEV:
#if defined(CONFIG_RSBAC_RC_NET_OBJ_PROT)
		case T_NETOBJ:
#endif
			return check_comp_rc
				(target, tid, request, caller_pid);

                case T_UNIXSOCK:
                case T_IPC:
#if defined(CONFIG_RSBAC_RC_NET_OBJ_UNIX_PROCESS)
			if (attr == A_process) {
				enum rsbac_adf_req_ret_t tmp_result;

				i_tid.process = attr_val.process;
				tmp_result = check_comp_rc(T_PROCESS, i_tid,
							R_SEND,
							caller_pid);
				if ((tmp_result == NOT_GRANTED)
				    || (tmp_result == UNDEFINED)
				    )
					return tmp_result;
			}
#endif				/* UNIX_PROCESS */
			return check_comp_rc
				(target, tid, request, caller_pid);


			/* all other cases are undefined */
		default:
			return DO_NOT_CARE;
		}

	case R_LISTEN:
	case R_NET_SHUTDOWN:
		switch (target) {
                case T_UNIXSOCK:
		case T_IPC:
#if defined(CONFIG_RSBAC_RC_NET_OBJ_PROT)
		case T_NETOBJ:
#endif
			return check_comp_rc
				(target, tid, request, caller_pid);

			/* all other cases are undefined */
		default:
			return DO_NOT_CARE;
		}
	case R_ACCEPT:
	case R_CONNECT:
	case R_RECEIVE:
		switch (target) {
                case T_UNIXSOCK:
		case T_IPC:
#if defined(CONFIG_RSBAC_RC_NET_OBJ_UNIX_PROCESS)
			if (attr == A_process) {
				enum rsbac_adf_req_ret_t tmp_result;

				i_tid.process = attr_val.process;
				tmp_result = check_comp_rc(T_PROCESS, i_tid,
							  request,
							  caller_pid);
				if ((tmp_result == NOT_GRANTED)
				    || (tmp_result == UNDEFINED)
				    )
					return tmp_result;
			}
#endif				/* UNIX_PROCESS */
			return check_comp_rc
				(target, tid, request, caller_pid);

#if defined(CONFIG_RSBAC_RC_NET_OBJ_PROT)
		case T_NETOBJ:
			return check_comp_rc
				(target, tid, request, caller_pid);
#endif

			/* all other cases are undefined */
		default:
			return DO_NOT_CARE;
		}

	case R_READ:
	case R_WRITE:
		switch (target) {
		case T_DIR:
#ifdef CONFIG_RSBAC_RW
		case T_FILE:
		case T_FIFO:
		case T_DEV:
#endif
#if defined(CONFIG_RSBAC_RC_UM_PROT)
		case T_USER:
		case T_GROUP:
#endif
#if defined(CONFIG_RSBAC_RC_NET_OBJ_PROT)
#if defined(CONFIG_RSBAC_NET_OBJ_RW)
		case T_NETTEMP:
#endif
#endif
			return check_comp_rc
				(target, tid, request, caller_pid);

#ifdef CONFIG_RSBAC_RW
		case T_IPC:
                case T_UNIXSOCK:
#if defined(CONFIG_RSBAC_RC_NET_OBJ_UNIX_PROCESS)
			if (attr == A_process) {
				enum rsbac_adf_req_ret_t tmp_result;

				i_tid.process = attr_val.process;
				if (request == R_READ)
					tmp_result =
					    check_comp_rc(T_PROCESS, i_tid,
							  R_RECEIVE,
							  caller_pid);
				else
					tmp_result =
					    check_comp_rc(T_PROCESS, i_tid,
							  R_SEND,
							  caller_pid);
				if ((tmp_result == NOT_GRANTED)
				    || (tmp_result == UNDEFINED)
				    )
					return tmp_result;
			}
#endif				/* UNIX_PROCESS */
			return check_comp_rc
				(target, tid, request, caller_pid);
#endif				/* RW */

		case T_SCD:
			return check_comp_rc_scd
				(tid.scd, request, caller_pid);

#if defined(CONFIG_RSBAC_RC_NET_OBJ_PROT)
#if defined(CONFIG_RSBAC_NET_OBJ_RW)
		case T_NETOBJ:
			return check_comp_rc
				(target, tid, request, caller_pid);
#endif
#endif

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_APPEND_OPEN:
	case R_READ_WRITE_OPEN:
		switch (target) {
		case T_FILE:
		case T_DEV:
		case T_FIFO:
		case T_IPC:
			return check_comp_rc
				(target, tid, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_MAP_EXEC:
		switch (target) {
		case T_FILE:
			return check_comp_rc
				(target, tid, request, caller_pid);
		case T_NONE:
			/* anonymous mapping */
			return check_comp_rc_scd
				(ST_other, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_CHANGE_GROUP:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
		case T_IPC:
#if defined(CONFIG_RSBAC_RC_UM_PROT)
		case T_USER:
#endif
			return check_comp_rc
				(target, tid, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_CHANGE_OWNER:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
		case T_IPC:
			return check_comp_rc
				(target, tid, request, caller_pid);

#ifdef CONFIG_RSBAC_USER_CHOWN
		case T_USER:
#if defined(CONFIG_RSBAC_AUTH)
			result = check_comp_rc(target, tid, request, caller_pid);
			if((result == GRANTED) || (result == DO_NOT_CARE))
				return result;
			i_tid.process = caller_pid;
			if ((err = rsbac_get_attr(SW_AUTH, T_PROCESS,
						  i_tid,
						  A_auth_last_auth,
						  &i_attr_val1, FALSE))) {
				rsbac_pr_get_error(A_auth_last_auth);
				return NOT_GRANTED;
			}
			if(i_attr_val1.auth_last_auth != tid.user)
				return NOT_GRANTED;
			else
				return check_comp_rc(target, tid, RCR_CHANGE_AUTHED_OWNER, caller_pid);
#else
			return check_comp_rc(target, tid, request, caller_pid);
#endif
#endif

		case T_PROCESS:
			/* get rc_role from process */
			if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
						  tid,
						  A_rc_role,
						  &i_attr_val1, FALSE))) {
				rsbac_pr_get_error(A_rc_role);
				return NOT_GRANTED;
			}
			/* get def_process_chown_type of role */
			i_rc_tid.role = i_attr_val1.rc_role;
			if ((err = rsbac_rc_get_item(0, RT_ROLE, i_rc_tid, i_rc_tid,	/* dummy */
						     RI_def_process_chown_type,
						     &i_rc_item_val1,
						     NULL))) {
				rsbac_rc_pr_get_error
				    (RI_def_process_chown_type);
				return NOT_GRANTED;
			}
			if ((i_rc_item_val1.type_id == RC_type_no_chown)
			    || (i_rc_item_val1.type_id ==
				RC_type_no_create)
			    )
				return NOT_GRANTED;
			else
				return GRANTED;

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_CHDIR:
		switch (target) {
		case T_DIR:
			return check_comp_rc
				(target, tid, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_CLONE:
		if (target == T_PROCESS) {
			/* check, whether we may create process of def_process_create_type */
			/* get rc_role from process */
			i_tid.process = caller_pid;
			if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
						  i_tid,
						  A_rc_role,
						  &i_attr_val1, FALSE))) {
				rsbac_pr_get_error(A_rc_role);
				return NOT_GRANTED;
			}
			/* get def_process_create_type of role */
			i_rc_tid.role = i_attr_val1.rc_role;
			if ((err = rsbac_rc_get_item(0,
						     RT_ROLE,
						     i_rc_tid,
						     i_rc_tid,
						     RI_def_process_create_type,
						     &i_rc_item_val1,
						     NULL))) {
				rsbac_rc_pr_get_error
				    (RI_def_process_create_type);
				return NOT_GRANTED;
			}
			switch (i_rc_item_val1.type_id) {
			case RC_type_no_create:
				rsbac_pr_debug(adf_rc, "pid %u (%.15s), owner %u, rc_role %u, def_process_create_type no_create, request CLONE -> NOT_GRANTED!\n",
					       pid_nr(caller_pid), current->comm,
					       current_uid(),
					       i_attr_val1.rc_role);
				return NOT_GRANTED;

			case RC_type_use_new_role_def_create:
			case RC_type_use_fd:
				/* error - complain and return error */
				rsbac_printk(KERN_WARNING "rsbac_adf_request_rc(): invalid type use_new_role_def_create in def_process_create_type of role %i!\n",
					     i_attr_val1.rc_role);
				return NOT_GRANTED;

			case RC_type_inherit_parent:
			case RC_type_inherit_process:
				return GRANTED;

			default:
				/* check, whether role has CREATE right to new type */
				/* check type_comp_process of role */
				i_rc_subtid.type = i_rc_item_val1.type_id;
				return rc_check_create(caller_pid,
							target,
							i_rc_tid,
							i_rc_subtid,
							RI_type_comp_process);
			}
		} else
			return DO_NOT_CARE;

		/* Creating dir or (pseudo) file IN target dir! */
	case R_CREATE:
		switch (target) {
		case T_DIR:
			/* check, whether we may create files/dirs in this dir */
			result =
			    check_comp_rc(target, tid, request,
					  caller_pid);
			if ((result != GRANTED) && (result != DO_NOT_CARE))
				return result;

			/* get rc_role from process */
			i_tid.process = caller_pid;
			if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
						  i_tid,
						  A_rc_role,
						  &i_attr_val1, FALSE))) {
				rsbac_pr_get_error(A_rc_role);
				return NOT_GRANTED;
			}
			/* Check, whether this process has a preselected type */
			i_tid.process = caller_pid;
			if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
						  i_tid,
						  A_rc_select_type,
						  &i_attr_val2, FALSE))) {
				rsbac_pr_get_error(A_rc_select_type);
				return NOT_GRANTED;
			}
			if (i_attr_val2.rc_select_type == RC_type_use_fd) {
				/* get def_fd_create_type of role */
				/* First get target dir's efftype */
				if ((err = rsbac_get_attr(SW_RC,
						  target,
						  tid,
						  A_rc_type_fd,
						  &i_attr_val2, TRUE))) {
					rsbac_pr_get_error(A_rc_type_fd);
					return NOT_GRANTED;
				}
				i_rc_tid.role = i_attr_val1.rc_role;
				i_rc_subtid.type = i_attr_val2.rc_type;
				if ((err = rsbac_rc_get_item(0, RT_ROLE, i_rc_tid, i_rc_subtid, RI_def_fd_ind_create_type, &i_rc_item_val1, NULL))) {	/* No individual create type -> try global */
					if ((err = rsbac_rc_get_item(0,
							     RT_ROLE,
							     i_rc_tid,
							     i_rc_subtid,
							     RI_def_fd_create_type,
							     &i_rc_item_val1,
							     NULL))) {
						rsbac_rc_pr_get_error
						    (RI_def_fd_create_type);
						return NOT_GRANTED;
					}
				}
			} else
				i_rc_item_val1.type_id = i_attr_val2.rc_select_type;
			
			switch (i_rc_item_val1.type_id) {
			case RC_type_inherit_parent:
				return GRANTED;
			case RC_type_no_create:
				rsbac_pr_debug(adf_rc, "pid %u (%.15s), owner %u, rc_role %u, def_fd_create_type no_create, request CREATE -> NOT_GRANTED!\n",
					       pid_nr(caller_pid), current->comm,
					       current_uid(),
					       i_attr_val1.rc_role);
				return NOT_GRANTED;
				break;

			case RC_type_use_new_role_def_create:
			case RC_type_inherit_process:
			case RC_type_use_fd:
				/* error - complain and return error */
				rsbac_printk(KERN_WARNING "rsbac_adf_request_rc(): invalid type use_new_role_def_create in def_fd_create_type of role %i!\n",
					     i_attr_val1.rc_role);
				return NOT_GRANTED;

			default:
				/* check, whether role has CREATE right to new type */
				/* get type_comp_fd of role */
				i_rc_tid.role = i_attr_val1.rc_role;
				i_rc_subtid.type = i_rc_item_val1.type_id;
				return rc_check_create(caller_pid,
							target,
							i_rc_tid,
							i_rc_subtid,
							RI_type_comp_fd);
			}

		case T_IPC:
			/* check, whether we may create IPC of def_ipc_create_type */
			/* get rc_role from process */
			i_tid.process = caller_pid;
			if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
						  i_tid,
						  A_rc_role,
						  &i_attr_val1, FALSE))) {
				rsbac_pr_get_error(A_rc_role);
				return NOT_GRANTED;
			}
			/* get def_ipc_create_type of role */
			i_rc_tid.role = i_attr_val1.rc_role;
			if ((err = rsbac_rc_get_item(0,
						     RT_ROLE,
						     i_rc_tid,
						     i_rc_tid,
						     RI_def_ipc_create_type,
						     &i_rc_item_val1,
						     NULL))) {
				rsbac_rc_pr_get_error
				    (RI_def_ipc_create_type);
				return NOT_GRANTED;
			}
			switch (i_rc_item_val1.type_id) {
			case RC_type_no_create:
				rsbac_pr_debug(adf_rc, "pid %u (%.15s), owner %u, rc_role %u, def_ipc_create_type no_create, request CREATE -> NOT_GRANTED!\n",
					       pid_nr(caller_pid), current->comm,
					       current_uid(),
					       i_attr_val1.rc_role);
				return NOT_GRANTED;

			case RC_type_use_new_role_def_create:
				/* error - complain and return error */
				rsbac_printk(KERN_WARNING "rsbac_adf_request_rc(): invalid type use_new_role_def_create in def_ipc_create_type of role %i!\n",
					     i_attr_val1.rc_role);
				return NOT_GRANTED;

			case RC_type_inherit_parent:
			case RC_type_inherit_process:
			case RC_type_use_fd:
				/* error - complain and return error */
				rsbac_printk(KERN_WARNING "rsbac_adf_request_rc(): invalid type inherit_parent in def_ipc_create_type of role %i!\n",
					     i_attr_val1.rc_role);
				return NOT_GRANTED;

			default:
				/* check, whether role has CREATE right to new type */
				/* get type_comp_ipc of role */
				i_rc_subtid.type = i_rc_item_val1.type_id;
				return rc_check_create(caller_pid,
							target,
							i_rc_tid,
							i_rc_subtid,
							RI_type_comp_ipc);
			}

#if defined(CONFIG_RSBAC_RC_UM_PROT)
		case T_USER:
			/* check, whether we may create USER of def_user_create_type */
			/* get rc_role from process */
			i_tid.process = caller_pid;
			if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
						  i_tid,
						  A_rc_role,
						  &i_attr_val1, FALSE))) {
				rsbac_pr_get_error(A_rc_role);
				return NOT_GRANTED;
			}
			/* get def_user_create_type of role */
			i_rc_tid.role = i_attr_val1.rc_role;
			if ((err = rsbac_rc_get_item(0,
						     RT_ROLE,
						     i_rc_tid,
						     i_rc_tid,
						     RI_def_user_create_type,
						     &i_rc_item_val1,
						     NULL))) {
				rsbac_rc_pr_get_error
				    (RI_def_user_create_type);
				return NOT_GRANTED;
			}
			switch (i_rc_item_val1.type_id) {
			case RC_type_no_create:
				rsbac_pr_debug(adf_rc, "pid %u (%.15s), owner %u, rc_role %u, def_user_create_type no_create, request CREATE -> NOT_GRANTED!\n",
					       pid_nr(caller_pid), current->comm,
					       current_uid(),
					       i_attr_val1.rc_role);
				return NOT_GRANTED;

			case RC_type_use_new_role_def_create:
				/* error - complain and return error */
				rsbac_printk(KERN_WARNING "rsbac_adf_request_rc(): invalid type use_new_role_def_create in def_user_create_type of role %i!\n",
					     i_attr_val1.rc_role);
				return NOT_GRANTED;

			case RC_type_inherit_parent:
			case RC_type_inherit_process:
			case RC_type_use_fd:
				/* error - complain and return error */
				rsbac_printk(KERN_WARNING "rsbac_adf_request_rc(): invalid type inherit_parent in def_user_create_type of role %i!\n",
					     i_attr_val1.rc_role);
				return NOT_GRANTED;

			default:
				/* check, whether role has CREATE right to new type */
				/* get type_comp_ipc of role */
				i_rc_subtid.type = i_rc_item_val1.type_id;
				return rc_check_create(caller_pid,
							target,
							i_rc_tid,
							i_rc_subtid,
							RI_type_comp_user);
			}

		case T_GROUP:
			/* check, whether we may create GROUP of def_group_create_type */
			/* get rc_role from process */
			i_tid.process = caller_pid;
			if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
						  i_tid,
						  A_rc_role,
						  &i_attr_val1, FALSE))) {
				rsbac_pr_get_error(A_rc_role);
				return NOT_GRANTED;
			}
			/* get def_group_create_type of role */
			i_rc_tid.role = i_attr_val1.rc_role;
			if ((err = rsbac_rc_get_item(0,
						     RT_ROLE,
						     i_rc_tid,
						     i_rc_tid,
						     RI_def_group_create_type,
						     &i_rc_item_val1,
						     NULL))) {
				rsbac_rc_pr_get_error
				    (RI_def_group_create_type);
				return NOT_GRANTED;
			}
			switch (i_rc_item_val1.type_id) {
			case RC_type_no_create:
				rsbac_pr_debug(adf_rc, "pid %u (%.15s), owner %u, rc_role %u, def_group_create_type no_create, request CREATE -> NOT_GRANTED!\n",
					       pid_nr(caller_pid), current->comm,
					       current_uid(),
					       i_attr_val1.rc_role);
				return NOT_GRANTED;

			case RC_type_use_new_role_def_create:
				/* error - complain and return error */
				rsbac_printk(KERN_WARNING "rsbac_adf_request_rc(): invalid type use_new_role_def_create in def_group_create_type of role %i!\n",
					     i_attr_val1.rc_role);
				return NOT_GRANTED;

			case RC_type_inherit_parent:
			case RC_type_inherit_process:
			case RC_type_use_fd:
				/* error - complain and return error */
				rsbac_printk(KERN_WARNING "rsbac_adf_request_rc(): invalid type inherit_parent in def_group_create_type of role %i!\n",
					     i_attr_val1.rc_role);
				return NOT_GRANTED;

			default:
				/* check, whether role has CREATE right to new type */
				/* get type_comp_ipc of role */
				i_rc_subtid.type = i_rc_item_val1.type_id;
				return rc_check_create(caller_pid,
							target,
							i_rc_tid,
							i_rc_subtid,
							RI_type_comp_group);
			}
#endif				/* RSBAC_RC_UM_PROT */

#if defined(CONFIG_RSBAC_RC_NET_OBJ_PROT)
		case T_NETTEMP:
			/* get rc_role from process */
			i_tid.process = caller_pid;
			if ((err = rsbac_get_attr(SW_RC,
						  T_PROCESS,
						  i_tid,
						  A_rc_role,
						  &i_attr_val1, FALSE))) {
				rsbac_pr_get_error(A_rc_role);
				return NOT_GRANTED;
			}
			/* get type_comp_xxx of role - we always use type GENERAL for CREATE */
			i_rc_tid.role = i_attr_val1.rc_role;
			i_rc_subtid.type = RSBAC_RC_GENERAL_TYPE;
			return rc_check_create(caller_pid,
						target,
						i_rc_tid,
						i_rc_subtid,
						RI_type_comp_nettemp);

		case T_NETOBJ:
			/* check, whether we may create NETOBJ of this type */
			return(check_comp_rc(target, tid, request, caller_pid));
#endif

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_DELETE:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
	        case T_UNIXSOCK:
		case T_IPC:
#if defined(CONFIG_RSBAC_RC_NET_OBJ_PROT)
		case T_NETTEMP:
		case T_NETOBJ:
#endif
#if defined(CONFIG_RSBAC_RC_UM_PROT)
		case T_USER:
		case T_GROUP:
#endif
			return check_comp_rc
				(target, tid, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_EXECUTE:
		switch (target) {
		case T_FILE:
			/* get rc_role from process */
			if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
						  tid,
						  A_rc_role,
						  &i_attr_val1, FALSE))) {
				rsbac_pr_get_error(A_rc_role);
				return NOT_GRANTED;
			}
			/* get def_process_execute_type of role */
			i_rc_tid.role = i_attr_val1.rc_role;
			if ((err = rsbac_rc_get_item(0,
						     RT_ROLE,
						     i_rc_tid,
						     i_rc_tid,
						     RI_def_process_execute_type,
						     &i_rc_item_val1,
						     NULL))) {
				rsbac_rc_pr_get_error
				    (RI_def_process_execute_type);
				return NOT_GRANTED;
			}
			if (i_rc_item_val1.type_id == RC_type_no_execute)
				return NOT_GRANTED;
			else
				return check_comp_rc
					(target, tid, request,
					 caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_GET_PERMISSIONS_DATA:
		switch (target) {
		case T_SCD:
			return check_comp_rc_scd
				(tid.scd, request, caller_pid);
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
	        case T_UNIXSOCK:
		case T_IPC:
		case T_DEV:
#if defined(CONFIG_RSBAC_RC_NET_OBJ_PROT)
		case T_NETOBJ:
#endif
#if defined(CONFIG_RSBAC_RC_UM_PROT)
		case T_USER:
		case T_GROUP:
#endif
			return check_comp_rc
				(target, tid, request, caller_pid);

		default:
			return DO_NOT_CARE;
		};

	case R_LINK_HARD:
		switch (target) {
		case T_FILE:
		case T_FIFO:
		case T_SYMLINK:
			return check_comp_rc
				(target, tid, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_MODIFY_ACCESS_DATA:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
		case T_UNIXSOCK:
			return check_comp_rc
				(target, tid, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_AUTHENTICATE:
		switch (target) {
		case T_USER:
			return check_comp_rc
				(target, tid, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_MODIFY_ATTRIBUTE:
		switch (attr) {	/* owner must be changed by other request to prevent inconsistency */
		case A_owner:
			return NOT_GRANTED;
		case A_rc_type:
		case A_local_rc_type:
		case A_remote_rc_type:
		case A_rc_type_fd:
		case A_rc_type_nt:
		case A_rc_select_type:
			/* Granted on target? */
			result =
			    check_comp_rc(target, tid, request,
					  caller_pid);
			if ((result == GRANTED)
			    || (result == DO_NOT_CARE)
			    ) {
				/* Granted on type? */
				if (   (target == T_NETTEMP)
				    && (attr == A_rc_type)
				   )
				   target = T_NETOBJ;
				result =
				    rsbac_rc_check_type_comp(target,
							     attr_val.
							     rc_type,
							     RCR_ASSIGN,
 							     caller_pid);
				if ((result == GRANTED)
				    || (result == DO_NOT_CARE)
				    )
					return result;
			}
			/* Classical admin_type check */
			if ((err = rsbac_rc_test_role_admin(TRUE)))
				return NOT_GRANTED;
			else
				return GRANTED;

		case A_rc_force_role:
		case A_rc_initial_role:
		case A_rc_role:
		case A_rc_def_role:
			/* Granted on target? */
			result =
			    check_comp_rc(target, tid, request,
					  caller_pid);
			if ((result == GRANTED)
			    || (result == DO_NOT_CARE)
			    ) {
				/* test assign_roles of process / modify */
				if (!
				    (err =
				     rsbac_rc_test_assign_roles(target,
								tid, attr,
								attr_val.
								rc_role)))
					return GRANTED;
			}
			/* Classical admin_type check */
			if (rsbac_rc_test_role_admin(TRUE))
				return NOT_GRANTED;
			else
				return GRANTED;

			/* you may only change a user's pseudo, if you also may assign her role */
		case A_pseudo:
			if (target != T_USER)
				return NOT_GRANTED;
			/* test assign_roles of process for user's role only */
			if (rsbac_rc_test_assign_roles
			    (target, tid, A_rc_def_role,
			     RC_role_inherit_user))
				return NOT_GRANTED;
			else
				return GRANTED;

#ifdef CONFIG_RSBAC_RC_GEN_PROT
		case A_log_array_low:
		case A_log_array_high:
		case A_log_program_based:
		case A_log_user_based:
		case A_symlink_add_remote_ip:
		case A_symlink_add_uid:
		case A_symlink_add_rc_role:
		case A_linux_dac_disable:
		case A_fake_root_uid:
		case A_audit_uid:
		case A_auid_exempt:
		case A_remote_ip:
		case A_vset:
		case A_program_file:
			/* Explicitely granted? */
			result =
			    check_comp_rc(target, tid, request,
					  caller_pid);
			if ((result == GRANTED)
			    || (result == DO_NOT_CARE)
			    )
				return result;
			/* Failed -> Classical admin_type check / modify */
			if (rsbac_rc_test_role_admin(TRUE))
				return NOT_GRANTED;
			else
				return GRANTED;
#endif

			/* All attributes (remove target!) */
		case A_none:
			switch (target) {
			case T_USER:
				/* test assign_roles of process for user's role */
				if ((err =
				     rsbac_rc_test_assign_roles(target,
								tid,
								A_rc_def_role,
								RC_role_inherit_user)))
					return NOT_GRANTED;
				else
					return GRANTED;

			default:
				/* Explicitely granted? */
				return check_comp_rc
					(target, tid, request,
					 caller_pid);
			}

#ifdef CONFIG_RSBAC_RC_AUTH_PROT
		case A_auth_may_setuid:
		case A_auth_may_set_cap:
		case A_auth_start_uid:
		case A_auth_start_euid:
		case A_auth_start_gid:
		case A_auth_start_egid:
		case A_auth_learn:
		case A_auth_add_f_cap:
		case A_auth_remove_f_cap:
		case A_auth_last_auth:
			/* may manipulate auth capabilities, if allowed in general... */
			result =
			    check_comp_rc_scd(RST_auth_administration,
					      request, caller_pid);
			if ((result == GRANTED)
			    || (result == DO_NOT_CARE)
			    ) {
				/* ...and for this target */
				result =
				    check_comp_rc(target, tid,
						  RCR_MODIFY_AUTH,
						  caller_pid);
				if ((result == GRANTED)
				    || (result == DO_NOT_CARE)
				    )
					return result;
			}
			/* Last chance: classical admin_type check */
			if ((err = rsbac_rc_test_role_admin(TRUE)))
				return NOT_GRANTED;
			else
				return GRANTED;
#endif
#if defined(CONFIG_RSBAC_RC_LEARN)
		case A_rc_learn:
			/* Only role admin */
			if ((err = rsbac_rc_test_role_admin(TRUE)))
				return NOT_GRANTED;
			else
				return GRANTED;
#endif

		default:
			return DO_NOT_CARE;
		}

	case R_MODIFY_PERMISSIONS_DATA:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
                case T_UNIXSOCK:
		case T_IPC:
		case T_DEV:
#if defined(CONFIG_RSBAC_RC_UM_PROT)
		case T_USER:
		case T_GROUP:
#endif
#if defined(CONFIG_RSBAC_RC_NET_OBJ_PROT)
		case T_NETOBJ:
#endif
			return check_comp_rc
				(target, tid, request, caller_pid);

		case T_SCD:
			return check_comp_rc_scd
				(tid.scd, request, caller_pid);

#ifdef CONFIG_RSBAC_ALLOW_DAC_DISABLE
		case T_NONE:
			/* may turn off Linux DAC, if compatible */
			return check_comp_rc_scd
				(ST_other, request, caller_pid);
#endif

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_MODIFY_SYSTEM_DATA:
		switch (target) {
		case T_SCD:
			return check_comp_rc_scd
				(tid.scd, request, caller_pid);

		case T_DEV:
		case T_PROCESS:
		case T_IPC:
#if defined(CONFIG_RSBAC_RC_NET_DEV_PROT)
		case T_NETDEV:
#endif
#if defined(CONFIG_RSBAC_RC_NET_OBJ_PROT)
		case T_NETOBJ:
#endif
			return check_comp_rc
				(target, tid, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_MOUNT:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_DEV:
			return check_comp_rc
				(target, tid, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_READ_ATTRIBUTE:
		switch (attr) {
		case A_rc_type:
		case A_rc_type_fd:
		case A_rc_type_nt:
		case A_rc_force_role:
		case A_rc_initial_role:
		case A_rc_role:
		case A_rc_def_role:
		case A_rc_select_type:
		case A_pseudo:
#ifdef CONFIG_RSBAC_RC_GEN_PROT
		case A_owner:
		case A_log_array_low:
		case A_log_array_high:
		case A_log_program_based:
		case A_log_user_based:
		case A_symlink_add_remote_ip:
		case A_symlink_add_uid:
		case A_symlink_add_rc_role:
		case A_linux_dac_disable:
		case A_fake_root_uid:
		case A_audit_uid:
		case A_auid_exempt:
		case A_remote_ip:
		case A_vset:
		case A_program_file:
#endif
			/* Explicitely granted? */
			result =
			    check_comp_rc(target, tid, request,
					  caller_pid);
			if ((result == GRANTED)
			    || (result == DO_NOT_CARE)
			    )
				return result;
			/* Failed -> Classical admin_type check / modify */
			if (rsbac_rc_test_role_admin(FALSE))
				return NOT_GRANTED;
			else
				return GRANTED;

#ifdef CONFIG_RSBAC_RC_AUTH_PROT
		case A_auth_may_setuid:
		case A_auth_may_set_cap:
		case A_auth_start_uid:
		case A_auth_start_euid:
		case A_auth_start_gid:
		case A_auth_start_egid:
		case A_auth_learn:
		case A_auth_add_f_cap:
		case A_auth_remove_f_cap:
		case A_auth_last_auth:
			/* may read auth capabilities, if compatible */
			result =
			    check_comp_rc_scd(RST_auth_administration,
					      request, caller_pid);
			if ((result == GRANTED)
			    || (result == DO_NOT_CARE)
			    )
				return result;
			/* Failed -> Classical admin_type check / modify */
			if (rsbac_rc_test_role_admin(FALSE))
				return NOT_GRANTED;
			else
				return GRANTED;
#endif

		default:
			return DO_NOT_CARE;
		}

	case R_READ_OPEN:
		switch (target) {
		case T_FILE:
		case T_FIFO:
                case T_UNIXSOCK:
		case T_DEV:
		case T_IPC:
			return check_comp_rc
				(target, tid, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_ADD_TO_KERNEL:
		switch (target) {
		case T_NONE:
			/* may add to kernel, if compatible */
			return check_comp_rc_scd
				(ST_other, request, caller_pid);

		case T_FILE:
		case T_DEV:
			return check_comp_rc
				(target, tid, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}


	case R_ALTER:
		/* only for IPC */
		switch (target) {
		case T_IPC:
			return check_comp_rc
				(target, tid, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_REMOVE_FROM_KERNEL:
		switch (target) {
		case T_NONE:
			return check_comp_rc_scd
				(ST_other, request, caller_pid);

		case T_FILE:
		case T_DEV:
			return check_comp_rc
				(target, tid, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_RENAME:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
                case T_UNIXSOCK:
#if defined(CONFIG_RSBAC_RC_UM_PROT)
		case T_USER:
		case T_GROUP:
#endif
			return check_comp_rc
				(target, tid, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_SEND_SIGNAL:
	case R_TRACE:
		if (target == T_PROCESS)
			return check_comp_rc
				(target, tid, request, caller_pid);
		else
			return DO_NOT_CARE;

	case R_SHUTDOWN:
		switch (target) {
		case T_NONE:
			return check_comp_rc_scd
				(ST_other, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_SWITCH_LOG:
		switch (target) {
		case T_NONE:
			return check_comp_rc_scd
				(ST_other, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_SWITCH_MODULE:
		switch (target) {
		case T_NONE:
			/* we need the switch_target */
			if (attr != A_switch_target)
				return NOT_GRANTED;
			/* do not care for other modules */
			if ((attr_val.switch_target != SW_RC)
#ifdef CONFIG_RSBAC_SOFTMODE
			    && (attr_val.switch_target != SW_SOFTMODE)
#endif
#ifdef CONFIG_RSBAC_FREEZE
			    && (attr_val.switch_target != SW_FREEZE)
#endif
#ifdef CONFIG_RSBAC_RC_AUTH_PROT
			    && (attr_val.switch_target != SW_AUTH)
#endif
			    )
				return DO_NOT_CARE;
			return check_comp_rc_scd
				(ST_other, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_TERMINATE:
		return DO_NOT_CARE;

	case R_TRUNCATE:
		switch (target) {
		case T_FILE:
			return check_comp_rc
				(target, tid, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_WRITE_OPEN:
		switch (target) {
		case T_FILE:
		case T_DEV:
		case T_FIFO:
                case T_UNIXSOCK:
		case T_IPC:
			return check_comp_rc
				(target, tid, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}

	case R_UMOUNT:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_DEV:
			return check_comp_rc
				(target, tid, request, caller_pid);

			/* all other cases are unknown */
		default:
			return DO_NOT_CARE;
		}


#if defined(CONFIG_RSBAC_NET)
	case R_BIND:
		switch (target) {
#if defined(CONFIG_RSBAC_RC_NET_DEV_PROT)
		case T_NETDEV:
			return check_comp_rc
				(target, tid, request, caller_pid);
#endif

#if defined(CONFIG_RSBAC_RC_NET_OBJ_PROT)
		case T_NETOBJ:
			return check_comp_rc
				(target, tid, request, caller_pid);
#endif

			/* all other cases are undefined */
		default:
			return DO_NOT_CARE;
		}
#endif

	case R_IOCTL:
		switch (target) {
		case T_DEV:
                case T_UNIXSOCK:
		case T_IPC:
			return check_comp_rc
				(target, tid, request, caller_pid);
#if defined(CONFIG_RSBAC_RC_NET_OBJ_PROT)
		case T_NETOBJ:
#endif
			return check_comp_rc
				(target, tid, request, caller_pid);

		default:
			return DO_NOT_CARE;
		}

	case R_LOCK:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
                case T_UNIXSOCK:
			return check_comp_rc
				(target, tid, request, caller_pid);

		default:
			return DO_NOT_CARE;
		}
	case RCR_SELECT:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
                case T_UNIXSOCK:
			return check_comp_rc
				(target, tid, request, caller_pid);
		default:
			return DO_NOT_CARE;
		}
	default:
		return DO_NOT_CARE;
	}

	return result;
}

/*****************************************************************************/
/* If the request returned granted and the operation is performed,           */
/* the following function can be called by the AEF to get all aci set        */
/* correctly. For write accesses that are performed fully within the kernel, */
/* this is usually not done to prevent extra calls, including R_CLOSE for    */
/* cleaning up. Because of this, the write boundary is not adjusted - there  */
/* is no user-level writing anyway...                                        */
/* The second instance of target specification is the new target, if one has */
/* been created, otherwise its values are ignored.                           */
/* On success, 0 is returned, and an error from rsbac/error.h otherwise.     */

inline int rsbac_adf_set_attr_rc(enum rsbac_adf_request_t request,
			  rsbac_pid_t caller_pid,
			  enum rsbac_target_t target,
			  union rsbac_target_id_t tid,
			  enum rsbac_target_t new_target,
			  union rsbac_target_id_t new_tid,
			  enum rsbac_attribute_t attr,
			  union rsbac_attribute_value_t attr_val,
			  rsbac_uid_t owner)
{
	int err;
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val1;
	union rsbac_attribute_value_t i_attr_val2;
	union rsbac_rc_target_id_t i_rc_tid;
	union rsbac_rc_target_id_t i_rc_subtid;
	union rsbac_rc_item_value_t i_rc_item_val1;

	switch (request) {
	case R_CLOSE:
	case R_ACCEPT:
	case R_READ:
		return 0;
	case R_CHANGE_OWNER:
		switch (target) {
		case T_PROCESS:
			/* setting owner for process is done in main dispatcher */
			/* Here we have to adjust the rc_type and set the rc_role */
			/* to the new owner's rc_def_role */
			if (attr != A_owner)
				return -RSBAC_EINVALIDATTR;

			/* get old rc_role from process */
			i_tid.process = caller_pid;
			if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
						  i_tid,
						  A_rc_role,
						  &i_attr_val1, TRUE))) {
				rsbac_pr_get_error(A_rc_role);
				return -RSBAC_EREADFAILED;
			}
			/* get def_process_chown_type of old role */
			i_rc_tid.role = i_attr_val1.rc_role;
			if ((err = rsbac_rc_get_item(0,
						     RT_ROLE,
						     i_rc_tid,
						     i_rc_tid,
						     RI_def_process_chown_type,
						     &i_rc_item_val1,
						     NULL))) {
				rsbac_rc_pr_get_error
				    (RI_def_process_chown_type);
				return -RSBAC_EREADFAILED;
			}

			/* get rc_force_role from process */
			i_tid.process = caller_pid;
			if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
						  i_tid,
						  A_rc_force_role,
						  &i_attr_val1, TRUE))) {
				rsbac_pr_get_error(A_rc_force_role);
				return -RSBAC_EREADFAILED;
			}
			/* only set to user's rc_def_role, if indicated by force_role, otherwise keep */
			if ((i_attr_val1.rc_force_role ==
			     RC_role_inherit_user)
			    || (i_attr_val1.rc_force_role ==
				RC_role_inherit_up_mixed)
			    ) {
				/* get rc_def_role from new owner */
				i_tid.user = attr_val.owner;
				if ((err = rsbac_get_attr(SW_RC, T_USER,
							  i_tid,
							  A_rc_def_role,
							  &i_attr_val1,
							  TRUE))) {
					rsbac_pr_get_error(A_rc_def_role);
					return -RSBAC_EREADFAILED;
				}
				/* check rc_def_role, warn, if unusable */
				if (i_attr_val1.rc_def_role >
				    RC_role_max_value) {
					rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_rc(): rc_def_role %u of user %u is higher than MAX_ROLE %u, setting role of process %u to GENERAL_ROLE %u!\n",
						     i_attr_val1.
						     rc_def_role,
						     attr_val.owner,
						     RC_role_max_value,
						     pid_nr(caller_pid),
						     RSBAC_RC_GENERAL_ROLE);
					i_attr_val1.rc_def_role =
					    RSBAC_RC_GENERAL_ROLE;
				}
				/* set new rc_role for process */
				i_tid.process = caller_pid;
				if ((err = rsbac_set_attr(SW_RC, T_PROCESS,
							  i_tid,
							  A_rc_role,
							  i_attr_val1))) {
					rsbac_pr_set_error(A_rc_role);
					return -RSBAC_EWRITEFAILED;
				}
			} else
			    /* set it to the force_role, if real role) */
			if ((i_attr_val1.rc_force_role <= RC_role_max_value)
			    ) {
				/* set new rc_role for process */
				i_tid.process = caller_pid;
				if ((err = rsbac_set_attr(SW_RC, T_PROCESS,
							  i_tid,
							  A_rc_role,
							  i_attr_val1))) {
					rsbac_pr_set_error(A_rc_role);
					return -RSBAC_EWRITEFAILED;
				}
			}

			/* adjust type: switch on def_process_chown_type of old role */
			switch (i_rc_item_val1.type_id) {
			case RC_type_inherit_parent:
			case RC_type_inherit_process:
				/* keep old type */
				break;
			case RC_type_use_new_role_def_create:
				/* get new rc_role from process */
				i_tid.process = caller_pid;
				if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
							  i_tid,
							  A_rc_role,
							  &i_attr_val1, TRUE))) {
					rsbac_pr_get_error(A_rc_role);
					return -RSBAC_EREADFAILED;
				}
				/* Cannot adjust, if new role is no real role */
				if (i_attr_val1.rc_role >
				    RC_role_max_value)
					break;
				/* get def_process_create_type of new role */
				i_rc_tid.role = i_attr_val1.rc_role;
				if ((err = rsbac_rc_get_item(0,
							     RT_ROLE,
							     i_rc_tid,
							     i_rc_tid,
							     RI_def_process_create_type,
							     &i_rc_item_val1,
							     NULL))) {
					rsbac_rc_pr_get_error
					    (RI_def_process_create_type);
					return -RSBAC_EREADFAILED;
				}
				switch (i_rc_item_val1.type_id) {
				case RC_type_inherit_parent:
				case RC_type_inherit_process:
					/* keep old type */
					break;
				case RC_type_use_new_role_def_create:
					/* error - complain, but keep type (inherit) */
					rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_rc(): invalid type use_new_role_def_create in def_process_create_type of role %i!\n",
						     i_attr_val1.rc_role);
					break;
				case RC_type_no_create:
					/* set rc_type for process to general */
					i_rc_item_val1.type_id =
					    RSBAC_RC_GENERAL_TYPE;
					/* fall through */
				default:
					/* set rc_type for process */
					i_attr_val1.rc_type =
					    i_rc_item_val1.type_id;
					if ((err =
					     rsbac_set_attr(SW_RC, T_PROCESS,
							    i_tid,
							    A_rc_type,
							    i_attr_val1)))
					{
						rsbac_pr_set_error(A_rc_type);
						return -RSBAC_EWRITEFAILED;
					}
				}
				break;
			case RC_type_no_create:
			case RC_type_no_chown:
				/* set rc_type for process to general */
				i_rc_item_val1.type_id =
				    RSBAC_RC_GENERAL_TYPE;
				/* fall through */
			default:
				/* set rc_type for process */
				i_attr_val1.rc_type =
				    i_rc_item_val1.type_id;
				if ((err =
				     rsbac_set_attr(SW_RC, T_PROCESS, i_tid,
						    A_rc_type,
						    i_attr_val1))) {
					rsbac_pr_set_error(A_rc_type);
					return -RSBAC_EWRITEFAILED;
				}
			}

			return 0;

			/* all other cases */
		default:
			return 0;
		}

	case R_CLONE:
		if (target == T_PROCESS) {
			/* get rc_role from process */
			if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
						  tid,
						  A_rc_role,
						  &i_attr_val1, FALSE))) {
				rsbac_pr_get_error(A_rc_role);
				return -RSBAC_EREADFAILED;
			}

			/* get rc_force_role from process */
			if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
						  tid,
						  A_rc_force_role,
						  &i_attr_val2, FALSE))) {
				rsbac_pr_get_error(A_rc_force_role);
				return -RSBAC_EREADFAILED;
			}

			/* set rc_role for new process */
			if ((err = rsbac_set_attr(SW_RC, T_PROCESS,
						  new_tid,
						  A_rc_role,
						  i_attr_val1))) {
				rsbac_pr_set_error(A_rc_role);
				return -RSBAC_EWRITEFAILED;
			}

			/* set rc_force_role for new process */
			if ((err = rsbac_set_attr(SW_RC, T_PROCESS,
						  new_tid,
						  A_rc_force_role,
						  i_attr_val2))) {
				rsbac_pr_set_error(A_rc_force_role);
				return -RSBAC_EWRITEFAILED;
			}

			/* get def_process_create_type of role */
			i_rc_tid.role = i_attr_val1.rc_role;
			if ((err = rsbac_rc_get_item(0,
						     RT_ROLE,
						     i_rc_tid,
						     i_rc_tid,
						     RI_def_process_create_type,
						     &i_rc_item_val1,
						     NULL))) {
				rsbac_rc_pr_get_error
				    (RI_def_process_create_type);
				return -RSBAC_EREADFAILED;
			}
			switch (i_rc_item_val1.type_id) {
			case RC_type_inherit_parent:
			case RC_type_inherit_process:
				/* copy old type */
				/* get rc_type from old process */
				if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
							  tid,
							  A_rc_type,
							  &i_attr_val1,
							  FALSE))) {
					rsbac_pr_get_error(A_rc_type);
					return -RSBAC_EREADFAILED;
				}
				/* set rc_type for new process */
				if ((err = rsbac_set_attr(SW_RC, T_PROCESS,
							  new_tid,
							  A_rc_type,
							  i_attr_val1))) {
					rsbac_pr_set_error(A_rc_type);
					return -RSBAC_EWRITEFAILED;
				}
				break;
			case RC_type_no_create:
				return -RSBAC_EDECISIONMISMATCH;
			case RC_type_use_new_role_def_create:
				/* error - complain, but keep type (inherit) */
				rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_rc(): invalid type use_new_role_def_create in def_process_create_type of role %i!\n",
					     i_attr_val1.rc_role);
				return -RSBAC_EINVALIDVALUE;
			default:
				/* set rc_type for new process */
				i_attr_val1.rc_type =
				    i_rc_item_val1.type_id;
				if ((err =
				     rsbac_set_attr(SW_RC, T_PROCESS, new_tid,
						    A_rc_type,
						    i_attr_val1))) {
					rsbac_pr_set_error(A_rc_type);
					return -RSBAC_EWRITEFAILED;
				}
			}
			return 0;
		} else
			return 0;

	case R_CREATE:
		switch (target) {
			/* Creating dir or (pseudo) file IN target dir! */
		case T_DIR:
			/* Mode of created item is ignored! */
			/* check for select_fd_type being set for calling
			 * process and enforce it if set. */
			i_tid.process = caller_pid;
			if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
						  i_tid,
						  A_rc_select_type,
						  &i_attr_val1, FALSE))) {
				rsbac_pr_get_error(A_rc_select_type);
				return -RSBAC_EREADFAILED;
			}
			if (i_attr_val1.rc_select_type != RC_type_use_fd) {
				i_attr_val2.rc_type_fd = i_attr_val1.rc_select_type;
				/* rc_select_type is one use only so we reset it
				 * to default value first.
				 * value to be set already backup'ed. */
				i_attr_val1.rc_select_type = RC_type_use_fd;
				if ((err = rsbac_set_attr(SW_RC, T_PROCESS,
						         i_tid, A_rc_select_type,
						         i_attr_val1)))
				{
					rsbac_printk("rsbac_adf_set_attr_rc(): unable to reset rc_select_type to default value!\n");
				}
				if ((err = rsbac_set_attr(SW_RC, new_target,
							  new_tid, A_rc_type_fd,
							  i_attr_val2)))
				{
					rsbac_pr_set_error(A_rc_type_fd);
					return -RSBAC_EWRITEFAILED;
				}
				return 0;
								
			}
			/* get rc_role from process */
			i_tid.process = caller_pid;
			if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
						  i_tid,
						  A_rc_role,
						  &i_attr_val1, FALSE))) {
				rsbac_pr_get_error(A_rc_role);
				return -RSBAC_EREADFAILED;
			}
			/* get def_fd_create_type of role */
			/* First get target dir's efftype */
			if ((err = rsbac_get_attr(SW_RC,
						  target,
						  tid,
						  A_rc_type_fd,
						  &i_attr_val2, TRUE))) {
				rsbac_pr_get_error(A_rc_type_fd);
				return -RSBAC_EREADFAILED;
			}
			i_rc_tid.role = i_attr_val1.rc_role;
			switch(new_target) {
				case T_UNIXSOCK:
					i_rc_subtid.type = i_attr_val2.rc_type;
					if ((err = rsbac_rc_get_item(0,
								     RT_ROLE,
								     i_rc_tid,
								     i_rc_subtid,
								     RI_def_unixsock_create_type,
								     &i_rc_item_val1,
								     NULL))) {
						rsbac_rc_pr_get_error
						    (RI_def_unixsock_create_type);
						return -RSBAC_EREADFAILED;
					}
					if(i_rc_item_val1.type_id != RC_type_use_fd)
						break;
					/* fall through */
				default:
					i_rc_subtid.type = i_attr_val2.rc_type;
					if ((err = rsbac_rc_get_item(0, RT_ROLE, i_rc_tid, i_rc_subtid, RI_def_fd_ind_create_type, &i_rc_item_val1, NULL))) {	/* No individual create type -> try global */
						if ((err = rsbac_rc_get_item(0,
									     RT_ROLE,
									     i_rc_tid,
									     i_rc_subtid,
									     RI_def_fd_create_type,
									     &i_rc_item_val1,
									     NULL))) {
							rsbac_rc_pr_get_error
							    (RI_def_fd_create_type);
							return -RSBAC_EREADFAILED;
						}
					}
			}
			switch (i_rc_item_val1.type_id) {
			case RC_type_no_create:
				return -RSBAC_EDECISIONMISMATCH;
				break;

			case RC_type_use_new_role_def_create:
			case RC_type_inherit_process:
				/* error - complain and return error */
				rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_rc(): invalid type inherit_process or use_new_role_def_create in def_fd_create_type or def_unixsock_create_type of role %i!\n",
					     i_attr_val1.rc_role);
				return -RSBAC_EINVALIDVALUE;

			case RC_type_inherit_parent:
			default:
				/* get type from new target */
				if ((err = rsbac_get_attr(SW_RC, new_target,
							  new_tid,
							  A_rc_type_fd,
							  &i_attr_val1,
							  FALSE))) {
					rsbac_pr_get_error(A_rc_type_fd);
					return -RSBAC_EREADFAILED;
				}
				/* set it for new target, if different */
				if (i_attr_val1.rc_type_fd !=
				    i_rc_item_val1.type_id) {
					i_attr_val1.rc_type_fd =
					    i_rc_item_val1.type_id;
					if ((err =
					     rsbac_set_attr(SW_RC, new_target,
							    new_tid,
							    A_rc_type_fd,
							    i_attr_val1)))
					{
						rsbac_pr_set_error(A_rc_type_fd);
						return -RSBAC_EWRITEFAILED;
					}
				}
			}
			return 0;

		case T_IPC:
			/* get rc_role from process */
			i_tid.process = caller_pid;
			if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
						  i_tid,
						  A_rc_role,
						  &i_attr_val1, FALSE))) {
				rsbac_pr_get_error(A_rc_role);
				return -RSBAC_EREADFAILED;
			}
			/* get def_ipc_create_type of role */
			i_rc_tid.role = i_attr_val1.rc_role;
			if ((err = rsbac_rc_get_item(0,
						     RT_ROLE,
						     i_rc_tid,
						     i_rc_tid,
						     RI_def_ipc_create_type,
						     &i_rc_item_val1,
						     NULL))) {
				rsbac_rc_pr_get_error
				    (RI_def_ipc_create_type);
				return -RSBAC_EREADFAILED;
			}
			switch (i_rc_item_val1.type_id) {
			case RC_type_no_create:
				return -RSBAC_EDECISIONMISMATCH;
				break;

			case RC_type_use_new_role_def_create:
				/* error - complain and return error */
				rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_rc(): invalid type use_new_role_def_create in def_ipc_create_type of role %i!\n",
					     i_attr_val1.rc_role);
				return -RSBAC_EINVALIDVALUE;

			case RC_type_inherit_parent:
			case RC_type_inherit_process:
				/* error - complain and return error */
				rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_rc(): invalid type inherit_parent in def_ipc_create_type of role %i!\n",
					     i_attr_val1.rc_role);
				return -RSBAC_EINVALIDVALUE;

			default:
				/* set rc_type for ipc target */
				i_attr_val1.rc_type =
				    i_rc_item_val1.type_id;
				/* get type from target */
				if ((err = rsbac_get_attr(SW_RC,
							  target,
							  tid,
							  A_rc_type,
							  &i_attr_val2,
							  FALSE))) {
					rsbac_pr_get_error(A_rc_type);
					return -RSBAC_EREADFAILED;
				}
				/* set it for new target, if different */
				if (i_attr_val1.rc_type !=
				    i_attr_val2.rc_type) {
					if ((err =
					     rsbac_set_attr(SW_RC, target,
							    tid, A_rc_type,
							    i_attr_val1)))
					{
						rsbac_pr_set_error
						    (A_rc_type);
						return -RSBAC_EWRITEFAILED;
					}
				}
			}
			return 0;

		case T_USER:
			/* get rc_role from process */
			i_tid.process = caller_pid;
			if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
						  i_tid,
						  A_rc_role,
						  &i_attr_val1, FALSE))) {
				rsbac_pr_get_error(A_rc_role);
				return -RSBAC_EREADFAILED;
			}
			/* get def_user_create_type of role */
			i_rc_tid.role = i_attr_val1.rc_role;
			if ((err = rsbac_rc_get_item(0,
						     RT_ROLE,
						     i_rc_tid,
						     i_rc_tid,
						     RI_def_user_create_type,
						     &i_rc_item_val1,
						     NULL))) {
				rsbac_rc_pr_get_error
				    (RI_def_user_create_type);
				return -RSBAC_EREADFAILED;
			}
			switch (i_rc_item_val1.type_id) {
			case RC_type_no_create:
				rsbac_pr_debug(adf_rc, "pid %u (%.15s), owner %u, rc_role %u, def_user_create_type no_create, request CREATE -> NOT_GRANTED!\n",
					       pid_nr(caller_pid), current->comm,
					       current_uid(),
					       i_attr_val1.rc_role);
				return -RSBAC_EDECISIONMISMATCH;

			case RC_type_use_new_role_def_create:
				/* error - complain and return error */
				rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_rc(): invalid type use_new_role_def_create in def_user_create_type of role %i!\n",
					     i_attr_val1.rc_role);
				return -RSBAC_EINVALIDVALUE;

			case RC_type_inherit_parent:
			case RC_type_inherit_process:
				/* error - complain and return error */
				rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_rc(): invalid type inherit_parent in def_user_create_type of role %i!\n",
					     i_attr_val1.rc_role);
				return -RSBAC_EINVALIDVALUE;

			default:
				/* set rc_type for user target */
				i_attr_val1.rc_type =
				    i_rc_item_val1.type_id;
				/* get type from target */
				if ((err = rsbac_get_attr(SW_RC,
							  target,
							  tid,
							  A_rc_type,
							  &i_attr_val2,
							  TRUE))) {
					rsbac_pr_get_error(A_rc_type);
					return -RSBAC_EREADFAILED;
				}
				/* set it for new target, if different */
				if (i_attr_val1.rc_type !=
				    i_attr_val2.rc_type) {
					if ((err =
					     rsbac_set_attr(SW_RC, target,
							    tid, A_rc_type,
							    i_attr_val1)))
					{
						rsbac_pr_set_error
						    (A_rc_type);
						return -RSBAC_EWRITEFAILED;
					}
				}
			}
			return 0;

		case T_GROUP:
			/* get rc_role from process */
			i_tid.process = caller_pid;
			if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
						  i_tid,
						  A_rc_role,
						  &i_attr_val1, TRUE))) {
				rsbac_pr_get_error(A_rc_role);
				return -RSBAC_EREADFAILED;
			}
			/* get def_group_create_type of role */
			i_rc_tid.role = i_attr_val1.rc_role;
			if ((err = rsbac_rc_get_item(0,
						     RT_ROLE,
						     i_rc_tid,
						     i_rc_tid,
						     RI_def_group_create_type,
						     &i_rc_item_val1,
						     NULL))) {
				rsbac_rc_pr_get_error
				    (RI_def_group_create_type);
				return -RSBAC_EREADFAILED;
			}
			switch (i_rc_item_val1.type_id) {
			case RC_type_no_create:
				rsbac_pr_debug(adf_rc, "pid %u (%.15s), owner %u, rc_role %u, def_group_create_type no_create, request CREATE -> NOT_GRANTED!\n",
					       pid_nr(caller_pid), current->comm,
					       current_uid(),
					       i_attr_val1.rc_role);
				return -RSBAC_EDECISIONMISMATCH;

			case RC_type_use_new_role_def_create:
				/* error - complain and return error */
				rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_rc(): invalid type use_new_role_def_create in def_group_create_type of role %i!\n",
					     i_attr_val1.rc_role);
				return -RSBAC_EINVALIDVALUE;

			case RC_type_inherit_parent:
			case RC_type_inherit_process:
				/* error - complain and return error */
				rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_rc(): invalid type inherit_parent in def_group_create_type of role %i!\n",
					     i_attr_val1.rc_role);
				return -RSBAC_EINVALIDVALUE;

			default:
				/* set rc_type for group target */
				i_attr_val1.rc_type =
				    i_rc_item_val1.type_id;
				/* get type from target */
				if ((err = rsbac_get_attr(SW_RC,
							  target,
							  tid,
							  A_rc_type,
							  &i_attr_val2,
							  TRUE))) {
					rsbac_pr_get_error(A_rc_type);
					return -RSBAC_EREADFAILED;
				}
				/* set it for new target, if different */
				if (i_attr_val1.rc_type !=
				    i_attr_val2.rc_type) {
					if ((err =
					     rsbac_set_attr(SW_RC, target,
							    tid, A_rc_type,
							    i_attr_val1)))
					{
						rsbac_pr_set_error
						    (A_rc_type);
						return -RSBAC_EWRITEFAILED;
					}
				}
			}
			return 0;

			/* all other cases are unknown */
		default:
			return 0;
		}

	case R_EXECUTE:
		switch (target) {
		case T_FILE:
			/* get rc_force_role from target file */
			if ((err = rsbac_get_attr(SW_RC, T_FILE,
						  tid,
						  A_rc_force_role,
						  &i_attr_val1, TRUE))) {
				rsbac_pr_get_error(A_rc_force_role);
				return -RSBAC_EREADFAILED;
			}
			/* check rc_force_role, warn, if unusable */
			if ((i_attr_val1.rc_force_role > RC_role_max_value)
			    && (i_attr_val1.rc_force_role <
				RC_role_min_special)
			    ) {
				rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_rc(): rc_force_role %u of file %u on device %02u:%02u is higher than MAX_ROLE %u, setting forced role of process %u to default value %u!\n",
					     i_attr_val1.rc_force_role,
					     tid.file.inode,
					     MAJOR(tid.file.device),
					     MINOR(tid.file.device),
					     RC_role_max_value, pid_nr(caller_pid),
					     RC_default_root_dir_force_role);
				i_attr_val1.rc_force_role =
				    RC_default_root_dir_force_role;
			}
			/* set rc_force_role for this process to keep track of it later */
			i_tid.process = caller_pid;
			if ((err = rsbac_set_attr(SW_RC, T_PROCESS,
						  i_tid,
						  A_rc_force_role,
						  i_attr_val1))) {
				rsbac_pr_set_error(A_rc_force_role);
				return -RSBAC_EWRITEFAILED;
			}
			/* get rc_initial_role from target file */
			if ((err = rsbac_get_attr(SW_RC, T_FILE,
						  tid,
						  A_rc_initial_role,
						  &i_attr_val2, TRUE))) {
				rsbac_pr_get_error(A_rc_initial_role);
				return -RSBAC_EREADFAILED;
			}
			/* check rc_initial_role, warn, if unusable */
			if ((i_attr_val2.rc_initial_role >
			     RC_role_max_value)
			    && (i_attr_val2.rc_initial_role !=
				RC_role_use_force_role)
			    ) {
				rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_rc(): rc_initial_role %u of file %u on device %02u:%02u is higher than MAX_ROLE %u, setting initial role of process %u to default value %u!\n",
					     i_attr_val2.rc_initial_role,
					     tid.file.inode,
					     MAJOR(tid.file.device),
					     MINOR(tid.file.device),
					     RC_role_max_value, pid_nr(caller_pid),
					     RC_default_root_dir_initial_role);
				i_attr_val2.rc_initial_role =
				    RC_default_root_dir_initial_role;
			}
			if (i_attr_val2.rc_initial_role ==
			    RC_role_use_force_role) {
				switch (i_attr_val1.rc_force_role) {
				case RC_role_inherit_user:
					/* get rc_def_role from process owner */
					i_tid.user = owner;
					if ((err =
					     rsbac_get_attr(SW_RC, T_USER,
							    i_tid,
							    A_rc_def_role,
							    &i_attr_val1,
							    TRUE))) {
						rsbac_pr_get_error
						    (A_rc_def_role);
						return -RSBAC_EREADFAILED;
					}
					/* set it for this process */
					i_tid.process = caller_pid;
					if ((err =
					     rsbac_set_attr(SW_RC, T_PROCESS,
							    i_tid,
							    A_rc_role,
							    i_attr_val1)))
					{
						rsbac_pr_set_error
						    (A_rc_role);
						return -RSBAC_EWRITEFAILED;
					}
					break;

				case RC_role_inherit_parent:
				case RC_role_inherit_process:
				case RC_role_inherit_up_mixed:
					/* keep current role */
					break;

				default:
					/* set forced role for this process */
					i_tid.process = caller_pid;
					if ((err =
					     rsbac_set_attr(SW_RC, T_PROCESS,
							    i_tid,
							    A_rc_role,
							    i_attr_val1)))
					{
						rsbac_pr_set_error
						    (A_rc_role);
						return -RSBAC_EWRITEFAILED;
					}
				}
			} else {	/* use initial_role */

				/* set initial role for this process */
				i_tid.process = caller_pid;
				if ((err = rsbac_set_attr(SW_RC, T_PROCESS,
							  i_tid,
							  A_rc_role,
							  i_attr_val2))) {
					rsbac_pr_set_error
					    (A_rc_role);
					return -RSBAC_EWRITEFAILED;
				}
			}
			/* Get role of process. */
			i_tid.process = caller_pid;
			if ((err = rsbac_get_attr(SW_RC, T_PROCESS,
						  i_tid,
						  A_rc_role,
						  &i_attr_val1, FALSE))) {
				rsbac_pr_get_error(A_rc_role);
				return -RSBAC_EREADFAILED;
			}
			/* get def_process_execute_type of role */
			i_rc_tid.role = i_attr_val1.rc_role;
			if ((err = rsbac_rc_get_item(0,
						     RT_ROLE,
						     i_rc_tid,
						     i_rc_tid,
						     RI_def_process_execute_type,
						     &i_rc_item_val1,
						     NULL))) {
				rsbac_rc_pr_get_error
				    (RI_def_process_execute_type);
				return -RSBAC_EREADFAILED;
			}
			switch (i_rc_item_val1.type_id) {
			case RC_type_no_create:
			case RC_type_use_new_role_def_create:
				/* Cannot reset, because of unusable default -> warn and keep */
				rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_rc(): invalid type in def_process_execute_type of role %i!\n",
					     i_attr_val1.rc_role);
				return -RSBAC_EINVALIDVALUE;
			case RC_type_inherit_parent:
			case RC_type_inherit_process:
				break;
			case RC_type_no_execute:
				return -RSBAC_EDECISIONMISMATCH;
			default:
				/* set rc_type for process */
				i_attr_val1.rc_type =
				    i_rc_item_val1.type_id;
				i_tid.process = caller_pid;
				if ((err =
				     rsbac_set_attr(SW_RC, T_PROCESS, i_tid,
						    A_rc_type,
						    i_attr_val1))) {
					rsbac_pr_set_error(A_rc_type);
					return -RSBAC_EWRITEFAILED;
				}
			}
			/* type and role are set - ready. */
			return 0;

			/* all other cases are unknown */
		default:
			return 0;
		}
	default:
		return 0;
	}

	return 0;
}

#ifdef CONFIG_RSBAC_SECDEL
inline rsbac_boolean_t rsbac_need_overwrite_rc(struct dentry * dentry_p)
{
	int err = 0;
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val1;
	union rsbac_rc_target_id_t i_rc_tid;
	union rsbac_rc_item_value_t i_rc_item_val1;

	if (!dentry_p || !dentry_p->d_inode)
		return FALSE;

	i_tid.file.device = dentry_p->d_sb->s_dev;
	i_tid.file.inode = dentry_p->d_inode->i_ino;
	i_tid.file.dentry_p = dentry_p;
	/* get target's rc_type_fd */
	if (rsbac_get_attr(SW_RC, T_FILE,
			   i_tid, A_rc_type_fd, &i_attr_val1, TRUE)) {
		rsbac_pr_get_error(A_rc_type_fd);
		return FALSE;
	}
	/* get type_fd_need_secdel of target's rc_type_fd */
	i_rc_tid.role = i_attr_val1.rc_role;
	if ((err = rsbac_rc_get_item(0,
				     RT_TYPE,
				     i_rc_tid,
				     i_rc_tid,
				     RI_type_fd_need_secdel,
				     &i_rc_item_val1, NULL))) {
		rsbac_rc_pr_get_error(RI_type_fd_need_secdel);
		return FALSE;
	}

	/* return need_overwrite */
	return i_rc_item_val1.need_secdel;
}
#endif
