/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of the Access Control Decision     */
/* Facility (ADF) - Mandatory Access Control         */
/* File: rsbac/adf/mac/main.c                        */
/*                                                   */
/* Author and (c) 1999-2011: Amon Ott <ao@rsbac.org> */
/* MAC_LIGHT Modifications (c) 2000 Stanislav Ievlev */
/*                     and (c) 2001 Amon Ott         */
/*                                                   */
/* Last modified: 12/Jul/2011                        */
/*************************************************** */

#include <linux/string.h>
#include <rsbac/aci.h>
#include <rsbac/mac.h>
#include <rsbac/adf_main.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/getname.h>
#include <rsbac/debug.h>
#include <rsbac/rkmem.h>

/************************************************* */
/*           Global Variables                      */
/************************************************* */

/************************************************* */
/*          Internal Help functions                */
/************************************************* */

static enum rsbac_adf_req_ret_t
mac_check_role(rsbac_uid_t owner,
		enum rsbac_system_role_t role)
{
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val1;

	i_tid.user = owner;
	if (rsbac_get_attr(SW_MAC,
			   T_USER,
			   i_tid, A_mac_role, &i_attr_val1, TRUE)) {
		rsbac_ds_get_error("mac_check_role", A_mac_role);
		return (NOT_GRANTED);
	}
	/* if correct role, then grant */
	if (i_attr_val1.system_role == role)
		return (GRANTED);
	else {
		rsbac_pr_debug(adf_mac, "pid %u/%.15s: wrong mac_role %u -> NOT_GRANTED!\n",
			       current->pid, current->comm,
			       i_attr_val1.system_role);
		return (NOT_GRANTED);
	}
}

/* auto_write() */
/* This function builds a decision for write-only access based on      */
/* ss-property and *-property. The Subject is given by process-id pid, */
/* its attributes are taken from the data structures module. */
/* For the object, only security_level is given to become independent  */
/* from different object/target types.                                 */
/* If attribute mac_auto is set, the current_security_level is changed */
/* within min_write and max_read boundaries to allow for more accesses.*/
/* If set_level is TRUE, the current_security_level and read/write     */
/* boundaries are set to appropiate values, otherwise they are only    */
/* checked. This provides only one function for decision and attribute */
/* setting.                                                            */
/* Trusted processes (attr. mac_trusted set) are always granted write  */
/* access.                                                             */

static enum rsbac_adf_req_ret_t
auto_write_attr(rsbac_pid_t pid,
		enum rsbac_target_t target,
		union rsbac_target_id_t tid,
		enum rsbac_attribute_t t_level_attr,
		enum rsbac_attribute_t t_cat_attr,
		rsbac_boolean_t set_level)
{
	rsbac_security_level_t curr_level;
	rsbac_mac_category_vector_t curr_categories;
	rsbac_security_level_t target_sec_level;
	rsbac_mac_category_vector_t target_categories;
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t attr_val1;
	union rsbac_attribute_value_t attr_val2;
	rsbac_mac_process_flags_t flags;
	rsbac_boolean_t mac_auto_used_level = FALSE;
	rsbac_boolean_t mac_auto_used_cat = FALSE;
	rsbac_boolean_t raise_object_level = FALSE;
	rsbac_boolean_t raise_object_cat = FALSE;

	/* first check for mac_override, which allows everything */
	i_tid.process = pid;
	if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_mac_process_flags, &attr_val1, FALSE)) {	/* failed! */
		rsbac_ds_get_error("mac_auto_write", A_none);
		return (NOT_GRANTED);
	}
	flags = attr_val1.mac_process_flags;
	if (flags & MAC_override)
		return GRANTED;

	/* Get current security level */
	if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_current_sec_level, &attr_val1, FALSE)) {	/* failed! */
		rsbac_ds_get_error("mac_auto_write", A_none);
		return (NOT_GRANTED);
	}
	curr_level = attr_val1.security_level;
	/* Get current categories */
	if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_mac_curr_categories, &attr_val1, FALSE)) {	/* failed! */
		rsbac_ds_get_error("mac_auto_write", A_none);
		return (NOT_GRANTED);
	}
	curr_categories = attr_val1.mac_categories;
	/* Get target security level */
	if (rsbac_get_attr(SW_MAC, target, tid, t_level_attr, &attr_val1, TRUE)) {	/* failed! */
		rsbac_ds_get_error("mac_auto_write", A_none);
		return (NOT_GRANTED);
	}
	target_sec_level = attr_val1.security_level;
	/* Get target categories */
	if (rsbac_get_attr(SW_MAC, target, tid, t_cat_attr, &attr_val1, TRUE)) {	/* failed! */
		rsbac_ds_get_error("mac_auto_write", A_none);
		return (NOT_GRANTED);
	}
	target_categories = attr_val1.mac_categories;

	if (target_sec_level > curr_level) {
		if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_security_level, &attr_val1, FALSE)) {	/* failed! */
			rsbac_ds_get_error("mac_auto_write", A_none);
			return (NOT_GRANTED);
		}
		if (attr_val1.security_level < target_sec_level) {
			rsbac_pr_debug(adf_mac, "pid %u/%.15s: security_level %u under target_sec_level %u, no override -> NOT_GRANTED!\n",
				       current->pid, current->comm,
				       attr_val1.security_level,
				       target_sec_level);
			return (NOT_GRANTED);
		}
		/* curr_level < target_level <= max_level -> need mac_auto,
		 * write_up, trusted (at process)
		 * or shared (at object) */
		if (flags & MAC_auto)
			mac_auto_used_level = TRUE;
		else {
			if (!(flags & MAC_write_up)
			    && !(flags & MAC_trusted)
			    ) {
				/* Try mac_file_flags on the target,
				 * if FD object */
				switch (target) {
				case T_FILE:
				case T_DIR:
				case T_FIFO:
				case T_SYMLINK:
				case T_UNIXSOCK:
					if (rsbac_get_attr(SW_MAC, target, tid, A_mac_file_flags, &attr_val1, TRUE)) {	/* failed! */
						rsbac_ds_get_error
						    ("mac_auto_write",
						     A_none);
						return (NOT_GRANTED);
					}
					if ((attr_val1.
					     mac_file_flags & MAC_write_up)
					    || (attr_val1.
						mac_file_flags &
						MAC_trusted)
					    ) {
						break;
					}
					/* fall through */

				default:
					rsbac_pr_debug(adf_mac, "pid %u/%.15s: current security_level %u under target_sec_level %u, no auto, write_up, trusted -> NOT_GRANTED!\n",
						       current->pid,
						       current->comm,
						       curr_level,
						       target_sec_level);
					return (NOT_GRANTED);
				}
			}
		}
	} else if (target_sec_level < curr_level) {
		if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_min_security_level, &attr_val1, FALSE)) {	/* failed! */
			rsbac_ds_get_error("mac_auto_write", A_none);
			return (NOT_GRANTED);
		}
		if (attr_val1.security_level > target_sec_level) {
			rsbac_pr_debug(adf_mac, "pid %u/%.15s: min_security_level %u over target_sec_level %u, no override -> NOT_GRANTED!\n",
				       current->pid,
				       current->comm, attr_val1.security_level,
				       target_sec_level);
			return (NOT_GRANTED);
		}
		/* min_level <= target_level < curr_level -> need mac_auto,
		 * write_down or trusted */
		if (flags & MAC_auto) {
			/* check max_read boundary */
			if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_max_read_open, &attr_val1, FALSE)) {	/* failed! */
				rsbac_ds_get_error("mac_auto_write",
						   A_none);
				return (NOT_GRANTED);
			}
			if (attr_val1.security_level > target_sec_level) {
				if (!(flags & MAC_write_down)
				    && !(flags & MAC_trusted)
				    ) {
					/* Try mac_file_flags on the target,
					 * if FD object */
					switch (target) {
					case T_FILE:
					case T_DIR:
					case T_FIFO:
					case T_SYMLINK:
					case T_UNIXSOCK:
						if (rsbac_get_attr(SW_MAC, target, tid, A_mac_file_flags, &attr_val1, TRUE)) {	/* failed! */
							rsbac_ds_get_error
							    ("mac_auto_write",
							     A_none);
							return
							    (NOT_GRANTED);
						}
						if ((attr_val1.
						     mac_file_flags &
						     MAC_write_down)
						    || (attr_val1.
							mac_file_flags &
							MAC_trusted)
						    ) {
							if (attr_val1.
							    mac_file_flags
							    & MAC_auto) {
								raise_object_level
								    = TRUE;
							}
							break;
						}
						/* fall through */

					default:
						rsbac_pr_debug(adf_mac, "pid %u/%.15s: max_read_open %u over target_sec_level %u, no write_down or trusted -> NOT_GRANTED!\n",
							     current->pid,
							     current->comm,
							     attr_val1.
							     security_level,
							     target_sec_level);
						return (NOT_GRANTED);
					}
				}
			} else
				mac_auto_used_level = TRUE;
		} else {
			if (!(flags & MAC_write_down)
			    && !(flags & MAC_trusted)
			    ) {
				/* Try mac_file_flags on the target,
				 * if FD object */
				switch (target) {
				case T_FILE:
				case T_DIR:
				case T_FIFO:
				case T_SYMLINK:
				case T_UNIXSOCK:
					if (rsbac_get_attr(SW_MAC, target, tid, A_mac_file_flags, &attr_val1, TRUE)) {	/* failed! */
						rsbac_ds_get_error
						    ("mac_auto_write",
						     A_none);
						return (NOT_GRANTED);
					}
					if ((attr_val1.
					     mac_file_flags &
					     MAC_write_down)
					    || (attr_val1.
						mac_file_flags &
						MAC_trusted)
					    ) {
						if (attr_val1.
						    mac_file_flags &
						    MAC_auto) {
							raise_object_level
							    = TRUE;
						}
						break;
					}
					/* fall through */

				default:
					rsbac_pr_debug(adf_mac, "pid %u/%.15s: current security_level %u over target_sec_level %u, no auto, write_down or trusted -> NOT_GRANTED!\n",
						       current->pid,
						       current->comm,
						       curr_level,
						       target_sec_level);
					return (NOT_GRANTED);
				}
			}
		}
	}

	if ((target_categories & curr_categories) != target_categories) {
		if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_mac_categories, &attr_val1, FALSE)) {	/* failed! */
			rsbac_ds_get_error("mac_auto_write", A_none);
			return (NOT_GRANTED);
		}
		if ((target_categories & attr_val1.mac_categories) !=
		    target_categories) {
#ifdef CONFIG_RSBAC_DEBUG
			if (rsbac_debug_adf_mac) {
				char *tmp =
				    rsbac_kmalloc(RSBAC_MAXNAMELEN);

				if (tmp) {
					char *tmp2 =
					    rsbac_kmalloc
					    (RSBAC_MAXNAMELEN);

					if (tmp2) {
						u64tostrmac(tmp,
							    attr_val1.
							    mac_categories);
						u64tostrmac(tmp2,
							    target_categories);
						rsbac_pr_debug(adf_mac, "pid %u/%.15s: max_categories %s under target categories %s, no override -> NOT_GRANTED!\n",
							     current->pid,
							     current->comm,
							     tmp, tmp2);
						rsbac_kfree(tmp2);
					}
					rsbac_kfree(tmp);
				}
			}
#endif
			return (NOT_GRANTED);
		}
		/* curr_categories < target_categories <= max_categories -> need mac_auto,
		 * write_up or trusted */
		if (flags & MAC_auto)
			mac_auto_used_cat = TRUE;
		else {
			if (!(flags & MAC_write_up)
			    && !(flags & MAC_trusted)
			    ) {
				/* Try mac_file_flags on the target,
				 * if FD object */
				switch (target) {
				case T_FILE:
				case T_DIR:
				case T_FIFO:
				case T_SYMLINK:
				case T_UNIXSOCK:
					if (rsbac_get_attr(SW_MAC, target, tid, A_mac_file_flags, &attr_val1, TRUE)) {	/* failed! */
						rsbac_ds_get_error
						    ("mac_auto_write",
						     A_none);
						return (NOT_GRANTED);
					}
					if ((attr_val1.
					     mac_file_flags & MAC_write_up)
					    || (attr_val1.
						mac_file_flags &
						MAC_trusted)
					    )
						break;
					/* fall through */

				default:
#ifdef CONFIG_RSBAC_DEBUG
					if (rsbac_debug_adf_mac) {
						char *tmp =
						    rsbac_kmalloc
						    (RSBAC_MAXNAMELEN);

						if (tmp) {
							char *tmp2 =
							    rsbac_kmalloc
							    (RSBAC_MAXNAMELEN);

							if (tmp2) {
								u64tostrmac
								    (tmp,
								     curr_categories);
								u64tostrmac
								    (tmp2,
								     target_categories);
								rsbac_pr_debug(adf_mac, "pid %u/%.15s: curr_categories %s under target categories %s, no auto, write_up or trusted -> NOT_GRANTED!\n",
								     current->
								     pid,
								     current->
								     comm,
								     tmp,
								     tmp2);
								rsbac_kfree
								    (tmp2);
							}
							rsbac_kfree(tmp);
						}
					}
#endif
					return (NOT_GRANTED);
				}
			}
		}
	} else
	    if ((target_categories & curr_categories) != curr_categories) {
		if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_mac_min_categories, &attr_val1, FALSE)) {	/* failed! */
			rsbac_ds_get_error("mac_auto_write", A_none);
			return (NOT_GRANTED);
		}
		if ((target_categories & attr_val1.mac_categories) !=
		    attr_val1.mac_categories) {
#ifdef CONFIG_RSBAC_DEBUG
			if (rsbac_debug_adf_mac) {
				char *tmp =
				    rsbac_kmalloc(RSBAC_MAXNAMELEN);

				if (tmp) {
					char *tmp2 =
					    rsbac_kmalloc
					    (RSBAC_MAXNAMELEN);

					if (tmp2) {
						u64tostrmac(tmp,
							    attr_val1.
							    mac_categories);
						u64tostrmac(tmp2,
							    target_categories);
						rsbac_pr_debug(adf_mac, "pid %u/%.15s: min_categories %s over target categories %s, no override -> NOT_GRANTED!\n",
							     current->pid,
							     current->comm,
							     tmp, tmp2);
						rsbac_kfree(tmp2);
					}
					rsbac_kfree(tmp);
				}
			}
#endif
			return (NOT_GRANTED);
		}
		/* min_level <= target_level < curr_level -> need mac_auto,
		 * write_down or trusted */
		if (flags & MAC_auto) {
			/* check max_read boundary */
			if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_max_read_categories, &attr_val1, FALSE)) {	/* failed! */
				rsbac_ds_get_error("mac_auto_write",
						   A_none);
				return (NOT_GRANTED);
			}
			if ((target_categories & attr_val1.
			     mac_categories) != attr_val1.mac_categories) {
				if (!(flags & MAC_write_down)
				    && !(flags & MAC_trusted)
				    ) {
					/* Try mac_file_flags on the target,
					 * if FD object */
					switch (target) {
					case T_FILE:
					case T_DIR:
					case T_FIFO:
					case T_SYMLINK:
					case T_UNIXSOCK:
						if (rsbac_get_attr(SW_MAC, target, tid, A_mac_file_flags, &attr_val1, TRUE)) {	/* failed! */
							rsbac_ds_get_error
							    ("mac_auto_write",
							     A_none);
							return
							    (NOT_GRANTED);
						}
						if ((attr_val1.
						     mac_file_flags &
						     MAC_write_down)
						    || (attr_val1.
							mac_file_flags &
							MAC_trusted)
						    ) {
							if (attr_val1.
							    mac_file_flags
							    & MAC_auto) {
								raise_object_cat
								    = TRUE;
							}
							break;
						}
						/* fall through */

					default:
#ifdef CONFIG_RSBAC_DEBUG
						if (rsbac_debug_adf_mac) {
							char *tmp =
							    rsbac_kmalloc
							    (RSBAC_MAXNAMELEN);

							if (tmp) {
								char *tmp2
								    =
								    rsbac_kmalloc
								    (RSBAC_MAXNAMELEN);

								if (tmp2) {
									u64tostrmac
									    (tmp,
									     attr_val1.
									     mac_categories);
									u64tostrmac
									    (tmp2,
									     target_categories);
									rsbac_pr_debug(adf_mac, "pid %u/%.15s: max_read_categories %s over target categories %s, no write_down or trusted -> NOT_GRANTED!\n",
									     current->
									     pid,
									     current->
									     comm,
									     tmp,
									     tmp2);
									rsbac_kfree
									    (tmp2);
								}
								rsbac_kfree
								    (tmp);
							}
						}
#endif
						return (NOT_GRANTED);
					}
				}
			} else
				mac_auto_used_cat = TRUE;
		} else {
			if (!(flags & MAC_write_down)
			    && !(flags & MAC_trusted)
			    ) {
				/* Try mac_file_flags on the target, if FD object */
				switch (target) {
				case T_FILE:
				case T_DIR:
				case T_FIFO:
				case T_SYMLINK:
				case T_UNIXSOCK:
					if (rsbac_get_attr(SW_MAC, target, tid, A_mac_file_flags, &attr_val1, TRUE)) {	/* failed! */
						rsbac_ds_get_error
						    ("mac_auto_write",
						     A_none);
						return (NOT_GRANTED);
					}
					if ((attr_val1.
					     mac_file_flags &
					     MAC_write_down)
					    || (attr_val1.
						mac_file_flags &
						MAC_trusted)
					    ) {
						if (attr_val1.
						    mac_file_flags &
						    MAC_auto) {
							raise_object_cat =
							    TRUE;
						}
						break;
					}
					/* fall through */

				default:
#ifdef CONFIG_RSBAC_DEBUG
					if (rsbac_debug_adf_mac) {
						char *tmp =
						    rsbac_kmalloc
						    (RSBAC_MAXNAMELEN);

						if (tmp) {
							char *tmp2 =
							    rsbac_kmalloc
							    (RSBAC_MAXNAMELEN);

							if (tmp2) {
								u64tostrmac
								    (tmp,
								     curr_categories);
								u64tostrmac
								    (tmp2,
								     target_categories);
								rsbac_pr_debug(adf_mac, "pid %u/%.15s: curr_categories %s over target categories %s, no auto, write_down or trusted -> NOT_GRANTED!\n",
								     current->
								     pid,
								     current->
								     comm,
								     tmp,
								     tmp2);
								rsbac_kfree
								    (tmp2);
							}
							rsbac_kfree(tmp);
						}
					}
#endif
					return (NOT_GRANTED);
				}
			}
		}
	}

	/* grant area */

	/* adjust current_sec_level and min_write_level, */
	/* if set_level is true and mac_auto has been used */
	if (set_level && (mac_auto_used_level || raise_object_level)
	    ) {
#ifdef CONFIG_RSBAC_MAC_LOG_LEVEL_CHANGE
		{
			char *target_type_name;
			char *target_id_name;

			target_type_name = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (target_type_name) {
#ifdef CONFIG_RSBAC_LOG_FULL_PATH
				target_id_name
				    =
				    rsbac_kmalloc(CONFIG_RSBAC_MAX_PATH_LEN
						  + RSBAC_MAXNAMELEN);
				/* max. path name len + some extra */
#else
				target_id_name =
				    rsbac_kmalloc(2 * RSBAC_MAXNAMELEN);
				/* max. file name len + some extra */
#endif
				if (target_id_name) {
					get_target_name(target_type_name,
							target,
							target_id_name,
							tid);

					if (mac_auto_used_level) {
						rsbac_printk(KERN_INFO "mac_auto_write(): Changing process %u (%.15s, owner %u) current level from %u to %u for %s %s\n",
							     pid,
							     current->comm,
							     current_uid(),
							     curr_level,
							     target_sec_level,
							     target_type_name,
							     target_id_name);
					} else {
						rsbac_printk(KERN_INFO "mac_auto_write(): Process %u (%.15s, owner %u): Raising object level from %u to %u for %s %s\n",
							     pid,
							     current->comm,
							     current_uid(),
							     target_sec_level,
							     curr_level,
							     target_type_name,
							     target_id_name);
					}
					rsbac_kfree(target_id_name);
				}
				rsbac_kfree(target_type_name);
			}
		}
#endif
		if (mac_auto_used_level) {
			i_tid.process = pid;
			attr_val1.current_sec_level = target_sec_level;
			if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_min_write_open, &attr_val2, TRUE)) {	/* failed! */
				rsbac_ds_get_error("mac_auto_write",
						   A_none);
				return (NOT_GRANTED);
			}
			if (attr_val1.min_write_open <
			    attr_val2.min_write_open) {
				if (rsbac_set_attr(SW_MAC, T_PROCESS, i_tid, A_min_write_open, attr_val1)) {	/* failed! */
					rsbac_ds_set_error
					    ("mac_auto_write", A_none);
					return (NOT_GRANTED);
				}
			}
			if (rsbac_set_attr(SW_MAC, T_PROCESS, i_tid, A_current_sec_level, attr_val1)) {	/* failed! */
				rsbac_ds_set_error("mac_auto_write",
						   A_none);
				return (NOT_GRANTED);
			}
		} else {
			attr_val1.security_level = curr_level;
			if (rsbac_set_attr(SW_MAC, target, tid, A_security_level, attr_val1)) {	/* failed! */
				rsbac_ds_set_error("mac_auto_write",
						   A_none);
				return (NOT_GRANTED);
			}
		}
	}
	/* adjust current_categories and min_write_categories, */
	/* if set_level is true and mac_auto has been used */
	if (set_level && (mac_auto_used_cat || raise_object_cat)
	    ) {
#ifdef CONFIG_RSBAC_MAC_LOG_LEVEL_CHANGE
		{
			char *target_type_name =
			    rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (target_type_name) {
				char *target_id_name;

#ifdef CONFIG_RSBAC_LOG_FULL_PATH
				target_id_name
				    =
				    rsbac_kmalloc(CONFIG_RSBAC_MAX_PATH_LEN
						  + RSBAC_MAXNAMELEN);
				/* max. path name len + some extra */
#else
				target_id_name =
				    rsbac_kmalloc(2 * RSBAC_MAXNAMELEN);
				/* max. file name len + some extra */
#endif
				if (target_id_name) {
					char *tmp1 =
					    rsbac_kmalloc
					    (RSBAC_MAXNAMELEN);
					if (tmp1) {
						char *tmp2 =
						    rsbac_kmalloc
						    (RSBAC_MAXNAMELEN);
						if (tmp2) {
							get_target_name
							    (target_type_name,
							     target,
							     target_id_name,
							     tid);

							if (mac_auto_used_cat) {
								rsbac_printk
								    (KERN_INFO "mac_auto_write(): Changing process %u (%.15s, owner %u) current categories from %s to %s for %s %s\n",
								     pid,
								     current->
								     comm,
								     current_uid(),
								     u64tostrmac
								     (tmp1,
								      curr_categories),
								     u64tostrmac
								     (tmp2,
								      target_categories),
								     target_type_name,
								     target_id_name);
							} else {
								rsbac_printk
								    (KERN_INFO "mac_auto_write(): Process %u (%.15s, owner %u): raising current categories from %s to %s for %s %s\n",
								     pid,
								     current->
								     comm,
								     current_uid(),
								     u64tostrmac
								     (tmp2,
								      target_categories),
								     u64tostrmac
								     (tmp1,
								      curr_categories),
								     target_type_name,
								     target_id_name);
							}
							rsbac_kfree(tmp2);
						}
						rsbac_kfree(tmp1);
					}
					rsbac_kfree(target_id_name);
				}
				rsbac_kfree(target_type_name);
			}
		}
#endif
		if (mac_auto_used_cat) {
			i_tid.process = pid;
			attr_val1.mac_categories = target_categories;
			if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_min_write_categories, &attr_val2, TRUE)) {	/* failed! */
				rsbac_ds_get_error("mac_auto_write",
						   A_none);
				return (NOT_GRANTED);
			}
			if ((attr_val1.mac_categories & attr_val2.
			     mac_categories)
			    != attr_val2.mac_categories) {
				if (rsbac_set_attr(SW_MAC, T_PROCESS, i_tid, A_min_write_categories, attr_val1)) {	/* failed! */
					rsbac_ds_set_error
					    ("mac_auto_write", A_none);
					return (NOT_GRANTED);
				}
			}
			if (rsbac_set_attr(SW_MAC, T_PROCESS, i_tid, A_mac_curr_categories, attr_val1)) {	/* failed! */
				rsbac_ds_set_error("mac_auto_write",
						   A_none);
				return (NOT_GRANTED);
			}
		} else {
			attr_val1.mac_categories = curr_categories;
			if (rsbac_set_attr(SW_MAC, target, tid, A_mac_categories, attr_val1)) {	/* failed! */
				rsbac_ds_set_error("mac_auto_write",
						   A_none);
				return (NOT_GRANTED);
			}
		}
	}

	/* Everything done, so return */
	return (GRANTED);
}

static enum rsbac_adf_req_ret_t
auto_write(rsbac_pid_t pid,
	   enum rsbac_target_t target,
	   union rsbac_target_id_t tid, rsbac_boolean_t set_level)
{
	return auto_write_attr(pid,
			       target,
			       tid,
			       A_security_level,
			       A_mac_categories, set_level);
}

/* auto_read() */
/* This function works similar to auto_write() */

static enum rsbac_adf_req_ret_t
auto_read_attr(rsbac_pid_t pid,
	       enum rsbac_target_t target,
	       union rsbac_target_id_t tid,
	       enum rsbac_attribute_t t_level_attr,
	       enum rsbac_attribute_t t_cat_attr,
	       rsbac_boolean_t set_level)
{
	rsbac_security_level_t curr_level;
	rsbac_mac_category_vector_t curr_categories;
	rsbac_security_level_t target_sec_level;
	rsbac_mac_category_vector_t target_categories;
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t attr_val1;
	union rsbac_attribute_value_t attr_val2;
	rsbac_mac_process_flags_t flags;
	rsbac_boolean_t mac_auto_used_level = FALSE;
	rsbac_boolean_t mac_auto_used_cat = FALSE;
	rsbac_boolean_t set_level_level = FALSE;
	rsbac_boolean_t set_level_cat = FALSE;

	/* first check for mac_override, which allows everything */
	i_tid.process = pid;
	if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_mac_process_flags, &attr_val1, FALSE)) {	/* failed! */
		rsbac_ds_get_error("mac_auto_read", A_none);
		return (NOT_GRANTED);
	}
	flags = attr_val1.mac_process_flags;
	if (flags & MAC_override)
		return GRANTED;

	/* Get current security level */
	if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_current_sec_level, &attr_val1, FALSE)) {	/* failed! */
		rsbac_ds_get_error("mac_auto_read", A_none);
		return (NOT_GRANTED);
	}
	curr_level = attr_val1.security_level;
	/* Get current categories */
	if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_mac_curr_categories, &attr_val1, FALSE)) {	/* failed! */
		rsbac_ds_get_error("mac_auto_read", A_none);
		return (NOT_GRANTED);
	}
	curr_categories = attr_val1.mac_categories;
	/* Get target security level */
	if (rsbac_get_attr(SW_MAC, target, tid, t_level_attr, &attr_val1, TRUE)) {	/* failed! */
		rsbac_ds_get_error("mac_auto_read", A_none);
		return (NOT_GRANTED);
	}
	target_sec_level = attr_val1.security_level;
	/* Get target categories */
	if (rsbac_get_attr(SW_MAC, target, tid, t_cat_attr, &attr_val1, TRUE)) {	/* failed! */
		rsbac_ds_get_error("mac_auto_read", A_none);
		return (NOT_GRANTED);
	}
	target_categories = attr_val1.mac_categories;

	if (target_sec_level > curr_level) {
		if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_security_level, &attr_val1, FALSE)) {	/* failed! */
			rsbac_ds_get_error("mac_auto_read", A_none);
			return (NOT_GRANTED);
		}
		if (attr_val1.security_level < target_sec_level) {
			rsbac_pr_debug(adf_mac, "pid %u/%.15s: security_level %u under target_sec_level %u, no override -> NOT_GRANTED!\n",
				       current->pid, current->comm,
				       attr_val1.security_level,
				       target_sec_level);
			return (NOT_GRANTED);
		}
		/* curr_level < target_level <= max_level -> need mac_auto, read_up or trusted (with read option) */
		if (flags & MAC_auto) {
			/* check min_write boundary */
			if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_min_write_open, &attr_val1, FALSE)) {	/* failed! */
				rsbac_ds_get_error("mac_auto_read",
						   A_none);
				return (NOT_GRANTED);
			}
			if (attr_val1.security_level < target_sec_level) {
				if (!(flags & MAC_read_up)
#ifdef CONFIG_RSBAC_MAC_TRUSTED_READ
				    && !(flags & MAC_trusted)
#endif
				    ) {
					/* Try mac_file_flags on the target, if FD object */
					switch (target) {
					case T_FILE:
					case T_DIR:
					case T_FIFO:
					case T_SYMLINK:
					case T_UNIXSOCK:
						if (rsbac_get_attr(SW_MAC, target, tid, A_mac_file_flags, &attr_val1, TRUE)) {	/* failed! */
							rsbac_ds_get_error
							    ("mac_auto_read",
							     A_none);
							return
							    (NOT_GRANTED);
						}
						if ((attr_val1.
						     mac_file_flags &
						     MAC_read_up)
#ifdef CONFIG_RSBAC_MAC_TRUSTED_READ
						    || (attr_val1.
							mac_file_flags &
							MAC_trusted)
#endif
						    ) {
							break;
						}
						/* fall through */

					default:
						rsbac_pr_debug(adf_mac, "pid %u/%.15s: min_write_open %u under target_sec_level %u, no read_up or trusted -> NOT_GRANTED!\n",
							     current->pid,
							     current->comm,
							     attr_val1.
							     security_level,
							     target_sec_level);
						return (NOT_GRANTED);
					}
				}
			} else {
				mac_auto_used_level = TRUE;
				set_level_level = TRUE;
			}
		} else {
			if (!(flags & MAC_read_up)
#ifdef CONFIG_RSBAC_MAC_TRUSTED_READ
			    && !(flags & MAC_trusted)
#endif
			    ) {
				/* Try mac_file_flags on the target, if FD object */
				switch (target) {
				case T_FILE:
				case T_DIR:
				case T_FIFO:
				case T_SYMLINK:
				case T_UNIXSOCK:
					if (rsbac_get_attr(SW_MAC, target, tid, A_mac_file_flags, &attr_val1, TRUE)) {	/* failed! */
						rsbac_ds_get_error
						    ("mac_auto_read",
						     A_none);
						return (NOT_GRANTED);
					}
					if ((attr_val1.
					     mac_file_flags & MAC_read_up)
#ifdef CONFIG_RSBAC_MAC_TRUSTED_READ
					    || (attr_val1.
						mac_file_flags &
						MAC_trusted)
#endif
					    ) {
						break;
					}
					/* fall through */

				default:
					rsbac_pr_debug(adf_mac, "pid %u/%.15s: current level %u under target_sec_level %u, no auto, read_up or trusted -> NOT_GRANTED!\n",
						       current->pid,
						       current->comm,
						       curr_level,
						       target_sec_level);
					return (NOT_GRANTED);
				}
			}
		}
	} else if (target_sec_level < curr_level) {
		if (flags & MAC_auto) {
			mac_auto_used_level = TRUE;
		}
	}
	if ((target_categories & curr_categories) != target_categories) {
		if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_mac_categories, &attr_val1, FALSE)) {	/* failed! */
			rsbac_ds_get_error("mac_auto_read", A_none);
			return (NOT_GRANTED);
		}
		if ((target_categories & attr_val1.mac_categories) !=
		    target_categories) {
#ifdef CONFIG_RSBAC_DEBUG
			if (rsbac_debug_adf_mac) {
				char *tmp =
				    rsbac_kmalloc(RSBAC_MAXNAMELEN);

				if (tmp) {
					char *tmp2 =
					    rsbac_kmalloc
					    (RSBAC_MAXNAMELEN);

					if (tmp2) {
						u64tostrmac(tmp,
							    attr_val1.
							    mac_categories);
						u64tostrmac(tmp2,
							    target_categories);
						rsbac_pr_debug(adf_mac, "pid %u/%.15s: max_categories %s under target categories %s, no override -> NOT_GRANTED!\n",
							     current->pid,
							     current->comm,
							     tmp, tmp2);
						rsbac_kfree(tmp2);
					}
					rsbac_kfree(tmp);
				}
			}
#endif
			return (NOT_GRANTED);
		}
		/* curr_categories < target_categories <= max_categories -> need mac_auto,
		 * read_up or trusted */
		if (flags & MAC_auto) {
			/* check min_write boundary */
			if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_min_write_categories, &attr_val1, FALSE)) {	/* failed! */
				rsbac_ds_get_error("mac_auto_read",
						   A_none);
				return (NOT_GRANTED);
			}
			if ((target_categories & attr_val1.
			     mac_categories) != target_categories) {
				if (!(flags & MAC_read_up)
#ifdef CONFIG_RSBAC_MAC_TRUSTED_READ
				    && !(flags & MAC_trusted)
#endif
				    ) {
					/* Try mac_file_flags on the target,
					 * if FD object */
					switch (target) {
					case T_FILE:
					case T_DIR:
					case T_FIFO:
					case T_SYMLINK:
					case T_UNIXSOCK:
						if (rsbac_get_attr(SW_MAC, target, tid, A_mac_file_flags, &attr_val1, TRUE)) {	/* failed! */
							rsbac_ds_get_error
							    ("mac_auto_read",
							     A_none);
							return
							    (NOT_GRANTED);
						}
						if ((attr_val1.
						     mac_file_flags &
						     MAC_read_up)
#ifdef CONFIG_RSBAC_MAC_TRUSTED_READ
						    || (attr_val1.
							mac_file_flags &
							MAC_trusted)
#endif
						    ) {
							break;
						}
						/* fall through */

					default:
#ifdef CONFIG_RSBAC_DEBUG
						if (rsbac_debug_adf_mac) {
							char *tmp =
							    rsbac_kmalloc
							    (RSBAC_MAXNAMELEN);

							if (tmp) {
								char *tmp2
								    =
								    rsbac_kmalloc
								    (RSBAC_MAXNAMELEN);

								if (tmp2) {
									u64tostrmac
									    (tmp,
									     attr_val1.
									     mac_categories);
									u64tostrmac
									    (tmp2,
									     target_categories);
									rsbac_pr_debug(adf_mac, "pid %u/%.15s: min_write_categories %s under target categories %s, no read_up or trusted with read option -> NOT_GRANTED!\n",
									     current->
									     pid,
									     current->
									     comm,
									     tmp,
									     tmp2);
									rsbac_kfree
									    (tmp2);
								}
								rsbac_kfree
								    (tmp);
							}
						}
#endif
						return (NOT_GRANTED);
					}
				}
			} else {
				mac_auto_used_cat = TRUE;
				set_level_cat = TRUE;
			}
		} else {
			if (!(flags & MAC_read_up)
#ifdef CONFIG_RSBAC_MAC_TRUSTED_READ
			    && !(flags & MAC_trusted)
#endif
			    ) {
				/* Try mac_file_flags on the target,
				 * if FD object */
				switch (target) {
				case T_FILE:
				case T_DIR:
				case T_FIFO:
				case T_SYMLINK:
				case T_UNIXSOCK:
					if (rsbac_get_attr(SW_MAC, target, tid, A_mac_file_flags, &attr_val1, TRUE)) {	/* failed! */
						rsbac_ds_get_error
						    ("mac_auto_read",
						     A_none);
						return (NOT_GRANTED);
					}
					if ((attr_val1.
					     mac_file_flags & MAC_read_up)
#ifdef CONFIG_RSBAC_MAC_TRUSTED_READ
					    || (attr_val1.
						mac_file_flags &
						MAC_trusted)
#endif
					    ) {
						break;
					}
					/* fall through */

				default:
#ifdef CONFIG_RSBAC_DEBUG
					if (rsbac_debug_adf_mac) {
						char *tmp =
						    rsbac_kmalloc
						    (RSBAC_MAXNAMELEN);

						if (tmp) {
							char *tmp2 =
							    rsbac_kmalloc
							    (RSBAC_MAXNAMELEN);

							if (tmp2) {
								u64tostrmac
								    (tmp,
								     curr_categories);
								u64tostrmac
								    (tmp2,
								     target_categories);
								rsbac_pr_debug(adf_mac, "pid %u/%.15s: curr_categories %s under target categories %s, no auto, read_up or trusted with read option -> NOT_GRANTED!\n",
								     current->
								     pid,
								     current->
								     comm,
								     tmp,
								     tmp2);
								rsbac_kfree
								    (tmp2);
							}
							rsbac_kfree(tmp);
						}
					}
#endif
					return (NOT_GRANTED);
				}
			}
		}
	} else
	    if ((target_categories & curr_categories) != curr_categories) {
		if (flags & MAC_auto) {
			mac_auto_used_level = TRUE;
		}
	}

	/* grant area */

	/* adjust current_sec_level and max_read_level, */
	/* if set_level is true and mac_auto has been used */
	if (set_level && mac_auto_used_level) {
		i_tid.process = pid;
		attr_val1.current_sec_level = target_sec_level;
		if (set_level_level) {
#ifdef CONFIG_RSBAC_MAC_LOG_LEVEL_CHANGE
			char *target_type_name;
			char *target_id_name;

			target_type_name = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (target_type_name) {
#ifdef CONFIG_RSBAC_LOG_FULL_PATH
				target_id_name
				    =
				    rsbac_kmalloc(CONFIG_RSBAC_MAX_PATH_LEN
						  + RSBAC_MAXNAMELEN);
				/* max. path name len + some extra */
#else
				target_id_name =
				    rsbac_kmalloc(2 * RSBAC_MAXNAMELEN);
				/* max. file name len + some extra */
#endif
				if (target_id_name) {
					get_target_name(target_type_name,
							target,
							target_id_name,
							tid);

					rsbac_printk(KERN_INFO "mac_auto_read(): Changing process %u (%.15s, owner %u) current level from %u to %u for %s %s\n",
						     pid,
						     current->comm,
						     current_uid(),
						     curr_level,
						     target_sec_level,
						     target_type_name,
						     target_id_name);
					rsbac_kfree(target_id_name);
				}
				rsbac_kfree(target_type_name);
			}
#endif
			if (rsbac_set_attr(SW_MAC, T_PROCESS, i_tid, A_current_sec_level, attr_val1)) {	/* failed! */
				rsbac_ds_set_error("mac_auto_read",
						   A_none);
				return (NOT_GRANTED);
			}
		}
		if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_max_read_open, &attr_val2, TRUE)) {	/* failed! */
			rsbac_ds_get_error("mac_auto_read", A_none);
			return (NOT_GRANTED);
		}
		if (attr_val1.max_read_open > attr_val2.max_read_open) {
			if (rsbac_set_attr(SW_MAC, T_PROCESS, i_tid, A_max_read_open, attr_val1)) {	/* failed! */
				rsbac_ds_set_error("mac_auto_read",
						   A_none);
				return (NOT_GRANTED);
			}
		}
	}
	/* adjust current_categories and max_read_categories, */
	/* if set_level is true and mac_auto has been used */
	if (set_level && mac_auto_used_cat) {
		i_tid.process = pid;
		attr_val1.mac_categories = target_categories;
		if (set_level_cat) {
#ifdef CONFIG_RSBAC_MAC_LOG_LEVEL_CHANGE
			char *target_type_name =
			    rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (target_type_name) {
				char *target_id_name;

#ifdef CONFIG_RSBAC_LOG_FULL_PATH
				target_id_name
				    =
				    rsbac_kmalloc(CONFIG_RSBAC_MAX_PATH_LEN
						  + RSBAC_MAXNAMELEN);
				/* max. path name len + some extra */
#else
				target_id_name =
				    rsbac_kmalloc(2 * RSBAC_MAXNAMELEN);
				/* max. file name len + some extra */
#endif
				if (target_id_name) {
					char *tmp1 =
					    rsbac_kmalloc
					    (RSBAC_MAXNAMELEN);
					if (tmp1) {
						char *tmp2 =
						    rsbac_kmalloc
						    (RSBAC_MAXNAMELEN);
						if (tmp2) {
							get_target_name
							    (target_type_name,
							     target,
							     target_id_name,
							     tid);

							rsbac_printk
							    (KERN_INFO "mac_auto_read(): Changing process %u (15%s, owner %u) current categories from %s to %s for %s %s\n",
							     pid,
							     current->comm,
							     current_uid(),
							     u64tostrmac
							     (tmp1,
							      curr_categories),
							     u64tostrmac
							     (tmp2,
							      target_categories),
							     target_type_name,
							     target_id_name);
							rsbac_kfree(tmp2);
						}
						rsbac_kfree(tmp1);
					}
					rsbac_kfree(target_id_name);
				}
				rsbac_kfree(target_type_name);
			}
#endif
			if (rsbac_set_attr(SW_MAC, T_PROCESS, i_tid, A_mac_curr_categories, attr_val1)) {	/* failed! */
				rsbac_ds_set_error("mac_auto_read",
						   A_none);
				return (NOT_GRANTED);
			}
		}
		if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_max_read_categories, &attr_val2, TRUE)) {	/* failed! */
			rsbac_ds_get_error("mac_auto_read", A_none);
			return (NOT_GRANTED);
		}
		if ((attr_val1.mac_categories & attr_val2.mac_categories)
		    != attr_val1.mac_categories) {
			if (rsbac_set_attr(SW_MAC, T_PROCESS, i_tid, A_max_read_categories, attr_val1)) {	/* failed! */
				rsbac_ds_set_error("mac_auto_read",
						   A_none);
				return (NOT_GRANTED);
			}
		}
	}

	/* Everything done, so return */
	return (GRANTED);
}

static enum rsbac_adf_req_ret_t
auto_read(rsbac_pid_t pid,
	  enum rsbac_target_t target,
	  union rsbac_target_id_t tid, rsbac_boolean_t set_level)
{
	return auto_read_attr(pid,
			      target,
			      tid,
			      A_security_level,
			      A_mac_categories, set_level);
}


/* auto-read-write() */
/* combines auto-read and auto-write */

static enum rsbac_adf_req_ret_t
auto_read_write_attr(rsbac_pid_t pid,
		     enum rsbac_target_t target,
		     union rsbac_target_id_t tid,
		     enum rsbac_attribute_t t_level_attr,
		     enum rsbac_attribute_t t_cat_attr,
		     rsbac_boolean_t set_level)
{
	rsbac_security_level_t curr_level;
	rsbac_mac_category_vector_t curr_categories;
	rsbac_security_level_t target_sec_level;
	rsbac_mac_category_vector_t target_categories;
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t attr_val1;
	union rsbac_attribute_value_t attr_val2;
	rsbac_mac_process_flags_t flags;
	rsbac_boolean_t mac_auto_used_level = FALSE;
	rsbac_boolean_t mac_auto_used_cat = FALSE;
	rsbac_boolean_t raise_object_level = FALSE;
	rsbac_boolean_t raise_object_cat = FALSE;

	/* first check for mac_override, which allows everything */
	i_tid.process = pid;
	if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_mac_process_flags, &attr_val1, FALSE)) {	/* failed! */
		rsbac_ds_get_error("mac_auto_read_write", A_none);
		return (NOT_GRANTED);
	}
	flags = attr_val1.mac_process_flags;
	if (flags & MAC_override)
		return GRANTED;

	/* Get current security level */
	if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_current_sec_level, &attr_val1, FALSE)) {	/* failed! */
		rsbac_ds_get_error("mac_auto_read_write", A_none);
		return (NOT_GRANTED);
	}
	curr_level = attr_val1.security_level;
	/* Get current categories */
	if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_mac_curr_categories, &attr_val1, FALSE)) {	/* failed! */
		rsbac_ds_get_error("mac_auto_read_write", A_none);
		return (NOT_GRANTED);
	}
	curr_categories = attr_val1.mac_categories;
	/* Get target security level */
	if (rsbac_get_attr(SW_MAC, target, tid, t_level_attr, &attr_val1, TRUE)) {	/* failed! */
		rsbac_ds_get_error("mac_auto_read_write", A_none);
		return (NOT_GRANTED);
	}
	target_sec_level = attr_val1.security_level;
	/* Get target categories */
	if (rsbac_get_attr(SW_MAC, target, tid, t_cat_attr, &attr_val1, TRUE)) {	/* failed! */
		rsbac_ds_get_error("mac_auto_read_write", A_none);
		return (NOT_GRANTED);
	}
	target_categories = attr_val1.mac_categories;

	if (target_sec_level > curr_level) {
		if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_security_level, &attr_val1, FALSE)) {	/* failed! */
			rsbac_ds_get_error("mac_auto_read_write", A_none);
			return (NOT_GRANTED);
		}
		if (attr_val1.security_level < target_sec_level) {
			rsbac_pr_debug(adf_mac, "pid %u/%.15s: security_level %u under target_sec_level %u, no override -> NOT_GRANTED!\n",
				       current->pid, current->comm,
				       attr_val1.security_level,
				       target_sec_level);
			return (NOT_GRANTED);
		}
		/* curr_level < target_level <= max_level */
		/* -> need mac_auto, (write_up && read_up)
		 * or trusted (with read option) */
		if (flags & MAC_auto) {
			/* check min_write boundary */
			if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_min_write_open, &attr_val1, FALSE)) {	/* failed! */
				rsbac_ds_get_error("mac_auto_read_write",
						   A_none);
				return (NOT_GRANTED);
			}
			if (attr_val1.security_level < target_sec_level) {
				if (!
				    ((flags & MAC_write_up)
				     && (flags & MAC_read_up))
#ifdef CONFIG_RSBAC_MAC_TRUSTED_READ
&& !(flags & MAC_trusted)
#endif
				    ) {
					/* Try mac_file_flags on the target, if FD object */
					switch (target) {
					case T_FILE:
					case T_DIR:
					case T_FIFO:
					case T_SYMLINK:
					case T_UNIXSOCK:
						if (rsbac_get_attr(SW_MAC, target, tid, A_mac_file_flags, &attr_val1, TRUE)) {	/* failed! */
							rsbac_ds_get_error
							    ("mac_auto_read_write",
							     A_none);
							return
							    (NOT_GRANTED);
						}
						if (((attr_val1.
						      mac_file_flags &
						      MAC_write_up)
						     && (attr_val1.
							 mac_file_flags &
							 MAC_read_up)
						    )
#ifdef CONFIG_RSBAC_MAC_TRUSTED_READ
						    || (flags &
							MAC_trusted)
#endif
						    ) {
							break;
						}
						/* fall through */

					default:
						rsbac_pr_debug(adf_mac, "pid %u/%.15s: min_write_open %u under target_sec_level %u, no read_up or trusted -> NOT_GRANTED!\n",
							     current->pid,
							     current->comm,
							     attr_val1.
							     security_level,
							     target_sec_level);
						return (NOT_GRANTED);
					}
				}
			} else
				mac_auto_used_level = TRUE;
		} else {
			if (!
			    ((flags & MAC_write_up)
			     && (flags & MAC_read_up))
#ifdef CONFIG_RSBAC_MAC_TRUSTED_READ
&& !(flags & MAC_trusted)
#endif
			    ) {
				/* Try mac_file_flags on the target, if FD object */
				switch (target) {
				case T_FILE:
				case T_DIR:
				case T_FIFO:
				case T_SYMLINK:
				case T_UNIXSOCK:
					if (rsbac_get_attr(SW_MAC, target, tid, A_mac_file_flags, &attr_val1, TRUE)) {	/* failed! */
						rsbac_ds_get_error
						    ("mac_auto_read_write",
						     A_none);
						return (NOT_GRANTED);
					}
					if (((attr_val1.
					      mac_file_flags &
					      MAC_write_up)
					     && (attr_val1.
						 mac_file_flags &
						 MAC_read_up)
					    )
#ifdef CONFIG_RSBAC_MAC_TRUSTED_READ
					    || (flags & MAC_trusted)
#endif
					    ) {
						break;
					}
					/* fall through */

				default:
					rsbac_pr_debug(adf_mac, "pid %u/%.15s: current level %u under target_sec_level %u, no auto, (write_up && read_up) or trusted -> NOT_GRANTED!\n",
						       current->pid,
						       current->comm,
						       curr_level,
						       target_sec_level);
					return (NOT_GRANTED);
				}
			}
		}
	} else if (target_sec_level < curr_level) {
		if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_min_security_level, &attr_val1, FALSE)) {	/* failed! */
			rsbac_ds_get_error("mac_auto_read_write", A_none);
			return (NOT_GRANTED);
		}
		if (attr_val1.security_level > target_sec_level) {
			rsbac_pr_debug(adf_mac, "pid %u/%.15s: min_security_level %u over target_sec_level %u, no override -> NOT_GRANTED!\n",
				       current->pid,
				       current->comm, attr_val1.security_level,
				       target_sec_level);
			return (NOT_GRANTED);
		}
		/* min_level <= target_level < curr_level -> need mac_auto,
		 * write_down or trusted */
		if (flags & MAC_auto) {
			/* check max_read boundary */
			if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_max_read_open, &attr_val1, FALSE)) {	/* failed! */
				rsbac_ds_get_error("mac_auto_read_write",
						   A_none);
				return (NOT_GRANTED);
			}
			if (attr_val1.security_level > target_sec_level) {
				if (!(flags & MAC_write_down)
				    && !(flags & MAC_trusted)
				    ) {
					/* Try mac_file_flags on the target,
					 * if FD object */
					switch (target) {
					case T_FILE:
					case T_DIR:
					case T_FIFO:
					case T_SYMLINK:
					case T_UNIXSOCK:
						if (rsbac_get_attr(SW_MAC, target, tid, A_mac_file_flags, &attr_val1, TRUE)) {	/* failed! */
							rsbac_ds_get_error
							    ("mac_auto_read_write",
							     A_none);
							return
							    (NOT_GRANTED);
						}
						if ((attr_val1.
						     mac_file_flags &
						     MAC_write_down)
						    || (attr_val1.
							mac_file_flags &
							MAC_trusted)
						    ) {
							if (attr_val1.
							    mac_file_flags
							    & MAC_auto) {
								raise_object_level
								    = TRUE;
							}
							break;
						}
						/* fall through */

					default:
						rsbac_pr_debug(adf_mac, "pid %u/%.15s: max_read_open %u over target_sec_level %u, no write_down or trusted -> NOT_GRANTED!\n",
							     current->pid,
							     current->comm,
							     attr_val1.
							     security_level,
							     target_sec_level);
						return (NOT_GRANTED);
					}
				}
			} else
				mac_auto_used_level = TRUE;
		} else {
			if (!(flags & MAC_write_down)
			    && !(flags & MAC_trusted)
			    ) {
				/* Try mac_file_flags on the target,
				 * if FD object */
				switch (target) {
				case T_FILE:
				case T_DIR:
				case T_FIFO:
				case T_SYMLINK:
				case T_UNIXSOCK:
					if (rsbac_get_attr(SW_MAC, target, tid, A_mac_file_flags, &attr_val1, TRUE)) {	/* failed! */
						rsbac_ds_get_error
						    ("mac_auto_read_write",
						     A_none);
						return (NOT_GRANTED);
					}
					if ((attr_val1.
					     mac_file_flags &
					     MAC_write_down)
					    || (attr_val1.
						mac_file_flags &
						MAC_trusted)
					    ) {
						if (attr_val1.
						    mac_file_flags &
						    MAC_auto) {
							raise_object_level
							    = TRUE;
						}
						break;
					}
					/* fall through */

				default:
					rsbac_pr_debug(adf_mac, "pid %u/%.15s: current security_level %u over target_sec_level %u, no auto, write_down or trusted -> NOT_GRANTED!\n",
						       current->pid,
						       current->comm,
						       curr_level,
						       target_sec_level);
					return (NOT_GRANTED);
				}
			}
		}
	}
	if ((target_categories & curr_categories) != target_categories) {
		if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_mac_categories, &attr_val1, FALSE)) {	/* failed! */
			rsbac_ds_get_error("mac_auto_read_write", A_none);
			return (NOT_GRANTED);
		}
		if ((target_categories & attr_val1.mac_categories) !=
		    target_categories) {
#ifdef CONFIG_RSBAC_DEBUG
			if (rsbac_debug_adf_mac) {
				char *tmp =
				    rsbac_kmalloc(RSBAC_MAXNAMELEN);

				if (tmp) {
					char *tmp2 =
					    rsbac_kmalloc
					    (RSBAC_MAXNAMELEN);

					if (tmp2) {
						u64tostrmac(tmp,
							    attr_val1.
							    mac_categories);
						u64tostrmac(tmp2,
							    target_categories);
						rsbac_pr_debug(adf_mac, "pid %u/%.15s: max_categories %s under target categories %s, no override -> NOT_GRANTED!\n",
							     current->pid,
							     current->comm,
							     tmp, tmp2);
						rsbac_kfree(tmp2);
					}
					rsbac_kfree(tmp);
				}
			}
#endif
			return (NOT_GRANTED);
		}
		/* curr_categories < target_categories <= max_categories */
		/* -> need mac_auto, (read_up && write_up) or 
		 * trusted (with read option) */
		if (flags & MAC_auto) {
			/* check min_write boundary */
			if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_min_write_categories, &attr_val1, FALSE)) {	/* failed! */
				rsbac_ds_get_error("mac_auto_read_write",
						   A_none);
				return (NOT_GRANTED);
			}
			if ((target_categories & attr_val1.
			     mac_categories) != target_categories) {
				if (!
				    ((flags & MAC_write_up)
				     && (flags & MAC_read_up))
#ifdef CONFIG_RSBAC_MAC_TRUSTED_READ
&& !(flags & MAC_trusted)
#endif
				    ) {
					/* Try mac_file_flags on the target,
					 * if FD object */
					switch (target) {
					case T_FILE:
					case T_DIR:
					case T_FIFO:
					case T_SYMLINK:
					case T_UNIXSOCK:
						if (rsbac_get_attr(SW_MAC, target, tid, A_mac_file_flags, &attr_val1, TRUE)) {	/* failed! */
							rsbac_ds_get_error
							    ("mac_auto_read_write",
							     A_none);
							return
							    (NOT_GRANTED);
						}
						if (((attr_val1.
						      mac_file_flags &
						      MAC_write_up)
						     && (attr_val1.
							 mac_file_flags &
							 MAC_read_up)
						    )
#ifdef CONFIG_RSBAC_MAC_TRUSTED_READ
						    || (flags &
							MAC_trusted)
#endif
						    ) {
							break;
						}
						/* fall through */

					default:
#ifdef CONFIG_RSBAC_DEBUG
						if (rsbac_debug_adf_mac) {
							char *tmp =
							    rsbac_kmalloc
							    (RSBAC_MAXNAMELEN);

							if (tmp) {
								char *tmp2
								    =
								    rsbac_kmalloc
								    (RSBAC_MAXNAMELEN);

								if (tmp2) {
									u64tostrmac
									    (tmp,
									     attr_val1.
									     mac_categories);
									u64tostrmac
									    (tmp2,
									     target_categories);
									rsbac_pr_debug(adf_mac, "pid %u/%.15s: min_write_categories %s under target categories %s, no (read_up and write_up) or trusted with read option -> NOT_GRANTED!\n",
									     current->
									     pid,
									     current->
									     comm,
									     tmp,
									     tmp2);
									rsbac_kfree
									    (tmp2);
								}
								rsbac_kfree
								    (tmp);
							}
						}
#endif
						return (NOT_GRANTED);
					}
				}
			} else
				mac_auto_used_cat = TRUE;
		} else {
			if (!
			    ((flags & MAC_write_up)
			     && (flags & MAC_read_up))
#ifdef CONFIG_RSBAC_MAC_TRUSTED_READ
&& !(flags & MAC_trusted)
#endif
			    ) {
				/* Try mac_file_flags on the target,
				 * if FD object */
				switch (target) {
				case T_FILE:
				case T_DIR:
				case T_FIFO:
				case T_SYMLINK:
				case T_UNIXSOCK:
					if (rsbac_get_attr(SW_MAC, target, tid, A_mac_file_flags, &attr_val1, TRUE)) {	/* failed! */
						rsbac_ds_get_error
						    ("mac_auto_read_write",
						     A_none);
						return (NOT_GRANTED);
					}
					if (((attr_val1.
					      mac_file_flags &
					      MAC_write_up)
					     && (attr_val1.
						 mac_file_flags &
						 MAC_read_up)
					    )
#ifdef CONFIG_RSBAC_MAC_TRUSTED_READ
					    || (flags & MAC_trusted)
#endif
					    ) {
						break;
					}
					/* fall through */

				default:
#ifdef CONFIG_RSBAC_DEBUG
					if (rsbac_debug_adf_mac) {
						char *tmp =
						    rsbac_kmalloc
						    (RSBAC_MAXNAMELEN);

						if (tmp) {
							char *tmp2 =
							    rsbac_kmalloc
							    (RSBAC_MAXNAMELEN);

							if (tmp2) {
								u64tostrmac
								    (tmp,
								     curr_categories);
								u64tostrmac
								    (tmp2,
								     target_categories);
								rsbac_pr_debug(adf_mac, "pid %u/%.15s: curr_categories %s under target categories %s, no auto, (read_up and write_up) or trusted -> NOT_GRANTED!\n",
								     current->
								     pid,
								     current->
								     comm,
								     tmp,
								     tmp2);
								rsbac_kfree
								    (tmp2);
							}
							rsbac_kfree(tmp);
						}
					}
#endif
					return (NOT_GRANTED);
				}
			}
		}
	} else
	    if ((target_categories & curr_categories) != curr_categories) {
		if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_mac_min_categories, &attr_val1, FALSE)) {	/* failed! */
			rsbac_ds_get_error("mac_auto_read_write", A_none);
			return (NOT_GRANTED);
		}
		if ((target_categories & attr_val1.mac_categories) !=
		    attr_val1.mac_categories) {
#ifdef CONFIG_RSBAC_DEBUG
			if (rsbac_debug_adf_mac) {
				char *tmp =
				    rsbac_kmalloc(RSBAC_MAXNAMELEN);

				if (tmp) {
					char *tmp2 =
					    rsbac_kmalloc
					    (RSBAC_MAXNAMELEN);

					if (tmp2) {
						u64tostrmac(tmp,
							    attr_val1.
							    mac_categories);
						u64tostrmac(tmp2,
							    target_categories);
						rsbac_pr_debug(adf_mac, "pid %u/%.15s: min_categories %s over target categories %s, no override -> NOT_GRANTED!\n",
							     current->pid,
							     current->comm,
							     tmp, tmp2);
						rsbac_kfree(tmp2);
					}
					rsbac_kfree(tmp);
				}
			}
#endif
			return (NOT_GRANTED);
		}
		/* min_level <= target_level < curr_level -> need mac_auto,
		 * write_down or trusted */
		if (flags & MAC_auto) {
			/* check max_read boundary */
			if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_max_read_categories, &attr_val1, FALSE)) {	/* failed! */
				rsbac_ds_get_error("mac_auto_read_write",
						   A_none);
				return (NOT_GRANTED);
			}
			if ((target_categories & attr_val1.
			     mac_categories) != attr_val1.mac_categories) {
				if (!(flags & MAC_write_down)
				    && !(flags & MAC_trusted)
				    ) {
					/* Try mac_file_flags on the target,
					 * if FD object */
					switch (target) {
					case T_FILE:
					case T_DIR:
					case T_FIFO:
					case T_SYMLINK:
					case T_UNIXSOCK:
						if (rsbac_get_attr(SW_MAC, target, tid, A_mac_file_flags, &attr_val1, TRUE)) {	/* failed! */
							rsbac_ds_get_error
							    ("mac_auto_read_write",
							     A_none);
							return
							    (NOT_GRANTED);
						}
						if ((attr_val1.
						     mac_file_flags &
						     MAC_write_down)
						    || (attr_val1.
							mac_file_flags &
							MAC_trusted)
						    ) {
							if (attr_val1.
							    mac_file_flags
							    & MAC_auto) {
								raise_object_cat
								    = TRUE;
							}
							break;
						}
						/* fall through */

					default:
#ifdef CONFIG_RSBAC_DEBUG
						if (rsbac_debug_adf_mac) {
							char *tmp =
							    rsbac_kmalloc
							    (RSBAC_MAXNAMELEN);

							if (tmp) {
								char *tmp2
								    =
								    rsbac_kmalloc
								    (RSBAC_MAXNAMELEN);

								if (tmp2) {
									u64tostrmac
									    (tmp,
									     attr_val1.
									     mac_categories);
									u64tostrmac
									    (tmp2,
									     target_categories);
									rsbac_pr_debug(adf_mac, "pid %u/%.15s: max_read_categories %s over target categories %s, no write_down or trusted -> NOT_GRANTED!\n",
									     current->
									     pid,
									     current->
									     comm,
									     tmp,
									     tmp2);
									rsbac_kfree
									    (tmp2);
								}
								rsbac_kfree
								    (tmp);
							}
						}
#endif
						return (NOT_GRANTED);
					}
				}
			} else
				mac_auto_used_cat = TRUE;
		} else {
			if (!(flags & MAC_write_down)
			    && !(flags & MAC_trusted)
			    ) {
				/* Try mac_file_flags on the target,
				 * if FD object */
				switch (target) {
				case T_FILE:
				case T_DIR:
				case T_FIFO:
				case T_SYMLINK:
				case T_UNIXSOCK:
					if (rsbac_get_attr(SW_MAC, target, tid, A_mac_file_flags, &attr_val1, TRUE)) {	/* failed! */
						rsbac_ds_get_error
						    ("mac_auto_read_write",
						     A_none);
						return (NOT_GRANTED);
					}
					if ((attr_val1.
					     mac_file_flags &
					     MAC_write_down)
					    || (attr_val1.
						mac_file_flags &
						MAC_trusted)
					    ) {
						if (attr_val1.
						    mac_file_flags &
						    MAC_auto) {
							raise_object_cat =
							    TRUE;
						}
						break;
					}
					/* fall through */

				default:
#ifdef CONFIG_RSBAC_DEBUG
					if (rsbac_debug_adf_mac) {
						char *tmp =
						    rsbac_kmalloc
						    (RSBAC_MAXNAMELEN);

						if (tmp) {
							char *tmp2 =
							    rsbac_kmalloc
							    (RSBAC_MAXNAMELEN);

							if (tmp2) {
								u64tostrmac
								    (tmp,
								     curr_categories);
								u64tostrmac
								    (tmp2,
								     target_categories);
								rsbac_pr_debug(adf_mac, "pid %u/%.15s: curr_categories %s over target categories %s, no auto, write_down or trusted -> NOT_GRANTED!\n",
								     current->
								     pid,
								     current->
								     comm,
								     tmp,
								     tmp2);
								rsbac_kfree
								    (tmp2);
							}
							rsbac_kfree(tmp);
						}
					}
#endif
					return (NOT_GRANTED);
				}
			}
		}
	}

	/* grant area */

	/* adjust current_sec_level and min_write_level, */
	/* if set_level is true and mac_auto has been used */
	if (set_level && (mac_auto_used_level || raise_object_level)
	    ) {
#ifdef CONFIG_RSBAC_MAC_LOG_LEVEL_CHANGE
		{
			char *target_type_name;
			char *target_id_name;

			target_type_name = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (target_type_name) {
#ifdef CONFIG_RSBAC_LOG_FULL_PATH
				target_id_name
				    =
				    rsbac_kmalloc(CONFIG_RSBAC_MAX_PATH_LEN
						  + RSBAC_MAXNAMELEN);
				/* max. path name len + some extra */
#else
				target_id_name =
				    rsbac_kmalloc(2 * RSBAC_MAXNAMELEN);
				/* max. file name len + some extra */
#endif
				if (target_id_name) {
					get_target_name(target_type_name,
							target,
							target_id_name,
							tid);

					if (mac_auto_used_level) {
						rsbac_printk(KERN_INFO "mac_auto_read_write(): Changing process %u (%.15s, owner %u) current level from %u to %u for %s %s\n",
							     pid,
							     current->comm,
							     current_uid(),
							     curr_level,
							     target_sec_level,
							     target_type_name,
							     target_id_name);
					} else {
						rsbac_printk(KERN_INFO "mac_auto_read_write(): Process %u (%.15s, owner %u): Raising object level from %u to %u for %s %s\n",
							     pid,
							     current->comm,
							     current_uid(),
							     target_sec_level,
							     curr_level,
							     target_type_name,
							     target_id_name);
					}
					rsbac_kfree(target_id_name);
				}
				rsbac_kfree(target_type_name);
			}
		}
#endif
		if (mac_auto_used_level) {
			i_tid.process = pid;
			attr_val1.current_sec_level = target_sec_level;
			if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_min_write_open, &attr_val2, TRUE)) {	/* failed! */
				rsbac_ds_get_error("mac_auto_read_write",
						   A_none);
				return (NOT_GRANTED);
			}
			if (attr_val1.min_write_open <
			    attr_val2.min_write_open) {
				if (rsbac_set_attr(SW_MAC, T_PROCESS, i_tid, A_min_write_open, attr_val1)) {	/* failed! */
					rsbac_ds_set_error
					    ("mac_auto_read_write",
					     A_none);
					return (NOT_GRANTED);
				}
			}
			if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_max_read_open, &attr_val2, TRUE)) {	/* failed! */
				rsbac_ds_get_error("mac_auto_read_write",
						   A_none);
				return (NOT_GRANTED);
			}
			if (attr_val1.max_read_open >
			    attr_val2.max_read_open) {
				if (rsbac_set_attr(SW_MAC, T_PROCESS, i_tid, A_max_read_open, attr_val1)) {	/* failed! */
					rsbac_ds_set_error
					    ("mac_auto_read_write",
					     A_none);
					return (NOT_GRANTED);
				}
			}
			if (rsbac_set_attr(SW_MAC, T_PROCESS, i_tid, A_current_sec_level, attr_val1)) {	/* failed! */
				rsbac_ds_set_error("mac_auto_read_write",
						   A_none);
				return (NOT_GRANTED);
			}
		} else {
			attr_val1.security_level = curr_level;
			if (rsbac_set_attr(SW_MAC, target, tid, A_security_level, attr_val1)) {	/* failed! */
				rsbac_ds_set_error("mac_auto_read_write",
						   A_none);
				return (NOT_GRANTED);
			}
		}
	}
	/* adjust current_categories and min_write_categories, */
	/* if set_level is true and mac_auto has been used */
	if (set_level && (mac_auto_used_cat || raise_object_cat)
	    ) {
#ifdef CONFIG_RSBAC_MAC_LOG_LEVEL_CHANGE
		{
			char *target_type_name =
			    rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (target_type_name) {
				char *target_id_name;

#ifdef CONFIG_RSBAC_LOG_FULL_PATH
				target_id_name
				    =
				    rsbac_kmalloc(CONFIG_RSBAC_MAX_PATH_LEN
						  + RSBAC_MAXNAMELEN);
				/* max. path name len + some extra */
#else
				target_id_name =
				    rsbac_kmalloc(2 * RSBAC_MAXNAMELEN);
				/* max. file name len + some extra */
#endif
				if (target_id_name) {
					char *tmp1 =
					    rsbac_kmalloc
					    (RSBAC_MAXNAMELEN);
					if (tmp1) {
						char *tmp2 =
						    rsbac_kmalloc
						    (RSBAC_MAXNAMELEN);
						if (tmp2) {
							get_target_name
							    (target_type_name,
							     target,
							     target_id_name,
							     tid);

							if (mac_auto_used_cat) {
								rsbac_printk
								    (KERN_INFO "mac_auto_read_write(): Changing process %u (%.15s, owner %u) current categories from %s to %s for %s %s\n",
								     pid,
								     current->
								     comm,
								     current_uid(),
								     u64tostrmac
								     (tmp1,
								      curr_categories),
								     u64tostrmac
								     (tmp2,
								      target_categories),
								     target_type_name,
								     target_id_name);
							} else {
								rsbac_printk
								    (KERN_INFO "mac_auto_read_write(): Process %u (%.15s, owner %u): raising current categories from %s to %s for %s %s\n",
								     pid,
								     current->
								     comm,
								     current_uid(),
								     u64tostrmac
								     (tmp2,
								      target_categories),
								     u64tostrmac
								     (tmp1,
								      curr_categories),
								     target_type_name,
								     target_id_name);
							}
							rsbac_kfree(tmp2);
						}
						rsbac_kfree(tmp1);
					}
					rsbac_kfree(target_id_name);
				}
				rsbac_kfree(target_type_name);
			}
		}
#endif
		if (mac_auto_used_cat) {
			i_tid.process = pid;
			attr_val1.mac_categories = target_categories;
			if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_min_write_categories, &attr_val2, TRUE)) {	/* failed! */
				rsbac_ds_set_error("mac_auto_read_write",
						   A_none);
				return (NOT_GRANTED);
			}
			if ((attr_val1.mac_categories & attr_val2.
			     mac_categories)
			    != attr_val2.mac_categories) {
				if (rsbac_set_attr(SW_MAC, T_PROCESS, i_tid, A_min_write_categories, attr_val1)) {	/* failed! */
					rsbac_ds_set_error
					    ("mac_auto_read_write",
					     A_none);
					return (NOT_GRANTED);
				}
			}
			if (rsbac_get_attr(SW_MAC, T_PROCESS, i_tid, A_max_read_categories, &attr_val2, TRUE)) {	/* failed! */
				rsbac_ds_get_error("mac_auto_read_write",
						   A_none);
				return (NOT_GRANTED);
			}
			if ((attr_val1.mac_categories & attr_val2.
			     mac_categories)
			    != attr_val1.mac_categories) {
				if (rsbac_set_attr(SW_MAC, T_PROCESS, i_tid, A_max_read_categories, attr_val1)) {	/* failed! */
					rsbac_ds_set_error
					    ("mac_auto_read_write",
					     A_none);
					return (NOT_GRANTED);
				}
			}
			if (rsbac_set_attr(SW_MAC, T_PROCESS, i_tid, A_mac_curr_categories, attr_val1)) {	/* failed! */
				rsbac_ds_set_error("mac_auto_read_write",
						   A_none);
				return (NOT_GRANTED);
			}
		} else {
			attr_val1.mac_categories = curr_categories;
			if (rsbac_set_attr(SW_MAC, target, tid, A_mac_categories, attr_val1)) {	/* failed! */
				rsbac_ds_set_error("mac_auto_read_write",
						   A_none);
				return (NOT_GRANTED);
			}
		}
	}

	/* Everything done, so return */
	return (GRANTED);
}

static enum rsbac_adf_req_ret_t
auto_read_write(rsbac_pid_t pid,
		enum rsbac_target_t target,
		union rsbac_target_id_t tid, rsbac_boolean_t set_level)
{
	return auto_read_write_attr(pid,
				    target,
				    tid,
				    A_security_level,
				    A_mac_categories, set_level);
}

/************************************************* */
/*          Externally visible functions           */
/************************************************* */

inline enum rsbac_adf_req_ret_t
rsbac_adf_request_mac(enum rsbac_adf_request_t request,
		      rsbac_pid_t caller_pid,
		      enum rsbac_target_t target,
		      union rsbac_target_id_t tid,
		      enum rsbac_attribute_t attr,
		      union rsbac_attribute_value_t attr_val,
		      rsbac_uid_t owner)
{
	enum rsbac_adf_req_ret_t result = DO_NOT_CARE;
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val1;
#if defined(CONFIG_RSBAC_MAC_NET_OBJ_PROT)
	union rsbac_attribute_value_t i_attr_val2;
#endif

	switch (request) {
	case R_ADD_TO_KERNEL:
		switch (target) {
		case T_FILE:
		case T_DEV:
		case T_NONE:
			/* test owner's mac_role */
			return mac_check_role(owner, SR_administrator);

			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_ALTER:
		/* only for IPC */
		if (target == T_IPC) {
			/* and perform auto-write without setting attributes */
			return (auto_write(caller_pid,
					   target, tid, FALSE));
		} else
			/* all other targets are unknown */
			return (DO_NOT_CARE);
		break;

	case R_APPEND_OPEN:
		switch (target) {
		case T_FILE:
		case T_FIFO:
		case T_UNIXSOCK:
			/* and perform auto-write without setting attributes */
			return (auto_write(caller_pid,
					   target, tid, FALSE));
			break;
		case T_IPC:
			/* and perform auto-write without setting attributes */
			return (auto_write(caller_pid,
					   target, tid, FALSE));
			break;
		case T_DEV:
			/* Only check for devices with mac_check set */
			if (rsbac_get_attr(SW_MAC,
					   T_DEV,
					   tid,
					   A_mac_check,
					   &i_attr_val1, TRUE)) {
				rsbac_ds_get_error("rsbac_adf_request_mac",
						   A_none);
				return (NOT_GRANTED);
			}
			if (!i_attr_val1.mac_check)
				return (DO_NOT_CARE);
			/* and perform auto-write without setting attributes */
			return (auto_write(caller_pid,
					   target, tid, FALSE));
			break;
			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_CHANGE_GROUP:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
		case T_UNIXSOCK:
			/* and perform auto-write without setting attributes */
			return (auto_write(caller_pid,
					   target, tid, FALSE));
		case T_IPC:
			/* and perform auto-write without setting attributes */
			return (auto_write(caller_pid,
					   target, tid, FALSE));

#if defined(CONFIG_RSBAC_MAC_UM_PROT)
		case T_USER:
			/* Security Officer? */
			return mac_check_role(owner, SR_security_officer);
#endif
			/* We do not care about */
			/* all other cases */
		default:
			return (DO_NOT_CARE);
		}

	case R_CHANGE_OWNER:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
		case T_UNIXSOCK:
			/* and perform auto-write without setting attributes */
			return (auto_write(caller_pid,
					   target, tid, FALSE));

		case T_IPC:
			return (auto_write(caller_pid,
					   target, tid, FALSE));

			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_CHDIR:
		switch (target) {
		case T_DIR:
			/* and perform auto-read without setting attributes */
			return (auto_read(caller_pid, target, tid, FALSE));
			break;
			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_CREATE:
		switch (target) {
			/* Creating dir or (pseudo) file IN target dir! */
		case T_DIR:
#ifdef CONFIG_RSBAC_MAC_LIGHT
			return GRANTED;
#else
			/* Mode of created item is ignored! */
			/* and perform auto-write without setting attributes */
			return (auto_write(caller_pid,
					   target, tid, FALSE));
#endif
			break;

#ifdef CONFIG_RSBAC_MAC_NET_OBJ_PROT
		case T_NETTEMP:
			return mac_check_role(owner, SR_security_officer);

		case T_NETOBJ:
			/* and perform auto-write without setting attributes */
			return (auto_write_attr(caller_pid,
						target,
						tid,
						A_local_sec_level,
						A_local_mac_categories,
						FALSE));
#endif

#if defined(CONFIG_RSBAC_MAC_UM_PROT)
		case T_USER:
		case T_GROUP:
			/* Security Officer? */
			return mac_check_role(owner, SR_security_officer);
#endif
			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_DELETE:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
		case T_UNIXSOCK:
			/* and perform auto-write without setting attributes */
			return (auto_write(caller_pid,
					   target, tid, FALSE));
			break;
		case T_IPC:
			/* and perform auto-write without setting attributes */
			return (auto_write(caller_pid,
					   target, tid, FALSE));
			break;

#ifdef CONFIG_RSBAC_MAC_NET_OBJ_PROT
		case T_NETTEMP:
			return mac_check_role(owner, SR_security_officer);
#endif
#if defined(CONFIG_RSBAC_MAC_UM_PROT)
		case T_USER:
		case T_GROUP:
			/* Security Officer? */
			return mac_check_role(owner, SR_security_officer);
#endif

			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_EXECUTE:
	case R_MAP_EXEC:
		switch (target) {
		case T_FILE:
			/* and perform auto-read without setting attributes */
			return (auto_read(caller_pid, target, tid, FALSE));

			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_GET_PERMISSIONS_DATA:
		switch (target) {
#if defined(CONFIG_RSBAC_MAC_UM_PROT)
		case T_USER:
		case T_GROUP:
			/* Security Officer? */
			return mac_check_role(owner, SR_security_officer);
#endif
#ifdef CONFIG_RSBAC_MAC_NET_OBJ_PROT
		case T_NETOBJ:
			/* and perform auto-read without setting attributes */
			return (auto_read_attr(caller_pid,
					       target,
					       tid,
					       A_local_sec_level,
					       A_local_mac_categories,
					       FALSE));
#endif

		default:
			return (DO_NOT_CARE);
		}

	case R_GET_STATUS_DATA:
		switch (target) {
		case T_SCD:
			/* target rsbaclog? only for secoff */
			if (tid.scd != ST_rsbac_log)
				return (GRANTED);
			/* Secoff? */
			if (mac_check_role(owner, SR_security_officer) ==
			    NOT_GRANTED)
				return mac_check_role(owner, SR_auditor);
			else
				return GRANTED;

		case T_PROCESS:
			/* perform auto-read without setting attributes */
			return (auto_read_attr(caller_pid,
					       target,
					       tid,
					       A_current_sec_level,
					       A_mac_curr_categories,
					       FALSE));

#ifdef CONFIG_RSBAC_MAC_NET_OBJ_PROT
		case T_NETOBJ:
			/* and perform auto-read without setting attributes */
			return (auto_read_attr(caller_pid,
					       target,
					       tid,
					       A_local_sec_level,
					       A_local_mac_categories,
					       FALSE));
#endif

		default:
			return (DO_NOT_CARE);
		}

	case R_LINK_HARD:
		switch (target) {
		case T_FILE:
		case T_FIFO:
		case T_SYMLINK:
			/* and perform auto-write without setting attributes */
			return (auto_write(caller_pid,
					   target, tid, FALSE));
			break;
			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_MODIFY_ACCESS_DATA:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
		case T_UNIXSOCK:
			/* and perform auto-write without setting attributes */
			return (auto_write(caller_pid,
					   target, tid, FALSE));
			break;
			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_MODIFY_ATTRIBUTE:
		switch (attr) {
		case A_security_level:
		case A_initial_security_level:
		case A_local_sec_level:
		case A_remote_sec_level:
		case A_min_security_level:
		case A_mac_categories:
		case A_mac_initial_categories:
		case A_local_mac_categories:
		case A_remote_mac_categories:
		case A_mac_min_categories:
		case A_mac_user_flags:
		case A_mac_process_flags:
		case A_mac_file_flags:
		case A_system_role:
		case A_mac_role:
		case A_current_sec_level:
		case A_mac_curr_categories:
		case A_min_write_open:
		case A_max_read_open:
		case A_min_write_categories:
		case A_max_read_categories:
		case A_mac_check:
		case A_mac_auto:
		case A_mac_prop_trusted:
		case A_symlink_add_mac_level:
#ifdef CONFIG_RSBAC_MAC_GEN_PROT
		case A_pseudo:
		case A_log_array_low:
		case A_log_array_high:
		case A_local_log_array_low:
		case A_local_log_array_high:
		case A_remote_log_array_low:
		case A_remote_log_array_high:
		case A_log_program_based:
		case A_log_user_based:
		case A_symlink_add_remote_ip:
		case A_symlink_add_uid:
		case A_linux_dac_disable:
		case A_fake_root_uid:
		case A_audit_uid:
		case A_auid_exempt:
		case A_remote_ip:
		case A_kernel_thread:
		case A_vset:
		case A_program_file:
#endif
#ifdef CONFIG_RSBAC_MAC_AUTH_PROT
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
#endif
			/* All attributes (remove target!) */
		case A_none:
			/* Security Officer? */
			return mac_check_role(owner, SR_security_officer);

		default:
			return (DO_NOT_CARE);
		}

	case R_MODIFY_PERMISSIONS_DATA:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
		case T_UNIXSOCK:
		case T_IPC:
			/* and perform auto-write without setting attributes */
			return (auto_write(caller_pid,
					   target, tid, FALSE));
			break;

		case T_SCD:
#ifdef CONFIG_RSBAC_USER_MOD_IOPERM
			if (tid.scd == ST_ioports)
				return GRANTED;
#endif
			/* Security Officer? */
			i_tid.user = owner;
			if (rsbac_get_attr(SW_MAC,
					   T_USER,
					   i_tid,
					   A_mac_role,
					   &i_attr_val1, TRUE)) {
				rsbac_ds_get_error("rsbac_adf_request_mac",
						   A_none);
				return (NOT_GRANTED);
			}
			/* if sec_officer, then grant */
			if (i_attr_val1.system_role == SR_security_officer)
				return (GRANTED);
			/* For booting: if administrator and ioports, then grant */
			if ((i_attr_val1.system_role == SR_administrator)
			    && (tid.scd == ST_ioports))
				return (GRANTED);
			else
				return (NOT_GRANTED);

#ifdef CONFIG_RSBAC_MAC_NET_OBJ_PROT
		case T_NETOBJ:
			/* and perform auto-write without setting attributes */
			return (auto_write_attr(caller_pid,
						target,
						tid,
						A_local_sec_level,
						A_local_mac_categories,
						FALSE));
#endif

#if defined(CONFIG_RSBAC_MAC_UM_PROT)
		case T_USER:
		case T_GROUP:
			/* Security Officer? */
			return mac_check_role(owner, SR_security_officer);
#endif
#ifdef CONFIG_RSBAC_ALLOW_DAC_DISABLE
			/* switching Linux DAC */
		case T_NONE:
			/* Security Officer? */
			i_tid.user = owner;
			if (rsbac_get_attr(SW_MAC,
					   T_USER,
					   i_tid,
					   A_mac_role,
					   &i_attr_val1, TRUE)) {
				rsbac_ds_get_error("rsbac_adf_request_mac",
						   A_none);
				return (NOT_GRANTED);
			}
			/* if sec_officer, then grant */
			if (i_attr_val1.system_role == SR_security_officer)
				return (GRANTED);
			else
				return (NOT_GRANTED);
#endif

			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_MODIFY_SYSTEM_DATA:
		switch (target) {
		case T_SCD:
			/* target rlimit? no problem, but needed -> grant */
			if (   (tid.scd == ST_rlimit)
			    || (tid.scd == ST_priority)
			    || (tid.scd == ST_mlock)
			   )
				return (GRANTED);
			/* Get role */
			i_tid.user = owner;
			if (rsbac_get_attr(SW_MAC,
					   T_USER,
					   i_tid,
					   A_mac_role,
					   &i_attr_val1, TRUE)) {
				rsbac_ds_get_error("rsbac_adf_request_mac",
						   A_none);
				return NOT_GRANTED;
			}
			/* if rsbaclog: grant only for secoff and auditor */
			if (tid.scd == ST_rsbac_log) {
				if ((i_attr_val1.system_role ==
				     SR_security_officer)
				    || (i_attr_val1.system_role ==
					SR_auditor)
				    )
					return (GRANTED);
				else
					return (NOT_GRANTED);
			}
			/* if rsbac_log_remote: grant only for secoff */
			if (tid.scd == ST_rsbac_remote_log) {
				if ((i_attr_val1.system_role ==
				     SR_security_officer)
				    )
					return (GRANTED);
				else
					return (NOT_GRANTED);
			}
			/* if rsbac: grant for secoff and adminr */
			if (tid.scd == ST_rsbac) {
				if ((i_attr_val1.system_role ==
				     SR_security_officer)
				    || (i_attr_val1.system_role ==
					SR_administrator)
				    )
					return (GRANTED);
				else
					return (NOT_GRANTED);
			}
			/* if administrator, then grant */
			if (i_attr_val1.system_role == SR_administrator)
				return (GRANTED);
			else
				return (NOT_GRANTED);

		case T_DEV:
			if (tid.dev.type == D_block)
				return mac_check_role(owner,
						      SR_administrator);
			else
				return DO_NOT_CARE;

		case T_PROCESS:
			/* and perform auto-write without setting attributes */
			return (auto_write_attr(caller_pid,
						target,
						tid,
						A_current_sec_level,
						A_mac_curr_categories,
						FALSE));

#ifdef CONFIG_RSBAC_MAC_NET_DEV_PROT
		case T_NETDEV:
			return mac_check_role(owner, SR_administrator);
#endif
#ifdef CONFIG_RSBAC_MAC_NET_OBJ_PROT
		case T_NETOBJ:
			/* and perform auto-write without setting attributes */
			return (auto_write_attr(caller_pid,
						target,
						tid,
						A_local_sec_level,
						A_local_mac_categories,
						FALSE));
#endif

			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_MOUNT:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_DEV:
			/* test owner's mac_role: Administrator? */
#ifndef CONFIG_RSBAC_MAC_LIGHT
			if (mac_check_role(owner, SR_administrator) ==
			    NOT_GRANTED)
				return (NOT_GRANTED);
#endif
			/* test read-write access to mount dir / dev: */
			/* and perform auto-read(-write) without setting of attributes */
			if ((target == T_DEV)
			    && (attr == A_mode)
			    && (attr_val.mode & MS_RDONLY))
				return (auto_read(caller_pid,
						  target, tid, FALSE));
			else
				return (auto_read_write(caller_pid,
							target,
							tid, FALSE));

			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_READ:
		switch (target) {
		case T_DIR:
#ifdef CONFIG_RSBAC_RW
		case T_IPC:
		case T_FILE:
		case T_FIFO:
		case T_UNIXSOCK:
#endif
			/* and perform auto-read without setting attributes */
			return (auto_read(caller_pid, target, tid, FALSE));
			break;

#ifdef CONFIG_RSBAC_RW
		case T_DEV:
			/* Only check for devices with mac_check set */
			if (rsbac_get_attr(SW_MAC,
					   T_DEV,
					   tid,
					   A_mac_check,
					   &i_attr_val1, TRUE)) {
				rsbac_ds_get_error("rsbac_adf_request_mac",
						   A_none);
				return (NOT_GRANTED);
			}
			if (!i_attr_val1.mac_check)
				return (DO_NOT_CARE);
			/* and perform auto-read without setting attributes */
			return (auto_read(caller_pid, target, tid, FALSE));
			break;
#endif

#if defined(CONFIG_RSBAC_MAC_NET_OBJ_PROT)
		case T_NETTEMP:
			if (mac_check_role(owner, SR_security_officer) ==
			    GRANTED)
				return GRANTED;
			return mac_check_role(owner, SR_administrator);

		case T_NETOBJ:
			/* and perform auto-read without setting attributes */
			return (auto_read_attr(caller_pid,
					       target,
					       tid,
					       A_remote_sec_level,
					       A_remote_mac_categories,
					       FALSE));
#endif

#if defined(CONFIG_RSBAC_MAC_UM_PROT)
		case T_USER:
			/* Security Officer or Admin? */
			if (mac_check_role(owner, SR_security_officer) ==
			    GRANTED)
				return GRANTED;
			else
				return mac_check_role(owner,
						      SR_administrator);
#endif
			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}


	case R_READ_ATTRIBUTE:
		switch (attr) {
		case A_owner:
		case A_security_level:
		case A_local_sec_level:
		case A_remote_sec_level:
		case A_min_security_level:
		case A_mac_categories:
		case A_local_mac_categories:
		case A_remote_mac_categories:
		case A_mac_min_categories:
		case A_pseudo:
		case A_system_role:
		case A_mac_role:
		case A_current_sec_level:
		case A_min_write_open:
		case A_max_read_open:
		case A_mac_user_flags:
		case A_mac_process_flags:
		case A_mac_check:
		case A_mac_auto:
		case A_mac_prop_trusted:
		case A_mac_file_flags:
		case A_initial_security_level:
		case A_mac_initial_categories:
		case A_symlink_add_mac_level:
#ifdef CONFIG_RSBAC_MAC_GEN_PROT
		case A_log_array_low:
		case A_log_array_high:
		case A_log_program_based:
		case A_log_user_based:
		case A_symlink_add_remote_ip:
		case A_symlink_add_uid:
		case A_fake_root_uid:
		case A_audit_uid:
		case A_auid_exempt:
		case A_remote_ip:
		case A_kernel_thread:
		case A_vset:	
		case A_program_file:
#endif
#ifdef CONFIG_RSBAC_MAC_AUTH_PROT
		case A_auth_may_setuid:
		case A_auth_may_set_cap:
		case A_auth_start_uid:
		case A_auth_start_euid:
		case A_auth_start_gid:
		case A_auth_start_egid:
		case A_auth_learn:
		case A_auth_last_auth:
#endif
			/* Security Officer ot Admin? */
			if (mac_check_role(owner, SR_security_officer) ==
			    GRANTED)
				return GRANTED;
			else
				return mac_check_role(owner,
						      SR_administrator);

		default:
			return (DO_NOT_CARE);
		}

	case R_READ_OPEN:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_UNIXSOCK:
		case T_IPC:
			/* and perform auto-read without setting attributes */
			return (auto_read(caller_pid, target, tid, FALSE));
			break;
		case T_DEV:
			/* Only check for devices with mac_check set */
			if (rsbac_get_attr(SW_MAC,
					   T_DEV,
					   tid,
					   A_mac_check,
					   &i_attr_val1, TRUE)) {
				rsbac_ds_get_error("rsbac_adf_request_mac",
						   A_none);
				return (NOT_GRANTED);
			}
			if (!i_attr_val1.mac_check)
				return (DO_NOT_CARE);
			/* and perform auto-read without setting attributes */
			return (auto_read(caller_pid, target, tid, FALSE));
			break;
			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_READ_WRITE_OPEN:
		switch (target) {
		case T_FILE:
		case T_FIFO:
		case T_UNIXSOCK:
		case T_IPC:
			/* and perform auto-read-write without setting attributes */
			return (auto_read_write(caller_pid,
						target, tid, FALSE));

		case T_DEV:
			/* Only check for devices with mac_check set */
			if (rsbac_get_attr(SW_MAC,
					   T_DEV,
					   tid,
					   A_mac_check,
					   &i_attr_val1, TRUE)) {
				rsbac_ds_get_error("rsbac_adf_request_mac",
						   A_none);
				return (NOT_GRANTED);
			}
			if (!i_attr_val1.mac_check)
				return (DO_NOT_CARE);
			/* and perform auto-read-write without setting attributes */
			return (auto_read_write(caller_pid,
						target, tid, FALSE));

			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_REMOVE_FROM_KERNEL:
		switch (target) {
		case T_FILE:
		case T_DEV:
		case T_NONE:
			/* test owner's mac_role */
			return mac_check_role(owner, SR_administrator);

			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_SHUTDOWN:
		switch (target) {
		case T_NONE:
			/* test owner's mac_role */
			return mac_check_role(owner, SR_administrator);

			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_RENAME:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
		case T_UNIXSOCK:
			/* and perform auto-write without setting attributes */
			result = auto_write(caller_pid,
					    target, tid, FALSE);
			/* if parent dir might change, convert inherit to explicit level/cat:
			   get and set effective value */
			if (((result == GRANTED)
			     || (result == DO_NOT_CARE)
			    )
			    && ((attr != A_new_dir_dentry_p)
				|| (attr_val.new_dir_dentry_p !=
				    tid.file.dentry_p->d_parent)
			    )
			    ) {
				if (rsbac_get_attr(SW_MAC, target, tid, A_security_level, &i_attr_val1, TRUE)) {	/* failed! */
					rsbac_ds_get_error
					    ("rsbac_adf_request_mac",
					     A_none);
					return (NOT_GRANTED);
				}
				if (rsbac_set_attr(SW_MAC, target, tid, A_security_level, i_attr_val1)) {	/* failed! */
					rsbac_ds_set_error
					    ("rsbac_adf_request_mac",
					     A_none);
					return (NOT_GRANTED);
				}
				if (rsbac_get_attr(SW_MAC, target, tid, A_mac_categories, &i_attr_val1, TRUE)) {	/* failed! */
					rsbac_ds_get_error
					    ("rsbac_adf_request_mac",
					     A_none);
					return (NOT_GRANTED);
				}
				if (rsbac_set_attr(SW_MAC, target, tid, A_mac_categories, i_attr_val1)) {	/* failed! */
					rsbac_ds_set_error
					    ("rsbac_adf_request_mac",
					     A_none);
					return (NOT_GRANTED);
				}
			}
			return result;
			break;
#if defined(CONFIG_RSBAC_MAC_UM_PROT)
		case T_USER:
		case T_GROUP:
			/* Security Officer? */
			return mac_check_role(owner, SR_security_officer);
#endif
			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}


	case R_SEARCH:
		switch (target) {
		case T_DIR:
		case T_SYMLINK:
		case T_UNIXSOCK:
			/* and perform auto-read without setting attributes */
			return (auto_read(caller_pid, target, tid, FALSE));
			break;
			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_SEND_SIGNAL:
		switch (target) {
		case T_PROCESS:
			/* and perform auto-write without setting attributes */
			return (auto_write_attr(caller_pid,
						target,
						tid,
						A_current_sec_level,
						A_mac_curr_categories,
						FALSE));

			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_SWITCH_LOG:
		switch (target) {
		case T_NONE:
			/* test owner's mac_role */
			return mac_check_role(owner, SR_security_officer);

			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_SWITCH_MODULE:
		switch (target) {
		case T_NONE:
			/* we need the switch_target */
			if (attr != A_switch_target)
				return NOT_GRANTED;
			/* do not care for other modules */
			if ((attr_val.switch_target != SW_MAC)
#ifdef CONFIG_RSBAC_MAC_AUTH_PROT
			    && (attr_val.switch_target != SW_AUTH)
#endif
#ifdef CONFIG_RSBAC_SOFTMODE
			    && (attr_val.switch_target != SW_SOFTMODE)
#endif
#ifdef CONFIG_RSBAC_FREEZE
			    && (attr_val.switch_target != SW_FREEZE)
#endif
			    )
				return (DO_NOT_CARE);
			/* test owner's mac_role */
			return mac_check_role(owner, SR_security_officer);

			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_TRACE:
		switch (target) {
		case T_PROCESS:
			/* and perform auto-read-write without setting attributes */
			return (auto_read_write_attr(caller_pid,
						     target,
						     tid,
						     A_current_sec_level,
						     A_mac_curr_categories,
						     FALSE));

			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_TRUNCATE:
		switch (target) {
		case T_FILE:
			/* and perform auto-write without setting attributes */
			return (auto_write(caller_pid,
					   target, tid, FALSE));
			break;
			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_UMOUNT:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_DEV:
#ifdef CONFIG_RSBAC_MAC_LIGHT
			return (GRANTED);
#else
			return mac_check_role(owner, SR_administrator);
#endif
			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_WRITE:
		switch (target) {
		case T_DIR:
		case T_IPC:
#ifdef CONFIG_RSBAC_RW
		case T_FILE:
		case T_FIFO:
		case T_UNIXSOCK:
#endif
			/* Mode of created item is ignored! */
			/* and perform auto-write without setting attributes */
			return (auto_write(caller_pid,
					   target, tid, FALSE));


#ifdef CONFIG_RSBAC_RW
		case T_DEV:
			/* Only check for devices with mac_check set */
			if (rsbac_get_attr(SW_MAC,
					   T_DEV,
					   tid,
					   A_mac_check,
					   &i_attr_val1, FALSE)) {
				rsbac_ds_get_error("rsbac_adf_request_mac",
						   A_none);
				return (NOT_GRANTED);
			}
			if (!i_attr_val1.mac_check)
				return (DO_NOT_CARE);
			/* and perform auto-write without setting attributes */
			return (auto_write(caller_pid,
					   target, tid, FALSE));
			break;
#endif

#if defined(CONFIG_RSBAC_MAC_NET_OBJ_PROT)
		case T_NETTEMP:
			return mac_check_role(owner, SR_security_officer);

		case T_NETOBJ:
			/* test write access to target: get its sec_level */
			if (rsbac_get_attr(SW_MAC,
					   target,
					   tid,
					   A_remote_sec_level,
					   &i_attr_val1, TRUE)) {
				rsbac_ds_get_error("rsbac_adf_request_mac",
						   A_none);
				return (NOT_GRANTED);
			}
			if (rsbac_get_attr(SW_MAC,
					   target,
					   tid,
					   A_remote_mac_categories,
					   &i_attr_val2, TRUE)) {
				rsbac_ds_get_error("rsbac_adf_request_mac",
						   A_none);
				return (NOT_GRANTED);
			}
			/* and perform auto-write without setting attributes */
			return (auto_write_attr(caller_pid,
						target,
						tid,
						A_remote_sec_level,
						A_remote_mac_categories,
						FALSE));
#endif

#if defined(CONFIG_RSBAC_MAC_UM_PROT)
		case T_USER:
		case T_GROUP:
			/* Security Officer? */
			return mac_check_role(owner, SR_security_officer);
#endif
			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_WRITE_OPEN:
		switch (target) {
		case T_FILE:
		case T_FIFO:
		case T_UNIXSOCK:
		case T_IPC:
			/* and perform auto-write without setting attributes */
			return (auto_write(caller_pid,
					   target, tid, FALSE));
			break;
		case T_DEV:
			/* Only check for devices with mac_check set */
			if (rsbac_get_attr(SW_MAC,
					   T_DEV,
					   tid,
					   A_mac_check,
					   &i_attr_val1, TRUE)) {
				rsbac_ds_get_error("rsbac_adf_request_mac",
						   A_none);
				return (NOT_GRANTED);
			}
			if (!i_attr_val1.mac_check)
				return (DO_NOT_CARE);
			/* and perform auto-write without setting attributes */
			return (auto_write(caller_pid,
					   target, tid, FALSE));

			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_SEND:
		switch (target) {
		case T_DEV:
			/* Only check for devices with mac_check set */
			if (rsbac_get_attr(SW_MAC,
					   T_DEV,
					   tid,
					   A_mac_check,
					   &i_attr_val1, TRUE)) {
				rsbac_ds_get_error("rsbac_adf_request_mac",
						   A_none);
				return (NOT_GRANTED);
			}
			if (!i_attr_val1.mac_check)
				return (DO_NOT_CARE);
			/* and perform auto-write without setting attributes */
			return (auto_write(caller_pid,
					   target, tid, FALSE));

		case T_UNIXSOCK:
			return (auto_write(caller_pid,
					   target, tid, FALSE));

#if defined(CONFIG_RSBAC_MAC_NET_OBJ_PROT)
		case T_NETOBJ:
			/* and perform auto-read-write without setting attributes */
			return (auto_read_write_attr(caller_pid,
						     target,
						     tid,
						     A_remote_sec_level,
						     A_remote_mac_categories,
						     FALSE));

#endif
			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
		}

	case R_BIND:
	case R_LISTEN:
		switch (target) {
		case T_UNIXSOCK:
			return (auto_read(caller_pid,
					   target, tid, FALSE));
#if defined(CONFIG_RSBAC_MAC_NET_OBJ_PROT)
		case T_NETOBJ:
			/* and perform auto-read-write without setting attributes */
			return (auto_read_write_attr(caller_pid,
						     target,
						     tid,
						     A_local_sec_level,
						     A_local_mac_categories,
						     FALSE));

			/* all other cases are unknown */
#endif
		default:
			return (DO_NOT_CARE);
		}

	case R_ACCEPT:
	case R_CONNECT:
	case R_RECEIVE:
		switch (target) {
		case T_UNIXSOCK:
			return (auto_read_write(caller_pid,
					   target, tid, FALSE));
#if defined(CONFIG_RSBAC_MAC_NET_OBJ_PROT)
		case T_NETOBJ:
			/* and perform auto-read-write without setting attributes */
			return (auto_read_write_attr(caller_pid,
						     target,
						     tid,
						     A_remote_sec_level,
						     A_remote_mac_categories,
						     FALSE));
#endif
			/* all other cases are unknown */
		default:
			return (DO_NOT_CARE);
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

inline int rsbac_adf_set_attr_mac(enum rsbac_adf_request_t request,
			   rsbac_pid_t caller_pid,
			   enum rsbac_target_t target,
			   union rsbac_target_id_t tid,
			   enum rsbac_target_t new_target,
			   union rsbac_target_id_t new_tid,
			   enum rsbac_attribute_t attr,
			   union rsbac_attribute_value_t attr_val,
			   rsbac_uid_t owner)
{
	enum rsbac_adf_req_ret_t result = DO_NOT_CARE;
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val1;
	union rsbac_attribute_value_t i_attr_val2;
	union rsbac_attribute_value_t i_attr_val3;
	union rsbac_attribute_value_t i_attr_val4;
	union rsbac_attribute_value_t i_attr_val5;
	union rsbac_attribute_value_t i_attr_val6;
	union rsbac_attribute_value_t i_attr_val7;
	union rsbac_attribute_value_t i_attr_val8;
	union rsbac_attribute_value_t i_attr_val9;
	rsbac_boolean_t inherit;

	switch (request) {
	case R_APPEND_OPEN:
		switch (target) {
		case T_FILE:
		case T_FIFO:
                case T_UNIXSOCK:
		case T_IPC:
			/* test write access to target: get its sec_level */
			if ((target == T_FILE)
			    || (target == T_FIFO)
			    )
				inherit = TRUE;
			else
				inherit = FALSE;
			if (rsbac_get_attr(SW_MAC,
					   target,
					   tid,
					   A_security_level,
					   &i_attr_val1, inherit)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			if (rsbac_get_attr(SW_MAC,
					   target,
					   tid,
					   A_mac_categories,
					   &i_attr_val2, inherit)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* and perform auto-write with setting attributes */
			result = auto_write(caller_pid, target, tid, TRUE);
			if ((result == GRANTED) || (result == DO_NOT_CARE))
				return 0;
			else
				return (-RSBAC_EDECISIONMISMATCH);
			break;
		case T_DEV:
			/* Only check for devices with mac_check set */
			if (rsbac_get_attr(SW_MAC,
					   T_DEV,
					   tid,
					   A_mac_check,
					   &i_attr_val1, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			if (!i_attr_val1.mac_check)
				return 0;
			/* and perform auto-write with setting attributes */
			result = auto_write(caller_pid, target, tid, TRUE);
			if ((result == GRANTED) || (result == DO_NOT_CARE))
				return 0;
			else
				return (-RSBAC_EDECISIONMISMATCH);
			break;
			/* all other cases are unknown */
		default:
			return 0;
		}

	case R_CHANGE_OWNER:
		switch (target) {
			/*  Changing process owner affects access decisions, */
			/*  so attributes have to be adjusted.               */
		case T_PROCESS:
			/* For target process there MUST be a new owner specified */
			if (attr != A_owner)
				return (-RSBAC_EINVALIDATTR);

			/* Get owner-sec-level and mac_categories for new owner */
			i_tid.user = attr_val.owner;
			if (rsbac_get_attr(SW_MAC,
					   T_USER,
					   i_tid,
					   A_security_level,
					   &i_attr_val2, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			if (rsbac_get_attr(SW_MAC,
					   T_USER,
					   i_tid,
					   A_mac_categories,
					   &i_attr_val3, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* set owner-sec-level and mac_categories for process to new values */
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_security_level,
					   i_attr_val2)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_mac_categories,
					   i_attr_val3)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			/* Get min_write_open and min_write_categories of process */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_min_write_open,
					   &i_attr_val4, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_min_write_categories,
					   &i_attr_val5, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* adjust min_write_open and min_write_categories, if too high */
			if (i_attr_val2.security_level <
			    i_attr_val4.min_write_open) {
				i_attr_val4.min_write_open =
				    i_attr_val2.security_level;
				if (rsbac_set_attr
				    (SW_MAC, T_PROCESS, tid, A_min_write_open,
				     i_attr_val4)) {
					rsbac_ds_set_error
					    ("rsbac_adf_set_attr_mac",
					     A_none);
					return (-RSBAC_EWRITEFAILED);
				}
			}
			/* does process have categories in min_write
			 * that the new owner has not? */
			/* If yes, throw them out. */
			if ((i_attr_val3.mac_categories & i_attr_val5.
			     mac_categories)
			    != i_attr_val5.mac_categories) {
				i_attr_val5.mac_categories &=
				    i_attr_val3.mac_categories;
				if (rsbac_set_attr
				    (SW_MAC, T_PROCESS, tid,
				     A_min_write_categories,
				     i_attr_val5)) {
					rsbac_ds_set_error
					    ("rsbac_adf_set_attr_mac",
					     A_none);
					return (-RSBAC_EWRITEFAILED);
				}
			}
			/* Get owner-initial-sec-level and
			 * mac_initial_categories for new owner */
			/* These values will be adjusted by 
			 * max_read / min_write and then used as */
			/* new current level/categories. */
			i_tid.user = owner;
			if (rsbac_get_attr(SW_MAC,
					   T_USER,
					   i_tid,
					   A_initial_security_level,
					   &i_attr_val6, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_initial_security_level,
					   i_attr_val6)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
#if 0
			/* restrict current_level to be a maximum of min_write */
			if (i_attr_val6.security_level >
			    i_attr_val4.min_write_open)
				i_attr_val6.security_level =
				    i_attr_val4.min_write_open;
#endif
			if (rsbac_get_attr(SW_MAC,
					   T_USER,
					   i_tid,
					   A_mac_initial_categories,
					   &i_attr_val7, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_mac_initial_categories,
					   i_attr_val7)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
#if 0
			/* restrict current_categories to be a maximum of min_write */
			if ((i_attr_val7.mac_categories & i_attr_val5.
			     mac_categories) != i_attr_val7.mac_categories)
				i_attr_val7.mac_categories &=
				    i_attr_val5.mac_categories;
#endif
			/* Get owner-min-sec-level and mac_min_categories for new owner */
			i_tid.user = owner;
			if (rsbac_get_attr(SW_MAC,
					   T_USER,
					   i_tid,
					   A_min_security_level,
					   &i_attr_val8, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			if (rsbac_get_attr(SW_MAC,
					   T_USER,
					   i_tid,
					   A_mac_min_categories,
					   &i_attr_val9, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* set owner-sec-level and mac_categories for process to new values */
			/* owner is set by main dispatcher! */
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_min_security_level,
					   i_attr_val8)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_mac_min_categories,
					   i_attr_val9)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			/* Get max_read_open and max_read_categories of process */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_max_read_open,
					   &i_attr_val4, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_max_read_categories,
					   &i_attr_val5, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* adjust max_read_open and max_read_categories, if too low */
			if (i_attr_val8.security_level >
			    i_attr_val4.max_read_open) {
				i_attr_val4.max_read_open =
				    i_attr_val8.security_level;
				if (rsbac_set_attr
				    (SW_MAC, T_PROCESS, tid, A_max_read_open,
				     i_attr_val4)) {
					rsbac_ds_set_error
					    ("rsbac_adf_set_attr_mac",
					     A_none);
					return (-RSBAC_EWRITEFAILED);
				}
			}
#if 0
			/* adjust current sec level to a minimum of max_read */
			if (i_attr_val6.security_level <
			    i_attr_val4.max_read_open)
				i_attr_val6.security_level =
				    i_attr_val4.max_read_open;
#endif
			/* but never set it over new max_level or under new min_level */
			if (i_attr_val6.security_level >
			    i_attr_val2.security_level)
				i_attr_val6.security_level =
				    i_attr_val2.security_level;
			else if (i_attr_val6.security_level <
				 i_attr_val8.security_level)
				i_attr_val6.security_level =
				    i_attr_val8.security_level;
			if (rsbac_set_attr
			    (SW_MAC, T_PROCESS, tid, A_current_sec_level,
			     i_attr_val6)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}

			/* does new owner have categories in min_categories that the process max_read 
			   has not? */
			/* If yes, add them. */
			if ((i_attr_val9.mac_categories & i_attr_val5.
			     mac_categories)
			    != i_attr_val9.mac_categories) {
				i_attr_val5.mac_categories |=
				    i_attr_val9.mac_categories;
				if (rsbac_set_attr
				    (SW_MAC, T_PROCESS, tid,
				     A_max_read_categories, i_attr_val5)) {
					rsbac_ds_set_error
					    ("rsbac_adf_set_attr_mac",
					     A_none);
					return (-RSBAC_EWRITEFAILED);
				}
			}
#if 0
			/* adjust current categories to include all from max_read (from initial) */
			if ((i_attr_val7.mac_categories & i_attr_val5.
			     mac_categories) != i_attr_val5.mac_categories)
				i_attr_val7.mac_categories |=
				    i_attr_val5.mac_categories;
#endif
			/* but never set it over new max_cats or under new min_cats */
			if ((i_attr_val7.mac_categories & i_attr_val3.
			     mac_categories) != i_attr_val7.mac_categories)
				i_attr_val7.mac_categories &=
				    i_attr_val3.mac_categories;
			else if ((i_attr_val7.mac_categories & i_attr_val9.
				  mac_categories) !=
				 i_attr_val9.mac_categories)
				i_attr_val7.mac_categories |=
				    i_attr_val9.mac_categories;
			if (rsbac_set_attr
			    (SW_MAC, T_PROCESS, tid, A_mac_curr_categories,
			     i_attr_val7)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}

			/* Get mac_user_flags from user */
			i_tid.user = attr_val.owner;
			if (rsbac_get_attr(SW_MAC,
					   T_USER,
					   i_tid,
					   A_mac_user_flags,
					   &i_attr_val3, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			i_attr_val1.mac_process_flags =
			    i_attr_val3.mac_user_flags;
			/* adjust flags - first get old process flags */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_mac_process_flags,
					   &i_attr_val2, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			if ((i_attr_val2.
			     mac_process_flags & MAC_program_auto)
			    && (i_attr_val3.
				mac_user_flags & MAC_allow_auto)
			    )
				i_attr_val1.mac_process_flags |= MAC_auto;

			i_attr_val1.mac_process_flags &= RSBAC_MAC_P_FLAGS;

			if (!(i_attr_val1.mac_process_flags & MAC_trusted)) {
				if (rsbac_mac_p_truset_member
				    (caller_pid, owner))
					i_attr_val1.mac_process_flags |=
					    MAC_trusted;
			}
			/* Set mac_process_flags on process */
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_mac_process_flags,
					   i_attr_val1)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			/* OK, we are ready */
			return 0;

			/* We do not care about other cases here */
		default:
			return 0;
		}

	case R_CLONE:
		if (target == T_PROCESS) {
			/* Get owner-sec-level from first process */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_security_level,
					   &i_attr_val2, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* Get current-sec-level from first process... */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_current_sec_level,
					   &i_attr_val3, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* Get min_write_open from first process */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_min_write_open,
					   &i_attr_val4, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* Get max_read_open from first process */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_max_read_open,
					   &i_attr_val5, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* Get mac_process_flags from first process */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_mac_process_flags,
					   &i_attr_val7, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* Set owner_sec_level for new process */
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   new_tid,
					   A_security_level,
					   i_attr_val2)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			/* Set current_sec_level for new process */
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   new_tid,
					   A_current_sec_level,
					   i_attr_val3)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			/* Set min_write_open for new process */
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   new_tid,
					   A_min_write_open,
					   i_attr_val4)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			/* Set max_read_open for new process */
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   new_tid,
					   A_max_read_open, i_attr_val5)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			/* Set mac_process_flags for new process */
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   new_tid,
					   A_mac_process_flags,
					   i_attr_val7)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}

			/* Get mac_categories from first process */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_mac_categories,
					   &i_attr_val2, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* Get mac_curr_categories from first process... */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_mac_curr_categories,
					   &i_attr_val3, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* Get min_write_categories from first process */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_min_write_categories,
					   &i_attr_val4, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* Get max_read_categories from first process */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_max_read_categories,
					   &i_attr_val5, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* Get initial_sec_level from first process */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_initial_security_level,
					   &i_attr_val6, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* Get initial_categories from first process */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_mac_initial_categories,
					   &i_attr_val7, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* Set mac_categories for new process */
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   new_tid,
					   A_mac_categories,
					   i_attr_val2)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			/* Set mac_curr_categories for new process */
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   new_tid,
					   A_mac_curr_categories,
					   i_attr_val3)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			/* Set min_write_categories for new process */
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   new_tid,
					   A_min_write_categories,
					   i_attr_val4)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			/* Set max_read_categories for new process */
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   new_tid,
					   A_max_read_categories,
					   i_attr_val5)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			/* Set initial_security_level for new process */
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   new_tid,
					   A_initial_security_level,
					   i_attr_val6)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			/* Set initial_categories for new process */
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   new_tid,
					   A_mac_initial_categories,
					   i_attr_val7)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			/* Get owner-min_sec-level/cat from first process */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_min_security_level,
					   &i_attr_val2, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   tid,
					   A_mac_min_categories,
					   &i_attr_val3, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* Set min_security_level for new process */
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   new_tid,
					   A_min_security_level,
					   i_attr_val2)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			/* Set min_categories for new process */
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   new_tid,
					   A_mac_min_categories,
					   i_attr_val3)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			if (rsbac_mac_copy_pp_truset
			    (tid.process, new_tid.process)) {
				rsbac_printk(KERN_WARNING
					     "rsbac_adf_set_attr_mac(): rsbac_mac_copy_pp_truset() returned error!\n");
				return (-RSBAC_EWRITEFAILED);
			}
			return 0;
		} else
			return 0;

	case R_CREATE:
		switch (target) {
			/* Creating dir or (pseudo) file IN target dir! */
		case T_DIR:
			/* Mode of created item is ignored! */
			/* and perform auto-write without(!) 
			 * setting of attributes - no need */
			/* -> decision consistency check only */
			/* only check, if not MAC_LIGHT */
#ifndef CONFIG_RSBAC_MAC_LIGHT
			result = auto_write(caller_pid,
					    target, tid, FALSE);
			if ((result != GRANTED) && (result != DO_NOT_CARE))
				return (-RSBAC_EDECISIONMISMATCH);
#endif
			/* test write access to target: get its sec_level */
			if (rsbac_get_attr(SW_MAC,
					   T_DIR,
					   tid,
					   A_security_level,
					   &i_attr_val1, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			if (rsbac_get_attr(SW_MAC,
					   T_DIR,
					   tid,
					   A_mac_categories,
					   &i_attr_val2, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* Get current_sec_level from process (initialized to owner_sec_level)... */
			i_tid.process = caller_pid;
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   i_tid,
					   A_current_sec_level,
					   &i_attr_val3, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
#ifdef CONFIG_RSBAC_MAC_SMART_INHERIT
			/* Only set, if different than inherited value */
			if (i_attr_val3.security_level !=
			    i_attr_val1.security_level)
#endif
				/* Set security-level for new item */
				if (rsbac_set_attr(SW_MAC,
						   new_target,
						   new_tid,
						   A_security_level,
						   i_attr_val3)) {
					rsbac_ds_set_error
					    ("rsbac_adf_set_attr_mac",
					     A_none);
					return (-RSBAC_EWRITEFAILED);
				}
			/* Get current_categories from process (initialized to owner_categories)... */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   i_tid,
					   A_mac_curr_categories,
					   &i_attr_val3, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
#ifdef CONFIG_RSBAC_MAC_SMART_INHERIT
			/* Only set, if different than inherited value */
			if (i_attr_val3.mac_categories !=
			    i_attr_val2.mac_categories)
#endif
				/* Set mac_categories for new item */
				if (rsbac_set_attr(SW_MAC,
						   new_target,
						   new_tid,
						   A_mac_categories,
						   i_attr_val3)) {
					rsbac_ds_set_error
					    ("rsbac_adf_set_attr_mac",
					     A_none);
					return (-RSBAC_EWRITEFAILED);
				}
			return 0;
			break;

		case T_IPC:
			i_tid.process = caller_pid;
			/* Get current-sec-level from process... */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   i_tid,
					   A_current_sec_level,
					   &i_attr_val1, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* Set security-level for this ipc item */
			if (rsbac_set_attr(SW_MAC,
					   T_IPC,
					   tid,
					   A_security_level,
					   i_attr_val1)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			/* Get mac_curr_categories from process... */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   i_tid,
					   A_mac_curr_categories,
					   &i_attr_val1, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* Set curr_categories for new item */
			if (rsbac_set_attr(SW_MAC,
					   T_IPC,
					   tid,
					   A_mac_categories,
					   i_attr_val1)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			return 0;
			break;

#ifdef CONFIG_RSBAC_MAC_NET_OBJ_PROT
		case T_NETOBJ:
			i_tid.process = caller_pid;
			/* Get current-sec-level from process... */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   i_tid,
					   A_current_sec_level,
					   &i_attr_val1, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* Set local security-level for this netobj item */
			if (rsbac_set_attr(SW_MAC,
					   target,
					   tid,
					   A_local_sec_level,
					   i_attr_val1)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			/* Get mac_curr_categories from process... */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   i_tid,
					   A_mac_curr_categories,
					   &i_attr_val1, FALSE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			/* Set local curr_categories for new item */
			if (rsbac_set_attr(SW_MAC,
					   target,
					   tid,
					   A_local_mac_categories,
					   i_attr_val1)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			return 0;
			break;
#endif

			/* all other cases are unknown */
		default:
			return 0;
		}

		/* removal of targets is done in main adf dispatcher! */
	case R_DELETE:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
                case T_UNIXSOCK:
		case T_IPC:
			/* and perform auto-write without(!) setting of attributes */
			/* - no information flow apart from missing file */
			/* -> decision consistency check only */
			result = auto_write(caller_pid,
					    target, tid, FALSE);
			if ((result != GRANTED) && (result != DO_NOT_CARE))
				return (-RSBAC_EDECISIONMISMATCH);
			else
				return 0;
			/* all other cases are unknown */
		default:
			return 0;
		}

	case R_EXECUTE:
		switch (target) {
		case T_FILE:
			/* copy trusted user list from file to process */
			if (rsbac_mac_copy_fp_truset(tid.file, caller_pid)) {
				rsbac_printk(KERN_WARNING
					     "rsbac_adf_set_attr_mac(): rsbac_mac_copy_fp_truset() returned error!\n");
				return (-RSBAC_EWRITEFAILED);
			}
			/* perform auto-read with setting of attributes */
			result = auto_read(caller_pid, target, tid, TRUE);
			if ((result != GRANTED) && (result != DO_NOT_CARE))
				return (-RSBAC_EDECISIONMISMATCH);

			/* reset current_sec_level, mac_auto, min_write_open */
			/* and max_read_open for process */
			i_tid.process = caller_pid;

#ifdef CONFIG_RSBAC_MAC_RESET_CURR
			/* First, set current_sec_level and min_write_open to process owner's initial and seclevel */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   i_tid,
					   A_initial_security_level,
					   &i_attr_val1, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   i_tid,
					   A_mac_initial_categories,
					   &i_attr_val2, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   i_tid,
					   A_current_sec_level,
					   i_attr_val1)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   i_tid,
					   A_mac_curr_categories,
					   i_attr_val2)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
#endif
#if 0
			/* Now, set min_write_open to process owner's seclevel */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   i_tid,
					   A_security_level,
					   &i_attr_val1, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
#endif
			i_attr_val1.min_write_open = SL_max;
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   i_tid,
					   A_min_write_open,
					   i_attr_val1)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
#if 0
			/* Next, set min_write_categories to process owner's mac_categories */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   i_tid,
					   A_mac_categories,
					   &i_attr_val2, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
#endif
			i_attr_val2.mac_categories =
			    RSBAC_MAC_MAX_CAT_VECTOR;
			if (rsbac_set_attr
			    (SW_MAC, T_PROCESS, i_tid, A_min_write_categories,
			     i_attr_val2)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			/* reset max_read boundary */
#if 0
			/* Get owner-min-sec-level and mac_min_categories for owner */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   i_tid,
					   A_min_security_level,
					   &i_attr_val1, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   i_tid,
					   A_mac_min_categories,
					   &i_attr_val2, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
#endif
			i_attr_val1.max_read_open = SL_min;
			i_attr_val2.mac_categories =
			    RSBAC_MAC_MIN_CAT_VECTOR;
			if (rsbac_set_attr
			    (SW_MAC, T_PROCESS, i_tid, A_max_read_open,
			     i_attr_val1)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			/* reset category max_read boundary */
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   i_tid,
					   A_max_read_categories,
					   i_attr_val2)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			/* set flags */
			if (rsbac_get_attr(SW_MAC,
					   T_PROCESS,
					   i_tid,
					   A_mac_process_flags,
					   &i_attr_val1, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			if (rsbac_get_attr(SW_MAC,
					   target,
					   tid,
					   A_mac_auto,
					   &i_attr_val2, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			if (i_attr_val2.mac_auto) {
				i_attr_val1.mac_process_flags |=
				    MAC_program_auto;
				i_tid.user = owner;
				if (rsbac_get_attr(SW_MAC,
						   T_USER,
						   i_tid,
						   A_mac_user_flags,
						   &i_attr_val2, TRUE)) {
					rsbac_ds_get_error
					    ("rsbac_adf_set_attr_mac",
					     A_none);
					return (-RSBAC_EREADFAILED);
				}
				if (i_attr_val2.
				    mac_user_flags & MAC_allow_auto)
					i_attr_val1.mac_process_flags |=
					    MAC_auto;
				else
					i_attr_val1.mac_process_flags &=
					    ~MAC_auto;
				i_tid.process = caller_pid;
			} else {
				i_attr_val1.mac_process_flags &=
				    ~MAC_program_auto;
				i_attr_val1.mac_process_flags &= ~MAC_auto;
			}
			if (rsbac_get_attr(SW_MAC,
					   T_FILE,
					   tid,
					   A_mac_prop_trusted,
					   &i_attr_val3, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			if (!(i_attr_val3.mac_prop_trusted)
			    || !(i_attr_val1.
				 mac_process_flags & MAC_trusted)
			    ) {
				if (rsbac_mac_p_truset_member
				    (caller_pid, owner))
					i_attr_val1.mac_process_flags |=
					    MAC_trusted;
				else {
					i_tid.user = owner;
					if (rsbac_get_attr(SW_MAC,
							   T_USER,
							   i_tid,
							   A_mac_user_flags,
							   &i_attr_val2,
							   TRUE)) {
						rsbac_ds_get_error
						    ("rsbac_adf_set_attr_mac",
						     A_none);
						return
						    (-RSBAC_EREADFAILED);
					}
					if (i_attr_val2.
					    mac_user_flags & MAC_trusted)
						i_attr_val1.
						    mac_process_flags |=
						    MAC_trusted;
					else
						i_attr_val1.
						    mac_process_flags &=
						    ~MAC_trusted;
					i_tid.process = caller_pid;
				}
			}
			if (rsbac_set_attr(SW_MAC,
					   T_PROCESS,
					   i_tid,
					   A_mac_process_flags,
					   i_attr_val1)) {
				rsbac_ds_set_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EWRITEFAILED);
			}
			return 0;

			/* all other cases */
		default:
			return 0;
		}

	case R_MOUNT:
		switch (target) {
		case T_DIR:
		case T_DEV:
			/* and perform auto-read(-write) with setting of attributes */
			if ((target == T_DEV)
			    && (attr == A_mode)
			    && (attr_val.mode & MS_RDONLY))
				result = auto_read(caller_pid,
						   target, tid, TRUE);
			else
				result = auto_read_write(caller_pid,
							 target,
							 tid, TRUE);
			if ((result != GRANTED) && (result != DO_NOT_CARE))
				return (-RSBAC_EDECISIONMISMATCH);
			else
				return 0;

			/* all other cases are unknown */
		default:
			return 0;
		}

	case R_READ:
		switch (target) {
		case T_DIR:
#ifdef CONFIG_RSBAC_RW
		case T_FILE:
		case T_FIFO:
                case T_UNIXSOCK:
		case T_IPC:
#endif
			/* and perform auto-read with setting of attributes */
			result = auto_read(caller_pid, target, tid, TRUE);
			if ((result != GRANTED) && (result != DO_NOT_CARE))
				return (-RSBAC_EDECISIONMISMATCH);
			return 0;

#ifdef CONFIG_RSBAC_RW
		case T_DEV:
			/* Only check for devices with mac_check set */
			if (rsbac_get_attr(SW_MAC,
					   T_DEV,
					   tid,
					   A_mac_check,
					   &i_attr_val1, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			if (!i_attr_val1.mac_check)
				return 0;
			/* and perform auto-read with setting of attributes */
			result = auto_read(caller_pid, target, tid, TRUE);
			if ((result != GRANTED) && (result != DO_NOT_CARE))
				return (-RSBAC_EDECISIONMISMATCH);
			return 0;
#endif

#ifdef CONFIG_RSBAC_MAC_NET_OBJ_PROT
		case T_NETOBJ:
			/* and perform auto-read with setting of attributes */
			result = auto_read_attr(caller_pid,
						target,
						tid,
						A_remote_sec_level,
						A_remote_mac_categories,
						TRUE);
			if ((result != GRANTED) && (result != DO_NOT_CARE))
				return (-RSBAC_EDECISIONMISMATCH);
			return 0;
#endif

			/* all other cases are unknown */
		default:
			return 0;
		}

	case R_READ_OPEN:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
                case T_UNIXSOCK:
		case T_IPC:
			/* and perform auto-read with setting attributes */
			result = auto_read(caller_pid, target, tid, TRUE);
			if ((result != GRANTED) && (result != DO_NOT_CARE))
				return (-RSBAC_EDECISIONMISMATCH);
			return 0;

		case T_DEV:
			/* Only check for devices with mac_check set */
			if (rsbac_get_attr(SW_MAC,
					   T_DEV,
					   tid,
					   A_mac_check,
					   &i_attr_val1, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			if (!i_attr_val1.mac_check)
				return 0;
			/* and perform auto-read with setting attributes */
			result = auto_read(caller_pid, target, tid, TRUE);
			if ((result != GRANTED) && (result != DO_NOT_CARE))
				return (-RSBAC_EDECISIONMISMATCH);
			return 0;

			/* all other cases are unknown */
		default:
			return 0;
		}

	case R_READ_WRITE_OPEN:
		switch (target) {
		case T_FILE:
		case T_FIFO:
                case T_UNIXSOCK:
		case T_IPC:
			/* and perform auto-read-write without setting attributes */
			result = auto_read_write(caller_pid,
						 target, tid, TRUE);
			if ((result != GRANTED) && (result != DO_NOT_CARE))
				return (-RSBAC_EDECISIONMISMATCH);
			return 0;

		case T_DEV:
			/* Only check for devices with mac_check set */
			if (rsbac_get_attr(SW_MAC,
					   T_DEV,
					   tid,
					   A_mac_check,
					   &i_attr_val1, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			if (!i_attr_val1.mac_check)
				return 0;
			/* and perform auto-read-write with setting of attributes */
			result = auto_read_write(caller_pid,
						 target, tid, TRUE);
			if ((result != GRANTED) && (result != DO_NOT_CARE))
				return (-RSBAC_EDECISIONMISMATCH);
			return 0;
			/* all other cases are unknown */
		default:
			return 0;
		}

	case R_SEARCH:
		switch (target) {
		case T_DIR:
		case T_SYMLINK:
			/* and perform auto-read with setting of attributes */
			result = auto_read(caller_pid, target, tid, TRUE);
			if ((result != GRANTED) && (result != DO_NOT_CARE))
				return (-RSBAC_EDECISIONMISMATCH);
			return 0;
			/* all other cases are unknown */
		default:
			return 0;
		}

	case R_TRACE:
		switch (target) {
		case T_PROCESS:
			/* and perform auto-read-write with setting attributes */
			result = auto_read_write_attr(caller_pid,
						      target,
						      tid,
						      A_current_sec_level,
						      A_mac_curr_categories,
						      TRUE);
			if ((result != GRANTED) && (result != DO_NOT_CARE))
				return (-RSBAC_EDECISIONMISMATCH);
			return 0;

			/* all other cases are unknown */
		default:
			return 0;
		}

	case R_WRITE:
	case R_WRITE_OPEN:
		switch (target) {
		case T_FILE:
		case T_FIFO:
                case T_UNIXSOCK:
		case T_IPC:
			/* and perform auto-write with setting attributes */
			result = auto_write(caller_pid, target, tid, TRUE);
			if ((result != GRANTED) && (result != DO_NOT_CARE))
				return (-RSBAC_EDECISIONMISMATCH);
			return 0;

		case T_DEV:
			/* Only check for devices with mac_check set */
			if (rsbac_get_attr(SW_MAC,
					   T_DEV,
					   tid,
					   A_mac_check,
					   &i_attr_val1, TRUE)) {
				rsbac_ds_get_error
				    ("rsbac_adf_set_attr_mac", A_none);
				return (-RSBAC_EREADFAILED);
			}
			if (!i_attr_val1.mac_check)
				return 0;
			/* and perform auto-write with setting attributes */
			result = auto_write(caller_pid, target, tid, TRUE);
			if ((result != GRANTED) && (result != DO_NOT_CARE))
				return (-RSBAC_EDECISIONMISMATCH);
			return 0;

#ifdef CONFIG_RSBAC_MAC_NET_OBJ_PROT
		case T_NETOBJ:
			/* and perform auto-write with setting attributes */
			result = auto_write_attr(caller_pid,
						 target,
						 tid,
						 A_remote_sec_level,
						 A_remote_mac_categories,
						 TRUE);
			if ((result != GRANTED) && (result != DO_NOT_CARE))
				return (-RSBAC_EDECISIONMISMATCH);
			return 0;
#endif

			/* all other cases are unknown */
		default:
			return 0;
		}

#ifdef CONFIG_RSBAC_MAC_NET_OBJ_PROT
	case R_BIND:
	case R_LISTEN:
		switch (target) {
		case T_NETOBJ:
			/* and perform auto-write with setting attributes */
			result = auto_write_attr(caller_pid,
						 target,
						 tid,
						 A_local_sec_level,
						 A_local_mac_categories,
						 TRUE);
			if ((result != GRANTED) && (result != DO_NOT_CARE))
				return (-RSBAC_EDECISIONMISMATCH);
			return 0;

			/* all other cases are unknown */
		default:
			return 0;
		}

	case R_ACCEPT:
	case R_CONNECT:
	case R_SEND:
	case R_RECEIVE:
		switch (target) {
		case T_NETOBJ:
			/* and perform auto-write with setting attributes */
			result = auto_write_attr(caller_pid,
						 target,
						 tid,
						 A_remote_sec_level,
						 A_remote_mac_categories,
						 TRUE);
			if ((result != GRANTED) && (result != DO_NOT_CARE))
				return (-RSBAC_EDECISIONMISMATCH);
			return 0;

			/* all other cases are unknown */
		default:
			return 0;
		}
#endif
	default:
		return 0;
	}

	return 0;
}
