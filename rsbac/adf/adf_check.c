/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of the Access Control Decision     */
/* Facility (ADF) - check for well defined requests  */
/* File: rsbac/adf/check.c                           */
/*                                                   */
/* Author and (c) 1999-2010: Amon Ott <ao@rsbac.org> */
/*                                                   */
/* Last modified: 19/May/2010                        */
/*************************************************** */

#include <linux/string.h>
#include <rsbac/types.h>
#include <rsbac/aci.h>
#include <rsbac/adf_main.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/getname.h>

/************************************************* */
/*           Global Variables                      */
/************************************************* */

/************************************************* */
/*          Externally visible functions           */
/************************************************* */

enum rsbac_adf_req_ret_t
rsbac_adf_request_check(enum rsbac_adf_request_t request,
			rsbac_pid_t caller_pid,
			enum rsbac_target_t target,
			union rsbac_target_id_t *tid_p,
			enum rsbac_attribute_t attr,
			union rsbac_attribute_value_t *attr_val_p,
			rsbac_uid_t owner)
{
	switch (request) {
	case R_SEARCH:
		switch (target) {
		case T_DIR:
		case T_FILE:
		case T_SYMLINK:
		case T_FIFO:
                case T_UNIXSOCK:
		case T_DEV:
		case T_NETOBJ:
#if defined(CONFIG_RSBAC_UM)
		case T_USER:
		case T_GROUP:
#endif
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_CLOSE:		/* only notifying for clean-up of opened-tables */
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
                case T_UNIXSOCK:
		case T_DEV:
		case T_IPC:
		case T_NETOBJ:
			return DO_NOT_CARE;
		default:
			return UNDEFINED;
		}

	case R_GET_STATUS_DATA:
		switch (target) {
		case T_PROCESS:
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
                case T_UNIXSOCK:
		case T_DEV:
		case T_IPC:
		case T_SCD:
		case T_NETDEV:
		case T_NETOBJ:
#if defined(CONFIG_RSBAC_UM)
		case T_USER:
		case T_GROUP:
#endif
			return DO_NOT_CARE;
		default:
			return UNDEFINED;
		}

	case R_READ:
		switch (target) {
		case T_DIR:
#ifdef CONFIG_RSBAC_RW
		case T_FILE:
		case T_FIFO:
                case T_UNIXSOCK:
		case T_DEV:
		case T_IPC:
#endif
#if defined(CONFIG_RSBAC_NET_OBJ)
		case T_NETTEMP:
#endif
#if defined(CONFIG_RSBAC_NET_OBJ_RW)
		case T_NETOBJ:
#endif
#if defined(CONFIG_RSBAC_UM)
		case T_USER:
		case T_GROUP:
#endif
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_GET_PERMISSIONS_DATA:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
                case T_UNIXSOCK:
		case T_IPC:
		case T_SCD:
		case T_DEV:
		case T_NETOBJ:
#if defined(CONFIG_RSBAC_UM)
		case T_USER:
		case T_GROUP:
#endif
			return DO_NOT_CARE;
		default:
			return UNDEFINED;
		};

	case R_MAP_EXEC:
		switch (target) {
		case T_FILE:
		case T_NONE:
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_SEND:
		switch (target) {
		case T_DEV:
                case T_UNIXSOCK:
                case T_IPC:
		case T_PROCESS:
#if defined(CONFIG_RSBAC_NET_OBJ)
		case T_NETOBJ:
#endif
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_RECEIVE:
		switch (target) {
		case T_UNIXSOCK:
		case T_IPC:
		case T_PROCESS:
#if defined(CONFIG_RSBAC_NET_OBJ)
		case T_NETOBJ:
#endif
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_LISTEN:
	case R_ACCEPT:
	case R_CONNECT:
	case R_NET_SHUTDOWN:
		switch (target) {
		case T_UNIXSOCK:
		case T_IPC:
#if defined(CONFIG_RSBAC_NET_OBJ)
		case T_NETOBJ:
#endif
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_EXECUTE:
		switch (target) {
		case T_FILE:
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_READ_OPEN:
		switch (target) {
		case T_FILE:
		case T_FIFO:
		case T_IPC:
		case T_DEV:
		case T_UNIXSOCK:
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_WRITE:
		switch (target) {
		case T_DIR:
                case T_UNIXSOCK:
		case T_SCD:
		case T_IPC:
#ifdef CONFIG_RSBAC_RW
		case T_FILE:
		case T_FIFO:
		case T_DEV:
#endif
#if defined(CONFIG_RSBAC_NET_OBJ)
		case T_NETTEMP:
#endif
#if defined(CONFIG_RSBAC_NET_OBJ_RW)
		case T_NETOBJ:
#endif
#if defined(CONFIG_RSBAC_UM)
		case T_USER:
		case T_GROUP:
#endif
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_APPEND_OPEN:
		switch (target) {
		case T_FILE:
		case T_FIFO:
		case T_DEV:
                case T_UNIXSOCK:
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_READ_WRITE_OPEN:
		switch (target) {
		case T_FILE:
		case T_FIFO:
		case T_IPC:
		case T_DEV:
		case T_UNIXSOCK:
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_WRITE_OPEN:
		switch (target) {
		case T_FILE:
		case T_FIFO:
		case T_DEV:
		case T_UNIXSOCK:
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_IOCTL:
		switch (target) {
                case T_UNIXSOCK:
                case T_IPC:
		case T_DEV:
#if defined(CONFIG_RSBAC_NET_OBJ)
		case T_NETOBJ:
#endif
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_ADD_TO_KERNEL:
		switch (target) {
		case T_FILE:
		case T_DEV:
		case T_NONE:
			return DO_NOT_CARE;
		default:
			return UNDEFINED;
		}

	case R_ALTER:
		/* only for IPC */
		if (target == T_IPC)
			return DO_NOT_CARE;
		else
			/* all other targets are undefined */
			return UNDEFINED;
		break;

	case R_CHANGE_GROUP:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
                case T_UNIXSOCK:
		case T_IPC:
		case T_PROCESS:
		case T_NONE:
#if defined(CONFIG_RSBAC_UM)
		case T_USER:
#endif
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

#ifdef CONFIG_RSBAC_DAC_GROUP
	case R_CHANGE_DAC_EFF_GROUP:
	case R_CHANGE_DAC_FS_GROUP:
		switch (target) {
		case T_PROCESS:
			/* there must be a new group specified */
			if (attr == A_group)
				return DO_NOT_CARE;
			/* fall through */
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}
#endif

	case R_CHANGE_OWNER:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
                case T_UNIXSOCK:
		case T_IPC:
			return DO_NOT_CARE;
		case T_PROCESS:
			/* there must be a new owner specified */
			if (attr == A_owner)
				return DO_NOT_CARE;
			else
				return UNDEFINED;
			/* all other cases are undefined */
#ifdef CONFIG_RSBAC_USER_CHOWN
		case T_USER:
			/* there must be a new owner specified */
			if (attr == A_process)
				return DO_NOT_CARE;
			else
				return UNDEFINED;
			/* all other cases are undefined */
#endif
		default:
			return UNDEFINED;
		}

#ifdef CONFIG_RSBAC_DAC_OWNER
	case R_CHANGE_DAC_EFF_OWNER:
	case R_CHANGE_DAC_FS_OWNER:
		switch (target) {
		case T_PROCESS:
			/* there must be a new owner specified */
			if (attr == A_owner)
				return DO_NOT_CARE;
			/* fall through */
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}
#endif

	case R_CHDIR:
		switch (target) {
		case T_DIR:
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_CLONE:
		if (target == T_PROCESS)
			return DO_NOT_CARE;
		else
			return UNDEFINED;

	case R_CREATE:
		switch (target) {
			/* Creating dir or (pseudo) file IN target dir! */
		case T_DIR:
		case T_IPC:
#if defined(CONFIG_RSBAC_NET_OBJ)
		case T_NETTEMP:
		case T_NETOBJ:
#endif
#if defined(CONFIG_RSBAC_UM)
		case T_USER:
		case T_GROUP:
#endif
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_DELETE:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
                case T_UNIXSOCK:
		case T_IPC:
#if defined(CONFIG_RSBAC_UM)
		case T_USER:
		case T_GROUP:
#endif
#if defined(CONFIG_RSBAC_NET_OBJ)
		case T_NETTEMP:
		case T_NETOBJ:
#endif
			return DO_NOT_CARE;
		default:
			return UNDEFINED;
		}

	case R_LINK_HARD:
		switch (target) {
		case T_FILE:
		case T_FIFO:
		case T_SYMLINK:
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_MODIFY_ACCESS_DATA:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
                case T_UNIXSOCK:
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_AUTHENTICATE:
		switch (target) {
		case T_USER:
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_MODIFY_ATTRIBUTE:
		return DO_NOT_CARE;

	case R_MODIFY_PERMISSIONS_DATA:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
		case T_UNIXSOCK:
		case T_IPC:
		case T_SCD:
		case T_DEV:
		case T_NETOBJ:
#if defined(CONFIG_RSBAC_UM)
		case T_USER:
		case T_GROUP:
#endif
#ifdef CONFIG_RSBAC_ALLOW_DAC_DISABLE
		case T_NONE:
#endif
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_MODIFY_SYSTEM_DATA:
		switch (target) {
                case T_UNIXSOCK:
                case T_IPC:
		case T_SCD:
		case T_DEV:
		case T_NETDEV:
		case T_PROCESS:
#if defined(CONFIG_RSBAC_NET_OBJ)
		case T_NETOBJ:
#endif
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_MOUNT:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_DEV:
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_READ_ATTRIBUTE:
		return DO_NOT_CARE;

	case R_REMOVE_FROM_KERNEL:
		switch (target) {
		case T_FILE:
		case T_DEV:
		case T_NONE:
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_RENAME:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
                case T_UNIXSOCK:
#if defined(CONFIG_RSBAC_UM)
		case T_USER:
		case T_GROUP:
#endif
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_SEND_SIGNAL:
		switch (target) {
		case T_PROCESS:
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_SHUTDOWN:
		switch (target) {
		case T_NONE:
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}


	case R_SWITCH_LOG:
		switch (target) {
		case T_NONE:
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_SWITCH_MODULE:
		switch (target) {
		case T_NONE:
			/* there must be a switch target specified */
			if (attr == A_switch_target)
				return DO_NOT_CARE;
			/* fall through */
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

		/* notify only, handled by adf-dispatcher */
	case R_TERMINATE:
		if (target == T_PROCESS)
			return DO_NOT_CARE;
		else
			return UNDEFINED;

	case R_TRACE:
		switch (target) {
		case T_PROCESS:
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_TRUNCATE:
		switch (target) {
		case T_FILE:
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_UMOUNT:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_DEV:
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}


	case R_BIND:
		switch (target) {
		case T_IPC:
			return DO_NOT_CARE;
#if defined(CONFIG_RSBAC_NET_DEV)
		case T_NETDEV:
			return DO_NOT_CARE;
#endif
#if defined(CONFIG_RSBAC_NET_OBJ)
		case T_NETOBJ:
			return DO_NOT_CARE;
#endif
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

	case R_LOCK:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
                case T_UNIXSOCK:
                case T_IPC:
			return DO_NOT_CARE;
			/* all other cases are undefined */
		default:
			return UNDEFINED;
		}

/*********************/
	default:
		return UNDEFINED;
	}

	return UNDEFINED;
}				/* end of rsbac_adf_request_check() */


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

int rsbac_adf_set_attr_check(enum rsbac_adf_request_t request,
			     rsbac_pid_t caller_pid,
			     enum rsbac_target_t target,
			     union rsbac_target_id_t tid,
			     enum rsbac_target_t new_target,
			     union rsbac_target_id_t new_tid,
			     enum rsbac_attribute_t attr,
			     union rsbac_attribute_value_t attr_val,
			     rsbac_uid_t owner)
{
	switch (request) {
	case R_CLOSE:		/* only notifying for clean-up of opened-tables */
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
                case T_UNIXSOCK:
		case T_DEV:
		case T_IPC:
		case T_NETOBJ:
			return 0;
		default:
			return -RSBAC_EINVALIDTARGET;
		};

	case R_APPEND_OPEN:
		switch (target) {
		case T_FILE:
		case T_FIFO:
                case T_UNIXSOCK:
		case T_DEV:
			return 0;
			/* all other cases are undefined */
		default:
			return -RSBAC_EINVALIDTARGET;
		}

	case R_CHANGE_OWNER:
		switch (target) {
			/*  Changing process owner affects access decisions, */
			/*  so attributes have to be adjusted.               */
		case T_PROCESS:
			/* there must be a new owner specified */
			if (attr != A_owner)
				return -RSBAC_EINVALIDATTR;
			/* fall through */
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
                case T_UNIXSOCK:
		case T_IPC:
		case T_NONE:
			return 0;
			/* all other cases are undefined */
		default:
			return -RSBAC_EINVALIDTARGET;
		}

#ifdef CONFIG_RSBAC_DAC_OWNER
	case R_CHANGE_DAC_EFF_OWNER:
	case R_CHANGE_DAC_FS_OWNER:
		switch (target) {
			/*  Changing process owner affects access decisions, */
			/*  so attributes have to be adjusted.               */
		case T_PROCESS:
			/* there must be a new owner specified */
			if (attr != A_owner)
				return -RSBAC_EINVALIDATTR;
			return 0;
			/* all other cases are undefined */
		default:
			return -RSBAC_EINVALIDTARGET;
		}
#endif

	case R_CHDIR:
		switch (target) {
		case T_DIR:
			return 0;
		default:
			return -RSBAC_EINVALIDTARGET;
		};

	case R_CLONE:
		if (target == T_PROCESS)
			return 0;
		else
			return -RSBAC_EINVALIDTARGET;

	case R_CREATE:
		switch (target) {
			/* Creating dir or (pseudo) file IN target dir! */
		case T_DIR:
		case T_IPC:
#if defined(CONFIG_RSBAC_NET_OBJ)
		case T_NETOBJ:
#endif
#if defined(CONFIG_RSBAC_UM)
		case T_USER:
		case T_GROUP:
#endif
			return 0;
			/* all other cases are undefined */
		default:
			return -RSBAC_EINVALIDTARGET;
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
#if defined(CONFIG_RSBAC_UM)
		case T_USER:
		case T_GROUP:
#endif
			return 0;
			/* all other cases are undefined */
		default:
			return -RSBAC_EINVALIDTARGET;
		}

	case R_EXECUTE:
		switch (target) {
		case T_FILE:
			return 0;
			/* all other cases are undefined */
		default:
			return -RSBAC_EINVALIDTARGET;
		}

	case R_SEND:
	case R_RECEIVE:
		switch (target) {
                case T_UNIXSOCK:
                case T_IPC:
                case T_PROCESS:
#if defined(CONFIG_RSBAC_NET_OBJ)
		case T_NETOBJ:
#endif
			return 0;
			/* all other cases are undefined */
		default:
			return -RSBAC_EINVALIDTARGET;
		}

	case R_BIND:
	case R_LISTEN:
	case R_ACCEPT:
	case R_CONNECT:
	case R_NET_SHUTDOWN:
		switch (target) {
                case T_UNIXSOCK:
                case T_IPC:
#if defined(CONFIG_RSBAC_NET_OBJ)
		case T_NETOBJ:
#endif
			return 0;
			/* all other cases are undefined */
		default:
			return -RSBAC_EINVALIDTARGET;
		}

	case R_MODIFY_SYSTEM_DATA:
		switch (target) {
		case T_SCD:
			return 0;
			/* all other cases are undefined */
		default:
			return -RSBAC_EINVALIDTARGET;
		}

	case R_MOUNT:
		switch (target) {
		case T_DIR:
			return 0;
			/* all other cases are undefined */
		default:
			return -RSBAC_EINVALIDTARGET;
		}

	case R_READ:
		switch (target) {
		case T_DIR:
#ifdef CONFIG_RSBAC_RW
		case T_FILE:
		case T_FIFO:
                case T_UNIXSOCK:
		case T_DEV:
		case T_IPC:
#endif
#if defined(CONFIG_RSBAC_NET_OBJ_RW) || defined(CONFIG_RSBAC_MS_SOCK)
		case T_NETOBJ:
#endif
			return 0;
			/* all other cases are undefined */
		default:
			return -RSBAC_EINVALIDTARGET;
		}

	case R_READ_OPEN:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_IPC:
		case T_DEV:
		case T_UNIXSOCK:
			return 0;
			/* all other cases are undefined */
		default:
			return -RSBAC_EINVALIDTARGET;
		}

	case R_READ_WRITE_OPEN:
		switch (target) {
		case T_FILE:
		case T_FIFO:
		case T_IPC:
		case T_DEV:
		case T_UNIXSOCK:
			return 0;
			/* all other cases are undefined */
		default:
			return -RSBAC_EINVALIDTARGET;
		}

	case R_RENAME:
		switch (target) {
		case T_FILE:
		case T_DIR:
		case T_FIFO:
		case T_SYMLINK:
                case T_UNIXSOCK:
			return 0;
			/* all other cases are undefined */
		default:
			return -RSBAC_EINVALIDTARGET;
		}

	case R_SEARCH:
		switch (target) {
                case T_DIR:
		case T_FILE:
		case T_SYMLINK:
		case T_FIFO:
                case T_UNIXSOCK:
		case T_DEV:
		case T_NETOBJ:
			return 0;
			/* all other cases are undefined */
		default:
			return -RSBAC_EINVALIDTARGET;
		}

#if defined(CONFIG_RSBAC_NET_OBJ)
	case R_SHUTDOWN:
		switch (target) {
		case T_NETOBJ:
			return 0;
			/* all other cases are undefined */
		default:
			return -RSBAC_EINVALIDTARGET;
		}
#endif

	case R_TRACE:
		switch (target) {
		case T_PROCESS:
			return 0;
			/* all other cases are undefined */
		default:
			return -RSBAC_EINVALIDTARGET;
		}

	case R_TRUNCATE:
		switch (target) {
		case T_FILE:
			return 0;
			/* all other cases are undefined */
		default:
			return -RSBAC_EINVALIDTARGET;
		}

#ifdef CONFIG_RSBAC_RW
	case R_WRITE:
		switch (target) {
		case T_FILE:
		case T_FIFO:
		case T_DEV:
		case T_UNIXSOCK:
		case T_IPC:
		case T_NETOBJ:
			return 0;
			/* all other cases are undefined */
		default:
			return -RSBAC_EINVALIDTARGET;
		}
#endif

	case R_WRITE_OPEN:
		switch (target) {
		case T_FILE:
		case T_FIFO:
		case T_DEV:
		case T_UNIXSOCK:
			return 0;
			/* all other cases are undefined */
		default:
			return -RSBAC_EINVALIDTARGET;
		}

	case R_MAP_EXEC:
		switch (target) {
		case T_FILE:
		case T_NONE:
			return 0;
			/* all other cases are undefined */
		default:
			return -RSBAC_EINVALIDTARGET;
		}


	default:
		return -RSBAC_EINVALIDTARGET;
	}

	return -RSBAC_EINVALIDTARGET;
}
