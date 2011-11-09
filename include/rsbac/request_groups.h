/************************************ */
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2008: Amon Ott */
/* Groups of ADF request for          */
/* administration                     */
/* Last modified: 21/Jan/2008         */
/************************************ */

#ifndef __RSBAC_REQUEST_GROUPS_H
#define __RSBAC_REQUEST_GROUPS_H

#define RSBAC_READ_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_CHDIR) | \
  ((rsbac_request_vector_t) 1 << R_CLOSE) | \
  ((rsbac_request_vector_t) 1 << R_GET_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_READ) | \
  ((rsbac_request_vector_t) 1 << R_READ_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_SEARCH) | \
  ((rsbac_request_vector_t) 1 << R_TERMINATE) | \
  ((rsbac_request_vector_t) 1 << R_AUTHENTICATE) \
  )

#define RSBAC_WRITE_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_ALTER) | \
  ((rsbac_request_vector_t) 1 << R_APPEND_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_EFF_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_FS_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_EFF_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_FS_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CLONE) | \
  ((rsbac_request_vector_t) 1 << R_CREATE) | \
  ((rsbac_request_vector_t) 1 << R_DELETE) | \
  ((rsbac_request_vector_t) 1 << R_LINK_HARD) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ACCESS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_RENAME) | \
  ((rsbac_request_vector_t) 1 << R_SEND_SIGNAL) | \
  ((rsbac_request_vector_t) 1 << R_TRACE) | \
  ((rsbac_request_vector_t) 1 << R_TRUNCATE) | \
  ((rsbac_request_vector_t) 1 << R_WRITE) | \
  ((rsbac_request_vector_t) 1 << R_WRITE_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_IOCTL) | \
  ((rsbac_request_vector_t) 1 << R_LOCK) \
  )

#define RSBAC_READ_WRITE_REQUEST_VECTOR (\
  RSBAC_READ_REQUEST_VECTOR | \
  ((rsbac_request_vector_t) 1 << R_ALTER) | \
  ((rsbac_request_vector_t) 1 << R_APPEND_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_EFF_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_FS_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_EFF_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_FS_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CLONE) | \
  ((rsbac_request_vector_t) 1 << R_CREATE) | \
  ((rsbac_request_vector_t) 1 << R_DELETE) | \
  ((rsbac_request_vector_t) 1 << R_LINK_HARD) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ACCESS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_SYSTEM_DATA) | \
  ((rsbac_request_vector_t) 1 << R_READ_WRITE_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_RENAME) | \
  ((rsbac_request_vector_t) 1 << R_SEND_SIGNAL) | \
  ((rsbac_request_vector_t) 1 << R_TRACE) | \
  ((rsbac_request_vector_t) 1 << R_TRUNCATE) | \
  ((rsbac_request_vector_t) 1 << R_WRITE) | \
  ((rsbac_request_vector_t) 1 << R_WRITE_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_BIND) | \
  ((rsbac_request_vector_t) 1 << R_LISTEN) | \
  ((rsbac_request_vector_t) 1 << R_ACCEPT) | \
  ((rsbac_request_vector_t) 1 << R_CONNECT) | \
  ((rsbac_request_vector_t) 1 << R_SEND) | \
  ((rsbac_request_vector_t) 1 << R_RECEIVE) | \
  ((rsbac_request_vector_t) 1 << R_NET_SHUTDOWN) | \
  ((rsbac_request_vector_t) 1 << R_IOCTL) | \
  ((rsbac_request_vector_t) 1 << R_LOCK) \
  )

#define RSBAC_READ_WRITE_OPEN_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_READ_WRITE_OPEN) \
  )

#define RSBAC_EXECUTE_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_EXECUTE) | \
  ((rsbac_request_vector_t) 1 << R_MAP_EXEC) \
  )


#define RSBAC_SYSTEM_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_ADD_TO_KERNEL) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_SYSTEM_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MOUNT) | \
  ((rsbac_request_vector_t) 1 << R_READ_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_REMOVE_FROM_KERNEL) | \
  ((rsbac_request_vector_t) 1 << R_SHUTDOWN) | \
  ((rsbac_request_vector_t) 1 << R_UMOUNT) \
  )

#define RSBAC_SECURITY_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_MODIFY_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_READ_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_LOG) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_MODULE) \
  )

#define RSBAC_FD_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_ADD_TO_KERNEL) | \
  ((rsbac_request_vector_t) 1 << R_APPEND_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CHDIR) | \
  ((rsbac_request_vector_t) 1 << R_CLOSE) | \
  ((rsbac_request_vector_t) 1 << R_CREATE) | \
  ((rsbac_request_vector_t) 1 << R_DELETE) | \
  ((rsbac_request_vector_t) 1 << R_EXECUTE) | \
  ((rsbac_request_vector_t) 1 << R_GET_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_LINK_HARD) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ACCESS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MOUNT) | \
  ((rsbac_request_vector_t) 1 << R_READ) | \
  ((rsbac_request_vector_t) 1 << R_READ_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_READ_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_READ_WRITE_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_REMOVE_FROM_KERNEL) | \
  ((rsbac_request_vector_t) 1 << R_RENAME) | \
  ((rsbac_request_vector_t) 1 << R_SEARCH) | \
  ((rsbac_request_vector_t) 1 << R_TRUNCATE) | \
  ((rsbac_request_vector_t) 1 << R_UMOUNT) | \
  ((rsbac_request_vector_t) 1 << R_WRITE) | \
  ((rsbac_request_vector_t) 1 << R_WRITE_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_MAP_EXEC) | \
  ((rsbac_request_vector_t) 1 << R_LISTEN) | \
  ((rsbac_request_vector_t) 1 << R_ACCEPT) | \
  ((rsbac_request_vector_t) 1 << R_CONNECT) | \
  ((rsbac_request_vector_t) 1 << R_SEND) | \
  ((rsbac_request_vector_t) 1 << R_RECEIVE) | \
  ((rsbac_request_vector_t) 1 << R_NET_SHUTDOWN) | \
  ((rsbac_request_vector_t) 1 << R_IOCTL) | \
  ((rsbac_request_vector_t) 1 << R_LOCK) \
  )

#define RSBAC_DEV_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_ADD_TO_KERNEL) | \
  ((rsbac_request_vector_t) 1 << R_APPEND_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_CLOSE) | \
  ((rsbac_request_vector_t) 1 << R_GET_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_SYSTEM_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MOUNT) | \
  ((rsbac_request_vector_t) 1 << R_READ) | \
  ((rsbac_request_vector_t) 1 << R_READ_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_READ_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_READ_WRITE_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_REMOVE_FROM_KERNEL) | \
  ((rsbac_request_vector_t) 1 << R_UMOUNT) | \
  ((rsbac_request_vector_t) 1 << R_WRITE) | \
  ((rsbac_request_vector_t) 1 << R_WRITE_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_SEND) | \
  ((rsbac_request_vector_t) 1 << R_IOCTL) \
  )

#define RSBAC_IPC_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_ALTER) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CLOSE) | \
  ((rsbac_request_vector_t) 1 << R_CREATE) | \
  ((rsbac_request_vector_t) 1 << R_DELETE) | \
  ((rsbac_request_vector_t) 1 << R_GET_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_SYSTEM_DATA) | \
  ((rsbac_request_vector_t) 1 << R_READ) | \
  ((rsbac_request_vector_t) 1 << R_READ_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_READ_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_READ_WRITE_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_WRITE) | \
  ((rsbac_request_vector_t) 1 << R_NET_SHUTDOWN) | \
  ((rsbac_request_vector_t) 1 << R_BIND) | \
  ((rsbac_request_vector_t) 1 << R_LISTEN) | \
  ((rsbac_request_vector_t) 1 << R_ACCEPT) | \
  ((rsbac_request_vector_t) 1 << R_CONNECT) | \
  ((rsbac_request_vector_t) 1 << R_SEND) | \
  ((rsbac_request_vector_t) 1 << R_RECEIVE) | \
  ((rsbac_request_vector_t) 1 << R_IOCTL) | \
  ((rsbac_request_vector_t) 1 << R_LOCK) \
  )

#define RSBAC_SCD_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_GET_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_SYSTEM_DATA) | \
  ((rsbac_request_vector_t) 1 << R_READ_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_WRITE) \
  )

#define RSBAC_USER_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_CHANGE_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CREATE) | \
  ((rsbac_request_vector_t) 1 << R_DELETE) | \
  ((rsbac_request_vector_t) 1 << R_GET_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_READ) | \
  ((rsbac_request_vector_t) 1 << R_READ_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_RENAME) | \
  ((rsbac_request_vector_t) 1 << R_SEARCH) | \
  ((rsbac_request_vector_t) 1 << R_WRITE) | \
  ((rsbac_request_vector_t) 1 << R_AUTHENTICATE) \
  )

#define RSBAC_GROUP_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_CREATE) | \
  ((rsbac_request_vector_t) 1 << R_DELETE) | \
  ((rsbac_request_vector_t) 1 << R_GET_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_READ) | \
  ((rsbac_request_vector_t) 1 << R_READ_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_RENAME) | \
  ((rsbac_request_vector_t) 1 << R_SEARCH) | \
  ((rsbac_request_vector_t) 1 << R_WRITE) \
  )

#define RSBAC_PROCESS_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_CHANGE_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_EFF_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_FS_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_EFF_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_FS_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CLONE) | \
  ((rsbac_request_vector_t) 1 << R_CREATE) | \
  ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_SYSTEM_DATA) | \
  ((rsbac_request_vector_t) 1 << R_READ_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_SEND_SIGNAL) | \
  ((rsbac_request_vector_t) 1 << R_TERMINATE) | \
  ((rsbac_request_vector_t) 1 << R_TRACE) \
  )

#define RSBAC_NETDEV_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_SYSTEM_DATA) | \
  ((rsbac_request_vector_t) 1 << R_READ_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_BIND) \
  )

#define RSBAC_NETTEMP_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_CREATE) | \
  ((rsbac_request_vector_t) 1 << R_DELETE) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_READ) | \
  ((rsbac_request_vector_t) 1 << R_READ_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_WRITE) \
  )

#define RSBAC_NETOBJ_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_CLOSE) | \
  ((rsbac_request_vector_t) 1 << R_CREATE) | \
  ((rsbac_request_vector_t) 1 << R_GET_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_SYSTEM_DATA) | \
  ((rsbac_request_vector_t) 1 << R_READ) | \
  ((rsbac_request_vector_t) 1 << R_READ_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_NET_SHUTDOWN) | \
  ((rsbac_request_vector_t) 1 << R_WRITE) | \
  ((rsbac_request_vector_t) 1 << R_BIND) | \
  ((rsbac_request_vector_t) 1 << R_LISTEN) | \
  ((rsbac_request_vector_t) 1 << R_ACCEPT) | \
  ((rsbac_request_vector_t) 1 << R_CONNECT) | \
  ((rsbac_request_vector_t) 1 << R_SEND) | \
  ((rsbac_request_vector_t) 1 << R_RECEIVE) | \
  ((rsbac_request_vector_t) 1 << R_IOCTL) \
  )

#define RSBAC_NONE_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_ADD_TO_KERNEL) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_READ_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_REMOVE_FROM_KERNEL) | \
  ((rsbac_request_vector_t) 1 << R_SHUTDOWN) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_LOG) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_MODULE) | \
  ((rsbac_request_vector_t) 1 << R_MAP_EXEC) \
  )

#define RSBAC_ALL_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_ADD_TO_KERNEL) | \
  ((rsbac_request_vector_t) 1 << R_ALTER) | \
  ((rsbac_request_vector_t) 1 << R_APPEND_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_EFF_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_FS_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_EFF_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_FS_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CHDIR) | \
  ((rsbac_request_vector_t) 1 << R_CLONE) | \
  ((rsbac_request_vector_t) 1 << R_CLOSE) | \
  ((rsbac_request_vector_t) 1 << R_CREATE) | \
  ((rsbac_request_vector_t) 1 << R_DELETE) | \
  ((rsbac_request_vector_t) 1 << R_EXECUTE) | \
  ((rsbac_request_vector_t) 1 << R_GET_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_LINK_HARD) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ACCESS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_SYSTEM_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MOUNT) | \
  ((rsbac_request_vector_t) 1 << R_READ) | \
  ((rsbac_request_vector_t) 1 << R_READ_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_READ_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_READ_WRITE_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_REMOVE_FROM_KERNEL) | \
  ((rsbac_request_vector_t) 1 << R_RENAME) | \
  ((rsbac_request_vector_t) 1 << R_SEARCH) | \
  ((rsbac_request_vector_t) 1 << R_SEND_SIGNAL) | \
  ((rsbac_request_vector_t) 1 << R_SHUTDOWN) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_LOG) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_MODULE) | \
  ((rsbac_request_vector_t) 1 << R_TERMINATE) | \
  ((rsbac_request_vector_t) 1 << R_TRACE) | \
  ((rsbac_request_vector_t) 1 << R_TRUNCATE) | \
  ((rsbac_request_vector_t) 1 << R_UMOUNT) | \
  ((rsbac_request_vector_t) 1 << R_WRITE) | \
  ((rsbac_request_vector_t) 1 << R_WRITE_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_MAP_EXEC) | \
  ((rsbac_request_vector_t) 1 << R_BIND) | \
  ((rsbac_request_vector_t) 1 << R_LISTEN) | \
  ((rsbac_request_vector_t) 1 << R_ACCEPT) | \
  ((rsbac_request_vector_t) 1 << R_CONNECT) | \
  ((rsbac_request_vector_t) 1 << R_SEND) | \
  ((rsbac_request_vector_t) 1 << R_RECEIVE) | \
  ((rsbac_request_vector_t) 1 << R_NET_SHUTDOWN) | \
  ((rsbac_request_vector_t) 1 << R_IOCTL) | \
  ((rsbac_request_vector_t) 1 << R_LOCK) \
  )

/* NW specials */

/* NWS == RSBAC_ACL_SUPERVISOR_RIGHT_VECTOR in ACL types */

#define RSBAC_NWR_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_CLOSE) | \
  ((rsbac_request_vector_t) 1 << R_EXECUTE) | \
  ((rsbac_request_vector_t) 1 << R_READ_OPEN) \
  )

#define RSBAC_NWW_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_ALTER) | \
  ((rsbac_request_vector_t) 1 << R_APPEND_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_EFF_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_FS_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_EFF_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_FS_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CLOSE) | \
  ((rsbac_request_vector_t) 1 << R_TRUNCATE) | \
  ((rsbac_request_vector_t) 1 << R_WRITE) | \
  ((rsbac_request_vector_t) 1 << R_WRITE_OPEN) \
  )

#define RSBAC_NWC_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_CLOSE) | \
  ((rsbac_request_vector_t) 1 << R_CREATE) \
  )

#define RSBAC_NWE_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_DELETE) \
  )

/* NWA == RSBAC_ACL_ACCESS_CONTROL_RIGHT_VECTOR in ACL types */

#define RSBAC_NWF_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_CHDIR) | \
  ((rsbac_request_vector_t) 1 << R_CLOSE) | \
  ((rsbac_request_vector_t) 1 << R_GET_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_READ) | \
  ((rsbac_request_vector_t) 1 << R_SEARCH) \
  )

#define RSBAC_NWM_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_CHANGE_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_EFF_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_FS_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_EFF_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_FS_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_LINK_HARD) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ACCESS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_RENAME) \
  )

#endif
