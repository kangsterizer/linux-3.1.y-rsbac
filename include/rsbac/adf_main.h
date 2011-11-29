/************************************ */
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2010:          */
/*   Amon Ott <ao@rsbac.org>          */
/* Data Structs etc. for Access       */
/* Control Decision Facility          */
/* Last modified: 21/May/2010         */
/************************************ */

#ifndef __RSBAC_ADF_MAIN_H
#define __RSBAC_ADF_MAIN_H

#include <linux/sched.h>
#include <rsbac/types.h>

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
#include <rsbac/reg.h>
#endif

#ifdef CONFIG_RSBAC_SECDEL
#include <linux/dcache.h>
#endif

/***************************************************/
/*              Global Variables                   */
/***************************************************/

extern __u64 rsbac_adf_request_count[T_NONE+1];
extern __u64 rsbac_adf_set_attr_count[T_NONE+1];
#ifdef CONFIG_RSBAC_XSTATS
extern __u64 rsbac_adf_request_xcount[T_NONE+1][R_NONE];
extern __u64 rsbac_adf_set_attr_xcount[T_NONE+1][R_NONE];
#endif

/* Bitmasks to ignore some requests on some modules */

#ifdef CONFIG_RSBAC_MAC
#define RSBAC_MAC_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_ADD_TO_KERNEL) | \
  ((rsbac_request_vector_t) 1 << R_ALTER) | \
  ((rsbac_request_vector_t) 1 << R_APPEND_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_GROUP) | \
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
  ((rsbac_request_vector_t) 1 << R_RECEIVE) \
  )
#define RSBAC_MAC_SET_ATTR_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_APPEND_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CLONE) | \
  ((rsbac_request_vector_t) 1 << R_CREATE) | \
  ((rsbac_request_vector_t) 1 << R_DELETE) | \
  ((rsbac_request_vector_t) 1 << R_EXECUTE) | \
  ((rsbac_request_vector_t) 1 << R_MOUNT) | \
  ((rsbac_request_vector_t) 1 << R_READ) | \
  ((rsbac_request_vector_t) 1 << R_READ_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_READ_WRITE_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_SEARCH) | \
  ((rsbac_request_vector_t) 1 << R_TRACE) | \
  ((rsbac_request_vector_t) 1 << R_WRITE) | \
  ((rsbac_request_vector_t) 1 << R_WRITE_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_BIND) | \
  ((rsbac_request_vector_t) 1 << R_LISTEN) | \
  ((rsbac_request_vector_t) 1 << R_ACCEPT) | \
  ((rsbac_request_vector_t) 1 << R_CONNECT) | \
  ((rsbac_request_vector_t) 1 << R_SEND) | \
  ((rsbac_request_vector_t) 1 << R_RECEIVE) \
  )
#endif

#ifdef CONFIG_RSBAC_PM
#define RSBAC_PM_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_ADD_TO_KERNEL) | \
  ((rsbac_request_vector_t) 1 << R_APPEND_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CLONE) | \
  ((rsbac_request_vector_t) 1 << R_CLOSE) | \
  ((rsbac_request_vector_t) 1 << R_CREATE) | \
  ((rsbac_request_vector_t) 1 << R_DELETE) | \
  ((rsbac_request_vector_t) 1 << R_EXECUTE) | \
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
  ((rsbac_request_vector_t) 1 << R_MAP_EXEC) \
  )
#define RSBAC_PM_SET_ATTR_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_APPEND_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_CLONE) | \
  ((rsbac_request_vector_t) 1 << R_CREATE) | \
  ((rsbac_request_vector_t) 1 << R_EXECUTE) | \
  ((rsbac_request_vector_t) 1 << R_READ) | \
  ((rsbac_request_vector_t) 1 << R_READ_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_READ_WRITE_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_WRITE) | \
  ((rsbac_request_vector_t) 1 << R_WRITE_OPEN) \
  )
#endif

#ifdef CONFIG_RSBAC_DAZ
#define RSBAC_DAZ_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_APPEND_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_CLOSE) | \
  ((rsbac_request_vector_t) 1 << R_DELETE) | \
  ((rsbac_request_vector_t) 1 << R_EXECUTE) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_READ_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_READ_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_READ_WRITE_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_WRITE_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_MODULE) \
  )
#define RSBAC_DAZ_SET_ATTR_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_APPEND_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_CLONE) | \
  ((rsbac_request_vector_t) 1 << R_CLOSE) | \
  ((rsbac_request_vector_t) 1 << R_DELETE) | \
  ((rsbac_request_vector_t) 1 << R_EXECUTE) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_READ_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_READ_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_READ_WRITE_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_MODULE) | \
  ((rsbac_request_vector_t) 1 << R_WRITE) | \
  ((rsbac_request_vector_t) 1 << R_WRITE_OPEN) )
#endif

#ifdef CONFIG_RSBAC_FF
#if defined(CONFIG_RSBAC_FF_UM_PROT)
#define RSBAC_FF_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_APPEND_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CHDIR) | \
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
  ((rsbac_request_vector_t) 1 << R_RENAME) | \
  ((rsbac_request_vector_t) 1 << R_SEARCH) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_LOG) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_MODULE) | \
  ((rsbac_request_vector_t) 1 << R_TRUNCATE) | \
  ((rsbac_request_vector_t) 1 << R_UMOUNT) | \
  ((rsbac_request_vector_t) 1 << R_WRITE) | \
  ((rsbac_request_vector_t) 1 << R_WRITE_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_MAP_EXEC) \
  )
#else
#define RSBAC_FF_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_APPEND_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_EFF_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_FS_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_EFF_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_FS_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CHDIR) | \
  ((rsbac_request_vector_t) 1 << R_CREATE) | \
  ((rsbac_request_vector_t) 1 << R_DELETE) | \
  ((rsbac_request_vector_t) 1 << R_EXECUTE) | \
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
  ((rsbac_request_vector_t) 1 << R_RENAME) | \
  ((rsbac_request_vector_t) 1 << R_SEARCH) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_LOG) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_MODULE) | \
  ((rsbac_request_vector_t) 1 << R_TRUNCATE) | \
  ((rsbac_request_vector_t) 1 << R_UMOUNT) | \
  ((rsbac_request_vector_t) 1 << R_WRITE) | \
  ((rsbac_request_vector_t) 1 << R_WRITE_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_MAP_EXEC) \
  )
#endif
#endif

#ifdef CONFIG_RSBAC_AUTH
#if defined(CONFIG_RSBAC_AUTH_UM_PROT)
#define RSBAC_AUTH_REQUEST_VECTOR_UM (\
  ((rsbac_request_vector_t) 1 << R_CREATE) | \
  ((rsbac_request_vector_t) 1 << R_DELETE) | \
  ((rsbac_request_vector_t) 1 << R_GET_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_RENAME) | \
  ((rsbac_request_vector_t) 1 << R_WRITE) )
#else
#define RSBAC_AUTH_REQUEST_VECTOR_UM 0
#endif
#if defined(CONFIG_RSBAC_AUTH_UM_PROT) || defined(CONFIG_RSBAC_AUTH_GROUP)
#define RSBAC_AUTH_REQUEST_VECTOR_CG ((rsbac_request_vector_t) 1 << R_CHANGE_GROUP)
#else
#define RSBAC_AUTH_REQUEST_VECTOR_CG 0
#endif
#if defined(CONFIG_RSBAC_AUTH_GROUP) && defined (CONFIG_RSBAC_AUTH_DAC_GROUP)
#define RSBAC_AUTH_REQUEST_VECTOR_DG ( \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_EFF_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_FS_GROUP) )
#else
#define RSBAC_AUTH_REQUEST_VECTOR_DG 0
#endif
#if defined (CONFIG_RSBAC_AUTH_DAC_OWNER)
#define RSBAC_AUTH_REQUEST_VECTOR_DO ( \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_EFF_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_DAC_FS_OWNER) )
#else
#define RSBAC_AUTH_REQUEST_VECTOR_DO 0
#endif
#if defined (CONFIG_RSBAC_AUTH_AUTH_PROT)
#define RSBAC_AUTH_REQUEST_VECTOR_AA ( \
  ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_PERMISSIONS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_SYSTEM_DATA) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_LOG) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_MODULE) )
#else
#define RSBAC_AUTH_REQUEST_VECTOR_AA 0
#endif

#define RSBAC_AUTH_REQUEST_VECTOR (\
  RSBAC_AUTH_REQUEST_VECTOR_UM | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_OWNER) | \
  RSBAC_AUTH_REQUEST_VECTOR_CG | \
  RSBAC_AUTH_REQUEST_VECTOR_DG | \
  RSBAC_AUTH_REQUEST_VECTOR_DO | \
  RSBAC_AUTH_REQUEST_VECTOR_AA | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ATTRIBUTE) \
  )

#if defined (CONFIG_RSBAC_AUTH_AUTH_PROT)
#define RSBAC_AUTH_SET_ATTR_VECTOR_AA ( \
  ((rsbac_request_vector_t) 1 << R_APPEND_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_CHANGE_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_DELETE) | \
  ((rsbac_request_vector_t) 1 << R_LINK_HARD) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ACCESS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_READ_WRITE_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_RENAME) | \
  ((rsbac_request_vector_t) 1 << R_TRUNCATE) | \
  ((rsbac_request_vector_t) 1 << R_WRITE_OPEN) )
#else
#define RSBAC_AUTH_SET_ATTR_VECTOR_AA 0
#endif
#define RSBAC_AUTH_SET_ATTR_VECTOR (\
  RSBAC_AUTH_SET_ATTR_VECTOR_AA | \
  ((rsbac_request_vector_t) 1 << R_CLONE) | \
  ((rsbac_request_vector_t) 1 << R_EXECUTE) \
  )
#endif

#ifdef CONFIG_RSBAC_CAP
#ifdef CONFIG_RSBAC_CAP_PROC_HIDE
#define RSBAC_CAP_REQUEST_VECTOR ( \
  ((rsbac_request_vector_t) 1 << R_CHANGE_GROUP) | \
  ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_MODIFY_SYSTEM_DATA) | \
  ((rsbac_request_vector_t) 1 << R_READ_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_SEND_SIGNAL) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_LOG) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_MODULE) | \
  ((rsbac_request_vector_t) 1 << R_TRACE) )
#else
#define RSBAC_CAP_REQUEST_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_MODIFY_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_READ_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_LOG) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_MODULE) )
#endif
#if defined (CONFIG_RSBAC_CAP_PROC_HIDE) || defined(CONFIG_RSBAC_CAP_LOG_MISSING)
#define RSBAC_CAP_SET_ATTR_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_CHANGE_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CLONE) | \
  ((rsbac_request_vector_t) 1 << R_EXECUTE) )
#else
#define RSBAC_CAP_SET_ATTR_VECTOR (\
  ((rsbac_request_vector_t) 1 << R_CHANGE_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_EXECUTE) )
#endif
#endif

#ifdef CONFIG_RSBAC_JAIL
#define RSBAC_JAIL_REQUEST_VECTOR ( \
  ((rsbac_request_vector_t) 1 << R_ADD_TO_KERNEL) | \
  ((rsbac_request_vector_t) 1 << R_ALTER) | \
  ((rsbac_request_vector_t) 1 << R_APPEND_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_CREATE) | \
  ((rsbac_request_vector_t) 1 << R_DELETE) | \
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
  ((rsbac_request_vector_t) 1 << R_SEND_SIGNAL) | \
  ((rsbac_request_vector_t) 1 << R_SHUTDOWN) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_LOG) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_MODULE) | \
  ((rsbac_request_vector_t) 1 << R_TRACE) | \
  ((rsbac_request_vector_t) 1 << R_UMOUNT) | \
  ((rsbac_request_vector_t) 1 << R_WRITE) | \
  ((rsbac_request_vector_t) 1 << R_WRITE_OPEN) | \
  ((rsbac_request_vector_t) 1 << R_BIND) | \
  ((rsbac_request_vector_t) 1 << R_LISTEN) | \
  ((rsbac_request_vector_t) 1 << R_ACCEPT) | \
  ((rsbac_request_vector_t) 1 << R_CONNECT) | \
  ((rsbac_request_vector_t) 1 << R_SEND) | \
  ((rsbac_request_vector_t) 1 << R_RECEIVE) | \
  ((rsbac_request_vector_t) 1 << R_NET_SHUTDOWN) )
#define RSBAC_JAIL_SET_ATTR_VECTOR ( \
  ((rsbac_request_vector_t) 1 << R_CHANGE_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_CLONE) | \
  ((rsbac_request_vector_t) 1 << R_CREATE) | \
  ((rsbac_request_vector_t) 1 << R_EXECUTE) | \
  ((rsbac_request_vector_t) 1 << R_CONNECT) | \
  ((rsbac_request_vector_t) 1 << R_BIND) )
#endif

#ifdef CONFIG_RSBAC_PAX
#define RSBAC_PAX_REQUEST_VECTOR ( \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_READ_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_LOG) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_MODULE) )
#endif

#ifdef CONFIG_RSBAC_RES
#define RSBAC_RES_REQUEST_VECTOR ( \
  ((rsbac_request_vector_t) 1 << R_MODIFY_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_READ_ATTRIBUTE) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_LOG) | \
  ((rsbac_request_vector_t) 1 << R_SWITCH_MODULE) )
#define RSBAC_RES_SET_ATTR_VECTOR ( \
  ((rsbac_request_vector_t) 1 << R_CHANGE_OWNER) | \
  ((rsbac_request_vector_t) 1 << R_EXECUTE) )
#endif

/***************************************************/
/*              General Prototypes                 */
/***************************************************/

/* We call this function in kernel/sched.c         */
extern struct task_struct * find_process_by_pid(pid_t);

#ifdef CONFIG_RSBAC_DEBUG
extern  enum rsbac_adf_req_ret_t
   rsbac_adf_request_check (enum  rsbac_adf_request_t     request,
                                  rsbac_pid_t             caller_pid,
                            enum  rsbac_target_t          target,
                            union rsbac_target_id_t     * tid_p,
                            enum  rsbac_attribute_t       attr,
                            union rsbac_attribute_value_t * attr_val_p,
                                  rsbac_uid_t             owner);

extern int rsbac_adf_set_attr_check( enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */
#endif

extern enum rsbac_adf_req_ret_t
    adf_and_plus(enum rsbac_adf_req_ret_t res1,
                 enum rsbac_adf_req_ret_t res2);

/***************************************************/
/*              Module Prototypes                  */
/***************************************************/

#if !defined(CONFIG_RSBAC_MAINT)

/******* MAC ********/

#ifdef CONFIG_RSBAC_MAC
#ifdef CONFIG_RSBAC_SWITCH_MAC
extern  rsbac_boolean_t rsbac_switch_mac;
#endif

extern  enum rsbac_adf_req_ret_t  rsbac_adf_request_mac(
                                     enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

extern  int  rsbac_adf_set_attr_mac( enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

#endif  /* MAC */


/******* PM ********/

#ifdef CONFIG_RSBAC_PM
#ifdef CONFIG_RSBAC_SWITCH_PM
extern  rsbac_boolean_t rsbac_switch_pm;
#endif

extern  enum rsbac_adf_req_ret_t  rsbac_adf_request_pm(
                                     enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

extern  int  rsbac_adf_set_attr_pm ( enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

#ifdef CONFIG_RSBAC_SECDEL
extern rsbac_boolean_t rsbac_need_overwrite_pm(struct dentry * dentry_p);
#endif

#endif  /* PM */

/******* DAZ ********/

#ifdef CONFIG_RSBAC_DAZ
#ifdef CONFIG_RSBAC_SWITCH_DAZ
extern  rsbac_boolean_t rsbac_switch_daz;
#endif

extern  enum rsbac_adf_req_ret_t  rsbac_adf_request_daz(
                                     enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

extern  int  rsbac_adf_set_attr_daz (enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

#endif  /* DAZ */
 
/******* FF ********/

#ifdef CONFIG_RSBAC_FF
#ifdef CONFIG_RSBAC_SWITCH_FF
extern  rsbac_boolean_t rsbac_switch_ff;
#endif

extern  enum rsbac_adf_req_ret_t  rsbac_adf_request_ff(
                                     enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

extern  int  rsbac_adf_set_attr_ff ( enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

#ifdef CONFIG_RSBAC_SECDEL
extern rsbac_boolean_t rsbac_need_overwrite_ff(struct dentry * dentry_p);
#endif

#endif  /* FF */
 
/******* RC ********/

#ifdef CONFIG_RSBAC_RC
#ifdef CONFIG_RSBAC_SWITCH_RC
extern  rsbac_boolean_t rsbac_switch_rc;
#endif

extern  enum rsbac_adf_req_ret_t  rsbac_adf_request_rc(
                                     enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

extern  int  rsbac_adf_set_attr_rc ( enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

/* Secure delete/truncate for this module */
#ifdef CONFIG_RSBAC_SECDEL
extern rsbac_boolean_t rsbac_need_overwrite_rc(struct dentry * dentry_p);
#endif
#endif  /* RC */

/****** AUTH *******/

#ifdef CONFIG_RSBAC_AUTH
#ifdef CONFIG_RSBAC_SWITCH_AUTH
extern  rsbac_boolean_t rsbac_switch_auth;
#endif

extern  enum rsbac_adf_req_ret_t  rsbac_adf_request_auth(
                                     enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

extern  int  rsbac_adf_set_attr_auth(enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

#endif /* AUTH */

/****** ACL *******/

#ifdef CONFIG_RSBAC_ACL
#ifdef CONFIG_RSBAC_SWITCH_ACL
extern  rsbac_boolean_t rsbac_switch_acl;
#endif

extern  enum rsbac_adf_req_ret_t  rsbac_adf_request_acl(
                                     enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

extern  int  rsbac_adf_set_attr_acl (enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

#endif /* ACL */

/****** CAP *******/

#ifdef CONFIG_RSBAC_CAP
#ifdef CONFIG_RSBAC_SWITCH_CAP
extern  rsbac_boolean_t rsbac_switch_cap;
#endif

extern  enum rsbac_adf_req_ret_t  rsbac_adf_request_cap(
                                     enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

extern  int  rsbac_adf_set_attr_cap (enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

#endif /* CAP */

/****** JAIL *******/

#ifdef CONFIG_RSBAC_JAIL
#ifdef CONFIG_RSBAC_SWITCH_JAIL
extern  rsbac_boolean_t rsbac_switch_jail;
#endif

extern  enum rsbac_adf_req_ret_t  rsbac_adf_request_jail(
                                     enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

extern  int  rsbac_adf_set_attr_jail(enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

#endif /* JAIL */

/******* PAX ********/

#ifdef CONFIG_RSBAC_PAX
#ifdef CONFIG_RSBAC_SWITCH_PAX
extern  rsbac_boolean_t rsbac_switch_pax;
#endif

extern  enum rsbac_adf_req_ret_t  rsbac_adf_request_pax(
                                     enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

extern  int  rsbac_adf_set_attr_pax( enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

#endif  /* PAX */


/****** RES *******/

#ifdef CONFIG_RSBAC_RES
#ifdef CONFIG_RSBAC_SWITCH_RES
extern  rsbac_boolean_t rsbac_switch_res;
#endif

extern  enum rsbac_adf_req_ret_t  rsbac_adf_request_res(
                                     enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

extern  int  rsbac_adf_set_attr_res (enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

#ifdef CONFIG_RSBAC_SECDEL
extern inline rsbac_boolean_t rsbac_need_overwrite_res(struct dentry * dentry_p)
  {
    return FALSE;
  }
#endif
#endif /* RES */

/****** REG *******/

#if defined(CONFIG_RSBAC_REG)
extern  enum rsbac_adf_req_ret_t  rsbac_adf_request_reg(
                                     enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

extern  int  rsbac_adf_set_attr_reg (enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

#ifdef CONFIG_RSBAC_SECDEL
extern inline rsbac_boolean_t rsbac_need_overwrite_reg(struct dentry * dentry_p)
  {
    return FALSE;
  }
#endif
#endif /* REG */

#endif /* !MAINT */

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
/* Init */
#ifdef CONFIG_RSBAC_INIT_DELAY
void rsbac_reg_init(void);
#else
void rsbac_reg_init(void) __init;
#endif

/* mounting and umounting */
extern int rsbac_mount_reg(kdev_t kdev);
extern int rsbac_umount_reg(kdev_t kdev);

/* RSBAC attribute saving to disk can be triggered from outside
 * param: call lock_kernel() before writing?
 */
#if defined(CONFIG_RSBAC_AUTO_WRITE)
extern int rsbac_write_reg(void);
#endif /* CONFIG_RSBAC_AUTO_WRITE */

/* Status checking */
extern int rsbac_check_reg(int correct, int check_inode);

#endif /* REG */

#endif /* End of adf_main.h */
