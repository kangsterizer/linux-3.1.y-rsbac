/******************************** */
/* Rule Set Based Access Control  */
/* Author and (c) 1999-2007:      */
/* Amon Ott <ao@rsbac.org>        */
/* Getname functions for all parts*/
/* Last modified: 17/Sep/2007     */
/******************************** */

#ifndef __RSBAC_GETNAME_H
#define __RSBAC_GETNAME_H

#include <rsbac/types.h>
#ifdef CONFIG_RSBAC_XSTATS
#include <rsbac/syscalls.h>
#endif

#if defined(__KERNEL__) && defined(CONFIG_RSBAC_LOG_FULL_PATH)
#include <linux/fs.h>
#if (CONFIG_RSBAC_MAX_PATH_LEN > 2000)
#undef CONFIG_RSBAC_MAX_PATH_LEN
#define CONFIG_RSBAC_MAX_PATH_LEN 2000
#endif
#if (CONFIG_RSBAC_MAX_PATH_LEN < RSBAC_MAXNAMELEN)
#undef CONFIG_RSBAC_MAX_PATH_LEN
#define CONFIG_RSBAC_MAX_PATH_LEN RSBAC_MAXNAMELEN
#endif
#endif

extern char * get_request_name(char * , enum rsbac_adf_request_t);

extern enum rsbac_adf_request_t get_request_nr(const char *);

extern char * get_result_name(char * , enum rsbac_adf_req_ret_t);

extern enum rsbac_adf_req_ret_t get_result_nr(const char *);

extern enum rsbac_switch_target_t get_attr_module(enum rsbac_attribute_t attr);

extern char * get_attribute_name(char * , enum rsbac_attribute_t);

extern char * get_attribute_value_name(     char *            attr_val_name,
                                       enum rsbac_attribute_t attr,
                                       union rsbac_attribute_value_t * attr_val_p);

extern enum rsbac_attribute_t get_attribute_nr(const char *);

extern char * get_target_name(char * , enum  rsbac_target_t,
                              char * , union rsbac_target_id_t);

extern char * get_target_name_only(char * target_type_name,
                                   enum   rsbac_target_t target);

extern enum rsbac_target_t get_target_nr(const char *);

extern char * get_ipc_target_name(char *,
                                  enum rsbac_ipc_type_t);

extern enum rsbac_ipc_type_t get_ipc_target_nr(const char *);

extern char * get_scd_type_name(char *,
                                enum rsbac_scd_type_t);

extern enum rsbac_scd_type_t get_scd_type_nr(const char *);

extern char * get_switch_target_name(char *,
                                     enum rsbac_switch_target_t);

extern enum rsbac_switch_target_t get_switch_target_nr(const char *);

extern char * get_error_name(char *,
                             int);

#ifndef __KERNEL__
extern char * get_attribute_param(char * , enum rsbac_attribute_t);
#endif

extern char * get_log_level_name(char *,
                                  enum rsbac_log_level_t);

extern enum rsbac_log_level_t get_log_level_nr(const char *);

#ifdef __KERNEL__
int rsbac_get_full_path(struct dentry * dentry_p, char path[], int maxlen);
#endif

char * get_cap_name(char * name,
                    u_int value);

int get_cap_nr(const char * name);

#ifdef CONFIG_RSBAC_XSTATS
char *get_syscall_name(char *syscall_name,
                       enum rsbac_syscall_t syscall);
#endif

#endif
