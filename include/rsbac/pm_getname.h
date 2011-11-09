/******************************** */
/* Rule Set Based Access Control  */
/* Author and (c) 1999: Amon Ott  */
/* Getname functions for PM parts */
/* Last modified: 08/Feb/99       */
/******************************** */

#ifndef __RSBAC_PM_GETNAME_H
#define __RSBAC_PM_GETNAME_H

#include <rsbac/types.h>

#ifndef NULL
#define NULL ((void *) 0)
#endif

#include <rsbac/helpers.h>
#include <rsbac/error.h>

char * get_pm_list_name(char *,
                        enum  rsbac_pm_list_t);

enum   rsbac_pm_list_t get_pm_list_nr(const char *);

char * get_pm_all_list_name(char *,
                            enum  rsbac_pm_all_list_t);

enum   rsbac_pm_all_list_t get_pm_all_list_nr(const char *);

char * get_pm_role_name(char *,
                        enum  rsbac_pm_role_t);

enum   rsbac_pm_role_t get_pm_role_nr(const char *);

char * get_pm_process_type_name(char *,
                        enum  rsbac_pm_process_type_t);

enum   rsbac_pm_process_type_t get_pm_process_type_nr(const char *);

char * get_pm_object_type_name(char *,
                        enum  rsbac_pm_object_type_t);

enum   rsbac_pm_object_type_t get_pm_object_type_nr(const char *);

#ifdef __KERNEL__
char * get_pm_set_name(char *,
                        enum  rsbac_pm_set_t);

enum   rsbac_pm_set_t get_pm_set_nr(const char *);

char * get_pm_target_name(char *,
                        enum  rsbac_pm_target_t);

enum   rsbac_pm_target_t get_pm_target_nr(const char *);

char * get_pm_data_name(char *,
                        enum  rsbac_pm_data_t);

enum   rsbac_pm_data_t get_pm_data_nr(const char *);
#endif

char * get_pm_function_type_name(char *,
                        enum  rsbac_pm_function_type_t);

enum   rsbac_pm_function_type_t get_pm_function_type_nr(const char *);

#ifndef __KERNEL__
char * get_pm_function_param(char *,
                        enum  rsbac_pm_function_type_t);

char * get_pm_tkt_function_param(char *,
                        enum  rsbac_pm_tkt_function_type_t);
#endif

char * get_pm_tkt_function_type_name(char *,
                        enum  rsbac_pm_tkt_function_type_t);

enum   rsbac_pm_tkt_function_type_t
    get_pm_tkt_function_type_nr(const char *);

#endif
