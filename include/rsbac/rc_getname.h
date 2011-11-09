/******************************** */
/* Rule Set Based Access Control  */
/* Author and (c) 1999: Amon Ott  */
/* Getname functions for RC parts */
/* Last modified: 18/Jan/99       */
/******************************** */

#ifndef __RSBAC_RC_GETNAME_H
#define __RSBAC_RC_GETNAME_H

#include <rsbac/rc_types.h>

#ifndef NULL
#define NULL ((void *) 0)
#endif

char *get_rc_target_name(char *name, enum rsbac_rc_target_t value);

enum rsbac_rc_target_t get_rc_target_nr(const char *name);

char *get_rc_admin_name(char *name, enum rsbac_rc_admin_type_t value);

enum rsbac_rc_admin_type_t get_rc_admin_nr(const char *name);

char *get_rc_scd_type_name(char *name, enum rsbac_rc_scd_type_t value);

enum rsbac_rc_scd_type_t get_rc_scd_type_nr(const char *name);

char *get_rc_item_name(char *name, enum rsbac_rc_item_t value);

enum rsbac_rc_item_t get_rc_item_nr(const char *name);

#ifndef __KERNEL__
char *get_rc_item_param(char *name, enum rsbac_rc_item_t value);
#endif

char *get_rc_special_right_name(char *name,
				enum rsbac_rc_special_rights_t value);

#ifndef __KERNEL__
enum rsbac_rc_special_rights_t get_rc_special_right_nr(const char *name);
#endif

#endif
