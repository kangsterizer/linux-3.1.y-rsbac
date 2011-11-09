/*
 * rc_getname.c: Getname functions for the RC module.
 *
 * Author and Copyright (C) 1999-2005 Amon Ott (ao@rsbac.org)
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License as
 *      published by the Free Software Foundation, version 2.
 *
 * Last modified 21/12/2004.
 */

#include <rsbac/getname.h>
#include <rsbac/rc_getname.h>
#include <rsbac/helpers.h>
#include <rsbac/error.h>

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#ifndef NULL
#define NULL ((void *) 0)
#endif

static char rc_target_list[RT_NONE + 1][13] = {
	"ROLE",
	"TYPE",
	"NONE"
};

static char rc_admin_list[RC_none + 1][13] = {
	"no_admin",
	"role_admin",
	"system_admin",
	"none"
};

static char rc_scd_type_list[RST_none - RST_min + 1][20] = {
	"auth_administration",
	"none"
};

static char rc_item_list[RI_none + 1][30] = {
	"role_comp",
	"admin_roles",
	"assign_roles",
	"type_comp_fd",
	"type_comp_dev",
	"type_comp_user",
	"type_comp_process",
	"type_comp_ipc",
	"type_comp_scd",
	"type_comp_group",
	"type_comp_netdev",
	"type_comp_nettemp",
	"type_comp_netobj",
	"admin_type",
	"name",
	"def_fd_create_type",
	"def_fd_ind_create_type",
	"def_user_create_type",
	"def_process_create_type",
	"def_process_chown_type",
	"def_process_execute_type",
	"def_ipc_create_type",
	"def_group_create_type",
	"def_unixsock_create_type",
	"boot_role",
	"req_reauth",
	"type_fd_name",
	"type_dev_name",
	"type_ipc_name",
	"type_user_name",
	"type_process_name",
	"type_group_name",
	"type_netdev_name",
	"type_nettemp_name",
	"type_netobj_name",
	"type_fd_need_secdel",
	"type_scd_name",
	"remove_role",
	"def_fd_ind_create_type_remove",
	"type_fd_remove",
	"type_dev_remove",
	"type_ipc_remove",
	"type_user_remove",
	"type_process_remove",
	"type_group_remove",
	"type_netdev_remove",
	"type_nettemp_remove",
	"type_netobj_remove",
#ifdef __KERNEL__
#endif
	"none"
};

#ifndef __KERNEL__
static char rc_item_param_list[RI_none + 1][100] = {
	"\t0 = FALSE, 1 = TRUE",
	"\t0 = FALSE, 1 = TRUE",
	"\t0 = FALSE, 1 = TRUE",
	"\t0 = FALSE, 1 = TRUE",
	"\t0 = FALSE, 1 = TRUE",
	"\t0 = FALSE, 1 = TRUE",
	"0 = FALSE, 1 = TRUE",
	"\t0 = FALSE, 1 = TRUE",
	"\t0 = FALSE, 1 = TRUE",
	"\t0 = FALSE, 1 = TRUE",
	"0 = FALSE, 1 = TRUE",
	"0 = FALSE, 1 = TRUE",
	"0 = FALSE, 1 = TRUE",
	"\t0 = no_admin, 1 = role_admin, 2 = system_admin\n\t\t\t(for RC administration only)",
	"\t\tString, max. 15 chars",
	"number, -2 = inherit from parent, -3 = no_create",
	"parent_type new_type, -2 = inherit from parent,\n\t\t\t-3 = no_create",
	"number, -2 = inherit from parent, -3 = no_create",
	"number, -1 = inherit from process,\n\t\t\t-3 = no_create",
	"number, -2 = inherit from parent (keep),\n\t\t\t-3 = no_create",
	"number, -2 = inherit from parent (keep),\n\t\t\t-5 = use def_create of new role, -6 = no_chown",
	"number, -1 = inherit from process (keep),\n\t\t\t-4 = no_execute",
	"number, -3 = no_create",
	"number, -7 = use_template (do not set)",
	"\t0 = FALSE, 1 = TRUE",
	"\tString, max. 15 chars",
	"\tString, max. 15 chars",
	"\tString, max. 15 chars",
	"\tString, max. 15 chars",
	"String, max. 15 chars",
	"\tString, max. 15 chars",
	"String, max. 15 chars",
	"String, max. 15 chars",
	"String, max. 15 chars",
	"0 = FALSE, 1 = TRUE",
	"\tString, max. 15 chars (read-only)",
	"\t\t(none)"
};
#endif

static char rc_special_right_list[RCR_NONE - RSBAC_RC_SPECIAL_RIGHT_BASE +
				  1][20] = {
	"ADMIN",
	"ASSIGN",
	"ACCESS_CONTROL",
	"SUPERVISOR",
	"MODIFY_AUTH",
	"CHANGE_AUTHED_OWNER",
	"SELECT",
	"NONE"
};

/*****************************************/

char *get_rc_target_name(char *name, enum rsbac_rc_target_t value)
{
	if (!name)
		return (NULL);
	if (value > RT_NONE)
		strcpy(name, "ERROR!");
	else
		strcpy(name, rc_target_list[value]);
	return (name);
};

enum rsbac_rc_target_t get_rc_target_nr(const char *name)
{
	enum rsbac_rc_target_t i;

	if (!name)
		return (RT_NONE);
	for (i = 0; i < RT_NONE; i++) {
		if (!strcmp(name, rc_target_list[i])) {
			return (i);
		}
	}
	return (RT_NONE);
};

char *get_rc_admin_name(char *name, enum rsbac_rc_admin_type_t value)
{
	if (!name)
		return (NULL);
	if (value > RC_none)
		strcpy(name, "ERROR!");
	else
		strcpy(name, rc_admin_list[value]);
	return (name);
};

enum rsbac_rc_admin_type_t get_rc_admin_nr(const char *name)
{
	enum rsbac_rc_admin_type_t i;

	if (!name)
		return (RC_none);
	for (i = 0; i < RC_none; i++) {
		if (!strcmp(name, rc_admin_list[i])) {
			return (i);
		}
	}
	return (RC_none);
};

char *get_rc_scd_type_name(char *name, enum rsbac_rc_scd_type_t value)
{
	if (!name)
		return (NULL);
	if (value < RST_min) {
		return (get_scd_type_name(name, value));
	}
	value -= RST_min;
	if (value > RST_none) {
		strcpy(name, "ERROR!");
		return (name);
	}
	strcpy(name, rc_scd_type_list[value]);
	return (name);
};

enum rsbac_rc_scd_type_t get_rc_scd_type_nr(const char *name)
{
	enum rsbac_rc_scd_type_t i;

	if (!name)
		return (RC_none);
	for (i = 0; i < RC_none - RST_min; i++) {
		if (!strcmp(name, rc_scd_type_list[i])) {
			return (i + RST_min);
		}
	}
	return (get_scd_type_nr(name));
};

char *get_rc_item_name(char *name, enum rsbac_rc_item_t value)
{
	if (!name)
		return (NULL);
	if (value > RI_none)
		strcpy(name, "ERROR!");
	else
		strcpy(name, rc_item_list[value]);
	return (name);
};

enum rsbac_rc_item_t get_rc_item_nr(const char *name)
{
	enum rsbac_rc_item_t i;

	if (!name)
		return (RI_none);
	for (i = 0; i < RI_none; i++) {
		if (!strcmp(name, rc_item_list[i])) {
			return (i);
		}
	}
	return (RI_none);
};

#ifndef __KERNEL__
char *get_rc_item_param(char *name, enum rsbac_rc_item_t value)
{
	if (!name)
		return (NULL);
	if (value > RI_none)
		strcpy(name, "ERROR!");
	else
		strcpy(name, rc_item_param_list[value]);
	return (name);
};
#endif

char *get_rc_special_right_name(char *name,
				enum rsbac_rc_special_rights_t value)
{
	if (!name)
		return (NULL);
	if (value < RSBAC_RC_SPECIAL_RIGHT_BASE) {
		return (get_request_name(name, value));
	}
	value -= RSBAC_RC_SPECIAL_RIGHT_BASE;
	if (value > RCR_NONE) {
		strcpy(name, "ERROR!");
		return (name);
	}
	strcpy(name, rc_special_right_list[value]);
	return (name);
};

#ifndef __KERNEL__
enum rsbac_rc_special_rights_t get_rc_special_right_nr(const char *name)
{
	enum rsbac_rc_special_rights_t i;

	if (!name)
		return (RCR_NONE);
	for (i = 0; i < (RCR_NONE - RSBAC_RC_SPECIAL_RIGHT_BASE); i++) {
		if (!strcmp(name, rc_special_right_list[i])) {
			return (i + RSBAC_RC_SPECIAL_RIGHT_BASE);
		}
	}
	return (get_request_nr(name));
}
#endif
