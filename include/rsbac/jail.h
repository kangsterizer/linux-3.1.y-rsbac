/************************************ */
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2007:          */
/*   Amon Ott <ao@rsbac.org>          */
/* Global definitions for JAIL module */
/* Last modified: 29/Jan/2007         */
/************************************ */

#ifndef __RSBAC_JAIL_H
#define __RSBAC_JAIL_H

extern rsbac_jail_id_t rsbac_jail_syslog_jail_id;

rsbac_boolean_t rsbac_jail_exists(rsbac_jail_id_t jail_id);

#endif
