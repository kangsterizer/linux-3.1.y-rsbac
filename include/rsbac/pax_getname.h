/********************************** */
/* Rule Set Based Access Control    */
/* Author and (c) 1999-2004:        */
/*   Amon Ott <ao@rsbac.org>        */
/* Getname functions for CAP module */
/* Last modified: 06/Jan/2004       */
/********************************** */

#ifndef __RSBAC_PAX_GETNAME_H
#define __RSBAC_PAX_GETNAME_H

#include <rsbac/types.h>

char * pax_print_flags(char * string, rsbac_pax_flags_t flags);

#ifndef __KERNEL__
rsbac_pax_flags_t pax_strtoflags(char * string, rsbac_pax_flags_t init_flags);
#endif

#endif
