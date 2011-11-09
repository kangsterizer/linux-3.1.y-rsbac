/************************************ */
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2004: Amon Ott */
/* API:                               */
/* Functions for Access               */
/* Control Information / PAX          */
/* Last modified: 12/Jan/2004         */
/************************************ */

#ifndef __RSBAC_PAX_H
#define __RSBAC_PAX_H

#include <rsbac/types.h>

/***************************************************/
/*               General Prototypes                */
/***************************************************/

void rsbac_pax_set_flags_func(struct linux_binprm * bprm);

#endif
