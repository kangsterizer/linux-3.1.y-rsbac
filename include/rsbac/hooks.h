/******************************* */
/* Rule Set Based Access Control */
/* Author and (c) 1999-2006:     */
/*   Amon Ott <ao@rsbac.org>     */
/* Common include file set       */
/* Last modified: 31/Mar/2006    */
/******************************* */

#ifndef __RSBAC_HOOKS_H
#define __RSBAC_HOOKS_H

#ifdef CONFIG_RSBAC
#include <rsbac/adf.h>
#include <rsbac/aci.h>
#include <rsbac/helpers.h>
#include <rsbac/fs.h>
#include <rsbac/debug.h>
//#include <rsbac/aci_data_structures.h>
//#include <rsbac/adf_main.h>
#else
#define rsbac_kthreads_init() do {} while(0)
#endif

#endif
