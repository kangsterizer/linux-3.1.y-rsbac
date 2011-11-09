/************************************ */
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2005: Amon Ott */
/* API:                               */
/* Functions for Access               */
/* Control Information / DAZ          */
/* Last modified: 18/Jan/2005         */
/************************************ */

#ifndef __RSBAC_DAZ_H
#define __RSBAC_DAZ_H

#include <rsbac/types.h>

/* Get ttl for new cache items in seconds */
/* This function returns 0, if no cache is available, and the ttl value
   otherwise */
rsbac_time_t rsbac_daz_get_ttl(void);

/* Set ttl for new cache items in seconds */
/* ttl must be positive, values bigger than 10 years in seconds
   (RSBAC_LIST_MAX_AGE_LIMIT in lists.h) are reduced to this limit */
void rsbac_daz_set_ttl(rsbac_time_t ttl);

/* Flush DAZuko cache lists */
int rsbac_daz_flush_cache(void);
#endif
