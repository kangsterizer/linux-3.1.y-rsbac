/********************************** */
/* Rule Set Based Access Control    */
/* Author and (c) 2002:             */
/*   Amon Ott <ao@rsbac.org>        */
/* Getname functions for RES module */
/* Last modified: 22/Nov/2002       */
/********************************** */

#ifndef __KERNEL__

#include <rsbac/getname.h>
#include <rsbac/res_getname.h>
#include <rsbac/helpers.h>
#include <rsbac/error.h>

#include <string.h>

static char  res_list[RSBAC_RES_MAX+2][8] = {
   "cpu",
   "fsize",
   "data",
   "stack",
   "core",
   "rss",
   "nproc",
   "nofile",
   "memlock",
   "as",
   "locks",
   "NONE" };

/*****************************************/

char * get_res_name(char * name,
                    u_int value)
  {
    if(!name)
      return(NULL);
    if(value > RSBAC_RES_MAX)
      strcpy(name, "ERROR!");
    else
      strcpy(name, res_list[value]);
    return(name);
  };

int get_res_nr(const char * name)
  {
    int i;
    
    if(!name)
      return(RSBAC_RES_NONE);
    for (i = 0; i <= RSBAC_RES_MAX; i++)
      {
        if (!strcmp(name, res_list[i]))
          {
            return(i);
          }
      }
    return(RSBAC_RES_NONE);
  };

#endif /* !__KERNEL__ */
