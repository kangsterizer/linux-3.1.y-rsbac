/********************************** */
/* Rule Set Based Access Control    */
/* Author and (c) 1999-2004:        */
/*   Amon Ott <ao@rsbac.org>        */
/* Getname functions for PAX module */
/* Last modified: 06/Jan/2004       */
/********************************** */

#include <rsbac/types.h>
#include <rsbac/pax_getname.h>
#include <rsbac/helpers.h>
#include <rsbac/error.h>

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <stdio.h>
#include <string.h>
#endif

char * pax_print_flags(char * string, rsbac_pax_flags_t flags)
  {
    sprintf(string, "%c%c%c%c%c%c",
           flags & PF_PAX_PAGEEXEC ? 'P' : 'p',
           flags & PF_PAX_EMUTRAMP ? 'E' : 'e',
           flags & PF_PAX_MPROTECT ? 'M' : 'm',
           flags & PF_PAX_RANDMMAP ? 'R' : 'r',
           flags & PF_PAX_RANDEXEC ? 'X' : 'x',
           flags & PF_PAX_SEGMEXEC ? 'S' : 's');
    return string;
  }

#ifndef __KERNEL__
rsbac_pax_flags_t pax_strtoflags(char * string, rsbac_pax_flags_t init_flags)
  {
    char * p = string;
    rsbac_pax_flags_t add_flags = 0;
    rsbac_pax_flags_t remove_flags = 0;

    if(!p)
      return init_flags;
    while(*p)
      {
        switch(*p)
          {
              case 'P':
                add_flags |= PF_PAX_PAGEEXEC;
                break;
              case 'p':
                remove_flags |= PF_PAX_PAGEEXEC;
                break;
              case 'E':
                add_flags |= PF_PAX_EMUTRAMP;
                break;
              case 'e':
                remove_flags |= PF_PAX_EMUTRAMP;
                break;
              case 'M':
                add_flags |= PF_PAX_MPROTECT;
                break;
              case 'm':
                remove_flags |= PF_PAX_MPROTECT;
                break;
              case 'R':
                add_flags |= PF_PAX_RANDMMAP;
                break;
              case 'r':
                remove_flags |= PF_PAX_RANDMMAP;
                break;
              case 'X':
                add_flags |= PF_PAX_RANDEXEC;
                break;
              case 'x':
                remove_flags |= PF_PAX_RANDEXEC;
                break;
              case 'S':
                add_flags |= PF_PAX_SEGMEXEC;
                break;
              case 's':
                remove_flags |= PF_PAX_SEGMEXEC;
                break;
              case 'z':
                remove_flags = RSBAC_PAX_ALL_FLAGS;
                break;
              case 'a':
                add_flags = RSBAC_PAX_ALL_FLAGS;
                break;
            default:
              break;
          }
        p++;
      }
    return (init_flags | add_flags) & ~remove_flags;
  }
#endif
