/*************************************************** */
/* Rule Set Based Access Control                     */
/* Author and (c) 1999-2005: Amon Ott <ao@rsbac.org> */
/* Generic lists - internal structures               */
/* Last modified: 04/Apr/2005                        */
/*************************************************** */

#ifndef __RSBAC_REPL_TYPES_H
#define __RSBAC_REPL_TYPES_H

#include <rsbac/types.h>

#define RSBAC_LIST_REPL_NAME_LEN 16
#define RSBAC_LIST_REPL_CRYPTKEY_LEN 256
#define RSBAC_LIST_REPL_CRYPTALGO_LEN 64

typedef __u32 rsbac_list_repl_partner_number_t;

struct rsbac_list_repl_partner_entry_t
  {
    char          name[RSBAC_LIST_REPL_NAME_LEN];
    __u32         ip_addr;
    char          crypt_algo[RSBAC_LIST_REPL_CRYPTALGO_LEN];
    char          crypt_key[RSBAC_LIST_REPL_CRYPTKEY_LEN];
    __u32         crypt_key_len;
  };

#endif
