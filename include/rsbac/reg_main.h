/************************************ */
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2005: Amon Ott */
/* REG - Module Registration          */
/* Internal declarations and types    */
/* Last modified: 22/Jul/2005         */
/************************************ */

#ifndef __RSBAC_REG_MAIN_H
#define __RSBAC_REG_MAIN_H

#include <rsbac/types.h>
#include <rsbac/debug.h>
#include <rsbac/reg.h>

#define RSBAC_REG_PROC_NAME "reg_entries"

/***************************************************/
/*                   Types                         */
/***************************************************/

#ifdef __KERNEL__

/* Since all registrations will be organized in double linked lists, we must  */
/* have list items and a list head.                                        */

struct rsbac_reg_list_item_t
    {
      struct rsbac_reg_entry_t       entry;
      struct rsbac_reg_list_item_t * prev;
      struct rsbac_reg_list_item_t * next;
    };
    
struct rsbac_reg_sc_list_item_t
    {
      struct rsbac_reg_syscall_entry_t  entry;
      struct rsbac_reg_sc_list_item_t * prev;
      struct rsbac_reg_sc_list_item_t * next;
    };
    
/* To provide consistency we use spinlocks for all list accesses. The     */
/* 'curr' entry is used to avoid repeated lookups for the same item.       */    
    
struct rsbac_reg_list_head_t
    {
      struct rsbac_reg_list_item_t * head;
      struct rsbac_reg_list_item_t * tail;
      struct rsbac_reg_list_item_t * curr;
      spinlock_t                     lock;
      int                            readers;
      u_int                          count;
    };

struct rsbac_reg_sc_list_head_t
    {
      struct rsbac_reg_sc_list_item_t * head;
      struct rsbac_reg_sc_list_item_t * tail;
      struct rsbac_reg_sc_list_item_t * curr;
      spinlock_t                        lock;
      int                               readers;
      u_int                             count;
    };

#endif /* __KERNEL__ */

/***************************************************/
/*                   Prototypes                    */
/***************************************************/

#endif
