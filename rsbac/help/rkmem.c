/*************************************************** */
/* Rule Set Based Access Control                     */
/* Author and (c) 1999-2010: Amon Ott <ao@rsbac.org> */
/* (a lot copied from mm/slab.c, with other          */
/*  copyrights)                                      */
/* Memory allocation functions for all parts         */
/* Last modified: 24/Jun/2010                        */
/*************************************************** */

#include <rsbac/types.h>
#include <rsbac/rkmem.h>
#include <rsbac/debug.h>
#include <rsbac/aci.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/timer.h>

/**
 * rsbac_kmalloc - allocate memory
 * @size: how many bytes of memory are required.
 *
 * rsbac_kmalloc is the normal method of allocating memory for RSBAC
 * in the kernel. It will always be of type GFP_KERNEL in 2.4 and
 * GFP_ATOMIC in 2.6.
 *
 * rsbac_kmalloc'd memory is freed by rsbac_kfree
 */
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_kmalloc);
#endif
void * rsbac_kmalloc (size_t size)
{
        if(!size)
          return NULL;

	return kmalloc(size, GFP_ATOMIC);
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_kmalloc_unlocked);
#endif
void * rsbac_kmalloc_unlocked (size_t size)
{
        if(!size)
          return NULL;

	return kmalloc(size, GFP_KERNEL);
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_kmalloc_clear);
#endif
void * rsbac_kmalloc_clear (size_t size)
{
        if(!size)
          return NULL;

	return kmalloc(size, GFP_ATOMIC | __GFP_ZERO);
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_kmalloc_clear_unlocked);
#endif
void * rsbac_kmalloc_clear_unlocked (size_t size)
{
        if(!size)
          return NULL;

	return kmalloc(size, GFP_KERNEL | __GFP_ZERO);
}

void rsbac_kfree (const void *objp)
{
	kfree(objp);
}
