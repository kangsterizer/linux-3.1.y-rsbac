/*************************************************** */
/* Rule Set Based Access Control                     */
/* Author and (c) 1999-2010: Amon Ott <ao@rsbac.org> */
/* Memory allocation                                 */
/* Last modified: 01/Jul/2010                        */
/*************************************************** */

#ifndef __RSBAC_RKMEM_H
#define __RSBAC_RKMEM_H

#include <linux/init.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/timer.h>

#define RSBAC_MAX_KMALLOC KMALLOC_MAX_SIZE
#define RSBAC_MAX_SLABNAME 32

/* alloc mem spinlock safe with GFP_ATOMIC */
extern void * rsbac_kmalloc (size_t size);
extern void * rsbac_kmalloc_clear (size_t size);

/* alloc outside locks with GFP_KERNEL */
extern void * rsbac_kmalloc_unlocked (size_t size);
extern void * rsbac_kmalloc_clear_unlocked (size_t size);

extern void rsbac_kfree (const void * objp);

/* Separate slabs for RSBAC */

/* name must stay available until after destroy, keep locally */
static inline struct kmem_cache * rsbac_slab_create(
	const char * name,
	size_t size)
{
	return kmem_cache_create(name, size, 0, 0, NULL);
}

/* remember to free up name after calling, if it has been allocated */
static inline void rsbac_slab_destroy(struct kmem_cache * cache)
{
	kmem_cache_destroy(cache);
}

static inline void * rsbac_smalloc(struct kmem_cache * cache)
{
	return kmem_cache_alloc(cache, GFP_ATOMIC);
}

static inline void * rsbac_smalloc_clear(struct kmem_cache * cache)
{
	return kmem_cache_alloc(cache, GFP_ATOMIC | __GFP_ZERO);
}

static inline void * rsbac_smalloc_unlocked(struct kmem_cache * cache)
{
	return kmem_cache_alloc(cache, GFP_KERNEL);
}

static inline void * rsbac_smalloc_clear_unlocked(struct kmem_cache * cache)
{
	return kmem_cache_alloc(cache, GFP_KERNEL | __GFP_ZERO);
}

static inline void rsbac_sfree(struct kmem_cache * cache, void * mem)
{
	if (cache)
		kmem_cache_free(cache, mem);
	else
		kfree(mem);
}

#endif
