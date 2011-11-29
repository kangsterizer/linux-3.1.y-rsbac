/* DazukoXP. Allow cross platform file access control for 3rd-party applications.
   Written by John Ogness <jogness@antivir.de>

   Copyright (c) 2002, 2003, 2004 H+BEDV Datentechnik GmbH
   Copyright (c) 2004-2011 Amon Ott <ao@rsbac.org>
   
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   3. Neither the name of Dazuko nor the names of its contributors may be used
   to endorse or promote products derived from this software without specific
   prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.
*/

#include <rsbac/types.h>
#include <rsbac/debug.h>

#include "dazuko_platform.h"

#include "dazuko_xp.h"
#include "dazukoio.h"

#include "dazuko_call.h"

#define NUM_SLOT_LISTS	5
#define NUM_SLOTS	25

#define	SCAN_ON_OPEN		(access_mask & DAZUKO_ON_OPEN)
#define	SCAN_ON_CLOSE		(access_mask & DAZUKO_ON_CLOSE)
#define	SCAN_ON_EXEC		(access_mask & DAZUKO_ON_EXEC)
#define	SCAN_ON_CLOSE_MODIFIED	(access_mask & DAZUKO_ON_CLOSE_MODIFIED)

struct dazuko_path
{
	/* A node in a linked list of paths. Used
	 * for the include and exclude lists. */

	struct dazuko_path	*next;
	int		len;
	char		path[1];	/* this MUST be at the end of the struct */
};

struct hash
{
	/* A node in a linked list of filenames.
	 * Used for the list of files to be
	 * scanned on close. */

	struct hash	*next;
	struct xp_file	file;
	int		dirty;
	int		namelen;
	char		name[1];	/* this MUST be at the end of the struct */
};

struct daemon_id
{
	int			unique;
	struct xp_daemon_id	*xp_id;
};

struct slot
{
	/* A representation of a daemon. It holds
	 * all information about the daemon, the
	 * file that is scanned, and the state of
	 * the scanning process. */

	int			id;		
	struct daemon_id	did;		/* identifier for our daemon */
	int			write_mode;
	int			state;
	int			response;
	int			event;
	int			filenamelength;	/* not including terminator */
	char			*filename;
	struct event_properties	event_p;
	struct file_properties	file_p;
	struct xp_mutex		mutex;
};

struct slot_list
{
	struct xp_atomic	use_count;
	struct slot		slots[NUM_SLOTS];
	char			reg_name[1];	/* this MUST be at the end of the struct */
};

struct slot_list_container
{
	struct slot_list	*slot_list;
	struct xp_mutex		mutex;
};

struct one_slot_state_not_condition_param
{
	struct slot	*slot;
	int		state;
};

struct two_slot_state_not_condition_param
{
	struct slot	*slot1;
	int		state1;
	struct slot	*slot2;
	int		state2;
};

struct get_ready_slot_condition_param
{
	struct slot		*slot;
	struct slot_list	*slotlist;
};

static int				unique_count = 1;
static char				access_mask = 7;
static struct slot_list_container	slot_lists[NUM_SLOT_LISTS];
static struct dazuko_path			*incl_paths = NULL;
static struct dazuko_path			*excl_paths = NULL;
static struct hash			*hash = NULL;
static struct xp_rwlock			lock_hash;
static struct xp_rwlock			lock_lists;
static struct xp_atomic			active;
static struct xp_mutex			mutex_unique_count;

static struct xp_queue			wait_kernel_waiting_for_free_slot;
static struct xp_queue			wait_daemon_waiting_for_work;
static struct xp_queue			wait_kernel_waiting_while_daemon_works;
static struct xp_queue			wait_daemon_waiting_for_free;

#ifdef CONFIG_RSBAC_DAZ_SELECT
static struct kmem_cache * dazuko_file_listnode_slab = NULL;
#endif
static struct kmem_cache * dazuko_request_slab = NULL;
static struct kmem_cache * access_compat12_slab = NULL;

int dazuko_vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
	char		*target;
	const char	*end;
	int		overflow = 0;
	char		number_buffer[32]; /* 32 should be enough to hold any number, right? */
	const char	*s;

	if (str == NULL || size < 1 || format == NULL)
		return -1;

	target = str;
	end = (target + size) - 1;

#define DAZUKO_VSNPRINTF_PRINTSTRING \
	for ( ; *s ; s++) \
	{ \
		if (target == end) \
		{ \
			overflow = 1; \
			goto dazuko_vsnprintf_out; \
		} \
		*target = *s; \
		target++; \
	}

	for ( ; *format ; format++)
	{
		if (target == end)
		{
			overflow = 1;
			goto dazuko_vsnprintf_out;
		}

		if (*format == '%')
		{
			format++;

			switch (*format)
			{
				case 's': /* %s */
					s = va_arg(ap, char *);
					if (s == NULL)
						s = "(null)";
					DAZUKO_VSNPRINTF_PRINTSTRING
					break;

				case 'd': /* %d */
					sprintf(number_buffer, "%d", va_arg(ap, int));
					s = number_buffer;
					DAZUKO_VSNPRINTF_PRINTSTRING
					break;

				case 'c': /* %c */
					*target = va_arg(ap, int);
					target++;
					break;

				case 'l': /* %lu */
					format++;
					if (*format != 'u')
					{
						/* print error message */
						goto dazuko_vsnprintf_out;
					}
					sprintf(number_buffer, "%lu", va_arg(ap, unsigned long));
					s = number_buffer;
					DAZUKO_VSNPRINTF_PRINTSTRING
					break;

				case '0': /* %02x */
					format++;
					if (*format != '2')
					{
						/* print error message */
						goto dazuko_vsnprintf_out;
					}
					format++;
					if (*format != 'x')
					{
						/* print error message */
						goto dazuko_vsnprintf_out;
					}
					sprintf(number_buffer, "%02x", va_arg(ap, int));
					s = number_buffer;
					DAZUKO_VSNPRINTF_PRINTSTRING
					break;

				default:
					/* print error message */
					goto dazuko_vsnprintf_out;
			}
		}
		else
		{
			*target = *format;
			target++;
		}
	}

dazuko_vsnprintf_out:

	*target = 0;

	/* We are returning what we've written. If there was an
	 * overflow, the returned value will match "size" rather
	 * than being less than "size"
	 */

	return ((target - str) + overflow);
}

int dazuko_snprintf(char *str, size_t size, const char *format, ...)
{
	va_list	ap;
	int	ret;

	va_start(ap, format);
	ret = dazuko_vsnprintf(str, size, format, ap);
	va_end(ap);

	return ret;
}

inline void dazuko_bzero(void *p, int len)
{
	/* "zero out" len bytes starting with p */

	char	*ptr = (char *)p;

	while (len--)
		*ptr++ = 0;
}

static inline int dazuko_get_new_unique(void)
{
	int	unique;

/* DOWN */
	call_xp_down(&mutex_unique_count);

	unique = unique_count;
	unique_count++;

	call_xp_up(&mutex_unique_count);
/* UP */

	return unique;
}

static inline int dazuko_slot_state(struct slot *s)
{
	int state;

/* DOWN */
	if (call_xp_down(&(s->mutex)) != 0)
		return XP_ERROR_INTERRUPT;

	state = s->state;

	call_xp_up(&(s->mutex));
/* UP */

	return state;
}

static int one_slot_state_not_condition(void *param)
{
	return (dazuko_slot_state(((struct one_slot_state_not_condition_param *)param)->slot)
		!= ((struct one_slot_state_not_condition_param *)param)->state);
}

static int two_slot_state_not_condition(void *param)
{
	return (dazuko_slot_state(((struct two_slot_state_not_condition_param *)param)->slot1)
		!= ((struct two_slot_state_not_condition_param *)param)->state1
		&& dazuko_slot_state(((struct two_slot_state_not_condition_param *)param)->slot2)
		!= ((struct two_slot_state_not_condition_param *)param)->state2);
}

static inline int __dazuko_change_slot_state(struct slot *s, int from_state, int to_state)
{
	/* Make a predicted state transition. We fail if it
	 * is an unpredicted change. We can ALWAYS go to the
	 * to_state if it is the same as from_state. Not SMP safe! */

	if (to_state != from_state)
	{
		/* make sure this is a predicted transition and there
		 * is a daemon on this slot (unique != 0)*/
		if (s->state != from_state || s->did.unique == 0)
			return 0;
	}

	s->state = to_state;

	/* handle appropriate wake_up's for basic
	 * state changes */

	if (to_state == DAZUKO_READY)
	{
		call_xp_notify(&wait_kernel_waiting_for_free_slot);
	}
	else if (to_state == DAZUKO_FREE)
	{
		call_xp_notify(&wait_kernel_waiting_while_daemon_works);
		call_xp_notify(&wait_daemon_waiting_for_free);
	}

	return 1;
}

static int dazuko_change_slot_state(struct slot *s, int from_state, int to_state, int release)
{
	/* SMP safe version of __dazuko_change_slot_state().
	 * This should only be used if we haven't
	 * already aquired slot.mutex. Use this function
	 * with CAUTION, since the mutex may or may not
	 * be released depending on the return value AND
	 * on the value of the "release" argument. */

	int	success;

	/* if we are interrupted, report the state as unpredicted */
/* DOWN */
	if (call_xp_down(&(s->mutex)) != 0)
		return 0;

	success = __dazuko_change_slot_state(s, from_state, to_state);

	/* the mutex is released if the state change was
	 * unpredicted or if the called wants it released */
	if (!success || release)
		call_xp_up(&(s->mutex));
/* UP */
	return success;
}

static struct slot * _dazuko_find_slot(struct daemon_id *did, int release, struct slot_list *sl)
{
	/* Find the first slot with the same given
	 * pid number. SMP safe. Use this function
	 * with CAUTION, since the mutex may or may not
	 * be released depending on the return value AND
	 * on the value of the "release" argument. */

	int	i;
	struct slot	*s = NULL;

	if (sl == NULL)
	{
		rsbac_printk(KERN_WARNING "dazuko: invalid slot_list given (bug!)\n");
		return NULL;
	}

	for (i=0 ; i<NUM_SLOTS ; i++)
	{
		s = &(sl->slots[i]);
/* DOWN */
		/* if we are interrupted, we say that no
 		 * slot was found */
		if (call_xp_down(&(s->mutex)) != 0)
			return NULL;

		if (did == NULL)
		{
			/* we are looking for an empty slot */
			if (s->did.unique == 0 && s->did.xp_id == NULL)
			{
				/* we release the mutex only if the
	 			* called wanted us to */
				if (release)
					call_xp_up(&(s->mutex));
/* UP */
				return s;
			}
		}
		else if (s->did.unique == 0 && s->did.xp_id == NULL)
		{
			/* this slot is emtpy, so it can't match */

			/* do nothing */
		}
		/* xp_id's must match! */
		else if (call_xp_id_compare(s->did.xp_id, did->xp_id) == 0)
		{
			/* unique's must also match (unless unique is negative,
			 * in which case we will trust xp_id) */
			if (did->unique < 0 || (s->did.unique == did->unique))
			{
				/* we release the mutex only if the
				 * called wanted us to */
				if (release)
					call_xp_up(&(s->mutex));
/* UP */
				return s;
			}
		}

		call_xp_up(&(s->mutex));
/* UP */
	}

	return NULL;
}

static struct slot * dazuko_find_slot_and_slotlist(struct daemon_id *did, int release, struct slot_list *slist, struct slot_list **sl_result)
{
	struct slot		*s;
	int		i;
	struct slot_list	*sl;

	if (slist == NULL)
	{
		for (i=0 ; i<NUM_SLOT_LISTS ; i++)
		{
/* DOWN */
			/* if we are interrupted, we say that no
 			* slot was found */
			if (call_xp_down(&(slot_lists[i].mutex)) != 0)
				return NULL;

			sl = slot_lists[i].slot_list;

			call_xp_up(&(slot_lists[i].mutex));
/* UP */

			if (sl != NULL)
			{
				s = _dazuko_find_slot(did, release, sl);
				if (s != NULL)
				{
					/* set the current slot_list */
					if (sl_result != NULL)
						*sl_result = sl;

					return s;
				}
			}
		}
	}
	else
	{
		return _dazuko_find_slot(did, release, slist);
	}

	return NULL;
}

static inline struct slot * dazuko_find_slot(struct daemon_id *did, int release, struct slot_list *slist)
{
	return dazuko_find_slot_and_slotlist(did, release, slist, NULL);
}

static int dazuko_insert_path_fs(struct dazuko_path **list, char *fs_path, int fs_len)
{
	/* Create a new struct dazuko_path structure and insert it
	 * into the linked list given (list argument).
	 * The fs_len argument is to help speed things
	 * up so we don't have to calculate the length
	 * of fs_path. */

	struct dazuko_path	*newitem;
	struct dazuko_path	*tmp;

	if (fs_path == NULL || fs_len < 1)
		return XP_ERROR_INVALID;

	/* we want only absolute paths */
	if (!call_xp_is_absolute_path(fs_path))
		return XP_ERROR_INVALID;

	/* create a new struct dazuko_path structure making room for path also */
	newitem = rsbac_kmalloc(sizeof(struct dazuko_path) + fs_len + 1);
	if (newitem == NULL)
		return XP_ERROR_FAULT;

	/* fs_path is already in kernelspace */
	memcpy(newitem->path, fs_path, fs_len);

	newitem->path[fs_len] = 0;

	while (newitem->path[fs_len-1] == 0)
	{
		fs_len--;
		if (fs_len == 0)
			break;
	}

	if (fs_len < 1)
	{
		rsbac_kfree(newitem);
		return XP_ERROR_INVALID;
	}

	newitem->len = fs_len;

	/* check if this path already exists in the list */
	for (tmp=*list ; tmp ; tmp=tmp->next)
	{
		if (newitem->len == tmp->len)
		{
			if (memcmp(newitem->path, tmp->path, tmp->len) == 0)
			{
				/* we already have this path */

				rsbac_kfree(newitem);

				return 0;
			}
		}
	}

	DPRINT(("dazuko: adding %s %s\n", (list == &incl_paths) ? "incl" : "excl", newitem->path));

	/* add struct dazuko_path to head of linked list */
/* LOCK */
	call_xp_write_lock(&lock_lists);
	newitem->next = *list;
	*list = newitem;
	call_xp_write_unlock(&lock_lists);
/* UNLOCK */

	return 0;
}

static void dazuko_remove_all_hash(void)
{
	/* Empty the hash linked list. */

	struct hash	*tmp;

/* LOCK */
	call_xp_write_lock(&lock_hash);
	while (hash)
	{
		tmp = hash;
		hash = hash->next;

		DPRINT(("dazuko: removing hash %s\n", tmp->name));

		rsbac_kfree(tmp);
	}
	call_xp_write_unlock(&lock_hash);
/* UNLOCK */
}

static void dazuko_remove_all_paths(void)
{
	/* Empty both include and exclude struct dazuko_path
	 * linked lists. */

	struct dazuko_path	*tmp;

/* LOCK */
	call_xp_write_lock(&lock_lists);

	/* empty include paths list */
	while (incl_paths)
	{
		tmp = incl_paths;
		incl_paths = incl_paths->next;

		DPRINT(("dazuko: removing incl %s\n", tmp->path));

		rsbac_kfree(tmp);
	}

	/* empty exclude paths list */
	while (excl_paths)
	{
		tmp = excl_paths;
		excl_paths = excl_paths->next;

		DPRINT(("dazuko: removing excl %s\n", tmp->path));

		rsbac_kfree(tmp);
	}

	call_xp_write_unlock(&lock_lists);
/* UNLOCK */
}

static int _dazuko_unregister_daemon(struct daemon_id *did)
{
	/* We unregister the daemon by finding the
	 * slot with the same slot->pid as the the
	 * current process id, the daemon. */

	struct slot		*s;
	struct slot_list	*sl;

	DPRINT(("dazuko: dazuko_unregister_daemon() [%d]\n", did->unique));

	/* find our slot and hold the mutex
	 * if we find it */
/* DOWN? */
	s = dazuko_find_slot_and_slotlist(did, 0, NULL, &sl);

	if (s == NULL)
	{
		/* this daemon was not registered */
		return 0;
	}

/* DOWN */

	/* clearing the unique and pid makes the slot available */
	s->did.unique = 0;
	call_xp_id_free(s->did.xp_id);
	s->did.xp_id = NULL;

	/* reset slot state */
	__dazuko_change_slot_state(s, DAZUKO_FREE, DAZUKO_FREE);

	call_xp_atomic_dec(&(sl->use_count));

	call_xp_up(&(s->mutex));
/* UP */

	/* active should always be positive here, but
	 * let's check just to be sure. ;) */
	if (call_xp_atomic_read(&active) > 0)
	{
		/* active and the kernel usage counter
		 * should always reflect how many daemons
		 * are active */

		call_xp_atomic_dec(&active);
	}
	else
	{
		rsbac_printk(KERN_WARNING "dazuko: active count error (possible bug)\n");
	}

	/* Wake up any kernel processes that are
	 * waiting for an available slot. Remove
	 * all the include and exclude paths
	 * if there are no more daemons */

	if (call_xp_atomic_read(&active) == 0)
	{
		/* clear out include and exclude paths */
		/* are we sure we want to do this? */
		dazuko_remove_all_paths();

		/* clear out hash nodes */
		dazuko_remove_all_hash();
	}

	call_xp_notify(&wait_kernel_waiting_for_free_slot);
	call_xp_notify(&wait_kernel_waiting_while_daemon_works);

	return 0;
}

int dazuko_unregister_daemon(struct xp_daemon_id *xp_id)
{
	struct daemon_id	did;
	int			ret;

	if (xp_id == NULL)
		return 0;

	did.unique = -1;
	did.xp_id = call_xp_id_copy(xp_id);

	ret = _dazuko_unregister_daemon(&did);

	call_xp_id_free(did.xp_id);

	return ret;
}

static inline int dazuko_state_error(struct slot *s, int current_state)
{
	if (dazuko_change_slot_state(s, current_state, DAZUKO_BROKEN, 1))
	{
		call_xp_notify(&wait_kernel_waiting_for_free_slot);
		call_xp_notify(&wait_kernel_waiting_while_daemon_works);
	}

	return 0;
}

static int dazuko_register_daemon(struct daemon_id *did, const char *reg_name, int string_length, int write_mode)
{
	const char	*p1;
	char		*p2;
	struct slot		*s;
	struct slot_list	*sl;
	int		i;

	rsbac_pr_debug(adf_daz, "Registering daemon %s [%d]\n", reg_name, did->unique);

	if (did == NULL || reg_name == NULL)
		return XP_ERROR_PERMISSION;

	s = dazuko_find_slot(did, 1, NULL);

	if (s != NULL)
	{
		/* We are already registered! */

		rsbac_printk(KERN_INFO "dazuko: daemon %d already assigned to slot[%d]\n", did->unique, s->id);

		return XP_ERROR_PERMISSION;
	}

	/* Find the slot_list with the matching name. */

	for (i=0 ; i<NUM_SLOT_LISTS ; i++)
	{
/* DOWN */
		/* if we are interrupted, we say that it
 		* was interrupted */
		if (call_xp_down(&(slot_lists[i].mutex)) != 0)
			return XP_ERROR_INTERRUPT;

		sl = slot_lists[i].slot_list;

		call_xp_up(&(slot_lists[i].mutex));
/* UP */

		if (sl != NULL)
		{
			p1 = reg_name;
			p2 = sl->reg_name;

			while (*p1 == *p2)
			{
				if (*p1 == 0)
					break;

				p1++;
				p2++;
			}

			if (*p1 == *p2)
				break;
		}
	}

	if (i == NUM_SLOT_LISTS)
	{
		/* There is no slot_list with this name. We
		 * need to make one. */

		sl = rsbac_kmalloc_clear_unlocked(sizeof(struct slot_list) + string_length + 1);
		if (sl == NULL)
			return XP_ERROR_FAULT;

		call_xp_atomic_set(&(sl->use_count), 0);

		p1 = reg_name;
		p2 = sl->reg_name;

		while (*p1)
		{
			*p2 = *p1;

			p1++;
			p2++;
		}
		*p2 = 0;

		/* give each slot a unique id */
		for (i=0 ; i<NUM_SLOTS ; i++)
		{
			sl->slots[i].id = i;
			call_xp_init_mutex(&(sl->slots[i].mutex));
		}

		/* we need to find an empty slot */
		for (i=0 ; i<NUM_SLOT_LISTS ; i++)
		{
/* DOWN */
			/* if we are interrupted, we need to cleanup
 			* and return error */
			if (call_xp_down(&(slot_lists[i].mutex)) != 0)
			{
				rsbac_kfree(sl);
				return XP_ERROR_INTERRUPT;
			}

			if (slot_lists[i].slot_list == NULL)
			{
				slot_lists[i].slot_list = sl;

				call_xp_up(&(slot_lists[i].mutex));
/* UP */
				break;
			}

			call_xp_up(&(slot_lists[i].mutex));
/* UP */
		}

		if (i == NUM_SLOT_LISTS)
		{
			/* no empty slot :( */
			rsbac_kfree(sl);
			return XP_ERROR_BUSY;
		}
	}

	/* find an available slot and hold the mutex
	 * if we find one */
/* DOWN? */
	s = dazuko_find_slot(NULL, 0, sl);

	if (s == NULL)
		return XP_ERROR_BUSY;

/* DOWN */

	/* We have found a slot, so increment the active
	 * variable and the kernel module use counter.
	 * The module counter will always reflect the
	 * number of daemons. */

	call_xp_atomic_inc(&active);

	/* get new unique id for this process */
	did->unique = dazuko_get_new_unique();

	s->did.unique = did->unique;
	s->did.xp_id = call_xp_id_copy(did->xp_id);
	s->write_mode = write_mode;

	call_xp_atomic_inc(&(sl->use_count));

	/* the daemon is registered, but not yet
	 * ready to receive files */
	__dazuko_change_slot_state(s, DAZUKO_FREE, DAZUKO_FREE);
	rsbac_pr_debug(adf_daz, "slot[%d] assigned to daemon %s [%d]", s->id, reg_name, did->unique);
	call_xp_up(&(s->mutex));
/* UP */

	return 0;
}

static struct slot* dazuko_get_an_access(struct daemon_id *did)
{
	/* The daemon is requesting a filename of a file
	 * to scan. This code will wait until a filename
	 * is available, or until we should be killed.
	 * (killing is done if any errors occur as well
	 * as when the user kills us) */

	/* If a slot is returned, it will be already locked! */

	int					i;
	struct slot					*s;
	struct one_slot_state_not_condition_param	cond_p;

tryagain:
	/* find our slot */
	s = dazuko_find_slot(did, 1, NULL);

	if (s == NULL)
	{
		i = dazuko_register_daemon(did, "_COMPAT", 7, 1);
		if (i != 0)
		{
			rsbac_printk(KERN_INFO "dazuko: unregistered daemon %d attempted to get access\n", did->unique);
			return NULL;
		}

		s = dazuko_find_slot(did, 1, NULL);
		if (s == NULL)
		{
			rsbac_printk(KERN_INFO "dazuko: unregistered daemon %d attempted to get access\n", did->unique);
			return NULL;
		}

		rsbac_printk(KERN_INFO "dazuko: warning: daemon %d is using a deprecated protocol\n", did->unique);
	}

	/* the daemon is now ready to receive a file */
	dazuko_change_slot_state(s, DAZUKO_READY, DAZUKO_READY, 1);

	cond_p.slot = s;
	cond_p.state = DAZUKO_READY;
	if (call_xp_wait_until_condition(&wait_daemon_waiting_for_work, one_slot_state_not_condition, &cond_p, 1) != 0)
	{
		/* The user has issued an interrupt.
		 * Return an error. The daemon should
		 * unregister itself. */

		DPRINT(("dazuko: daemon %d killed while waiting for work\n", did->unique));

		if (dazuko_change_slot_state(s, DAZUKO_READY, DAZUKO_BROKEN, 1) || dazuko_change_slot_state(s, DAZUKO_WAITING, DAZUKO_BROKEN, 1))
		{
			call_xp_notify(&wait_kernel_waiting_for_free_slot);
			call_xp_notify(&wait_kernel_waiting_while_daemon_works);
		}

		return NULL;
	}

	/* slot SHOULD now be in DAZUKO_WAITING state */

	/* we will be working with the slot, so
	 * we need to lock it */

/* DOWN? */
	if (!dazuko_change_slot_state(s, DAZUKO_WAITING, DAZUKO_WORKING, 0))
	{
		/* State transition error. Try again., */

		goto tryagain;
	}

/* DOWN */

	/* Slot IS in DAZUKO_WORKING state. Copy all the
	 * necessary information to userspace structure. */

	/* IMPORTANT: slot is still locked! */

	return s;  /* access is available */
}

static int dazuko_return_access(struct daemon_id *did, int response, struct slot *s)
{
	/* The daemon has finished scanning a file
	 * and has the response to give. The daemon's
	 * slot should be in the DAZUKO_WORKING state. */

	struct one_slot_state_not_condition_param	cond_p;

	/* do we already have a slot? */
	if (s == NULL)
	{
		/* find our slot */
		s = dazuko_find_slot(did, 1, NULL);

		if (s == NULL)
		{
			/* It appears the kernel isn't interested
			 * in us or our response. It gave our slot away! */

			DPRINT(("dazuko: daemon %d unexpectedly lost slot\n", did->unique));

			return XP_ERROR_PERMISSION;
		}
	}

	/* we will be writing into the slot, so we
	 * need to lock it */

/* DOWN? */
	if (!dazuko_change_slot_state(s, DAZUKO_WORKING, DAZUKO_DONE, 0))
	{
		/* The slot is in the wrong state. We will
		 * assume the kernel has cancelled the file
		 * access. */

		DPRINT(("dazuko: response from daemon %d on slot[%d] not needed\n", did->unique, s->id));

		return 0;
	}

/* DOWN */

	s->response = response;

	call_xp_up(&(s->mutex));
/* UP */

	/* wake up any kernel processes that are
	 * waiting for responses */
	call_xp_notify(&wait_kernel_waiting_while_daemon_works);

	cond_p.slot = s;
	cond_p.state = DAZUKO_DONE;
	if (call_xp_wait_until_condition(&wait_daemon_waiting_for_free, one_slot_state_not_condition, &cond_p, 1) != 0)
	{
		/* The user has issued an interrupt.
		 * Return an error. The daemon should
		 * unregister itself. */

		DPRINT(("dazuko: daemon %d killed while waiting for response acknowledgement\n", did->unique));

		return XP_ERROR_INTERRUPT;
	}

	return 0;
}

static inline int dazuko_isdigit(const char c)
{
	return (c >= '0' && c <= '9');
}

static inline long dazuko_strtol(const char *string)
{
	long		num = 1;
	const char	*p = string;

	if (string == NULL)
		return 0;

	switch (*p)
	{
		case '-':
			num = -1;
			p++;
			break;

		case '+':
			p++;
			break;
	}

	if (dazuko_isdigit(*p))
	{
		num *= *p - '0';
		p++;
	}
	else
	{
		return 0;
	}

	while (dazuko_isdigit(*p))
	{
		num *= 10;
		num += *p - '0';
		p++;
	}

	return num;
}

static inline int dazuko_strlen(const char *string)
{
	const char	*p;

	if (string == NULL)
		return -1;

	for (p=string ; *p ; p++)
		continue;

	return (p - string);
}

static inline const char* dazuko_strchr(const char *haystack, char needle)
{
	const char	*p;

	if (haystack == NULL)
		return NULL;

	for (p=haystack ; *p ; p++)
	{
		if (*p == needle)
			return p;
	}

	return NULL;
}

static inline const char* dazuko_strstr(const char *haystack, const char *needle)
{
	const char	*p1;
	const char	*p2;
	const char	*p3;

	if (haystack == NULL || needle == NULL)
		return NULL;

	for (p1=haystack ; *p1 ; p1++)
	{
		for (p2=needle,p3=p1 ; *p2&&*p3 ; p2++,p3++)
		{
			if (*p2 != *p3)
				break;
		}

		if (*p2 == 0)
			return p1;
	}

	return NULL;
}

int dazuko_get_value(const char *key, const char *string, char **value)
{
	const char	*p1;
	const char	*p2;
	int		size;

	if (value == NULL)
		return -1;

	*value = NULL;

	if (key == NULL || string == NULL)
		return -1;

	p1 = dazuko_strstr(string, key);
	if (p1 == NULL)
		return -1;

	p1 += dazuko_strlen(key);

	for (p2=p1 ; *p2 && *p2!='\n' ; p2++)
		continue;

	size = (p2 - p1) + 1;
	*value = rsbac_kmalloc_unlocked(size);
	if (*value == NULL)
		return -1;

	memcpy(*value, p1, size - 1);
	(*value)[size - 1] = 0;

	return 0;
}

static inline void dazuko_clear_replybuffer(struct dazuko_request *request)
{
	dazuko_bzero(request->reply_buffer, request->reply_buffer_size);
	request->reply_buffer_size_used = 0;
}

static inline void dazuko_close_replybuffer(struct dazuko_request *request)
{
	request->reply_buffer[request->reply_buffer_size_used] = 0;
	request->reply_buffer_size_used++;
}

static inline void dazuko_add_keyvalue_to_replybuffer(struct dazuko_request *request, const char *key, void *value, char vtype)
{

#define DAZUKO_VSNPRINT(type, name) dazuko_snprintf(request->reply_buffer + request->reply_buffer_size_used, (request->reply_buffer_size - request->reply_buffer_size_used) - 1, "%s%" #type , key, *((name *)value))

	switch (vtype)
	{
		case 'd':
			DAZUKO_VSNPRINT(d, const int);
			break;

		case 's':
			DAZUKO_VSNPRINT(s, const char *);
			break;

		case 'l':
			DAZUKO_VSNPRINT(lu, const unsigned long);
			break;

		default:
			/* all other types treated as chars */
			DAZUKO_VSNPRINT(c, const char);
			break;
	}

	/* update how much buffer we have used */
	request->reply_buffer_size_used += strlen(request->reply_buffer + request->reply_buffer_size_used);
}

static inline int dazuko_printable(char c)
{
	/* hopefully this counts for all operating systems! */

	return ((c >= ' ') && (c <= '~') && (c != '\\'));
}

static inline void dazuko_add_esc_to_replybuffer(struct dazuko_request *request, const char *key, char **filename)
{
	int		found = 0;
	char		*p_rq;
	const char	*limit;
	const char	*p_fn;
	unsigned char	c;

	/* check for escape characters in filename */
	for (p_fn=*filename ; *p_fn ; p_fn++)
	{
		if (!dazuko_printable(*p_fn))
		{
			found = 1;
			break;
		}
	}

	if (found)
	{
		/* this is expensive, but it will also almost never occur */

		p_rq = request->reply_buffer + request->reply_buffer_size_used;
		limit = request->reply_buffer + request->reply_buffer_size - 1;

		dazuko_snprintf(p_rq, limit - p_rq, "%s", key);
		p_rq += strlen(p_rq);

		for (p_fn=*filename ; *p_fn && (p_rq<limit) ; p_fn++)
		{
			if (dazuko_printable(*p_fn))
			{
				*p_rq = *p_fn;
				p_rq++;
			}
			else
			{
				c = *p_fn & 0xFF;
				dazuko_snprintf(p_rq, limit - p_rq, "\\x%02x", c);
				p_rq += strlen(p_rq);
			}
		}

		request->reply_buffer_size_used += strlen(request->reply_buffer + request->reply_buffer_size_used);
	}
	else
	{
		/* no escape characters found */

		dazuko_add_keyvalue_to_replybuffer(request, key, filename, 's');
	}
}

static int dazuko_set_option(struct daemon_id *did, int opt, void *param, int len)
{
	/* The daemon wants to set a configuration
	 * option in the kernel. */

	struct slot	*s;
	int		error;

	/* sanity check */
	if (len < 0 || len > 8192)
		return XP_ERROR_PERMISSION;

	/* make sure we are already registered
	 * (or that we don't register twice) */

	/* find our slot */
	s = dazuko_find_slot(did, 1, NULL);

	switch (opt)
	{
		case REGISTER:
			rsbac_printk(KERN_INFO "dazuko: dazuko_set_option does not support REGISTER (bug!)\n");
			return XP_ERROR_PERMISSION;

		case UNREGISTER:
			if (s == NULL)
			{
				/* We are not registered! */

				return 0;
			}
			break;

		default:
			if (s == NULL)
			{
				error = dazuko_register_daemon(did, "_COMPAT", 7, 1);
				if (error)
				{
					rsbac_printk(KERN_INFO "dazuko: unregistered daemon %d attempted access\n", did->unique);
					return XP_ERROR_PERMISSION;
				}

				s = dazuko_find_slot(did, 1, NULL);
				if (s == NULL)
				{
					rsbac_printk(KERN_INFO "dazuko: unregistered daemon %d attempted access\n", did->unique);
					return XP_ERROR_PERMISSION;
				}

				rsbac_printk(KERN_INFO "dazuko: warning: daemon %d is using a deprecated protocol\n", did->unique);
			}
			break;
	}

	/* check option type and take the appropriate action */
	switch (opt)
	{
		case UNREGISTER:
			error = _dazuko_unregister_daemon(did);
			if (error)
				return error;
			break;

		case SET_ACCESS_MASK:
			memcpy(&access_mask, (char *)param, sizeof(char));
			break;

		case ADD_INCLUDE_PATH:
			error = dazuko_insert_path_fs(&incl_paths, (char *)param, len);
			if (error)
				return error;
			break;

		case ADD_EXCLUDE_PATH:
			error = dazuko_insert_path_fs(&excl_paths, (char *)param, len);
			if (error)
				return error;
			break;

		case REMOVE_ALL_PATHS:
			dazuko_remove_all_paths();
			break;

		default:
			rsbac_printk(KERN_INFO "dazuko: daemon %d requested unknown set %d (possible bug)\n", did->unique, opt);
			break;
	}

	return 0;
}

static int dazuko_handle_request(struct dazuko_request *request, struct xp_daemon_id *xp_id)
{
	char			*value1;
	char			*value2;
	int			error = 0;
	int			type;
	struct slot		*s;
	struct daemon_id	did;

	if (request == NULL || xp_id == NULL)
		return -1;

	type = request->type[0] + (256 * request->type[1]);

	switch (type)
	{
		case REGISTER:
			/* read "\nRM=regmode\nGN=group" */
			/* send "\nID=id" */

			if (request->buffer_size <= 0)
				return -1;

			if (request->reply_buffer_size <= 0)
				return -1;

			if (dazuko_get_value("\nGN=", request->buffer, &value1) != 0)
				return -1;

			if (dazuko_get_value("\nRM=", request->buffer, &value2) != 0)
			{
				rsbac_kfree(value1);
				return -1;
			}

			did.xp_id = call_xp_id_copy(xp_id);
			did.unique = 0; /* a unique is not yet assigned */

			error = dazuko_register_daemon(&did, value1, dazuko_strlen(value1), dazuko_strchr(value2, 'W') != NULL);

			dazuko_clear_replybuffer(request);
			dazuko_add_keyvalue_to_replybuffer(request, "\nID=", &(did.unique), 'd');
			dazuko_close_replybuffer(request);

			rsbac_kfree(value1);
			rsbac_kfree(value2);
			call_xp_id_free(did.xp_id);

			break;

		case UNREGISTER:
			/* read "\nID=id" */

			if (request->buffer_size <= 0)
				return -1;

			if (dazuko_get_value("\nID=", request->buffer, &value1) != 0)
				return -1;

			did.xp_id = call_xp_id_copy(xp_id);
			did.unique = dazuko_strtol(value1);

			error = dazuko_set_option(&did, UNREGISTER, NULL, 0);

			rsbac_kfree(value1);
			call_xp_id_free(did.xp_id);

			break;

		case SET_ACCESS_MASK:
			/* read "\nID=id\nAM=mask" */

			if (request->buffer_size <= 0)
				return -1;

			if (dazuko_get_value("\nID=", request->buffer, &value1) != 0)
				return -1;

			if (dazuko_get_value("\nAM=", request->buffer, &value2) != 0)
			{
				rsbac_kfree(value1);
				return -1;
			}

			access_mask = (char)dazuko_strtol(value2);

			rsbac_kfree(value1);
			rsbac_kfree(value2);

			break;

		case ADD_INCLUDE_PATH:
			/* read "\nID=id\nPT=path" */

			if (request->buffer_size <= 0)
				return -1;

			if (dazuko_get_value("\nID=", request->buffer, &value1) != 0)
				return -1;

			if (dazuko_get_value("\nPT=", request->buffer, &value2) != 0)
			{
				rsbac_kfree(value1);
				return -1;
			}

			did.xp_id = call_xp_id_copy(xp_id);
			did.unique = dazuko_strtol(value1);

			error = dazuko_set_option(&did, ADD_INCLUDE_PATH, value2, dazuko_strlen(value2));

			rsbac_kfree(value1);
			rsbac_kfree(value2);
			call_xp_id_free(did.xp_id);

			break;

		case ADD_EXCLUDE_PATH:
			/* read "\nID=id\nPT=path" */

			if (request->buffer_size <= 0)
				return -1;

			if (dazuko_get_value("\nID=", request->buffer, &value1) != 0)
				return -1;

			if (dazuko_get_value("\nPT=", request->buffer, &value2) != 0)
			{
				rsbac_kfree(value1);
				return -1;
			}

			did.xp_id = call_xp_id_copy(xp_id);
			did.unique = dazuko_strtol(value1);

			error = dazuko_set_option(&did, ADD_EXCLUDE_PATH, value2, dazuko_strlen(value2));

			rsbac_kfree(value1);
			rsbac_kfree(value2);
			call_xp_id_free(did.xp_id);

			break;

		case REMOVE_ALL_PATHS:
			/* read "\nID=id" */

			if (request->buffer_size <= 0)
				return -1;

			if (dazuko_get_value("\nID=", request->buffer, &value1) != 0)
				return -1;

			did.xp_id = call_xp_id_copy(xp_id);
			did.unique = dazuko_strtol(value1);

			error = dazuko_set_option(&did, REMOVE_ALL_PATHS, NULL, 0);

			rsbac_kfree(value1);
			call_xp_id_free(did.xp_id);

			break;

		case GET_AN_ACCESS:
			/* read "\nID=id" */
			/* send "\nFN=file\nFL=flags\nMD=mode\nUI=uid\nPI=pid" */

			if (request->buffer_size <= 0)
				return -1;

			if (request->reply_buffer_size <= 0)
				return -1;

			if (dazuko_get_value("\nID=", request->buffer, &value1) != 0)
				return -1;

			did.xp_id = call_xp_id_copy(xp_id);
			did.unique = dazuko_strtol(value1);

			rsbac_kfree(value1);

/* DOWN? */
			s = dazuko_get_an_access(&did);

			if (s == NULL)
			{
				call_xp_id_free(did.xp_id);
				return XP_ERROR_INTERRUPT;
			}
/* DOWN */

			/* Slot IS in DAZUKO_WORKING state. Copy all the
			 * necessary information to userspace structure. */

			dazuko_clear_replybuffer(request);
			dazuko_add_keyvalue_to_replybuffer(request, "\nEV=", &(s->event), 'd');
			dazuko_add_esc_to_replybuffer(request, "\nFN=", &(s->filename));

			if (s->event_p.set_uid)
				dazuko_add_keyvalue_to_replybuffer(request, "\nUI=", &(s->event_p.uid), 'd');

			if (s->event_p.set_pid)
				dazuko_add_keyvalue_to_replybuffer(request, "\nPI=", &(s->event_p.pid), 'd');

			if (s->event_p.set_flags)
				dazuko_add_keyvalue_to_replybuffer(request, "\nFL=", &(s->event_p.flags), 'd');

			if (s->event_p.set_mode)
				dazuko_add_keyvalue_to_replybuffer(request, "\nMD=", &(s->event_p.mode), 'd');

			if (s->file_p.set_size)
				dazuko_add_keyvalue_to_replybuffer(request, "\nFS=", &(s->file_p.size), 'l');

			if (s->file_p.set_uid)
				dazuko_add_keyvalue_to_replybuffer(request, "\nFU=", &(s->file_p.uid), 'd');

			if (s->file_p.set_gid)
				dazuko_add_keyvalue_to_replybuffer(request, "\nFG=", &(s->file_p.gid), 'd');

			if (s->file_p.set_mode)
				dazuko_add_keyvalue_to_replybuffer(request, "\nFM=", &(s->file_p.mode), 'd');

			if (s->file_p.set_device_type)
				dazuko_add_keyvalue_to_replybuffer(request, "\nDT=", &(s->file_p.device_type), 'd');

			dazuko_close_replybuffer(request);

/* XXX: What do we do if there is a problem copying back to userspace?! */
/* dazuko_state_error(s, DAZUKO_WORKING); */

			/* are we in read_only mode? */
			if (!(s->write_mode))
			{
				/* the access is immediately (and at the kernel level)
				 * returned */

				call_xp_up(&(s->mutex));
/* UP */

				dazuko_return_access(&did, 0, s);
			}
			else
			{
				call_xp_up(&(s->mutex));
/* UP */
			}

			call_xp_id_free(did.xp_id);

			break;

		case RETURN_AN_ACCESS:
			/* read "\nID=id\nDN=deny" */

			if (request->buffer_size <= 0)
				return -1;

			if (dazuko_get_value("\nID=", request->buffer, &value1) != 0)
				return -1;

			if (dazuko_get_value("\nDN=", request->buffer, &value2) != 0)
			{
				rsbac_kfree(value1);
				return -1;
			}

			did.xp_id = call_xp_id_copy(xp_id);
			did.unique = dazuko_strtol(value1);

			error = dazuko_return_access(&did, dazuko_strtol(value2), NULL);

			rsbac_kfree(value1);
			rsbac_kfree(value2);
			call_xp_id_free(did.xp_id);

			break;

		default:
			rsbac_printk(KERN_INFO "dazuko: daemon made unknown request %d (possible bug)\n", type);

			break;
	}

	return error;
}

int dazuko_handle_user_request(struct dazuko_request *user_request, struct xp_daemon_id *xp_id)
{
	int			error = 0;
	struct dazuko_request	*request;
	struct dazuko_request	*temp_request;

	if (user_request == NULL || xp_id == NULL)
		return XP_ERROR_FAULT;

	/* allocate kernel request */
	request = rsbac_smalloc_unlocked(dazuko_request_slab);
	if (request == NULL)
		return XP_ERROR_FAULT;

/* use out0 now */

	/* allocate temp kernel request */
	temp_request = rsbac_smalloc_unlocked(dazuko_request_slab);
	if (temp_request == NULL)
	{
		error = XP_ERROR_FAULT;
		goto dazuko_handle_user_request_out0;
	}

/* use out1 now */

	/* copy in the request */
	if (call_xp_copyin(user_request, temp_request, sizeof(struct dazuko_request)) != 0)
	{
		error = XP_ERROR_FAULT;
		goto dazuko_handle_user_request_out1;
	}

	memcpy(request->type, temp_request->type, sizeof(char[2]));
	request->buffer_size = temp_request->buffer_size;

	/* sanity check */
	if (request->buffer_size < 0 || request->buffer_size > 8192)
	{
		error = XP_ERROR_FAULT;
		goto dazuko_handle_user_request_out1;
	}

	request->reply_buffer_size = temp_request->reply_buffer_size;

	/* sanity check */
	if (request->reply_buffer_size < 0 || request->reply_buffer_size > 8192)
	{
		error = XP_ERROR_PERMISSION;
		goto dazuko_handle_user_request_out1;
	}

	/* allocate buffer */
	request->buffer = rsbac_kmalloc_unlocked(request->buffer_size + 1);
	if (request->buffer == NULL)
	{
		error = XP_ERROR_FAULT;
		goto dazuko_handle_user_request_out1;
	}

/* use out2 now */

	if (request->reply_buffer_size > 0)
	{
		/* allocate reply buffer */
		request->reply_buffer = rsbac_kmalloc_unlocked(request->reply_buffer_size + 1);
		if (request->reply_buffer == NULL)
		{
			error = XP_ERROR_FAULT;
			goto dazuko_handle_user_request_out2;
		}

/* use out3 now */

		request->reply_buffer_size_used = 0;
	}

	/* copy the buffer from userspace to kernelspace */
	if (call_xp_copyin(temp_request->buffer, request->buffer, request->buffer_size) != 0)
	{
		error = XP_ERROR_FAULT;
		goto dazuko_handle_user_request_out3;
	}

	request->buffer[request->buffer_size] = 0;

	error = dazuko_handle_request(request, xp_id);

	if (error == 0 && request->reply_buffer_size > 0)
	{
		request->reply_buffer[request->reply_buffer_size] = 0;

		temp_request->reply_buffer_size_used = request->reply_buffer_size_used;

		if (call_xp_copyout(temp_request, user_request, sizeof(struct dazuko_request)) != 0)
		{
			error = XP_ERROR_FAULT;
			goto dazuko_handle_user_request_out3;
		}

		if (request->reply_buffer_size_used > 0)
		{
			if (call_xp_copyout(request->reply_buffer, temp_request->reply_buffer, request->reply_buffer_size_used) != 0)
			{
				error = XP_ERROR_FAULT;
				goto dazuko_handle_user_request_out3;
			}
		}
	}

dazuko_handle_user_request_out3:
	if (request->reply_buffer_size > 0)
		rsbac_kfree(request->reply_buffer);
dazuko_handle_user_request_out2:
	rsbac_kfree(request->buffer);
dazuko_handle_user_request_out1:
	rsbac_sfree(dazuko_request_slab, temp_request);
dazuko_handle_user_request_out0:
	rsbac_sfree(dazuko_request_slab, request);

	return error;
}

int dazuko_handle_user_request_compat12(void *ptr, int cmd, struct xp_daemon_id *xp_id)
{
	struct access_compat12	*user_request12;
	struct access_compat12	*temp_request12;
	int			error = 0;
	struct slot		*s;
	char			*k_param;
	struct daemon_id	did;
	int			temp_length;
	int			temp_int;

	if (ptr == NULL || xp_id == NULL)
		return XP_ERROR_FAULT;

	did.xp_id = call_xp_id_copy(xp_id);
	did.unique = -1;

	switch (cmd)
	{
		case IOCTL_GET_AN_ACCESS:
			/* The daemon is requesting a filename of a file
			 * to scan. This code will wait until a filename
			 * is available, or until we should be killed.
			 * (killing is done if any errors occur as well
			 * as when the user kills us) */

			user_request12 = (struct access_compat12 *)ptr;

			error = call_xp_verify_user_writable(user_request12, sizeof(struct access_compat12));
			if (error)
			{
				error = XP_ERROR_FAULT;
				break;
			}

/* DOWN? */
			s = dazuko_get_an_access(&did);

			if (s == NULL)
			{
				error = XP_ERROR_INTERRUPT;
				break;
			}

/* DOWN */

			/* Slot IS in WORKING state. Copy all the
			 * necessary information to userspace structure. */

			if (s->filenamelength >= DAZUKO_FILENAME_MAX_LENGTH_COMPAT12)
			{
				/* filename length overflow :( */

				s->filename[DAZUKO_FILENAME_MAX_LENGTH_COMPAT12 - 1] = 0;
				temp_length = DAZUKO_FILENAME_MAX_LENGTH_COMPAT12;
			}
			else
			{
				temp_length = s->filenamelength + 1;
			}

			temp_request12 = rsbac_smalloc_unlocked(access_compat12_slab);
			if (temp_request12 == NULL)
			{
				error = XP_ERROR_FAULT;
			}
			else if (call_xp_copyin(user_request12, temp_request12, sizeof(struct access_compat12)) != 0)
			{
				error = XP_ERROR_FAULT;
			}

			if (error == 0)
			{
				temp_request12->event = s->event;
				temp_request12->o_flags = s->event_p.flags;
				temp_request12->o_mode = s->event_p.mode;
				temp_request12->uid = s->event_p.uid;
				temp_request12->pid = s->event_p.pid;
				memcpy(temp_request12->filename, s->filename, temp_length);

				if (call_xp_copyout(temp_request12, user_request12, sizeof(struct access_compat12)) != 0)
				{
					error = XP_ERROR_FAULT;
				}
			}

			call_xp_up(&(s->mutex));
/* UP */

			if (error)
			{
				dazuko_state_error(s, DAZUKO_WORKING);
			}

			if (temp_request12 != NULL)
			{
				rsbac_sfree(access_compat12_slab, temp_request12);
			}

			break;

		case IOCTL_RETURN_ACCESS:
			/* The daemon has finished scanning a file
			 * and has the response to give. The daemon's
			 * slot should be in the WORKING state. */

			user_request12 = (struct access_compat12 *)ptr;

			error = call_xp_verify_user_readable(user_request12, sizeof(struct access_compat12));
			if (error)
			{
				error = XP_ERROR_FAULT;
				break;
			}

			temp_request12 = rsbac_smalloc_unlocked(access_compat12_slab);
			if (temp_request12 == NULL)
			{
				error = XP_ERROR_FAULT;
				break;
			}

			if (call_xp_copyin(user_request12, temp_request12, sizeof(struct access_compat12)) != 0)
			{
				error = XP_ERROR_FAULT;
			}

			temp_int = temp_request12->deny;

			rsbac_sfree(access_compat12_slab, temp_request12);

			error = dazuko_return_access(&did, temp_int, NULL);
			break;

		case IOCTL_SET_OPTION:
			/* The daemon wants to set a configuration
			 * option in the kernel. */

			error = call_xp_verify_user_readable(ptr, 2*sizeof(int));
			if (error)
			{
				error = XP_ERROR_FAULT;
				break;
			}

			/* copy option type from userspace */
			if (call_xp_copyin(ptr, &temp_int, sizeof(int)) != 0)
			{
				error = XP_ERROR_FAULT;
				break;
			}

			ptr = ((char *)ptr + sizeof(int));

			/* copy path length from userspace */
			if (call_xp_copyin(ptr, &temp_length, sizeof(int)) != 0)
			{
				error = XP_ERROR_FAULT;
				break;
			}

			/* sanity check */
			if (temp_length < 0 || temp_length > 4096)
			{
				error = XP_ERROR_INVALID;
				break;
			}

			ptr = ((char *)ptr + sizeof(int));

			error = call_xp_verify_user_readable(ptr, temp_length);
			if (error)
			{
				error = XP_ERROR_FAULT;
				break;
			}

			k_param = rsbac_kmalloc_unlocked(temp_length + 1);
			if (k_param == NULL)
			{
				error = XP_ERROR_FAULT;
				break;
			}

			/* We must copy the param from userspace to kernelspace. */

			if (call_xp_copyin(ptr, k_param, temp_length) != 0)
			{
				rsbac_kfree(k_param);
				error = XP_ERROR_FAULT;
				break;
			}

			k_param[temp_length] = 0;

			if (temp_int == REGISTER)
				error = dazuko_register_daemon(&did, k_param, temp_length, 1);
			else
				error = dazuko_set_option(&did, temp_int, k_param, temp_length);

			rsbac_kfree(k_param);

			break;

		default:
			rsbac_printk(KERN_INFO "dazuko: daemon requested unknown device_ioctl %d (possible bug)\n", cmd);

			break;
	}

	call_xp_id_free(did.xp_id);

	return error;
}

static struct slot * dazuko_get_and_hold_ready_slot(struct slot_list *sl)
{
	/* This is a simple search to find a
	 * slot whose state is DAZUKO_READY. This means
	 * it is able to accept work. If a slot
	 * is found, the slot.mutex is held so
	 * it can be filled with work by the caller.
	 * It is the responsibility of the caller
	 * to RELEASE THE MUTEX. */

	int		i;
	struct slot	*s;

	for (i=0 ; i<NUM_SLOTS ; i++)
	{
		s = &(sl->slots[i]);
/* DOWN? */
		if (dazuko_change_slot_state(s, DAZUKO_READY, DAZUKO_WAITING, 0))
		{
/* DOWN */
			return s;
		}
	}

	/* we didn't find a slot that is ready for work */

	return NULL;
}

static int get_ready_slot_condition(void *param)
{
	return ((((struct get_ready_slot_condition_param *)param)->slot = dazuko_get_and_hold_ready_slot(((struct get_ready_slot_condition_param *)param)->slotlist)) != NULL
		|| call_xp_atomic_read(&active) == 0
		|| call_xp_atomic_read(&(((struct get_ready_slot_condition_param *)param)->slotlist->use_count)) == 0);
}

static int dazuko_run_daemon_on_slotlist(int event, char *filename, int filenamelength, struct event_properties *event_p, struct file_properties *file_p, int prev_response, struct slot_list *sl)
{
	/* This is the main function called by the kernel
	 * to work with a daemon. */

	int						rc;
	int						unique;
	struct slot					*s;
	struct get_ready_slot_condition_param		cond_p1;
	struct two_slot_state_not_condition_param	cond_p2;

begin:
	/* we initialize the slot value because
	 * we cannot guarentee that it will be
	 * assigned a new value BEFORE !active
	 * is checked */
	s = NULL;

	/* wait for a slot to become ready */
	cond_p1.slotlist = sl;
	cond_p1.slot = s;
	if (call_xp_wait_until_condition(&wait_kernel_waiting_for_free_slot, get_ready_slot_condition, &cond_p1, 0) != 0)
	{
		/* The kernel process was killed while
		 * waiting for a slot to become ready.
		 * This is fine. */

		DPRINT(("dazuko: kernel process %d killed while waiting for free slot\n", event_p->pid));

		return -1;  /* user interrupted */
	}

	/* Make sure we have a slot. We may have
	 * gotten past the last wait because we
	 * are no longer active. */

	s = cond_p1.slot;

	if (s == NULL)
	{
		/* We were no longer active. We don't
		 * need to initiate a daemon. This also
		 * means we never acquired the lock. */

		return 0;  /* allow access */
	}

/* DOWN */

	/* the slot is already locked at this point */

	/* grab the daemon's unique */
	unique = s->did.unique;

	/* At this point we have a locked slot. It IS
	 * sitting in the DAZUKO_WAITING state, waiting for
	 * us to give it some work. */
	
	/* set up the slot to do work */
	s->filename = filename;
	s->event = event;
	s->response = prev_response;
	s->filenamelength = filenamelength;

	if (event_p == NULL)
		dazuko_bzero(&(s->event_p), sizeof(struct event_properties));
	else
		memcpy(&(s->event_p), event_p, sizeof(struct event_properties));

	if (file_p == NULL)
		dazuko_bzero(&(s->file_p), sizeof(struct file_properties));
	else
		memcpy(&(s->file_p), file_p, sizeof(struct file_properties));

	/* we are done modifying the slot */
	call_xp_up(&(s->mutex));
/* UP */

	/* wake up any daemons waiting for work */
	call_xp_notify(&wait_daemon_waiting_for_work);

	/* wait until the daemon is finished with the slot */
	cond_p2.slot1 = s;
	cond_p2.state1 = DAZUKO_WAITING;
	cond_p2.slot2 = s;
	cond_p2.state2 = DAZUKO_WORKING;
	if (call_xp_wait_until_condition(&wait_kernel_waiting_while_daemon_works, two_slot_state_not_condition, &cond_p2, 0) != 0)
	{
		/* The kernel process was killed while
		 * waiting for a daemon to process the file.
		 * This is fine. */

		DPRINT(("dazuko: kernel process %d killed while waiting for daemon response\n", event_p->pid));

		/* change the slot's state to let the
		 * daemon know we are not interested
		 * in a response */
		dazuko_change_slot_state(s, DAZUKO_FREE, DAZUKO_FREE, 1);

		return -1;  /* user interrupted */
	}

	/* we are working with the slot, so
	 * we need to lock it */
/* DOWN */
	if (call_xp_down(&(s->mutex)) != 0)
	{
		return -1;  /* user interrupted */
	}

	/* make sure this is the right daemon */
	if (s->did.unique != unique)
	{
		/* This is a different daemon than
		 * the one we assigned work to.
		 * We need to scan again. */
		call_xp_up(&(s->mutex));
/* UP */
		goto begin;
	}

	/* The slot should now be in the DAZUKO_DONE state. */
	if (!__dazuko_change_slot_state(s, DAZUKO_DONE, DAZUKO_FREE))
	{
		/* The daemon was killed while scanning.
		 * We need to scan again. */

		call_xp_up(&(s->mutex));
/* UP */
		goto begin;
	}

	/* grab the response */
	rc = s->response;

	call_xp_up(&(s->mutex));
/* UP */

	/* CONGRATULATIONS! You successfully completed a full state cycle! */

	return rc;
}

static int dazuko_run_daemon(int event, char *filename, int filenamelength, struct event_properties *event_p, struct file_properties *file_p)
{
	struct slot_list	*sl;
	int			i;
	int			rc = 0;
	int			error;

	if (event_p != NULL)
	{
		/* we don't want to throw the same event twice */
		if (event_p->thrown)
			return 0;
		event_p->thrown = 1;
	}

	for (i=0 ; i<NUM_SLOT_LISTS ; i++)
	{
/* DOWN */
		/* if we are interrupted, we report error */
		if (call_xp_down(&(slot_lists[i].mutex)) != 0)
			return XP_ERROR_INTERRUPT;

		sl = slot_lists[i].slot_list;

		call_xp_up(&(slot_lists[i].mutex));
/* UP */

		if (sl != NULL)
		{
			error = dazuko_run_daemon_on_slotlist(event, filename, filenamelength, event_p, file_p, rc, sl);

			if (error < 0)
			{
				/* most likely user interrupt */
				rc = error;
				break;
			}
			else if (error > 0)
			{
				/* this daemon wants access blocked */
				rc = 1;
			}
		}
	}

	return rc;
}

inline int dazuko_is_our_daemon(struct xp_daemon_id *xp_id)
{
	/* Check if the current process is one
	 * of the daemons. */

	struct daemon_id	did;
	int			ret;

	did.xp_id = call_xp_id_copy(xp_id);
	did.unique = -1;

	ret = (dazuko_find_slot(&did, 1, NULL) != NULL);

	call_xp_id_free(did.xp_id);

	return ret;
}

#ifdef CONFIG_RSBAC_DAZ_SELECT
static int dazuko_is_selected(struct dazuko_file_struct *kfs)
{
	/* Check if the given filename (with path) is
	 * under our include directories but not under
	 * the exclude directories. */

	struct dazuko_file_listnode	*cur;
	struct dazuko_path			*path;
	int				selected = 0;
	int				use_aliases = 1;

	if (kfs == NULL)
		return 0;

	/* If we are interrupted here, we will report that
	 * this file is not selected. This will make the
	 * kernel allow normal access. Is this dangerous? */
/* LOCK */
	call_xp_read_lock(&lock_lists);

	if (kfs->aliases == NULL && kfs->filename != NULL)
	{
		/* extension is not using aliases */

		use_aliases = 0;

		kfs->aliases = rsbac_smalloc_clear(dazuko_file_listnode_slab);
		if (kfs->aliases == NULL)
		{
			rsbac_printk(KERN_WARNING "dazuko: warning: access not controlled (%s)\n", kfs->filename);
			return 0;
		}

		kfs->aliases->filename = kfs->filename;
		kfs->aliases->filename_length = kfs->filename_length;
	}

	for (cur=kfs->aliases ; cur ; cur=cur->next)
	{
		if (cur->filename != NULL && cur->filename_length > 0)
		{
			/* check if filename is under our include paths */
			for (path=incl_paths ; path ; path=path->next)
			{
				/* the include item must be at least as long as the given filename */
				if (path->len <= cur->filename_length)
				{
					/* the include item should match the beginning of the given filename */
					if (memcmp(path->path, cur->filename, path->len) == 0)
					{
						kfs->filename = cur->filename;
						kfs->filename_length = cur->filename_length;

						selected = 1;
						break;
					}
				}
			}

			/* If we didn't find a path, it isn't in our
			 * include directories. It can't be one of
			 * the selected files to scan. */
			if (!selected)
			{
				continue;
			}

			/* check if filename is under our exclude paths */
			for (path=excl_paths ; path ; path=path->next)
			{
				/* the exclude item must be at least as long as the given filename */
				if (path->len <= cur->filename_length)
				{
					/* the exclude item should match the beginning of the given filename */
					if (memcmp(path->path, cur->filename, path->len) == 0)
					{
						kfs->filename = NULL;
						kfs->filename_length = 0;

						selected = 0;
						break;
					}
				}
			}

			/* If we are still selected, then we can stop. */
			if (selected)
				break;
		}
	}

	call_xp_read_unlock(&lock_lists);
/* UNLOCK */

	if (!use_aliases)
	{
		rsbac_sfree(dazuko_file_listnode_slab, kfs->aliases);
		kfs->aliases = NULL;
	}

	return selected;
}
#endif

static int dazuko_add_hash(struct xp_file *file, char *filename, int len)
{
	/* Add the given file and filename to the linked list
	 * of files to scan once they are closed. */

	struct hash	*h;

	/* create a new struct hash structure making room for name also */
	h = rsbac_kmalloc_unlocked(sizeof(struct hash) + len + 1);
	if (h == NULL)
		return XP_ERROR_FAULT;

	/* fill in structure items */

	call_xp_copy_file(&(h->file), file);
	h->dirty = 0;
	h->namelen = len;
	memcpy(h->name, filename, len);
	h->name[len] = 0;

	/* add the new struct hash item to the head of the
	 * struct hash linked list */

/* LOCK */
	call_xp_write_lock(&lock_hash);
	h->next = hash;
	hash = h;
	call_xp_write_unlock(&lock_hash);
/* UNLOCK */
	return 0;
}

/* Code based on code from: Swade 12/08/02: Move dirty to end of list */
static void dazuko_mark_hash_dirty(struct xp_file *file)
{
	struct hash	*h = NULL;
	struct hash	*entry = NULL;
	struct hash	*prev = NULL;
	struct hash	*prev_entry = NULL;

/* LOCK */
	call_xp_write_lock(&lock_hash);

	for (h=hash ; h ; h=h->next)
	{
		/* not found if hit first dirty entry */
		if (h->dirty)
		{
			entry = NULL;
			break;
		}

		if (call_xp_compare_file(&(h->file), file) == 0)
		{
			/* we found the entry */

			prev_entry = prev;
			entry = h;
			break;
		}

		prev = h;
	} 

	if (entry)
	{
		if (!entry->dirty)
		{
			/* mark as dirty */
			entry->dirty = 1;

			/* If we already are last entry or next
		 	 * entry dirty, we don't need to move */

			if (entry->next)
			{
				if (!entry->next->dirty)
				{
					for (h=entry->next ; h ; h=h->next)
					{
						if (h->dirty)
							break;

						prev = h;
					}

					/* remove from current position */
					if (prev_entry)
						prev_entry->next = entry->next;
					else
						hash = entry->next;

					if (prev == NULL)
					{
						/* insert as first item */
						entry->next = hash;
						hash = entry;
					}
					else if (h)
					{
						/* insert before h (after prev) */
						entry->next = prev->next;
						prev->next = entry;
					}
					else
					{
						/* insert as last item (after prev) */
						entry->next = NULL;
						prev->next = entry;
					}
				}
			}
		}
	}

	call_xp_write_unlock(&lock_hash);
/* UNLOCK */

}

static struct hash *dazuko_get_hash(struct xp_file *file)
{
	/* Find the given file within our list
	 * and then remove it from the list and
	 * return it. */

	struct hash	*prev;
	struct hash	*cur;

/* LOCK */
	call_xp_write_lock(&lock_hash);

	prev = NULL;
	cur = hash;
	while (cur)
	{
		if (call_xp_compare_file(&(cur->file), file) == 0)
		{
			/* we found the entry */

			/* remove the item from the list */
			if (!prev)
				hash = cur->next;
			else
				prev->next = cur->next;
			break;
		}

		prev = cur;
		cur = cur->next;
	}

	call_xp_write_unlock(&lock_hash);
/* UNLOCK */

	return cur;
}

static int dazuko_should_scan(struct dazuko_file_struct *kfs)
{
	/* Check if we are supposed to scan this file.
	 * This checks for all the correct file types,
	 * permissions, and if it is within the desired
	 * paths to scan. */

	int result = 0;

	/* check if we already know if we scan this file */
	switch (kfs->should_scan)
	{
		/* case 0 means that we do not know yet. This is a little
		 * confusing, because 0 represents uninitialized. However,
		 * the should_scan variable is used in this function ONLY
		 * so this optimization shouldn't cause any problems. */

		case 1:
			/* we already know it should be scanned */
			return 1;

		case 2:
			/* we already know it should not be scanned */
			return 2;
	}

	/* make necessary platform-dependent checks */
	if (call_xp_fill_file_struct(kfs) == 0)
	{
#ifdef CONFIG_RSBAC_DAZ_SELECT
		if (dazuko_is_selected(kfs))
		{
#endif
			/* If we made it this far, we are supposed
			 * to scan this file. We mark it so that
			 * any further immediate inquiries don't have
			 * to do all this work all over again. */
 
			/* yes, should be scanned */
			kfs->should_scan = 1;

			result = 1;
#ifdef CONFIG_RSBAC_DAZ_SELECT
		}
		else
		{
			/* We will still mark it so that any further
			 * immediate inquiries don't have to do all
			 * this work all over again. */

			/* no, should not be scanned */
			kfs->should_scan = 2;
		}
#endif
	}

	return result;
}

inline int dazuko_sys_check(unsigned long event, int daemon_is_allowed, struct xp_daemon_id *xp_id)
{
	/* is this event in our mask? */
	switch (event)
	{
		case DAZUKO_ON_OPEN:
			/* this is a special case because the on_close information needs
			 * to be saved during the on_open event */

			if ((SCAN_ON_OPEN || SCAN_ON_CLOSE || SCAN_ON_CLOSE_MODIFIED) == 0)
				return -1;
			break;

		case DAZUKO_ON_CLOSE:
			/* will need to scan if ON_CLOSE_MODIFIED is in the mask too */

			if ((SCAN_ON_CLOSE || SCAN_ON_CLOSE_MODIFIED) == 0)
				return -2;
			break;

		default:
			if ((access_mask & event) == 0)
				return -3;
			break;
	}

	/* do we have any daemons? */
	if (call_xp_atomic_read(&active) <= 0)
		return -4;

	/* should daemons be allowed this event without a scan? */
	if (daemon_is_allowed)
	{
		if (dazuko_is_our_daemon(xp_id))
		{
			/* this is one of our daemons, so we will report as
			 * as if this event was not in the mask */

			return -5;
		}
	}

	return 0;
}

inline int dazuko_sys_pre(unsigned long event, struct dazuko_file_struct *kfs, struct xp_file *file, struct event_properties *event_p)
{
	/* return codes:
	 *   >0 -> access should be blocked
	 *   <0 -> access should be blocked (because user interrupted)
	 *    0 -> access is allowed
	 *   -2 -> unscanned access should not be taken care of
	 */

	int		error = 0;
	struct hash	*h = NULL;

	switch (event)
	{
		case DAZUKO_ON_OPEN:
			/* special case, because this pre may be called
			 * in order to record ON_CLOSE events (in post) */

			if (!SCAN_ON_OPEN)
				return 2;
			break;

		case DAZUKO_ON_CLOSE:
			/* handled in post */

			return 2;

		case DAZUKO_ON_CLOSE_MODIFIED:
			/* (this is really sys_write) always permitted */

			return 2;

		default:
			break;
	}

	if (kfs == NULL)
	{
		/* kfs is required */

		rsbac_printk(KERN_WARNING "dazuko: kfs=NULL (possible bug)\n");

		return XP_ERROR_PERMISSION;
	}

	if (file != NULL)
	{
		/* we search for the file descriptor first */

/* LOCK */
		call_xp_read_lock(&lock_hash);

		for (h=hash ; h ; h=h->next)
		{
			if (call_xp_compare_file(&(h->file), file) == 0)
			{
				/* we found the file descriptor */

				kfs->filename = rsbac_kmalloc_unlocked(h->namelen + 1);
				if (kfs->filename != NULL)
				{
					memcpy(kfs->filename, h->name, h->namelen);
					kfs->filename[h->namelen] = 0;
					kfs->filename_length = h->namelen;
					kfs->should_scan = 1;
				}
				else
				{
					/* error allocating, so we get out */
					h = NULL;
				}
				break;
			}
		}

		call_xp_read_unlock(&lock_hash);
/* UNLOCK */

		if (h == NULL && kfs->extra_data == NULL)
		{
			/* we don't know this file descriptor
			 * and we cannot fallback on name lookups
			 */

			/* we should not scan this file */
			kfs->should_scan = 2;

			return 0;
		}
	}

	/* make sure we should scan this file */
	if (dazuko_should_scan(kfs))
		error = dazuko_run_daemon(event, kfs->filename, kfs->filename_length, event_p, &(kfs->file_p));
	else
		return 2;

	if (error > 0)
	{
		/* access will be blocked */

		/* dazuko_sys_post should NOT be called! */

		return XP_ERROR_PERMISSION;
	}
	else if (error < 0)
	{
		/* user interrupted */

		/* dazuko_sys_post should NOT be called! */

		return XP_ERROR_INTERRUPT;
	}

	/* access allowed */

	return 0;
}

inline int dazuko_sys_post(unsigned long event, struct dazuko_file_struct *kfs, struct xp_file *file, struct event_properties *event_p)
{
	struct hash	*h = NULL;

	switch (event)
	{
		case DAZUKO_ON_OPEN: /* kfs,file required */
			/* if the file was opened and we are interested
			 * in scanning on close, add this file to our struct hash list */

			if ((call_xp_atomic_read(&active) > 0) && file != NULL && kfs != NULL)
			{
				if (SCAN_ON_OPEN || SCAN_ON_CLOSE || SCAN_ON_CLOSE_MODIFIED)
				{
					/* make sure we should scan this file */
					if (dazuko_should_scan(kfs))
					{
						/* hash is added if we were given an xp_file */
						if (file != NULL)
							dazuko_add_hash(file, kfs->filename, kfs->filename_length);

						/* this is a fallback in case we didn't process the event in "sys_pre" */
						dazuko_run_daemon(event, kfs->filename, kfs->filename_length, event_p, &(kfs->file_p));
					}
				}
			}
			break;

		case DAZUKO_ON_CLOSE: /* file,o_flags,o_mode,pid,uid required */
			if (file != NULL)
			{
				/* find hash entry and remove it from list */
				h = dazuko_get_hash(file);

				/* if we found the file in our list and the file was
	 			* successfully closed, we need to scan it */
				if (h != NULL)
				{
					/* determine if we are scanning on close or close_modified */

					/* note that close_modified has priority over just close */

					if (SCAN_ON_CLOSE_MODIFIED && h->dirty)
						dazuko_run_daemon(DAZUKO_ON_CLOSE_MODIFIED, h->name, h->namelen, event_p, NULL);
					else if (SCAN_ON_CLOSE)
						dazuko_run_daemon(DAZUKO_ON_CLOSE, h->name, h->namelen, event_p, NULL);

					/* clean up the struct hash structure */
					rsbac_kfree(h);
				}
			}
			else
			{
				if (SCAN_ON_CLOSE)
				{
					if (dazuko_should_scan(kfs))
					{
						dazuko_run_daemon(DAZUKO_ON_CLOSE, kfs->filename, kfs->filename_length, event_p, &(kfs->file_p));
					}
				}
			}
			break;

		case DAZUKO_ON_CLOSE_MODIFIED: /* file required */
			if (file != NULL)
			{
				/* if we actually wrote something and we found the
				 * file in our list, set it as dirty */

				/* Swade 4/24/02: Move to end of clean list */
				dazuko_mark_hash_dirty(file);
			}
			break;

		default:
			break;
	}

	return 0;
}

inline int dazuko_init(void)
{
	int	i;
	int	error;

#ifdef CONFIG_RSBAC_DAZ_SELECT
	dazuko_file_listnode_slab = rsbac_slab_create("rsbac_dazuko_file_listnode",
					sizeof(struct dazuko_file_listnode));
#endif
	dazuko_request_slab = rsbac_slab_create("rsbac_dazuko_request",
					sizeof(struct dazuko_request));
	access_compat12_slab = rsbac_slab_create("rsbac_dazuko_access_compat12",
					sizeof(struct access_compat12));

	call_xp_init_mutex(&mutex_unique_count);

	call_xp_init_rwlock(&lock_hash);
	call_xp_init_rwlock(&lock_lists);

	call_xp_init_queue(&wait_kernel_waiting_for_free_slot);
	call_xp_init_queue(&wait_daemon_waiting_for_work);
	call_xp_init_queue(&wait_kernel_waiting_while_daemon_works);
	call_xp_init_queue(&wait_daemon_waiting_for_free);

	dazuko_bzero(&slot_lists, sizeof(slot_lists));

	for (i=0 ; i<NUM_SLOT_LISTS ; i++)
		call_xp_init_mutex(&(slot_lists[i].mutex));

	call_xp_atomic_set(&active, 0);

	error = call_xp_sys_hook();

	if (error == 0)
		rsbac_printk(KERN_INFO "dazuko: loaded, version=%s\n", VERSION);

  	return error;
}

inline int dazuko_exit(void)
{
	int	error;
	int	i;
	int	j;

	i = call_xp_atomic_read(&active);

	if (i != 0)
	{
		rsbac_printk(KERN_INFO "dazuko: warning: trying to remove Dazuko with %d process%s still registered\n", i, i==1 ? "" : "es");
		return -1;
	}

	dazuko_remove_all_paths();
	dazuko_remove_all_hash();

	error = call_xp_sys_unhook();

	if (error == 0)
	{
		call_xp_destroy_mutex(&mutex_unique_count);

		call_xp_destroy_rwlock(&lock_hash);
		call_xp_destroy_rwlock(&lock_lists);

		call_xp_destroy_queue(&wait_kernel_waiting_for_free_slot);
		call_xp_destroy_queue(&wait_daemon_waiting_for_work);
		call_xp_destroy_queue(&wait_kernel_waiting_while_daemon_works);
		call_xp_destroy_queue(&wait_daemon_waiting_for_free);

		for (i=0 ; i<NUM_SLOT_LISTS ; i++)
		{
			if (slot_lists[i].slot_list != NULL)
			{
				if (call_xp_atomic_read(&(slot_lists[i].slot_list->use_count)) != 0)
					rsbac_printk(KERN_WARNING "dazuko: slot_list count was not 0 (possible bug)\n");

				for (j=0 ; j<NUM_SLOTS ; j++)
				{
					call_xp_destroy_mutex(&(slot_lists[i].slot_list->slots[j].mutex));
				}

				rsbac_kfree(slot_lists[i].slot_list);
				slot_lists[i].slot_list = NULL;
			}

			call_xp_destroy_mutex(&(slot_lists[i].mutex));
		}

		rsbac_printk(KERN_INFO "dazuko: unloaded, version=%s\n", VERSION);
	}

	return error;
}
