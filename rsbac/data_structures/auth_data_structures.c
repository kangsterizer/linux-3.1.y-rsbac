/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of AUTH data structures            */
/* Author and (c) 1999-2011: Amon Ott <ao@rsbac.org> */
/*                                                   */
/* Last modified: 12/Jul/2011                        */
/*************************************************** */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <asm/uaccess.h>
#include <rsbac/types.h>
#include <rsbac/aci_data_structures.h>
#include <rsbac/auth_data_structures.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/adf.h>
#include <rsbac/aci.h>
#include <rsbac/auth.h>
#include <rsbac/lists.h>
#include <rsbac/proc_fs.h>
#include <rsbac/rkmem.h>
#include <rsbac/getname.h>
#include <linux/string.h>
#include <linux/srcu.h>
#include <linux/seq_file.h>
#include <linux/module.h>

/************************************************************************** */
/*                          Global Variables                                */
/************************************************************************** */

/* The following global variables are needed for access to PM data.         */

static struct rsbac_auth_device_list_head_t * device_list_head_p;
static spinlock_t device_list_lock;
static struct srcu_struct device_list_srcu;
static struct lock_class_key device_list_lock_class;

static rsbac_list_handle_t process_handle = NULL;
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
static rsbac_list_handle_t process_eff_handle = NULL;
static rsbac_list_handle_t process_fs_handle = NULL;
#endif

#ifdef CONFIG_RSBAC_AUTH_GROUP
static rsbac_list_handle_t process_group_handle = NULL;
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
static rsbac_list_handle_t process_group_eff_handle = NULL;
static rsbac_list_handle_t process_group_fs_handle = NULL;
#endif
#endif

#if defined(CONFIG_RSBAC_AUTH_LEARN)
#ifdef CONFIG_RSBAC_AUTH_LEARN_TA
rsbac_list_ta_number_t auth_learn_ta = CONFIG_RSBAC_AUTH_LEARN_TA;
#else
rsbac_list_ta_number_t auth_learn_ta = 0;
#endif
#endif

static struct kmem_cache * auth_device_item_slab = NULL;

/**************************************************/
/*       Declarations of external functions       */
/**************************************************/

rsbac_boolean_t writable(struct super_block *sb_p);

/**************************************************/
/*       Declarations of internal functions       */
/**************************************************/

/************************************************* */
/*               Internal Help functions           */
/************************************************* */

static u_int nr_fd_hashes = RSBAC_AUTH_NR_CAP_FD_LISTS;

#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
static u_int nr_eff_fd_hashes = RSBAC_AUTH_NR_CAP_EFF_FD_LISTS;
static u_int nr_fs_fd_hashes = RSBAC_AUTH_NR_CAP_FS_FD_LISTS;
#endif

#ifdef CONFIG_RSBAC_AUTH_GROUP
static u_int nr_group_fd_hashes = RSBAC_AUTH_NR_CAP_GROUP_FD_LISTS;

#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
static u_int nr_group_eff_fd_hashes = RSBAC_AUTH_NR_CAP_GROUP_EFF_FD_LISTS;
static u_int nr_group_fs_fd_hashes = RSBAC_AUTH_NR_CAP_GROUP_FS_FD_LISTS;
#endif
#endif

static int cap_compare(void *desc1, void *desc2)
{
	struct rsbac_auth_cap_range_t *range1 = desc1;
	struct rsbac_auth_cap_range_t *range2 = desc2;

	if (!desc1 || !desc2)
		return 0;
	if (range1->first < range2->first)
		return -1;
	if (range1->first > range2->first)
		return 1;
	if (range1->last < range2->last)
		return -1;
	if (range1->last > range2->last)
		return 1;
	return 0;
}

static int single_cap_compare(void *desc1, void *desc2)
{
	struct rsbac_auth_cap_range_t *range = desc1;
	rsbac_uid_t *uid = desc2;

	if (!desc1 || !desc2)
		return 0;
	if ((*uid < range->first)
	    || (*uid > range->last)
	    )
		return 1;
	else
		return 0;
}

static int auth_subconv(void *old_desc,
		       void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_auth_cap_range_t *tmp_new_desc = new_desc;
        struct rsbac_auth_old_cap_range_t *tmp_old_desc = old_desc;

        tmp_new_desc->first = tmp_old_desc->first;
        tmp_new_desc->last = tmp_old_desc->last;
	return 0;
}

static rsbac_list_conv_function_t *auth_get_subconv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_AUTH_FD_OLD_LIST_VERSION:
		return auth_subconv;
	default:
		return NULL;
	}
}

static int auth_conv(void *old_desc,
		       void *old_data, void *new_desc, void *new_data)
{
	memcpy(new_desc, old_desc, sizeof(rsbac_inode_nr_t));
	return 0;
}

static rsbac_list_conv_function_t *auth_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_AUTH_FD_OLD_LIST_VERSION:
		return auth_conv;
	default:
		return NULL;
	}
}


/* auth_register_fd_lists() */
/* register fd ACL lists for device */

static int auth_register_fd_lists(struct rsbac_auth_device_list_item_t
				  *device_p, kdev_t kdev)
{
	int err = 0;
	int tmperr;
	struct rsbac_list_lol_info_t lol_info;

	if (!device_p)
		return -RSBAC_EINVALIDPOINTER;

	lol_info.version = RSBAC_AUTH_FD_LIST_VERSION;
	lol_info.key = RSBAC_AUTH_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_inode_nr_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size =
	    sizeof(struct rsbac_auth_cap_range_t);
	lol_info.subdata_size = 0;	/* rights */
	lol_info.max_age = 0;
	tmperr = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
					 &device_p->handle,
					 &lol_info,
					 RSBAC_LIST_PERSIST |
					 RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					 NULL,
					 cap_compare,
					 auth_get_conv, auth_get_subconv,
					 NULL, NULL,
					 RSBAC_AUTH_FD_FILENAME, kdev,
					 nr_fd_hashes,
					 rsbac_list_hash_fd,
					 RSBAC_AUTH_FD_OLD_FILENAME);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "auth_register_fd_lists(): registering list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_AUTH_FD_FILENAME,
				     RSBAC_MAJOR(kdev),
				     RSBAC_MINOR(kdev),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
	/* register all the AUTH DAC lists of lists */
	lol_info.version = RSBAC_AUTH_FD_EFF_LIST_VERSION;
	lol_info.key = RSBAC_AUTH_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_inode_nr_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size =
	    sizeof(struct rsbac_auth_cap_range_t);
	lol_info.subdata_size = 0;	/* rights */
	lol_info.max_age = 0;
	tmperr = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
					 &device_p->eff_handle,
					 &lol_info,
					 RSBAC_LIST_PERSIST |
					 RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					 NULL,
					 cap_compare,
					 auth_get_conv, auth_get_subconv,
					 NULL, NULL,
					 RSBAC_AUTH_FD_EFF_FILENAME, kdev,
					 nr_eff_fd_hashes,
					 rsbac_list_hash_fd,
					 RSBAC_AUTH_FD_OLD_EFF_FILENAME);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "auth_register_fd_lists(): registering list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_AUTH_FD_EFF_FILENAME,
				     RSBAC_MAJOR(kdev),
				     RSBAC_MINOR(kdev),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
	lol_info.version = RSBAC_AUTH_FD_FS_LIST_VERSION;
	lol_info.key = RSBAC_AUTH_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_inode_nr_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size =
	    sizeof(struct rsbac_auth_cap_range_t);
	lol_info.subdata_size = 0;	/* rights */
	lol_info.max_age = 0;
	tmperr = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
					 &device_p->fs_handle,
					 &lol_info,
					 RSBAC_LIST_PERSIST |
					 RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					 NULL,
					 cap_compare,
					 auth_get_conv, auth_get_subconv,
					 NULL, NULL,
					 RSBAC_AUTH_FD_FS_FILENAME, kdev,
					 nr_fs_fd_hashes,
					 rsbac_list_hash_fd,
					 RSBAC_AUTH_FD_OLD_FS_FILENAME);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "auth_register_fd_lists(): registering list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_AUTH_FD_FS_FILENAME,
				     RSBAC_MAJOR(kdev),
				     RSBAC_MINOR(kdev),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#endif

#ifdef CONFIG_RSBAC_AUTH_GROUP
	lol_info.version = RSBAC_AUTH_FD_GROUP_LIST_VERSION;
	lol_info.key = RSBAC_AUTH_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_inode_nr_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size =
	    sizeof(struct rsbac_auth_cap_range_t);
	lol_info.subdata_size = 0;	/* rights */
	lol_info.max_age = 0;
	tmperr = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
					 &device_p->group_handle,
					 &lol_info,
					 RSBAC_LIST_PERSIST |
					 RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					 NULL,
					 cap_compare,
					 auth_get_conv, auth_get_subconv,
					 NULL, NULL,
					 RSBAC_AUTH_FD_GROUP_FILENAME, kdev,
					 nr_group_fd_hashes,
					 rsbac_list_hash_fd,
					 RSBAC_AUTH_FD_OLD_GROUP_FILENAME);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "auth_register_fd_lists(): registering list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_AUTH_FD_GROUP_FILENAME,
				     RSBAC_MAJOR(kdev),
				     RSBAC_MINOR(kdev),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
	lol_info.version = RSBAC_AUTH_FD_GROUP_EFF_LIST_VERSION;
	lol_info.key = RSBAC_AUTH_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_inode_nr_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size =
	    sizeof(struct rsbac_auth_cap_range_t);
	lol_info.subdata_size = 0;	/* rights */
	lol_info.max_age = 0;
	tmperr = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
					 &device_p->group_eff_handle,
					 &lol_info,
					 RSBAC_LIST_PERSIST |
					 RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					 NULL,
					 cap_compare,
					 auth_get_conv, auth_get_subconv,
					 NULL, NULL,
					 RSBAC_AUTH_FD_GROUP_EFF_FILENAME, kdev,
					 nr_group_eff_fd_hashes,
					 rsbac_list_hash_fd,
					 RSBAC_AUTH_FD_OLD_GROUP_EFF_FILENAME);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "auth_register_fd_lists(): registering list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_AUTH_FD_GROUP_EFF_FILENAME,
				     RSBAC_MAJOR(kdev),
				     RSBAC_MINOR(kdev),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
	lol_info.version = RSBAC_AUTH_FD_GROUP_FS_LIST_VERSION;
	lol_info.key = RSBAC_AUTH_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_inode_nr_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size =
	    sizeof(struct rsbac_auth_cap_range_t);
	lol_info.subdata_size = 0;	/* rights */
	lol_info.max_age = 0;
	tmperr = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
					 &device_p->group_fs_handle,
					 &lol_info,
					 RSBAC_LIST_PERSIST |
					 RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					 NULL,
					 cap_compare,
					 auth_get_conv, auth_get_subconv,
					 NULL, NULL,
					 RSBAC_AUTH_FD_GROUP_FS_FILENAME, kdev,
					 nr_group_fs_fd_hashes,
					 rsbac_list_hash_fd,
					 RSBAC_AUTH_FD_OLD_GROUP_FS_FILENAME);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "auth_register_fd_lists(): registering list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_AUTH_FD_GROUP_FS_FILENAME,
				     RSBAC_MAJOR(kdev),
				     RSBAC_MINOR(kdev),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#endif
#endif				/* AUTH_GROUP */

	return err;
}

/* auth_detach_fd_lists() */
/* detach from fd AUTH lists for device */

static int auth_detach_fd_lists(struct rsbac_auth_device_list_item_t
				*device_p)
{
	int err = 0;
	int tmperr;

	if (!device_p)
		return -RSBAC_EINVALIDPOINTER;

	/* detach all the AUTH lists of lists */
	tmperr = rsbac_list_lol_detach(&device_p->handle,
					       RSBAC_AUTH_LIST_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "auth_detach_fd_lists(): detaching from list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_AUTH_FD_FILENAME,
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
	tmperr = rsbac_list_lol_detach(&device_p->eff_handle,
					  RSBAC_AUTH_LIST_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "auth_detach_fd_lists(): detaching from list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_AUTH_FD_EFF_FILENAME,
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
	tmperr = rsbac_list_lol_detach(&device_p->fs_handle,
					  RSBAC_AUTH_LIST_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "auth_detach_fd_lists(): detaching from list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_AUTH_FD_FS_FILENAME,
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#endif

#ifdef CONFIG_RSBAC_AUTH_GROUP
	tmperr = rsbac_list_lol_detach(&device_p->group_handle,
					  RSBAC_AUTH_LIST_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "auth_detach_fd_lists(): detaching from list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_AUTH_FD_GROUP_FILENAME,
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
	tmperr = rsbac_list_lol_detach(&device_p->group_eff_handle,
					  RSBAC_AUTH_LIST_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "auth_detach_fd_lists(): detaching from list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_AUTH_FD_GROUP_EFF_FILENAME,
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
	tmperr = rsbac_list_lol_detach(&device_p->group_fs_handle,
					  RSBAC_AUTH_LIST_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "auth_detach_fd_lists(): detaching from list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_AUTH_FD_GROUP_FS_FILENAME,
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#endif
#endif				/* AUTH_GROUP */

	return err;
}

/************************************************************************** */
/* The lookup functions return NULL, if the item is not found, and a        */
/* pointer to the item otherwise.                                           */

/* first the device item lookup */
static struct rsbac_auth_device_list_item_t *lookup_device(kdev_t kdev)
{
	struct rsbac_auth_device_list_item_t *curr = rcu_dereference(device_list_head_p)->curr;

	/* if there is no current item or it is not the right one, search... */
	if (!(curr && (RSBAC_MAJOR(curr->id) == RSBAC_MAJOR(kdev))
	      && (RSBAC_MINOR(curr->id) == RSBAC_MINOR(kdev))
	    )
	    ) {
		curr = rcu_dereference(device_list_head_p)->head;
		while (curr
		       && ((RSBAC_MAJOR(curr->id) != RSBAC_MAJOR(kdev))
			   || (RSBAC_MINOR(curr->id) != RSBAC_MINOR(kdev))
		       )
		    ) {
			curr = curr->next;
		}
		if (curr)
			rcu_dereference(device_list_head_p)->curr = curr;
	}
	/* it is the current item -> return it */
	return curr;
}

/************************************************************************** */
/* The add_item() functions add an item to the list, set head.curr to it,   */
/* and return a pointer to the item.                                        */
/* These functions will NOT check, if there is already an item under the    */
/* same ID! If this happens, the lookup functions will return the old item! */
/* All list manipulation is protected by rw-spinlocks to prevent inconsistency */
/* and undefined behaviour in other concurrent functions.                   */

/* Create a device item without adding to list. No locking needed. */
static struct rsbac_auth_device_list_item_t
*create_device_item(kdev_t kdev)
{
	struct rsbac_auth_device_list_item_t *new_item_p;

	/* allocate memory for new device, return NULL, if failed */
	if (!(new_item_p = rsbac_smalloc_clear_unlocked(auth_device_item_slab)))
		return NULL;

	new_item_p->id = kdev;
	new_item_p->mount_count = 1;
	return new_item_p;
}

/* Add an existing device item to list. Locking needed. */
static struct rsbac_auth_device_list_item_t
*add_device_item(struct rsbac_auth_device_list_item_t *device_p)
{
	struct rsbac_auth_device_list_head_t * new_p;
	struct rsbac_auth_device_list_head_t * old_p;

	if (!device_p)
		return NULL;

	spin_lock(&device_list_lock);
	old_p = device_list_head_p;
	new_p = rsbac_kmalloc(sizeof(*new_p));
	*new_p = *old_p;
	/* add new device to device list */
	if (!new_p->head) {	/* first device */
		new_p->head = device_p;
		new_p->tail = device_p;
		new_p->curr = device_p;
		new_p->count = 1;
		device_p->prev = NULL;
		device_p->next = NULL;
	} else {		/* there is another device -> hang to tail */
		device_p->prev = new_p->tail;
		device_p->next = NULL;
		new_p->tail->next = device_p;
		new_p->tail = device_p;
		new_p->curr = device_p;
		new_p->count++;
	}
	rcu_assign_pointer(device_list_head_p, new_p);
	spin_unlock(&device_list_lock);
	synchronize_srcu(&device_list_srcu);
	rsbac_kfree(old_p);
	return device_p;
}

/************************************************************************** */
/* The remove_item() functions remove an item from the list. If this item   */
/* is head, tail or curr, these pointers are set accordingly.               */
/* To speed up removing several subsequent items, curr is set to the next   */
/* item, if possible.                                                       */
/* If the item is not found, nothing is done.                               */

static void clear_device_item(struct rsbac_auth_device_list_item_t *item_p)
{
	if (!item_p)
		return;

	auth_detach_fd_lists(item_p);
	rsbac_sfree(auth_device_item_slab, item_p);
}

static void remove_device_item(kdev_t kdev)
{
	struct rsbac_auth_device_list_item_t *item_p;
	struct rsbac_auth_device_list_head_t * new_p;
	struct rsbac_auth_device_list_head_t * old_p;
     
	old_p = device_list_head_p;
	new_p = rsbac_kmalloc(sizeof(*new_p));
	*new_p = *old_p;
	/* first we must locate the item. */
	if ((item_p = lookup_device(kdev))) {	/* ok, item was found */
		if (new_p->head == item_p) {	/* item is head */
			if (new_p->tail == item_p) {	/* item is head and tail = only item -> list will be empty */
				new_p->head = NULL;
				new_p->tail = NULL;
			} else {	/* item is head, but not tail -> next item becomes head */
				item_p->next->prev = NULL;
				new_p->head = item_p->next;
			}
		} else {	/* item is not head */
			if (new_p->tail == item_p) {	/*item is not head, but tail -> previous item becomes tail */
				item_p->prev->next = NULL;
				new_p->tail = item_p->prev;
			} else {	/* item is neither head nor tail -> item is cut out */
				item_p->prev->next = item_p->next;
				item_p->next->prev = item_p->prev;
			}
		}

		/* curr is no longer valid -> reset.                              */
		new_p->curr = NULL;
		/* adjust counter */
		new_p->count--;
		rcu_assign_pointer(device_list_head_p, new_p);
		spin_unlock(&device_list_lock);
		synchronize_srcu(&device_list_srcu);
		rsbac_kfree(old_p);

		/* now we can remove the item from memory. This means cleaning up */
		/* everything below. */
		clear_device_item(item_p);
	}			/* end of if: item was found */
	else
		spin_unlock(&device_list_lock);
}				/* end of remove_device_item() */

/************************************************************************** */
/* The copy_fp_cap_set_item() function copies a file cap set to a process   */
/* cap set */

static int copy_fp_cap_set_item(struct rsbac_auth_device_list_item_t
				*device_p, rsbac_auth_file_t file,
				rsbac_pid_t pid)
{
	struct rsbac_auth_cap_range_t *cap_item_p;
	rsbac_time_t *ttl_p;
	int i;
	long count;
	enum rsbac_target_t target = T_FILE;
	union rsbac_target_id_t tid;

	rsbac_list_lol_remove(process_handle, &pid);
	count =
	    rsbac_list_lol_get_all_subdesc_ttl(device_p->handle,
					       &file.inode,
					       (void **) &cap_item_p,
					       &ttl_p);
	if (!count || (count == -RSBAC_ENOTFOUND)
	    ) {
		tid.file = file;
		if (!rsbac_get_parent(target, tid, &target, &tid))
			count =
			    rsbac_list_lol_get_all_subdesc_ttl(device_p->handle,
							       &tid.file.
							       inode,
							       (void **)
							       &cap_item_p,
							       &ttl_p);
	}
	if (count > 0) {
		for (i = 0; i < count; i++) {
			rsbac_list_lol_subadd_ttl(process_handle,
						  ttl_p[i],
						  &pid,
						  &cap_item_p[i], NULL);
		}
		rsbac_kfree(cap_item_p);
		rsbac_kfree(ttl_p);
	} else {
		if ((count < 0)
		    && (count != -RSBAC_ENOTFOUND)
		    )
			return count;
	}

#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
	rsbac_list_lol_remove(process_eff_handle, &pid);
	count =
	    rsbac_list_lol_get_all_subdesc_ttl(device_p->eff_handle,
					       &file.inode,
					       (void **) &cap_item_p,
					       &ttl_p);
	if (!count || (count == -RSBAC_ENOTFOUND)
	    ) {
		tid.file = file;
		if (!rsbac_get_parent(target, tid, &target, &tid))
			count =
			    rsbac_list_lol_get_all_subdesc_ttl(device_p->eff_handle,
							       &tid.file.
							       inode,
							       (void **)
							       &cap_item_p,
							       &ttl_p);
	}
	if (count > 0) {
		for (i = 0; i < count; i++) {
			rsbac_list_lol_subadd_ttl(process_eff_handle,
						  ttl_p[i],
						  &pid,
						  &cap_item_p[i], NULL);
		}
		rsbac_kfree(cap_item_p);
		rsbac_kfree(ttl_p);
	} else {
		if ((count < 0)
		    && (count != -RSBAC_ENOTFOUND)
		    )
			return count;
	}
	rsbac_list_lol_remove(process_fs_handle, &pid);
	count =
	    rsbac_list_lol_get_all_subdesc_ttl(device_p->fs_handle,
					       &file.inode,
					       (void **) &cap_item_p,
					       &ttl_p);
	if (!count || (count == -RSBAC_ENOTFOUND)
	    ) {
		tid.file = file;
		if (!rsbac_get_parent(target, tid, &target, &tid))
			count =
			    rsbac_list_lol_get_all_subdesc_ttl(device_p->fs_handle,
							       &tid.file.
							       inode,
							       (void **)
							       &cap_item_p,
							       &ttl_p);
	}
	if (count > 0) {
		for (i = 0; i < count; i++) {
			rsbac_list_lol_subadd_ttl(process_fs_handle,
						  ttl_p[i],
						  &pid,
						  &cap_item_p[i], NULL);
		}
		rsbac_kfree(cap_item_p);
		rsbac_kfree(ttl_p);
	} else {
		if ((count < 0)
		    && (count != -RSBAC_ENOTFOUND)
		    )
			return count;
	}
#endif

#ifdef CONFIG_RSBAC_AUTH_GROUP
	rsbac_list_lol_remove(process_group_handle, &pid);
	count =
	    rsbac_list_lol_get_all_subdesc_ttl(device_p->
					       group_handle,
					       &file.inode,
					       (void **) &cap_item_p,
					       &ttl_p);
	if (!count || (count == -RSBAC_ENOTFOUND)
	    ) {
		tid.file = file;
		if (!rsbac_get_parent(target, tid, &target, &tid))
			count =
			    rsbac_list_lol_get_all_subdesc_ttl(device_p->group_handle,
							       &tid.file.
							       inode,
							       (void **)
							       &cap_item_p,
							       &ttl_p);
	}
	if (count > 0) {
		for (i = 0; i < count; i++) {
			rsbac_list_lol_subadd_ttl(process_group_handle,
						  ttl_p[i],
						  &pid,
						  &cap_item_p[i], NULL);
		}
		rsbac_kfree(cap_item_p);
		rsbac_kfree(ttl_p);
	} else {
		if ((count < 0)
		    && (count != -RSBAC_ENOTFOUND)
		    )
			return count;
	}

#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
	rsbac_list_lol_remove(process_group_eff_handle, &pid);
	count =
	    rsbac_list_lol_get_all_subdesc_ttl(device_p->group_eff_handle,
						&file.inode,
						(void **) &cap_item_p,
						&ttl_p);
	if (!count || (count == -RSBAC_ENOTFOUND)
	    ) {
		tid.file = file;
		if (!rsbac_get_parent(target, tid, &target, &tid))
			count =
			    rsbac_list_lol_get_all_subdesc_ttl(device_p->group_eff_handle,
							       &tid.file.
							       inode,
							       (void **)
							       &cap_item_p,
							       &ttl_p);
	}
	if (count > 0) {
		for (i = 0; i < count; i++) {
			rsbac_list_lol_subadd_ttl(process_group_eff_handle,
						  ttl_p[i],
						  &pid,
						  &cap_item_p[i], NULL);
		}
		rsbac_kfree(cap_item_p);
		rsbac_kfree(ttl_p);
	} else {
		if ((count < 0)
		    && (count != -RSBAC_ENOTFOUND)
		    )
			return count;
	}
	rsbac_list_lol_remove(process_group_fs_handle, &pid);
	count =
	    rsbac_list_lol_get_all_subdesc_ttl(device_p->group_fs_handle,
						&file.inode,
						(void **) &cap_item_p,
						&ttl_p);
	if (!count || (count == -RSBAC_ENOTFOUND)
	    ) {
		tid.file = file;
		if (!rsbac_get_parent(target, tid, &target, &tid))
			count =
			    rsbac_list_lol_get_all_subdesc_ttl(device_p->group_fs_handle,
							       &tid.file.
							       inode,
							       (void **)
							       &cap_item_p,
							       &ttl_p);
	}
	if (count > 0) {
		for (i = 0; i < count; i++) {
			rsbac_list_lol_subadd_ttl(process_group_fs_handle,
						  ttl_p[i],
						  &pid,
						  &cap_item_p[i], NULL);
		}
		rsbac_kfree(cap_item_p);
		rsbac_kfree(ttl_p);
	} else {
		if ((count < 0)
		    && (count != -RSBAC_ENOTFOUND)
		    )
			return count;
	}
#endif
#endif				/* AUTH_GROUP */

	return 0;
}				/* end of copy_fp_cap_set_item() */

/************************************************************************** */
/* The copy_pp_cap_set_item() function copies a process cap set to another  */

static int copy_pp_cap_set_item_handle(rsbac_list_handle_t handle,
				       rsbac_pid_t old_pid,
				       rsbac_pid_t new_pid)
{
	struct rsbac_auth_cap_range_t *cap_item_p;
	rsbac_time_t *ttl_p;
	int i;
	long count;

	rsbac_list_lol_remove(handle, &new_pid);
	count = rsbac_list_lol_get_all_subdesc_ttl(handle,
						   &old_pid,
						   (void **) &cap_item_p,
						   &ttl_p);
	if (count > 0) {
		for (i = 0; i < count; i++) {
			rsbac_list_lol_subadd_ttl(handle,
						  ttl_p[i],
						  &new_pid,
						  &cap_item_p[i], NULL);
		}
		rsbac_kfree(cap_item_p);
		rsbac_kfree(ttl_p);
	} else {
		if (count < 0)
			return count;
	}
	return 0;
}

static int copy_pp_cap_set_item(rsbac_pid_t old_pid, rsbac_pid_t new_pid)
{
	int res;

	res =
	    copy_pp_cap_set_item_handle(process_handle, old_pid, new_pid);

#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
	if (res)
		return res;
	res =
	    copy_pp_cap_set_item_handle(process_eff_handle, old_pid,
					new_pid);
	if (res)
		return res;
	res =
	    copy_pp_cap_set_item_handle(process_fs_handle, old_pid,
					new_pid);
#endif

#ifdef CONFIG_RSBAC_AUTH_GROUP
	res =
	    copy_pp_cap_set_item_handle(process_group_handle, old_pid,
					new_pid);

#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
	if (res)
		return res;
	res =
	    copy_pp_cap_set_item_handle(process_group_eff_handle, old_pid,
					new_pid);
	if (res)
		return res;
	res =
	    copy_pp_cap_set_item_handle(process_group_fs_handle, old_pid,
					new_pid);
#endif
#endif

	return res;
}				/* end of copy_pp_cap_set_item() */

/************************************************* */
/*               proc functions                    */
/************************************************* */

#if defined(CONFIG_RSBAC_PROC) && defined(CONFIG_PROC_FS)
static int
auth_devices_proc_show(struct seq_file *m, void *v)
{
	struct rsbac_auth_device_list_item_t *device_p;
	int srcu_idx;

	if (!rsbac_is_initialized())
		return -ENOSYS;

	seq_printf(m,
		    "%u RSBAC AUTH Devices\n--------------------\n",
		    rcu_dereference(device_list_head_p)->count);

	srcu_idx = srcu_read_lock(&device_list_srcu);
	for (device_p = rcu_dereference(device_list_head_p)->head; device_p;
	     device_p = device_p->next) {
		seq_printf(m,
			    "%02u:%02u with mount_count = %u\n",
			    RSBAC_MAJOR(device_p->id),
			    RSBAC_MINOR(device_p->id),
			    device_p->mount_count);
	}

	srcu_read_unlock(&device_list_srcu, srcu_idx);

	return 0;
}

static int auth_devices_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, auth_devices_proc_show, NULL);
}

static const struct file_operations auth_devices_proc_fops = {
       .owner          = THIS_MODULE,
       .open           = auth_devices_proc_open,
       .read           = seq_read,
       .llseek         = seq_lseek,
       .release        = single_release,
};

static struct proc_dir_entry *auth_devices;

static int
stats_auth_proc_show(struct seq_file *m, void *v)
{
	u_int cap_set_count = 0;
	u_int member_count = 0;
	struct rsbac_auth_device_list_item_t *device_p;
	int srcu_idx;

	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "stats_auth_proc_info(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	rsbac_pr_debug(aef_auth, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	seq_printf(m, "AUTH Status\n-----------\n");

	seq_printf(m,
		    "%lu process cap set items, sum of %lu members\n",
		    rsbac_list_lol_count(process_handle),
		    rsbac_list_lol_all_subcount(process_handle));
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
	seq_printf(m,
		    "%lu process eff cap set items, sum of %lu members\n",
		    rsbac_list_lol_count(process_eff_handle),
		    rsbac_list_lol_all_subcount(process_eff_handle));
	seq_printf(m,
		    "%lu process fs cap set items, sum of %lu members\n",
		    rsbac_list_lol_count(process_fs_handle),
		    rsbac_list_lol_all_subcount(process_fs_handle));
#endif

#ifdef CONFIG_RSBAC_AUTH_GROUP
	seq_printf(m,
		    "%lu process group cap set items, sum of %lu members\n",
		    rsbac_list_lol_count(process_group_handle),
		    rsbac_list_lol_all_subcount(process_group_handle));
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
	seq_printf(m,
		    "%lu process group eff cap set items, sum of %lu members\n",
		    rsbac_list_lol_count(process_group_eff_handle),
		    rsbac_list_lol_all_subcount(process_group_eff_handle));
	seq_printf(m,
		    "%lu process group fs cap set items, sum of %lu members\n",
		    rsbac_list_lol_count(process_group_fs_handle),
		    rsbac_list_lol_all_subcount(process_group_fs_handle));
#endif
#endif				/* AUTH_GROUP */

	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = rcu_dereference(device_list_head_p)->head;
	while (device_p) {
		/* reset counters */
		cap_set_count = rsbac_list_lol_count(device_p->handle);
		member_count = rsbac_list_lol_all_subcount(device_p->handle);
		seq_printf(m,
			    "device %02u:%02u has %u file cap set items, sum of %u members\n",
			    RSBAC_MAJOR(device_p->id),
			    RSBAC_MINOR(device_p->id), cap_set_count,
			    member_count);
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
		cap_set_count = rsbac_list_lol_count(device_p->eff_handle);
		member_count = rsbac_list_lol_all_subcount(device_p->eff_handle);
		seq_printf(m,
			    "device %02u:%02u has %u file eff cap set items, sum of %u members\n",
			    RSBAC_MAJOR(device_p->id),
			    RSBAC_MINOR(device_p->id), cap_set_count,
			    member_count);
		cap_set_count = rsbac_list_lol_count(device_p->fs_handle);
		member_count = rsbac_list_lol_all_subcount(device_p->fs_handle);
		seq_printf(m,
			    "device %02u:%02u has %u file fs cap set items, sum of %u members\n",
			    RSBAC_MAJOR(device_p->id),
			    RSBAC_MINOR(device_p->id), cap_set_count,
			    member_count);
#endif

#ifdef CONFIG_RSBAC_AUTH_GROUP
		cap_set_count = rsbac_list_lol_count(device_p->group_handle);
		member_count = rsbac_list_lol_all_subcount(device_p->group_handle);
		seq_printf(m,
			    "device %02u:%02u has %u file group cap set items, sum of %u members\n",
			    RSBAC_MAJOR(device_p->id),
			    RSBAC_MINOR(device_p->id), cap_set_count,
			    member_count);
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
		cap_set_count = rsbac_list_lol_count(device_p->group_eff_handle);
		member_count = rsbac_list_lol_all_subcount(device_p->group_eff_handle);
		seq_printf(m,
			    "device %02u:%02u has %u file group eff cap set items, sum of %u members\n",
			    RSBAC_MAJOR(device_p->id),
			    RSBAC_MINOR(device_p->id), cap_set_count,
			    member_count);
		cap_set_count = rsbac_list_lol_count(device_p->group_fs_handle);
		member_count = rsbac_list_lol_all_subcount(device_p->group_fs_handle);
		seq_printf(m,
			    "device %02u:%02u has %u file group fs cap set items, sum of %u members\n",
			    RSBAC_MAJOR(device_p->id),
			    RSBAC_MINOR(device_p->id), cap_set_count,
			    member_count);
#endif
#endif				/* AUTH_GROUP */

		device_p = device_p->next;
	}
	srcu_read_unlock(&device_list_srcu, srcu_idx);

	return 0;
}

static int stats_auth_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, stats_auth_proc_show, NULL);
}

static const struct file_operations stats_auth_proc_fops = {
       .owner          = THIS_MODULE,
       .open           = stats_auth_proc_open,
       .read           = seq_read,
       .llseek         = seq_lseek,
       .release        = single_release,
};

static struct proc_dir_entry *stats_auth;

static int
auth_caplist_proc_show(struct seq_file *m, void *v)
{
	u_int count = 0;
	u_int member_count = 0;
	u_long all_count;
	u_long all_member_count;
	int i, j;
	struct rsbac_auth_device_list_item_t *device_p;
	rsbac_pid_t *p_list;
	rsbac_inode_nr_t *f_list;
	struct rsbac_auth_cap_range_t *cap_list;
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "auth_caplist_proc_info(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	rsbac_pr_debug(aef_auth, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	seq_printf(m, "AUTH Cap Lists\n--------------\n");

	seq_printf(m,
		    "Process capabilities:\nset-id  count   cap-members");
	all_member_count = 0;
	count = rsbac_list_lol_get_all_desc(process_handle,
					    (void **) &p_list);
	if (count > 0) {
		for (i = 0; i < count; i++) {
			member_count =
			    rsbac_list_lol_get_all_subdesc(process_handle,
							   &p_list[i],
							   (void **)
							   &cap_list);
			seq_printf(m, "\n %u\t%u\t", pid_vnr(p_list[i]),
				    member_count);
			if (member_count > 0) {
				for (j = 0; j < member_count; j++) {
					if (cap_list[j].first !=
					    cap_list[j].last) {
					    
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first)
						    || RSBAC_UID_SET(cap_list[j].last)
						   )
						    seq_printf(m,
							    "%u/%u:%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_SET(cap_list[j].last),
							    RSBAC_UID_NUM(cap_list[j].last));
						else
#endif
						   seq_printf(m,
							    "%u:%u ",
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].last));
					} else {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first))
						    seq_printf(m,
							    "%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first));
						else
#endif
						    seq_printf(m,
							    "%u ",
							    RSBAC_UID_NUM(cap_list[j].first));
					}
				}
				rsbac_kfree(cap_list);
				all_member_count += member_count;
			}
		}
		rsbac_kfree(p_list);
	}
	seq_printf(m,
		    "\n%u process cap set items, sum of %lu members\n",
		    count, all_member_count);
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
	seq_printf(m,
		    "\nProcess eff capabilities:\nset-id  count   cap-members");

	all_member_count = 0;
	count = rsbac_list_lol_get_all_desc(process_eff_handle,
					    (void **) &p_list);
	if (count > 0) {
		for (i = 0; i < count; i++) {
			member_count =
			    rsbac_list_lol_get_all_subdesc
			    (process_eff_handle, &p_list[i],
			     (void **) &cap_list);
			seq_printf(m, "\n %u\t%u\t", pid_vnr(p_list[i]),
				    member_count);
			if (member_count > 0) {
				for (j = 0; j < member_count; j++) {
					if (cap_list[j].first !=
					    cap_list[j].last) {
					    
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first)
						    || RSBAC_UID_SET(cap_list[j].last)
						   )
						    seq_printf(m,
							    "%u/%u:%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_SET(cap_list[j].last),
							    RSBAC_UID_NUM(cap_list[j].last));
						else
#endif
						    seq_printf(m,
							    "%u:%u ",
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].last));
					} else {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first))
						    seq_printf(m,
							    "%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first));
						else
#endif
						    seq_printf(m,
							    "%u ",
							    RSBAC_UID_NUM(cap_list[j].first));
					}
				}
				rsbac_kfree(cap_list);
				all_member_count += member_count;
			}
		}
		rsbac_kfree(p_list);
	}
	seq_printf(m,
		    "\n%u process eff cap set items, sum of %lu members\n",
		    count, all_member_count);
	seq_printf(m,
		    "\nProcess fs capabilities:\nset-id  count   cap-members");

	all_member_count = 0;
	count = rsbac_list_lol_get_all_desc(process_fs_handle,
					    (void **) &p_list);
	if (count > 0) {
		for (i = 0; i < count; i++) {
			member_count =
			    rsbac_list_lol_get_all_subdesc
			    (process_fs_handle, &p_list[i],
			     (void **) &cap_list);
			seq_printf(m, "\n %u\t%u\t", pid_vnr(p_list[i]),
				    member_count);
			if (member_count > 0) {
				for (j = 0; j < member_count; j++) {
					if (cap_list[j].first !=
					    cap_list[j].last) {
					    
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first)
						    || RSBAC_UID_SET(cap_list[j].last)
						   )
						   seq_printf(m,
							    "%u/%u:%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_SET(cap_list[j].last),
							    RSBAC_UID_NUM(cap_list[j].last));
						else
#endif
						    seq_printf(m,
							    "%u:%u ",
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].last));
					} else {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first))
						    seq_printf(m,
							    "%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first));
						else
#endif
						    seq_printf(m,
							    "%u ",
							    RSBAC_UID_NUM(cap_list[j].first));
					}
				}
				rsbac_kfree(cap_list);
				all_member_count += member_count;
			}
		}
		rsbac_kfree(p_list);
	}
	seq_printf(m,
		    "\n\n%u process fs cap set items, sum of %lu members\n",
		    count, all_member_count);
#endif

#ifdef CONFIG_RSBAC_AUTH_GROUP
	seq_printf(m,
		    "\nProcess group capabilities:\nset-id  count   cap-members");
	all_member_count = 0;
	count = rsbac_list_lol_get_all_desc(process_group_handle,
					    (void **) &p_list);
	if (count > 0) {
		for (i = 0; i < count; i++) {
			member_count =
			    rsbac_list_lol_get_all_subdesc
			    (process_group_handle, &p_list[i],
			     (void **) &cap_list);
			    seq_printf(m, "\n %u\t%u\t", pid_vnr(p_list[i]),
				    member_count);
			if (member_count > 0) {
				for (j = 0; j < member_count; j++) {
					if (cap_list[j].first !=
					    cap_list[j].last) {
					    
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first)
						    || RSBAC_UID_SET(cap_list[j].last)
						   )
						    seq_printf(m,
							    "%u/%u:%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_SET(cap_list[j].last),
							    RSBAC_UID_NUM(cap_list[j].last));
						else
#endif
						    seq_printf(m,
							    "%u:%u ",
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].last));
					} else {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first))
						    seq_printf(m,
							    "%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first));
						else
#endif
						    seq_printf(m,
							    "%u ",
							    RSBAC_UID_NUM(cap_list[j].first));
					}
				}
				rsbac_kfree(cap_list);
				all_member_count += member_count;
			}
		}
		rsbac_kfree(p_list);
	}
	seq_printf(m,
		    "\n%u process group cap set items, sum of %lu members\n",
		    count, all_member_count);

#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
	seq_printf(m,
		    "\nProcess group eff capabilities:\nset-id  count   cap-members");
	all_member_count = 0;
	count = rsbac_list_lol_get_all_desc(process_group_eff_handle,
					    (void **) &p_list);
	if (count > 0) {
		for (i = 0; i < count; i++) {
			member_count =
			    rsbac_list_lol_get_all_subdesc
			    (process_group_eff_handle, &p_list[i],
			     (void **) &cap_list);
			seq_printf(m, "\n %u\t%u\t", pid_vnr(p_list[i]),
				    member_count);
			if (member_count > 0) {
				for (j = 0; j < member_count; j++) {
					if (cap_list[j].first !=
					    cap_list[j].last) {
					    
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first)
						    || RSBAC_UID_SET(cap_list[j].last)
						   )
						    seq_printf(m,
							    "%u/%u:%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_SET(cap_list[j].last),
							    RSBAC_UID_NUM(cap_list[j].last));
						else
#endif
						    seq_printf(m,
							    "%u:%u ",
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].last));
					} else {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first))
						    seq_printf(m,
							    "%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first));
						else
#endif
						    seq_printf(m,
							    "%u ",
							    RSBAC_UID_NUM(cap_list[j].first));
					}
				}
				rsbac_kfree(cap_list);
				all_member_count += member_count;
			}
		}
		rsbac_kfree(p_list);
	}
	seq_printf(m,
		    "\n%u process group eff cap set items, sum of %lu members\n",
		    count, all_member_count);
	seq_printf(m,
		    "\nProcess group fs capabilities:\nset-id  count   cap-members");

	all_member_count = 0;
	count = rsbac_list_lol_get_all_desc(process_group_fs_handle,
					    (void **) &p_list);
	if (count > 0) {
		for (i = 0; i < count; i++) {
			member_count =
			    rsbac_list_lol_get_all_subdesc
			    (process_group_fs_handle, &p_list[i],
			     (void **) &cap_list);
			    seq_printf(m, "\n %u\t%u\t", pid_vnr(p_list[i]),
				    member_count);
			if (member_count > 0) {
				for (j = 0; j < member_count; j++) {
					if (cap_list[j].first !=
					    cap_list[j].last) {
					    
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first)
						    || RSBAC_UID_SET(cap_list[j].last)
						   )
						    seq_printf(m,
							    "%u/%u:%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_SET(cap_list[j].last),
							    RSBAC_UID_NUM(cap_list[j].last));
						else
#endif
						    seq_printf(m,
							    "%u:%u ",
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].last));
					} else {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first))
						    seq_printf(m,
							    "%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first));
						else
#endif
						    seq_printf(m,
							    "%u ",
							    RSBAC_UID_NUM(cap_list[j].first));
					}
				}
				rsbac_kfree(cap_list);
				all_member_count += member_count;
			}
		}
		rsbac_kfree(p_list);
	}
	seq_printf(m,
		    "\n\n%u process group fs cap set items, sum of %lu members\n",
		    count, all_member_count);
#endif
#endif				/* AUTH_GROUP */

	seq_printf(m,
		    "\nFile capabilities:\nset-id  count   cap-members");

	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = rcu_dereference(device_list_head_p)->head;
	while (device_p) {
		/* reset counters */
		all_member_count = 0;
		all_count = 0;
		count = rsbac_list_lol_get_all_desc(device_p->handle,
							(void **) &f_list);
		if (count > 0) {
			for (i = 0; i < count; i++) {
				member_count =
				    rsbac_list_lol_get_all_subdesc
					    (device_p->handle,
					     &f_list[i],
					     (void **) &cap_list);
				seq_printf(m,
					    "\n %u\t%u\t",
					    f_list[i],
					    member_count);
				if (member_count > 0) {
					for (j = 0;
					     j < member_count;
					     j++) {
						if (cap_list[j].
						    first !=
						    cap_list[j].
						    last) {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						    if (RSBAC_UID_SET(cap_list[j].first)
						        || RSBAC_UID_SET(cap_list[j].last)
						       )
						          seq_printf(m,
							    "%u/%u:%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_SET(cap_list[j].last),
							    RSBAC_UID_NUM(cap_list[j].last));
						    else
#endif
							  seq_printf
							    (m,
							     "%u:%u ",
							     RSBAC_UID_NUM(cap_list[j].first),
							     RSBAC_UID_NUM(cap_list[j].last));
						} else {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
							if (RSBAC_UID_SET(cap_list[j].first))
							    seq_printf(m,
							    "%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first));
							else
#endif
							  seq_printf(m,
							    "%u ",
							    RSBAC_UID_NUM(cap_list[j].first));
						}
					}
					rsbac_kfree(cap_list);
					all_member_count +=
					    member_count;
				}
			}
			rsbac_kfree(f_list);
			all_count += count;
		}
		seq_printf(m,
			    "\ndevice %02u:%02u has %lu file cap set items, sum of %lu members, list is clean\n",
			    RSBAC_MAJOR(device_p->id),
			    RSBAC_MINOR(device_p->id), all_count,
			    all_member_count);
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
		all_member_count = 0;
		all_count = 0;
		count =
		    rsbac_list_lol_get_all_desc(device_p->eff_handle,
						(void **) &f_list);
		if (count > 0) {
			for (i = 0; i < count; i++) {
				member_count =
				    rsbac_list_lol_get_all_subdesc
				    (device_p->eff_handle,
				     &f_list[i],
				     (void **) &cap_list);
				    seq_printf(m,
					    "\n %u\t%u\t",
					    f_list[i],
					    member_count);
				if (member_count > 0) {
					for (j = 0;
					     j < member_count;
					     j++) {
					if (cap_list[j].first !=
					    cap_list[j].last) {
					    
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first)
						    || RSBAC_UID_SET(cap_list[j].last)
						   )
						    seq_printf(m,
							    "%u/%u:%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_SET(cap_list[j].last),
							    RSBAC_UID_NUM(cap_list[j].last));
						else
#endif
						    seq_printf(m,
							    "%u:%u ",
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].last));
					} else {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first))
						    seq_printf(m,
							    "%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first));
						else
#endif
						    seq_printf(m,
							    "%u ",
							    RSBAC_UID_NUM(cap_list[j].first));
					}
					}
					rsbac_kfree(cap_list);
					all_member_count +=
					    member_count;
				}
			}
			rsbac_kfree(f_list);
			all_count += count;
		}
		seq_printf(m,
			    "\ndevice %02u:%02u has %lu file eff cap set items, sum of %lu members, list is clean\n",
			    RSBAC_MAJOR(device_p->id),
			    RSBAC_MINOR(device_p->id), all_count,
			    all_member_count);
		all_member_count = 0;
		all_count = 0;
		count =
		    rsbac_list_lol_get_all_desc(device_p->
						fs_handle,
						(void **) &f_list);
		if (count > 0) {
			for (i = 0; i < count; i++) {
				member_count =
				    rsbac_list_lol_get_all_subdesc
				    (device_p->fs_handle,
				     &f_list[i],
				     (void **) &cap_list);
				    seq_printf(m,
					    "\n %u\t%u\t",
					    f_list[i],
					    member_count);
				if (member_count > 0) {
					for (j = 0;
					     j < member_count;
					     j++) {
					if (cap_list[j].first !=
					    cap_list[j].last) {
					    
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first)
						    || RSBAC_UID_SET(cap_list[j].last)
						   )
						    seq_printf(m,
							    "%u/%u:%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_SET(cap_list[j].last),
							    RSBAC_UID_NUM(cap_list[j].last));
						else
#endif
						    seq_printf(m,
							    "%u:%u ",
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].last));
					} else {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first))
						    seq_printf(m,
							    "%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first));
						else
#endif
						    seq_printf(m,
							    "%u ",
							    RSBAC_UID_NUM(cap_list[j].first));
					}
					}
					rsbac_kfree(cap_list);
					all_member_count +=
					    member_count;
				}
			}
			rsbac_kfree(f_list);
			all_count += count;
		}
		seq_printf(m,
			    "\ndevice %02u:%02u has %lu file fs cap set items, sum of %lu members, list is clean\n",
			    RSBAC_MAJOR(device_p->id),
			    RSBAC_MINOR(device_p->id), all_count,
			    all_member_count);
#endif

#ifdef CONFIG_RSBAC_AUTH_GROUP
		all_member_count = 0;
		all_count = 0;
		count =
		    rsbac_list_lol_get_all_desc(device_p->
						group_handle,
						(void **) &f_list);
		if (count > 0) {
			for (i = 0; i < count; i++) {
				member_count =
				    rsbac_list_lol_get_all_subdesc
				    (device_p->group_handle,
				     &f_list[i],
				     (void **) &cap_list);
				seq_printf(m,
					    "\n %u\t%u\t",
					    f_list[i],
					    member_count);
				if (member_count > 0) {
					for (j = 0;
					     j < member_count;
					     j++) {
					if (cap_list[j].first !=
					    cap_list[j].last) {
					    
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first)
						    || RSBAC_UID_SET(cap_list[j].last)
						   )
						    seq_printf(m,
							    "%u/%u:%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_SET(cap_list[j].last),
							    RSBAC_UID_NUM(cap_list[j].last));
						else
#endif
						    seq_printf(m,
							    "%u:%u ",
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].last));
					} else {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first))
						    seq_printf(m,
							    "%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first));
						else
#endif
						    seq_printf(m,
							    "%u ",
							    RSBAC_UID_NUM(cap_list[j].first));
					}
					}
					rsbac_kfree(cap_list);
					all_member_count +=
					    member_count;
				}
			}
			rsbac_kfree(f_list);
			all_count += count;
		}
		seq_printf(m,
			    "\ndevice %02u:%02u has %lu file group cap set items, sum of %lu members, list is clean\n",
			    RSBAC_MAJOR(device_p->id),
			    RSBAC_MINOR(device_p->id), all_count,
			    all_member_count);
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
		all_member_count = 0;
		all_count = 0;
		count = rsbac_list_lol_get_all_desc(device_p->
						group_eff_handle,
						(void **) &f_list);
		if (count > 0) {
			for (i = 0; i < count; i++) {
				member_count =
				    rsbac_list_lol_get_all_subdesc
				    (device_p->group_eff_handle,
				     &f_list[i],
				     (void **) &cap_list);
				seq_printf(m,
					    "\n %u\t%u\t",
					    f_list[i],
					    member_count);
				if (member_count > 0) {
					for (j = 0;
					     j < member_count;
					     j++) {
					if (cap_list[j].first !=
					    cap_list[j].last) {
					    
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first)
						    || RSBAC_UID_SET(cap_list[j].last)
						   )
						    seq_printf(m,
							    "%u/%u:%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_SET(cap_list[j].last),
							    RSBAC_UID_NUM(cap_list[j].last));
						else
#endif
						    seq_printf(m,
							    "%u:%u ",
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].last));
					} else {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first))
						    seq_printf(m,
							    "%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first));
						else
#endif
						    seq_printf(m,
							    "%u ",
							    RSBAC_UID_NUM(cap_list[j].first));
					}
					}
					rsbac_kfree(cap_list);
					all_member_count +=
					    member_count;
				}
			}
			rsbac_kfree(f_list);
			all_count += count;
		}
		seq_printf(m,
			    "\ndevice %02u:%02u has %lu file group eff cap set items, sum of %lu members, list is clean\n",
			    RSBAC_MAJOR(device_p->id),
			    RSBAC_MINOR(device_p->id), all_count,
			    all_member_count);
		all_member_count = 0;
		all_count = 0;
		count = rsbac_list_lol_get_all_desc(device_p->
						group_fs_handle,
						(void **) &f_list);
		if (count > 0) {
			for (i = 0; i < count; i++) {
				member_count =
				    rsbac_list_lol_get_all_subdesc
				    (device_p->group_fs_handle,
				     &f_list[i],
				     (void **) &cap_list);
				seq_printf(m,
					    "\n %u\t%u\t",
					    f_list[i],
					    member_count);
				if (member_count > 0) {
					for (j = 0;
					     j < member_count;
					     j++) {
					if (cap_list[j].first !=
					    cap_list[j].last) {
					    
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first)
						    || RSBAC_UID_SET(cap_list[j].last)
						   )
						    seq_printf(m,
							    "%u/%u:%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_SET(cap_list[j].last),
							    RSBAC_UID_NUM(cap_list[j].last));
						else
#endif
						    seq_printf(m,
							    "%u:%u ",
							    RSBAC_UID_NUM(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].last));
					} else {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
						if (RSBAC_UID_SET(cap_list[j].first))
						    seq_printf(m,
							    "%u/%u ",
							    RSBAC_UID_SET(cap_list[j].first),
							    RSBAC_UID_NUM(cap_list[j].first));
						else
#endif
						    seq_printf(m,
							    "%u ",
							    RSBAC_UID_NUM(cap_list[j].first));
					}
					}
					rsbac_kfree(cap_list);
					all_member_count +=
					    member_count;
				}
			}
			rsbac_kfree(f_list);
			all_count += count;
		}
		seq_printf(m,
			    "\ndevice %02u:%02u has %lu file group fs cap set items, sum of %lu members, list is clean\n",
			    RSBAC_MAJOR(device_p->id),
			    RSBAC_MINOR(device_p->id), all_count,
			    all_member_count);
#endif
#endif				/* AUTH_GROUP */

		device_p = device_p->next;
	}
	srcu_read_unlock(&device_list_srcu, srcu_idx);

	return 0;
}

static int auth_caplist_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, auth_caplist_proc_show, NULL);
}

static const struct file_operations auth_caplist_proc_fops = {
       .owner          = THIS_MODULE,
       .open           = auth_caplist_proc_open,
       .read           = seq_read,
       .llseek         = seq_lseek,
       .release        = single_release,
};

static struct proc_dir_entry *auth_caplist;
#endif				/* CONFIG_PROC_FS && CONFIG_RSBAC_PROC */

/************************************************* */
/*               Init functions                    */
/************************************************* */

/* All functions return 0, if no error occurred, and a negative error code  */
/* otherwise. The error codes are defined in rsbac/error.h.                 */

/************************************************************************** */
/* Initialization of all AUTH data structures. After this call, all AUTH    */
/* data is kept in memory for performance reasons, but is written to disk   */
/* on every change. */

/* Because there can be no access to aci data structures before init,       */
/* rsbac_init_auth() will initialize all rw-spinlocks to unlocked.          */

#ifdef CONFIG_RSBAC_INIT_DELAY
int rsbac_init_auth(void)
#else
int __init rsbac_init_auth(void)
#endif
{
	int err = 0;
	struct rsbac_auth_device_list_item_t *device_p = NULL;
	struct rsbac_list_lol_info_t lol_info;

	if (rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_init_auth(): RSBAC already initialized\n");
		return -RSBAC_EREINIT;
	}

	rsbac_printk(KERN_INFO "rsbac_init_auth(): Initializing RSBAC: AUTH subsystem\n");

	lol_info.version = RSBAC_AUTH_P_LIST_VERSION;
	lol_info.key = RSBAC_AUTH_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_pid_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(struct rsbac_auth_cap_range_t);
	lol_info.subdata_size = 0;
	lol_info.max_age = 0;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &process_handle,
				      &lol_info,
				      RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
				      NULL,
				      cap_compare,
				      NULL,
				      NULL,
				      NULL,
				      NULL,
				      RSBAC_AUTH_P_LIST_NAME,
				      RSBAC_AUTO_DEV,
				      RSBAC_LIST_MIN_MAX_HASHES,
				      rsbac_list_hash_pid,
				      NULL);
	if (err) {
		char *tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

		if (tmp) {
			rsbac_printk(KERN_WARNING "rsbac_init_auth(): Registering AUTH process cap list failed with error %s\n",
				     get_error_name(tmp, err));
			rsbac_kfree(tmp);
		}
	}
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
	lol_info.version = RSBAC_AUTH_P_LIST_VERSION;
	lol_info.key = RSBAC_AUTH_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_pid_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(struct rsbac_auth_cap_range_t);
	lol_info.subdata_size = 0;
	lol_info.max_age = 0;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &process_eff_handle,
				      &lol_info,
				      RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
				      NULL,
				      cap_compare,
				      NULL,
				      NULL,
				      NULL,
				      NULL,
				      RSBAC_AUTH_P_EFF_LIST_NAME,
				      RSBAC_AUTO_DEV,
				      RSBAC_LIST_MIN_MAX_HASHES,
				      rsbac_list_hash_pid,
				      NULL);
	if (err) {
		char *tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

		if (tmp) {
			rsbac_printk(KERN_WARNING "rsbac_init_auth(): Registering AUTH process eff cap list failed with error %s\n",
				     get_error_name(tmp, err));
			rsbac_kfree(tmp);
		}
	}
	lol_info.version = RSBAC_AUTH_P_LIST_VERSION;
	lol_info.key = RSBAC_AUTH_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_pid_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(struct rsbac_auth_cap_range_t);
	lol_info.subdata_size = 0;
	lol_info.max_age = 0;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &process_fs_handle,
				      &lol_info,
				      RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
				      NULL,
				      cap_compare,
				      NULL,
				      NULL,
				      NULL,
				      NULL,
				      RSBAC_AUTH_P_FS_LIST_NAME,
				      RSBAC_AUTO_DEV,
				      RSBAC_LIST_MIN_MAX_HASHES,
				      rsbac_list_hash_pid,
				      NULL);
	if (err) {
		char *tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

		if (tmp) {
			rsbac_printk(KERN_WARNING "rsbac_init_auth(): Registering AUTH process fs cap list failed with error %s\n",
				     get_error_name(tmp, err));
			rsbac_kfree(tmp);
		}
	}
#endif

#ifdef CONFIG_RSBAC_AUTH_GROUP
	lol_info.version = RSBAC_AUTH_P_LIST_VERSION;
	lol_info.key = RSBAC_AUTH_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_pid_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(struct rsbac_auth_cap_range_t);
	lol_info.subdata_size = 0;
	lol_info.max_age = 0;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &process_group_handle,
				      &lol_info,
				      RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
				      NULL,
				      cap_compare,
				      NULL,
				      NULL,
				      NULL,
				      NULL,
				      RSBAC_AUTH_P_GROUP_LIST_NAME,
				      RSBAC_AUTO_DEV,
				      RSBAC_LIST_MIN_MAX_HASHES,
				      rsbac_list_hash_pid,
				      NULL);
	if (err) {
		char *tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

		if (tmp) {
			rsbac_printk(KERN_WARNING "rsbac_init_auth(): Registering AUTH process group cap list failed with error %s\n",
				     get_error_name(tmp, err));
			rsbac_kfree(tmp);
		}
	}
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
	lol_info.version = RSBAC_AUTH_P_LIST_VERSION;
	lol_info.key = RSBAC_AUTH_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_pid_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(struct rsbac_auth_cap_range_t);
	lol_info.subdata_size = 0;
	lol_info.max_age = 0;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &process_group_eff_handle,
				      &lol_info,
				      RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
				      NULL,
				      cap_compare,
				      NULL,
				      NULL,
				      NULL,
				      NULL,
				      RSBAC_AUTH_P_GROUP_EFF_LIST_NAME,
				      RSBAC_AUTO_DEV,
				      RSBAC_LIST_MIN_MAX_HASHES,
				      rsbac_list_hash_pid,
				      NULL);
	if (err) {
		char *tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

		if (tmp) {
			rsbac_printk(KERN_WARNING "rsbac_init_auth(): Registering AUTH process group eff cap list failed with error %s\n",
				     get_error_name(tmp, err));
			rsbac_kfree(tmp);
		}
	}
	lol_info.version = RSBAC_AUTH_P_LIST_VERSION;
	lol_info.key = RSBAC_AUTH_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_pid_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(struct rsbac_auth_cap_range_t);
	lol_info.subdata_size = 0;
	lol_info.max_age = 0;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &process_group_fs_handle,
				      &lol_info,
				      RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
				      NULL,
				      cap_compare,
				      NULL,
				      NULL,
				      NULL,
				      NULL,
				      RSBAC_AUTH_P_GROUP_FS_LIST_NAME,
				      RSBAC_AUTO_DEV,
				      RSBAC_LIST_MIN_MAX_HASHES,
				      rsbac_list_hash_pid,
				      NULL);
	if (err) {
		char *tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

		if (tmp) {
			rsbac_printk(KERN_WARNING "rsbac_init_auth(): Registering AUTH process group fs cap list failed with error %s\n",
				     get_error_name(tmp, err));
			rsbac_kfree(tmp);
		}
	}
#endif
#endif				/* AUTH_GROUP */

	auth_device_item_slab = rsbac_slab_create("rsbac_auth_device_item",
					sizeof(struct rsbac_auth_device_list_item_t));

	/* Init FD lists */
	device_list_head_p = kmalloc(sizeof(*device_list_head_p), GFP_KERNEL);
	if (!device_list_head_p) {
		rsbac_printk(KERN_WARNING
			"rsbac_init_auth(): Failed to allocate device_list_head\n");
		return -ENOMEM;
	}
	spin_lock_init(&device_list_lock);
	init_srcu_struct(&device_list_srcu);
	lockdep_set_class(&device_list_lock, &device_list_lock_class);
	device_list_head_p->head = NULL;
	device_list_head_p->tail = NULL;
	device_list_head_p->curr = NULL;
	device_list_head_p->count = 0;

	/* read all data */
	rsbac_pr_debug(ds_auth, "rsbac_init_auth(): Registering FD lists\n");
	device_p = create_device_item(rsbac_root_dev);
	if (!device_p) {
		rsbac_printk(KERN_CRIT
			     "rsbac_init_auth(): Could not add device!\n");
		return -RSBAC_ECOULDNOTADDDEVICE;
	}
	if ((err = auth_register_fd_lists(device_p, rsbac_root_dev))) {
		char tmp[RSBAC_MAXNAMELEN];

		rsbac_printk(KERN_WARNING "rsbac_init_auth(): File/Dir cap set registration failed for dev %02u:%02u, err %s!\n",
			     RSBAC_MAJOR(rsbac_root_dev),
			     RSBAC_MINOR(rsbac_root_dev),
			     get_error_name(tmp, err));
	}
	device_p = add_device_item(device_p);
	if (!device_p) {
		rsbac_printk(KERN_CRIT
			     "rsbac_init_auth(): Could not add device!\n");
		return -RSBAC_ECOULDNOTADDDEVICE;
	}
#if defined(CONFIG_RSBAC_PROC) && defined(CONFIG_PROC_FS)
	auth_devices = proc_create("auth_devices",
					S_IFREG | S_IRUGO,
					proc_rsbac_root_p,
					&auth_devices_proc_fops);
	stats_auth = proc_create("stats_auth",
					S_IFREG | S_IRUGO,
					proc_rsbac_root_p,
					&stats_auth_proc_fops);
	auth_caplist = proc_create("auth_caplist",
					S_IFREG | S_IRUGO,
					proc_rsbac_root_p,
					&auth_caplist_proc_fops);
#endif

	rsbac_pr_debug(ds_auth, "Ready.\n");
	return err;
}

int rsbac_mount_auth(kdev_t kdev)
{
	int err = 0;
	struct rsbac_auth_device_list_item_t *device_p;
	struct rsbac_auth_device_list_item_t *new_device_p;
	int srcu_idx;

	rsbac_pr_debug(ds_auth, "mounting device %02u:%02u\n",
		       RSBAC_MAJOR(kdev), RSBAC_MINOR(kdev));
	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = lookup_device(kdev);
	/* repeated mount? */
	if (device_p) {
		rsbac_printk(KERN_WARNING "rsbac_mount_auth: repeated mount %u of device %02u:%02u\n",
			     device_p->mount_count, RSBAC_MAJOR(kdev),
			     RSBAC_MINOR(kdev));
		device_p->mount_count++;
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		return 0;
	}
	srcu_read_unlock(&device_list_srcu, srcu_idx);

	new_device_p = create_device_item(kdev);
	if (!new_device_p)
		return -RSBAC_ECOULDNOTADDDEVICE;

	/* register lists */
	if ((err = auth_register_fd_lists(new_device_p, kdev))) {
		char tmp[RSBAC_MAXNAMELEN];

		rsbac_printk(KERN_WARNING "rsbac_mount_auth(): File/Dir ACL registration failed for dev %02u:%02u, err %s!\n",
			     RSBAC_MAJOR(kdev), RSBAC_MINOR(kdev),
			     get_error_name(tmp, err));
	}

	srcu_idx = srcu_read_lock(&device_list_srcu);
	/* make sure to only add, if this device item has not been added in the meantime */
	device_p = lookup_device(kdev);
	if (device_p) {
		rsbac_printk(KERN_WARNING "rsbac_mount_auth(): mount race for device %02u:%02u detected!\n",
			     RSBAC_MAJOR(kdev), RSBAC_MINOR(kdev));
		device_p->mount_count++;
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		clear_device_item(new_device_p);
	} else {
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		device_p = add_device_item(new_device_p);
		if (!device_p) {
			rsbac_printk(KERN_WARNING "rsbac_mount_auth: adding device %02u:%02u failed!\n",
				     RSBAC_MAJOR(kdev), RSBAC_MINOR(kdev));
			clear_device_item(new_device_p);
			err = -RSBAC_ECOULDNOTADDDEVICE;
		}
	}
	return err;
}

/* When umounting a device, its file cap set list must be removed. */

int rsbac_umount_auth(kdev_t kdev)
{
	struct rsbac_auth_device_list_item_t *device_p;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_umount(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	rsbac_pr_debug(ds_auth, "umounting device %02u:%02u\n",
		       RSBAC_MAJOR(kdev), RSBAC_MINOR(kdev));
	/* sync of attribute lists was done in rsbac_umount */
	spin_lock(&device_list_lock);
	device_p = lookup_device(kdev);
	if (device_p) {
		if (device_p->mount_count == 1)
			remove_device_item(kdev);
		else {
			if (device_p->mount_count > 1) {
				device_p->mount_count--;
				spin_unlock(&device_list_lock);
			} else {
				spin_unlock(&device_list_lock);
				rsbac_printk(KERN_WARNING "rsbac_mount_auth: device %02u:%02u has mount_count < 1!\n",
					     RSBAC_MAJOR(kdev),
					     RSBAC_MINOR(kdev));
			}
		}
	}
	else
		spin_unlock(&device_list_lock);
	return 0;
}

/***************************************************/
/* We also need some status information...         */

int rsbac_stats_auth(void)
{
	u_int cap_set_count = 0;
	u_int member_count = 0;
	struct rsbac_auth_device_list_item_t *device_p;
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_stats_auth(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	rsbac_pr_debug(aef_auth, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	rsbac_printk(KERN_INFO "AUTH Status\n-----------\n");

	rsbac_printk(KERN_INFO "%lu process cap set items, sum of %lu members\n",
		     rsbac_list_lol_count(process_handle),
		     rsbac_list_lol_all_subcount(process_handle));

	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = rcu_dereference(device_list_head_p)->head;
	while (device_p) {
		/* reset counters */
		cap_set_count = rsbac_list_lol_count(device_p->handle);
		member_count = rsbac_list_lol_all_subcount(device_p->handle);
		rsbac_printk(KERN_INFO "device %02u:%02u has %u file cap set items, sum of %u members\n",
			     RSBAC_MAJOR(device_p->id),
			     RSBAC_MINOR(device_p->id), cap_set_count,
			     member_count);
		device_p = device_p->next;
	}
	srcu_read_unlock(&device_list_srcu, srcu_idx);
	return 0;
}

/************************************************* */
/*               Access functions                  */
/************************************************* */

/* All these procedures handle the rw-spinlocks to protect the targets during */
/* access.                                                                  */
/* Trying to access a never created or removed set returns an error! */

/* rsbac_auth_add_to_capset */
/* Add a set member to a set sublist. Set behaviour: also returns success, */
/* if member was already in set! */

int rsbac_auth_add_to_p_capset(rsbac_list_ta_number_t ta_number,
			       rsbac_pid_t pid,
			       enum rsbac_auth_cap_type_t cap_type,
			       struct rsbac_auth_cap_range_t cap_range,
			       rsbac_time_t ttl)
{
	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_add_to_p_capset(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_add_to_p_capset(): called from interrupt!\n");
	}
	if (cap_range.first > cap_range.last)
		return -RSBAC_EINVALIDVALUE;
	switch (cap_type) {
	case ACT_real:
		return rsbac_ta_list_lol_subadd_ttl(ta_number,
						    process_handle, ttl,
						    &pid, &cap_range,
						    NULL);
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
	case ACT_eff:
		return rsbac_ta_list_lol_subadd_ttl(ta_number,
						    process_eff_handle,
						    ttl, &pid, &cap_range,
						    NULL);
	case ACT_fs:
		return rsbac_ta_list_lol_subadd_ttl(ta_number,
						    process_fs_handle, ttl,
						    &pid, &cap_range,
						    NULL);
#endif
#ifdef CONFIG_RSBAC_AUTH_GROUP
	case ACT_group_real:
		return rsbac_ta_list_lol_subadd_ttl(ta_number,
						    process_group_handle,
						    ttl, &pid, &cap_range,
						    NULL);
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
	case ACT_group_eff:
		return rsbac_ta_list_lol_subadd_ttl(ta_number,
						    process_group_eff_handle,
						    ttl, &pid, &cap_range,
						    NULL);
	case ACT_group_fs:
		return rsbac_ta_list_lol_subadd_ttl(ta_number,
						    process_group_fs_handle,
						    ttl, &pid, &cap_range,
						    NULL);
#endif
#endif				/* AUTH_GROUP */

	default:
		return -RSBAC_EINVALIDATTR;
	}
}

int rsbac_auth_add_to_f_capset(rsbac_list_ta_number_t ta_number,
			       rsbac_auth_file_t file,
			       enum rsbac_auth_cap_type_t cap_type,
			       struct rsbac_auth_cap_range_t cap_range,
			       rsbac_time_t ttl)
{
	int err = 0;
	struct rsbac_auth_device_list_item_t *device_p;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_add_to_f_capset(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_add_to_f_capset(): called from interrupt!\n");
	}
	if (cap_range.first > cap_range.last)
		return -RSBAC_EINVALIDVALUE;

	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = lookup_device(file.device);
	if (!device_p) {
		rsbac_printk(KERN_WARNING "rsbac_auth_add_to_f_capset(): invalid device %02u:%02u!\n",
			     RSBAC_MAJOR(file.device),
			     RSBAC_MINOR(file.device));
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		return -RSBAC_EINVALIDDEV;
	}

	switch (cap_type) {
	case ACT_real:
		err = rsbac_ta_list_lol_subadd_ttl(ta_number,
						 device_p->handle,
						 ttl, &file.inode,
						 &cap_range, NULL);
		break;
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
	case ACT_eff:
		err = rsbac_ta_list_lol_subadd_ttl(ta_number,
						 device_p->eff_handle,
						 ttl, &file.inode,
						 &cap_range, NULL);
		break;
	case ACT_fs:
		err = rsbac_ta_list_lol_subadd_ttl(ta_number,
						 device_p->fs_handle,
						 ttl, &file.inode,
						 &cap_range, NULL);
		break;
#endif
#ifdef CONFIG_RSBAC_AUTH_GROUP
	case ACT_group_real:
		err = rsbac_ta_list_lol_subadd_ttl(ta_number,
						 device_p->group_handle,
						 ttl,
						 &file.inode, &cap_range,
						 NULL);
		break;
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
	case ACT_group_eff:
		err = rsbac_ta_list_lol_subadd_ttl(ta_number,
						 device_p->group_eff_handle,
						 ttl,
						 &file.inode, &cap_range,
						 NULL);
		break;
	case ACT_group_fs:
		err = rsbac_ta_list_lol_subadd_ttl(ta_number,
						 device_p->group_fs_handle,
						 ttl,
						 &file.inode, &cap_range,
						 NULL);
		break;
#endif
#endif				/* AUTH_GROUP */

	default:
		err = -RSBAC_EINVALIDATTR;
	}
	srcu_read_unlock(&device_list_srcu, srcu_idx);
	return err;
}

/* rsbac_auth_remove_from_capset */
/* Remove a set member from a sublist. Set behaviour: Returns no error, if */
/* member is not in list.                                                  */

int rsbac_auth_remove_from_p_capset(rsbac_list_ta_number_t ta_number,
				    rsbac_pid_t pid,
				    enum rsbac_auth_cap_type_t cap_type,
				    struct rsbac_auth_cap_range_t
				    cap_range)
{
	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_remove_from_p_capset(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_remove_from_p_capset(): called from interrupt!\n");
	}
	if (cap_range.first > cap_range.last)
		return -RSBAC_EINVALIDVALUE;
	switch (cap_type) {
	case ACT_real:
		return rsbac_ta_list_lol_subremove(ta_number,
						   process_handle, &pid,
						   &cap_range);
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
	case ACT_eff:
		return rsbac_ta_list_lol_subremove(ta_number,
						   process_eff_handle,
						   &pid, &cap_range);
	case ACT_fs:
		return rsbac_ta_list_lol_subremove(ta_number,
						   process_fs_handle, &pid,
						   &cap_range);
#endif
#ifdef CONFIG_RSBAC_AUTH_GROUP
	case ACT_group_real:
		return rsbac_ta_list_lol_subremove(ta_number,
						   process_group_handle,
						   &pid, &cap_range);
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
	case ACT_group_eff:
		return rsbac_ta_list_lol_subremove(ta_number,
						   process_group_eff_handle,
						   &pid, &cap_range);
	case ACT_group_fs:
		return rsbac_ta_list_lol_subremove(ta_number,
						   process_group_fs_handle,
						   &pid, &cap_range);
#endif
#endif				/* AUTH_GROUP */

	default:
		return -RSBAC_EINVALIDATTR;
	}
}

int rsbac_auth_remove_from_f_capset(rsbac_list_ta_number_t ta_number,
				    rsbac_auth_file_t file,
				    enum rsbac_auth_cap_type_t cap_type,
				    struct rsbac_auth_cap_range_t
				    cap_range)
{
	int err = 0;
	struct rsbac_auth_device_list_item_t *device_p;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_remove_from_f_capset(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_remove_from_f_capset(): called from interrupt!\n");
	}
	if (cap_range.first > cap_range.last)
		return -RSBAC_EINVALIDVALUE;

	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = lookup_device(file.device);
	if (!device_p) {
		rsbac_printk(KERN_WARNING "rsbac_auth_remove_from_f_capset(): invalid device %02u:%02u!\n",
			     RSBAC_MAJOR(file.device),
			     RSBAC_MINOR(file.device));
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		return -RSBAC_EINVALIDDEV;
	}
	switch (cap_type) {
	case ACT_real:
		err = rsbac_ta_list_lol_subremove(ta_number,
						device_p->handle,
						&file.inode, &cap_range);
		break;
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
	case ACT_eff:
		err = rsbac_ta_list_lol_subremove(ta_number,
						device_p->eff_handle,
						&file.inode, &cap_range);
		break;
	case ACT_fs:
		err = rsbac_ta_list_lol_subremove(ta_number,
						device_p->fs_handle,
						&file.inode, &cap_range);
		break;
#endif
#ifdef CONFIG_RSBAC_AUTH_GROUP
	case ACT_group_real:
		err = rsbac_ta_list_lol_subremove(ta_number,
						device_p->group_handle,
						&file.inode, &cap_range);
		break;
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
	case ACT_group_eff:
		err = rsbac_ta_list_lol_subremove(ta_number,
						device_p->group_eff_handle,
						&file.inode, &cap_range);
		break;
	case ACT_group_fs:
		err = rsbac_ta_list_lol_subremove(ta_number,
						device_p->group_fs_handle,
						&file.inode, &cap_range);
		break;
#endif
#endif				/* AUTH_GROUP */

	default:
		err = -RSBAC_EINVALIDATTR;
	}
	srcu_read_unlock(&device_list_srcu, srcu_idx);
	return err;
}

/* rsbac_auth_clear_capset */
/* Remove all set members from a sublist. Set behaviour: Returns no error, */
/* if list is empty.                                                       */

int rsbac_auth_clear_p_capset(rsbac_list_ta_number_t ta_number,
			      rsbac_pid_t pid,
			      enum rsbac_auth_cap_type_t cap_type)
{
	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_clear_p_capset(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_clear_p_capset(): called from interrupt!\n");
	}
	switch (cap_type) {
	case ACT_real:
		return rsbac_ta_list_lol_remove(ta_number, process_handle,
						&pid);
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
	case ACT_eff:
		return rsbac_ta_list_lol_remove(ta_number,
						process_eff_handle, &pid);
	case ACT_fs:
		return rsbac_ta_list_lol_remove(ta_number,
						process_fs_handle, &pid);
#endif
#ifdef CONFIG_RSBAC_AUTH_GROUP
	case ACT_group_real:
		return rsbac_ta_list_lol_remove(ta_number,
						process_group_handle,
						&pid);
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
	case ACT_group_eff:
		return rsbac_ta_list_lol_remove(ta_number,
						process_group_eff_handle,
						&pid);
	case ACT_group_fs:
		return rsbac_ta_list_lol_remove(ta_number,
						process_group_fs_handle,
						&pid);
#endif
#endif				/* AUTH_GROUP */

	default:
		return -RSBAC_EINVALIDTARGET;
	}
}

int rsbac_auth_clear_f_capset(rsbac_list_ta_number_t ta_number,
			      rsbac_auth_file_t file,
			      enum rsbac_auth_cap_type_t cap_type)
{
	int err = 0;
	struct rsbac_auth_device_list_item_t *device_p;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_clear_f_capset(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_clear_f_capset(): called from interrupt!\n");
	}
	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = lookup_device(file.device);
	if (!device_p) {
		rsbac_printk(KERN_WARNING "rsbac_auth_clear_f_capset(): invalid device %02u:%02u!\n",
			     RSBAC_MAJOR(file.device),
			     RSBAC_MINOR(file.device));
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		return -RSBAC_EINVALIDDEV;
	}
	switch (cap_type) {
	case ACT_real:
		err = rsbac_ta_list_lol_remove(ta_number,
					device_p->handle,
					&file.inode);
		break;
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
	case ACT_eff:
		err = rsbac_ta_list_lol_remove(ta_number,
					device_p->eff_handle,
					&file.inode);
		break;
	case ACT_fs:
		err = rsbac_ta_list_lol_remove(ta_number,
					device_p->fs_handle,
					&file.inode);
		break;
#endif
#ifdef CONFIG_RSBAC_AUTH_GROUP
	case ACT_group_real:
		err = rsbac_ta_list_lol_remove(ta_number,
					device_p->group_handle,
					&file.inode);
		break;
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
	case ACT_group_eff:
		err = rsbac_ta_list_lol_remove(ta_number,
					device_p->group_eff_handle,
					&file.inode);
		break;
	case ACT_group_fs:
		err = rsbac_ta_list_lol_remove(ta_number,
					device_p-> group_fs_handle,
					&file.inode);
		break;
#endif
#endif				/* AUTH_GROUP */

	default:
		err = -RSBAC_EINVALIDTARGET;
	}
	srcu_read_unlock(&device_list_srcu, srcu_idx);
	return err;
}

/* rsbac_auth_capset_member */
/* Return truth value, whether member is in set */

rsbac_boolean_t rsbac_auth_p_capset_member(rsbac_pid_t pid,
					   enum rsbac_auth_cap_type_t
					   cap_type, rsbac_uid_t member)
{
	rsbac_boolean_t result;
#if defined(CONFIG_RSBAC_AUTH_LEARN)
	int srcu_idx;
#endif

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_p_capset_member(): RSBAC not initialized\n");
		return FALSE;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_p_capset_member(): called from interrupt!\n");
	}
	switch (cap_type) {
	case ACT_real:
		result = rsbac_list_lol_subexist_compare(process_handle, &pid,
						    &member,
						    single_cap_compare);
#if defined(CONFIG_RSBAC_UM_VIRTUAL)
		/* check for pseudo set "all" */
		if (!result) {
			rsbac_uid_t amember;

			amember = RSBAC_GEN_UID(RSBAC_UM_VIRTUAL_ALL, member);
			result = rsbac_list_lol_subexist_compare(process_handle,
								&pid,
								&amember,
								single_cap_compare);
		}
#endif
#if defined(CONFIG_RSBAC_AUTH_LEARN)
		if (!result && (RSBAC_UID_NUM(member) <= RSBAC_AUTH_MAX_RANGE_UID)
		    ) {
			union rsbac_target_id_t tid;
			union rsbac_attribute_value_t attr_val;
			rsbac_boolean_t learn;

			learn = rsbac_auth_learn;
			if (!learn) {
				tid.process = pid;
				/* check learn on process */
				if (!rsbac_get_attr
				    (SW_AUTH, T_PROCESS, tid, A_auth_learn,
				     &attr_val, FALSE))
					learn = attr_val.auth_learn;
			}
			if (learn) {
				struct rsbac_auth_cap_range_t range;
				int err;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
				if(RSBAC_UID_SET(member))
					rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH capability for uid %u/%u to process %u (%.15s) to transaction %u!\n",
						RSBAC_UID_SET(member),
						RSBAC_UID_NUM(member),
						pid_nr(pid),
						current->comm,
						auth_learn_ta);
				else
#endif
				rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH capability for uid %u to process %u (%.15s) to transaction %u!\n",
					     RSBAC_UID_NUM(member), pid_nr(pid), current->comm, auth_learn_ta);
				range.first = member;
				range.last = member;
#ifdef CONFIG_RSBAC_AUTH_LEARN_TA
				if (!rsbac_list_ta_exist(auth_learn_ta))
					rsbac_list_ta_begin(CONFIG_RSBAC_LIST_TRANS_MAX_TTL,
							&auth_learn_ta,
							RSBAC_ALL_USERS,
							RSBAC_AUTH_LEARN_TA_NAME,
							NULL);
#endif
				rsbac_ta_list_lol_subadd_ttl(auth_learn_ta,
							process_handle,
							RSBAC_LIST_TTL_KEEP,
							&pid,
							&range,
							NULL);

				tid.process = pid;
				if (!(err = rsbac_get_attr
				    (SW_GEN, T_PROCESS, tid,
				     A_program_file, &attr_val,
				     FALSE))) {
					struct
					    rsbac_auth_device_list_item_t
					    *device_p;
					union rsbac_attribute_value_t
					    attr_val2;
					char * target_id_name;

#ifdef CONFIG_RSBAC_LOG_FULL_PATH
				        target_id_name
				         = rsbac_kmalloc_unlocked(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
				           /* max. path name len + some extra */
#else
				        target_id_name = rsbac_kmalloc_unlocked(2 * RSBAC_MAXNAMELEN);
				           /* max. file name len + some extra */
#endif
					if (!rsbac_get_attr
					    (SW_AUTH, T_PROCESS, tid,
					     A_auth_start_uid, &attr_val2,
					     FALSE)
					    && (range.first ==
						attr_val2.auth_start_uid)
					    ) {
						range.first =
						    RSBAC_AUTH_OWNER_F_CAP;
						range.last = range.first;
					}
					tid.file = attr_val.program_file;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
					if(RSBAC_UID_SET(range.first))
						rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH capability for uid %u/%u to FILE %s to transaction %u!\n",
							     RSBAC_UID_SET(range.first),
							     RSBAC_UID_NUM(range.first),
							     get_target_name(NULL, T_FILE, target_id_name, tid),
							     auth_learn_ta);
					else
#endif
					rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH capability for uid %u to FILE %s to transaction %u!\n",
						     RSBAC_UID_NUM(range.first),
						     get_target_name(NULL, T_FILE, target_id_name, tid),
						     auth_learn_ta);
					rsbac_kfree(target_id_name);
					srcu_idx = srcu_read_lock(&device_list_srcu);
					device_p =
					    lookup_device(attr_val.
							  program_file.
							  device);
					if (device_p) {
						rsbac_ta_list_lol_subadd_ttl(
							auth_learn_ta,
							device_p->handle,
							RSBAC_LIST_TTL_KEEP,
							&attr_val.program_file.inode,
							&range,
							NULL);
					} else {
						rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): unknown device %02u:%02u!\n",
							     MAJOR
							     (attr_val.
							      program_file.
							      device),
							     MINOR
							     (attr_val.
							      program_file.
							      device));
					}
					srcu_read_unlock(&device_list_srcu, srcu_idx);
				} else
					rsbac_pr_get_error_num(A_program_file, err);
				result = TRUE;
			}
		}
#endif
		break;

#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
	case ACT_eff:
		result =
		    rsbac_list_lol_subexist_compare(process_eff_handle,
						    &pid, &member,
						    single_cap_compare);
#if defined(CONFIG_RSBAC_UM_VIRTUAL)
		/* check for pseudo set "all" */
		if (!result) {
			rsbac_uid_t amember;

			amember = RSBAC_GEN_UID(RSBAC_UM_VIRTUAL_ALL, member);
			result = rsbac_list_lol_subexist_compare(process_eff_handle,
								&pid,
								&amember,
								single_cap_compare);
		}
#endif

#if defined(CONFIG_RSBAC_AUTH_LEARN)
		if (!result && (RSBAC_UID_NUM(member) <= RSBAC_AUTH_MAX_RANGE_UID)
		    ) {
			union rsbac_target_id_t tid;
			union rsbac_attribute_value_t attr_val;
			rsbac_boolean_t learn;

			learn = rsbac_auth_learn;
			if (!learn) {
				tid.process = pid;
				/* check learn on process */
				if (!rsbac_get_attr
				    (SW_AUTH, T_PROCESS, tid, A_auth_learn,
				     &attr_val, FALSE))
					learn = attr_val.auth_learn;
			}
			if (learn) {
				struct rsbac_auth_cap_range_t range;
				int err;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
				if(RSBAC_UID_SET(member))
					rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH eff capability for uid %u/%u to process %u (%.15s) to transaction %u!\n",
						RSBAC_UID_SET(member),
						RSBAC_UID_NUM(member),
						pid_nr(pid),
						current->comm,
						auth_learn_ta);
				else
#endif
				rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH eff capability for uid %u to process %u (%.15s) to transaction %u!\n",
					     RSBAC_UID_NUM(member), pid_nr(pid), current->comm, auth_learn_ta);
				range.first = member;
				range.last = member;
#ifdef CONFIG_RSBAC_AUTH_LEARN_TA
				if (!rsbac_list_ta_exist(auth_learn_ta))
					rsbac_list_ta_begin(CONFIG_RSBAC_LIST_TRANS_MAX_TTL,
							&auth_learn_ta,
							RSBAC_ALL_USERS,
							RSBAC_AUTH_LEARN_TA_NAME,
							NULL);
#endif
				rsbac_ta_list_lol_subadd_ttl(auth_learn_ta,
							process_eff_handle,
							RSBAC_LIST_TTL_KEEP,
							&pid,
							&range,
							NULL);

				tid.process = pid;
				if (!(err = rsbac_get_attr
				    (SW_GEN, T_PROCESS, tid,
				     A_program_file, &attr_val,
				     FALSE))) {
					struct
					    rsbac_auth_device_list_item_t
					    *device_p;
					union rsbac_attribute_value_t
					    attr_val2;
					char * target_id_name;

#ifdef CONFIG_RSBAC_LOG_FULL_PATH
				        target_id_name
				         = rsbac_kmalloc_unlocked(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
				           /* max. path name len + some extra */
#else
				        target_id_name = rsbac_kmalloc_unlocked(2 * RSBAC_MAXNAMELEN);
				           /* max. file name len + some extra */
#endif
					if (!rsbac_get_attr
					    (SW_AUTH, T_PROCESS, tid,
					     A_auth_start_uid, &attr_val2,
					     FALSE)
					    && (range.first ==
						attr_val2.auth_start_uid)
					    ) {
						range.first =
						    RSBAC_AUTH_OWNER_F_CAP;
						range.last = range.first;
					} else
					    if (!rsbac_get_attr
						(SW_AUTH, T_PROCESS, tid,
						 A_auth_start_euid,
						 &attr_val2, FALSE)
						&& (range.first ==
						    attr_val2.
						    auth_start_euid)
					    ) {
						range.first =
						    RSBAC_AUTH_DAC_OWNER_F_CAP;
						range.last = range.first;
					}
					tid.file = attr_val.program_file;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
					if(RSBAC_UID_SET(range.first))
						rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH eff capability for uid %u/%u to FILE %s to transaction %u!\n",
							     RSBAC_UID_SET(range.first),
							     RSBAC_UID_NUM(range.first),
							     get_target_name(NULL, T_FILE, target_id_name, tid),
							     auth_learn_ta);
					else
#endif
					rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH eff capability for uid %u to FILE %s to transaction %u!\n",
						     RSBAC_UID_NUM(range.first),
						     get_target_name(NULL, T_FILE, target_id_name, tid),
						     auth_learn_ta);
					rsbac_kfree(target_id_name);
					srcu_idx = srcu_read_lock(&device_list_srcu);
					device_p =
					    lookup_device(attr_val.
							  program_file.
							  device);
					if (device_p) {
						rsbac_ta_list_lol_subadd_ttl(
							auth_learn_ta,
							device_p->eff_handle,
							RSBAC_LIST_TTL_KEEP,
							&attr_val.program_file.inode,
							&range,
							NULL);
					} else {
						rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): unknown device %02u:%02u!\n",
							     MAJOR
							     (attr_val.
							      program_file.
							      device),
							     MINOR
							     (attr_val.
							      program_file.
							      device));
					}
					srcu_read_unlock(&device_list_srcu, srcu_idx);
				} else
					rsbac_pr_get_error_num(A_program_file, err);
				result = TRUE;
			}
		}
#endif
		break;

	case ACT_fs:
		result =
		    rsbac_list_lol_subexist_compare(process_fs_handle,
						    &pid, &member,
						    single_cap_compare);
#if defined(CONFIG_RSBAC_UM_VIRTUAL)
		/* check for pseudo set "all" */
		if (!result) {
			rsbac_uid_t amember;

			amember = RSBAC_GEN_UID(RSBAC_UM_VIRTUAL_ALL, member);
			result = rsbac_list_lol_subexist_compare(process_fs_handle,
								&pid,
								&amember,
								single_cap_compare);
		}
#endif

#if defined(CONFIG_RSBAC_AUTH_LEARN)
		if (!result && (RSBAC_UID_NUM(member) <= RSBAC_AUTH_MAX_RANGE_UID)
		    ) {
			union rsbac_target_id_t tid;
			union rsbac_attribute_value_t attr_val;
			rsbac_boolean_t learn;

			learn = rsbac_auth_learn;
			if (!learn) {
				tid.process = pid;
				/* check learn on process */
				if (!rsbac_get_attr
				    (SW_AUTH, T_PROCESS, tid, A_auth_learn,
				     &attr_val, FALSE))
					learn = attr_val.auth_learn;
			}
			if (learn) {
				struct rsbac_auth_cap_range_t range;
				int err;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
				if(RSBAC_UID_SET(member))
					rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH fs capability for uid %u/%u to process %u (%.15s) to transaction %u!\n",
						RSBAC_UID_SET(member),
						RSBAC_UID_NUM(member),
						pid_nr(pid),
						current->comm,
						auth_learn_ta);
				else
#endif
				rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH fs capability for uid %u to process %u (%.15s) to transaction %u!\n",
					     RSBAC_UID_NUM(member), pid_nr(pid), current->comm, auth_learn_ta);
				range.first = member;
				range.last = member;
#ifdef CONFIG_RSBAC_AUTH_LEARN_TA
				if (!rsbac_list_ta_exist(auth_learn_ta))
					rsbac_list_ta_begin(CONFIG_RSBAC_LIST_TRANS_MAX_TTL,
							&auth_learn_ta,
							RSBAC_ALL_USERS,
							RSBAC_AUTH_LEARN_TA_NAME,
							NULL);
#endif
				rsbac_ta_list_lol_subadd_ttl(auth_learn_ta,
							process_fs_handle,
							RSBAC_LIST_TTL_KEEP,
							&pid,
							&range,
							NULL);

				tid.process = pid;
				if (!(err = rsbac_get_attr
				    (SW_GEN, T_PROCESS, tid,
				     A_program_file, &attr_val,
				     FALSE))) {
					struct
					    rsbac_auth_device_list_item_t
					    *device_p;
					union rsbac_attribute_value_t
					    attr_val2;
					char * target_id_name;

#ifdef CONFIG_RSBAC_LOG_FULL_PATH
				        target_id_name
				         = rsbac_kmalloc_unlocked(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
				           /* max. path name len + some extra */
#else
				        target_id_name = rsbac_kmalloc_unlocked(2 * RSBAC_MAXNAMELEN);
				           /* max. file name len + some extra */
#endif
					if (!rsbac_get_attr
					    (SW_AUTH, T_PROCESS, tid,
					     A_auth_start_uid, &attr_val2,
					     FALSE)
					    && (range.first ==
						attr_val2.auth_start_uid)
					    ) {
						range.first =
						    RSBAC_AUTH_OWNER_F_CAP;
						range.last = range.first;
					} else
					    if (!rsbac_get_attr
						(SW_AUTH, T_PROCESS, tid,
						 A_auth_start_euid,
						 &attr_val2, FALSE)
						&& (range.first ==
						    attr_val2.
						    auth_start_euid)
					    ) {
						range.first =
						    RSBAC_AUTH_DAC_OWNER_F_CAP;
						range.last = range.first;
					}
					tid.file = attr_val.program_file;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
					if(RSBAC_UID_SET(range.first))
						rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH fs capability for uid %u/%u to FILE %s to transaction %u!\n",
							     RSBAC_UID_SET(range.first),
							     RSBAC_UID_NUM(range.first),
							     get_target_name(NULL, T_FILE, target_id_name, tid),
							     auth_learn_ta);
					else
#endif
					rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH fs capability for uid %u to FILE %s to transaction %u!\n",
						     RSBAC_UID_NUM(range.first),
						     get_target_name(NULL, T_FILE, target_id_name, tid),
						     auth_learn_ta);
					rsbac_kfree(target_id_name);
					srcu_idx = srcu_read_lock(&device_list_srcu);
					device_p =
					    lookup_device(attr_val.
							  program_file.
							  device);
					if (device_p) {
						rsbac_ta_list_lol_subadd_ttl(
							auth_learn_ta,
							device_p->fs_handle,
							RSBAC_LIST_TTL_KEEP,
							&attr_val.program_file.inode,
							&range,
							NULL);
					} else {
						rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): unknown device %02u:%02u!\n",
							     MAJOR
							     (attr_val.
							      program_file.
							      device),
							     MINOR
							     (attr_val.
							      program_file.
							      device));
					}
					srcu_read_unlock(&device_list_srcu, srcu_idx);
				} else
					rsbac_pr_get_error_num(A_program_file, err);
				result = TRUE;
			}
		}
#endif
		break;
#endif				/* AUTH_DAC_OWNER */

#ifdef CONFIG_RSBAC_AUTH_GROUP
	case ACT_group_real:
		result =
		    rsbac_list_lol_subexist_compare(process_group_handle,
						    &pid, &member,
						    single_cap_compare);
#if defined(CONFIG_RSBAC_UM_VIRTUAL)
		/* check for pseudo set "all" */
		if (!result) {
			rsbac_uid_t amember;

			amember = RSBAC_GEN_GID(RSBAC_UM_VIRTUAL_ALL, member);
			result = rsbac_list_lol_subexist_compare(process_group_handle,
								&pid,
								&amember,
								single_cap_compare);
		}
#endif

#if defined(CONFIG_RSBAC_AUTH_LEARN)
		if (!result && (RSBAC_GID_NUM(member) <= RSBAC_AUTH_MAX_RANGE_GID)
		    ) {
			union rsbac_target_id_t tid;
			union rsbac_attribute_value_t attr_val;
			rsbac_boolean_t learn;

			learn = rsbac_auth_learn;
			if (!learn) {
				tid.process = pid;
				/* check learn on process */
				if (!rsbac_get_attr
				    (SW_AUTH, T_PROCESS, tid, A_auth_learn,
				     &attr_val, FALSE))
					learn = attr_val.auth_learn;
			}
			if (learn) {
				struct rsbac_auth_cap_range_t range;
				int err;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
				if(RSBAC_GID_SET(member))
					rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH group capability for gid %u/%u to process %u (%.15s) to transaction %u!\n",
						RSBAC_GID_SET(member),
						RSBAC_GID_NUM(member),
						pid_nr(pid),
						current->comm,
						auth_learn_ta);
				else
#endif
				rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH group capability for gid %u to process %u (%.15s) to transaction %u!\n",
					     RSBAC_GID_NUM(member), pid_nr(pid), current->comm, auth_learn_ta);
				range.first = member;
				range.last = member;
#ifdef CONFIG_RSBAC_AUTH_LEARN_TA
				if (!rsbac_list_ta_exist(auth_learn_ta))
					rsbac_list_ta_begin(CONFIG_RSBAC_LIST_TRANS_MAX_TTL,
							&auth_learn_ta,
							RSBAC_ALL_USERS,
							RSBAC_AUTH_LEARN_TA_NAME,
							NULL);
#endif
				rsbac_ta_list_lol_subadd_ttl(auth_learn_ta,
							process_group_handle,
							RSBAC_LIST_TTL_KEEP,
							&pid,
							&range,
							NULL);

				tid.process = pid;
				if (!(err = rsbac_get_attr
				    (SW_GEN, T_PROCESS, tid,
				     A_program_file, &attr_val,
				     FALSE))) {
					struct
					    rsbac_auth_device_list_item_t
					    *device_p;
					union rsbac_attribute_value_t
					    attr_val2;
					char * target_id_name;

#ifdef CONFIG_RSBAC_LOG_FULL_PATH
				        target_id_name
				         = rsbac_kmalloc_unlocked(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
				           /* max. path name len + some extra */
#else
				        target_id_name = rsbac_kmalloc_unlocked(2 * RSBAC_MAXNAMELEN);
				           /* max. file name len + some extra */
#endif
					if (!rsbac_get_attr
					    (SW_AUTH, T_PROCESS, tid,
					     A_auth_start_gid, &attr_val2,
					     FALSE)
					    && (range.first ==
						attr_val2.auth_start_gid)
					    ) {
						range.first =
						    RSBAC_AUTH_GROUP_F_CAP;
						range.last = range.first;
					}
					tid.file = attr_val.program_file;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
					if(RSBAC_GID_SET(range.first))
						rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH group capability for gid %u/%u to FILE %s to transaction %u!\n",
							     RSBAC_GID_SET(range.first),
							     RSBAC_GID_NUM(range.first),
							     get_target_name(NULL, T_FILE, target_id_name, tid),
							     auth_learn_ta);
					else
#endif
					rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH group capability for gid %u to FILE %s to transaction %u!\n",
						     RSBAC_GID_NUM(range.first),
						     get_target_name(NULL, T_FILE, target_id_name, tid),
						     auth_learn_ta);
					rsbac_kfree(target_id_name);
					srcu_idx = srcu_read_lock(&device_list_srcu);
					device_p =
					    lookup_device(attr_val.
							  program_file.
							  device);
					if (device_p) {
						rsbac_ta_list_lol_subadd_ttl(
							auth_learn_ta,
							device_p->group_handle,
							RSBAC_LIST_TTL_KEEP,
							&attr_val.program_file.inode,
							&range,
							NULL);
					} else {
						rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): unknown device %02u:%02u!\n",
							     MAJOR
							     (attr_val.
							      program_file.
							      device),
							     MINOR
							     (attr_val.
							      program_file.
							      device));
					}
					srcu_read_unlock(&device_list_srcu, srcu_idx);
				} else
					rsbac_pr_get_error_num(A_program_file, err);
				result = TRUE;
			}
		}
#endif
		break;

#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
	case ACT_group_eff:
		result =
		    rsbac_list_lol_subexist_compare
		    (process_group_eff_handle, &pid, &member,
		     single_cap_compare);
#if defined(CONFIG_RSBAC_UM_VIRTUAL)
		/* check for pseudo set "all" */
		if (!result) {
			rsbac_uid_t amember;

			amember = RSBAC_GEN_GID(RSBAC_UM_VIRTUAL_ALL, member);
			result = rsbac_list_lol_subexist_compare(process_group_eff_handle,
								&pid,
								&amember,
								single_cap_compare);
		}
#endif

#if defined(CONFIG_RSBAC_AUTH_LEARN)
		if (!result && (RSBAC_GID_NUM(member) <= RSBAC_AUTH_MAX_RANGE_GID)
		    ) {
			union rsbac_target_id_t tid;
			union rsbac_attribute_value_t attr_val;
			rsbac_boolean_t learn;

			learn = rsbac_auth_learn;
			if (!learn) {
				tid.process = pid;
				/* check learn on process */
				if (!rsbac_get_attr
				    (SW_AUTH, T_PROCESS, tid, A_auth_learn,
				     &attr_val, FALSE))
					learn = attr_val.auth_learn;
			}
			if (learn) {
				struct rsbac_auth_cap_range_t range;
				int err;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
				if(RSBAC_GID_SET(member))
					rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH group eff capability for gid %u/%u to process %u (%.15s) to transaction %u!\n",
						RSBAC_GID_SET(member),
						RSBAC_GID_NUM(member),
						pid_nr(pid),
						current->comm,
						auth_learn_ta);
				else
#endif
				rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH group eff capability for gid %u to process %u (%.15s) to transaction %u!\n",
					     RSBAC_GID_NUM(member), pid_nr(pid), current->comm, auth_learn_ta);
				range.first = member;
				range.last = member;
#ifdef CONFIG_RSBAC_AUTH_LEARN_TA
				if (!rsbac_list_ta_exist(auth_learn_ta))
					rsbac_list_ta_begin(CONFIG_RSBAC_LIST_TRANS_MAX_TTL,
							&auth_learn_ta,
							RSBAC_ALL_USERS,
							RSBAC_AUTH_LEARN_TA_NAME,
							NULL);
#endif
				rsbac_ta_list_lol_subadd_ttl(auth_learn_ta,
							process_group_eff_handle,
							RSBAC_LIST_TTL_KEEP,
							&pid,
							&range,
							NULL);

				tid.process = pid;
				if (!(err = rsbac_get_attr
				    (SW_GEN, T_PROCESS, tid,
				     A_program_file, &attr_val,
				     FALSE))) {
					struct
					    rsbac_auth_device_list_item_t
					    *device_p;
					union rsbac_attribute_value_t
					    attr_val2;
					char * target_id_name;

#ifdef CONFIG_RSBAC_LOG_FULL_PATH
				        target_id_name
				         = rsbac_kmalloc_unlocked(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
				           /* max. path name len + some extra */
#else
				        target_id_name = rsbac_kmalloc_unlocked(2 * RSBAC_MAXNAMELEN);
				           /* max. file name len + some extra */
#endif
					if (!rsbac_get_attr
					    (SW_AUTH, T_PROCESS, tid,
					     A_auth_start_gid, &attr_val2,
					     FALSE)
					    && (range.first ==
						attr_val2.auth_start_gid)
					    ) {
						range.first =
						    RSBAC_AUTH_GROUP_F_CAP;
						range.last = range.first;
					} else
					    if (!rsbac_get_attr
						(SW_AUTH, T_PROCESS, tid,
						 A_auth_start_egid,
						 &attr_val2, FALSE)
						&& (range.first ==
						    attr_val2.
						    auth_start_egid)
					    ) {
						range.first =
						    RSBAC_AUTH_DAC_GROUP_F_CAP;
						range.last = range.first;
					}
					tid.file = attr_val.program_file;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
					if(RSBAC_GID_SET(range.first))
						rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH group eff capability for gid %u/%u to FILE %s to transaction %u!\n",
							     RSBAC_GID_SET(range.first),
							     RSBAC_GID_NUM(range.first),
							     get_target_name(NULL, T_FILE, target_id_name, tid),
							     auth_learn_ta);
					else
#endif
					rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH group eff capability for gid %u to FILE %s to transaction %u!\n",
						     RSBAC_GID_NUM(range.first),
						     get_target_name(NULL, T_FILE, target_id_name, tid),
						     auth_learn_ta);
					rsbac_kfree(target_id_name);
					srcu_idx = srcu_read_lock(&device_list_srcu);
					device_p =
					    lookup_device(attr_val.
							  program_file.
							  device);
					if (device_p) {
						rsbac_ta_list_lol_subadd_ttl(
							auth_learn_ta,
							device_p->group_eff_handle,
							RSBAC_LIST_TTL_KEEP,
							&attr_val.program_file.inode,
							&range,
							NULL);
					} else {
						rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): unknown device %02u:%02u!\n",
							     MAJOR
							     (attr_val.
							      program_file.
							      device),
							     MINOR
							     (attr_val.
							      program_file.
							      device));
					}
					srcu_read_unlock(&device_list_srcu, srcu_idx);
				} else
					rsbac_pr_get_error_num(A_program_file, err);
				result = TRUE;
			}
		}
#endif
		break;

	case ACT_group_fs:
		result =
		    rsbac_list_lol_subexist_compare
		    (process_group_fs_handle, &pid, &member,
		     single_cap_compare);
#if defined(CONFIG_RSBAC_UM_VIRTUAL)
		/* check for pseudo set "all" */
		if (!result) {
			rsbac_uid_t amember;

			amember = RSBAC_GEN_GID(RSBAC_UM_VIRTUAL_ALL, member);
			result = rsbac_list_lol_subexist_compare(process_group_fs_handle,
								&pid,
								&amember,
								single_cap_compare);
		}
#endif

#if defined(CONFIG_RSBAC_AUTH_LEARN)
		if (!result && (RSBAC_GID_NUM(member) <= RSBAC_AUTH_MAX_RANGE_GID)
		    ) {
			union rsbac_target_id_t tid;
			union rsbac_attribute_value_t attr_val;
			rsbac_boolean_t learn;

			learn = rsbac_auth_learn;
			if (!learn) {
				tid.process = pid;
				/* check learn on process */
				if (!rsbac_get_attr
				    (SW_AUTH, T_PROCESS, tid, A_auth_learn,
				     &attr_val, FALSE))
					learn = attr_val.auth_learn;
			}
			if (learn) {
				struct rsbac_auth_cap_range_t range;
				int err;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
				if(RSBAC_GID_SET(member))
					rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH group fs capability for gid %u/%u to process %u (%.15s) to transaction %u!\n",
						RSBAC_GID_SET(member),
						RSBAC_GID_NUM(member),
						pid_nr(pid),
						current->comm,
						auth_learn_ta);
				else
#endif
				rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH group fs capability for gid %u to process %u (%.15s) to transaction %u!\n",
					     RSBAC_GID_NUM(member), pid_nr(pid), current->comm, auth_learn_ta);
				range.first = member;
				range.last = member;
#ifdef CONFIG_RSBAC_AUTH_LEARN_TA
				if (!rsbac_list_ta_exist(auth_learn_ta))
					rsbac_list_ta_begin(CONFIG_RSBAC_LIST_TRANS_MAX_TTL,
							&auth_learn_ta,
							RSBAC_ALL_USERS,
							RSBAC_AUTH_LEARN_TA_NAME,
							NULL);
#endif
				rsbac_ta_list_lol_subadd_ttl(auth_learn_ta,
							process_group_fs_handle,
							RSBAC_LIST_TTL_KEEP,
							&pid,
							&range,
							NULL);

				tid.process = pid;
				if (!(err = rsbac_get_attr
				    (SW_GEN, T_PROCESS, tid,
				     A_program_file, &attr_val,
				     FALSE))) {
					struct
					    rsbac_auth_device_list_item_t
					    *device_p;
					union rsbac_attribute_value_t
					    attr_val2;
					char * target_id_name;

#ifdef CONFIG_RSBAC_LOG_FULL_PATH
				        target_id_name
				         = rsbac_kmalloc_unlocked(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
				           /* max. path name len + some extra */
#else
				        target_id_name = rsbac_kmalloc_unlocked(2 * RSBAC_MAXNAMELEN);
				           /* max. file name len + some extra */
#endif
					if (!rsbac_get_attr
					    (SW_AUTH, T_PROCESS, tid,
					     A_auth_start_gid, &attr_val2,
					     FALSE)
					    && (range.first ==
						attr_val2.auth_start_gid)
					    ) {
						range.first =
						    RSBAC_AUTH_GROUP_F_CAP;
						range.last = range.first;
					} else
					    if (!rsbac_get_attr
						(SW_AUTH, T_PROCESS, tid,
						 A_auth_start_egid,
						 &attr_val2, FALSE)
						&& (range.first ==
						    attr_val2.
						    auth_start_egid)
					    ) {
						range.first =
						    RSBAC_AUTH_DAC_GROUP_F_CAP;
						range.last = range.first;
					}
					tid.file = attr_val.program_file;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
					if(RSBAC_GID_SET(range.first))
						rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH group fs capability for gid %u/%u to FILE %s to transaction %u!\n",
							     RSBAC_GID_SET(range.first),
							     RSBAC_GID_NUM(range.first),
							     get_target_name(NULL, T_FILE, target_id_name, tid),
							     auth_learn_ta);
					else
#endif
					rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): adding AUTH group fs capability for gid %u to FILE %s to transaction %u!\n",
						     RSBAC_GID_NUM(range.first),
						     get_target_name(NULL, T_FILE, target_id_name, tid),
						     auth_learn_ta);
					rsbac_kfree(target_id_name);
					srcu_idx = srcu_read_lock(&device_list_srcu);
					device_p =
					    lookup_device(attr_val.
							  program_file.
							  device);
					if (device_p) {
						rsbac_ta_list_lol_subadd_ttl(
							auth_learn_ta,
							device_p->group_fs_handle,
							RSBAC_LIST_TTL_KEEP,
							&attr_val.program_file.inode,
							&range,
							NULL);
					} else {
						rsbac_printk(KERN_INFO "rsbac_auth_p_capset_member(): unknown device %02u:%02u!\n",
							     MAJOR
							     (attr_val.
							      program_file.
							      device),
							     MINOR
							     (attr_val.
							      program_file.
							      device));
					}
					srcu_read_unlock(&device_list_srcu, srcu_idx);
				} else
					rsbac_pr_get_error_num(A_program_file, err);
				result = TRUE;
			}
		}
#endif
		break;
#endif				/* AUTH_DAC_GROUP */
#endif				/* AUTH_GROUP */

	default:
		return FALSE;
	}
	return result;
}

/* rsbac_auth_remove_capset */
/* Remove a full set. For cleanup, if object is deleted. */
/* To empty an existing set use rsbac_auth_clear_capset. */

int rsbac_auth_remove_p_capsets(rsbac_pid_t pid)
{
	int err;

	err = rsbac_auth_clear_p_capset(0, pid, ACT_real);
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
	err = rsbac_auth_clear_p_capset(0, pid, ACT_eff);
	err = rsbac_auth_clear_p_capset(0, pid, ACT_fs);
#endif
#ifdef CONFIG_RSBAC_AUTH_GROUP
	err = rsbac_auth_clear_p_capset(0, pid, ACT_group_real);
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
	err = rsbac_auth_clear_p_capset(0, pid, ACT_group_eff);
	err = rsbac_auth_clear_p_capset(0, pid, ACT_group_fs);
#endif
#endif				/* AUTH_GROUP */

	return err;
}

int rsbac_auth_remove_f_capsets(rsbac_auth_file_t file)
{
	int err;

	err = rsbac_auth_clear_f_capset(0, file, ACT_real);
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
	if (!err)
		err = rsbac_auth_clear_f_capset(0, file, ACT_eff);
	if (!err)
		err = rsbac_auth_clear_f_capset(0, file, ACT_fs);
#endif
#ifdef CONFIG_RSBAC_AUTH_GROUP
	err = rsbac_auth_clear_f_capset(0, file, ACT_group_real);
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
	if (!err)
		err = rsbac_auth_clear_f_capset(0, file, ACT_group_eff);
	if (!err)
		err = rsbac_auth_clear_f_capset(0, file, ACT_group_fs);
#endif
#endif				/* AUTH_GROUP */

	return err;
}

int rsbac_auth_copy_fp_capset(rsbac_auth_file_t file,
			      rsbac_pid_t p_cap_set_id)
{
	struct rsbac_auth_device_list_item_t *device_p;
	int err = 0;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_copy_fp_capset(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_copy_fp_capset(): called from interrupt!\n");
	}
/*
	rsbac_pr_debug(ds_auth, "Copying file cap set data to process cap set\n");
*/
	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = lookup_device(file.device);
	if (!device_p) {
		rsbac_printk(KERN_WARNING "rsbac_auth_copy_fp_capset(): invalid device %02u:%02u!\n",
			     RSBAC_MAJOR(file.device),
			     RSBAC_MINOR(file.device));
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		return -RSBAC_EINVALIDDEV;
	}
	/* call the copy function */
	err = copy_fp_cap_set_item(device_p, file, p_cap_set_id);
	srcu_read_unlock(&device_list_srcu, srcu_idx);
	return err;
}

int rsbac_auth_copy_pp_capset(rsbac_pid_t old_p_set_id,
			      rsbac_pid_t new_p_set_id)
{
	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_copy_pp_capset(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_copy_pp_capset(): called from interrupt!\n");
	}
/*
	rsbac_pr_debug(ds_auth, "Copying process cap set data to process cap set\n");
*/
	/* call the copy function */
	return copy_pp_cap_set_item(old_p_set_id, new_p_set_id);
}

int rsbac_auth_get_f_caplist(rsbac_list_ta_number_t ta_number,
			     rsbac_auth_file_t file,
			     enum rsbac_auth_cap_type_t cap_type,
			     struct rsbac_auth_cap_range_t **caplist_p,
			     rsbac_time_t ** ttllist_p)
{
	struct rsbac_auth_device_list_item_t *device_p;
	long count;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_get_f_caplist(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_get_f_caplist(): called from interrupt!\n");
	}
/*
	rsbac_pr_debug(ds_auth, "Getting file/dir cap set list\n");
*/
	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = lookup_device(file.device);
	if (!device_p) {
		rsbac_printk(KERN_WARNING "rsbac_auth_get_f_caplist(): invalid device %02u:%02u!\n",
			     RSBAC_MAJOR(file.device),
			     RSBAC_MINOR(file.device));
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		return -RSBAC_EINVALIDDEV;
	}
	switch (cap_type) {
	case ACT_real:
		count = rsbac_ta_list_lol_get_all_subdesc_ttl(ta_number,
							      device_p->handle,
							      &file.inode,
							      (void **)
							      caplist_p,
							      ttllist_p);
		break;
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
	case ACT_eff:
		count = rsbac_ta_list_lol_get_all_subdesc_ttl(ta_number,
							      device_p->eff_handle,
							      &file.inode,
							      (void **)
							      caplist_p,
							      ttllist_p);
		break;
	case ACT_fs:
		count = rsbac_ta_list_lol_get_all_subdesc_ttl(ta_number,
							      device_p->fs_handle,
							      &file.inode,
							      (void **)
							      caplist_p,
							      ttllist_p);
		break;
#endif
#ifdef CONFIG_RSBAC_AUTH_GROUP
	case ACT_group_real:
		count = rsbac_ta_list_lol_get_all_subdesc_ttl(ta_number,
							      device_p->group_handle,
							      &file.inode,
							      (void **)
							      caplist_p,
							      ttllist_p);
		break;
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
	case ACT_group_eff:
		count = rsbac_ta_list_lol_get_all_subdesc_ttl(ta_number,
							      device_p->group_eff_handle,
							      &file.inode,
							      (void **)
							      caplist_p,
							      ttllist_p);
		break;
	case ACT_group_fs:
		count = rsbac_ta_list_lol_get_all_subdesc_ttl(ta_number,
							      device_p->group_fs_handle,
							      &file.inode,
							      (void **)
							      caplist_p,
							      ttllist_p);
		break;
#endif
#endif				/* AUTH_GROUP */

	default:
		count = -RSBAC_EINVALIDTARGET;
	}
	srcu_read_unlock(&device_list_srcu, srcu_idx);
	return count;
}

int rsbac_auth_get_p_caplist(rsbac_list_ta_number_t ta_number,
			     rsbac_pid_t pid,
			     enum rsbac_auth_cap_type_t cap_type,
			     struct rsbac_auth_cap_range_t **caplist_p,
			     rsbac_time_t ** ttllist_p)
{
	long count;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_get_p_caplist(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_auth_get_p_caplist(): called from interrupt!\n");
	}
/*
	rsbac_pr_debug(ds_auth, "Getting process cap set list\n");
*/
	switch (cap_type) {
	case ACT_real:
		count = rsbac_ta_list_lol_get_all_subdesc_ttl(ta_number,
							      process_handle,
							      &pid,
							      (void **)
							      caplist_p,
							      ttllist_p);
		break;
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
	case ACT_eff:
		count = rsbac_ta_list_lol_get_all_subdesc_ttl(ta_number,
							      process_eff_handle,
							      &pid,
							      (void **)
							      caplist_p,
							      ttllist_p);
		break;
	case ACT_fs:
		count = rsbac_ta_list_lol_get_all_subdesc_ttl(ta_number,
							      process_fs_handle,
							      &pid,
							      (void **)
							      caplist_p,
							      ttllist_p);
		break;
#endif
#ifdef CONFIG_RSBAC_AUTH_GROUP
	case ACT_group_real:
		count = rsbac_ta_list_lol_get_all_subdesc_ttl(ta_number,
							      process_group_handle,
							      &pid,
							      (void **)
							      caplist_p,
							      ttllist_p);
		break;
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
	case ACT_group_eff:
		count = rsbac_ta_list_lol_get_all_subdesc_ttl(ta_number,
							      process_group_eff_handle,
							      &pid,
							      (void **)
							      caplist_p,
							      ttllist_p);
		break;
	case ACT_group_fs:
		count = rsbac_ta_list_lol_get_all_subdesc_ttl(ta_number,
							      process_group_fs_handle,
							      &pid,
							      (void **)
							      caplist_p,
							      ttllist_p);
		break;
#endif
#endif				/* AUTH_GROUP */

	default:
		count = -RSBAC_EINVALIDTARGET;
	}
	return count;
}
