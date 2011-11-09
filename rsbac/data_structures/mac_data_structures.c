/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of MAC data structures            */
/* Author and (c) 1999-2011: Amon Ott <ao@rsbac.org> */
/*                                                   */
/* Last modified: 12/Jul/2011                        */
/*************************************************** */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/ext2_fs.h>
#include <linux/srcu.h>
#include <asm/uaccess.h>
#include <rsbac/types.h>
#include <rsbac/aci_data_structures.h>
#include <rsbac/mac_data_structures.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/adf.h>
#include <rsbac/aci.h>
#include <rsbac/lists.h>
#include <rsbac/proc_fs.h>
#include <rsbac/rkmem.h>
#include <rsbac/getname.h>
#include <linux/string.h>
#include <linux/seq_file.h>
#include <linux/module.h>

/************************************************************************** */
/*                          Global Variables                                */
/************************************************************************** */

static struct rsbac_mac_device_list_head_t device_list_head;
static struct srcu_struct device_list_srcu;
static struct lock_class_key device_list_lock_class;

static rsbac_list_handle_t process_handle = NULL;

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

static u_int nr_fd_hashes = RSBAC_MAC_NR_TRU_FD_LISTS;

static int fd_conv(void *old_desc,
		void *old_data, void *new_desc, void *new_data)
{
	memcpy(new_desc, old_desc, sizeof(rsbac_inode_nr_t));
	return 0;
}

static rsbac_list_conv_function_t *fd_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_MAC_FD_OLD_LIST_VERSION:
		return fd_conv;
	default:
		return NULL;
	}
}

static int fd_subconv(void *old_desc,
		void *old_data, void *new_desc, void *new_data)
{
	*((rsbac_uid_t *) new_desc) = *((rsbac_old_uid_t *) old_desc);
	return 0;
}

static rsbac_list_conv_function_t *fd_get_subconv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_MAC_FD_OLD_LIST_VERSION:
		return fd_subconv;
	default:
		return NULL;
	}
}



/* mac_register_fd_lists() */
/* register fd ACL lists for device */

static int mac_register_fd_lists(struct rsbac_mac_device_list_item_t
				 *device_p, kdev_t kdev)
{
	int err = 0;
	int tmperr;
	struct rsbac_list_lol_info_t lol_info;

	if (!device_p)
		return -RSBAC_EINVALIDPOINTER;

	lol_info.version = RSBAC_MAC_FD_LIST_VERSION;
	lol_info.key = RSBAC_MAC_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_inode_nr_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_uid_t);
	lol_info.subdata_size = 0;	/* rights */
	lol_info.max_age = 0;
	tmperr = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
					 &device_p->handle,
					 &lol_info,
					 RSBAC_LIST_PERSIST |
					 RSBAC_LIST_DEF_DATA,
					 NULL,
					 NULL,
					 fd_get_conv, fd_get_subconv,
					 NULL, NULL,
					 RSBAC_MAC_FD_FILENAME, kdev,
					 nr_fd_hashes,
					 rsbac_list_hash_fd,
					 RSBAC_MAC_FD_OLD_FILENAME);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "mac_register_fd_lists(): registering list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_MAC_FD_FILENAME,
				     RSBAC_MAJOR(kdev),
				     RSBAC_MINOR(kdev),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
	return err;
}

/* mac_detach_fd_lists() */
/* detach from fd MAC lists for device */

static int mac_detach_fd_lists(struct rsbac_mac_device_list_item_t
			       *device_p)
{
	int err = 0;

	if (!device_p)
		return -RSBAC_EINVALIDPOINTER;

	err = rsbac_list_lol_detach(&device_p->handle,
				       RSBAC_MAC_LIST_KEY);
	if (err) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "mac_detach_fd_lists(): detaching from list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_MAC_FD_FILENAME,
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id),
				     get_error_name(tmp, err));
			rsbac_kfree(tmp);
		}
	}
	return err;
}

/************************************************************************** */
/* The lookup functions return NULL, if the item is not found, and a        */
/* pointer to the item otherwise.                                           */

/* first the device item lookup */
static struct rsbac_mac_device_list_item_t *lookup_device(kdev_t kdev)
{
	struct rsbac_mac_device_list_item_t *curr = rcu_dereference(device_list_head.curr);

	/* if there is no current item or it is not the right one, search... */
	if (!(curr && (RSBAC_MAJOR(curr->id) == RSBAC_MAJOR(kdev))
	      && (RSBAC_MINOR(curr->id) == RSBAC_MINOR(kdev))
	    )
	    ) {
		curr = rcu_dereference(device_list_head.head);
		while (curr
		       && ((RSBAC_MAJOR(curr->id) != RSBAC_MAJOR(kdev))
			   || (RSBAC_MINOR(curr->id) != RSBAC_MINOR(kdev))
		       )
		    ) {
			curr = rcu_dereference(curr->next);
		}
		if (curr)
			rcu_assign_pointer(device_list_head.curr, curr);
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
static struct rsbac_mac_device_list_item_t
*create_device_item(kdev_t kdev)
{
	struct rsbac_mac_device_list_item_t *new_item_p;

	/* allocate memory for new device, return NULL, if failed */
	if (!(new_item_p = (struct rsbac_mac_device_list_item_t *)
	      rsbac_kmalloc(sizeof(*new_item_p))))
		return NULL;

	new_item_p->id = kdev;
	new_item_p->mount_count = 1;

	/* init file/dir sublists */
	new_item_p->handle = NULL;
	return new_item_p;
}

/* Add an existing device item to list. Locking needed. */
static struct rsbac_mac_device_list_item_t
*add_device_item(struct rsbac_mac_device_list_item_t *device_p)
{
	if (!device_p)
		return NULL;

	/* add new device to device list */
	if (!device_list_head.head) {	/* first device */
		device_p->prev = NULL;
		device_p->next = NULL;
		rcu_assign_pointer(device_list_head.head, device_p);
		rcu_assign_pointer(device_list_head.tail, device_p);
		rcu_assign_pointer(device_list_head.curr, device_p);
		device_list_head.count = 1;
	} else {		/* there is another device -> hang to tail */
		device_p->prev = device_list_head.tail;
		device_p->next = NULL;
		rcu_assign_pointer(device_list_head.tail->next, device_p);
		rcu_assign_pointer(device_list_head.tail, device_p);
		rcu_assign_pointer(device_list_head.curr, device_p);
		device_list_head.count++;
	}
	return device_p;
}

/************************************************************************** */
/* The remove_item() functions remove an item from the list. If this item   */
/* is head, tail or curr, these pointers are set accordingly.               */
/* To speed up removing several subsequent items, curr is set to the next   */
/* item, if possible.                                                       */
/* If the item is not found, nothing is done.                               */

static void clear_device_item(struct rsbac_mac_device_list_item_t *item_p)
{
	if (!item_p)
		return;

	/* First deregister lists... */
	mac_detach_fd_lists(item_p);
	rsbac_kfree(item_p);
}

static void remove_device_item(struct rsbac_mac_device_list_item_t *item_p)
{
	/* first we must locate the item. */
	if (item_p) {	/* ok, item was found */
		if (device_list_head.head == item_p) {	/* item is head */
			if (device_list_head.tail == item_p) {	/* item is head and tail = only item -> list will be empty */
				rcu_assign_pointer(device_list_head.head, NULL);
				rcu_assign_pointer(device_list_head.tail, NULL);
			} else {	/* item is head, but not tail -> next item becomes head */
				rcu_assign_pointer(item_p->next->prev, NULL);
				rcu_assign_pointer(device_list_head.head, item_p->next);
			}
		} else {	/* item is not head */
			if (device_list_head.tail == item_p) {	/*item is not head, but tail -> previous item becomes tail */
				rcu_assign_pointer(item_p->prev->next, NULL);
				rcu_assign_pointer(device_list_head.tail, item_p->prev);
			} else {	/* item is neither head nor tail -> item is cut out */
				rcu_assign_pointer(item_p->prev->next, item_p->next);
				rcu_assign_pointer(item_p->next->prev, item_p->prev);
			}
		}

		/* curr is no longer valid -> reset.                              */
		device_list_head.curr = NULL;
		/* adjust counter */
		device_list_head.count--;
	}
}

/************************************************************************** */
/* The copy_fp_tru_set_item() function copies a file cap set to a process   */
/* cap set */

static int copy_fp_tru_set_item(struct rsbac_mac_device_list_item_t
				*device_p, rsbac_mac_file_t file,
				rsbac_pid_t pid)
{
	rsbac_uid_t *tru_item_p;
	rsbac_time_t *ttl_p;
	int i;
	long count;
	enum rsbac_target_t target = T_FILE;
	union rsbac_target_id_t tid;

	rsbac_list_lol_remove(process_handle, &pid);
	count = rsbac_list_lol_get_all_subdesc_ttl(device_p->handle,
					       &file.inode,
					       (void **) &tru_item_p,
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
							       &tru_item_p,
							       &ttl_p);
	}
	if (count > 0) {
		for (i = 0; i < count; i++) {
			rsbac_list_lol_subadd_ttl(process_handle,
						  ttl_p[i],
						  &pid,
						  &tru_item_p[i], NULL);
		}
		rsbac_kfree(tru_item_p);
		rsbac_kfree(ttl_p);
	} else {
		if ((count < 0)
		    && (count != -RSBAC_ENOTFOUND)
		    )
			return count;
	}

	return 0;
}				/* end of copy_fp_tru_set_item() */

/************************************************************************** */
/* The copy_pp_tru_set_item() function copies a process cap set to another  */

static int copy_pp_tru_set_item_handle(rsbac_list_handle_t handle,
				       rsbac_pid_t old_pid,
				       rsbac_pid_t new_pid)
{
	rsbac_uid_t *tru_item_p;
	rsbac_time_t *ttl_p;
	int i;
	long count;

	rsbac_list_lol_remove(handle, &new_pid);
	count = rsbac_list_lol_get_all_subdesc_ttl(handle,
						   &old_pid,
						   (void **) &tru_item_p,
						   &ttl_p);
	if (count > 0) {
		for (i = 0; i < count; i++) {
			rsbac_list_lol_subadd_ttl(handle,
						  ttl_p[i],
						  &new_pid,
						  &tru_item_p[i], NULL);
		}
		rsbac_kfree(tru_item_p);
		rsbac_kfree(ttl_p);
	} else {
		if (count < 0)
			return count;
	}
	return 0;
}

static int copy_pp_tru_set_item(rsbac_pid_t old_pid, rsbac_pid_t new_pid)
{
	return copy_pp_tru_set_item_handle(process_handle, old_pid,
					   new_pid);
}				/* end of copy_pp_tru_set_item() */

/************************************************* */
/*               proc functions                    */
/************************************************* */

#if defined(CONFIG_RSBAC_PROC) && defined(CONFIG_PROC_FS)
static int
mac_devices_proc_show(struct seq_file *m, void *v)
{
	struct rsbac_mac_device_list_item_t *device_p;
	int srcu_idx;

	if (!rsbac_is_initialized())
		return -ENOSYS;

	seq_printf(m, "%u RSBAC MAC Devices\n-------------------\n",
		    device_list_head.count);

	/* wait for read access to device_list_head */
	srcu_idx = srcu_read_lock(&device_list_srcu);
	/* OK, go on */
	for (device_p = rcu_dereference(device_list_head.head); device_p;
	     device_p = rcu_dereference(device_p->next)) {
		seq_printf(m,
			    "%02u:%02u with mount_count = %u\n",
			    RSBAC_MAJOR(device_p->id),
			    RSBAC_MINOR(device_p->id),
			    device_p->mount_count);
	}

	/* free access to device_list_head */
	srcu_read_unlock(&device_list_srcu, srcu_idx);

	return 0;
}

static ssize_t mac_devices_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, mac_devices_proc_show, NULL);
}

static const struct file_operations mac_devices_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= mac_devices_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static struct proc_dir_entry *mac_devices;

static int
stats_mac_proc_show(struct seq_file *m, void *v)
{
	struct rsbac_mac_device_list_item_t *device_p;
	int srcu_idx;

	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "stats_mac_proc_info(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	rsbac_pr_debug(aef_mac, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	seq_printf(m, "MAC Status\n----------\n");

	seq_printf(m,
		    "%lu process trusted user set items, sum of %lu members\n",
		    rsbac_list_lol_count(process_handle),
		    rsbac_list_lol_all_subcount(process_handle));

	/* protect device list */
	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = rcu_dereference(device_list_head.head);
	while (device_p) {
		/* reset counters */
		seq_printf(m,
			    "device %02u:%02u has %lu file trusted user set items, sum of %lu members\n",
			    RSBAC_MAJOR(device_p->id),
			    RSBAC_MINOR(device_p->id),
			    rsbac_list_lol_count(device_p->handle),
			    rsbac_list_lol_all_subcount(device_p->handle));
		device_p = rcu_dereference(device_p->next);
	}
	/* unprotect device list */
	srcu_read_unlock(&device_list_srcu, srcu_idx);

	return 0;
}

static ssize_t stats_mac_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, stats_mac_proc_show, NULL);
}

static const struct file_operations stats_mac_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= stats_mac_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static struct proc_dir_entry *stats_mac;

static int
mac_trulist_proc_show(struct seq_file *m, void *v)
{
	u_int count = 0;
	u_int member_count = 0;
	u_long all_member_count;
	int i, j;
	struct rsbac_mac_device_list_item_t *device_p;
	rsbac_pid_t *p_list;
	rsbac_inode_nr_t *f_list;
	rsbac_uid_t *tru_list;
	int srcu_idx;

	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "mac_trulist_proc_info(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	rsbac_pr_debug(aef_mac, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	seq_printf(m,
		    "MAC Trusted User Lists\n---------------------\n");

	/* protect process cap set list */
	seq_printf(m,
		    "Process trusted user sets:\nset-id  count   members");

	all_member_count = 0;
	count = rsbac_list_lol_get_all_desc(process_handle,
					    (void **) &p_list);
	if (count > 0) {
		for (i = 0; i < count; i++) {
			member_count =
			    rsbac_list_lol_get_all_subdesc(process_handle,
							   &p_list[i],
							   (void **)
							   &tru_list);
			seq_printf(m, "\n %u\t%u\t", pid_vnr(p_list[i]),
				    member_count);
			if (member_count > 0) {
				for (j = 0; j < member_count; j++) {
					if (RSBAC_UID_SET(tru_list[j]))
						seq_printf(m, "%u/%u ",
						       RSBAC_UID_SET(tru_list[j]),
						       RSBAC_UID_NUM(tru_list[j]));
					else
						seq_printf(m, "%u ",
						       RSBAC_UID_NUM(tru_list[j]));
				}
				rsbac_kfree(tru_list);
				all_member_count += member_count;
			}
		}
		rsbac_kfree(p_list);
	}
	seq_printf(m,
		    "\n%u process trusted user set items, sum of %lu members\n",
		    count, all_member_count);

	seq_printf(m,
		    "\nFile trusted user sets:\nset-id  count   members");

	/* protect device list */
	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = rcu_dereference(device_list_head.head);
	while (device_p) {
		/* reset counters */
		all_member_count = 0;
		count = rsbac_list_lol_get_all_desc(device_p->handle,
							(void **) &f_list);
		if (count > 0) {
			for (i = 0; i < count; i++) {
				member_count =
				    rsbac_list_lol_get_all_subdesc
				    (device_p->handle,
				     &f_list[i],
				     (void **) &tru_list);
				    seq_printf(m,
					    "\n %u\t%u\t",
					    f_list[i],
					    member_count);
				if (member_count > 0) {
					for (j = 0;
					     j < member_count;
					     j++) {
					        if (RSBAC_UID_SET(tru_list[j]))
						  seq_printf(m,
							    "%u/%u ",
							    RSBAC_UID_SET(tru_list[j]),
							    RSBAC_UID_NUM(tru_list[j]));
					        else
						    seq_printf(m,
							    "%u ",
							    RSBAC_UID_NUM(tru_list[j]));
					}
					rsbac_kfree(tru_list);
					all_member_count +=
					    member_count;
				}
			}
			rsbac_kfree(f_list);
		}
		seq_printf(m,
			    "\ndevice %02u:%02u has %u file trusted user set items, sum of %lu members\n",
			    RSBAC_MAJOR(device_p->id),
			    RSBAC_MINOR(device_p->id), count,
			    all_member_count);
		device_p = rcu_dereference(device_p->next);
	}
	/* unprotect device list */
	srcu_read_unlock(&device_list_srcu, srcu_idx);

	return 0;
}

static ssize_t mac_trulist_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, mac_trulist_proc_show, NULL);
}

static const struct file_operations mac_trulist_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= mac_trulist_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static struct proc_dir_entry *mac_trulist;

#endif				/* CONFIG_PROC_FS && CONFIG_RSBAC_PROC */

/************************************************* */
/*               Init functions                    */
/************************************************* */

/* All functions return 0, if no error occurred, and a negative error code  */
/* otherwise. The error codes are defined in rsbac/error.h.                 */

/************************************************************************** */
/* Initialization of all MAC data structures. After this call, all MAC    */
/* data is kept in memory for performance reasons, but is written to disk   */
/* on every change. */

/* Because there can be no access to aci data structures before init,       */
/* rsbac_init_mac() will initialize all rw-spinlocks to unlocked.          */

#ifdef CONFIG_RSBAC_INIT_DELAY
int rsbac_init_mac(void)
#else
int __init rsbac_init_mac(void)
#endif
{
	int err = 0;
	struct rsbac_mac_device_list_item_t *device_p = NULL;
	struct rsbac_list_lol_info_t lol_info;

	if (rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_init_mac(): RSBAC already initialized\n");
		return -RSBAC_EREINIT;
	}

	rsbac_printk(KERN_INFO "rsbac_init_mac(): Initializing RSBAC: MAC subsystem\n");

	lol_info.version = RSBAC_MAC_P_LIST_VERSION;
	lol_info.key = RSBAC_MAC_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_pid_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_uid_t);
	lol_info.subdata_size = 0;
	lol_info.max_age = 0;
	err = rsbac_list_lol_register(RSBAC_LIST_VERSION,
				      &process_handle,
				      &lol_info,
				      RSBAC_LIST_DEF_DATA,
				      NULL,
				      NULL,
				      NULL,
				      NULL,
				      NULL,
				      NULL,
				      RSBAC_MAC_P_LIST_NAME,
				      RSBAC_AUTO_DEV);
	if (err) {
		char *tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

		if (tmp) {
			rsbac_printk(KERN_WARNING "rsbac_init_mac(): Registering MAC process trusted user list failed with error %s\n",
				     get_error_name(tmp, err));
			rsbac_kfree(tmp);
		}
	}

	/* Init FD lists */
	spin_lock_init(&device_list_head.lock);
	init_srcu_struct(&device_list_srcu);
	lockdep_set_class(&device_list_head.lock, &device_list_lock_class);
	device_list_head.head = NULL;
	device_list_head.tail = NULL;
	device_list_head.curr = NULL;
	device_list_head.count = 0;

	/* read all data */
	rsbac_pr_debug(ds_mac, "rsbac_init_mac(): Registering FD lists\n");
	device_p = create_device_item(rsbac_root_dev);
	if (!device_p) {
		rsbac_printk(KERN_CRIT
			     "rsbac_init_mac(): Could not add device!\n");
		return -RSBAC_ECOULDNOTADDDEVICE;
	}
	if ((err = mac_register_fd_lists(device_p, rsbac_root_dev))) {
		char tmp[RSBAC_MAXNAMELEN];

		rsbac_printk(KERN_WARNING "rsbac_init_mac(): File/Dir trusted user set registration failed for dev %02u:%02u, err %s!\n",
			     RSBAC_MAJOR(rsbac_root_dev),
			     RSBAC_MINOR(rsbac_root_dev),
			     get_error_name(tmp, err));
	}
	/* wait for write access to device_list_head */
	spin_lock(&device_list_head.lock);
	device_p = add_device_item(device_p);
	/* device was added, allow access */
	spin_unlock(&device_list_head.lock);
	if (!device_p) {
		rsbac_printk(KERN_CRIT
			     "rsbac_init_mac(): Could not add device!\n");
		return -RSBAC_ECOULDNOTADDDEVICE;
	}
#if defined(CONFIG_RSBAC_PROC) && defined(CONFIG_PROC_FS)
	mac_devices = proc_create("mac_devices",
			S_IFREG | S_IRUGO | S_IWUGO,
			proc_rsbac_root_p, &mac_devices_proc_fops);
	stats_mac = proc_create("stats_mac",
			S_IFREG | S_IRUGO,
			proc_rsbac_root_p, &stats_mac_proc_fops);
	mac_trulist = proc_create("mac_trusted",
			S_IFREG | S_IRUGO,
			proc_rsbac_root_p, &mac_trulist_proc_fops);
#endif

	rsbac_pr_debug(aef_mac, "Ready.\n");
	return err;
}

int rsbac_mount_mac(kdev_t kdev)
{
	int err = 0;
	struct rsbac_mac_device_list_item_t *device_p;
	struct rsbac_mac_device_list_item_t *new_device_p;
	int srcu_idx;

	rsbac_pr_debug(aef_mac, "mounting device %02u:%02u\n",
		       RSBAC_MAJOR(kdev), RSBAC_MINOR(kdev));
	/* wait for write access to device_list_head */
	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = lookup_device(kdev);
	/* repeated mount? */
	if (device_p) {
		rsbac_printk(KERN_WARNING "rsbac_mount_mac: repeated mount %u of device %02u:%02u\n",
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
	if ((err = mac_register_fd_lists(new_device_p, kdev))) {
		char tmp[RSBAC_MAXNAMELEN];

		rsbac_printk(KERN_WARNING "rsbac_mount_mac(): File/Dir ACL registration failed for dev %02u:%02u, err %s!\n",
			     RSBAC_MAJOR(kdev), RSBAC_MINOR(kdev),
			     get_error_name(tmp, err));
	}

	/* wait for read access to device_list_head */
	srcu_idx = srcu_read_lock(&device_list_srcu);
	/* make sure to only add, if this device item has not been added in the meantime */
	device_p = lookup_device(kdev);
	if (device_p) {
		rsbac_printk(KERN_WARNING "rsbac_mount_mac(): mount race for device %02u:%02u detected!\n",
			     RSBAC_MAJOR(kdev), RSBAC_MINOR(kdev));
		device_p->mount_count++;
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		clear_device_item(new_device_p);
	} else {
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		spin_lock(&device_list_head.lock);
		device_p = add_device_item(new_device_p);
		spin_unlock(&device_list_head.lock);
		if (!device_p) {
			rsbac_printk(KERN_WARNING "rsbac_mount_mac: adding device %02u:%02u failed!\n",
				     RSBAC_MAJOR(kdev), RSBAC_MINOR(kdev));
			clear_device_item(new_device_p);
			err = -RSBAC_ECOULDNOTADDDEVICE;
		}
	}
	return err;
}

/* When umounting a device, its file lists must be removed. */

int rsbac_umount_mac(kdev_t kdev)
{
	struct rsbac_mac_device_list_item_t *device_p;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_umount(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	rsbac_pr_debug(aef_mac, "umounting device %02u:%02u\n",
		       RSBAC_MAJOR(kdev), RSBAC_MINOR(kdev));
	/* sync of attribute lists was done in rsbac_umount */
	/* wait for write access to device_list_head */
	spin_lock(&device_list_head.lock);
	/* OK, nobody else is working on it... */
	device_p = lookup_device(kdev);
	if (device_p) {
		if (device_p->mount_count == 1) {
			remove_device_item(device_p);
			spin_unlock(&device_list_head.lock);
			synchronize_srcu(&device_list_srcu);
			clear_device_item(device_p);
		} else {
			if (device_p->mount_count > 1) {
				device_p->mount_count--;
			} else {
				rsbac_printk(KERN_WARNING "rsbac_mount_mac: device %02u:%02u has mount_count < 1!\n",
					     RSBAC_MAJOR(kdev),
					     RSBAC_MINOR(kdev));
			}
			spin_unlock(&device_list_head.lock);
		}
	} else
		spin_unlock(&device_list_head.lock);
	return 0;
}

/***************************************************/
/* We also need some status information...         */

int rsbac_stats_mac(void)
{
	struct rsbac_mac_device_list_item_t *device_p;
	int srcu_idx;

	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_stats_mac(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	rsbac_pr_debug(aef_mac, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	rsbac_printk(KERN_INFO "MAC Status\n----------\n");

	rsbac_printk(KERN_INFO "%lu process trusted user set items, sum of %lu members\n",
		     rsbac_list_lol_count(process_handle),
		     rsbac_list_lol_all_subcount(process_handle));

	/* protect device list */
	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = rcu_dereference(device_list_head.head);
	while (device_p) {
		rsbac_printk(KERN_INFO "device %02u:%02u has %u file trusted user set items, sum of %u members\n",
			     RSBAC_MAJOR(device_p->id),
			     RSBAC_MINOR(device_p->id),
			     rsbac_list_lol_count(device_p->handle),
			     rsbac_list_lol_all_subcount(device_p->handle));
		device_p = rcu_dereference(device_p->next);
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

/* rsbac_mac_add_to_truset */
/* Add a set member to a set sublist. Set behaviour: also returns success, */
/* if member was already in set! */

int rsbac_mac_add_to_p_truset(rsbac_list_ta_number_t ta_number,
			      rsbac_pid_t pid,
			      rsbac_uid_t member, rsbac_time_t ttl)
{
	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_add_to_p_truset(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_add_to_p_truset(): called from interrupt!\n");
	}
	return rsbac_ta_list_lol_subadd_ttl(ta_number, process_handle, ttl,
					    &pid, &member, NULL);
}

int rsbac_mac_add_to_f_truset(rsbac_list_ta_number_t ta_number,
			      rsbac_mac_file_t file,
			      rsbac_uid_t member, rsbac_time_t ttl)
{
	int err = 0;
	struct rsbac_mac_device_list_item_t *device_p;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_add_to_f_truset(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_add_to_f_truset(): called from interrupt!\n");
	}

	/* protect device list */
	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = lookup_device(file.device);
	if (!device_p) {
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		rsbac_printk(KERN_WARNING "rsbac_mac_add_to_f_truset(): invalid device %02u:%02u!\n",
			     RSBAC_MAJOR(file.device),
			     RSBAC_MINOR(file.device));
		return -RSBAC_EINVALIDDEV;
	}

	err = rsbac_ta_list_lol_subadd_ttl(ta_number,
					   device_p->handle,
					   ttl, &file.inode, &member,
					   NULL);
	srcu_read_unlock(&device_list_srcu, srcu_idx);
	return err;
}

/* rsbac_mac_remove_from_truset */
/* Remove a set member from a sublist. Set behaviour: Returns no error, if */
/* member is not in list.                                                  */

int rsbac_mac_remove_from_p_truset(rsbac_list_ta_number_t ta_number,
				   rsbac_pid_t pid, rsbac_uid_t member)
{
	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_remove_from_p_truset(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_remove_from_p_truset(): called from interrupt!\n");
	}
	return rsbac_ta_list_lol_subremove(ta_number, process_handle, &pid,
					   &member);
}

int rsbac_mac_remove_from_f_truset(rsbac_list_ta_number_t ta_number,
				   rsbac_mac_file_t file,
				   rsbac_uid_t member)
{
	int err = 0;
	struct rsbac_mac_device_list_item_t *device_p;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_remove_from_f_truset(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_remove_from_f_truset(): called from interrupt!\n");
	}

	/* protect device list */
	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = lookup_device(file.device);
	if (!device_p) {
		rsbac_printk(KERN_WARNING "rsbac_mac_remove_from_f_truset(): invalid device %02u:%02u!\n",
			     RSBAC_MAJOR(file.device),
			     RSBAC_MINOR(file.device));
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		return -RSBAC_EINVALIDDEV;
	}
	err = rsbac_ta_list_lol_subremove(ta_number,
					  device_p->handle,
					  &file.inode, &member);
	srcu_read_unlock(&device_list_srcu, srcu_idx);
	return err;
}

/* rsbac_mac_clear_truset */
/* Remove all set members from a sublist. Set behaviour: Returns no error, */
/* if list is empty.                                                       */

int rsbac_mac_clear_p_truset(rsbac_list_ta_number_t ta_number,
			     rsbac_pid_t pid)
{
	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_clear_p_truset(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_clear_p_truset(): called from interrupt!\n");
	}
	return rsbac_ta_list_lol_remove(ta_number, process_handle, &pid);
}

int rsbac_mac_clear_f_truset(rsbac_list_ta_number_t ta_number,
			     rsbac_mac_file_t file)
{
	int err = 0;
	struct rsbac_mac_device_list_item_t *device_p;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_clear_f_truset(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_clear_f_truset(): called from interrupt!\n");
	}
	/* protect device list */
	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = lookup_device(file.device);
	if (!device_p) {
		rsbac_printk(KERN_WARNING "rsbac_mac_clear_f_truset(): invalid device %02u:%02u!\n",
			     RSBAC_MAJOR(file.device),
			     RSBAC_MINOR(file.device));
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		return -RSBAC_EINVALIDDEV;
	}
	err = rsbac_ta_list_lol_remove(ta_number,
				     device_p->handle,
				     &file.inode);
	srcu_read_unlock(&device_list_srcu, srcu_idx);
	return err;
}

/* rsbac_mac_truset_member */
/* Return truth value, whether member is in set */

rsbac_boolean_t rsbac_mac_p_truset_member(rsbac_pid_t pid,
					  rsbac_uid_t member)
{
	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_p_truset_member(): RSBAC not initialized\n");
		return FALSE;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_p_truset_member(): called from interrupt!\n");
	}
	if (rsbac_list_lol_subexist(process_handle, &pid, &member))
		return TRUE;
	member = RSBAC_ALL_USERS;
	return rsbac_list_lol_subexist(process_handle, &pid, &member);
}

/* rsbac_mac_remove_truset */
/* Remove a full set. For cleanup, if object is deleted. */
/* To empty an existing set use rsbac_mac_clear_truset. */

int rsbac_mac_remove_p_trusets(rsbac_pid_t pid)
{
	return rsbac_mac_clear_p_truset(FALSE, pid);
}

int rsbac_mac_remove_f_trusets(rsbac_mac_file_t file)
{
	return rsbac_mac_clear_f_truset(FALSE, file);
}

int rsbac_mac_copy_fp_truset(rsbac_mac_file_t file,
			     rsbac_pid_t p_tru_set_id)
{
	struct rsbac_mac_device_list_item_t *device_p;
	int err = 0;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_copy_fp_truset(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_copy_fp_truset(): called from interrupt!\n");
	}
/*
	rsbac_pr_debug(ds_mac, "Copying file cap set data to process cap set\n");
*/
	/* protect device list */
	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = lookup_device(file.device);
	if (!device_p) {
		rsbac_printk(KERN_WARNING "rsbac_mac_copy_fp_truset(): invalid device %02u:%02u!\n",
			     RSBAC_MAJOR(file.device),
			     RSBAC_MINOR(file.device));
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		return -RSBAC_EINVALIDDEV;
	}
	/* call the copy function */
	err = copy_fp_tru_set_item(device_p, file, p_tru_set_id);
	srcu_read_unlock(&device_list_srcu, srcu_idx);
	return err;
}

int rsbac_mac_copy_pp_truset(rsbac_pid_t old_p_set_id,
			     rsbac_pid_t new_p_set_id)
{
	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_copy_pp_truset(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_copy_pp_truset(): called from interrupt!\n");
	}
/*
	rsbac_pr_debug(ds_mac, "Copying process cap set data to process cap set\n");
*/
	/* call the copy function */
	return copy_pp_tru_set_item(old_p_set_id, new_p_set_id);
}

int rsbac_mac_get_f_trulist(rsbac_list_ta_number_t ta_number,
			    rsbac_mac_file_t file,
			    rsbac_uid_t ** trulist_p,
			    rsbac_time_t ** ttllist_p)
{
	struct rsbac_mac_device_list_item_t *device_p;
	long count;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_get_f_trulist(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_get_f_trulist(): called from interrupt!\n");
	}
/*
	rsbac_pr_debug(ds_mac, "Getting file/dir trusted user set list\n");
*/
	/* protect device list */
	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = lookup_device(file.device);
	if (!device_p) {
		rsbac_printk(KERN_WARNING "rsbac_mac_get_f_trulist(): invalid device %02u:%02u!\n",
			     RSBAC_MAJOR(file.device),
			     RSBAC_MINOR(file.device));
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		return -RSBAC_EINVALIDDEV;
	}
	count = rsbac_ta_list_lol_get_all_subdesc_ttl(ta_number,
						      device_p->handle,
						      &file.inode,
						      (void **) trulist_p,
						      ttllist_p);
	srcu_read_unlock(&device_list_srcu, srcu_idx);
	return count;
}

int rsbac_mac_get_p_trulist(rsbac_list_ta_number_t ta_number,
			    rsbac_pid_t pid,
			    rsbac_uid_t ** trulist_p,
			    rsbac_time_t ** ttllist_p)
{
	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_get_p_trulist(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_mac_get_p_trulist(): called from interrupt!\n");
	}
/*
	rsbac_pr_debug(ds_mac, "Getting process trusted user set list\n");
*/
	return rsbac_ta_list_lol_get_all_subdesc_ttl(ta_number,
						     process_handle,
						     &pid,
						     (void **) trulist_p,
						     ttllist_p);
}
