/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of User Management data structures */
/* Author and (c) 1999-2011: Amon Ott <ao@rsbac.org> */
/*                                                   */
/* Last modified: 12/Jul/2011                        */
/*************************************************** */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/random.h>
#include <asm/uaccess.h>
#include <rsbac/types.h>
#include <rsbac/aci_data_structures.h>
#include <rsbac/um_types.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/adf.h>
#include <rsbac/aci.h>
#include <rsbac/um.h>
#include <rsbac/lists.h>
#include <rsbac/proc_fs.h>
#include <rsbac/rkmem.h>
#include <rsbac/getname.h>
#include <linux/string.h>
#include <linux/delay.h>
#ifdef CONFIG_RSBAC_UM_DIGEST
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#endif
#include <linux/seq_file.h>
/************************************************************************** */
/*                          Global Variables                                */
/************************************************************************** */

static rsbac_list_handle_t user_handle;
static rsbac_list_handle_t group_handle;
#ifdef CONFIG_RSBAC_UM_PWHISTORY
static rsbac_list_handle_t user_pwhistory_handle;
#endif
#ifdef CONFIG_RSBAC_UM_ONETIME
static rsbac_list_handle_t onetime_handle;
#endif
#define EXTRA_ROOM 20

/**************************************************/
/*       Declarations of external functions       */
/**************************************************/

/**************************************************/
/*       Declarations of internal functions       */
/**************************************************/

/************************************************* */
/*               Internal Help functions           */
/************************************************* */

static u_int nr_user_hashes = RSBAC_UM_NR_USER_LISTS;
static u_int nr_group_hashes = RSBAC_UM_NR_GROUP_LISTS;

#ifdef CONFIG_RSBAC_UM_PWHISTORY
static u_int nr_user_pwhistory_hashes = RSBAC_UM_NR_USER_PWHISTORY_LISTS;
#endif

static int user_conv(void *old_desc,
		       void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_um_user_entry_t * new_aci = new_data;
	struct rsbac_um_old_user_entry_t * old_aci = old_data;

	memcpy(&new_aci->name, &old_aci->name, RSBAC_UM_OLD_NAME_LEN);
	memcpy(&new_aci->pass, &old_aci->pass, RSBAC_UM_PASS_LEN);
	memcpy(&new_aci->fullname, &old_aci->fullname, RSBAC_UM_OLD_FULLNAME_LEN);
	memcpy(&new_aci->homedir, &old_aci->homedir, RSBAC_UM_OLD_HOMEDIR_LEN);
	memcpy(&new_aci->shell, &old_aci->shell, RSBAC_UM_OLD_SHELL_LEN);
	new_aci->group = old_aci->group;
	new_aci->lastchange = old_aci->lastchange;
	new_aci->minchange = old_aci->minchange;
	new_aci->maxchange = old_aci->maxchange;
	new_aci->warnchange = old_aci->warnchange;
	new_aci->inactive = old_aci->inactive;
	new_aci->expire = old_aci->expire;
	*((rsbac_uid_t *)new_desc) = *((rsbac_uid_t *)old_desc);
	return 0;
}

static int user_old_conv(void *old_desc,
		       void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_um_user_entry_t * new_aci = new_data;
	struct rsbac_um_old_user_entry_t * old_aci = old_data;

	memcpy(&new_aci->name, &old_aci->name, RSBAC_UM_OLD_NAME_LEN);
	memcpy(&new_aci->pass, &old_aci->pass, RSBAC_UM_PASS_LEN);
	memcpy(&new_aci->fullname, &old_aci->fullname, RSBAC_UM_OLD_FULLNAME_LEN);
	memcpy(&new_aci->homedir, &old_aci->homedir, RSBAC_UM_OLD_HOMEDIR_LEN);
	memcpy(&new_aci->shell, &old_aci->shell, RSBAC_UM_OLD_SHELL_LEN);
	new_aci->group = old_aci->group;
	new_aci->lastchange = old_aci->lastchange;
	new_aci->minchange = old_aci->minchange;
	new_aci->maxchange = old_aci->maxchange;
	new_aci->warnchange = old_aci->warnchange;
	new_aci->inactive = old_aci->inactive;
	new_aci->expire = old_aci->expire;
	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	return 0;
}

rsbac_list_conv_function_t *user_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_UM_USER_OLD_LIST_VERSION:
		return user_conv;
	case RSBAC_UM_USER_OLD_OLD_LIST_VERSION:
		return user_old_conv;
	default:
		return NULL;
	}
}

static int user_subconv(void *old_desc,
		       void *old_data, void *new_desc, void *new_data)
{
	*((rsbac_gid_num_t *)new_desc) = *((rsbac_gid_num_t *)old_desc);
	return 0;
}

static int user_old_subconv(void *old_desc,
		       void *old_data, void *new_desc, void *new_data)
{
	*((rsbac_gid_num_t *)new_desc) = *((rsbac_old_gid_t *)old_desc);
	return 0;
}

rsbac_list_conv_function_t *user_get_subconv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_UM_USER_OLD_LIST_VERSION:
		return user_subconv;
	case RSBAC_UM_USER_OLD_OLD_LIST_VERSION:
		return user_old_subconv;
	default:
		return NULL;
	}
}

static int group_conv(void *old_desc,
		       void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_um_group_entry_t * new_aci = new_data;
	struct rsbac_um_old_group_entry_t * old_aci = old_data;

	memcpy(&new_aci->name, &old_aci->name, RSBAC_UM_OLD_NAME_LEN);
	memcpy(&new_aci->pass, &old_aci->pass, RSBAC_UM_PASS_LEN);
	*((rsbac_gid_t *)new_desc) = *((rsbac_gid_t *)old_desc);
	return 0;
}

static int group_old_conv(void *old_desc,
		       void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_um_group_entry_t * new_aci = new_data;
	struct rsbac_um_old_group_entry_t * old_aci = old_data;

	memcpy(&new_aci->name, &old_aci->name, RSBAC_UM_OLD_NAME_LEN);
	memcpy(&new_aci->pass, &old_aci->pass, RSBAC_UM_PASS_LEN);
	*((rsbac_gid_t *)new_desc) = *((rsbac_old_gid_t *)old_desc);
	return 0;
}

rsbac_list_conv_function_t *group_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_UM_GROUP_OLD_LIST_VERSION:
		return group_conv;
	case RSBAC_UM_GROUP_OLD_OLD_LIST_VERSION:
		return group_old_conv;
	default:
		return NULL;
	}
}

static int user_pwh_conv(void *old_desc,
		       void *old_data, void *new_desc, void *new_data)
{
	memcpy(new_data, old_data, sizeof(__u8));
	*((rsbac_uid_t *) new_desc) = *((rsbac_old_uid_t *) old_desc);
	return 0;
}

rsbac_list_conv_function_t *user_pwh_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_UM_USER_PWHISTORY_OLD_LIST_VERSION:
		return user_pwh_conv;
	default:
		return NULL;
	}
}

static int user_pwh_subconv(void *old_desc,
		       void *old_data, void *new_desc, void *new_data)
{
	memcpy(new_desc, old_desc, sizeof(__u32));
	memcpy(new_data, old_data, RSBAC_UM_PASS_LEN);
	return 0;
}

rsbac_list_conv_function_t *user_pwh_get_subconv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_UM_USER_PWHISTORY_OLD_LIST_VERSION:
		return user_pwh_subconv;
	default:
		return NULL;
	}
}

#ifdef CONFIG_RSBAC_UM_VIRTUAL
static int vset_selector(void *desc, void * param)
{
  if (RSBAC_UID_SET(*((rsbac_uid_t *) desc)) == *((rsbac_um_set_t *) param))
    return TRUE;
  else
    return FALSE;
}
#endif

#if defined(CONFIG_RSBAC_PROC)
static int
stats_um_proc_show(struct seq_file *m, void *v)
{
	u_long user_count;
	u_long group_count;
	u_long member_count;

	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "stats_um_proc_info(): RSBAC not initialized\n");
		return (-RSBAC_ENOTINITIALIZED);
	}
	rsbac_pr_debug(aef_um, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	user_count = rsbac_list_lol_count(user_handle);
	member_count = rsbac_list_lol_all_subcount(user_handle);
	group_count = rsbac_list_count(group_handle);

	seq_printf(m, "UM Status\n---------\n");

	seq_printf(m,
		    "%lu user items with sum of %lu group memberships, %lu group items\n",
		    user_count, member_count, group_count);
	return 0;
}

static ssize_t stats_um_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, stats_um_proc_show, NULL);
}

static const struct file_operations stats_um_proc_fops = {
       .owner          = THIS_MODULE,
       .open           = stats_um_proc_open,
       .read           = seq_read,
       .llseek         = seq_lseek,
       .release        = single_release,
};

static struct proc_dir_entry *stats_um;

#endif				/* CONFIG_PROC_FS && CONFIG_RSBAC_PROC */

static int name_compare(void *data1, void *data2)
{
	struct rsbac_um_user_entry_t *entry_p = data1;
	char *name = data2;

	if (!entry_p || !name)
		return 1;

	return strcmp(entry_p->name, name);
}

static int group_name_compare(void *data1, void *data2)
{
	struct rsbac_um_group_entry_t *entry_p = data1;
	char *name = data2;

	if (!entry_p || !name)
		return 1;

	return strcmp(entry_p->name, name);
}

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
int rsbac_init_um(void)
#else
int __init rsbac_init_um(void)
#endif
{
	int err = 0;
	struct rsbac_list_info_t *list_info_p;
	struct rsbac_list_lol_info_t *lol_info_p;

	if (rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_init_um(): RSBAC already initialized\n");
		return (-RSBAC_EREINIT);
	}

	/* set rw-spinlocks to unlocked status and init data structures */
	rsbac_printk(KERN_INFO "rsbac_init_um(): Initializing RSBAC: User Management subsystem\n");

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
	lol_info_p = rsbac_kmalloc_unlocked(sizeof(*lol_info_p));
	if (!lol_info_p) {
		rsbac_kfree(list_info_p);
		return -ENOMEM;
	}

	lol_info_p->version = RSBAC_UM_USER_LIST_VERSION;
	lol_info_p->key = RSBAC_UM_USER_LIST_KEY;
	lol_info_p->desc_size = sizeof(rsbac_uid_t);
	lol_info_p->data_size = sizeof(struct rsbac_um_user_entry_t);
	lol_info_p->subdesc_size = sizeof(rsbac_gid_num_t);
	lol_info_p->subdata_size = 0;
	lol_info_p->max_age = 0;
	nr_user_hashes = RSBAC_UM_NR_USER_LISTS;

	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				&user_handle, lol_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
				RSBAC_LIST_BACKUP |
#endif
				RSBAC_LIST_PERSIST |
				RSBAC_LIST_REPLICATE |
				RSBAC_LIST_AUTO_HASH_RESIZE |
				RSBAC_LIST_OWN_SLAB,
				NULL, NULL,
				user_get_conv,
				user_get_subconv,
				NULL, NULL,
				RSBAC_UM_USER_LIST_NAME,
				RSBAC_AUTO_DEV,
				nr_user_hashes,
				rsbac_list_hash_uid,
				RSBAC_UM_OLD_USER_LIST_NAME);
	if (err) {
		char *tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

		if (tmp) {
			rsbac_printk(KERN_WARNING "rsbac_init_um(): Registering user list of lists %s failed with error %s\n",
				     RSBAC_UM_USER_LIST_NAME, get_error_name(tmp, err));
			rsbac_kfree(tmp);
		}
	}

	list_info_p->version = RSBAC_UM_GROUP_LIST_VERSION;
	list_info_p->key = RSBAC_UM_GROUP_LIST_KEY;
	list_info_p->desc_size = sizeof(rsbac_gid_t);
	list_info_p->data_size = sizeof(struct rsbac_um_group_entry_t);
	list_info_p->max_age = 0;
	nr_group_hashes = RSBAC_UM_NR_GROUP_LISTS;
	err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
				&group_handle, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
				RSBAC_LIST_BACKUP |
#endif
				RSBAC_LIST_PERSIST |
				RSBAC_LIST_REPLICATE |
				RSBAC_LIST_AUTO_HASH_RESIZE |
				RSBAC_LIST_OWN_SLAB,
				NULL,
				group_get_conv,
				NULL, RSBAC_UM_GROUP_LIST_NAME,
				RSBAC_AUTO_DEV,
				nr_group_hashes,
				rsbac_list_hash_gid,
				RSBAC_UM_OLD_GROUP_LIST_NAME);
	if (err) {
		char *tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

		if (tmp) {
			rsbac_printk(KERN_WARNING "rsbac_init_um(): Registering group list %s failed with error %s\n",
				     RSBAC_UM_GROUP_LIST_NAME, get_error_name(tmp, err));
			rsbac_kfree(tmp);
		}
	}

#ifdef CONFIG_RSBAC_UM_PWHISTORY
	{
		__u8 def_max_history = CONFIG_RSBAC_UM_PWHISTORY_MAX;

		lol_info_p->version = RSBAC_UM_USER_PWHISTORY_LIST_VERSION;
		lol_info_p->key = RSBAC_UM_USER_PWHISTORY_LIST_KEY;
		lol_info_p->desc_size = sizeof(rsbac_uid_t);
		lol_info_p->data_size = sizeof(__u8);
		lol_info_p->subdesc_size = sizeof(__u32);
		lol_info_p->subdata_size = RSBAC_UM_PASS_LEN;
		lol_info_p->max_age = 0;
		nr_user_pwhistory_hashes = RSBAC_UM_NR_USER_LISTS;
		err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
						&user_pwhistory_handle,
						lol_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
						RSBAC_LIST_BACKUP |
#endif
						RSBAC_LIST_PERSIST |
						RSBAC_LIST_DEF_DATA |
						RSBAC_LIST_AUTO_HASH_RESIZE,
						NULL, NULL,
						user_pwh_get_conv, user_pwh_get_subconv,
						&def_max_history, NULL,
						RSBAC_UM_USER_PWHISTORY_LIST_NAME,
						RSBAC_AUTO_DEV,
						nr_user_pwhistory_hashes,
						rsbac_list_hash_uid,
						RSBAC_UM_OLD_USER_PWHISTORY_LIST_NAME);
		if (err) {
			char *tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

			if (tmp) {
				rsbac_printk(KERN_WARNING "rsbac_init_um(): Registering user password history list of lists %s failed with error %s\n",
					     RSBAC_UM_USER_PWHISTORY_LIST_NAME,
					     get_error_name(tmp,
							    err));
				rsbac_kfree(tmp);
			}
		}
	}
#endif

#ifdef CONFIG_RSBAC_UM_ONETIME
	{
		lol_info_p->version = RSBAC_UM_ONETIME_LIST_VERSION;
		lol_info_p->key = RSBAC_UM_ONETIME_LIST_KEY;
		lol_info_p->desc_size = sizeof(rsbac_uid_t);
		lol_info_p->data_size = 0;
		lol_info_p->subdesc_size = RSBAC_UM_PASS_LEN;
		lol_info_p->subdata_size = 0;
		lol_info_p->max_age = 0;
		err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
						&onetime_handle,
						lol_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
						RSBAC_LIST_BACKUP |
#endif
						RSBAC_LIST_PERSIST |
						RSBAC_LIST_DEF_DATA |
						RSBAC_LIST_AUTO_HASH_RESIZE |
						RSBAC_LIST_OWN_SLAB,
						NULL, NULL,
						NULL, NULL, /* conv */
						NULL, NULL,
						RSBAC_UM_ONETIME_LIST_NAME,
						RSBAC_AUTO_DEV,
						1,
						rsbac_list_hash_uid,
						NULL);
		if (err) {
			char *tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

			if (tmp) {
				rsbac_printk(KERN_WARNING "rsbac_init_um(): Registering user password one-time list of lists %s failed with error %s\n",
					     RSBAC_UM_USER_PWHISTORY_LIST_NAME,
					     get_error_name(tmp,
							    err));
				rsbac_kfree(tmp);
			}
		} else {
			rsbac_list_lol_max_items(onetime_handle,
				RSBAC_UM_ONETIME_LIST_KEY,
				RSBAC_LIST_MAX_NR_ITEMS,
				CONFIG_RSBAC_UM_ONETIME_MAX);
		}
	}
#endif


#if defined(CONFIG_RSBAC_PROC)
	stats_um = proc_create("stats_um", S_IFREG | S_IRUGO,
					proc_rsbac_root_p, &stats_um_proc_fops);
#endif

	rsbac_pr_debug(ds_um, "Ready.\n");
	rsbac_kfree(list_info_p);
	rsbac_kfree(lol_info_p);
	return err;
}

/***************************************************/
/* We also need some status information...         */

int rsbac_stats_um(void)
{
	u_long user_count;
	u_long group_count;
	u_long member_count;

	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_stats_um(): RSBAC not initialized\n");
		return (-RSBAC_ENOTINITIALIZED);
	}
	rsbac_pr_debug(aef_um, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	user_count = rsbac_list_lol_count(user_handle);
	member_count = rsbac_list_lol_all_subcount(user_handle);
	group_count = rsbac_list_count(group_handle);
	rsbac_printk(KERN_INFO "UM Status\n---------\n");

	rsbac_printk(KERN_INFO "%lu user items with sum of %lu group memberships, %lu group items\n",
		     user_count, member_count, group_count);
	return 0;
}

/************************************************* */
/*               Access functions                  */
/************************************************* */

/* Trying to access a never created or removed user entry returns an error! */
#ifndef offset_in_page
#define offset_in_page(p) ((unsigned long)(p) & ~PAGE_MASK)
#endif

static inline void new_salt(__u32 * salt_p)
{
	*salt_p = 0;
	while (!*salt_p)
		get_random_bytes(salt_p, sizeof(*salt_p));
}

int rsbac_um_hash(char *pass, __u32 salt)
{
#ifdef CONFIG_RSBAC_UM_DIGEST
	char *buffer;
	struct scatterlist sg[1];
	struct crypto_hash *tfm;
	struct hash_desc hd;
	u_int len;
	u_int plen;
	int err = 0;

	plen = strlen(pass);
	len = rsbac_max(plen + sizeof(salt), RSBAC_UM_PASS_LEN);
	buffer = rsbac_kmalloc_unlocked(len);
	if (!buffer)
		return -RSBAC_ENOMEM;

	if (!crypto_has_hash("sha1", 0, 0)) {
		rsbac_printk(KERN_WARNING "rsbac_um_hash(): User management configured for crypto API with SHA1, but SHA1 is not available!\n");
		err = -RSBAC_ENOTFOUND;
		goto out;
	}

	tfm = crypto_alloc_hash("sha1", 0, 0);
	if (!tfm) {
		rsbac_printk(KERN_WARNING "pid %u/%.15s: rsbac_um_hash(): Could not allocate tfm for SHA1!\n",
			current->pid, current->comm);
		err = -RSBAC_ENOTFOUND;
		goto out;
	}
	memset(buffer, 0, len);
	memcpy(buffer, &salt, sizeof(salt));
	strcpy(buffer + sizeof(salt), pass);
	sg_init_one(sg, buffer, plen + sizeof(salt));

	hd.tfm = tfm;
	hd.flags = 0;
	err = crypto_hash_init(&hd);
	if(err) {
		rsbac_printk(KERN_WARNING "pid %u/%.15s: rsbac_um_hash(): crypto_hash_init() failed with error %u!\n",
			current->pid, current->comm, err);
		goto out;
	}
	err = crypto_hash_update(&hd, sg, sg[0].length);
	if(err) {
		rsbac_printk(KERN_WARNING "pid %u/%.15s: rsbac_um_hash(): crypto_hash_update() failed with error %u!\n",
			current->pid, current->comm, err);
		goto out;
	}
	err = crypto_hash_final(&hd, pass);
	if(err) {
		rsbac_printk(KERN_WARNING "pid %u/%.15s: rsbac_um_hash(): crypto_hash_final() failed with error %u!\n",
			current->pid, current->comm, err);
		goto out;
	}
	crypto_free_hash(tfm);
out:
	rsbac_kfree(buffer);
	return err;
#else
	/* no crypto: just zero rest of string to allow comparizon */
	u_int len;

	len = strlen(pass);
	if (len < RSBAC_UM_PASS_LEN)
		memset(pass + len, 0, RSBAC_UM_PASS_LEN - len);
	return 0;
#endif
}

int rsbac_um_get_uid(rsbac_list_ta_number_t ta_number,
			char *name,
			rsbac_uid_t * uid_p)
{
	int err;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
	rsbac_um_set_t vset;
#endif

	if (!name || !uid_p)
		return -RSBAC_EINVALIDPOINTER;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
	vset = RSBAC_UID_SET(*uid_p);
	if (vset == RSBAC_UM_VIRTUAL_KEEP) {
		char * p = name;

		while (*p && (*p != '/'))
			p++;
		if (*p) {
			*p = 0;
			err = rsbac_get_vset_num(name, &vset);
			if (err)
				return err;
			p++;
			name = p;
			if (vset == RSBAC_UM_VIRTUAL_KEEP)
				vset = rsbac_get_vset();
		} else
			vset = rsbac_get_vset();
	}
	if (!strcmp(name, "ALL")) {
		*uid_p = RSBAC_GEN_UID(vset, RSBAC_ALL_USERS);
		return 0;
	}
	if (vset != RSBAC_UM_VIRTUAL_ALL)
		err = rsbac_ta_list_lol_get_desc_selector(ta_number,
					user_handle,
					uid_p,
					name,
					name_compare,
					vset_selector,
					&vset);
	else
#endif
		err = rsbac_ta_list_lol_get_desc(ta_number,
					user_handle,
					uid_p,
					name,
					name_compare);
	if (!err)
		return 0;
	else
		return -RSBAC_ENOTFOUND;
}

int rsbac_um_get_gid(rsbac_list_ta_number_t ta_number,
		     char *name, rsbac_gid_t * gid_p)
{
	int err;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
	rsbac_um_set_t vset;
#endif

	if (!name || !gid_p)
		return -RSBAC_EINVALIDPOINTER;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
	vset = RSBAC_GID_SET(*gid_p);
	if (vset == RSBAC_UM_VIRTUAL_KEEP) {
		char * p = name;

		while (*p && (*p != '/'))
			p++;
		if (*p) {
			*p = 0;
			err = rsbac_get_vset_num(name, &vset);
			if (err)
				return err;
			p++;
			name = p;
			if (vset == RSBAC_UM_VIRTUAL_KEEP)
				vset = rsbac_get_vset();
		} else
			vset = rsbac_get_vset();
	}
	if (!strcmp(name, "ALL")) {
		*gid_p = RSBAC_GEN_GID(vset, RSBAC_ALL_GROUPS);
		return 0;
	}
	if (vset != RSBAC_UM_VIRTUAL_ALL)
		err = rsbac_ta_list_get_desc_selector(ta_number,
					group_handle,
					gid_p,
					name,
					group_name_compare,
					vset_selector,
					&vset);
	else
#endif
		err = rsbac_ta_list_get_desc(ta_number,
				    group_handle,
				    gid_p,
				    name, group_name_compare);
	if (!err)
		return 0;
	else
		return -RSBAC_ENOTFOUND;
}

int rsbac_um_add_user(rsbac_list_ta_number_t ta_number,
		      rsbac_uid_t * user_p,
		      struct rsbac_um_user_entry_t *entry_p,
		      char *pass, rsbac_time_t ttl)
{
	int err;
	rsbac_uid_t user;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_um_add_user(): RSBAC not initialized\n");
		return (-RSBAC_ENOTINITIALIZED);
	}
	if (!entry_p || !user_p)
		return -RSBAC_EINVALIDPOINTER;
	user = *user_p;
#ifdef CONFIG_RSBAC_UM_EXCL
	if (!rsbac_um_no_excl) {
	    rsbac_gid_t gid = RSBAC_GEN_GID(RSBAC_UID_SET(user),
					entry_p->group);
	    if (!rsbac_ta_list_exist(ta_number,
				    group_handle,
				    &gid)) {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
		if (RSBAC_GID_SET(gid))
			rsbac_printk(KERN_INFO "rsbac_um_add_user(): gid %u/%u not known to RSBAC User Management!\n",
			     RSBAC_GID_SET(gid), entry_p->group);
		else
#endif
			rsbac_printk(KERN_INFO "rsbac_um_add_user(): gid %u not known to RSBAC User Management!\n",
			     entry_p->group);
		return -RSBAC_EINVALIDVALUE;
	    }
	}
#endif
	if (RSBAC_UID_NUM(user) == RSBAC_NO_USER) {
		user = RSBAC_GEN_UID(RSBAC_UID_SET(user),
				CONFIG_RSBAC_UM_USER_MIN);
		while (rsbac_ta_list_lol_exist
		       (ta_number, user_handle, &user))
			user++;
	} else
	    if (rsbac_ta_list_lol_exist
		(ta_number, user_handle, &user))
		return -RSBAC_EEXISTS;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
	if (RSBAC_UID_SET(user))
		rsbac_pr_debug(aef_um, "pid %u/%.15s: adding user %u/%u\n",
			current->pid, current->comm,
			RSBAC_UID_SET(user), RSBAC_UID_NUM(user));
	else
#endif
		rsbac_pr_debug(aef_um, "pid %u/%.15s: adding user %u\n",
			current->pid, current->comm, RSBAC_UID_NUM(user));
	if (pass) {
		__u32 salt;

		new_salt(&salt);
		err = rsbac_um_hash(pass, salt);
		if (err)
			return err;
		memcpy(entry_p->pass, &salt, sizeof(salt));
		memcpy(entry_p->pass + sizeof(salt), pass,
		       RSBAC_UM_PASS_LEN - sizeof(salt));
	} else
		memset(entry_p->pass, 0, RSBAC_UM_PASS_LEN);
	err =
	    rsbac_ta_list_lol_add_ttl(ta_number,
				      user_handle, ttl,
				      &user, entry_p);
	if (!err)
		*user_p = user;
	return err;
}

int rsbac_um_add_group(rsbac_list_ta_number_t ta_number,
		       rsbac_gid_t * group_p,
		       struct rsbac_um_group_entry_t *entry_p,
		       char *pass, rsbac_time_t ttl)
{
	int err;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_um_add_group(): RSBAC not initialized\n");
		return (-RSBAC_ENOTINITIALIZED);
	}
	if (!entry_p || !group_p)
		return -RSBAC_EINVALIDPOINTER;
	if (RSBAC_GID_NUM(*group_p) == RSBAC_NO_USER) {
		*group_p = RSBAC_GEN_GID(RSBAC_GID_SET(*group_p), CONFIG_RSBAC_UM_GROUP_MIN);
		while (rsbac_ta_list_exist
		       (ta_number, group_handle,
			group_p))
			(*group_p)++;
	} else
	    if (rsbac_ta_list_exist
		(ta_number, group_handle, group_p))
		return -RSBAC_EEXISTS;
	if (RSBAC_GID_SET(*group_p))
		rsbac_pr_debug(aef_um, "pid %u/%.15s: adding group %u/%u\n",
			current->pid, current->comm,
			RSBAC_GID_SET(*group_p), RSBAC_GID_NUM(*group_p));
	else
		rsbac_pr_debug(aef_um, "pid %u/%.15s: adding group %u\n",
			current->pid, current->comm, RSBAC_GID_NUM(*group_p));
	if (pass) {
		__u32 salt;

		new_salt(&salt);
		err = rsbac_um_hash(pass, salt);
		if (err)
			return err;
		memcpy(entry_p->pass, &salt, sizeof(salt));
		memcpy(entry_p->pass + sizeof(salt), pass,
		       RSBAC_UM_PASS_LEN - sizeof(salt));
	} else
		memset(entry_p->pass, 0, RSBAC_UM_PASS_LEN);
	return rsbac_ta_list_add_ttl(ta_number,
				     group_handle,
				     ttl, group_p, entry_p);
}

int rsbac_um_add_gm(rsbac_list_ta_number_t ta_number,
		    rsbac_uid_t user, rsbac_gid_num_t group, rsbac_time_t ttl)
{
	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_um_add_gm(): RSBAC not initialized\n");
		return (-RSBAC_ENOTINITIALIZED);
	}
#ifdef CONFIG_RSBAC_UM_EXCL
	if (!rsbac_um_no_excl) {
        	rsbac_gid_t gid = RSBAC_GEN_GID(RSBAC_UID_SET(user),
					group);

		if (!rsbac_ta_list_exist
		    (ta_number, user_handle, &user)) {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
			if (RSBAC_UID_SET(user))
				rsbac_printk(KERN_INFO "rsbac_um_add_gm(): uid %u/%u not known to RSBAC User Management!\n",
				     RSBAC_UID_SET(user), RSBAC_UID_NUM(user));
		else
#endif
			rsbac_printk(KERN_INFO "rsbac_um_add_gm(): uid %u not known to RSBAC User Management!\n",
				     RSBAC_UID_SET(user));
			return -RSBAC_ENOTFOUND;
		}
		if (!rsbac_ta_list_exist
		    (ta_number, group_handle, &gid)) {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
			if (RSBAC_GID_SET(gid))
				rsbac_printk(KERN_INFO "rsbac_um_add_gm(): gid %u/%u not known to RSBAC User Management!\n",
				     RSBAC_GID_SET(gid), group);
		else
#endif
			rsbac_printk(KERN_INFO "rsbac_um_add_gm(): gid %u not known to RSBAC User Management!\n",
				     group);
			return -RSBAC_ENOTFOUND;
		}
	}
#endif
	rsbac_pr_debug(aef_um, "pid %u/%.15s: adding user %u group %u\n",
		current->pid, current->comm, user, group);
	return rsbac_ta_list_lol_subadd_ttl(ta_number,
					    user_handle,
					    ttl, &user, &group, NULL);
}

int rsbac_um_mod_user(rsbac_list_ta_number_t ta_number,
		      rsbac_uid_t user,
		      enum rsbac_um_mod_t mod,
		      union rsbac_um_mod_data_t *data_p)
{
	int err;
	struct rsbac_um_user_entry_t *entry_p;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_um_mod_user(): RSBAC not initialized\n");
		return (-RSBAC_ENOTINITIALIZED);
	}
	if (!data_p && (mod != UM_pass)
	    )
		return -RSBAC_EINVALIDPOINTER;
	if (!rsbac_ta_list_lol_exist
	    (ta_number, user_handle, &user))
		return -RSBAC_ENOTFOUND;

	entry_p = rsbac_kmalloc_unlocked(sizeof(*entry_p));
	if (!entry_p)
		return -RSBAC_ENOMEM;
	err =
	    rsbac_ta_list_lol_get_data_ttl(ta_number,
					   user_handle,
					   NULL, &user, entry_p);
	if (err) {
		rsbac_kfree(entry_p);
		return err;
	}
	rsbac_pr_debug(aef_um, "pid %u/%.15s: modifying user %u\n",
		current->pid, current->comm, user);
	switch (mod) {
	case UM_name:
		{
			rsbac_uid_t tmp_user = user;

			if (!rsbac_um_get_uid
			    (ta_number, data_p->string, &tmp_user)
			    && (tmp_user != user)
			    )
				return -RSBAC_EEXISTS;
			strncpy(entry_p->name, data_p->string,
				RSBAC_UM_NAME_LEN);
			entry_p->name[RSBAC_UM_NAME_LEN - 1] = 0;
		}
		break;

	case UM_pass:
		if (data_p) {
			__u32 salt;

			new_salt(&salt);
			err = rsbac_um_hash(data_p->string, salt);
			if (err) {
				rsbac_kfree(entry_p);
				return err;
			}
			memcpy(entry_p->pass, &salt, sizeof(salt));
			memcpy(entry_p->pass + sizeof(salt),
			       data_p->string,
			       RSBAC_UM_PASS_LEN - sizeof(salt));
		} else
			memset(entry_p->pass, 0, RSBAC_UM_PASS_LEN);
		entry_p->lastchange = RSBAC_CURRENT_TIME / 86400;
		break;

	case UM_cryptpass:
		memcpy(entry_p->pass, data_p->string, RSBAC_UM_PASS_LEN);
		break;

	case UM_fullname:
		strncpy(entry_p->fullname, data_p->string,
			RSBAC_UM_FULLNAME_LEN);
		entry_p->fullname[RSBAC_UM_FULLNAME_LEN - 1] = 0;
		break;

	case UM_homedir:
		strncpy(entry_p->homedir, data_p->string,
			RSBAC_UM_HOMEDIR_LEN);
		entry_p->homedir[RSBAC_UM_HOMEDIR_LEN - 1] = 0;
		break;

	case UM_shell:
		strncpy(entry_p->shell, data_p->string,
			RSBAC_UM_SHELL_LEN);
		entry_p->shell[RSBAC_UM_SHELL_LEN - 1] = 0;
		break;

	case UM_group:
#ifdef CONFIG_RSBAC_UM_EXCL
		{
			rsbac_gid_t gid = RSBAC_GEN_GID(RSBAC_UID_SET(user),
							data_p->group);
			if (!rsbac_um_no_excl
			    && !rsbac_ta_list_exist(ta_number,
						    group_handle,
						    &gid)) {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
				if (RSBAC_GID_SET(gid))
					rsbac_printk(KERN_INFO "rsbac_um_mod_user(): gid %u/%u not known to RSBAC User Management!\n",
					     RSBAC_GID_SET(gid), RSBAC_GID_NUM(gid));
				else
#endif
					rsbac_printk(KERN_INFO "rsbac_um_mod_user(): gid %u not known to RSBAC User Management!\n",
					     RSBAC_GID_NUM(gid));
				rsbac_kfree(entry_p);
				return -RSBAC_EINVALIDVALUE;
			}
		}
#endif
		entry_p->group = data_p->group;
		break;

	case UM_lastchange:
		entry_p->lastchange = data_p->days;
		break;

	case UM_minchange:
		entry_p->minchange = data_p->days;
		break;

	case UM_maxchange:
		entry_p->maxchange = data_p->days;
		break;

	case UM_warnchange:
		entry_p->warnchange = data_p->days;
		break;

	case UM_inactive:
		entry_p->inactive = data_p->days;
		break;

	case UM_expire:
		entry_p->expire = data_p->days;
		break;

	case UM_ttl:
		err =
		    rsbac_ta_list_lol_add_ttl(ta_number,
					      user_handle,
					      data_p->ttl, &user, entry_p);
		rsbac_kfree(entry_p);
		return err;

	default:
		rsbac_kfree(entry_p);
		return -RSBAC_EINVALIDREQUEST;
	}

	err =
	    rsbac_ta_list_lol_add_ttl(ta_number,
				      user_handle,
				      RSBAC_LIST_TTL_KEEP, &user, entry_p);
	rsbac_kfree(entry_p);
	return err;
}

int rsbac_um_mod_group(rsbac_list_ta_number_t ta_number,
		       rsbac_uid_t group,
		       enum rsbac_um_mod_t mod,
		       union rsbac_um_mod_data_t *data_p)
{
	int err;
	struct rsbac_um_group_entry_t *entry_p;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_um_mod_group(): RSBAC not initialized\n");
		return (-RSBAC_ENOTINITIALIZED);
	}
	if (!data_p && (mod != UM_pass)
	    )
		return -RSBAC_EINVALIDPOINTER;
	if (!rsbac_ta_list_exist
	    (ta_number, group_handle, &group))
		return -RSBAC_ENOTFOUND;

	entry_p = rsbac_kmalloc_unlocked(sizeof(*entry_p));
	if (!entry_p)
		return -RSBAC_ENOMEM;
	err =
	    rsbac_ta_list_get_data_ttl(ta_number,
				       group_handle,
				       NULL, &group, entry_p);
	if (err) {
		rsbac_kfree(entry_p);
		return err;
	}
	rsbac_pr_debug(aef_um, "pid %u/%.15s: modifying group %u\n",
		current->pid, current->comm, group);
	switch (mod) {
	case UM_name:
		{
			rsbac_gid_t tmp_group = group;

			if (!rsbac_um_get_gid
			    (ta_number, data_p->string, &tmp_group)
			    && (tmp_group != group)
			    )
				return -RSBAC_EEXISTS;
			strncpy(entry_p->name, data_p->string,
				RSBAC_UM_NAME_LEN);
			entry_p->name[RSBAC_UM_NAME_LEN - 1] = 0;
		}
		break;

	case UM_pass:
		if (data_p) {
			__u32 salt;

			new_salt(&salt);
			err = rsbac_um_hash(data_p->string, salt);
			if (err) {
				rsbac_kfree(entry_p);
				return err;
			}
			memcpy(entry_p->pass, &salt, sizeof(salt));
			memcpy(entry_p->pass + sizeof(salt),
			       data_p->string,
			       RSBAC_UM_PASS_LEN - sizeof(salt));
		} else
			memset(entry_p->pass, 0, RSBAC_UM_PASS_LEN);
		break;

	case UM_cryptpass:
		memcpy(entry_p->pass, data_p->string, RSBAC_UM_PASS_LEN);
		break;

	case UM_ttl:
		err =
		    rsbac_ta_list_add_ttl(ta_number,
					  group_handle,
					  data_p->ttl, &group, entry_p);
		rsbac_kfree(entry_p);
		return err;

	default:
		rsbac_kfree(entry_p);
		return -RSBAC_EINVALIDREQUEST;
	}

	err =
	    rsbac_ta_list_add_ttl(ta_number,
				  group_handle,
				  RSBAC_LIST_TTL_KEEP, &group, entry_p);
	rsbac_kfree(entry_p);
	return err;
}

int rsbac_um_get_user_item(rsbac_list_ta_number_t ta_number,
			   rsbac_uid_t user,
			   enum rsbac_um_mod_t mod,
			   union rsbac_um_mod_data_t *data_p)
{
	int err;
	struct rsbac_um_user_entry_t *entry_p;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_um_get_user_item(): RSBAC not initialized\n");
		return (-RSBAC_ENOTINITIALIZED);
	}
	if (!data_p)
		return -RSBAC_EINVALIDPOINTER;
	if (!rsbac_ta_list_lol_exist
	    (ta_number, user_handle, &user))
		return -RSBAC_ENOTFOUND;
	if (mod == UM_ttl)
		return rsbac_ta_list_lol_get_data_ttl(ta_number,
						      user_handle,
						      &data_p->ttl, &user,
						      NULL);

	entry_p = rsbac_kmalloc_unlocked(sizeof(*entry_p));
	if (!entry_p)
		return -RSBAC_ENOMEM;
	err =
	    rsbac_ta_list_lol_get_data_ttl(ta_number,
					   user_handle,
					   NULL, &user, entry_p);
	if (err) {
		rsbac_kfree(entry_p);
		return err;
	}
	switch (mod) {
	case UM_name:
		strcpy(data_p->string, entry_p->name);
		break;

	case UM_pass:
		memcpy(data_p->string, entry_p->pass, RSBAC_UM_PASS_LEN);
		break;

	case UM_fullname:
		strcpy(data_p->string, entry_p->fullname);
		break;

	case UM_homedir:
		strcpy(data_p->string, entry_p->homedir);
		break;

	case UM_shell:
		strcpy(data_p->string, entry_p->shell);
		break;

	case UM_group:
		data_p->group = entry_p->group;
		break;

	case UM_lastchange:
		data_p->days = entry_p->lastchange;
		break;

	case UM_minchange:
		data_p->days = entry_p->minchange;
		break;

	case UM_maxchange:
		data_p->days = entry_p->maxchange;
		break;

	case UM_warnchange:
		data_p->days = entry_p->warnchange;
		break;

	case UM_inactive:
		data_p->days = entry_p->inactive;
		break;

	case UM_expire:
		data_p->days = entry_p->expire;
		break;

	default:
		rsbac_kfree(entry_p);
		return -RSBAC_EINVALIDREQUEST;
	}

	rsbac_kfree(entry_p);
	return 0;
}

int rsbac_um_get_group_item(rsbac_list_ta_number_t ta_number,
			    rsbac_gid_t group,
			    enum rsbac_um_mod_t mod,
			    union rsbac_um_mod_data_t *data_p)
{
	int err;
	struct rsbac_um_group_entry_t *entry_p;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_um_get_group_item(): RSBAC not initialized\n");
		return (-RSBAC_ENOTINITIALIZED);
	}
	if (!data_p)
		return -RSBAC_EINVALIDPOINTER;
	if (!rsbac_ta_list_exist
	    (ta_number, group_handle, &group))
		return -RSBAC_ENOTFOUND;
	if (mod == UM_ttl)
		return rsbac_ta_list_get_data_ttl(ta_number,
						  group_handle,
						  &data_p->ttl, &group,
						  NULL);

	entry_p = rsbac_kmalloc_unlocked(sizeof(*entry_p));
	if (!entry_p)
		return -RSBAC_ENOMEM;
	err =
	    rsbac_ta_list_get_data_ttl(ta_number,
				       group_handle,
				       NULL, &group, entry_p);
	if (err) {
		rsbac_kfree(entry_p);
		return err;
	}
	switch (mod) {
	case UM_name:
		strcpy(data_p->string, entry_p->name);
		break;

	case UM_pass:
		memcpy(data_p->string, entry_p->pass, RSBAC_UM_PASS_LEN);
		break;

	default:
		rsbac_kfree(entry_p);
		return -RSBAC_EINVALIDREQUEST;
	}

	rsbac_kfree(entry_p);
	return 0;
}

int rsbac_um_user_exists(rsbac_list_ta_number_t ta_number,
			 rsbac_uid_t user)
{
	return rsbac_ta_list_lol_exist(ta_number,
				       user_handle,
				       &user);
}

int rsbac_um_group_exists(rsbac_list_ta_number_t ta_number,
			  rsbac_gid_t group)
{
	return rsbac_ta_list_exist(ta_number,
				   group_handle,
				   &group);
}

int rsbac_um_remove_user(rsbac_list_ta_number_t ta_number,
			 rsbac_uid_t user)
{
	if (!rsbac_ta_list_lol_exist
	    (ta_number, user_handle, &user))
		return -RSBAC_ENOTFOUND;
	return rsbac_ta_list_lol_remove(ta_number,
					user_handle,
					&user);
}

int rsbac_um_remove_group(rsbac_list_ta_number_t ta_number,
			  rsbac_gid_t group)
{
	rsbac_gid_num_t group_num;

	if (!rsbac_ta_list_exist
	    (ta_number, group_handle, &group))
		return -RSBAC_ENOTFOUND;
	group_num = RSBAC_GID_NUM(group);
	rsbac_ta_list_lol_subremove_from_all(ta_number,
					     user_handle,
					     &group_num);
	return rsbac_ta_list_remove(ta_number,
				    group_handle,
				    &group);
}

int rsbac_um_remove_gm(rsbac_list_ta_number_t ta_number,
		       rsbac_uid_t user, rsbac_gid_num_t group)
{
	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_um_remove_gm(): RSBAC not initialized\n");
		return (-RSBAC_ENOTINITIALIZED);
	}
	rsbac_pr_debug(aef_um, "pid %u/%.15s: removing user %u group %u\n",
		current->pid, current->comm, user, group);
	return rsbac_ta_list_lol_subremove(ta_number,
					   user_handle,
					   &user, &group);
}

int rsbac_um_get_user_entry(rsbac_list_ta_number_t ta_number,
			    rsbac_uid_t user,
			    struct rsbac_um_user_entry_t *entry_p,
			    rsbac_time_t * ttl_p)
{
	return rsbac_ta_list_lol_get_data_ttl(ta_number,
					      user_handle,
					      ttl_p, &user, entry_p);
}

int rsbac_um_get_next_user(rsbac_list_ta_number_t ta_number,
			   rsbac_uid_t old_user, rsbac_uid_t * next_user_p)
{
	rsbac_uid_t *old_user_p;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
	rsbac_um_set_t vset;
#endif

	if (old_user == RSBAC_NO_USER)
		old_user_p = NULL;
	else
		old_user_p = &old_user;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
	vset = RSBAC_UID_SET(old_user);
	if (vset != RSBAC_UM_VIRTUAL_ALL)
		return rsbac_ta_list_lol_get_next_desc_selector(ta_number,
					    user_handle,
					    old_user_p,
					    next_user_p,
					    vset_selector,
					    &vset);
	else
#endif
		return rsbac_ta_list_lol_get_next_desc(ta_number,
					    user_handle,
					    old_user_p,
					    next_user_p);
}

int rsbac_um_get_user_list(rsbac_list_ta_number_t ta_number,
			rsbac_um_set_t vset,
			rsbac_uid_t ** list_pp)
{
	if(!list_pp)
		return rsbac_ta_list_lol_count(ta_number, user_handle);
	else {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
		if (vset != RSBAC_UM_VIRTUAL_ALL)
			return rsbac_ta_list_lol_get_all_desc_selector(
					ta_number,
					user_handle,
					(void **) list_pp,
					vset_selector,
					&vset);
		else
#endif
			return rsbac_ta_list_lol_get_all_desc(ta_number,
					   user_handle,
					   (void **) list_pp);
	}
}

int rsbac_um_get_gm_list(rsbac_list_ta_number_t ta_number,
			 rsbac_uid_t user, rsbac_gid_num_t ** list_pp)
{
	if (!list_pp)
		return rsbac_ta_list_lol_subcount(ta_number,
						  user_handle,
						  &user);
	else
		return rsbac_ta_list_lol_get_all_subdesc_ttl(ta_number,
							     user_handle,
							     &user,
							     (void **) list_pp,
							     NULL);
}

int rsbac_um_get_gm_user_list(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t group,
  rsbac_uid_num_t ** list_pp)
  {
    int j;
    long all_count = 0;
    long copy_count = 0;
    long tmp_count;
    rsbac_uid_t * tmp_list_p;
    rsbac_uid_num_t * collect_list_p;
    rsbac_uid_num_t * p;
    rsbac_um_set_t gid_set;
    rsbac_gid_num_t gid_num;

#ifdef CONFIG_RSBAC_UM_EXCL
    if(!rsbac_um_no_excl && !rsbac_ta_list_exist(ta_number, group_handle, &group))
      {
        return -RSBAC_ENOTFOUND;
      }
#endif
    all_count = rsbac_ta_list_lol_count(ta_number, user_handle);
    if(!list_pp || (all_count <= 0))
      return all_count;

    /* provide some extra room in case new groups have been added during this function run */
    all_count += EXTRA_ROOM;
    collect_list_p = rsbac_kmalloc_unlocked(all_count * sizeof(rsbac_uid_num_t));
    if(!collect_list_p)
      return -RSBAC_ENOMEM;
    p = collect_list_p;
    tmp_count = rsbac_ta_list_lol_get_all_desc(ta_number, user_handle, (void *) &tmp_list_p);
    if(tmp_count > 0)
      {
        gid_set = RSBAC_GID_SET(group);
        gid_num = RSBAC_GID_NUM(group);
        for(j=0; j<tmp_count; j++)
          {
            if(   (RSBAC_UID_SET(tmp_list_p[j]) == gid_set)
               && rsbac_ta_list_lol_subexist(ta_number, user_handle, &tmp_list_p[j], &gid_num))
              {
                *p = RSBAC_UID_NUM(tmp_list_p[j]);
                p++;
                copy_count++;
              }
          }
        rsbac_kfree(tmp_list_p);
      }
    if(!copy_count)
      rsbac_kfree(collect_list_p);
    else
      *list_pp = collect_list_p;
    return copy_count;
  }

int rsbac_um_get_group_list(rsbac_list_ta_number_t ta_number,
			rsbac_um_set_t vset,
			rsbac_gid_t ** list_pp)
{
	if(!list_pp)
		return rsbac_ta_list_count(ta_number, group_handle);
	else {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
		if (vset != RSBAC_UM_VIRTUAL_ALL)
			return rsbac_ta_list_get_all_desc_selector(
					ta_number,
					group_handle,
					(void **) list_pp,
					vset_selector,
					&vset);
		else
#endif
			return rsbac_ta_list_get_all_desc(ta_number,
					   group_handle,
					   (void **) list_pp);
	}
}

int rsbac_um_check_pass(rsbac_uid_t uid, char *pass)
{
	int err;
	struct rsbac_um_user_entry_t *entry_p;
	__u32 salt;
	u_long curdays;
	char * pass_copy;

	if (!pass)
		return -RSBAC_EINVALIDPOINTER;
	entry_p = rsbac_kmalloc_unlocked(sizeof(*entry_p));
	if (!entry_p)
		return -RSBAC_ENOMEM;
	err = rsbac_ta_list_lol_get_data_ttl(0, user_handle,
					NULL, &uid, entry_p);
	if (err)
		goto out_free;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
	if(RSBAC_UID_SET(uid))
		rsbac_pr_debug(aef_um, "pid %u/%.15s: checking password for user %u/%u\n",
			current->pid, current->comm, RSBAC_UID_SET(uid), RSBAC_UID_NUM(uid));
	else
#endif
		rsbac_pr_debug(aef_um, "pid %u/%.15s: checking password for user %u\n",
			current->pid, current->comm, RSBAC_UID_NUM(uid));
	/* check whether account or password has expired */
	curdays = RSBAC_CURRENT_TIME / 86400;
	if ((curdays > entry_p->expire) && (entry_p->expire != -1)
	    && (entry_p->expire != 0) && (entry_p->lastchange != 0)) {
		err = -RSBAC_EEXPIRED;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
		if(RSBAC_UID_SET(uid))
			rsbac_pr_debug(aef_um, "pid %u/%.15s: account for user %u/%u has expired\n",
				current->pid, current->comm, RSBAC_UID_SET(uid), RSBAC_UID_NUM(uid));
		else
#endif
			rsbac_pr_debug(aef_um, "pid %u/%.15s: account for user %u has expired\n",
				current->pid, current->comm, RSBAC_UID_NUM(uid));
		goto out_free;
	}
	if ((curdays >
	     (entry_p->lastchange + entry_p->maxchange +
	      entry_p->inactive))
	    && (entry_p->maxchange != -1)
	    && (entry_p->maxchange)
	    && (entry_p->inactive != -1)
	    && (entry_p->inactive)
	    && (entry_p->lastchange)
	    ) {
		err = -RSBAC_EEXPIRED;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
		if(RSBAC_UID_SET(uid))
			rsbac_pr_debug(aef_um, "pid %u/%.15s: password for user %u/%u has expired\n",
			       current->pid, current->comm, RSBAC_UID_SET(uid), RSBAC_UID_NUM(uid));
		else
#endif
			rsbac_pr_debug(aef_um, "pid %u/%.15s: password for user %u has expired\n",
			       current->pid, current->comm, RSBAC_UID_NUM(uid));
		goto out_free;
	}

/* rsbac_um_hash destroys old pass, so make a copy */
	pass_copy = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
	if (!pass_copy) {
		err = -RSBAC_ENOMEM;
		goto out_free;
	}
	strncpy(pass_copy, pass, RSBAC_MAXNAMELEN);
	pass_copy[RSBAC_MAXNAMELEN - 1] = 0;
	salt = *((__u32 *) entry_p->pass);
	if (   !salt
	    || rsbac_um_hash(pass_copy, salt)
	    || memcmp (pass_copy, entry_p->pass + sizeof(salt),
			RSBAC_UM_PASS_LEN - sizeof(salt))) {
#ifdef CONFIG_RSBAC_UM_ONETIME
		rsbac_um_password_t * pw_array;
		int count;

		count = rsbac_list_lol_get_all_subdesc(onetime_handle,
			&uid, (void **) &pw_array);
		if (count > 0) {
			u_int i;

			rsbac_pr_debug(aef_um, "pid %u/%.15s: check %u one-time passwords for user %u/%u\n",
			       current->pid, current->comm, count, RSBAC_UID_SET(uid), RSBAC_UID_NUM(uid));
			err = -EPERM;
			for (i=0; i<count ;i++) {
				salt = *((__u32 *) pw_array[i]);
				strncpy(pass_copy, pass, RSBAC_MAXNAMELEN);
				pass_copy[RSBAC_MAXNAMELEN - 1] = 0;
				if (!salt || rsbac_um_hash(pass_copy, salt))
					continue;
				if (!memcmp
				    (pass_copy, pw_array[i] + sizeof(salt),
				     RSBAC_UM_PASS_LEN - sizeof(salt))) {
					/* found pw: remove and success */
					rsbac_pr_debug(aef_um, "pid %u/%.15s: one-time password %u for user %u/%u matched, removing\n",
					       current->pid, current->comm, i, RSBAC_UID_SET(uid), RSBAC_UID_NUM(uid));
					rsbac_list_lol_subremove(onetime_handle,
						&uid, pw_array[i]);
					err = 0;
					break;
				}
			}
			rsbac_kfree(pw_array);
		} else
#endif
		err = -EPERM;
	} else
		err = 0;

	rsbac_kfree(pass_copy);
out_free:
	rsbac_kfree(entry_p);
	if (err)
		ssleep(1);
	return err;
}

int rsbac_um_good_pass(rsbac_uid_t uid, char *pass)
{
#ifdef CONFIG_RSBAC_UM_NON_ALPHA
	char *p;
#endif
#ifdef CONFIG_RSBAC_UM_PWHISTORY
	int i;
	long count;
	char *hist_pass;
	char *tmp;
	__u8 *pwhistory_array;
	__u32 salt;
#endif

	if (!pass)
		return -RSBAC_EINVALIDPOINTER;
	if (strlen(pass) < CONFIG_RSBAC_UM_MIN_PASS_LEN)
		return -RSBAC_EWEAKPASSWORD;

#ifdef CONFIG_RSBAC_UM_NON_ALPHA
	p = pass;
	while (*p && (((*p >= 'a')
		       && (*p <= 'z')
		      )
		      || ((*p >= 'A')
			  && (*p <= 'Z')
		      )
	       )
	    )
		p++;
	if (!(*p))
		return -RSBAC_EWEAKPASSWORD;
#endif

#ifdef CONFIG_RSBAC_UM_PWHISTORY
	count = rsbac_ta_list_lol_get_all_subdata(0,
					      user_pwhistory_handle,
					      &uid,
					      (void **) &pwhistory_array);
	if (count > 0) {
		tmp =
		    rsbac_kmalloc_unlocked(rsbac_max
				  (strlen(pass), RSBAC_UM_PASS_LEN));
		hist_pass = pwhistory_array;

		for (i = 0; i < count; i++) {
			salt = *((__u32 *) hist_pass);
			memcpy(tmp, pass,
			       rsbac_max(strlen(pass), RSBAC_UM_PASS_LEN));
			rsbac_um_hash(tmp, salt);

			if (memcmp
			    (tmp, hist_pass + sizeof(salt),
			     RSBAC_UM_PASS_LEN - sizeof(salt)) == 0) {
				rsbac_kfree(tmp);
				rsbac_kfree(pwhistory_array);
				return -RSBAC_EWEAKPASSWORD;
			}
			hist_pass += RSBAC_UM_PASS_LEN;
		}
		rsbac_kfree(tmp);
		rsbac_kfree(pwhistory_array);
	}
#endif

	return 0;
}

#ifdef CONFIG_RSBAC_UM_ONETIME
int rsbac_um_add_onetime(rsbac_uid_t uid, char *pass, rsbac_time_t ttl)
{
	int err;
	__u32 salt;
	char pass_entry[RSBAC_UM_PASS_LEN];

	if (!pass)
		return -RSBAC_EINVALIDPOINTER;

	if (RSBAC_UID_SET(uid))
		rsbac_pr_debug(aef_um, "pid %u/%.15s: add one-time password for user %u/%u with ttl %lu\n",
			current->pid, current->comm, RSBAC_UID_SET(uid), RSBAC_UID_NUM(uid), ttl);
	else
		rsbac_pr_debug(aef_um, "pid %u/%.15s: add one-time password for user %u with ttl %lu\n",
			current->pid, current->comm, RSBAC_UID_NUM(uid), ttl);
	new_salt(&salt);
	err = rsbac_um_hash(pass, salt);
	if (err)
		return err;
	memcpy(pass_entry, &salt, sizeof(salt));
	memcpy(pass_entry + sizeof(salt), pass,
	       RSBAC_UM_PASS_LEN - sizeof(salt));

	return rsbac_list_lol_subadd_ttl(onetime_handle, ttl, &uid, pass_entry, NULL);
}

int rsbac_um_remove_all_onetime(rsbac_uid_t uid)
{
	rsbac_pr_debug(aef_um, "pid %u/%.15s: remove all one-time passwords for user %u/%u\n",
		current->pid, current->comm, RSBAC_UID_SET(uid), RSBAC_UID_NUM(uid));
	return rsbac_list_lol_subremove_all(onetime_handle, &uid);
}

int rsbac_um_count_onetime(rsbac_uid_t uid)
{
	int err;

	rsbac_pr_debug(aef_um, "pid %u/%.15s: counting one-time passwords for user %u/%u\n",
		current->pid, current->comm, RSBAC_UID_SET(uid), RSBAC_UID_NUM(uid));
	err = rsbac_list_lol_subcount(onetime_handle, &uid);
	if (err == -RSBAC_ENOTFOUND)
		err = 0;
	return err;
}
#endif

int rsbac_um_set_pass(rsbac_uid_t uid, char *pass)
{
	int err;
	struct rsbac_um_user_entry_t *entry_p;
	__u32 salt;

	entry_p = rsbac_kmalloc_unlocked(sizeof(*entry_p));
	if (!entry_p)
		return -RSBAC_ENOMEM;
	err =
	    rsbac_ta_list_lol_get_data_ttl(0, user_handle,
					   NULL, &uid, entry_p);
	if (err)
		goto out_free;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
	if(RSBAC_UID_SET(uid))
		rsbac_pr_debug(aef_um, "pid %u/%.15s: setting password for user %u/%u\n",
			current->pid, current->comm, RSBAC_UID_SET(uid), RSBAC_UID_NUM(uid));
	else
#endif
		rsbac_pr_debug(aef_um, "pid %u/%.15s: setting password for user %u\n",
			current->pid, current->comm, RSBAC_UID_NUM(uid));
	if (pass) {
#ifdef CONFIG_RSBAC_UM_PWHISTORY
		__u32 max_index = 0;
		__u8 max_history = CONFIG_RSBAC_UM_PWHISTORY_MAX;
		long count;
#endif
		new_salt(&salt);
		err = rsbac_um_hash(pass, salt);
		if (err)
			goto out_free;
		memcpy(entry_p->pass, &salt, sizeof(salt));
		memcpy(entry_p->pass + sizeof(salt), pass,
		       RSBAC_UM_PASS_LEN - sizeof(salt));
#ifdef CONFIG_RSBAC_UM_PWHISTORY
		rsbac_list_lol_get_data(user_pwhistory_handle,
					&uid,
					&max_history);
		if (max_history > 0) {
			rsbac_ta_list_lol_get_max_subdesc(0,
						user_pwhistory_handle,
						&uid,
						&max_index);
			max_index++;

			if (max_index != 0)
				rsbac_list_lol_subadd(user_pwhistory_handle,
						      &uid, &max_index,
						      entry_p->pass);
			else {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
				if(RSBAC_UID_SET(uid))
					rsbac_printk(KERN_WARNING "rsbac_um_set_pass(): maximum password history index reached for user %u/%u, password will not be stored!\n",
						RSBAC_UID_SET(uid), RSBAC_UID_NUM(uid));
				else
#endif
					rsbac_printk(KERN_WARNING "rsbac_um_set_pass(): maximum password history index reached for user %u, password will not be stored!\n",
						RSBAC_UID_NUM(uid));
			}
			count =
			    rsbac_list_lol_subcount(user_pwhistory_handle,
					    &uid);
			if (count > max_history)
				rsbac_ta_list_lol_subremove_count(0,
								 user_pwhistory_handle,
								 &uid,
								 (count - max_history));
		}
#endif
	} else
		memset(entry_p->pass, 0, RSBAC_UM_PASS_LEN);
	entry_p->lastchange = RSBAC_CURRENT_TIME / 86400;
	err = rsbac_ta_list_lol_add_ttl(0, user_handle,
					0, &uid, entry_p);

      out_free:
	rsbac_kfree(entry_p);
	return err;
}

int rsbac_um_set_group_pass(rsbac_gid_t gid, char *pass)
{
	int err;
	struct rsbac_um_group_entry_t *entry_p;
	__u32 salt;

	entry_p = rsbac_kmalloc_unlocked(sizeof(*entry_p));
	if (!entry_p)
		return -RSBAC_ENOMEM;
	err = rsbac_ta_list_get_data_ttl(0, group_handle,
					 NULL, &gid, entry_p);
	if (err)
		goto out_free;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
	if(RSBAC_GID_SET(gid))
		rsbac_pr_debug(aef_um, "pid %u/%.15s: setting password for group %u/%u\n",
			current->pid, current->comm, RSBAC_GID_SET(gid), RSBAC_GID_NUM(gid));
	else
#endif
		rsbac_pr_debug(aef_um, "pid %u/%.15s: setting password for group %u\n",
			current->pid, current->comm, RSBAC_GID_NUM(gid));
	if (pass) {
		new_salt(&salt);
		err = rsbac_um_hash(pass, salt);
		if (err)
			goto out_free;
		memcpy(entry_p->pass, &salt, sizeof(salt));
		memcpy(entry_p->pass + sizeof(salt), pass,
		       RSBAC_UM_PASS_LEN - sizeof(salt));
	} else
		memset(entry_p->pass, 0, RSBAC_UM_PASS_LEN);
	err =
	    rsbac_ta_list_add_ttl(0, group_handle, 0,
				  &gid, entry_p);

      out_free:
	rsbac_kfree(entry_p);
	return err;
}

int rsbac_um_check_account(rsbac_uid_t uid)
{
	int err;
	struct rsbac_um_user_entry_t *entry_p;
	u_long curdays;

	entry_p = rsbac_kmalloc_unlocked(sizeof(*entry_p));
	if (!entry_p)
		return -RSBAC_ENOMEM;
	err =
	    rsbac_ta_list_lol_get_data_ttl(0, user_handle,
					   NULL, &uid, entry_p);
	if (err)
		goto out_free;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
	if(RSBAC_UID_SET(uid))
		rsbac_pr_debug(aef_um, "pid %u/%.15s: checking account for user %u/%u\n",
			current->pid, current->comm, RSBAC_UID_SET(uid), RSBAC_UID_NUM(uid));
	else
#endif
		rsbac_pr_debug(aef_um, "pid %u/%.15s: checking account for user %u\n",
			current->pid, current->comm, RSBAC_UID_NUM(uid));
	/* check whether account or password has expired */
	curdays = RSBAC_CURRENT_TIME / 86400;
	if (*((__u32 *) entry_p->pass)
	    && !entry_p->lastchange) {
		err = -RSBAC_EMUSTCHANGE;
		rsbac_pr_debug(aef_um, "pid %u/%.15s: user %u must change password, "
			       "lastchange = 0\n", current->pid, current->comm, uid);
                               goto out_free;
	}
	if ((curdays > entry_p->expire)
	    && (entry_p->expire != -1)
	    && (entry_p->expire)
	    ) {
		err = -RSBAC_EEXPIRED;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
		if(RSBAC_UID_SET(uid))
			rsbac_pr_debug(aef_um, "pid %u/%.15s: account for user %u/%u has expired\n",
			       current->pid, current->comm, RSBAC_UID_SET(uid), RSBAC_UID_NUM(uid));
		else
#endif
			rsbac_pr_debug(aef_um, "pid %u/%.15s: account for user %u has expired\n",
			       current->pid, current->comm, RSBAC_UID_NUM(uid));
		goto out_free;
	}
	if ((curdays >
	     (entry_p->lastchange + entry_p->maxchange +
	      entry_p->inactive))
	    && (entry_p->maxchange != -1)
	    && (entry_p->maxchange)
	    && (entry_p->inactive != -1)
	    && (entry_p->inactive)
	    ) {
		err = -RSBAC_EEXPIRED;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
		if(RSBAC_UID_SET(uid))
			rsbac_pr_debug(aef_um, "pid %u/%.15s: password for user %u/%u has expired\n",
			       current->pid, current->comm, RSBAC_UID_SET(uid), RSBAC_UID_NUM(uid));
		else
#endif
			rsbac_pr_debug(aef_um, "pid %u/%.15s: password for user %u has expired\n",
			       current->pid, current->comm, RSBAC_UID_NUM(uid));
		goto out_free;
	}
	if (((entry_p->lastchange + entry_p->maxchange) < curdays)
	    && entry_p->maxchange && (entry_p->maxchange != -1)
	    ) {
		err = -RSBAC_EMUSTCHANGE;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
		if(RSBAC_UID_SET(uid))
			rsbac_pr_debug(aef_um, "pid %u/%.15s: user %u/%u must change password, "
			       "lastchange too old\n",
			       current->pid, current->comm, RSBAC_UID_SET(uid), RSBAC_UID_NUM(uid));
		else
#endif
			rsbac_pr_debug(aef_um, "pid %u/%.15s: user %u must change password, "
			       "lastchange too old\n",
			       current->pid, current->comm, RSBAC_UID_NUM(uid));
		goto out_free;
	}
	if ((curdays >
	     (entry_p->lastchange + entry_p->maxchange -
	      entry_p->warnchange))
	    && (entry_p->maxchange != -1)
	    && (entry_p->warnchange != -1)
	    && entry_p->maxchange && entry_p->warnchange) {
		err = (entry_p->lastchange + entry_p->maxchange) - curdays;
	} else
		err = 0;

      out_free:
	rsbac_kfree(entry_p);
	return err;
}

#ifdef CONFIG_RSBAC_UM_PWHISTORY
int rsbac_um_get_max_history(rsbac_list_ta_number_t ta_number, rsbac_uid_t uid)
{
	int err;
	__u8 max_history;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
	if(RSBAC_UID_SET(uid))
		rsbac_pr_debug(aef_um, "pid %u/%.15s: getting max_history for user %u/%u\n",
			current->pid, current->comm, RSBAC_UID_SET(uid), RSBAC_UID_NUM(uid));
	else
#endif
		rsbac_pr_debug(aef_um, "pid %u/%.15s: getting max_history for user %u\n",
			current->pid, current->comm, RSBAC_UID_NUM(uid));
	err = rsbac_ta_list_lol_get_data_ttl(ta_number, user_pwhistory_handle,
					NULL,
					&uid,
					&max_history);
	if (err)
		return err;
	else
		return max_history;
}

int rsbac_um_set_max_history(rsbac_list_ta_number_t ta_number, rsbac_uid_t uid, __u8 max_history)
{
	int err;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
	if(RSBAC_UID_SET(uid))
		rsbac_pr_debug(aef_um, "pid %u/%.15s: setting max_history for user %u/%u to %u\n",
			current->pid, current->comm, RSBAC_UID_SET(uid), RSBAC_UID_NUM(uid), max_history);
	else
#endif
		rsbac_pr_debug(aef_um, "pid %u/%.15s: setting max_history for user %u to %u\n",
			current->pid, current->comm, RSBAC_UID_NUM(uid), max_history);
	err = rsbac_ta_list_lol_add_ttl(ta_number, user_pwhistory_handle,
					0,
					&uid,
					&max_history);
	if (err)
		return err;
	if (max_history > 0) {
		long count;

		count = rsbac_ta_list_lol_subcount(ta_number,
						user_pwhistory_handle,
						&uid);
		if (count > max_history)
			rsbac_ta_list_lol_subremove_count(ta_number,
							user_pwhistory_handle,
							&uid,
							(count - max_history));
	} else {
		rsbac_ta_list_lol_subremove_all(ta_number,
						user_pwhistory_handle,
						&uid);
	}
	return 0;
}
#endif
