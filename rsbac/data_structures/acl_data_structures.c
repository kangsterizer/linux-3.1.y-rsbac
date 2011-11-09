/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of ACL data structures             */
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
#include <rsbac/acl_data_structures.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/adf.h>
#include <rsbac/aci.h>
#include <rsbac/acl.h>
#include <rsbac/lists.h>
#include <rsbac/proc_fs.h>
#include <rsbac/getname.h>
#include <rsbac/acl_getname.h>
#include <rsbac/rkmem.h>
#include <rsbac/network.h>
#include <linux/string.h>
#include <linux/srcu.h>
#include <linux/seq_file.h>
#include <linux/module.h>

/************************************************************************** */
/*                          Global Variables                                */
/************************************************************************** */

/* The following global variables are needed for access to ACL data.*/

static struct rsbac_acl_device_list_head_t * device_list_head_p;
static spinlock_t device_list_lock;
static struct srcu_struct device_list_srcu;
static struct lock_class_key device_list_lock_class;

static rsbac_list_handle_t dev_handle = NULL;
static rsbac_list_handle_t dev_major_handle = NULL;
static rsbac_list_handle_t scd_handle = NULL;
static rsbac_list_handle_t group_handle = NULL;
static rsbac_list_handle_t gm_handle = NULL;
#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
static rsbac_list_handle_t netdev_handle = NULL;
#endif
#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
static rsbac_list_handle_t nettemp_nt_handle = NULL;
static rsbac_list_handle_t nettemp_handle = NULL;
static rsbac_list_handle_t netobj_handle = NULL;
#endif

static rsbac_list_handle_t default_fd_handle = NULL;
static rsbac_list_handle_t default_dev_handle = NULL;
static rsbac_list_handle_t default_ipc_handle = NULL;
static rsbac_list_handle_t default_scd_handle = NULL;
static rsbac_list_handle_t u_handle = NULL;
static rsbac_list_handle_t default_u_handle = NULL;
static rsbac_list_handle_t default_p_handle = NULL;
#ifdef CONFIG_RSBAC_ACL_UM_PROT
static rsbac_list_handle_t g_handle = NULL;
static rsbac_list_handle_t default_g_handle = NULL;
#endif
#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
static rsbac_list_handle_t default_netdev_handle = NULL;
static rsbac_acl_rights_vector_t default_netdev_rights = 0;
#endif
#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
static rsbac_list_handle_t default_nettemp_nt_handle = NULL;
static rsbac_list_handle_t default_netobj_handle = NULL;
static rsbac_acl_rights_vector_t default_nettemp_nt_rights = 0;
static rsbac_acl_rights_vector_t default_netobj_rights = 0;
#endif

static rsbac_acl_group_id_t group_last_new = 0;

static rsbac_acl_rights_vector_t default_fd_rights = 0;
static rsbac_acl_rights_vector_t default_dev_rights = 0;
static rsbac_acl_rights_vector_t default_ipc_rights = 0;
static rsbac_acl_rights_vector_t default_scd_rights = 0;
static rsbac_acl_rights_vector_t default_u_rights = 0;
#ifdef CONFIG_RSBAC_ACL_UM_PROT
static rsbac_acl_rights_vector_t default_g_rights = 0;
#endif
static rsbac_acl_rights_vector_t default_p_rights = 0;

static struct kmem_cache * acl_device_item_slab = NULL;

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

/* nr_hashes is always 2^n, no matter what the macros say */

static u_int nr_fd_hashes = RSBAC_ACL_NR_FD_LISTS;

static u_int group_hash(void * desc, __u32 nr_hashes)
{
	return (*((rsbac_acl_group_id_t *) desc) & (nr_hashes - 1));
}

static int entry_compare(void *desc1, void *desc2)
{
	int result;
	struct rsbac_acl_entry_desc_t *i_desc1 = desc1;
	struct rsbac_acl_entry_desc_t *i_desc2 = desc2;

	result = memcmp(&i_desc1->subj_type,
			&i_desc2->subj_type, sizeof(i_desc1->subj_type));
	if (result)
		return result;
	else
		return memcmp(&i_desc1->subj_id,
			      &i_desc2->subj_id, sizeof(i_desc1->subj_id));
}

static int dev_compare(void *desc1, void *desc2)
{
	int result;
	struct rsbac_dev_desc_t *i_desc1 = desc1;
	struct rsbac_dev_desc_t *i_desc2 = desc2;

	result = memcmp(&i_desc1->type,
			&i_desc2->type, sizeof(i_desc1->type));
	if (result)
		return result;
	result = memcmp(&i_desc1->major,
			&i_desc2->major, sizeof(i_desc1->major));
	if (result)
		return result;
	return memcmp(&i_desc1->minor,
		      &i_desc2->minor, sizeof(i_desc1->minor));
}

static int dev_major_compare(void *desc1, void *desc2)
{
	int result;
	struct rsbac_dev_desc_t *i_desc1 = desc1;
	struct rsbac_dev_desc_t *i_desc2 = desc2;

	result = memcmp(&i_desc1->type,
			&i_desc2->type, sizeof(i_desc1->type));
	if (result)
		return result;
	return memcmp(&i_desc1->major,
		      &i_desc2->major, sizeof(i_desc1->major));
}

#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
static int netdev_compare(void *desc1, void *desc2)
{
	return strncmp(desc1, desc2, RSBAC_IFNAMSIZ);
}
#endif

static int fd_conv(void *old_desc,
		   void *old_data, void *new_desc, void *new_data)
{
	memcpy(new_desc, old_desc, sizeof(rsbac_inode_nr_t));
	memcpy(new_data, old_data, sizeof(rsbac_acl_rights_vector_t));
	return 0;
}

static int fd_old_conv(void *old_desc,
		   void *old_data, void *new_desc, void *new_data)
{
	rsbac_acl_rights_vector_t *new = new_data;
	rsbac_acl_rights_vector_t *old = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_inode_nr_t));
	*new = (*old & RSBAC_ALL_REQUEST_VECTOR)
	    | ((*old & ~(RSBAC_ALL_REQUEST_VECTOR)) <<
	       (RSBAC_ACL_SPECIAL_RIGHT_BASE -
		RSBAC_ACL_OLD_SPECIAL_RIGHT_BASE));
	return 0;
}

static rsbac_list_conv_function_t *fd_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_FD_OLD_LIST_VERSION:
		return fd_conv;
	case RSBAC_ACL_FD_OLD_OLD_LIST_VERSION:
		return fd_old_conv;
	default:
		return NULL;
	}
}

static int dev_conv(void *old_desc,
		   void *old_data, void *new_desc, void *new_data)
{
	memcpy(new_desc, old_desc, sizeof(struct rsbac_dev_desc_t));
	memcpy(new_data, old_data, sizeof(rsbac_acl_rights_vector_t));
	return 0;
}

static int dev_old_conv(void *old_desc,
		    void *old_data, void *new_desc, void *new_data)
{
	rsbac_acl_rights_vector_t *new = new_data;
	rsbac_acl_rights_vector_t *old = old_data;

	memcpy(new_desc, old_desc, sizeof(struct rsbac_dev_desc_t));
	*new = (*old & RSBAC_ALL_REQUEST_VECTOR)
	    | ((*old & ~(RSBAC_ALL_REQUEST_VECTOR)) <<
	       (RSBAC_ACL_SPECIAL_RIGHT_BASE -
		RSBAC_ACL_OLD_SPECIAL_RIGHT_BASE));
	return 0;
}

static int dev_old_old_conv(void *old_desc,
			void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_dev_desc_t *new = new_desc;
	struct rsbac_dev_t *old = old_desc;
	rsbac_acl_rights_vector_t *newd = new_data;
	rsbac_acl_rights_vector_t *oldd = old_data;


	memcpy(new_data, old_data, sizeof(rsbac_acl_rights_vector_t));
	new->type = old->type;
	new->major = RSBAC_MAJOR(old->id);
	new->minor = RSBAC_MINOR(old->id);
	*newd = (*oldd & RSBAC_ALL_REQUEST_VECTOR)
	    | ((*oldd & ~(RSBAC_ALL_REQUEST_VECTOR)) <<
	       (RSBAC_ACL_SPECIAL_RIGHT_BASE -
		RSBAC_ACL_OLD_SPECIAL_RIGHT_BASE));
	return 0;
}

static rsbac_list_conv_function_t *dev_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_DEV_OLD_LIST_VERSION:
		return dev_conv;
	case RSBAC_ACL_DEV_OLD_OLD_LIST_VERSION:
		return dev_old_conv;
	case RSBAC_ACL_DEV_OLD_OLD_OLD_LIST_VERSION:
		return dev_old_old_conv;
	default:
		return NULL;
	}
}

static int scd_conv(void *old_desc,
		   void *old_data, void *new_desc, void *new_data)
{
	memcpy(new_desc, old_desc, sizeof(__u8));
	memcpy(new_data, old_data, sizeof(rsbac_acl_rights_vector_t));
	return 0;
}

static int scd_old_conv(void *old_desc,
		    void *old_data, void *new_desc, void *new_data)
{
	rsbac_acl_rights_vector_t *new = new_data;
	rsbac_acl_rights_vector_t *old = old_data;

	memcpy(new_desc, old_desc, sizeof(__u8));
	*new = (*old & RSBAC_ALL_REQUEST_VECTOR)
	    | ((*old & ~(RSBAC_ALL_REQUEST_VECTOR)) <<
	       (RSBAC_ACL_SPECIAL_RIGHT_BASE -
		RSBAC_ACL_OLD_SPECIAL_RIGHT_BASE));
	return 0;
}

static rsbac_list_conv_function_t *scd_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_SCD_OLD_LIST_VERSION:
		return scd_conv;
	case RSBAC_ACL_SCD_OLD_OLD_LIST_VERSION:
		return scd_old_conv;
	default:
		return NULL;
	}
}

static int u_conv(void *old_desc,
		   void *old_data, void *new_desc, void *new_data)
{
	rsbac_uid_t *new = new_desc;
	rsbac_old_uid_t *old = old_desc;

	*new = *old;
	memcpy(new_data, old_data, sizeof(rsbac_acl_rights_vector_t));
	return 0;
}

static rsbac_list_conv_function_t *u_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_U_OLD_LIST_VERSION:
		return u_conv;
	default:
		return NULL;
	}
}

#ifdef CONFIG_RSBAC_ACL_UM_PROT
static int g_conv(void *old_desc,
		   void *old_data, void *new_desc, void *new_data)
{
	rsbac_gid_t *new = new_desc;
	rsbac_old_gid_t *old = old_desc;

	*new = *old;
	memcpy(new_data, old_data, sizeof(rsbac_acl_rights_vector_t));
	return 0;
}

static rsbac_list_conv_function_t *g_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_G_OLD_LIST_VERSION:
		return g_conv;
	default:
		return NULL;
	}
}
#endif

#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
static int netdev_conv(void *old_desc,
		   void *old_data, void *new_desc, void *new_data)
{
	memcpy(new_desc, old_desc, sizeof(rsbac_netdev_id_t));
	memcpy(new_data, old_data, sizeof(rsbac_acl_rights_vector_t));
	return 0;
}

static int netdev_old_conv(void *old_desc,
		       void *old_data, void *new_desc, void *new_data)
{
	rsbac_acl_rights_vector_t *new = new_data;
	rsbac_acl_rights_vector_t *old = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_netdev_id_t));
	*new = (*old & RSBAC_ALL_REQUEST_VECTOR)
	    | ((*old & ~(RSBAC_ALL_REQUEST_VECTOR)) <<
	       (RSBAC_ACL_SPECIAL_RIGHT_BASE -
		RSBAC_ACL_OLD_SPECIAL_RIGHT_BASE));
	return 0;
}

static rsbac_list_conv_function_t *netdev_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_NETDEV_OLD_LIST_VERSION:
		return netdev_conv;
	case RSBAC_ACL_NETDEV_OLD_OLD_LIST_VERSION:
		return netdev_old_conv;
	default:
		return NULL;
	}
}
#endif

static int nettemp_nt_conv(void *old_desc,
		   void *old_data, void *new_desc, void *new_data)
{
	memcpy(new_desc, old_desc, sizeof(rsbac_net_temp_id_t));
	memcpy(new_data, old_data, sizeof(rsbac_acl_rights_vector_t));
	return 0;
}

static int nettemp_nt_old_conv(void *old_desc,
			   void *old_data, void *new_desc, void *new_data)
{
	rsbac_acl_rights_vector_t *new = new_data;
	rsbac_acl_rights_vector_t *old = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_net_temp_id_t));
	*new = (*old & RSBAC_ALL_REQUEST_VECTOR)
	    | ((*old & ~(RSBAC_ALL_REQUEST_VECTOR)) <<
	       (RSBAC_ACL_SPECIAL_RIGHT_BASE -
		RSBAC_ACL_OLD_SPECIAL_RIGHT_BASE));
	return 0;
}

static rsbac_list_conv_function_t *nettemp_nt_get_conv(rsbac_version_t
						old_version)
{
	switch (old_version) {
	case RSBAC_ACL_NETTEMP_NT_OLD_LIST_VERSION:
		return nettemp_nt_conv;
	case RSBAC_ACL_NETTEMP_NT_OLD_OLD_LIST_VERSION:
		return nettemp_nt_old_conv;
	default:
		return NULL;
	}
}

static int nettemp_old_conv(void *old_desc,
		   void *old_data, void *new_desc, void *new_data)
{
	memcpy(new_desc, old_desc, sizeof(rsbac_net_temp_id_t));
	memcpy(new_data, old_data, sizeof(rsbac_acl_rights_vector_t));
	return 0;
}

static int nettemp_conv(void *old_desc,
			void *old_data, void *new_desc, void *new_data)
{
	rsbac_acl_rights_vector_t *new = new_data;
	rsbac_acl_rights_vector_t *old = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_net_temp_id_t));
	*new = (*old & RSBAC_ALL_REQUEST_VECTOR)
	    | ((*old & ~(RSBAC_ALL_REQUEST_VECTOR)) <<
	       (RSBAC_ACL_SPECIAL_RIGHT_BASE -
		RSBAC_ACL_OLD_SPECIAL_RIGHT_BASE));
	return 0;
}

static rsbac_list_conv_function_t *nettemp_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_NETTEMP_OLD_LIST_VERSION:
		return nettemp_conv;
	case RSBAC_ACL_NETTEMP_OLD_OLD_LIST_VERSION:
		return nettemp_old_conv;
	default:
		return NULL;
	}
}

static int netobj_conv(void *old_desc,
		   void *old_data, void *new_desc, void *new_data)
{
	memcpy(new_desc, old_desc, sizeof(rsbac_net_obj_id_t));
	memcpy(new_data, old_data, sizeof(rsbac_acl_rights_vector_t));
	return 0;
}

static rsbac_list_conv_function_t *netobj_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_NETOBJ_OLD_LIST_VERSION:
		return netobj_conv;
	default:
		return NULL;
	}
}

static int gm_conv(void *old_desc,
		   void *old_data, void *new_desc, void *new_data)
{
	*((rsbac_uid_t *) new_desc) = *((rsbac_old_uid_t *) old_desc);
	return 0;
}

static rsbac_list_conv_function_t *gm_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_GM_OLD_VERSION:
		return gm_conv;
	default:
		return NULL;
	}
}


static int common_subconv(void *old_desc,
			  void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_acl_entry_desc_t *new_d = new_desc;
	struct rsbac_acl_old_entry_desc_t *old_d = old_desc;

	memcpy(new_data, old_data, sizeof(rsbac_acl_rights_vector_t));
	new_d->subj_type = old_d->subj_type;
	new_d->subj_id = old_d->subj_id;
	return 0;
}

static int common_old_subconv(void *old_desc,
			  void *old_data, void *new_desc, void *new_data)
{
	rsbac_acl_rights_vector_t *new = new_data;
	rsbac_acl_rights_vector_t *old = old_data;
	struct rsbac_acl_entry_desc_t *new_d = new_desc;
	struct rsbac_acl_old_entry_desc_t *old_d = old_desc;

	new_d->subj_type = old_d->subj_type;
	new_d->subj_id = old_d->subj_id;
	*new = (*old & RSBAC_ALL_REQUEST_VECTOR)
	    | ((*old & ~(RSBAC_ALL_REQUEST_VECTOR)) <<
	       (RSBAC_ACL_SPECIAL_RIGHT_BASE -
		RSBAC_ACL_OLD_SPECIAL_RIGHT_BASE));
	return 0;
}

static rsbac_list_conv_function_t *fd_get_subconv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_FD_OLD_LIST_VERSION:
		return common_subconv;
	case RSBAC_ACL_FD_OLD_OLD_LIST_VERSION:
		return common_old_subconv;
	default:
		return NULL;
	}
}

static rsbac_list_conv_function_t *dev_get_subconv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_DEV_OLD_LIST_VERSION:
		return common_subconv;
	case RSBAC_ACL_DEV_OLD_OLD_LIST_VERSION:
		return common_old_subconv;
	default:
		return NULL;
	}
}

static rsbac_list_conv_function_t *scd_get_subconv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_SCD_OLD_LIST_VERSION:
		return common_subconv;
	case RSBAC_ACL_SCD_OLD_OLD_LIST_VERSION:
		return common_old_subconv;
	default:
		return NULL;
	}
}

static rsbac_list_conv_function_t *u_get_subconv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_U_OLD_LIST_VERSION:
		return common_subconv;
	default:
		return NULL;
	}
}

#ifdef CONFIG_RSBAC_ACL_UM_PROT
static rsbac_list_conv_function_t *g_get_subconv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_G_OLD_LIST_VERSION:
		return common_subconv;
	default:
		return NULL;
	}
}
#endif

#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
static rsbac_list_conv_function_t *netdev_get_subconv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_NETDEV_OLD_LIST_VERSION:
		return common_subconv;
	default:
		return NULL;
	}
}
#endif

static rsbac_list_conv_function_t *nettemp_nt_get_subconv(rsbac_version_t
						   old_version)
{
	switch (old_version) {
	case RSBAC_ACL_NETTEMP_NT_OLD_LIST_VERSION:
		return common_subconv;
	default:
		return NULL;
	}
}

static rsbac_list_conv_function_t *nettemp_get_subconv(rsbac_version_t
						old_version)
{
	switch (old_version) {
	case RSBAC_ACL_NETTEMP_OLD_LIST_VERSION:
		return common_subconv;
	default:
		return NULL;
	}
}

static rsbac_list_conv_function_t *netobj_get_subconv(rsbac_version_t
						old_version)
{
	switch (old_version) {
	case RSBAC_ACL_NETOBJ_OLD_LIST_VERSION:
		return common_subconv;
	default:
		return NULL;
	}
}

static int gm_subconv(void *old_desc,
			  void *old_data, void *new_desc, void *new_data)
{
	memcpy(new_desc, old_desc, sizeof(rsbac_acl_group_id_t));
	return 0;
}

static rsbac_list_conv_function_t *gm_get_subconv(rsbac_version_t
						old_version)
{
	switch (old_version) {
	case RSBAC_ACL_GM_OLD_VERSION:
		return gm_subconv;
	default:
		return NULL;
	}
}

static rsbac_list_conv_function_t *def_fd_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_DEF_FD_OLD_LIST_VERSION:
		return common_subconv;
	case RSBAC_ACL_DEF_FD_OLD_OLD_LIST_VERSION:
		return common_old_subconv;
	default:
		return NULL;
	}
}

static rsbac_list_conv_function_t *def_dev_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_DEF_DEV_OLD_LIST_VERSION:
		return common_subconv;
	case RSBAC_ACL_DEF_DEV_OLD_OLD_LIST_VERSION:
		return common_old_subconv;
	default:
		return NULL;
	}
}

static rsbac_list_conv_function_t *def_ipc_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_DEF_IPC_OLD_LIST_VERSION:
		return common_subconv;
	case RSBAC_ACL_DEF_IPC_OLD_OLD_LIST_VERSION:
		return common_old_subconv;
	default:
		return NULL;
	}
}

static rsbac_list_conv_function_t *def_scd_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_DEF_SCD_OLD_LIST_VERSION:
		return common_subconv;
	case RSBAC_ACL_DEF_SCD_OLD_OLD_LIST_VERSION:
		return common_old_subconv;
	default:
		return NULL;
	}
}

static rsbac_list_conv_function_t *def_u_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_DEF_U_OLD_LIST_VERSION:
		return common_subconv;
	case RSBAC_ACL_DEF_U_OLD_OLD_LIST_VERSION:
		return common_old_subconv;
	default:
		return NULL;
	}
}

static rsbac_list_conv_function_t *def_p_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_DEF_P_OLD_LIST_VERSION:
		return common_subconv;
	case RSBAC_ACL_DEF_P_OLD_OLD_LIST_VERSION:
		return common_old_subconv;
	default:
		return NULL;
	}
}

#ifdef CONFIG_RSBAC_ACL_UM_PROT
static rsbac_list_conv_function_t *def_g_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_ACL_DEF_G_OLD_LIST_VERSION:
		return common_subconv;
	case RSBAC_ACL_DEF_G_OLD_OLD_LIST_VERSION:
		return common_old_subconv;
	default:
		return NULL;
	}
}
#endif

#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
static rsbac_list_conv_function_t *def_netdev_get_conv(rsbac_version_t
						old_version)
{
	switch (old_version) {
	case RSBAC_ACL_DEF_NETDEV_OLD_LIST_VERSION:
		return common_subconv;
	case RSBAC_ACL_DEF_NETDEV_OLD_OLD_LIST_VERSION:
		return common_old_subconv;
	default:
		return NULL;
	}
}
#endif

static rsbac_list_conv_function_t *def_nettemp_nt_get_conv(rsbac_version_t
						    old_version)
{
	switch (old_version) {
	case RSBAC_ACL_DEF_NETTEMP_NT_OLD_LIST_VERSION:
		return common_subconv;
	case RSBAC_ACL_DEF_NETTEMP_NT_OLD_OLD_LIST_VERSION:
		return common_old_subconv;
	default:
		return NULL;
	}
}

static rsbac_list_conv_function_t *def_netobj_get_conv(rsbac_version_t
						old_version)
{
	switch (old_version) {
	case RSBAC_ACL_DEF_NETOBJ_OLD_LIST_VERSION:
		return common_subconv;
	case RSBAC_ACL_DEF_NETOBJ_OLD_OLD_LIST_VERSION:
		return common_old_subconv;
	default:
		return NULL;
	}
}


/* acl_register_fd_lists() */
/* register fd ACL lists for device */

static int acl_register_fd_lists(struct rsbac_acl_device_list_item_t
				 *device_p, kdev_t kdev)
{
	int err = 0;
	int tmperr;
	struct rsbac_list_lol_info_t lol_info;
	rsbac_acl_rights_vector_t def_mask = RSBAC_ACL_DEFAULT_FD_MASK;

	if (!device_p)
		return -RSBAC_EINVALIDPOINTER;

	/* register all the ACL lists of lists */
	lol_info.version = RSBAC_ACL_FD_LIST_VERSION;
	lol_info.key = RSBAC_ACL_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_inode_nr_t);
	lol_info.data_size = sizeof(rsbac_acl_rights_vector_t);	/* mask */
	lol_info.subdesc_size = sizeof(struct rsbac_acl_entry_desc_t);	/* subj_type + subj_id */
	lol_info.subdata_size = sizeof(rsbac_acl_rights_vector_t);	/* rights */
	lol_info.max_age = 0;
	tmperr = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
					 &device_p->handle,
					 &lol_info,
					 RSBAC_LIST_PERSIST |
					 RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
					 NULL,
					 entry_compare,
					 fd_get_conv,
					 fd_get_subconv, &def_mask,
					 NULL,
					 RSBAC_ACL_FD_FILENAME, kdev,
					 nr_fd_hashes,
					 (nr_fd_hashes > 0) ? rsbac_list_hash_fd : NULL,
					 RSBAC_ACL_FD_OLD_FILENAME);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "acl_register_fd_lists(): registering list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_ACL_FD_FILENAME,
				     RSBAC_MAJOR(kdev),
				     RSBAC_MINOR(kdev),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
	return err;
}

/* acl_detach_fd_lists() */
/* detach from fd ACL lists for device */

static int acl_detach_fd_lists(struct rsbac_acl_device_list_item_t
			       *device_p)
{
	int err = 0;
	int tmperr;

	if (!device_p)
		return -RSBAC_EINVALIDPOINTER;

	/* detach all the ACL lists of lists */
	tmperr = rsbac_list_lol_detach(&device_p->handle,
				       RSBAC_ACL_LIST_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "acl_detach_fd_lists(): detaching from list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_ACL_FD_FILENAME,
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
	return err;
}

/************************************************************************** */
/* The lookup functions return NULL, if the item is not found, and a        */
/* pointer to the item otherwise.                                           */

/* first the device item lookup */
static struct rsbac_acl_device_list_item_t *acl_lookup_device(kdev_t kdev)
{
	struct rsbac_acl_device_list_item_t *curr = rcu_dereference(device_list_head_p)->curr;

	/* if there is no current item or it is not the right one, search... */
	if (!curr || (RSBAC_MAJOR(curr->id) != RSBAC_MAJOR(kdev))
	    || (RSBAC_MINOR(curr->id) != RSBAC_MINOR(kdev))
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

/* Create a device item without adding to list. No locking needed. */
static struct rsbac_acl_device_list_item_t
*create_device_item(kdev_t kdev)
{
	struct rsbac_acl_device_list_item_t *new_item_p;

	/* allocate memory for new device, return NULL, if failed */
	if (!(new_item_p = rsbac_smalloc_clear_unlocked(acl_device_item_slab)))
		return NULL;
	new_item_p->id = kdev;
	new_item_p->mount_count = 1;
	return new_item_p;
}

/* Add an existing device item to list. Locking needed. */
static struct rsbac_acl_device_list_item_t
*add_device_item(struct rsbac_acl_device_list_item_t *device_p)
{
	struct rsbac_acl_device_list_head_t * new_p;
	struct rsbac_acl_device_list_head_t * old_p;

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

static void clear_device_item(struct rsbac_acl_device_list_item_t
			      *device_p)
{
	if (!device_p)
		return;
	acl_detach_fd_lists(device_p);
	rsbac_sfree(acl_device_item_slab, device_p);;
}

static void remove_device_item(kdev_t kdev)
{
	struct rsbac_acl_device_list_item_t *item_p;
	struct rsbac_acl_device_list_head_t * new_p;
	struct rsbac_acl_device_list_head_t * old_p;
               
	old_p = device_list_head_p;
	new_p = rsbac_kmalloc(sizeof(*new_p));
	*new_p = *old_p;

	/* first we must locate the item. */
	if ((item_p = acl_lookup_device(kdev))) {	/* ok, item was found */
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
		synchronize_rcu();
		rsbac_kfree(old_p);

		/* now we can remove the item from memory. This means cleaning up */
		/* everything below. */
		clear_device_item(item_p);
	}			/* end of if: item was found */
	else
		spin_unlock(&device_list_lock);
}

/************************************************* */
/*               proc functions                    */
/************************************************* */

#if defined(CONFIG_RSBAC_PROC)
static int
acl_devices_proc_show(struct seq_file *m, void *v)
{
	struct rsbac_acl_device_list_item_t *device_p;
	int srcu_idx;

	if (!rsbac_is_initialized())
		return -ENOSYS;

	seq_printf(m, "%u RSBAC ACL Devices\n-------------------\n",
		    rcu_dereference(device_list_head_p)->count);

	/* wait for read access to device_list_head */
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

static ssize_t acl_devices_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, acl_devices_proc_show, NULL);
}

static const struct file_operations acl_devices_proc_fops = {
       .owner          = THIS_MODULE,
       .open           = acl_devices_proc_open,
       .read           = seq_read,
       .llseek         = seq_lseek,
       .release        = single_release,
};

static struct proc_dir_entry *acl_devices;

static int
stats_acl_proc_show(struct seq_file *m, void *v)
{
	u_int item_count = 0;
	u_int member_count = 0;
	struct rsbac_acl_device_list_item_t *device_p;
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "stats_acl_proc_info(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	rsbac_pr_debug(aef_acl, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	seq_printf(m, "ACL Status\n-----------\n");

	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = rcu_dereference(device_list_head_p)->head;
	while (device_p) {
		item_count = rsbac_list_lol_count(device_p->handle);
		member_count = rsbac_list_lol_all_subcount(device_p->handle);
		seq_printf(m,
			    "device %02u:%02u has %i file ACLs, sum of %i members\n",
			    RSBAC_MAJOR(device_p->id),
			    RSBAC_MINOR(device_p->id), item_count,
			    member_count);
		device_p = device_p->next;
	}
	srcu_read_unlock(&device_list_srcu, srcu_idx);

	/* dev list */
	seq_printf(m,
		    "%li device ACL items, sum of %li members\n",
		    rsbac_list_lol_count(dev_handle),
		    rsbac_list_lol_all_subcount(dev_handle));
	seq_printf(m,
		    "%li device major ACL items, sum of %li members\n",
		    rsbac_list_lol_count(dev_major_handle),
		    rsbac_list_lol_all_subcount(dev_major_handle));

	/* SCD list */
	seq_printf(m,
		    "%li scd ACL items, sum of %li members\n",
		    rsbac_list_lol_count(scd_handle),
		    rsbac_list_lol_all_subcount(scd_handle));

	/* user list */
	seq_printf(m,
		    "%li user ACL items, sum of %li members\n",
		    rsbac_list_lol_count(u_handle),
		    rsbac_list_lol_all_subcount(u_handle));

#ifdef CONFIG_RSBAC_ACL_UM_PROT
	/* Linux group list */
	seq_printf(m,
		    "%li Linux group ACL items, sum of %li members\n",
		    rsbac_list_lol_count(g_handle),
		    rsbac_list_lol_all_subcount(g_handle));
#endif

#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
	/* netdev list */
	seq_printf(m,
		    "%li network device ACL items, sum of %li members\n",
		    rsbac_list_lol_count(netdev_handle),
		    rsbac_list_lol_all_subcount(netdev_handle));
#endif

#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
	/* nettemp_nt list */
	seq_printf(m,
		    "%li network template NT ACL items, sum of %li members\n",
		    rsbac_list_lol_count(nettemp_nt_handle),
		    rsbac_list_lol_all_subcount(nettemp_nt_handle));
	/* nettemp list */
	seq_printf(m,
		    "%li network template ACL items, sum of %li members\n",
		    rsbac_list_lol_count(nettemp_handle),
		    rsbac_list_lol_all_subcount(nettemp_handle));
	/* netobj list */
	seq_printf(m,
		    "%li network object ACL items, sum of %li members\n",
		    rsbac_list_lol_count(netobj_handle),
		    rsbac_list_lol_all_subcount(netobj_handle));
#endif

	seq_printf(m, "%li groups, last new is %u\n",
		       rsbac_list_count(group_handle), group_last_new);

	/* protect gm list */
	seq_printf(m,
		    "%li group member items, sum of %li group memberships\n",
		    rsbac_list_lol_count(gm_handle),
		    rsbac_list_lol_all_subcount(gm_handle));
	return 0;
}

static ssize_t stats_acl_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, stats_acl_proc_show, NULL);
}

static const struct file_operations stats_acl_proc_fops = {
       .owner          = THIS_MODULE,
       .open           = stats_acl_proc_open,
       .read           = seq_read,
       .llseek         = seq_lseek,
       .release        = single_release,
};

static struct proc_dir_entry *stats_acl;

static int
acl_acllist_proc_show(struct seq_file *m, void *v)
{
	u_int i, j, k;
	char tmp1[80], tmp2[80];
	u_int count = 0;
	int tmp_count;
	int tmp_sub_count;
	u_int member_count = 0;
	struct rsbac_acl_device_list_item_t *device_p;
	rsbac_inode_nr_t *fd_desc_p;
	struct rsbac_dev_desc_t *dev_desc_p;
	__u8 *scd_desc_p;
	rsbac_uid_t *u_desc_p;
#ifdef CONFIG_RSBAC_ACL_UM_PROT
	rsbac_gid_t *g_desc_p;
#endif
#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
	rsbac_netdev_id_t *netdev_desc_p;
#endif
#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
	rsbac_net_temp_id_t *nettemp_desc_p;
	rsbac_net_obj_id_t *netobj_desc_p;
#endif
	struct rsbac_acl_entry_desc_t *sub_desc_p;
	rsbac_acl_rights_vector_t rights;
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "acl_acllist_proc_info(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	rsbac_pr_debug(aef_acl, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	seq_printf(m, "ACL Lists\n----------\n");

	seq_printf(m,
		       "Default FD ACL:          %li members:",
		       rsbac_list_count(default_fd_handle));
	tmp_count =
	    rsbac_list_get_all_desc(default_fd_handle,
				    (void **) &sub_desc_p);
	if (tmp_count > 0) {
		for (i = 0; i < tmp_count; i++) {
			if (RSBAC_UID_SET(sub_desc_p[i].subj_id))
				seq_printf(m, " %s %u/%u,",
				       get_acl_subject_type_name(tmp1,
								 sub_desc_p
								 [i].
								 subj_type),
				       RSBAC_UID_SET(sub_desc_p[i].subj_id),
				       RSBAC_UID_NUM(sub_desc_p[i].subj_id));
			else
				seq_printf(m, " %s %u,",
				       get_acl_subject_type_name(tmp1,
								 sub_desc_p
								 [i].
								 subj_type),
				       RSBAC_UID_NUM(sub_desc_p[i].subj_id));
		}
		rsbac_kfree(sub_desc_p);
	}

	/* default_dev list */
	seq_printf(m,
		    "\nDefault Device ACL:      %li members:",
		    rsbac_list_count(default_dev_handle));
	tmp_count =
	    rsbac_list_get_all_desc(default_dev_handle,
				    (void **) &sub_desc_p);
	if (tmp_count > 0) {
		for (i = 0; i < tmp_count; i++) {
			if (RSBAC_UID_SET(sub_desc_p[i].subj_id))
				seq_printf(m, " %s %u/%u,",
				       get_acl_subject_type_name(tmp1,
								 sub_desc_p
								 [i].
								 subj_type),
				       RSBAC_UID_SET(sub_desc_p[i].subj_id),
				       RSBAC_UID_NUM(sub_desc_p[i].subj_id));
			else
				seq_printf(m, " %s %u,",
				       get_acl_subject_type_name(tmp1,
								 sub_desc_p
								 [i].
								 subj_type),
				       RSBAC_UID_NUM(sub_desc_p[i].subj_id));
		}
		rsbac_kfree(sub_desc_p);
	}

	/* default_ipc_list */
	seq_printf(m,
		    "\nDefault IPC ACL:         %li members:",
		    rsbac_list_count(default_ipc_handle));
	tmp_count =
	    rsbac_list_get_all_desc(default_ipc_handle,
				    (void **) &sub_desc_p);
	if (tmp_count > 0) {
		for (i = 0; i < tmp_count; i++) {
			if (RSBAC_UID_SET(sub_desc_p[i].subj_id))
				seq_printf(m, " %s %u/%u,",
				       get_acl_subject_type_name(tmp1,
								 sub_desc_p
								 [i].
								 subj_type),
				       RSBAC_UID_SET(sub_desc_p[i].subj_id),
				       RSBAC_UID_NUM(sub_desc_p[i].subj_id));
			else
				seq_printf(m, " %s %u,",
				       get_acl_subject_type_name(tmp1,
								 sub_desc_p
								 [i].
								 subj_type),
				       RSBAC_UID_NUM(sub_desc_p[i].subj_id));
		}
		rsbac_kfree(sub_desc_p);
	}

	/* default_scd_list */
	seq_printf(m,
		    "\nDefault SCD ACL:         %li members:",
		    rsbac_list_count(default_scd_handle));
	tmp_count =
	    rsbac_list_get_all_desc(default_scd_handle,
				    (void **) &sub_desc_p);
	if (tmp_count > 0) {
		for (i = 0; i < tmp_count; i++) {
			if (RSBAC_UID_SET(sub_desc_p[i].subj_id))
				seq_printf(m, " %s %u/%u,",
				       get_acl_subject_type_name(tmp1,
								 sub_desc_p
								 [i].
								 subj_type),
				       RSBAC_UID_SET(sub_desc_p[i].subj_id),
				       RSBAC_UID_NUM(sub_desc_p[i].subj_id));
			else
				seq_printf(m, " %s %u,",
				       get_acl_subject_type_name(tmp1,
								 sub_desc_p
								 [i].
								 subj_type),
				       RSBAC_UID_NUM(sub_desc_p[i].subj_id));
		}
		rsbac_kfree(sub_desc_p);
	}

	/* default_u_list */
	seq_printf(m,
		    "\nDefault User ACL:        %li members:",
		    rsbac_list_count(default_u_handle));
	tmp_count =
	    rsbac_list_get_all_desc(default_u_handle,
				    (void **) &sub_desc_p);
	if (tmp_count > 0) {
		for (i = 0; i < tmp_count; i++) {
			if (RSBAC_UID_SET(sub_desc_p[i].subj_id))
				seq_printf(m, " %s %u/%u,",
				       get_acl_subject_type_name(tmp1,
								 sub_desc_p
								 [i].
								 subj_type),
				       RSBAC_UID_SET(sub_desc_p[i].subj_id),
				       RSBAC_UID_NUM(sub_desc_p[i].subj_id));
			else
				seq_printf(m, " %s %u,",
				       get_acl_subject_type_name(tmp1,
								 sub_desc_p
								 [i].
								 subj_type),
				       RSBAC_UID_NUM(sub_desc_p[i].subj_id));
		}
		rsbac_kfree(sub_desc_p);
	}

	/* default_p list */
	seq_printf(m,
		    "\nDefault Process ACL:     %li members:",
		    rsbac_list_count(default_p_handle));
	tmp_count =
	    rsbac_list_get_all_desc(default_p_handle,
				    (void **) &sub_desc_p);
	if (tmp_count > 0) {
		for (i = 0; i < tmp_count; i++) {
			if (RSBAC_UID_SET(sub_desc_p[i].subj_id))
				seq_printf(m, " %s %u/%u,",
				       get_acl_subject_type_name(tmp1,
								 sub_desc_p
								 [i].
								 subj_type),
				       RSBAC_UID_SET(sub_desc_p[i].subj_id),
				       RSBAC_UID_NUM(sub_desc_p[i].subj_id));
			else
				seq_printf(m, " %s %u,",
				       get_acl_subject_type_name(tmp1,
								 sub_desc_p
								 [i].
								 subj_type),
				       RSBAC_UID_NUM(sub_desc_p[i].subj_id));
		}
		rsbac_kfree(sub_desc_p);
	}
#ifdef CONFIG_RSBAC_ACL_UM_PROT
	/* default_g_list */
	seq_printf(m,
		    "\nDefault Linux Group ACL: %li members:",
		    rsbac_list_count(default_g_handle));
	tmp_count =
	    rsbac_list_get_all_desc(default_g_handle,
				    (void **) &sub_desc_p);
	if (tmp_count > 0) {
		for (i = 0; i < tmp_count; i++) {
			if (RSBAC_UID_SET(sub_desc_p[i].subj_id))
				seq_printf(m, " %s %u/%u,",
				       get_acl_subject_type_name(tmp1,
								 sub_desc_p
								 [i].
								 subj_type),
				       RSBAC_UID_SET(sub_desc_p[i].subj_id),
				       RSBAC_UID_NUM(sub_desc_p[i].subj_id));
			else
				seq_printf(m, " %s %u,",
				       get_acl_subject_type_name(tmp1,
								 sub_desc_p
								 [i].
								 subj_type),
				       RSBAC_UID_NUM(sub_desc_p[i].subj_id));
		}
		rsbac_kfree(sub_desc_p);
	}
#endif

#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
	/* default_netdev list */
	seq_printf(m,
		    "\nDefault Network Device ACL:      %li members:",
		    rsbac_list_count(default_netdev_handle));
	tmp_count =
	    rsbac_list_get_all_desc(default_netdev_handle,
				    (void **) &sub_desc_p);
	if (tmp_count > 0) {
		for (i = 0; i < tmp_count; i++) {
			if (RSBAC_UID_SET(sub_desc_p[i].subj_id))
				seq_printf(m, " %s %u/%u,",
				       get_acl_subject_type_name(tmp1,
								 sub_desc_p
								 [i].
								 subj_type),
				       RSBAC_UID_SET(sub_desc_p[i].subj_id),
				       RSBAC_UID_NUM(sub_desc_p[i].subj_id));
			else
				seq_printf(m, " %s %u,",
				       get_acl_subject_type_name(tmp1,
								 sub_desc_p
								 [i].
								 subj_type),
				       RSBAC_UID_NUM(sub_desc_p[i].subj_id));
		}
		rsbac_kfree(sub_desc_p);
	}
#endif

#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
	/* default_netdev list */
	seq_printf(m,
		    "\nDefault Network Template NT ACL: %li members:",
		    rsbac_list_count(default_nettemp_nt_handle));
	tmp_count =
	    rsbac_list_get_all_desc(default_nettemp_nt_handle,
				    (void **) &sub_desc_p);
	if (tmp_count > 0) {
		for (i = 0; i < tmp_count; i++) {
			if (RSBAC_UID_SET(sub_desc_p[i].subj_id))
				seq_printf(m, " %s %u/%u,",
				       get_acl_subject_type_name(tmp1,
								 sub_desc_p
								 [i].
								 subj_type),
				       RSBAC_UID_SET(sub_desc_p[i].subj_id),
				       RSBAC_UID_NUM(sub_desc_p[i].subj_id));
			else
				seq_printf(m, " %s %u,",
				       get_acl_subject_type_name(tmp1,
								 sub_desc_p
								 [i].
								 subj_type),
				       RSBAC_UID_NUM(sub_desc_p[i].subj_id));
		}
		rsbac_kfree(sub_desc_p);
	}
	/* default_netobj list */
	seq_printf(m,
		    "\nDefault Network Object ACL:      %li members:",
		    rsbac_list_count(default_netobj_handle));
	tmp_count =
	    rsbac_list_get_all_desc(default_netobj_handle,
				    (void **) &sub_desc_p);
	if (tmp_count > 0) {
		for (i = 0; i < tmp_count; i++) {
			if (RSBAC_UID_SET(sub_desc_p[i].subj_id))
				seq_printf(m, " %s %u/%u,",
				       get_acl_subject_type_name(tmp1,
								 sub_desc_p
								 [i].
								 subj_type),
				       RSBAC_UID_SET(sub_desc_p[i].subj_id),
				       RSBAC_UID_NUM(sub_desc_p[i].subj_id));
			else
				seq_printf(m, " %s %u,",
				       get_acl_subject_type_name(tmp1,
								 sub_desc_p
								 [i].
								 subj_type),
				       RSBAC_UID_NUM(sub_desc_p[i].subj_id));
		}
		rsbac_kfree(sub_desc_p);
	}
#endif

	seq_printf(m, "\n\nFile/Dir/Fifo/Symlink ACLs:\n");

	/* protect device list */
	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = rcu_dereference(device_list_head_p)->head;
	while (device_p) {
		/* reset counters */
		count = 0;
		member_count = 0;
		    seq_printf(m,
			    "\nDevice %02u:%02u\n inode  count   mask+members",
			    RSBAC_MAJOR(device_p->id),
			    RSBAC_MINOR(device_p->id));
		tmp_count = rsbac_list_lol_get_all_desc(device_p->handle,
							(void **)
							&fd_desc_p);
		if (tmp_count > 0) {
			for (j = 0; j < tmp_count; j++) {
				    seq_printf(m,
					    "\n%6u\t  %li\t",
					    fd_desc_p[j],
					    rsbac_list_lol_subcount
					    (device_p->handle,
					     &fd_desc_p[j]));
				}
				if (!rsbac_list_lol_get_data
				    (device_p->handle,
				     &fd_desc_p[j], &rights)) {
					    seq_printf(m,
						    "%s\n\t\t",
						    u64tostracl
						    (tmp1,
						     rights));
				}
					tmp_sub_count =
				    rsbac_list_lol_get_all_subdesc
				    (device_p->handle,
				     &fd_desc_p[j],
				     (void **) &sub_desc_p);
				if (tmp_sub_count > 0) {
					for (k = 0;
					     k < tmp_sub_count;
					     k++) {
			if (RSBAC_UID_SET(sub_desc_p[k].subj_id))
				seq_printf(m, " %s %u/%u,",
				       get_acl_subject_type_name(tmp1,
								 sub_desc_p
								 [k].
								 subj_type),
				       RSBAC_UID_SET(sub_desc_p[k].subj_id),
				       RSBAC_UID_NUM(sub_desc_p[k].subj_id));
			else
						    seq_printf(m,
							    "%s %u, ",
							    get_acl_subject_type_name
							    (tmp1,
							     sub_desc_p
							     [k].
							     subj_type),
							    RSBAC_UID_NUM(sub_desc_p
							    [k].
							    subj_id));
					}
					rsbac_kfree(sub_desc_p);
					member_count +=
					    tmp_sub_count;
				}
			count += tmp_count;
			rsbac_kfree(fd_desc_p);
		}
		seq_printf(m,
			    "\n%u file ACLs, sum of %u members\n", count,
			    member_count);
		device_p = device_p->next;
	}
	/* unprotect device list */
	srcu_read_unlock(&device_list_srcu, srcu_idx);

	/* dev list */
	seq_printf(m,
		    "\nDevice ACLs:\ntype+id  count  mask+members");

	member_count = 0;
	tmp_count =
	    rsbac_list_lol_get_all_desc(dev_handle, (void **) &dev_desc_p);
	if (tmp_count > 0) {
		for (i = 0; i < tmp_count; i++) {
			if (!rsbac_list_lol_get_data
			    (dev_handle, &dev_desc_p[i], &rights)) {
				    seq_printf(m,
					    "\n%c%02u:%02u\t  %3li\t%s\n\t\t",
					    'B' + dev_desc_p[i].type,
					    dev_desc_p[i].major,
					    dev_desc_p[i].minor,
					    rsbac_list_lol_subcount
					    (dev_handle, &dev_desc_p[i]),
					    u64tostracl(tmp1, rights));
			}
			tmp_sub_count =
			    rsbac_list_lol_get_all_subdesc(dev_handle,
							   &dev_desc_p[i],
							   (void **)
							   &sub_desc_p);
			if (tmp_sub_count > 0) {
				for (j = 0; j < tmp_sub_count; j++) {
					if (RSBAC_UID_SET(sub_desc_p[j].subj_id))
						seq_printf(m, " %s %u/%u,",
						       get_acl_subject_type_name(tmp1,
									 sub_desc_p
									 [j].
									 subj_type),
						       RSBAC_UID_SET(sub_desc_p[j].subj_id),
						       RSBAC_UID_NUM(sub_desc_p[j].subj_id));
					else
					    seq_printf(m,
						    "%s %u, ",
						    get_acl_subject_type_name
						    (tmp1,
						     sub_desc_p[j].
						     subj_type),
						    RSBAC_UID_NUM(sub_desc_p[j].subj_id));
				}
				rsbac_kfree(sub_desc_p);
				member_count += tmp_sub_count;
			}
		}
		rsbac_kfree(dev_desc_p);
	}
	seq_printf(m,
		    "\n\n%i device ACL items, sum of %u members\n",
		    tmp_count, member_count);

	/* dev major list */
	seq_printf(m,
		    "\nDevice major ACLs:\ntype+id  count  mask+members");

	member_count = 0;
	tmp_count =
	    rsbac_list_lol_get_all_desc(dev_major_handle,
					(void **) &dev_desc_p);
	if (tmp_count > 0) {
		for (i = 0; i < tmp_count; i++) {
			if (!rsbac_list_lol_get_data
			    (dev_major_handle, &dev_desc_p[i], &rights)) {
				    seq_printf(m,
					    "\n%c%02u\t  %3li\t%s\n\t\t",
					    'B' + dev_desc_p[i].type,
					    dev_desc_p[i].major,
					    rsbac_list_lol_subcount
					    (dev_major_handle,
					     &dev_desc_p[i]),
					    u64tostracl(tmp1, rights));
			}
			tmp_sub_count =
			    rsbac_list_lol_get_all_subdesc
			    (dev_major_handle, &dev_desc_p[i],
			     (void **) &sub_desc_p);
			if (tmp_sub_count > 0) {
				for (j = 0; j < tmp_sub_count; j++) {
					if (RSBAC_UID_SET(sub_desc_p[j].subj_id))
						seq_printf(m, " %s %u/%u,",
						       get_acl_subject_type_name(tmp1,
									 sub_desc_p
									 [j].
									 subj_type),
						       RSBAC_UID_SET(sub_desc_p[j].subj_id),
						       RSBAC_UID_NUM(sub_desc_p[j].subj_id));
					else
					    seq_printf(m,
						    "%s %u, ",
						    get_acl_subject_type_name
						    (tmp1,
						     sub_desc_p[j].
						     subj_type),
						    RSBAC_UID_NUM(sub_desc_p[j].subj_id));
				}
				rsbac_kfree(sub_desc_p);
				member_count += tmp_sub_count;
			}
		}
		rsbac_kfree(dev_desc_p);
	}
	seq_printf(m,
		    "\n\n%i device major ACL items, sum of %u members\n",
		    tmp_count, member_count);
	/* scd list */
	member_count = 0;
	seq_printf(m,
		    "\nSCD ACLs:\nname             count  mask+members");
	tmp_count =
	    rsbac_list_lol_get_all_desc(scd_handle, (void **) &scd_desc_p);
	if (tmp_count > 0) {
		for (i = 0; i < tmp_count; i++) {
			if (!rsbac_list_lol_get_data
			    (scd_handle, &scd_desc_p[i], &rights)) {
				    seq_printf(m,
					    "\n%-16s  %3li\t%s\n\t\t\t",
					    get_acl_scd_type_name(tmp1,
								  scd_desc_p
								  [i]),
					    rsbac_list_lol_subcount
					    (scd_handle, &scd_desc_p[i]),
					    u64tostracl(tmp2, rights));
			}
			tmp_sub_count =
			    rsbac_list_lol_get_all_subdesc(scd_handle,
							   &scd_desc_p[i],
							   (void **)
							   &sub_desc_p);
			if (tmp_sub_count > 0) {
				for (j = 0; j < tmp_sub_count; j++) {
					if (RSBAC_UID_SET(sub_desc_p[j].subj_id))
						seq_printf(m, " %s %u/%u,",
						       get_acl_subject_type_name(tmp1,
									 sub_desc_p
									 [j].
									 subj_type),
						       RSBAC_UID_SET(sub_desc_p[j].subj_id),
						       RSBAC_UID_NUM(sub_desc_p[j].subj_id));
					else
					    seq_printf(m,
						    "%s %u, ",
						    get_acl_subject_type_name
						    (tmp1,
						     sub_desc_p[j].
						     subj_type),
						    RSBAC_UID_NUM(sub_desc_p[j].subj_id));
				}
				rsbac_kfree(sub_desc_p);
				member_count += tmp_sub_count;
			}
		}
		rsbac_kfree(scd_desc_p);
	}
	seq_printf(m,
		    "\n\n%u SCD ACL items, sum of %u members\n", tmp_count,
		    member_count);

	/* user list */
	seq_printf(m,
		    "\nUser ACLs:\nuid      count  mask+members");

	member_count = 0;
	tmp_count =
	    rsbac_list_lol_get_all_desc(u_handle, (void **) &u_desc_p);
	if (tmp_count > 0) {
		for (i = 0; i < tmp_count; i++) {
			if (!rsbac_list_lol_get_data
			    (u_handle, &u_desc_p[i], &rights)) {
			        if (RSBAC_UID_SET(u_desc_p[i]))
					    seq_printf(m,
					    "\n%u/%u\t  %3li\t%s\n\t\t",
					    RSBAC_UID_SET(u_desc_p[i]),
					    RSBAC_UID_NUM(u_desc_p[i]),
					    rsbac_list_lol_subcount
					    (u_handle, &u_desc_p[i]),
					    u64tostracl(tmp1, rights));
			        else
					    seq_printf(m,
					    "\n%u\t  %3li\t%s\n\t\t",
					    RSBAC_UID_NUM(u_desc_p[i]),
					    rsbac_list_lol_subcount
					    (u_handle, &u_desc_p[i]),
					    u64tostracl(tmp1, rights));
			}
			tmp_sub_count =
			    rsbac_list_lol_get_all_subdesc(u_handle,
							   &u_desc_p[i],
							   (void **)
							   &sub_desc_p);
			if (tmp_sub_count > 0) {
				for (j = 0; j < tmp_sub_count; j++) {
					if (RSBAC_UID_SET(sub_desc_p[j].subj_id))
						seq_printf(m, " %s %u/%u,",
						       get_acl_subject_type_name(tmp1,
									 sub_desc_p
									 [j].
									 subj_type),
						       RSBAC_UID_SET(sub_desc_p[j].subj_id),
						       RSBAC_UID_NUM(sub_desc_p[j].subj_id));
					else
					    seq_printf(m,
						    "%s %u, ",
						    get_acl_subject_type_name
						    (tmp1,
						     sub_desc_p[j].
						     subj_type),
						    RSBAC_UID_NUM(sub_desc_p[j].subj_id));
				}
				rsbac_kfree(sub_desc_p);
				member_count += tmp_sub_count;
			}
		}
		rsbac_kfree(u_desc_p);
	}
	seq_printf(m,
		    "\n\n%i user ACL items, sum of %u members\n",
		    tmp_count, member_count);

#ifdef CONFIG_RSBAC_ACL_UM_PROT
	/* Linux group list */
	seq_printf(m,
		    "\nLinux group ACLs:\ngid      count  mask+members");

	member_count = 0;
	tmp_count =
	    rsbac_list_lol_get_all_desc(g_handle, (void **) &g_desc_p);
	if (tmp_count > 0) {
		for (i = 0; i < tmp_count; i++) {
			if (!rsbac_list_lol_get_data
			    (g_handle, &g_desc_p[i], &rights)) {
			        if (RSBAC_GID_SET(g_desc_p[i]))
					    seq_printf(m,
					    "\n%u/%u\t  %3li\t%s\n\t\t",
					    RSBAC_GID_SET(g_desc_p[i]),
					    RSBAC_GID_NUM(g_desc_p[i]),
					    rsbac_list_lol_subcount
					    (g_handle, &g_desc_p[i]),
					    u64tostracl(tmp1, rights));
			        else
					    seq_printf(m,
					    "\n%u\t  %3li\t%s\n\t\t",
					    RSBAC_GID_NUM(g_desc_p[i]),
					    rsbac_list_lol_subcount
					    (g_handle, &g_desc_p[i]),
					    u64tostracl(tmp1, rights));
			}
			tmp_sub_count =
			    rsbac_list_lol_get_all_subdesc(g_handle,
							   &g_desc_p[i],
							   (void **)
							   &sub_desc_p);
			if (tmp_sub_count > 0) {
				for (j = 0; j < tmp_sub_count; j++) {
					if (RSBAC_GID_SET(sub_desc_p[j].subj_id))
						seq_printf(m, " %s %u/%u,",
						       get_acl_subject_type_name(tmp1,
									 sub_desc_p
									 [j].
									 subj_type),
						       RSBAC_GID_SET(sub_desc_p[j].subj_id),
						       RSBAC_GID_NUM(sub_desc_p[j].subj_id));
					else
					    seq_printf(m,
						    "%s %u, ",
						    get_acl_subject_type_name
						    (tmp1,
						     sub_desc_p[j].
						     subj_type),
						    RSBAC_UID_NUM(sub_desc_p[j].subj_id));
				}
				rsbac_kfree(sub_desc_p);
				member_count += tmp_sub_count;
			}
		}
		rsbac_kfree(g_desc_p);
	}
	seq_printf(m,
		    "\n\n%i Linux group ACL items, sum of %u members\n",
		    tmp_count, member_count);
#endif

#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
	/* netdev list */
	seq_printf(m,
		    "\nNetwork Device ACLs:\nname\t\t count  mask+members");
	member_count = 0;
	tmp_count =
	    rsbac_list_lol_get_all_desc(netdev_handle,
					(void **) &netdev_desc_p);
	if (tmp_count > 0) {
		for (i = 0; i < tmp_count; i++) {
			if (!rsbac_list_lol_get_data
			    (netdev_handle, &netdev_desc_p[i], &rights)) {
				    seq_printf(m,
					    "\n%-16s  %3li\t  %s\n\t\t",
					    netdev_desc_p[i],
					    rsbac_list_lol_subcount
					    (netdev_handle,
					     &netdev_desc_p[i]),
					    u64tostracl(tmp1, rights));
			}
			tmp_sub_count =
			    rsbac_list_lol_get_all_subdesc(netdev_handle,
							   &netdev_desc_p
							   [i],
							   (void **)
							   &sub_desc_p);
			if (tmp_sub_count > 0) {
				for (j = 0; j < tmp_sub_count; j++) {
					if (RSBAC_UID_SET(sub_desc_p[j].subj_id))
						seq_printf(m, " %s %u/%u,",
						       get_acl_subject_type_name(tmp1,
									 sub_desc_p
									 [j].
									 subj_type),
						       RSBAC_UID_SET(sub_desc_p[j].subj_id),
						       RSBAC_UID_NUM(sub_desc_p[j].subj_id));
					else
					    seq_printf(m,
						    "%s %u, ",
						    get_acl_subject_type_name
						    (tmp1,
						     sub_desc_p[j].
						     subj_type),
						    RSBAC_UID_NUM(sub_desc_p[j].subj_id));
				}
				rsbac_kfree(sub_desc_p);
				member_count += tmp_sub_count;
			}
		}
		rsbac_kfree(netdev_desc_p);
	}
	seq_printf(m,
		    "\n\n%i network device ACL items, sum of %u members\n",
		    tmp_count, member_count);
#endif

#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
	/* nettemp_nt list */
	seq_printf(m,
		    "\nNetwork Template NT (template protection) ACLs:\nTemplate   count  mask+members");

	member_count = 0;
	tmp_count =
	    rsbac_list_lol_get_all_desc(nettemp_nt_handle,
					(void **) &nettemp_desc_p);
	if (tmp_count > 0) {
		for (i = 0; i < tmp_count; i++) {
			if (!rsbac_list_lol_get_data
			    (nettemp_nt_handle, &nettemp_desc_p[i],
			     &rights)) {
				    seq_printf(m,
					    "\n%10u %3li\t%s\n\t\t",
					    nettemp_desc_p[i],
					    rsbac_list_lol_subcount
					    (nettemp_nt_handle,
					     &nettemp_desc_p[i]),
					    u64tostracl(tmp1, rights));
			}
			tmp_sub_count =
			    rsbac_list_lol_get_all_subdesc
			    (nettemp_nt_handle, &nettemp_desc_p[i],
			     (void **) &sub_desc_p);
			if (tmp_sub_count > 0) {
				for (j = 0; j < tmp_sub_count; j++) {
					if (RSBAC_UID_SET(sub_desc_p[j].subj_id))
						seq_printf(m, " %s %u/%u,",
						       get_acl_subject_type_name(tmp1,
									 sub_desc_p
									 [j].
									 subj_type),
						       RSBAC_UID_SET(sub_desc_p[j].subj_id),
						       RSBAC_UID_NUM(sub_desc_p[j].subj_id));
					else
					    seq_printf(m,
						    "%s %u, ",
						    get_acl_subject_type_name
						    (tmp1,
						     sub_desc_p[j].
						     subj_type),
						    RSBAC_UID_NUM(sub_desc_p[j].subj_id));
				}
				rsbac_kfree(sub_desc_p);
				member_count += tmp_sub_count;
			}
		}
		rsbac_kfree(nettemp_desc_p);
	}
	seq_printf(m,
		    "\n\n%i network template NT ACL items, sum of %u members\n",
		    tmp_count, member_count);

	/* nettemp list */
	seq_printf(m,
		    "\nNetwork Template (netobj protection) ACLs:\nTemplate   count  mask+members");
	member_count = 0;
	tmp_count =
	    rsbac_list_lol_get_all_desc(nettemp_handle,
					(void **) &nettemp_desc_p);
	if (tmp_count > 0) {
		for (i = 0; i < tmp_count; i++) {
			if (!rsbac_list_lol_get_data
			    (nettemp_handle, &nettemp_desc_p[i],
			     &rights)) {
				    seq_printf(m,
					    "\n%10u %3li\t%s\n\t\t",
					    nettemp_desc_p[i],
					    rsbac_list_lol_subcount
					    (nettemp_handle,
					     &nettemp_desc_p[i]),
					    u64tostracl(tmp1, rights));
			}
			tmp_sub_count =
			    rsbac_list_lol_get_all_subdesc(nettemp_handle,
							   &nettemp_desc_p
							   [i],
							   (void **)
							   &sub_desc_p);
			if (tmp_sub_count > 0) {
				for (j = 0; j < tmp_sub_count; j++) {
					if (RSBAC_UID_SET(sub_desc_p[j].subj_id))
						seq_printf(m, " %s %u/%u,",
						       get_acl_subject_type_name(tmp1,
									 sub_desc_p
									 [j].
									 subj_type),
						       RSBAC_UID_SET(sub_desc_p[j].subj_id),
						       RSBAC_UID_NUM(sub_desc_p[j].subj_id));
					else
					    seq_printf(m,
						    "%s %u, ",
						    get_acl_subject_type_name
						    (tmp1,
						     sub_desc_p[j].
						     subj_type),
						    RSBAC_UID_NUM(sub_desc_p[j].subj_id));
				}
				rsbac_kfree(sub_desc_p);
				member_count += tmp_sub_count;
			}
		}
		rsbac_kfree(nettemp_desc_p);
	}
	seq_printf(m,
		    "\n\n%i network template ACL items, sum of %u members\n",
		    tmp_count, member_count);

	/* netobj list */
	seq_printf(m,
		    "\nNetwork Object ACLs:\nObject-ID count  mask+members");

	member_count = 0;
	tmp_count =
	    rsbac_list_lol_get_all_desc(netobj_handle,
					(void **) &netobj_desc_p);
	if (tmp_count > 0) {
		for (i = 0; i < tmp_count; i++) {
			if (!rsbac_list_lol_get_data
			    (netobj_handle, &netobj_desc_p[i], &rights)) {
				 seq_printf(m,
					    "\n%p   %3li\t%s\n\t\t",
					    netobj_desc_p[i],
					    rsbac_list_lol_subcount
					    (netobj_handle,
					     &netobj_desc_p[i]),
					    u64tostracl(tmp1, rights));
			}
			tmp_sub_count =
			    rsbac_list_lol_get_all_subdesc(netobj_handle,
							   &netobj_desc_p
							   [i],
							   (void **)
							   &sub_desc_p);
			if (tmp_sub_count > 0) {
				for (j = 0; j < tmp_sub_count; j++) {
					if (RSBAC_UID_SET(sub_desc_p[j].subj_id))
						seq_printf(m, " %s %u/%u,",
						       get_acl_subject_type_name(tmp1,
									 sub_desc_p
									 [j].
									 subj_type),
						       RSBAC_UID_SET(sub_desc_p[j].subj_id),
						       RSBAC_UID_NUM(sub_desc_p[j].subj_id));
					else
					    seq_printf(m,
						    "%s %u, ",
						    get_acl_subject_type_name
						    (tmp1,
						     sub_desc_p[j].
						     subj_type),
						    RSBAC_UID_NUM(sub_desc_p[j].subj_id));
				}
				rsbac_kfree(sub_desc_p);
				member_count += tmp_sub_count;
			}
		}
		rsbac_kfree(netobj_desc_p);
	}
	seq_printf(m,
		    "\n\n%i network object ACL items, sum of %u members\n",
		    tmp_count, member_count);
#endif

	return 0;
}

static ssize_t acl_acllist_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, acl_acllist_proc_show, NULL);
}

static const struct file_operations acl_acllist_proc_fops = {
       .owner          = THIS_MODULE,
       .open           = acl_acllist_proc_open,
       .read           = seq_read,
       .llseek         = seq_lseek,
       .release        = single_release,
};

static struct proc_dir_entry *acl_acllist;

static int
acl_grouplist_proc_show(struct seq_file *m, void *v)
{
	char type;
	int count, sub_count;
	int i, j;
	u_int member_count = 0;
	struct rsbac_acl_group_entry_t *entry_p;
	rsbac_uid_t *user_p;
	rsbac_acl_group_id_t *group_p;
	rsbac_time_t *ttl_p;

	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "acl_grouplist_proc_info(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	rsbac_pr_debug(aef_acl, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	seq_printf(m, "ACL Groups\n----------\n");

	/* group list */
	seq_printf(m,
		    "Group list:  %li groups, last new is %u\nID\ttype name\t\towner\n",
		    rsbac_list_count(group_handle), group_last_new);

	count = rsbac_list_get_all_data(group_handle, (void **) &entry_p);
	if (count > 0) {
		for (i = 0; i < count; i++) {
			if (entry_p[i].type == ACLG_GLOBAL)
				type = 'G';
			else
				type = 'P';
			if (RSBAC_UID_SET(entry_p[i].owner))
				    seq_printf(m, "%u\t%c    %-18s %u/%u\n",
					    entry_p[i].id, type, entry_p[i].name,
					    RSBAC_UID_SET(entry_p[i].owner),
					    RSBAC_UID_NUM(entry_p[i].owner));
			else
				    seq_printf(m, "%u\t%c    %-18s %u\n",
					    entry_p[i].id, type, entry_p[i].name,
					    RSBAC_UID_NUM(entry_p[i].owner));
		}
		rsbac_kfree(entry_p);
	}

	/* group member list */
	member_count = 0;
	seq_printf(m,
		    "\nGroup memberships:\nuser   count\tgroups");

	count = rsbac_list_lol_get_all_desc(gm_handle, (void **) &user_p);
	if (count > 0) {
		for (i = 0; i < count; i++) {
			sub_count =
			    rsbac_list_lol_get_all_subdesc_ttl(gm_handle,
							       &user_p[i],
							       (void **)
							       &group_p,
							       &ttl_p);
			if (RSBAC_UID_SET(user_p[i]))
				    seq_printf(m, "\n%u/%u\t%i\t",
					    RSBAC_UID_SET(user_p[i]),
					    RSBAC_UID_NUM(user_p[i]),
					    sub_count);
			else
				    seq_printf(m, "\n%u\t%i\t",
					    RSBAC_UID_NUM(user_p[i]),
					    sub_count);
			if (sub_count > 0) {
				for (j = 0; j < sub_count; j++) {
					if (ttl_p[j])
						    seq_printf(m,
							    "%u(ttl:%i) ",
							    group_p[j],
							    ttl_p[j]);
					else
						    seq_printf(m,
							    "%u ",
							    group_p[j]);
				}
				member_count += sub_count;
				rsbac_kfree(group_p);
				rsbac_kfree(ttl_p);
			}
		}
		rsbac_kfree(user_p);
	}
	seq_printf(m,
		    "\n\n%u user items, sum of %u memberships\n", count,
		    member_count);
	return 0;
}

static ssize_t acl_grouplist_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, acl_grouplist_proc_show, NULL);
}

static const struct file_operations acl_grouplist_proc_fops = {
       .owner          = THIS_MODULE,
       .open           = acl_grouplist_proc_open,
       .read           = seq_read,
       .llseek         = seq_lseek,
       .release        = single_release,
};

static struct proc_dir_entry *acl_grouplist;

#endif


/************************************************* */
/*               Init functions                    */
/************************************************* */

/* All functions return 0, if no error occurred, and a negative error code  */
/* otherwise. The error codes are defined in rsbac/error.h.                 */

/************************************************************************** */
/* Initialization of all ACL data structures. After this call, all ACL    */
/* data is kept in memory for performance reasons, but is written to disk   */
/* on every change. */

#ifdef CONFIG_RSBAC_INIT_DELAY
static void registration_error(int err, char *listname)
#else
static void __init registration_error(int err, char *listname)
#endif
{
	if (err) {
		char *tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

		if (tmp) {
			rsbac_printk(KERN_WARNING "rsbac_init_acl(): Registering ACL %s list failed with error %s\n",
				     listname, get_error_name(tmp, err));
			rsbac_kfree(tmp);
		}
	}
}


#ifdef CONFIG_RSBAC_INIT_DELAY
void acl_create_def(void)
#else
void __init acl_create_def(void)
#endif
{
	if (!rsbac_list_count(default_fd_handle)) {
		struct rsbac_acl_entry_desc_t desc;
		struct rsbac_acl_entry_t acman_entry =
		    RSBAC_ACL_ACMAN_FD_ENTRY;
		struct rsbac_acl_entry_t sysadm_entry =
		    RSBAC_ACL_SYSADM_FD_ENTRY;
		struct rsbac_acl_entry_t gen_entry =
		    RSBAC_ACL_GENERAL_FD_ENTRY;

		rsbac_printk(KERN_WARNING "rsbac_init_acl(): File/Dir default ACL empty on dev %02u:%02u, generating standard ACL!\n",
			     RSBAC_MAJOR(rsbac_root_dev),
			     RSBAC_MINOR(rsbac_root_dev));
		desc.subj_type = acman_entry.subj_type;
		desc.subj_id = acman_entry.subj_id;
		rsbac_list_add(default_fd_handle, &desc,
			       &acman_entry.rights);
		desc.subj_type = sysadm_entry.subj_type;
		desc.subj_id = sysadm_entry.subj_id;
		rsbac_list_add(default_fd_handle, &desc,
			       &sysadm_entry.rights);
		desc.subj_type = gen_entry.subj_type;
		desc.subj_id = gen_entry.subj_id;
		rsbac_list_add(default_fd_handle, &desc,
			       &gen_entry.rights);
	}
	if (!rsbac_list_count(default_dev_handle)) {
		struct rsbac_acl_entry_desc_t desc;
		struct rsbac_acl_entry_t acman_entry =
		    RSBAC_ACL_ACMAN_DEV_ENTRY;
		struct rsbac_acl_entry_t sysadm_entry =
		    RSBAC_ACL_SYSADM_DEV_ENTRY;
		struct rsbac_acl_entry_t gen_entry =
		    RSBAC_ACL_GENERAL_DEV_ENTRY;

		rsbac_printk(KERN_WARNING "rsbac_init_acl(): Device default ACL empty on dev %02u:%02u, generating standard ACL!\n",
			     RSBAC_MAJOR(rsbac_root_dev),
			     RSBAC_MINOR(rsbac_root_dev));
		desc.subj_type = acman_entry.subj_type;
		desc.subj_id = acman_entry.subj_id;
		rsbac_list_add(default_dev_handle, &desc,
			       &acman_entry.rights);
		desc.subj_type = sysadm_entry.subj_type;
		desc.subj_id = sysadm_entry.subj_id;
		rsbac_list_add(default_dev_handle, &desc,
			       &sysadm_entry.rights);
		desc.subj_type = gen_entry.subj_type;
		desc.subj_id = gen_entry.subj_id;
		rsbac_list_add(default_dev_handle, &desc,
			       &gen_entry.rights);
	}
	if (!rsbac_list_count(default_ipc_handle)) {
		struct rsbac_acl_entry_desc_t desc;
		struct rsbac_acl_entry_t acman_entry =
		    RSBAC_ACL_ACMAN_IPC_ENTRY;
		struct rsbac_acl_entry_t sysadm_entry =
		    RSBAC_ACL_SYSADM_IPC_ENTRY;
		struct rsbac_acl_entry_t gen_entry =
		    RSBAC_ACL_GENERAL_IPC_ENTRY;

		rsbac_printk(KERN_WARNING "rsbac_init_acl(): IPC default ACL empty on dev %02u:%02u, generating standard ACL!\n",
			     RSBAC_MAJOR(rsbac_root_dev),
			     RSBAC_MINOR(rsbac_root_dev));
		desc.subj_type = acman_entry.subj_type;
		desc.subj_id = acman_entry.subj_id;
		rsbac_list_add(default_ipc_handle, &desc,
			       &acman_entry.rights);
		desc.subj_type = sysadm_entry.subj_type;
		desc.subj_id = sysadm_entry.subj_id;
		rsbac_list_add(default_ipc_handle, &desc,
			       &sysadm_entry.rights);
		desc.subj_type = gen_entry.subj_type;
		desc.subj_id = gen_entry.subj_id;
		rsbac_list_add(default_ipc_handle, &desc,
			       &gen_entry.rights);
	}
	if (!rsbac_list_count(default_scd_handle)) {
		struct rsbac_acl_entry_desc_t desc;
		struct rsbac_acl_entry_t acman_entry =
		    RSBAC_ACL_ACMAN_SCD_ENTRY;

		rsbac_printk(KERN_WARNING "rsbac_init_acl(): SCD default ACL empty on dev %02u:%02u, generating standard ACL!\n",
			     RSBAC_MAJOR(rsbac_root_dev),
			     RSBAC_MINOR(rsbac_root_dev));
		desc.subj_type = acman_entry.subj_type;
		desc.subj_id = acman_entry.subj_id;
		rsbac_list_add(default_scd_handle, &desc,
			       &acman_entry.rights);
	}
	if (!rsbac_list_lol_count(scd_handle)) {
		struct rsbac_acl_entry_desc_t desc;
		rsbac_acl_rights_vector_t mask =
		    RSBAC_ACL_DEFAULT_SCD_MASK;
		struct rsbac_acl_entry_t gen_entry =
		    RSBAC_ACL_GENERAL_SCD_ENTRY;
#ifdef CONFIG_RSBAC_USER_MOD_IOPERM
		struct rsbac_acl_entry_t gen_ioports_entry =
		    RSBAC_ACL_GENERAL_SCD_IOPORTS_ENTRY;
#endif
		struct rsbac_acl_entry_t gen_other_entry =
		    RSBAC_ACL_GENERAL_SCD_OTHER_ENTRY;
		struct rsbac_acl_entry_t gen_network_entry =
		    RSBAC_ACL_GENERAL_SCD_NETWORK_ENTRY;
		struct rsbac_acl_entry_t sysadm_entry =
		    RSBAC_ACL_SYSADM_SCD_ENTRY;
		struct rsbac_acl_entry_t sysadm_other_entry =
		    RSBAC_ACL_SYSADM_SCD_OTHER_ENTRY;
#ifdef CONFIG_RSBAC_USER_MOD_IOPERM
		struct rsbac_acl_entry_t sysadm_kmem_entry =
		    RSBAC_ACL_SYSADM_SCD_KMEM_ENTRY;
#endif
		struct rsbac_acl_entry_t acman_other_entry =
		    RSBAC_ACL_ACMAN_SCD_OTHER_ENTRY;
		struct rsbac_acl_entry_t auditor_rsbaclog_entry =
		    RSBAC_ACL_AUDITOR_SCD_RSBACLOG_ENTRY;
		__u8 scd;

		rsbac_printk(KERN_WARNING "rsbac_init_acl(): SCD ACLs empty on dev %02u:%02u, generating standard entries!\n",
			     RSBAC_MAJOR(rsbac_root_dev),
			     RSBAC_MINOR(rsbac_root_dev));
		scd = ST_rlimit;
		if (!rsbac_list_lol_add(scd_handle, &scd, &mask)) {
			desc.subj_type = gen_entry.subj_type;
			desc.subj_id = gen_entry.subj_id;
			rsbac_list_lol_subadd(scd_handle, &scd, &desc,
					      &gen_entry.rights);
		}
		for (scd = ST_time_strucs; scd <= ST_rsbac; scd++) {
			if (!rsbac_list_lol_add(scd_handle, &scd, &mask)) {
				desc.subj_type = sysadm_entry.subj_type;
				desc.subj_id = sysadm_entry.subj_id;
				rsbac_list_lol_subadd(scd_handle, &scd,
						      &desc,
						      &sysadm_entry.
						      rights);
			}
		}
		scd = ST_rsbac_log;
		if (!rsbac_list_lol_add(scd_handle, &scd, &mask)) {
			desc.subj_type = auditor_rsbaclog_entry.subj_type;
			desc.subj_id = auditor_rsbaclog_entry.subj_id;
			rsbac_list_lol_subadd(scd_handle, &scd, &desc,
					      &auditor_rsbaclog_entry.
					      rights);
		}
		scd = ST_network;
		if (!rsbac_list_lol_add(scd_handle, &scd, &mask)) {
			desc.subj_type = sysadm_entry.subj_type;
			desc.subj_id = sysadm_entry.subj_id;
			rsbac_list_lol_subadd(scd_handle, &scd, &desc,
					      &sysadm_entry.rights);
			desc.subj_type = gen_network_entry.subj_type;
			desc.subj_id = gen_network_entry.subj_id;
			rsbac_list_lol_subadd(scd_handle, &scd, &desc,
					      &gen_network_entry.rights);
		}
		scd = ST_firewall;
		if (!rsbac_list_lol_add(scd_handle, &scd, &mask)) {
			desc.subj_type = sysadm_entry.subj_type;
			desc.subj_id = sysadm_entry.subj_id;
			rsbac_list_lol_subadd(scd_handle, &scd, &desc,
					      &sysadm_entry.rights);
			desc.subj_type = gen_network_entry.subj_type;
			desc.subj_id = gen_network_entry.subj_id;
			rsbac_list_lol_subadd(scd_handle, &scd, &desc,
					      &gen_network_entry.rights);
		}
		scd = ST_priority;
		if (!rsbac_list_lol_add(scd_handle, &scd, &mask)) {
			desc.subj_type = sysadm_entry.subj_type;
			desc.subj_id = sysadm_entry.subj_id;
			rsbac_list_lol_subadd(scd_handle, &scd, &desc,
					      &sysadm_entry.rights);
		}
		scd = ST_sysfs;
		if (!rsbac_list_lol_add(scd_handle, &scd, &mask)) {
			desc.subj_type = sysadm_entry.subj_type;
			desc.subj_id = sysadm_entry.subj_id;
			rsbac_list_lol_subadd(scd_handle, &scd, &desc,
					      &sysadm_entry.rights);
		}
		for (scd = ST_quota; scd < ST_none; scd++)
			if (!rsbac_list_lol_add(scd_handle, &scd, &mask)) {
				desc.subj_type = sysadm_entry.subj_type;
				desc.subj_id = sysadm_entry.subj_id;
				rsbac_list_lol_subadd(scd_handle, &scd,
						      &desc,
						      &sysadm_entry.
						      rights);
			}
#ifdef CONFIG_RSBAC_USER_MOD_IOPERM
		scd = ST_ioports;
		if (!rsbac_list_lol_add(scd_handle, &scd, &mask)) {
			desc.subj_type = gen_ioports_entry.subj_type;
			desc.subj_id = gen_ioports_entry.subj_id;
			rsbac_list_lol_subadd(scd_handle, &scd, &desc,
					      &gen_ioports_entry.rights);
		}
		scd = ST_kmem;
		if (!rsbac_list_lol_add(scd_handle, &scd, &mask)) {
			desc.subj_type = sysadm_kmem_entry.subj_type;
			desc.subj_id = sysadm_kmem_entry.subj_id;
			rsbac_list_lol_subadd(scd_handle, &scd, &desc,
					      &sysadm_kmem_entry.rights);
		}
#endif

		scd = ST_other;
		if (!rsbac_list_lol_add(scd_handle, &scd, &mask)) {
			desc.subj_type = sysadm_other_entry.subj_type;
			desc.subj_id = sysadm_other_entry.subj_id;
			rsbac_list_lol_subadd(scd_handle, &scd, &desc,
					      &sysadm_other_entry.rights);
			desc.subj_type = acman_other_entry.subj_type;
			desc.subj_id = acman_other_entry.subj_id;
			rsbac_list_lol_subadd(scd_handle, &scd, &desc,
					      &acman_other_entry.rights);
			desc.subj_type = gen_other_entry.subj_type;
			desc.subj_id = gen_other_entry.subj_id;
			rsbac_list_lol_subadd(scd_handle, &scd, &desc,
					      &gen_other_entry.rights);
		}
	}
}

#ifdef CONFIG_RSBAC_INIT_DELAY
void acl_create_def2(void)
#else
void __init acl_create_def2(void)
#endif
{
	if (!rsbac_list_count(default_u_handle)) {
		struct rsbac_acl_entry_desc_t desc;
		struct rsbac_acl_entry_t acman_entry =
		    RSBAC_ACL_ACMAN_U_ENTRY;
		struct rsbac_acl_entry_t sysadm_entry =
		    RSBAC_ACL_SYSADM_U_ENTRY;
		struct rsbac_acl_entry_t gen_entry =
		    RSBAC_ACL_GENERAL_U_ENTRY;

		rsbac_printk(KERN_WARNING "rsbac_init_acl(): User default ACL empty on dev %02u:%02u, generating standard ACL!\n",
			     RSBAC_MAJOR(rsbac_root_dev),
			     RSBAC_MINOR(rsbac_root_dev));
		desc.subj_type = sysadm_entry.subj_type;
		desc.subj_id = sysadm_entry.subj_id;
		rsbac_list_add(default_u_handle, &desc,
			       &sysadm_entry.rights);
		desc.subj_type = acman_entry.subj_type;
		desc.subj_id = acman_entry.subj_id;
		rsbac_list_add(default_u_handle, &desc,
			       &acman_entry.rights);
		desc.subj_type = gen_entry.subj_type;
		desc.subj_id = gen_entry.subj_id;
		rsbac_list_add(default_u_handle, &desc, &gen_entry.rights);
	}
	if (!rsbac_list_count(default_p_handle)) {
		struct rsbac_acl_entry_desc_t desc;
		struct rsbac_acl_entry_t acman_entry =
		    RSBAC_ACL_ACMAN_P_ENTRY;
		struct rsbac_acl_entry_t sysadm_entry =
		    RSBAC_ACL_SYSADM_P_ENTRY;
		struct rsbac_acl_entry_t gen_entry =
		    RSBAC_ACL_GENERAL_P_ENTRY;

		rsbac_printk(KERN_WARNING "rsbac_init_acl(): Process default ACL empty on dev %02u:%02u, generating standard ACL!\n",
			     RSBAC_MAJOR(rsbac_root_dev),
			     RSBAC_MINOR(rsbac_root_dev));
		desc.subj_type = sysadm_entry.subj_type;
		desc.subj_id = sysadm_entry.subj_id;
		rsbac_list_add(default_p_handle, &desc,
			       &sysadm_entry.rights);
		desc.subj_type = acman_entry.subj_type;
		desc.subj_id = acman_entry.subj_id;
		rsbac_list_add(default_p_handle, &desc,
			       &acman_entry.rights);
		desc.subj_type = gen_entry.subj_type;
		desc.subj_id = gen_entry.subj_id;
		rsbac_list_add(default_p_handle, &desc, &gen_entry.rights);
	}
	if (!rsbac_list_lol_count(gm_handle)) {
		rsbac_printk(KERN_WARNING "rsbac_init_acl(): Group membership list empty on dev %02u:%02u!\n",
		     RSBAC_MAJOR(rsbac_root_dev),
		     RSBAC_MINOR(rsbac_root_dev));
	}
	if (!rsbac_list_count(group_handle)) {
		rsbac_printk(KERN_WARNING "rsbac_init_acl(): Group list empty on dev %02u:%02u!\n",
			     RSBAC_MAJOR(rsbac_root_dev),
			     RSBAC_MINOR(rsbac_root_dev));
	} else {
		rsbac_list_get_max_desc(group_handle, &group_last_new);
	}
#ifdef CONFIG_RSBAC_ACL_UM_PROT
	if (!rsbac_list_count(default_g_handle)) {
		struct rsbac_acl_entry_desc_t desc;
		struct rsbac_acl_entry_t acman_entry =
		    RSBAC_ACL_ACMAN_G_ENTRY;
		struct rsbac_acl_entry_t sysadm_entry =
		    RSBAC_ACL_SYSADM_G_ENTRY;
		struct rsbac_acl_entry_t gen_entry =
		    RSBAC_ACL_GENERAL_G_ENTRY;

		rsbac_printk(KERN_WARNING "rsbac_init_acl(): Linux group default ACL empty on dev %02u:%02u, generating standard ACL!\n",
			     RSBAC_MAJOR(rsbac_root_dev),
			     RSBAC_MINOR(rsbac_root_dev));
		desc.subj_type = sysadm_entry.subj_type;
		desc.subj_id = sysadm_entry.subj_id;
		rsbac_list_add(default_g_handle, &desc,
			       &sysadm_entry.rights);
		desc.subj_type = acman_entry.subj_type;
		desc.subj_id = acman_entry.subj_id;
		rsbac_list_add(default_g_handle, &desc,
			       &acman_entry.rights);
		desc.subj_type = gen_entry.subj_type;
		desc.subj_id = gen_entry.subj_id;
		rsbac_list_add(default_g_handle, &desc, &gen_entry.rights);
	}
#endif
#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
	if (!rsbac_list_count(default_netdev_handle)) {
		struct rsbac_acl_entry_desc_t desc;
		struct rsbac_acl_entry_t acman_entry =
		    RSBAC_ACL_ACMAN_NETDEV_ENTRY;
		struct rsbac_acl_entry_t sysadm_entry =
		    RSBAC_ACL_SYSADM_NETDEV_ENTRY;
		struct rsbac_acl_entry_t gen_entry =
		    RSBAC_ACL_GENERAL_NETDEV_ENTRY;

		rsbac_printk(KERN_WARNING "rsbac_init_acl(): Network Device default ACL empty on dev %02u:%02u, generating standard ACL!\n",
			     RSBAC_MAJOR(rsbac_root_dev),
			     RSBAC_MINOR(rsbac_root_dev));
		desc.subj_type = acman_entry.subj_type;
		desc.subj_id = acman_entry.subj_id;
		rsbac_list_add(default_netdev_handle, &desc,
			       &acman_entry.rights);
		desc.subj_type = sysadm_entry.subj_type;
		desc.subj_id = sysadm_entry.subj_id;
		rsbac_list_add(default_netdev_handle, &desc,
			       &sysadm_entry.rights);
		desc.subj_type = gen_entry.subj_type;
		desc.subj_id = gen_entry.subj_id;
		rsbac_list_add(default_netdev_handle, &desc,
			       &gen_entry.rights);
	}
#endif
#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
	if (!rsbac_no_defaults
	    && !rsbac_list_count(default_nettemp_nt_handle)) {
		struct rsbac_acl_entry_desc_t desc;
		struct rsbac_acl_entry_t acman_entry =
		    RSBAC_ACL_ACMAN_NETTEMP_NT_ENTRY;
		struct rsbac_acl_entry_t sysadm_entry =
		    RSBAC_ACL_SYSADM_NETTEMP_NT_ENTRY;
		struct rsbac_acl_entry_t gen_entry =
		    RSBAC_ACL_GENERAL_NETTEMP_NT_ENTRY;

		rsbac_printk(KERN_WARNING "rsbac_init_acl(): Network Template NT (template protection) default ACL empty on dev %02u:%02u, generating standard ACL!\n",
			     RSBAC_MAJOR(rsbac_root_dev),
			     RSBAC_MINOR(rsbac_root_dev));
		desc.subj_type = acman_entry.subj_type;
		desc.subj_id = acman_entry.subj_id;
		rsbac_list_add(default_nettemp_nt_handle, &desc,
			       &acman_entry.rights);
		desc.subj_type = sysadm_entry.subj_type;
		desc.subj_id = sysadm_entry.subj_id;
		rsbac_list_add(default_nettemp_nt_handle, &desc,
			       &sysadm_entry.rights);
		desc.subj_type = gen_entry.subj_type;
		desc.subj_id = gen_entry.subj_id;
		rsbac_list_add(default_nettemp_nt_handle, &desc,
			       &gen_entry.rights);
	}
	if (!rsbac_list_count(default_netobj_handle)) {
		struct rsbac_acl_entry_desc_t desc;
		struct rsbac_acl_entry_t acman_entry =
		    RSBAC_ACL_ACMAN_NETOBJ_ENTRY;
		struct rsbac_acl_entry_t sysadm_entry =
		    RSBAC_ACL_SYSADM_NETOBJ_ENTRY;
		struct rsbac_acl_entry_t gen_entry =
		    RSBAC_ACL_GENERAL_NETOBJ_ENTRY;

		rsbac_printk(KERN_WARNING "rsbac_init_acl(): Network Object default ACL empty on dev %02u:%02u, generating standard ACL!\n",
			     RSBAC_MAJOR(rsbac_root_dev),
			     RSBAC_MINOR(rsbac_root_dev));
		desc.subj_type = acman_entry.subj_type;
		desc.subj_id = acman_entry.subj_id;
		rsbac_list_add(default_netobj_handle, &desc,
			       &acman_entry.rights);
		desc.subj_type = sysadm_entry.subj_type;
		desc.subj_id = sysadm_entry.subj_id;
		rsbac_list_add(default_netobj_handle, &desc,
			       &sysadm_entry.rights);
		desc.subj_type = gen_entry.subj_type;
		desc.subj_id = gen_entry.subj_id;
		rsbac_list_add(default_netobj_handle, &desc,
			       &gen_entry.rights);
	}
#endif
}

/* Because there can be no access to aci data structures before init, */
/* rsbac_init_acl() will initialize all rw-spinlocks to unlocked. */

#ifdef CONFIG_RSBAC_INIT_DELAY
int rsbac_init_acl(void)
#else
int __init rsbac_init_acl(void)
#endif
{
	int err = 0;
	struct rsbac_acl_device_list_item_t *device_p = NULL;
	char tmp[80];
	struct rsbac_list_lol_info_t lol_info;
	struct rsbac_list_info_t list_info;
	rsbac_acl_rights_vector_t def_mask;

	if (rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_init_acl(): RSBAC already initialized\n");
		return -RSBAC_EREINIT;
	}

	/* set rw-spinlocks to unlocked status and init data structures */
	rsbac_printk(KERN_INFO "rsbac_init_acl(): Initializing RSBAC: ACL subsystem\n");

	acl_device_item_slab = rsbac_slab_create("rsbac_acl_device_item",
				sizeof(struct rsbac_acl_device_list_item_t));

	/* Init device list */
	device_list_head_p = kmalloc(sizeof(*device_list_head_p), GFP_KERNEL);
	if (!device_list_head_p) {
		rsbac_printk(KERN_WARNING
			"rsbac_init_acl(): Failed to allocate device_list_head\n");
		return -ENOMEM;
	}
	spin_lock_init(&device_list_lock);
	init_srcu_struct(&device_list_srcu);
	lockdep_set_class(&device_list_lock, &device_list_lock_class);
	device_list_head_p->head = NULL;
	device_list_head_p->tail = NULL;
	device_list_head_p->curr = NULL;
	device_list_head_p->count = 0;

	/* register ACL lists */
	rsbac_pr_debug(ds_acl, "Registering lists\n");
	device_p = create_device_item(rsbac_root_dev);
	if (!device_p) {
		rsbac_printk(KERN_CRIT
			     "rsbac_init_acl(): Could not create device!\n");
		return -RSBAC_ECOULDNOTADDDEVICE;
	}
	if ((err = acl_register_fd_lists(device_p, rsbac_root_dev))) {
		rsbac_printk(KERN_WARNING "rsbac_init_acl(): File/Dir ACL registration failed for dev %02u:%02u, err %s!\n",
			     RSBAC_MAJOR(rsbac_root_dev),
			     RSBAC_MINOR(rsbac_root_dev),
			     get_error_name(tmp, err));
	}
	device_p = add_device_item(device_p);
	if (!device_p) {
		rsbac_printk(KERN_CRIT
			     "rsbac_init_acl(): Could not add device!\n");
		return -RSBAC_ECOULDNOTADDDEVICE;
	}

	list_info.version = RSBAC_ACL_DEF_FD_LIST_VERSION;
	list_info.key = RSBAC_ACL_LIST_KEY;
	list_info.desc_size = sizeof(struct rsbac_acl_entry_desc_t);	/* subj_type + subj_id */
	list_info.data_size = sizeof(rsbac_acl_rights_vector_t);	/* rights */
	list_info.max_age = 0;
	err = rsbac_list_register(RSBAC_LIST_VERSION,
				  &default_fd_handle, &list_info,
#if defined(CONFIG_RSBAC_ACL_BACKUP)
				  RSBAC_LIST_BACKUP |
#endif
				  RSBAC_LIST_PERSIST,
				  entry_compare,
				  def_fd_get_conv,
				  NULL,
				  RSBAC_ACL_DEF_FD_FILENAME,
				  RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "default fd");
	}

	lol_info.version = RSBAC_ACL_DEV_LIST_VERSION;
	lol_info.key = RSBAC_ACL_LIST_KEY;
	lol_info.desc_size = sizeof(struct rsbac_dev_desc_t);
	lol_info.data_size = sizeof(rsbac_acl_rights_vector_t);	/* mask */
	lol_info.subdesc_size = sizeof(struct rsbac_acl_entry_desc_t);	/* subj_type + subj_id */
	lol_info.subdata_size = sizeof(rsbac_acl_rights_vector_t);	/* rights */
	lol_info.max_age = 0;
	def_mask = RSBAC_ACL_DEFAULT_DEV_MASK;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &dev_handle, &lol_info,
#if defined(CONFIG_RSBAC_ACL_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST |
				      RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
				      dev_compare,
				      entry_compare, dev_get_conv,
				      dev_get_subconv, &def_mask, NULL,
				      RSBAC_ACL_DEV_FILENAME,
				      RSBAC_AUTO_DEV,
					1,
					rsbac_list_hash_dev,
					NULL);
	if (err) {
		registration_error(err, "dev");
	}
	lol_info.version = RSBAC_ACL_DEV_LIST_VERSION;
	lol_info.key = RSBAC_ACL_LIST_KEY;
	lol_info.desc_size = sizeof(struct rsbac_dev_desc_t);
	lol_info.data_size = sizeof(rsbac_acl_rights_vector_t);	/* mask */
	lol_info.subdesc_size = sizeof(struct rsbac_acl_entry_desc_t);	/* subj_type + subj_id */
	lol_info.subdata_size = sizeof(rsbac_acl_rights_vector_t);	/* rights */
	lol_info.max_age = 0;
	def_mask = RSBAC_ACL_DEFAULT_DEV_MASK;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &dev_major_handle, &lol_info,
#if defined(CONFIG_RSBAC_ACL_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST |
				      RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
				      dev_major_compare, entry_compare,
				      dev_get_conv, dev_get_subconv,
				      &def_mask, NULL,
				      RSBAC_ACL_DEV_MAJOR_FILENAME,
				      RSBAC_AUTO_DEV,
					1,
					rsbac_list_hash_dev,
					NULL);
	if (err) {
		registration_error(err, "dev major");
	}
	list_info.version = RSBAC_ACL_DEF_DEV_LIST_VERSION;
	list_info.key = RSBAC_ACL_LIST_KEY;
	list_info.desc_size = sizeof(struct rsbac_acl_entry_desc_t);	/* subj_type + subj_id */
	list_info.data_size = sizeof(rsbac_acl_rights_vector_t);	/* rights */
	list_info.max_age = 0;
	err = rsbac_list_register(RSBAC_LIST_VERSION,
				  &default_dev_handle, &list_info,
#if defined(CONFIG_RSBAC_ACL_BACKUP)
				  RSBAC_LIST_BACKUP |
#endif
				  RSBAC_LIST_PERSIST,
				  entry_compare,
				  def_dev_get_conv,
				  NULL,
				  RSBAC_ACL_DEF_DEV_FILENAME,
				  RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "default dev");
	}

	list_info.version = RSBAC_ACL_DEF_IPC_LIST_VERSION;
	list_info.key = RSBAC_ACL_LIST_KEY;
	list_info.desc_size = sizeof(struct rsbac_acl_entry_desc_t);	/* subj_type + subj_id */
	list_info.data_size = sizeof(rsbac_acl_rights_vector_t);	/* rights */
	list_info.max_age = 0;
	err = rsbac_list_register(RSBAC_LIST_VERSION,
				  &default_ipc_handle, &list_info,
#if defined(CONFIG_RSBAC_ACL_BACKUP)
				  RSBAC_LIST_BACKUP |
#endif
				  RSBAC_LIST_PERSIST,
				  entry_compare,
				  def_ipc_get_conv,
				  NULL,
				  RSBAC_ACL_DEF_IPC_FILENAME,
				  RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "default ipc");
	}

	lol_info.version = RSBAC_ACL_SCD_LIST_VERSION;
	lol_info.key = RSBAC_ACL_LIST_KEY;
	lol_info.desc_size = sizeof(__u8);
	lol_info.data_size = sizeof(rsbac_acl_rights_vector_t);	/* mask */
	lol_info.subdesc_size = sizeof(struct rsbac_acl_entry_desc_t);	/* subj_type + subj_id */
	lol_info.subdata_size = sizeof(rsbac_acl_rights_vector_t);	/* rights */
	lol_info.max_age = 0;
	def_mask = RSBAC_ACL_DEFAULT_SCD_MASK;
	err = rsbac_list_lol_register(RSBAC_LIST_VERSION,
				      &scd_handle, &lol_info,
#if defined(CONFIG_RSBAC_ACL_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST |
				      RSBAC_LIST_DEF_DATA, NULL,
				      entry_compare, scd_get_conv,
				      scd_get_subconv, &def_mask, NULL,
				      RSBAC_ACL_SCD_FILENAME,
				      RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "scd");
	}

	list_info.version = RSBAC_ACL_DEF_SCD_LIST_VERSION;
	list_info.key = RSBAC_ACL_LIST_KEY;
	list_info.desc_size = sizeof(struct rsbac_acl_entry_desc_t);	/* subj_type + subj_id */
	list_info.data_size = sizeof(rsbac_acl_rights_vector_t);	/* rights */
	list_info.max_age = 0;
	err = rsbac_list_register(RSBAC_LIST_VERSION,
				  &default_scd_handle, &list_info,
#if defined(CONFIG_RSBAC_ACL_BACKUP)
				  RSBAC_LIST_BACKUP |
#endif
				  RSBAC_LIST_PERSIST,
				  entry_compare,
				  def_scd_get_conv,
				  NULL,
				  RSBAC_ACL_DEF_SCD_FILENAME,
				  RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "default scd");
	}

	lol_info.version = RSBAC_ACL_U_LIST_VERSION;
	lol_info.key = RSBAC_ACL_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_uid_t);
	lol_info.data_size = sizeof(rsbac_acl_rights_vector_t);	/* mask */
	lol_info.subdesc_size = sizeof(struct rsbac_acl_entry_desc_t);	/* subj_type + subj_id */
	lol_info.subdata_size = sizeof(rsbac_acl_rights_vector_t);	/* rights */
	lol_info.max_age = 0;
	def_mask = RSBAC_ACL_DEFAULT_U_MASK;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &u_handle, &lol_info,
#if defined(CONFIG_RSBAC_ACL_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST | RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
				      NULL,
				      entry_compare,
				      u_get_conv,
				      u_get_subconv,
				      &def_mask,
				      NULL,
				      RSBAC_ACL_U_FILENAME,
				      RSBAC_AUTO_DEV,
					1,
					rsbac_list_hash_uid,
					NULL);
	if (err) {
		registration_error(err, "user");
	}
	list_info.version = RSBAC_ACL_DEF_U_LIST_VERSION;
	list_info.key = RSBAC_ACL_LIST_KEY;
	list_info.desc_size = sizeof(struct rsbac_acl_entry_desc_t);	/* subj_type + subj_id */
	list_info.data_size = sizeof(rsbac_acl_rights_vector_t);	/* rights */
	list_info.max_age = 0;
	err = rsbac_list_register(RSBAC_LIST_VERSION,
				  &default_u_handle, &list_info,
#if defined(CONFIG_RSBAC_ACL_BACKUP)
				  RSBAC_LIST_BACKUP |
#endif
				  RSBAC_LIST_PERSIST,
				  entry_compare,
				  def_u_get_conv,
				  NULL,
				  RSBAC_ACL_DEF_U_FILENAME,
				  RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "default user");
	}

	list_info.version = RSBAC_ACL_DEF_P_LIST_VERSION;
	list_info.key = RSBAC_ACL_LIST_KEY;
	list_info.desc_size = sizeof(struct rsbac_acl_entry_desc_t);	/* subj_type + subj_id */
	list_info.data_size = sizeof(rsbac_acl_rights_vector_t);	/* rights */
	list_info.max_age = 0;
	err = rsbac_list_register(RSBAC_LIST_VERSION,
				  &default_p_handle, &list_info,
#if defined(CONFIG_RSBAC_ACL_BACKUP)
				  RSBAC_LIST_BACKUP |
#endif
				  RSBAC_LIST_PERSIST,
				  entry_compare,
				  def_p_get_conv,
				  NULL,
				  RSBAC_ACL_DEF_P_FILENAME,
				  RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "default process");
	}
#ifdef CONFIG_RSBAC_ACL_UM_PROT
	lol_info.version = RSBAC_ACL_G_LIST_VERSION;
	lol_info.key = RSBAC_ACL_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_gid_t);
	lol_info.data_size = sizeof(rsbac_acl_rights_vector_t);	/* mask */
	lol_info.subdesc_size = sizeof(struct rsbac_acl_entry_desc_t);	/* subj_type + subj_id */
	lol_info.subdata_size = sizeof(rsbac_acl_rights_vector_t);	/* rights */
	lol_info.max_age = 0;
	def_mask = RSBAC_ACL_DEFAULT_G_MASK;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &g_handle, &lol_info,
#if defined(CONFIG_RSBAC_ACL_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST | RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
				      NULL,
				      entry_compare,
				      g_get_conv,
				      g_get_subconv,
				      &def_mask,
				      NULL,
				      RSBAC_ACL_G_FILENAME,
				      RSBAC_AUTO_DEV,
					1,
					rsbac_list_hash_gid,
					NULL);
	if (err) {
		registration_error(err, "Linux group");
	}
	list_info.version = RSBAC_ACL_DEF_G_LIST_VERSION;
	list_info.key = RSBAC_ACL_LIST_KEY;
	list_info.desc_size = sizeof(struct rsbac_acl_entry_desc_t);	/* subj_type + subj_id */
	list_info.data_size = sizeof(rsbac_acl_rights_vector_t);	/* rights */
	list_info.max_age = 0;
	err = rsbac_list_register(RSBAC_LIST_VERSION,
				  &default_g_handle, &list_info,
#if defined(CONFIG_RSBAC_ACL_BACKUP)
				  RSBAC_LIST_BACKUP |
#endif
				  RSBAC_LIST_PERSIST,
				  entry_compare,
				  def_g_get_conv,
				  NULL,
				  RSBAC_ACL_DEF_G_FILENAME,
				  RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "default Linux group");
	}
#endif

#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
	lol_info.version = RSBAC_ACL_NETDEV_LIST_VERSION;
	lol_info.key = RSBAC_ACL_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_netdev_id_t);
	lol_info.data_size = sizeof(rsbac_acl_rights_vector_t);	/* mask */
	lol_info.subdesc_size = sizeof(struct rsbac_acl_entry_desc_t);	/* subj_type + subj_id */
	lol_info.subdata_size = sizeof(rsbac_acl_rights_vector_t);	/* rights */
	lol_info.max_age = 0;
	def_mask = RSBAC_ACL_DEFAULT_NETDEV_MASK;
	err = rsbac_list_lol_register(RSBAC_LIST_VERSION,
				      &netdev_handle, &lol_info,
#if defined(CONFIG_RSBAC_ACL_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST |
				      RSBAC_LIST_DEF_DATA, netdev_compare,
				      entry_compare, netdev_get_conv,
				      netdev_get_subconv, &def_mask, NULL,
				      RSBAC_ACL_NETDEV_FILENAME,
				      RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "netdev");
	}
	list_info.version = RSBAC_ACL_DEF_NETDEV_LIST_VERSION;
	list_info.key = RSBAC_ACL_LIST_KEY;
	list_info.desc_size = sizeof(struct rsbac_acl_entry_desc_t);	/* subj_type + subj_id */
	list_info.data_size = sizeof(rsbac_acl_rights_vector_t);	/* rights */
	list_info.max_age = 0;
	err = rsbac_list_register(RSBAC_LIST_VERSION,
				  &default_netdev_handle, &list_info,
#if defined(CONFIG_RSBAC_ACL_BACKUP)
				  RSBAC_LIST_BACKUP |
#endif
				  RSBAC_LIST_PERSIST,
				  entry_compare,
				  def_netdev_get_conv,
				  NULL,
				  RSBAC_ACL_DEF_NETDEV_FILENAME,
				  RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "default netdev");
	}
#endif

#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
	lol_info.version = RSBAC_ACL_NETTEMP_NT_LIST_VERSION;
	lol_info.key = RSBAC_ACL_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_net_temp_id_t);
	lol_info.data_size = sizeof(rsbac_acl_rights_vector_t);	/* mask */
	lol_info.subdesc_size = sizeof(struct rsbac_acl_entry_desc_t);	/* subj_type + subj_id */
	lol_info.subdata_size = sizeof(rsbac_acl_rights_vector_t);	/* rights */
	lol_info.max_age = 0;
	def_mask = RSBAC_ACL_DEFAULT_NETTEMP_MASK;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &nettemp_nt_handle, &lol_info,
#if defined(CONFIG_RSBAC_ACL_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST | RSBAC_LIST_AUTO_HASH_RESIZE,
				      NULL,
				      entry_compare,
				      nettemp_nt_get_conv,
				      nettemp_nt_get_subconv,
				      &def_mask,
				      NULL,
				      RSBAC_ACL_NETTEMP_NT_FILENAME,
				      RSBAC_AUTO_DEV,
					1,
					rsbac_list_hash_nettemp,
					NULL);
	if (err) {
		registration_error(err, "nettemp_nt");
	}
	list_info.version = RSBAC_ACL_DEF_NETTEMP_NT_LIST_VERSION;
	list_info.key = RSBAC_ACL_LIST_KEY;
	list_info.desc_size = sizeof(struct rsbac_acl_entry_desc_t);	/* subj_type + subj_id */
	list_info.data_size = sizeof(rsbac_acl_rights_vector_t);	/* rights */
	list_info.max_age = 0;
	err = rsbac_list_register(RSBAC_LIST_VERSION,
				  &default_nettemp_nt_handle, &list_info,
#if defined(CONFIG_RSBAC_ACL_BACKUP)
				  RSBAC_LIST_BACKUP |
#endif
				  RSBAC_LIST_PERSIST,
				  entry_compare,
				  def_nettemp_nt_get_conv,
				  NULL,
				  RSBAC_ACL_DEF_NETTEMP_NT_FILENAME,
				  RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "default nettemp_nt");
	}
	lol_info.version = RSBAC_ACL_NETTEMP_LIST_VERSION;
	lol_info.key = RSBAC_ACL_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_net_temp_id_t);
	lol_info.data_size = sizeof(rsbac_acl_rights_vector_t);	/* mask */
	lol_info.subdesc_size = sizeof(struct rsbac_acl_entry_desc_t);	/* subj_type + subj_id */
	lol_info.subdata_size = sizeof(rsbac_acl_rights_vector_t);	/* rights */
	lol_info.max_age = 0;
	def_mask = RSBAC_ACL_DEFAULT_NETOBJ_MASK;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &nettemp_handle, &lol_info,
#if defined(CONFIG_RSBAC_ACL_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST | RSBAC_LIST_AUTO_HASH_RESIZE,
				      NULL,
				      entry_compare,
				      nettemp_get_conv,
				      nettemp_get_subconv,
				      &def_mask,
				      NULL,
				      RSBAC_ACL_NETTEMP_FILENAME,
				      RSBAC_AUTO_DEV,
					1,
					rsbac_list_hash_nettemp,
					NULL);
	if (err) {
		registration_error(err, "nettemp");
	}
	lol_info.version = RSBAC_ACL_NETOBJ_LIST_VERSION;
	lol_info.key = RSBAC_ACL_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_net_obj_id_t);
	lol_info.data_size = sizeof(rsbac_acl_rights_vector_t);	/* mask */
	lol_info.subdesc_size = sizeof(struct rsbac_acl_entry_desc_t);	/* subj_type + subj_id */
	lol_info.subdata_size = sizeof(rsbac_acl_rights_vector_t);	/* rights */
	lol_info.max_age = 0;
	def_mask = RSBAC_ACL_DEFAULT_NETOBJ_MASK;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &netobj_handle,
				      &lol_info,
				      RSBAC_LIST_AUTO_HASH_RESIZE,
				      NULL,
				      entry_compare,
				      netobj_get_conv,
				      netobj_get_subconv,
				      &def_mask,
				      NULL,
				      RSBAC_ACL_NETOBJ_FILENAME,
				      RSBAC_AUTO_DEV,
					1,
					rsbac_list_hash_netobj,
					NULL);
	if (err) {
		registration_error(err, "netobj");
	}
	list_info.version = RSBAC_ACL_DEF_NETOBJ_LIST_VERSION;
	list_info.key = RSBAC_ACL_LIST_KEY;
	list_info.desc_size = sizeof(struct rsbac_acl_entry_desc_t);	/* subj_type + subj_id */
	list_info.data_size = sizeof(rsbac_acl_rights_vector_t);	/* rights */
	list_info.max_age = 0;
	err = rsbac_list_register(RSBAC_LIST_VERSION,
				  &default_netobj_handle, &list_info,
#if defined(CONFIG_RSBAC_ACL_BACKUP)
				  RSBAC_LIST_BACKUP |
#endif
				  RSBAC_LIST_PERSIST,
				  entry_compare,
				  def_netobj_get_conv,
				  NULL,
				  RSBAC_ACL_DEF_NETOBJ_FILENAME,
				  RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "default netobj");
	}
#endif				/* NET_OBJ_PROT */

	/* groups */
	list_info.version = RSBAC_ACL_GROUP_VERSION;
	list_info.key = RSBAC_ACL_LIST_KEY;
	list_info.desc_size = sizeof(rsbac_acl_group_id_t);
	list_info.data_size = sizeof(struct rsbac_acl_group_entry_t);
	list_info.max_age = 0;
	err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
				  &group_handle, &list_info,
#if defined(CONFIG_RSBAC_ACL_BACKUP)
				  RSBAC_LIST_BACKUP |
#endif
				  RSBAC_LIST_PERSIST | RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
				  NULL,
				  NULL,
				  NULL,
				  RSBAC_ACL_GROUP_FILENAME,
				  RSBAC_AUTO_DEV,
				  1,
				  group_hash,
				  NULL);
	if (err) {
		registration_error(err, "group");
	}

	/* group memberships */
	lol_info.version = RSBAC_ACL_GM_VERSION;
	lol_info.key = RSBAC_ACL_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_uid_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_acl_group_id_t);
	lol_info.subdata_size = 0;
	lol_info.max_age = 0;
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				      &gm_handle, &lol_info,
#if defined(CONFIG_RSBAC_ACL_BACKUP)
				      RSBAC_LIST_BACKUP |
#endif
				      RSBAC_LIST_PERSIST |
				      RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
				      NULL,
				      NULL,
				      gm_get_conv,
				      gm_get_subconv,
				      NULL, NULL, RSBAC_ACL_GM_FILENAME,
				      RSBAC_AUTO_DEV,
					1,
					rsbac_list_hash_uid,
					NULL);
	if (err) {
		registration_error(err, "gm");
	}

/* Create default lists */
	if (!rsbac_no_defaults) {
		acl_create_def();
		acl_create_def2();
	}
#if defined(CONFIG_RSBAC_PROC)
	acl_devices = proc_create("acl_devices",
					S_IFREG | S_IRUGO,
					proc_rsbac_root_p, &acl_devices_proc_fops);
	stats_acl = proc_create("stats_acl",
					S_IFREG | S_IRUGO,
					proc_rsbac_root_p, &stats_acl_proc_fops);
	acl_acllist = proc_create("acl_acllist",
					S_IFREG | S_IRUGO,
					proc_rsbac_root_p, &acl_acllist_proc_fops);
	acl_grouplist = proc_create("acl_grouplist",
					S_IFREG | S_IRUGO,
					proc_rsbac_root_p, &acl_grouplist_proc_fops);
#endif

	rsbac_pr_debug(ds_acl, "Ready.\n");
	return err;
}

int rsbac_mount_acl(kdev_t kdev)
{
	int err = 0;
	struct rsbac_acl_device_list_item_t *device_p;
	struct rsbac_acl_device_list_item_t *new_device_p;
	int srcu_idx;

	rsbac_pr_debug(ds_acl, "mounting device %02u:%02u\n",
		       RSBAC_MAJOR(kdev), RSBAC_MINOR(kdev));
	/* wait for read access to device_list_head */
	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = acl_lookup_device(kdev);
	/* repeated mount? */
	if (device_p) {
		rsbac_printk(KERN_INFO "rsbac_mount_acl: repeated mount %u of device %02u:%02u\n",
			     device_p->mount_count, RSBAC_MAJOR(kdev),
			     RSBAC_MINOR(kdev));
		device_p->mount_count++;
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		return 0;
	}
	srcu_read_unlock(&device_list_srcu, srcu_idx);
	/* OK, go on */
	new_device_p = create_device_item(kdev);
	if (!new_device_p)
		return -RSBAC_ECOULDNOTADDDEVICE;

	if ((err = acl_register_fd_lists(new_device_p, kdev))) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "rsbac_mount_acl(): File/Dir ACL registration failed for dev %02u:%02u, err %s!\n",
				     RSBAC_MAJOR(kdev), RSBAC_MINOR(kdev),
				     get_error_name(tmp, err));
			rsbac_kfree(tmp);
		}
	}
	srcu_idx = srcu_read_lock(&device_list_srcu);
	/* make sure to only add, if this device item has not been added in the meantime */
	device_p = acl_lookup_device(kdev);
	if (device_p) {
		rsbac_printk(KERN_WARNING "rsbac_mount_acl(): mount race for device %02u:%02u detected!\n",
			     RSBAC_MAJOR(kdev), RSBAC_MINOR(kdev));
		device_p->mount_count++;
		/* also detaches lists */
		clear_device_item(new_device_p);
		srcu_read_unlock(&device_list_srcu, srcu_idx);
	} else {
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		device_p = add_device_item(new_device_p);
		if (!device_p) {
			rsbac_printk(KERN_WARNING "rsbac_mount_acl: adding device %02u:%02u failed!\n",
				     RSBAC_MAJOR(kdev), RSBAC_MINOR(kdev));
			/* also detaches lists */
			clear_device_item(new_device_p);
			err = -RSBAC_ECOULDNOTADDDEVICE;
		}
	}

	return err;
}

/* When umounting a device, its file/dir ACLs must be removed. */

int rsbac_umount_acl(kdev_t kdev)
{
	struct rsbac_acl_device_list_item_t *device_p;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_umount(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	rsbac_pr_debug(ds_acl, "umounting device %02u:%02u\n",
		     RSBAC_MAJOR(kdev), RSBAC_MINOR(kdev));
	/* sync of attribute lists was done in rsbac_umount */
	spin_lock(&device_list_lock);
	/* OK, nobody else is working on it... */
	device_p = acl_lookup_device(kdev);
	if (device_p) {
		if (device_p->mount_count == 1)
			remove_device_item(kdev);
		else {
			if (device_p->mount_count > 1) {
				device_p->mount_count--;
				spin_unlock(&device_list_lock);
			} else {
				spin_unlock(&device_list_lock);
				rsbac_printk(KERN_WARNING "rsbac_umount_acl: device %02u:%02u has mount_count < 1!\n",
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

int rsbac_stats_acl(void)
{
	struct rsbac_acl_device_list_item_t *device_p;
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_stats_acl(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	rsbac_pr_debug(aef_acl, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	rsbac_printk(KERN_INFO "ACL Status\n-----------\n");

	/* protect device list */
	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = rcu_dereference(device_list_head_p)->head;
	while (device_p) {
		rsbac_printk(KERN_INFO "device %02u:%02u has %u file ACLs, sum of %u members\n",
			     RSBAC_MAJOR(device_p->id),
			     RSBAC_MINOR(device_p->id),
			     rsbac_list_lol_count(device_p->handle),
			     rsbac_list_lol_all_subcount(device_p->handle));
		device_p = device_p->next;
	}
	/* unprotect device list */
	srcu_read_unlock(&device_list_srcu, srcu_idx);

	/* dev list */
	rsbac_printk(KERN_INFO "%li device major ACL items, sum of %li members\n",
		     rsbac_list_lol_count(dev_major_handle),
		     rsbac_list_lol_all_subcount(dev_major_handle));
	rsbac_printk(KERN_INFO "%li device ACL items, sum of %li members\n",
		     rsbac_list_lol_count(dev_handle),
		     rsbac_list_lol_all_subcount(dev_handle));

	/* SCD list */
	rsbac_printk(KERN_INFO "%li scd ACL items, sum of %li members\n",
		     rsbac_list_lol_count(scd_handle),
		     rsbac_list_lol_all_subcount(scd_handle));

	/* user list */
	rsbac_printk(KERN_INFO "%li user ACL items, sum of %li members\n",
		     rsbac_list_lol_count(u_handle),
		     rsbac_list_lol_all_subcount(u_handle));

#ifdef CONFIG_RSBAC_ACL_UM_PROT
	/* Linux group list */
	rsbac_printk(KERN_INFO "%li Linux group ACL items, sum of %li members\n",
		     rsbac_list_lol_count(g_handle),
		     rsbac_list_lol_all_subcount(g_handle));
#endif

#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
	/* netdev list */
	rsbac_printk(KERN_INFO "%li network device ACL items, sum of %li members\n",
		     rsbac_list_lol_count(netdev_handle),
		     rsbac_list_lol_all_subcount(netdev_handle));
#endif

#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
	/* nettemp_nt list */
	rsbac_printk(KERN_INFO "%li network template NT ACL items, sum of %li members\n",
		     rsbac_list_lol_count(nettemp_nt_handle),
		     rsbac_list_lol_all_subcount(nettemp_nt_handle));
	/* nettemp list */
	rsbac_printk(KERN_INFO "%li network template ACL items, sum of %li members\n",
		     rsbac_list_lol_count(nettemp_handle),
		     rsbac_list_lol_all_subcount(nettemp_handle));
	/* netobj list */
	rsbac_printk(KERN_INFO "%li network object ACL items, sum of %li members\n",
		     rsbac_list_lol_count(netobj_handle),
		     rsbac_list_lol_all_subcount(netobj_handle));
#endif

	rsbac_printk(KERN_INFO "%li groups, last new is %u\n",
		     rsbac_list_count(group_handle), group_last_new);

	/* protect gm list */
	rsbac_printk(KERN_INFO "%li group member items, sum of %li group memberships\n",
		     rsbac_list_lol_count(gm_handle),
		     rsbac_list_lol_all_subcount(gm_handle));

	return 0;
}

/***************************************************/
/* consistency checking (as far as possible)       */

int rsbac_check_acl(int correct)
{
	struct rsbac_acl_device_list_item_t *device_p;
	u_long f_count = 0, f_sum = 0, tmp_count,
	    r_count, u_count, b_count, no_member_count;
	long desc_count;
	long sub_desc_count;
	rsbac_inode_nr_t *fd_desc_p;
	struct rsbac_dev_desc_t *dev_desc_p;
	__u8 *scd_desc_p;
	rsbac_uid_t *u_desc_p;
#ifdef CONFIG_RSBAC_ACL_UM_PROT
	rsbac_gid_t *g_desc_p;
#endif
#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
	rsbac_netdev_id_t *netdev_desc_p;
#endif
#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
	rsbac_net_temp_id_t *nettemp_desc_p;
	rsbac_net_obj_id_t *netobj_desc_p;
#endif
	struct rsbac_acl_entry_desc_t *sub_desc_p;
	rsbac_uid_t *user_p;
	rsbac_acl_group_id_t *group_p;
	u_int i, j;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_check_acl(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}

	/* group membership list */
	tmp_count = 0;
	desc_count =
	    rsbac_list_lol_get_all_desc(gm_handle, (void **) &user_p);
	if (desc_count > 0) {
		for (i = 0; i < desc_count; i++) {
			sub_desc_count =
			    rsbac_list_lol_get_all_subdesc(gm_handle,
							   &user_p[i],
							   (void **)
							   &group_p);
			if (sub_desc_count > 0) {
				for (j = 0; j < sub_desc_count; j++) {
					if (!rsbac_list_exist
					    (group_handle, &group_p[j])) {
						rsbac_printk(KERN_WARNING "rsbac_check_acl(): removing user %u membership in non-existent group %u!\n",
							     user_p[i],
							     group_p[j]);
						rsbac_list_lol_subremove
						    (gm_handle, &user_p[i],
						     &group_p[j]);
					}
				}
				rsbac_kfree(group_p);
			} else {
				/* remove empty membership list */
				if (!sub_desc_count)
					rsbac_list_lol_remove(gm_handle,
							      &user_p[i]);
			}
		}
		rsbac_kfree(user_p);
	}
	/* recalculated values! */
	rsbac_printk(KERN_INFO "rsbac_check_acl(): %li group membership items\n",
		     rsbac_list_lol_count(gm_handle));

	/* group list */
	rsbac_printk(KERN_INFO "rsbac_check_acl(): %li group items\n",
		     rsbac_list_count(group_handle));

	srcu_idx = srcu_read_lock(&device_list_srcu);
/*    rsbac_printk(KERN_INFO "rsbac_check_acl(): currently %u processes working on file/dir aci\n",
                     device_list_head.lock.lock); */
	device_p = rcu_dereference(device_list_head_p)->head;
	while (device_p) {	/* for all sublists */
		f_count = 0;
		r_count = 0;
		u_count = 0;
		b_count = 0;
		no_member_count = 0;

		tmp_count = 0;
		desc_count = rsbac_list_lol_get_all_desc(device_p->handle,
							(void **)
							&fd_desc_p);
		if (desc_count > 0) {
			for (i = 0; i < desc_count; i++) {
				/* check for group existence of all ACL entries for groups */
				sub_desc_count =
				    rsbac_list_lol_get_all_subdesc
				    (device_p->handle,
				     &fd_desc_p[i],
				     (void **) &sub_desc_p);
				if (sub_desc_count > 0) {
					for (j = 0;
					     j < sub_desc_count;
					     j++) {
						if ((sub_desc_p[j].
						     subj_type ==
						     ACLS_GROUP)
						    &&
						    sub_desc_p[j].
						    subj_id
						    &&
						    !rsbac_list_exist
						    (group_handle,
						     &sub_desc_p
						     [j].
						     subj_id)) {
							if (correct) {
								/* remove sub item and complain */
								rsbac_pr_debug(ds, "fd_item for inode %u on device %02u:%02u has invalid group %u in ACL -> removing entry!\n",
									       fd_desc_p[i],
									       RSBAC_MAJOR(device_p->id),
									       RSBAC_MINOR(device_p->id),
									       sub_desc_p[j].subj_id);
								rsbac_list_lol_subremove
								    (device_p->handle,
								     &fd_desc_p
								     [i],
								     &sub_desc_p
								     [j]);
							} else /* complain */
								rsbac_pr_debug(ds, "fd_item for inode %u on device %02u:%02u has invalid group %u in ACL!\n",
									       fd_desc_p[i],
									       RSBAC_MAJOR(device_p->id),
									       RSBAC_MINOR(device_p->id),
									       sub_desc_p[j].subj_id);
						}
#if defined(CONFIG_RSBAC_RC)
						else if ((sub_desc_p[j].subj_type == ACLS_ROLE)
							 &&
							 (sub_desc_p
							  [j].
							  subj_id >
							  RC_role_max_value)
						    ) {
							if (correct) {
								/* remove sub item and complain */
								rsbac_pr_debug(ds, "fd_item for inode %u on device %02u:%02u has invalid RC role %u in ACL -> removing entry!\n",
									       fd_desc_p[i],
									       RSBAC_MAJOR(device_p->id),
									       RSBAC_MINOR(device_p->id),
									       sub_desc_p[j].subj_id);
								rsbac_list_lol_subremove
								    (device_p->handle,
								     &fd_desc_p
								     [i],
								     &sub_desc_p
								     [j]);
							} else /* complain */
								rsbac_pr_debug(ds, "fd_item for inode %u on device %02u:%02u has invalid role %u in ACL!\n",
									       fd_desc_p[i],
									       RSBAC_MAJOR(device_p->id),
									       RSBAC_MINOR(device_p->id),
									       sub_desc_p[j].subj_id);
						}
#endif
					}
					rsbac_kfree(sub_desc_p);
				}
			}
			tmp_count++;
			rsbac_kfree(fd_desc_p);
			f_count += desc_count;
		}

		switch (correct) {
		case 2:
			rsbac_printk(KERN_INFO "rsbac_check_acl(): Device %02u:%02u has %lu file/dir ACLs (%lu removed (%lu bad inodes, %lu dtimed inodes, %lu unlinked inodes, %lu had no members and default mask))\n",
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id), f_count,
				     b_count + r_count + u_count +
				     no_member_count, b_count, r_count,
				     u_count, no_member_count);
			break;
		case 1:
			rsbac_printk(KERN_INFO "rsbac_check_acl(): Device %02u:%02u has %lu file/dir ACLs (%lu removed (%lu bad inodes, %lu dtimed inodes, %lu had no members and default mask), %lu unlinked inodes)\n",
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id), f_count,
				     b_count + r_count + no_member_count,
				     b_count, r_count, no_member_count,
				     u_count);
			break;
		default:
			rsbac_printk(KERN_INFO "rsbac_check_acl(): Device %02u:%02u has %lu file/dir ACLs (%lu with bad inodes, %lu with dtimed inodes, %lu unlinked inodes, %lu without members and with default mask)\n",
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id), f_count,
				     b_count, r_count, u_count,
				     no_member_count);
		}
		f_sum += f_count;
		/* go on */
		device_p = device_p->next;
	}
	rsbac_printk(KERN_INFO "rsbac_check_acl(): Sum of %u Devices with %lu file/dir ACLs\n",
		     rcu_dereference(device_list_head_p)->count, f_sum);
	/* free access to device_list_head */
	srcu_read_unlock(&device_list_srcu, srcu_idx);

	/* dev list */
	tmp_count = 0;
	desc_count =
	    rsbac_list_lol_get_all_desc(dev_handle, (void **) &dev_desc_p);
	if (desc_count > 0) {
		for (i = 0; i < desc_count; i++) {
			/* check for group existence of all ACL entries for groups */
			sub_desc_count =
			    rsbac_list_lol_get_all_subdesc(dev_handle,
							   &dev_desc_p[i],
							   (void **)
							   &sub_desc_p);
			if (sub_desc_count > 0) {
				for (j = 0; j < sub_desc_count; j++) {
					if ((sub_desc_p[j].subj_type ==
					     ACLS_GROUP)
					    && sub_desc_p[j].subj_id
					    &&
					    !rsbac_list_exist(group_handle,
							      &sub_desc_p
							      [j].
							      subj_id)) {
						if (correct) {
							/* remove sub item and complain */
							rsbac_pr_debug(ds, "dev_item %c%02u:%02u, has invalid group %u in ACL -> removing entry!\n",
								       'B' + dev_desc_p[i].type,
								       dev_desc_p[i].major,
								       dev_desc_p[i].minor,
								       sub_desc_p[j].subj_id);
							rsbac_list_lol_subremove
							    (dev_handle,
							     &dev_desc_p
							     [i],
							     &sub_desc_p
							     [j]);
						} else /* complain */
							rsbac_pr_debug(ds, "dev_item %c%02u:%02u, has invalid group %u in ACL!\n",
								       'B' + dev_desc_p[i].type,
								       dev_desc_p[i].major,
								       dev_desc_p[i].minor,
								       sub_desc_p[j].subj_id);
					}
#if defined(CONFIG_RSBAC_RC)
					else if ((sub_desc_p[j].
						  subj_type == ACLS_ROLE)
						 && (sub_desc_p[j].
						     subj_id >
						     RC_role_max_value)
					    ) {
						if (correct) {
							/* remove sub item and complain */
							rsbac_pr_debug(ds, "dev_item %c%02u:%02u, has invalid role %u in ACL -> removing entry!\n",
								       'B' + dev_desc_p[i].type,
								       dev_desc_p[i].major,
								       dev_desc_p[i].minor,
								       sub_desc_p[j].subj_id);
							rsbac_list_lol_subremove
							    (dev_handle,
							     &dev_desc_p
							     [i],
							     &sub_desc_p
							     [j]);
						} else /* complain */
							rsbac_pr_debug(ds, "dev_item %c%02u:%02u, has invalid role %u in ACL!\n",
								       'B' + dev_desc_p[i].type,
								       dev_desc_p[i].major,
								       dev_desc_p[i].minor,
								       sub_desc_p[j].subj_id);
					}
#endif
				}
				rsbac_kfree(sub_desc_p);
			}
		}
		rsbac_kfree(dev_desc_p);
		f_sum += desc_count;
	}
	rsbac_printk(KERN_INFO "rsbac_check_acl(): %li device items\n",
		     desc_count);
	tmp_count = 0;
	desc_count =
	    rsbac_list_lol_get_all_desc(dev_major_handle,
					(void **) &dev_desc_p);
	if (desc_count > 0) {
		for (i = 0; i < desc_count; i++) {
			/* check for group existence of all ACL entries for groups */
			sub_desc_count =
			    rsbac_list_lol_get_all_subdesc
			    (dev_major_handle, &dev_desc_p[i],
			     (void **) &sub_desc_p);
			if (sub_desc_count > 0) {
				for (j = 0; j < sub_desc_count; j++) {
					if ((sub_desc_p[j].subj_type ==
					     ACLS_GROUP)
					    && sub_desc_p[j].subj_id
					    &&
					    !rsbac_list_exist(group_handle,
							      &sub_desc_p
							      [j].
							      subj_id)) {
						if (correct) {
							/* remove sub item and complain */
							rsbac_pr_debug(ds, "dev_item %c%02u:%02u, has invalid group %u in ACL -> removing entry!\n",
								       'B' + dev_desc_p[i].type,
								       dev_desc_p[i].major,
								       dev_desc_p[i].minor,
								       sub_desc_p[j].subj_id);
							rsbac_list_lol_subremove
							    (dev_major_handle,
							     &dev_desc_p
							     [i],
							     &sub_desc_p
							     [j]);
						} else /* complain */
							rsbac_pr_debug(ds, "dev_item %c%02u:%02u, has invalid group %u in ACL!\n",
								       'B' + dev_desc_p[i].type,
								       dev_desc_p[i].major,
								       dev_desc_p[i].minor,
								       sub_desc_p[j].subj_id);
					}
#if defined(CONFIG_RSBAC_RC)
					else if ((sub_desc_p[j].
						  subj_type == ACLS_ROLE)
						 && (sub_desc_p[j].
						     subj_id >
						     RC_role_max_value)
					    ) {
						if (correct) {
							/* remove sub item and complain */
							rsbac_pr_debug(ds, "dev_item %c%02u:%02u, has invalid role %u in ACL -> removing entry!\n",
								       'B' + dev_desc_p[i].type,
								       dev_desc_p[i].major,
								       dev_desc_p[i].minor,
								       sub_desc_p[j].subj_id);
							rsbac_list_lol_subremove
							    (dev_major_handle,
							     &dev_desc_p
							     [i],
							     &sub_desc_p
							     [j]);
						} else /* complain */
							rsbac_pr_debug(ds, "dev_item %c%02u:%02u, has invalid role %u in ACL!\n",
								       'B' + dev_desc_p[i].type,
								       dev_desc_p[i].major,
								       dev_desc_p[i].minor,
								       sub_desc_p[j].subj_id);
					}
#endif
				}
				rsbac_kfree(sub_desc_p);
			}
		}
		rsbac_kfree(dev_desc_p);
		f_sum += desc_count;
	}
	rsbac_printk(KERN_INFO "rsbac_check_acl(): %li device items\n",
		     desc_count);

	/* SCD list */
	tmp_count = 0;
	desc_count =
	    rsbac_list_lol_get_all_desc(scd_handle, (void **) &scd_desc_p);
	if (desc_count > 0) {
		for (i = 0; i < desc_count; i++) {
			/* check for group existence of all ACL entries for groups */
			sub_desc_count =
			    rsbac_list_lol_get_all_subdesc(scd_handle,
							   &scd_desc_p[i],
							   (void **)
							   &sub_desc_p);
			if (sub_desc_count > 0) {
				for (j = 0; j < sub_desc_count; j++) {
					if ((sub_desc_p[j].subj_type ==
					     ACLS_GROUP)
					    && sub_desc_p[j].subj_id
					    &&
					    !rsbac_list_exist(group_handle,
							      &sub_desc_p
							      [j].
							      subj_id)) {
						if (correct) {
							/* remove sub item and complain */
							rsbac_pr_debug(ds, "scd_item %u has invalid group %u in ACL -> removing entry!\n",
								       scd_desc_p[i],
								       sub_desc_p[j].subj_id);
							rsbac_list_lol_subremove
							    (scd_handle,
							     &scd_desc_p
							     [i],
							     &sub_desc_p
							     [j]);
						} else /* complain */
							rsbac_pr_debug(ds, "scd_item %u has invalid group %u in ACL!\n",
								       scd_desc_p[i],
								       sub_desc_p[j].subj_id);
					}
#if defined(CONFIG_RSBAC_RC)
					else if ((sub_desc_p[j].
						  subj_type == ACLS_ROLE)
						 && (sub_desc_p[j].
						     subj_id >
						     RC_role_max_value)
					    ) {
						if (correct) {
							/* remove sub item and complain */
							rsbac_pr_debug(ds, "scd_item %u has invalid role %u in ACL -> removing entry!\n",
								       scd_desc_p[i],
								       sub_desc_p[j].subj_id);
							rsbac_list_lol_subremove
							    (scd_handle,
							     &scd_desc_p
							     [i],
							     &sub_desc_p
							     [j]);
						} else /* complain */
							rsbac_pr_debug(ds, "scd_item %u has invalid role %u in ACL!\n",
								       scd_desc_p[i],
								       sub_desc_p[j].subj_id);
					}
#endif
				}
				rsbac_kfree(sub_desc_p);
			}
		}
		rsbac_kfree(scd_desc_p);
		f_sum += desc_count;
	}
	rsbac_printk(KERN_INFO "rsbac_check_acl(): %li SCD items\n",
		     desc_count);

	/* User list */
	tmp_count = 0;
	desc_count =
	    rsbac_list_lol_get_all_desc(u_handle, (void **) &u_desc_p);
	if (desc_count > 0) {
		for (i = 0; i < desc_count; i++) {
			/* check for group existence of all ACL entries for groups */
			sub_desc_count =
			    rsbac_list_lol_get_all_subdesc(u_handle,
							   &u_desc_p[i],
							   (void **)
							   &sub_desc_p);
			if (sub_desc_count > 0) {
				for (j = 0; j < sub_desc_count; j++) {
					if ((sub_desc_p[j].subj_type ==
					     ACLS_GROUP)
					    && sub_desc_p[j].subj_id
					    &&
					    !rsbac_list_exist(group_handle,
							      &sub_desc_p
							      [j].
							      subj_id)) {
						if (correct) {
							/* remove sub item and complain */
							rsbac_pr_debug(ds, "u_item %u has invalid group %u in ACL -> removing entry!\n",
								       u_desc_p[i],
								       sub_desc_p[j].subj_id);
							rsbac_list_lol_subremove
							    (u_handle,
							     &u_desc_p[i],
							     &sub_desc_p
							     [j]);
						} else /* complain */
							rsbac_pr_debug(ds, "u_item %u has invalid group %u in ACL!\n",
								       u_desc_p[i],
								       sub_desc_p[j].subj_id);
					}
#if defined(CONFIG_RSBAC_RC)
					else if ((sub_desc_p[j].
						  subj_type == ACLS_ROLE)
						 && (sub_desc_p[j].
						     subj_id >
						     RC_role_max_value)
					    ) {
						if (correct) {
							/* remove sub item and complain */
							rsbac_pr_debug(ds, "u_item %u has invalid role %u in ACL -> removing entry!\n",
								       u_desc_p[i],
								       sub_desc_p[j].subj_id);
							rsbac_list_lol_subremove
							    (u_handle,
							     &u_desc_p[i],
							     &sub_desc_p
							     [j]);
						} else /* complain */
							rsbac_pr_debug(ds, "u_item %u has invalid role %u in ACL!\n",
								       u_desc_p[i],
								       sub_desc_p[j].subj_id);
					}
#endif
				}
				rsbac_kfree(sub_desc_p);
			}
		}
		rsbac_kfree(u_desc_p);
		f_sum += desc_count;
	}
	rsbac_printk(KERN_INFO "rsbac_check_acl(): %li user items\n",
		     desc_count);

#ifdef CONFIG_RSBAC_ACL_UM_PROT
	/* User list */
	tmp_count = 0;
	desc_count =
	    rsbac_list_lol_get_all_desc(g_handle, (void **) &g_desc_p);
	if (desc_count > 0) {
		for (i = 0; i < desc_count; i++) {
			/* check for group existence of all ACL entries for groups */
			sub_desc_count =
			    rsbac_list_lol_get_all_subdesc(g_handle,
							   &g_desc_p[i],
							   (void **)
							   &sub_desc_p);
			if (sub_desc_count > 0) {
				for (j = 0; j < sub_desc_count; j++) {
					if ((sub_desc_p[j].subj_type ==
					     ACLS_GROUP)
					    && sub_desc_p[j].subj_id
					    &&
					    !rsbac_list_exist(group_handle,
							      &sub_desc_p
							      [j].
							      subj_id)) {
						if (correct) {
							/* remove sub item and complain */
							rsbac_pr_debug(ds, "g_item %u has invalid group %u in ACL -> removing entry!\n",
								       g_desc_p[i],
								       sub_desc_p[j].subj_id);
							rsbac_list_lol_subremove
							    (g_handle,
							     &g_desc_p[i],
							     &sub_desc_p
							     [j]);
						} else /* complain */
							rsbac_pr_debug(ds, "g_item %u has invalid group %u in ACL!\n",
								       g_desc_p[i],
								       sub_desc_p[j].subj_id);
					}
#if defined(CONFIG_RSBAC_RC)
					else if ((sub_desc_p[j].
						  subj_type == ACLS_ROLE)
						 && (sub_desc_p[j].
						     subj_id >
						     RC_role_max_value)
					    ) {
						if (correct) {
							/* remove sub item and complain */
							rsbac_pr_debug(ds, "g_item %u has invalid role %u in ACL -> removing entry!\n",
								       g_desc_p[i],
								       sub_desc_p[j].subj_id);
							rsbac_list_lol_subremove
							    (g_handle,
							     &g_desc_p[i],
							     &sub_desc_p
							     [j]);
						} else /* complain */
							rsbac_pr_debug(ds, "g_item %u has invalid role %u in ACL!\n",
								       g_desc_p[i],
								       sub_desc_p[j].subj_id);
					}
#endif
				}
				rsbac_kfree(sub_desc_p);
			}
		}
		rsbac_kfree(g_desc_p);
		f_sum += desc_count;
	}
	rsbac_printk(KERN_INFO "rsbac_check_acl(): %li Linux group items\n",
		     desc_count);
#endif

#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
	/* netdev list */
	tmp_count = 0;
	desc_count =
	    rsbac_list_lol_get_all_desc(netdev_handle,
					(void **) &netdev_desc_p);
	if (desc_count > 0) {
		for (i = 0; i < desc_count; i++) {
			/* check for group existence of all ACL entries for groups */
			sub_desc_count =
			    rsbac_list_lol_get_all_subdesc(netdev_handle,
							   &netdev_desc_p
							   [i],
							   (void **)
							   &sub_desc_p);
			if (sub_desc_count > 0) {
				for (j = 0; j < sub_desc_count; j++) {
					if ((sub_desc_p[j].subj_type ==
					     ACLS_GROUP)
					    && sub_desc_p[j].subj_id
					    &&
					    !rsbac_list_exist(group_handle,
							      &sub_desc_p
							      [j].
							      subj_id)) {
						if (correct) {
							/* remove sub item and complain */
							rsbac_pr_debug(ds, "netdev_item %s has invalid group %u in ACL -> removing entry!\n",
								       netdev_desc_p[i],
								       sub_desc_p[j].subj_id);
							rsbac_list_lol_subremove
							    (netdev_handle,
							     &netdev_desc_p
							     [i],
							     &sub_desc_p
							     [j]);
						} else /* complain */
							rsbac_pr_debug(ds, "netdev_item %s has invalid group %u in ACL!\n",
								       netdev_desc_p[i],
								       sub_desc_p[j].subj_id);
					}
#if defined(CONFIG_RSBAC_RC)
					else if ((sub_desc_p[j].
						  subj_type == ACLS_ROLE)
						 && (sub_desc_p[j].
						     subj_id >
						     RC_role_max_value)
					    ) {
						if (correct) {
							/* remove sub item and complain */
							rsbac_pr_debug(ds, "netdev_item %s has invalid role %u in ACL -> removing entry!\n",
								       netdev_desc_p[i],
								       sub_desc_p[j].subj_id);
							rsbac_list_lol_subremove
							    (netdev_handle,
							     &netdev_desc_p
							     [i],
							     &sub_desc_p
							     [j]);
						} else /* complain */
							rsbac_pr_debug(ds, "netdev_item %s has invalid role %u in ACL!\n",
								       netdev_desc_p[i],
								       sub_desc_p[j].subj_id);
					}
#endif
				}
				rsbac_kfree(sub_desc_p);
			}
		}
		rsbac_kfree(netdev_desc_p);
		f_sum += desc_count;
	}
	rsbac_printk(KERN_INFO "rsbac_check_acl(): %li network device items\n",
		     desc_count);
#endif				/* NET_DEV_PROT */

#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
	/* nettemp_nt list */
	tmp_count = 0;
	desc_count =
	    rsbac_list_lol_get_all_desc(nettemp_nt_handle,
					(void **) &nettemp_desc_p);
	if (desc_count > 0) {
		for (i = 0; i < desc_count; i++) {
			/* check for group existence of all ACL entries for groups */
			sub_desc_count =
			    rsbac_list_lol_get_all_subdesc
			    (nettemp_nt_handle, &nettemp_desc_p[i],
			     (void **) &sub_desc_p);
			if (sub_desc_count > 0) {
				for (j = 0; j < sub_desc_count; j++) {
					if ((sub_desc_p[j].subj_type ==
					     ACLS_GROUP)
					    && sub_desc_p[j].subj_id
					    &&
					    !rsbac_list_exist(group_handle,
							      &sub_desc_p
							      [j].
							      subj_id)) {
						if (correct) {
							/* remove sub item and complain */
							rsbac_pr_debug(ds, "nettemp_nt_item %u has invalid group %u in ACL -> removing entry!\n",
								       nettemp_desc_p[i],
								       sub_desc_p[j].subj_id);
							rsbac_list_lol_subremove
							    (nettemp_nt_handle,
							     &nettemp_desc_p
							     [i],
							     &sub_desc_p
							     [j]);
						} else /* complain */
							rsbac_pr_debug(ds, "nettemp_nt_item %u has invalid group %u in ACL!\n",
								       nettemp_desc_p[i],
								       sub_desc_p[j].subj_id);
					}
#if defined(CONFIG_RSBAC_RC)
					else if ((sub_desc_p[j].
						  subj_type == ACLS_ROLE)
						 && (sub_desc_p[j].
						     subj_id >
						     RC_role_max_value)
					    ) {
						if (correct) {
							/* remove sub item and complain */
							rsbac_pr_debug(ds, "nettemp_nt_item %u has invalid role %u in ACL -> removing entry!\n",
								       nettemp_desc_p[i],
								       sub_desc_p[j].subj_id);
							rsbac_list_lol_subremove
							    (nettemp_nt_handle,
							     &nettemp_desc_p
							     [i],
							     &sub_desc_p
							     [j]);
						} else /* complain */
							rsbac_pr_debug(ds, "nettemp_nt_item %u has invalid role %u in ACL!\n",
								       nettemp_desc_p[i],
								       sub_desc_p[j].subj_id);
					}
#endif
				}
				rsbac_kfree(sub_desc_p);
			}
		}
		rsbac_kfree(nettemp_desc_p);
		f_sum += desc_count;
	}
	rsbac_printk(KERN_INFO "rsbac_check_acl(): %li network template NT items\n",
		     desc_count);

	/* nettemp list */
	tmp_count = 0;
	desc_count =
	    rsbac_list_lol_get_all_desc(nettemp_handle,
					(void **) &nettemp_desc_p);
	if (desc_count > 0) {
		for (i = 0; i < desc_count; i++) {
			/* check for group existence of all ACL entries for groups */
			sub_desc_count =
			    rsbac_list_lol_get_all_subdesc(nettemp_handle,
							   &nettemp_desc_p
							   [i],
							   (void **)
							   &sub_desc_p);
			if (sub_desc_count > 0) {
				for (j = 0; j < sub_desc_count; j++) {
					if ((sub_desc_p[j].subj_type ==
					     ACLS_GROUP)
					    && sub_desc_p[j].subj_id
					    &&
					    !rsbac_list_exist(group_handle,
							      &sub_desc_p
							      [j].
							      subj_id)) {
						if (correct) {
							/* remove sub item and complain */
							rsbac_pr_debug(ds, "nettemp_item %u has invalid group %u in ACL -> removing entry!\n",
								       nettemp_desc_p[i],
								       sub_desc_p[j].subj_id);
							rsbac_list_lol_subremove
							    (nettemp_handle,
							     &nettemp_desc_p
							     [i],
							     &sub_desc_p
							     [j]);
						} else /* complain */
							rsbac_pr_debug(ds, "nettemp_item %u has invalid group %u in ACL!\n",
								       nettemp_desc_p[i],
								       sub_desc_p[j].subj_id);
					}
#if defined(CONFIG_RSBAC_RC)
					else if ((sub_desc_p[j].
						  subj_type == ACLS_ROLE)
						 && (sub_desc_p[j].
						     subj_id >
						     RC_role_max_value)
					    ) {
						if (correct) {
							/* remove sub item and complain */
							rsbac_pr_debug(ds, "nettemp_item %u has invalid role %u in ACL -> removing entry!\n",
								       nettemp_desc_p[i],
								       sub_desc_p[j].subj_id);
							rsbac_list_lol_subremove
							    (nettemp_handle,
							     &nettemp_desc_p
							     [i],
							     &sub_desc_p
							     [j]);
						} else /* complain */
							rsbac_pr_debug(ds, "nettemp_item %u has invalid role %u in ACL!\n",
								       nettemp_desc_p[i],
								       sub_desc_p[j].subj_id);
					}
#endif
				}
				rsbac_kfree(sub_desc_p);
			}
		}
		rsbac_kfree(nettemp_desc_p);
		f_sum += desc_count;
	}
	rsbac_printk(KERN_INFO "rsbac_check_acl(): %li network template items\n",
		     desc_count);

	/* netobj list */
	tmp_count = 0;
	desc_count =
	    rsbac_list_lol_get_all_desc(netobj_handle,
					(void **) &netobj_desc_p);
	if (desc_count > 0) {
		for (i = 0; i < desc_count; i++) {
			/* check for group existence of all ACL entries for groups */
			sub_desc_count =
			    rsbac_list_lol_get_all_subdesc(netobj_handle,
							   &netobj_desc_p
							   [i],
							   (void **)
							   &sub_desc_p);
			if (sub_desc_count > 0) {
				for (j = 0; j < sub_desc_count; j++) {
					if ((sub_desc_p[j].subj_type ==
					     ACLS_GROUP)
					    && sub_desc_p[j].subj_id
					    &&
					    !rsbac_list_exist(group_handle,
							      &sub_desc_p
							      [j].
							      subj_id)) {
						if (correct) {
							/* remove sub item and complain */
							rsbac_pr_debug(ds, "netobj_item %p has invalid group %u in ACL -> removing entry!\n",
								       netobj_desc_p[i],
								       sub_desc_p[j].subj_id);
							rsbac_list_lol_subremove
							    (netobj_handle,
							     &netobj_desc_p
							     [i],
							     &sub_desc_p
							     [j]);
						} else /* complain */
							rsbac_pr_debug(ds, "netobj_item %p has invalid group %u in ACL!\n",
								       netobj_desc_p[i],
								       sub_desc_p[j].subj_id);
					}
#if defined(CONFIG_RSBAC_RC)
					else if ((sub_desc_p[j].
						  subj_type == ACLS_ROLE)
						 && (sub_desc_p[j].
						     subj_id >
						     RC_role_max_value)
					    ) {
						if (correct) {
							/* remove sub item and complain */
							rsbac_pr_debug(ds, "netobj_item %p has invalid role %u in ACL -> removing entry!\n",
								       netobj_desc_p[i],
								       sub_desc_p[j].subj_id);
							rsbac_list_lol_subremove
							    (netobj_handle,
							     &netobj_desc_p
							     [i],
							     &sub_desc_p
							     [j]);
						} else /* complain */
							rsbac_pr_debug(ds, "netobj_item %p has invalid role %u in ACL!\n",
								       netobj_desc_p[i],
								       sub_desc_p[j].subj_id);
					}
#endif
				}
				rsbac_kfree(sub_desc_p);
			}
		}
		rsbac_kfree(netobj_desc_p);
		f_sum += desc_count;
	}
	rsbac_printk(KERN_INFO "rsbac_check_acl(): %li network object items\n",
		     desc_count);
#endif				/* NET_OBJ_PROT */

	rsbac_printk(KERN_INFO "rsbac_check_acl(): Total of %lu registered ACLs\n",
		     f_sum);

	return 0;
}

/************************************************* */
/*               Access functions                  */
/************************************************* */

/* All these procedures handle the spinlocks to protect the targets during */
/* access.                                                                 */

/* rsbac_acl_set_acl_entry
 * Set ACL entry for given target and subject to given rights. If entry does
 * not exist, it is created, thus cutting the inheritance from default/parent.
 */

int rsbac_acl_set_acl_entry(rsbac_list_ta_number_t ta_number,
			    enum rsbac_target_t target,
			    union rsbac_target_id_t tid,
			    enum rsbac_acl_subject_type_t subj_type,
			    rsbac_acl_subject_id_t subj_id,
			    rsbac_acl_rights_vector_t rights,
			    rsbac_time_t ttl)
{
	int err = 0;
	struct rsbac_acl_device_list_item_t *device_p;
	struct rsbac_acl_entry_desc_t desc;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_acl_set_acl_entry(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (subj_type >= ACLS_NONE)
		return -RSBAC_EINVALIDVALUE;
#ifdef CONFIG_RSBAC_DEBUG
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_acl_set_acl_entry(): called from interrupt!\n");
	}
#endif
	desc.subj_type = subj_type;
	desc.subj_id = subj_id;

	switch (target) {
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_UNIXSOCK:
		rsbac_pr_debug(ds_acl, "Setting file/dir/fifo/symlink ACL for device %02u:%02u, inode %u\n",
			       RSBAC_MAJOR(tid.file.device),
			       RSBAC_MINOR(tid.file.device), tid.file.inode);
		/* default entry? */
		if (RSBAC_IS_ZERO_DEV(tid.file.device) && !tid.file.inode
		    && !tid.file.dentry_p)
			return rsbac_ta_list_add_ttl(ta_number,
						     default_fd_handle,
						     ttl, &desc, &rights);
		srcu_idx = srcu_read_lock(&device_list_srcu);
		/* lookup device */
		device_p = acl_lookup_device(tid.file.device);
		if (!device_p) {
			rsbac_printk(KERN_WARNING "rsbac_acl_set_acl_entry(): Could not lookup device!\n");
			/* free read lock */
			srcu_read_unlock(&device_list_srcu, srcu_idx);
			return -RSBAC_EINVALIDDEV;
		}
		if (!rsbac_ta_list_lol_exist
		    (ta_number, device_p->handle,
		     &tid.file.inode)) {
			rsbac_acl_rights_vector_t mask =
			    RSBAC_ACL_DEFAULT_FD_MASK;

			err = rsbac_ta_list_lol_add_ttl(ta_number,
							device_p->handle,
							0, &tid.file.inode,
							&mask);
			if (err) {
				srcu_read_unlock(&device_list_srcu, srcu_idx);
				return err;
			}
		}
		err =
		    rsbac_ta_list_lol_subadd_ttl(ta_number,
						 device_p->handle, ttl,
						 &tid.file.inode, &desc,
						 &rights);
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		/* ready. */
		return err;

	case T_DEV:
		rsbac_pr_debug(ds_acl, "Setting device ACL for dev %c %02u:%02u\n",
			       'B' + tid.dev.type, tid.dev.major,
			       tid.dev.minor);
		/* default entry? */
		if (RSBAC_IS_ZERO_DEV_DESC(tid.dev))
			return rsbac_ta_list_add_ttl(ta_number,
						     default_dev_handle,
						     ttl, &desc, &rights);

		{
			switch (tid.dev.type) {
			case D_char:
			case D_block:
				if (!rsbac_ta_list_lol_exist
				    (ta_number, dev_handle, &tid.dev)) {
					rsbac_acl_rights_vector_t mask =
					    RSBAC_ACL_DEFAULT_DEV_MASK;

					err =
					    rsbac_ta_list_lol_add_ttl
					    (ta_number, dev_handle, 0,
					     &tid.dev, &mask);
					if (err)
						return err;
				}
				return
				    rsbac_ta_list_lol_subadd_ttl(ta_number,
								 dev_handle,
								 ttl,
								 &tid.dev,
								 &desc,
								 &rights);

			case D_char_major:
			case D_block_major:
				tid.dev.type -= (D_block_major - D_block);
				if (!rsbac_ta_list_lol_exist
				    (ta_number, dev_major_handle,
				     &tid.dev)) {
					rsbac_acl_rights_vector_t mask =
					    RSBAC_ACL_DEFAULT_DEV_MASK;

					err =
					    rsbac_ta_list_lol_add_ttl
					    (ta_number, dev_major_handle,
					     0, &tid.dev, &mask);
					if (err)
						return err;
				}
				return
				    rsbac_ta_list_lol_subadd_ttl(ta_number,
								 dev_major_handle,
								 ttl,
								 &tid.dev,
								 &desc,
								 &rights);

			default:
				return -RSBAC_EINVALIDTARGET;
			}
		}

	case T_IPC:
		/* default entry? */
		if (tid.ipc.type == I_none)
			return rsbac_ta_list_add_ttl(ta_number,
						     default_ipc_handle,
						     ttl, &desc, &rights);
		else
			return -RSBAC_EINVALIDTARGET;

	case T_SCD:
		/* default entry? */
		if (tid.scd == AST_none)
			return rsbac_ta_list_add_ttl(ta_number,
						     default_scd_handle,
						     ttl, &desc, &rights);

		if (!rsbac_ta_list_lol_exist
		    (ta_number, scd_handle, &tid.scd)) {
			rsbac_acl_rights_vector_t mask =
			    RSBAC_ACL_DEFAULT_SCD_MASK;

			err = rsbac_ta_list_lol_add_ttl(ta_number,
							scd_handle,
							0,
							&tid.scd, &mask);
			if (err)
				return err;
		}
		return rsbac_ta_list_lol_subadd_ttl(ta_number, scd_handle,
						    ttl, &tid.scd, &desc,
						    &rights);

	case T_USER:
		/* default entry? */
		if (tid.user == RSBAC_NO_USER)
			return rsbac_ta_list_add_ttl(ta_number,
						     default_u_handle, ttl,
						     &desc, &rights);
		if (!rsbac_ta_list_lol_exist
		    (ta_number, u_handle, &tid.user)) {
			rsbac_acl_rights_vector_t mask =
			    RSBAC_ACL_DEFAULT_U_MASK;

			err = rsbac_ta_list_lol_add_ttl(ta_number,
							u_handle,
							0,
							&tid.user, &mask);
			if (err)
				return err;
		}
		return rsbac_ta_list_lol_subadd_ttl(ta_number, u_handle,
						    ttl, &tid.user, &desc,
						    &rights);


	case T_PROCESS:
		/* default entry? */
		if (!tid.process)
			return rsbac_ta_list_add_ttl(ta_number,
						     default_p_handle, ttl,
						     &desc, &rights);
		else
			return -RSBAC_EINVALIDTARGET;

#ifdef CONFIG_RSBAC_ACL_UM_PROT
	case T_GROUP:
		/* default entry? */
		if (tid.group == RSBAC_NO_GROUP)
			return rsbac_ta_list_add_ttl(ta_number,
						     default_g_handle, ttl,
						     &desc, &rights);
		if (!rsbac_ta_list_lol_exist
		    (ta_number, g_handle, &tid.group)) {
			rsbac_acl_rights_vector_t mask =
			    RSBAC_ACL_DEFAULT_G_MASK;

			err = rsbac_ta_list_lol_add_ttl(ta_number,
							g_handle,
							0,
							&tid.group, &mask);
			if (err)
				return err;
		}
		return rsbac_ta_list_lol_subadd_ttl(ta_number, g_handle,
						    ttl, &tid.group, &desc,
						    &rights);
#endif

#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
	case T_NETDEV:
		rsbac_pr_debug(ds_acl, "Setting network device ACL for netdev %s\n",
			       tid.netdev);
		/* default entry? */
		if (!tid.netdev[0])
			return rsbac_ta_list_add_ttl(ta_number,
						     default_netdev_handle,
						     ttl, &desc, &rights);

		if (!rsbac_ta_list_lol_exist
		    (ta_number, netdev_handle, &tid.netdev)) {
			rsbac_acl_rights_vector_t mask =
			    RSBAC_ACL_DEFAULT_NETDEV_MASK;

			err = rsbac_ta_list_lol_add_ttl(ta_number,
							netdev_handle,
							0,
							&tid.netdev,
							&mask);
			if (err)
				return err;
		}
		return rsbac_ta_list_lol_subadd_ttl(ta_number,
						    netdev_handle, ttl,
						    &tid.netdev, &desc,
						    &rights);
#endif

#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
	case T_NETTEMP_NT:
		rsbac_pr_debug(ds_acl, "Setting network template NT ACL for "
			       "nettemp_nt %u\n", tid.nettemp);
		/* default entry? */
		if (!tid.nettemp)
			return rsbac_ta_list_add_ttl(ta_number,
						     default_nettemp_nt_handle,
						     ttl, &desc, &rights);

		if (!rsbac_ta_list_lol_exist
		    (ta_number, nettemp_nt_handle, &tid.nettemp)) {
			rsbac_acl_rights_vector_t mask =
			    RSBAC_ACL_DEFAULT_NETTEMP_MASK;

			err = rsbac_ta_list_lol_add_ttl(ta_number,
							nettemp_nt_handle,
							0,
							&tid.nettemp,
							&mask);
			if (err)
				return err;
		}
		return rsbac_ta_list_lol_subadd_ttl(ta_number,
						    nettemp_nt_handle, ttl,
						    &tid.nettemp, &desc,
						    &rights);

	case T_NETTEMP:
		rsbac_pr_debug(ds_acl, "Setting network template ACL for nettemp %u\n",
			       tid.nettemp);
		/* default entry? */
		if (!tid.nettemp)
			return -RSBAC_EINVALIDTARGET;
		if (!rsbac_ta_net_template_exist(ta_number, tid.nettemp))
			return -RSBAC_EINVALIDTARGET;

		if (!rsbac_ta_list_lol_exist
		    (ta_number, nettemp_handle, &tid.nettemp)) {
			rsbac_acl_rights_vector_t mask =
			    RSBAC_ACL_DEFAULT_NETOBJ_MASK;

			err = rsbac_ta_list_lol_add_ttl(ta_number,
							nettemp_handle,
							0,
							&tid.nettemp,
							&mask);
			if (err)
				return err;
		}
		return rsbac_ta_list_lol_subadd_ttl(ta_number,
						    nettemp_handle, ttl,
						    &tid.nettemp, &desc,
						    &rights);

	case T_NETOBJ:
		rsbac_pr_debug(ds_acl, "Setting network object ACL for netobj %p\n",
			       tid.netobj.sock_p);
		/* default entry? */
		if (!tid.netobj.sock_p)
			return rsbac_ta_list_add_ttl(ta_number,
						     default_netobj_handle,
						     ttl, &desc, &rights);

		if (!rsbac_ta_list_lol_exist
		    (ta_number, netobj_handle, &tid.netobj.sock_p)) {
			rsbac_acl_rights_vector_t mask =
			    RSBAC_ACL_DEFAULT_NETOBJ_MASK;

			err = rsbac_ta_list_lol_add_ttl(ta_number,
							netobj_handle,
							0,
							&tid.netobj.sock_p,
							&mask);
			if (err)
				return err;
		}
		return rsbac_ta_list_lol_subadd_ttl(ta_number,
						    netobj_handle, ttl,
						    &tid.netobj.sock_p,
						    &desc, &rights);
#endif				/* NET_OBJ_PROT */


	default:
		err = -RSBAC_EINVALIDTARGET;
	}
	return err;
}

/* rsbac_acl_remove_acl_entry
 * Remove ACL entry for given target and subject. This reactivates the
 * inheritance from default/parent.
 */

int rsbac_acl_remove_acl_entry(rsbac_list_ta_number_t ta_number,
			       enum rsbac_target_t target,
			       union rsbac_target_id_t tid,
			       enum rsbac_acl_subject_type_t subj_type,
			       rsbac_acl_subject_id_t subj_id)
{
	int err = 0;
	struct rsbac_acl_device_list_item_t *device_p;
	struct rsbac_acl_entry_desc_t desc;
	char tmp[RSBAC_MAXNAMELEN];
	rsbac_acl_rights_vector_t mask;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_acl_remove_acl_entry(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (subj_type >= ACLS_NONE)
		return -RSBAC_EINVALIDVALUE;
#ifdef CONFIG_RSBAC_DEBUG
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_acl_remove_acl_entry(): called from interrupt!\n");
	}
#endif
	desc.subj_type = subj_type;
	desc.subj_id = subj_id;

	switch (target) {
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_UNIXSOCK:
		rsbac_pr_debug(ds_acl, "Removing file/dir/fifo/symlink ACL entry %s %u for device %02u:%02u, inode %u\n",
			       get_acl_subject_type_name(tmp, desc.subj_type),
			       desc.subj_id,
			       RSBAC_MAJOR(tid.file.device),
			       RSBAC_MINOR(tid.file.device), tid.file.inode);
		/* default entry? */
		if (RSBAC_IS_ZERO_DEV(tid.file.device) && !tid.file.inode
		    && !tid.file.dentry_p)
			return rsbac_ta_list_remove(ta_number,
						    default_fd_handle,
						    &desc);

		srcu_idx = srcu_read_lock(&device_list_srcu);
		/* lookup device */
		device_p = acl_lookup_device(tid.file.device);
		if (!device_p) {
			rsbac_printk(KERN_WARNING "rsbac_acl_remove_acl_entry(): Could not lookup device!\n");
			srcu_read_unlock(&device_list_srcu, srcu_idx);
			return -RSBAC_EINVALIDDEV;
		}
		err = rsbac_ta_list_lol_subremove(ta_number,
						device_p->handle,
						&tid.file.inode, &desc);
		/* if ACL is empty, remove it */
		if (!err
		    && !rsbac_ta_list_lol_subcount(ta_number,
						   device_p->handle,
						   &tid.file.inode)
		    && !rsbac_ta_list_lol_get_data_ttl(ta_number,
						       device_p->handle,
						       NULL,
						       &tid.file.inode,
						       &mask)
		    && (mask == RSBAC_ACL_DEFAULT_FD_MASK)
		    ) {
			err = rsbac_ta_list_lol_remove(ta_number,
						     device_p->handle,
						     &tid.file.inode);
		}
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		return err;

	case T_DEV:
		rsbac_pr_debug(ds_acl, "Removing device ACL entry for dev %c %02u:%02u\n",
			       'B' + tid.dev.type, tid.dev.major,
			       tid.dev.minor);
		/* default entry? */
		if (RSBAC_IS_ZERO_DEV_DESC(tid.dev))
			return rsbac_ta_list_remove(ta_number,
						    default_dev_handle,
						    &desc);

		{
			switch (tid.dev.type) {
			case D_char:
			case D_block:
				err =
				    rsbac_ta_list_lol_subremove(ta_number,
								dev_handle,
								&tid.dev,
								&desc);
				/* if ACL is empty, remove it */
				if (!err
				    &&
				    !rsbac_ta_list_lol_subcount(ta_number,
								dev_handle,
								&tid.dev)
				    &&
				    !rsbac_ta_list_lol_get_data_ttl
				    (ta_number, dev_handle, NULL, &tid.dev,
				     &mask)
				    && (mask == RSBAC_ACL_DEFAULT_DEV_MASK)
				    ) {
					err =
					    rsbac_ta_list_lol_remove
					    (ta_number, dev_handle,
					     &tid.dev);
				}
				return err;

			case D_char_major:
			case D_block_major:
				tid.dev.type -= (D_block_major - D_block);
				err =
				    rsbac_ta_list_lol_subremove(ta_number,
								dev_major_handle,
								&tid.dev,
								&desc);
				/* if ACL is empty, remove it */
				if (!err
				    &&
				    !rsbac_ta_list_lol_subcount(ta_number,
								dev_major_handle,
								&tid.dev)
				    &&
				    !rsbac_ta_list_lol_get_data_ttl
				    (ta_number, dev_major_handle, NULL,
				     &tid.dev, &mask)
				    && (mask == RSBAC_ACL_DEFAULT_DEV_MASK)
				    ) {
					err =
					    rsbac_ta_list_lol_remove
					    (ta_number, dev_major_handle,
					     &tid.dev);
				}
				return err;

			default:
				return -RSBAC_EINVALIDTARGET;
			}
		}

	case T_IPC:
		rsbac_pr_debug(ds_acl, "Removing IPC ACL for type %u\n", tid.ipc.type);
		/* default entry? */
		if (tid.ipc.type == I_none)
			return rsbac_ta_list_remove(ta_number,
						    default_ipc_handle,
						    &desc);
		else
			return -RSBAC_EINVALIDTARGET;

	case T_SCD:
		rsbac_pr_debug(ds_acl, "Removing SCD ACL entry for %s\n",
			       get_acl_scd_type_name(tmp, tid.scd));
		/* default entry? */
		if (tid.scd == AST_none)
			return rsbac_ta_list_remove(ta_number,
						    default_scd_handle,
						    &desc);
		err =
		    rsbac_ta_list_lol_subremove(ta_number, scd_handle,
						&tid.scd, &desc);
		/* if ACL is empty, remove it */
		if (!err
		    && !rsbac_ta_list_lol_subcount(ta_number, scd_handle,
						   &tid.scd)
		    && !rsbac_ta_list_lol_get_data_ttl(ta_number,
						       scd_handle, NULL,
						       &tid.scd, &mask)
		    && (mask == RSBAC_ACL_DEFAULT_SCD_MASK)
		    ) {
			err =
			    rsbac_ta_list_lol_remove(ta_number, scd_handle,
						     &tid.scd);
		}
		return err;

	case T_USER:
		rsbac_pr_debug(ds_acl, "Removing user ACL for user %u\n",
			       tid.user);
		/* default entry? */
		if (tid.user == RSBAC_NO_USER)
			return rsbac_ta_list_remove(ta_number,
						    default_u_handle,
						    &desc);
		err =
		    rsbac_ta_list_lol_subremove(ta_number, u_handle,
						&tid.user, &desc);
		/* if ACL is empty, remove it */
		if (!err
		    && !rsbac_ta_list_lol_subcount(ta_number, u_handle,
						   &tid.user)
		    && !rsbac_ta_list_lol_get_data_ttl(ta_number, u_handle,
						       NULL, &tid.user,
						       &mask)
		    && (mask == RSBAC_ACL_DEFAULT_U_MASK)
		    ) {
			err =
			    rsbac_ta_list_lol_remove(ta_number, u_handle,
						     &tid.user);
		}
		return err;

	case T_PROCESS:
		rsbac_pr_debug(ds_acl, "Removing process ACL for pid %u\n",
			       tid.process);
		/* default entry? */
		if (!tid.process)
			return rsbac_ta_list_remove(ta_number,
						    default_p_handle,
						    &desc);
		else
			return -RSBAC_EINVALIDTARGET;

#ifdef CONFIG_RSBAC_ACL_UM_PROT
	case T_GROUP:
		rsbac_pr_debug(ds_acl, "Removing Linux group ACL for group %u\n",
			       tid.group);
		/* default entry? */
		if (tid.group == RSBAC_NO_GROUP)
			return rsbac_ta_list_remove(ta_number,
						    default_g_handle,
						    &desc);
		err =
		    rsbac_ta_list_lol_subremove(ta_number, g_handle,
						&tid.group, &desc);
		/* if ACL is empty, remove it */
		if (!err
		    && !rsbac_ta_list_lol_subcount(ta_number, g_handle,
						   &tid.group)
		    && !rsbac_ta_list_lol_get_data_ttl(ta_number, g_handle,
						       NULL, &tid.group,
						       &mask)
		    && (mask == RSBAC_ACL_DEFAULT_G_MASK)
		    ) {
			err =
			    rsbac_ta_list_lol_remove(ta_number, g_handle,
						     &tid.group);
		}
		return err;
#endif

#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
	case T_NETDEV:
		rsbac_pr_debug(ds_acl, "Removing network device ACL entry for netdev %s\n",
			       tid.netdev);
		/* default entry? */
		if (!tid.netdev[0])
			return rsbac_ta_list_remove(ta_number,
						    default_netdev_handle,
						    &desc);

		err =
		    rsbac_ta_list_lol_subremove(ta_number, netdev_handle,
						&tid.netdev, &desc);
		/* if ACL is empty, remove it */
		if (!err
		    && !rsbac_ta_list_lol_subcount(ta_number,
						   netdev_handle,
						   &tid.netdev)
		    && !rsbac_ta_list_lol_get_data_ttl(ta_number,
						       netdev_handle, NULL,
						       &tid.netdev, &mask)
		    && (mask == RSBAC_ACL_DEFAULT_NETDEV_MASK)
		    ) {
			err =
			    rsbac_ta_list_lol_remove(ta_number,
						     netdev_handle,
						     &tid.netdev);
		}
		return err;
#endif

#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
	case T_NETTEMP_NT:
		rsbac_pr_debug(ds_acl, "Removing network template NT ACL entry for "
			       "nettemp_nt %u\n", tid.nettemp);
		/* default entry? */
		if (!tid.nettemp)
			return rsbac_ta_list_remove(ta_number,
						    default_nettemp_nt_handle,
						    &desc);
		if (!rsbac_ta_net_template_exist(ta_number, tid.nettemp))
			return -RSBAC_EINVALIDTARGET;

		err =
		    rsbac_ta_list_lol_subremove(ta_number,
						nettemp_nt_handle,
						&tid.nettemp, &desc);
		/* if ACL is empty, remove it */
		if (!err
		    && !rsbac_ta_list_lol_subcount(ta_number,
						   nettemp_nt_handle,
						   &tid.nettemp)
		    && !rsbac_ta_list_lol_get_data_ttl(ta_number,
						       nettemp_nt_handle,
						       NULL, &tid.nettemp,
						       &mask)
		    && (mask == RSBAC_ACL_DEFAULT_NETTEMP_MASK)
		    ) {
			err =
			    rsbac_ta_list_lol_remove(ta_number,
						     nettemp_nt_handle,
						     &tid.nettemp);
		}
		return err;

	case T_NETTEMP:
		rsbac_pr_debug(ds_acl, "Removing network template ACL entry for nettemp_nt %u\n",
			       tid.nettemp);
		/* default entry? */
		if (!tid.nettemp)
			return -RSBAC_EINVALIDTARGET;
		if (!rsbac_ta_net_template_exist(ta_number, tid.nettemp))
			return -RSBAC_EINVALIDTARGET;

		err =
		    rsbac_ta_list_lol_subremove(ta_number, nettemp_handle,
						&tid.nettemp, &desc);
		/* if ACL is empty, remove it */
		if (!err
		    && !rsbac_ta_list_lol_subcount(ta_number,
						   nettemp_handle,
						   &tid.nettemp)
		    && !rsbac_ta_list_lol_get_data_ttl(ta_number,
						       nettemp_handle,
						       NULL, &tid.nettemp,
						       &mask)
		    && (mask == RSBAC_ACL_DEFAULT_NETOBJ_MASK)
		    ) {
			err =
			    rsbac_ta_list_lol_remove(ta_number,
						     nettemp_handle,
						     &tid.nettemp);
		}
		return err;

	case T_NETOBJ:
		rsbac_pr_debug(ds_acl, "Removing network object ACL entry for netobj %p\n",
			       tid.netobj.sock_p);
		/* default entry? */
		if (!tid.netobj.sock_p)
			return rsbac_ta_list_remove(ta_number,
						    default_netobj_handle,
						    &desc);

		err =
		    rsbac_ta_list_lol_subremove(ta_number, netobj_handle,
						&tid.netobj.sock_p, &desc);
		/* if ACL is empty, remove it */
		if (!err
		    && !rsbac_ta_list_lol_subcount(ta_number,
						   netobj_handle,
						   &tid.netobj.sock_p)
		    && !rsbac_ta_list_lol_get_data_ttl(ta_number,
						       netobj_handle, NULL,
						       &tid.netobj, &mask)
		    && (mask == RSBAC_ACL_DEFAULT_NETOBJ_MASK)
		    ) {
			err =
			    rsbac_ta_list_lol_remove(ta_number,
						     netobj_handle,
						     &tid.netobj.sock_p);
		}
		return err;
#endif				/* NET_OBJ_PROT */

	default:
		return -RSBAC_EINVALIDTARGET;
	}
}

/* rsbac_acl_remove_acl
 * Remove ACL for given target. For cleanup on delete.
 */

int rsbac_acl_remove_acl(rsbac_list_ta_number_t ta_number,
			 enum rsbac_target_t target,
			 union rsbac_target_id_t tid)
{
	int err = 0;
	char tmp[RSBAC_MAXNAMELEN];
	struct rsbac_acl_device_list_item_t *device_p;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_acl_remove_acl(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
#ifdef CONFIG_RSBAC_DEBUG
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_acl_remove_acl(): called from interrupt!\n");
	}
#endif
	switch (target) {
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_UNIXSOCK:
		rsbac_pr_debug(ds_acl, "Removing file/dir/fifo/symlink ACL for device %02u:%02u, inode %u\n",
			       RSBAC_MAJOR(tid.file.device),
			       RSBAC_MINOR(tid.file.device), tid.file.inode);
		/* default entry? */
		if (RSBAC_IS_ZERO_DEV(tid.file.device) && !tid.file.inode
		    && !tid.file.dentry_p)
			return -RSBAC_EINVALIDTARGET;

		srcu_idx = srcu_read_lock(&device_list_srcu);
		/* lookup device */
		device_p = acl_lookup_device(tid.file.device);
		if (!device_p) {
			rsbac_printk(KERN_WARNING "rsbac_acl_remove_acl(): Could not lookup device!\n");
			srcu_read_unlock(&device_list_srcu, srcu_idx);
			return -RSBAC_EINVALIDDEV;
		}
		err = rsbac_ta_list_lol_remove(ta_number,
					     device_p->handle,
					     &tid.file.inode);
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		return err;

	case T_DEV:
		rsbac_pr_debug(ds_acl, "Removing device ACL for dev %c %02u:%02u\n",
			       'B' + tid.dev.type, tid.dev.major,
			       tid.dev.minor);
		/* default entry? */
		if (RSBAC_IS_ZERO_DEV_DESC(tid.dev))
			return -RSBAC_EINVALIDTARGET;
		switch (tid.dev.type) {
		case D_char:
		case D_block:
			return rsbac_ta_list_lol_remove(ta_number,
							dev_handle,
							&tid.dev);

		case D_char_major:
		case D_block_major:
			tid.dev.type -= (D_block_major - D_block);
			return rsbac_ta_list_lol_remove(ta_number,
							dev_major_handle,
							&tid.dev);

		default:
			return -RSBAC_EINVALIDTARGET;
		}

	case T_SCD:
		rsbac_pr_debug(ds_acl, "Removing SCD ACL for %s\n",
			       get_acl_scd_type_name(tmp, tid.scd));
		/* default entry? */
		if (tid.scd == AST_none)
			return -RSBAC_EINVALIDTARGET;
		else
			return rsbac_ta_list_lol_remove(ta_number,
							scd_handle,
							&tid.scd);

	case T_USER:
		rsbac_pr_debug(ds_acl, "Removing user ACL for user %u\n",
			       tid.user);
		/* default entry? */
		if (tid.user == RSBAC_NO_USER)
			return -RSBAC_EINVALIDTARGET;
		else
			return rsbac_ta_list_lol_remove(ta_number,
							u_handle,
							&tid.user);

#ifdef CONFIG_RSBAC_ACL_UM_PROT
	case T_GROUP:
		rsbac_pr_debug(ds_acl, "Removing Linux group ACL for group %u\n",
			       tid.group);
		/* default entry? */
		if (tid.group == RSBAC_NO_GROUP)
			return -RSBAC_EINVALIDTARGET;
		else
			return rsbac_ta_list_lol_remove(ta_number,
							g_handle,
							&tid.group);
#endif

#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
	case T_NETDEV:
		rsbac_pr_debug(ds_acl, "Removing network device ACL for netdev %s\n",
			       tid.netdev);
		/* default entry? */
		if (!tid.netdev[0])
			return -RSBAC_EINVALIDTARGET;
		else
			return rsbac_ta_list_lol_remove(ta_number,
							netdev_handle,
							&tid.netdev);
#endif

#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
	case T_NETTEMP_NT:
		rsbac_pr_debug(ds_acl, "Removing network template NT ACL for nettemp_nt %u\n",
			       tid.nettemp);
		/* default entry? */
		if (!tid.nettemp)
			return -RSBAC_EINVALIDTARGET;
		else
			return rsbac_ta_list_lol_remove(ta_number,
							nettemp_nt_handle,
							&tid.nettemp);
	case T_NETTEMP:
		rsbac_pr_debug(ds_acl, "Removing network template ACL for nettemp %u\n",
			       tid.nettemp);
		/* default entry? */
		if (!tid.nettemp)
			return -RSBAC_EINVALIDTARGET;
		else
			return rsbac_ta_list_lol_remove(ta_number,
							nettemp_handle,
							&tid.nettemp);
	case T_NETOBJ:
		rsbac_pr_debug(ds_acl, "Removing network object ACL for netobj %p\n",
			       tid.netobj.sock_p);
		/* default entry? */
		if (!tid.netobj.sock_p)
			return -RSBAC_EINVALIDTARGET;
		else
			return rsbac_ta_list_lol_remove(ta_number,
							netobj_handle,
							&tid.netobj.
							sock_p);
#endif

	default:
		err = -RSBAC_EINVALIDTARGET;
	}
	return err;
}

/* rsbac_acl_add_to_acl_entry
 * Add given rights to ACL entry for given target and subject. If entry does
 * not exist, behaviour is exactly like rsbac_acl_set_acl_entry.
 */

int rsbac_acl_add_to_acl_entry(rsbac_list_ta_number_t ta_number,
			       enum rsbac_target_t target,
			       union rsbac_target_id_t tid,
			       enum rsbac_acl_subject_type_t subj_type,
			       rsbac_acl_subject_id_t subj_id,
			       rsbac_acl_rights_vector_t rights,
			       rsbac_time_t ttl)
{
	int err = 0;
	struct rsbac_acl_device_list_item_t *device_p;
	rsbac_acl_rights_vector_t old_rights;
	struct rsbac_acl_entry_desc_t desc;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_acl_add_to_acl_entry(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (subj_type >= ACLS_NONE)
		return -RSBAC_EINVALIDVALUE;
#ifdef CONFIG_RSBAC_DEBUG
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_acl_add_to_acl_entry(): called from interrupt!\n");
	}
#endif
	desc.subj_type = subj_type;
	desc.subj_id = subj_id;

	switch (target) {
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_UNIXSOCK:
		/* default entry? */
		if (RSBAC_IS_ZERO_DEV(tid.file.device) && !tid.file.inode
		    && !tid.file.dentry_p) {
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_fd_handle, NULL, &desc,
			     &old_rights))
				rights |= old_rights;
			return rsbac_ta_list_add_ttl(ta_number,
						     default_fd_handle,
						     ttl, &desc, &rights);
		}
		srcu_idx = srcu_read_lock(&device_list_srcu);
		/* lookup device */
		device_p = acl_lookup_device(tid.file.device);
		if (!device_p) {
			rsbac_printk(KERN_WARNING "rsbac_acl_set_acl_entry(): Could not lookup device!\n");
			srcu_read_unlock(&device_list_srcu, srcu_idx);
			return -RSBAC_EINVALIDDEV;
		}
		/* protect this list */
		if (!rsbac_ta_list_lol_exist(ta_number, device_p->handle, &tid.file.inode)) {	/* new acl */
			rsbac_acl_rights_vector_t mask =
			    RSBAC_ACL_DEFAULT_FD_MASK;

			err =
			    rsbac_ta_list_lol_add_ttl(ta_number,
						      device_p->handle, 0,
						      &tid.file.inode,
						      &mask);
			if (err) {
				srcu_read_unlock(&device_list_srcu, srcu_idx);
				return err;
			}
		} else {	/* old entry? */
			if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							       device_p->handle,
							       NULL,
							       &tid.file.
							       inode,
							       &desc,
							       &old_rights))
				rights |= old_rights;
		}
		err = rsbac_ta_list_lol_subadd_ttl(ta_number,
						   device_p->handle, ttl,
						   &tid.file.inode, &desc,
						   &rights);
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		return err;

	case T_DEV:
		/* default entry? */
		if (RSBAC_IS_ZERO_DEV_DESC(tid.dev)) {
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_dev_handle, NULL, &desc,
			     &old_rights))
				rights |= old_rights;
			return rsbac_ta_list_add_ttl(ta_number,
						     default_dev_handle,
						     ttl, &desc, &rights);
		}
		switch (tid.dev.type) {
		case D_char:
		case D_block:
			if (!rsbac_ta_list_lol_exist(ta_number, dev_handle, &tid.dev)) {	/* new acl */
				rsbac_acl_rights_vector_t mask =
				    RSBAC_ACL_DEFAULT_DEV_MASK;

				err =
				    rsbac_ta_list_lol_add_ttl(ta_number,
							      dev_handle,
							      0, &tid.dev,
							      &mask);
				if (err)
					return err;
			} else {	/* old entry? */
				if (!rsbac_ta_list_lol_get_subdata_ttl
				    (ta_number, dev_handle, NULL, &tid.dev,
				     &desc, &old_rights))
					rights |= old_rights;
			}
			return rsbac_ta_list_lol_subadd_ttl(ta_number,
							    dev_handle,
							    ttl, &tid.dev,
							    &desc,
							    &rights);

		case D_char_major:
		case D_block_major:
			tid.dev.type -= (D_block_major - D_block);
			if (!rsbac_ta_list_lol_exist(ta_number, dev_major_handle, &tid.dev)) {	/* new acl */
				rsbac_acl_rights_vector_t mask =
				    RSBAC_ACL_DEFAULT_DEV_MASK;

				err =
				    rsbac_ta_list_lol_add_ttl(ta_number,
							      dev_major_handle,
							      0, &tid.dev,
							      &mask);
				if (err)
					return err;
			} else {	/* old entry? */
				if (!rsbac_ta_list_lol_get_subdata_ttl
				    (ta_number, dev_major_handle, NULL,
				     &tid.dev, &desc, &old_rights))
					rights |= old_rights;
			}
			return rsbac_ta_list_lol_subadd_ttl(ta_number,
							    dev_major_handle,
							    ttl, &tid.dev,
							    &desc,
							    &rights);

		default:
			return -RSBAC_EINVALIDTARGET;
		}

	case T_IPC:
		/* default entry? */
		if (tid.ipc.type == I_none) {
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_ipc_handle, NULL, &desc,
			     &old_rights))
				rights |= old_rights;
			return rsbac_ta_list_add_ttl(ta_number,
						     default_ipc_handle,
						     ttl, &desc, &rights);
		} else
			return -RSBAC_EINVALIDTARGET;

	case T_SCD:
		/* default entry? */
		if (tid.scd == AST_none) {
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_scd_handle, NULL, &desc,
			     &old_rights))
				rights |= old_rights;
			return rsbac_ta_list_add_ttl(ta_number,
						     default_scd_handle,
						     ttl, &desc, &rights);
		}
		if (!rsbac_ta_list_lol_exist(ta_number, scd_handle, &tid.scd)) {	/* new acl */
			rsbac_acl_rights_vector_t mask =
			    RSBAC_ACL_DEFAULT_SCD_MASK;

			err =
			    rsbac_ta_list_lol_add_ttl(ta_number,
						      scd_handle, 0,
						      &tid.scd, &mask);
			if (err)
				return err;
		} else {	/* old entry? */
			if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							       scd_handle,
							       NULL,
							       &tid.scd,
							       &desc,
							       &old_rights))
				rights |= old_rights;
		}
		return rsbac_ta_list_lol_subadd_ttl(ta_number,
						    scd_handle,
						    ttl,
						    &tid.scd,
						    &desc, &rights);

	case T_USER:
		/* default entry? */
		if (tid.user == RSBAC_NO_USER) {
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_u_handle, NULL, &desc,
			     &old_rights))
				rights |= old_rights;
			return rsbac_ta_list_add_ttl(ta_number,
						     default_u_handle, ttl,
						     &desc, &rights);
		}
		if (!rsbac_ta_list_lol_exist(ta_number, u_handle, &tid.user)) {	/* new acl */
			rsbac_acl_rights_vector_t mask =
			    RSBAC_ACL_DEFAULT_U_MASK;

			err =
			    rsbac_ta_list_lol_add_ttl(ta_number, u_handle,
						      0, &tid.user, &mask);
			if (err)
				return err;
		} else {	/* old subentry? */
			if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							       u_handle,
							       NULL,
							       &tid.user,
							       &desc,
							       &old_rights))
				rights |= old_rights;
		}
		return rsbac_ta_list_lol_subadd_ttl(ta_number,
						    u_handle,
						    ttl,
						    &tid.user,
						    &desc, &rights);

	case T_PROCESS:
		/* default entry? */
		if (!tid.process) {
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_p_handle, NULL, &desc,
			     &old_rights))
				rights |= old_rights;
			return rsbac_ta_list_add_ttl(ta_number,
						     default_p_handle, ttl,
						     &desc, &rights);
		} else
			return -RSBAC_EINVALIDTARGET;

#ifdef CONFIG_RSBAC_ACL_UM_PROT
	case T_GROUP:
		/* default entry? */
		if (tid.group == RSBAC_NO_GROUP) {
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_g_handle, NULL, &desc,
			     &old_rights))
				rights |= old_rights;
			return rsbac_ta_list_add_ttl(ta_number,
						     default_g_handle, ttl,
						     &desc, &rights);
		}
		if (!rsbac_ta_list_lol_exist(ta_number, g_handle, &tid.group)) {	/* new acl */
			rsbac_acl_rights_vector_t mask =
			    RSBAC_ACL_DEFAULT_G_MASK;

			err =
			    rsbac_ta_list_lol_add_ttl(ta_number, g_handle,
						      0, &tid.group,
						      &mask);
			if (err)
				return err;
		} else {	/* old subentry? */
			if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							       g_handle,
							       NULL,
							       &tid.group,
							       &desc,
							       &old_rights))
				rights |= old_rights;
		}
		return rsbac_ta_list_lol_subadd_ttl(ta_number,
						    g_handle,
						    ttl,
						    &tid.group,
						    &desc, &rights);
#endif

#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
	case T_NETDEV:
		/* default entry? */
		if (!tid.netdev[0]) {
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_netdev_handle, NULL, &desc,
			     &old_rights))
				rights |= old_rights;
			return rsbac_ta_list_add_ttl(ta_number,
						     default_netdev_handle,
						     ttl, &desc, &rights);
		}
		if (!rsbac_ta_list_lol_exist(ta_number, netdev_handle, &tid.netdev)) {	/* new acl */
			rsbac_acl_rights_vector_t mask =
			    RSBAC_ACL_DEFAULT_NETDEV_MASK;

			err =
			    rsbac_ta_list_lol_add_ttl(ta_number,
						      netdev_handle, 0,
						      &tid.netdev, &mask);
			if (err)
				return err;
		} else {	/* old entry? */
			if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							       netdev_handle,
							       NULL,
							       &tid.netdev,
							       &desc,
							       &old_rights))
				rights |= old_rights;
		}
		return rsbac_ta_list_lol_subadd_ttl(ta_number,
						    netdev_handle,
						    ttl,
						    &tid.netdev,
						    &desc, &rights);
#endif

#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
	case T_NETTEMP_NT:
		/* default entry? */
		if (!tid.nettemp) {
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_nettemp_nt_handle, NULL,
			     &desc, &old_rights))
				rights |= old_rights;
			return rsbac_ta_list_add_ttl(ta_number,
						     default_nettemp_nt_handle,
						     ttl, &desc, &rights);
		}
		if (!rsbac_ta_net_template_exist(ta_number, tid.nettemp))
			return -RSBAC_EINVALIDTARGET;
		if (!rsbac_ta_list_lol_exist(ta_number, nettemp_nt_handle, &tid.nettemp)) {	/* new acl */
			rsbac_acl_rights_vector_t mask =
			    RSBAC_ACL_DEFAULT_NETTEMP_MASK;

			err =
			    rsbac_ta_list_lol_add_ttl(ta_number,
						      nettemp_nt_handle, 0,
						      &tid.nettemp, &mask);
			if (err)
				return err;
		} else {	/* old entry? */
			if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							       nettemp_nt_handle,
							       NULL,
							       &tid.
							       nettemp,
							       &desc,
							       &old_rights))
				rights |= old_rights;
		}
		return rsbac_ta_list_lol_subadd_ttl(ta_number,
						    nettemp_nt_handle,
						    ttl,
						    &tid.nettemp,
						    &desc, &rights);
	case T_NETTEMP:
		/* default entry? */
		if (!tid.nettemp) {
			return -RSBAC_EINVALIDTARGET;
		}
		if (!rsbac_ta_net_template_exist(ta_number, tid.nettemp))
			return -RSBAC_EINVALIDTARGET;
		if (!rsbac_ta_list_lol_exist(ta_number, nettemp_handle, &tid.nettemp)) {	/* new acl */
			rsbac_acl_rights_vector_t mask =
			    RSBAC_ACL_DEFAULT_NETOBJ_MASK;

			err =
			    rsbac_ta_list_lol_add_ttl(ta_number,
						      nettemp_handle, 0,
						      &tid.nettemp, &mask);
			if (err)
				return err;
		} else {	/* old entry? */
			if (!rsbac_ta_list_lol_get_subdata_ttl
			    (ta_number, nettemp_handle, NULL, &tid.nettemp,
			     &desc, &old_rights))
				rights |= old_rights;
		}
		return rsbac_ta_list_lol_subadd_ttl(ta_number,
						    nettemp_handle, ttl,
						    &tid.nettemp, &desc,
						    &rights);
	case T_NETOBJ:
		/* default entry? */
		if (!tid.netobj.sock_p) {
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_netobj_handle, NULL, &desc,
			     &old_rights))
				rights |= old_rights;
			return rsbac_ta_list_add_ttl(ta_number,
						     default_netobj_handle,
						     ttl, &desc, &rights);
		}
		if (!rsbac_ta_list_lol_exist(ta_number, netobj_handle, &tid.netobj.sock_p)) {	/* new acl */
			rsbac_acl_rights_vector_t mask =
			    RSBAC_ACL_DEFAULT_NETOBJ_MASK;

			err =
			    rsbac_ta_list_lol_add_ttl(ta_number,
						      netobj_handle, 0,
						      &tid.netobj.sock_p,
						      &mask);
			if (err)
				return err;
		} else {	/* old entry? */
			if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							       netobj_handle,
							       NULL,
							       &tid.netobj.
							       sock_p,
							       &desc,
							       &old_rights))
				rights |= old_rights;
		}
		return rsbac_ta_list_lol_subadd_ttl(ta_number,
						    netobj_handle,
						    ttl,
						    &tid.netobj.sock_p,
						    &desc, &rights);
#endif				/* NET_OBJ_PROT */

	default:
		return -RSBAC_EINVALIDTARGET;
	}
}

/* rsbac_acl_remove_from_acl_entry
 * Remove given rights from ACL entry for given target and subject. If entry does
 * not exist, nothing happens.
 * This function does NOT remove the ACL entry, so removing all rights results in
 * NO rights for this subject/target combination!
 */

int rsbac_acl_remove_from_acl_entry(rsbac_list_ta_number_t ta_number,
				    enum rsbac_target_t target,
				    union rsbac_target_id_t tid,
				    enum rsbac_acl_subject_type_t
				    subj_type,
				    rsbac_acl_subject_id_t subj_id,
				    rsbac_acl_rights_vector_t rights)
{
	int err = 0;
	struct rsbac_acl_device_list_item_t *device_p;
	rsbac_acl_rights_vector_t old_rights;
	struct rsbac_acl_entry_desc_t desc;
	rsbac_time_t ttl;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_acl_remove_from_acl_entry(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (subj_type >= ACLS_NONE)
		return -RSBAC_EINVALIDVALUE;
#ifdef CONFIG_RSBAC_DEBUG
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_acl_remove_from_acl_entry(): called from interrupt!\n");
	}
#endif
	desc.subj_type = subj_type;
	desc.subj_id = subj_id;

	switch (target) {
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_UNIXSOCK:
		/* default entry? */
		if (RSBAC_IS_ZERO_DEV(tid.file.device) && !tid.file.inode
		    && !tid.file.dentry_p) {
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_fd_handle, &ttl, &desc,
			     &old_rights)) {
				old_rights &= ~rights;
				return rsbac_ta_list_add_ttl(ta_number,
							     default_fd_handle,
							     ttl, &desc,
							     &old_rights);
			} else
				return 0;
		}
		srcu_idx = srcu_read_lock(&device_list_srcu);
		/* lookup device */
		device_p = acl_lookup_device(tid.file.device);
		if (!device_p) {
			rsbac_printk(KERN_WARNING "rsbac_acl_remove_from_acl_entry(): Could not lookup device!\n");
			srcu_read_unlock(&device_list_srcu, srcu_idx);
			return -RSBAC_EINVALIDDEV;
		}
		if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
						       device_p->handle,
						       &ttl,
						       &tid.file.inode,
						       &desc,
						       &old_rights)) {
			old_rights &= ~rights;
			err = rsbac_ta_list_lol_subadd_ttl(ta_number,
							   device_p->handle,
							   ttl,
							   &tid.file.inode,
							   &desc,
							   &old_rights);
		} else
			err = 0;
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		return err;

	case T_DEV:
		/* default entry? */
		if (RSBAC_IS_ZERO_DEV_DESC(tid.dev)) {
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_dev_handle, &ttl, &desc,
			     &old_rights)) {
				old_rights &= ~rights;
				return rsbac_ta_list_add_ttl(ta_number,
							     default_dev_handle,
							     ttl, &desc,
							     &old_rights);
			} else
				return 0;
		}
		switch (tid.dev.type) {
		case D_char:
		case D_block:
			if (!rsbac_ta_list_lol_get_subdata_ttl
			    (ta_number, dev_handle, &ttl, &tid.dev, &desc,
			     &old_rights)) {
				old_rights &= ~rights;
				return
				    rsbac_ta_list_lol_subadd_ttl(ta_number,
								 dev_handle,
								 ttl,
								 &tid.dev,
								 &desc,
								 &old_rights);
			} else
				return 0;

		case D_char_major:
		case D_block_major:
			tid.dev.type -= (D_block_major - D_block);
			if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							       dev_major_handle,
							       &ttl,
							       &tid.dev,
							       &desc,
							       &old_rights))
			{
				old_rights &= ~rights;
				return
				    rsbac_ta_list_lol_subadd_ttl(ta_number,
								 dev_major_handle,
								 ttl,
								 &tid.dev,
								 &desc,
								 &old_rights);
			} else
				return 0;

		default:
			return -RSBAC_EINVALIDTARGET;
		}

	case T_IPC:
		/* default entry? */
		if (tid.ipc.type == I_none) {
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_ipc_handle, &ttl, &desc,
			     &old_rights)) {
				old_rights &= ~rights;
				return rsbac_ta_list_add_ttl(ta_number,
							     default_ipc_handle,
							     ttl, &desc,
							     &old_rights);
			} else
				return 0;
		} else
			return -RSBAC_EINVALIDTARGET;

	case T_SCD:
		/* default entry? */
		if (tid.scd == AST_none) {
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_scd_handle, &ttl, &desc,
			     &old_rights)) {
				old_rights &= ~rights;
				return rsbac_ta_list_add_ttl(ta_number,
							     default_scd_handle,
							     ttl, &desc,
							     &old_rights);
			} else
				return 0;
		}
		if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
						       scd_handle,
						       &ttl,
						       &tid.scd,
						       &desc,
						       &old_rights)) {
			old_rights &= ~rights;
			return rsbac_ta_list_lol_subadd_ttl(ta_number,
							    scd_handle,
							    ttl,
							    &tid.scd,
							    &desc,
							    &old_rights);
		} else
			return 0;

	case T_USER:
		/* default entry? */
		if (tid.user == RSBAC_NO_USER) {
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_u_handle, &ttl, &desc,
			     &old_rights)) {
				old_rights &= ~rights;
				return rsbac_ta_list_add_ttl(ta_number,
							     default_u_handle,
							     ttl, &desc,
							     &old_rights);
			} else
				return 0;
		}
		if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
						       u_handle,
						       &ttl,
						       &tid.user,
						       &desc,
						       &old_rights)) {
			old_rights &= ~rights;
			return rsbac_ta_list_lol_subadd_ttl(ta_number,
							    u_handle,
							    ttl,
							    &tid.user,
							    &desc,
							    &old_rights);
		} else
			return 0;

	case T_PROCESS:
		/* default entry? */
		if (!tid.process) {
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_p_handle, &ttl, &desc,
			     &old_rights)) {
				old_rights &= ~rights;
				return rsbac_ta_list_add_ttl(ta_number,
							     default_p_handle,
							     ttl, &desc,
							     &old_rights);
			} else
				return 0;
		} else
			return -RSBAC_EINVALIDTARGET;

#ifdef CONFIG_RSBAC_ACL_UM_PROT
	case T_GROUP:
		/* default entry? */
		if (tid.group == RSBAC_NO_GROUP) {
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_g_handle, &ttl, &desc,
			     &old_rights)) {
				old_rights &= ~rights;
				return rsbac_ta_list_add_ttl(ta_number,
							     default_g_handle,
							     ttl, &desc,
							     &old_rights);
			} else
				return 0;
		}
		if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
						       g_handle,
						       &ttl,
						       &tid.group,
						       &desc,
						       &old_rights)) {
			old_rights &= ~rights;
			return rsbac_ta_list_lol_subadd_ttl(ta_number,
							    g_handle,
							    ttl,
							    &tid.group,
							    &desc,
							    &old_rights);
		} else
			return 0;
#endif

#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
	case T_NETDEV:
		/* default entry? */
		if (!tid.netdev[0]) {
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_netdev_handle, &ttl, &desc,
			     &old_rights)) {
				old_rights &= ~rights;
				return rsbac_ta_list_add_ttl(ta_number,
							     default_netdev_handle,
							     ttl, &desc,
							     &old_rights);
			} else
				return 0;
		}
		if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
						       netdev_handle,
						       &ttl,
						       &tid.netdev,
						       &desc,
						       &old_rights)) {
			old_rights &= ~rights;
			return rsbac_ta_list_lol_subadd_ttl(ta_number,
							    netdev_handle,
							    ttl,
							    &tid.netdev,
							    &desc,
							    &old_rights);
		} else
			return 0;
#endif

#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
	case T_NETTEMP_NT:
		/* default entry? */
		if (!tid.nettemp) {
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_nettemp_nt_handle, &ttl,
			     &desc, &old_rights)) {
				old_rights &= ~rights;
				return rsbac_ta_list_add_ttl(ta_number,
							     default_nettemp_nt_handle,
							     ttl, &desc,
							     &old_rights);
			} else
				return 0;
		}
		if (!rsbac_ta_net_template_exist(ta_number, tid.nettemp))
			return -RSBAC_EINVALIDTARGET;
		if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
						       nettemp_nt_handle,
						       &ttl,
						       &tid.nettemp,
						       &desc,
						       &old_rights)) {
			old_rights &= ~rights;
			return rsbac_ta_list_lol_subadd_ttl(ta_number,
							    nettemp_nt_handle,
							    ttl,
							    &tid.nettemp,
							    &desc,
							    &old_rights);
		} else
			return 0;
	case T_NETTEMP:
		/* default entry? */
		if (!tid.nettemp) {
			return -RSBAC_EINVALIDTARGET;
		}
		if (!rsbac_ta_net_template_exist(ta_number, tid.nettemp))
			return -RSBAC_EINVALIDTARGET;
		if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
						       nettemp_handle,
						       &ttl,
						       &tid.nettemp,
						       &desc,
						       &old_rights)) {
			old_rights &= ~rights;
			return rsbac_ta_list_lol_subadd_ttl(ta_number,
							    nettemp_handle,
							    ttl,
							    &tid.nettemp,
							    &desc,
							    &old_rights);
		} else
			return 0;
	case T_NETOBJ:
		/* default entry? */
		if (!tid.netobj.sock_p) {
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_netobj_handle, &ttl, &desc,
			     &old_rights)) {
				old_rights &= ~rights;
				return rsbac_ta_list_add_ttl(ta_number,
							     default_netobj_handle,
							     ttl, &desc,
							     &old_rights);
			} else
				return 0;
		}
		if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
						       netobj_handle,
						       &ttl,
						       &tid.netobj.sock_p,
						       &desc,
						       &old_rights)) {
			old_rights &= ~rights;
			return rsbac_ta_list_lol_subadd_ttl(ta_number,
							    netobj_handle,
							    ttl,
							    &tid.netobj.
							    sock_p, &desc,
							    &old_rights);
		} else
			return 0;
#endif				/* NET_OBJ_PROT */

	default:
		return -RSBAC_EINVALIDTARGET;
	}
}

/* rsbac_acl_set_mask
 * Set inheritance mask for given target to given rights. If item does
 * not exist, it is created.
 */

int rsbac_acl_set_mask(rsbac_list_ta_number_t ta_number,
		       enum rsbac_target_t target,
		       union rsbac_target_id_t tid,
		       rsbac_acl_rights_vector_t mask)
{
	int err = 0;
	char tmp[80];
	struct rsbac_acl_device_list_item_t *device_p;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_acl_set_mask(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (target >= T_NONE)
		return -RSBAC_EINVALIDTARGET;
#ifdef CONFIG_RSBAC_DEBUG
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_acl_set_mask(): called from interrupt!\n");
	}
#endif
	switch (target) {
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_UNIXSOCK:
		/* default entry? */
		if (RSBAC_IS_ZERO_DEV_DESC(tid.dev)) {
			return -RSBAC_EINVALIDTARGET;
		}
		rsbac_pr_debug(ds_acl, "Setting file/dir/fifo/symlink inheritance mask for device %02u:%02u, inode %u\n",
			       RSBAC_MAJOR(tid.file.device),
			       RSBAC_MINOR(tid.file.device), tid.file.inode);
		srcu_idx = srcu_read_lock(&device_list_srcu);
		device_p = acl_lookup_device(tid.file.device);
		if (!device_p) {
			rsbac_printk(KERN_WARNING "rsbac_acl_set_mask(): Could not lookup device!\n");
			srcu_read_unlock(&device_list_srcu, srcu_idx);
			return -RSBAC_EINVALIDDEV;
		}
		err = rsbac_ta_list_lol_add_ttl(ta_number,
					      device_p->handle,
					      0, &tid.file.inode, &mask);
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		return err;

	case T_DEV:
		/* default entry? */
		if (tid.dev.type == D_none) {
			return -RSBAC_EINVALIDTARGET;
		}
		rsbac_pr_debug(ds_acl, "Setting device inheritance mask for dev %c %02u:%02u\n",
			       'B' + tid.dev.type,
			       tid.dev.major, tid.dev.minor);
		switch (tid.dev.type) {
		case D_char:
		case D_block:
			return rsbac_ta_list_lol_add_ttl(ta_number,
							 dev_handle, 0,
							 &tid.dev, &mask);

		case D_char_major:
		case D_block_major:
			tid.dev.type -= (D_block_major - D_block);
			return rsbac_ta_list_lol_add_ttl(ta_number,
							 dev_major_handle,
							 0, &tid.dev,
							 &mask);

		default:
			return -RSBAC_EINVALIDTARGET;
		}

	case T_SCD:
		/* default entry? */
		if (tid.scd == AST_none) {
			return -RSBAC_EINVALIDTARGET;
		}
		rsbac_pr_debug(ds_acl, "Setting SCD inheritance mask for %s\n",
			       get_acl_scd_type_name(tmp, tid.scd));
		return rsbac_ta_list_lol_add_ttl(ta_number, scd_handle, 0,
						 &tid.scd, &mask);

	case T_USER:
		/* default entry? */
		if (tid.user == RSBAC_NO_USER) {
			return -RSBAC_EINVALIDTARGET;
		}
		rsbac_pr_debug(ds_acl, "Setting user inheritance mask for user %u\n",
			       tid.user);
		return rsbac_ta_list_lol_add_ttl(ta_number, u_handle, 0,
						 &tid.user, &mask);

#ifdef CONFIG_RSBAC_ACL_UM_PROT
	case T_GROUP:
		/* default entry? */
		if (tid.group == RSBAC_NO_GROUP) {
			return -RSBAC_EINVALIDTARGET;
		}
		rsbac_pr_debug(ds_acl, "Setting Linux group inheritance mask for group %u\n",
			       tid.group);
		return rsbac_ta_list_lol_add_ttl(ta_number, g_handle, 0,
						 &tid.group, &mask);
#endif

#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
	case T_NETDEV:
		/* default entry? */
		if (!tid.netdev[0]) {
			return -RSBAC_EINVALIDTARGET;
		}
		rsbac_pr_debug(ds_acl, "Setting network device inheritance mask for netdev %s\n",
			       tid.netdev);
		return rsbac_ta_list_lol_add_ttl(ta_number, netdev_handle,
						 0, &tid.netdev, &mask);
#endif

#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
	case T_NETTEMP_NT:
		/* default entry? */
		if (!tid.nettemp) {
			return -RSBAC_EINVALIDTARGET;
		}
		if (!rsbac_ta_net_template_exist(ta_number, tid.nettemp))
			return -RSBAC_EINVALIDTARGET;
		rsbac_pr_debug(ds_acl, "Setting network template NT inheritance mask for nettemp %u\n",
			       tid.nettemp);
		return rsbac_ta_list_lol_add_ttl(ta_number,
						 nettemp_nt_handle, 0,
						 &tid.nettemp, &mask);

	case T_NETTEMP:
		/* default entry? */
		if (!tid.nettemp) {
			return -RSBAC_EINVALIDTARGET;
		}
		if (!rsbac_ta_net_template_exist(ta_number, tid.nettemp))
			return -RSBAC_EINVALIDTARGET;
		rsbac_pr_debug(ds_acl, "Setting network template inheritance mask for nettemp %u\n",
			       tid.nettemp);
		return rsbac_ta_list_lol_add_ttl(ta_number, nettemp_handle,
						 0, &tid.nettemp, &mask);

	case T_NETOBJ:
		/* default entry? */
		if (!tid.netobj.sock_p) {
			return -RSBAC_EINVALIDTARGET;
		}
		rsbac_pr_debug(ds_acl, "Setting network object inheritance mask for netobj %p\n",
			       tid.netobj.sock_p);
		return rsbac_ta_list_lol_add_ttl(ta_number, netobj_handle,
						 0, &tid.netobj.sock_p,
						 &mask);
#endif				/* NET_OBJ_PROT */

	default:
		err = -RSBAC_EINVALIDTARGET;
	}
	return err;
}

/* rsbac_acl_get_mask
 * Get inheritance mask for given target. If item does
 * not exist, default mask is returned.
 */

int rsbac_acl_get_mask(rsbac_list_ta_number_t ta_number,
		       enum rsbac_target_t target,
		       union rsbac_target_id_t tid,
		       rsbac_acl_rights_vector_t * mask_p)
{
	int err = 0;
	struct rsbac_acl_device_list_item_t *device_p;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_acl_get_mask(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (target >= T_NONE)
		return -RSBAC_EINVALIDTARGET;
#ifdef CONFIG_RSBAC_DEBUG
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_acl_get_mask(): called from interrupt!\n");
	}
#endif
	switch (target) {
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_UNIXSOCK:
		/* default entry? */
		if (RSBAC_IS_ZERO_DEV(tid.file.device) && !tid.file.inode
		    && !tid.file.dentry_p) {
			return -RSBAC_EINVALIDTARGET;
		}

		srcu_idx = srcu_read_lock(&device_list_srcu);
		/* lookup device */
		device_p = acl_lookup_device(tid.file.device);
		if (!device_p) {
			rsbac_printk(KERN_WARNING "rsbac_acl_get_mask(): Could not lookup device!\n");
			srcu_read_unlock(&device_list_srcu, srcu_idx);
			return -RSBAC_EINVALIDDEV;
		}
		err = rsbac_ta_list_lol_get_data_ttl(ta_number,
						   device_p->handle, NULL,
						   &tid.file.inode,
						   mask_p);
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		if (err == -RSBAC_ENOTFOUND) {
			*mask_p = RSBAC_ACL_DEFAULT_FD_MASK;
			err = 0;
		}
		/* ready. */
		return err;

	case T_DEV:
		/* default entry? */
		if (tid.dev.type == D_none) {
			return -RSBAC_EINVALIDTARGET;
		}

		switch (tid.dev.type) {
		case D_char:
		case D_block:
			err =
			    rsbac_ta_list_lol_get_data_ttl(ta_number,
							   dev_handle,
							   NULL, &tid.dev,
							   mask_p);
			break;

		case D_char_major:
		case D_block_major:
			tid.dev.type -= (D_block_major - D_block);
			err =
			    rsbac_ta_list_lol_get_data_ttl(ta_number,
							   dev_major_handle,
							   NULL, &tid.dev,
							   mask_p);
			break;

		default:
			return -RSBAC_EINVALIDTARGET;
		}
		if (err == -RSBAC_ENOTFOUND) {
			*mask_p = RSBAC_ACL_DEFAULT_DEV_MASK;
			err = 0;
		}
		/* ready. */
		return err;

	case T_SCD:
		/* default entry? */
		if (tid.scd == AST_none) {
			return -RSBAC_EINVALIDTARGET;
		}
		err =
		    rsbac_ta_list_lol_get_data_ttl(ta_number, scd_handle,
						   NULL, &tid.scd, mask_p);
		if (err == -RSBAC_ENOTFOUND) {
			*mask_p = RSBAC_ACL_DEFAULT_SCD_MASK;
			err = 0;
		}
		/* ready. */
		return err;

	case T_USER:
		/* default entry? */
		if (tid.user == RSBAC_NO_USER) {
			return -RSBAC_EINVALIDTARGET;
		}
		err =
		    rsbac_ta_list_lol_get_data_ttl(ta_number, u_handle,
						   NULL, &tid.user,
						   mask_p);
		if (err == -RSBAC_ENOTFOUND) {
			*mask_p = RSBAC_ACL_DEFAULT_U_MASK;
			err = 0;
		}
		/* ready. */
		return err;

#ifdef CONFIG_RSBAC_ACL_UM_PROT
	case T_GROUP:
		/* default entry? */
		if (tid.group == RSBAC_NO_GROUP) {
			return -RSBAC_EINVALIDTARGET;
		}
		err =
		    rsbac_ta_list_lol_get_data_ttl(ta_number, g_handle,
						   NULL, &tid.group,
						   mask_p);
		if (err == -RSBAC_ENOTFOUND) {
			*mask_p = RSBAC_ACL_DEFAULT_G_MASK;
			err = 0;
		}
		/* ready. */
		return err;
#endif

#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
	case T_NETDEV:
		/* default entry? */
		if (!tid.netdev[0]) {
			return -RSBAC_EINVALIDTARGET;
		}

		err =
		    rsbac_ta_list_lol_get_data_ttl(ta_number,
						   netdev_handle, NULL,
						   &tid.netdev, mask_p);
		if (err == -RSBAC_ENOTFOUND) {
			*mask_p = RSBAC_ACL_DEFAULT_NETDEV_MASK;
			err = 0;
		}
		/* ready. */
		return err;
#endif

#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
	case T_NETTEMP_NT:
		/* default entry? */
		if (!tid.nettemp) {
			return -RSBAC_EINVALIDTARGET;
		}
		if (!rsbac_ta_net_template_exist(ta_number, tid.nettemp))
			return -RSBAC_EINVALIDTARGET;

		err =
		    rsbac_ta_list_lol_get_data_ttl(ta_number,
						   nettemp_nt_handle, NULL,
						   &tid.nettemp, mask_p);
		if (err == -RSBAC_ENOTFOUND) {
			*mask_p = RSBAC_ACL_DEFAULT_NETTEMP_MASK;
			err = 0;
		}
		/* ready. */
		return err;
	case T_NETTEMP:
		/* default entry? */
		if (!tid.nettemp) {
			return -RSBAC_EINVALIDTARGET;
		}
		if (!rsbac_ta_net_template_exist(ta_number, tid.nettemp))
			return -RSBAC_EINVALIDTARGET;

		err =
		    rsbac_ta_list_lol_get_data_ttl(ta_number,
						   nettemp_handle, NULL,
						   &tid.nettemp, mask_p);
		if (err == -RSBAC_ENOTFOUND) {
			*mask_p = RSBAC_ACL_DEFAULT_NETOBJ_MASK;
			err = 0;
		}
		/* ready. */
		return err;
	case T_NETOBJ:
		/* default entry? */
		if (!tid.netobj.sock_p) {
			return -RSBAC_EINVALIDTARGET;
		}

		err =
		    rsbac_ta_list_lol_get_data_ttl(ta_number,
						   netobj_handle, NULL,
						   &tid.netobj.sock_p,
						   mask_p);
		if (err == -RSBAC_ENOTFOUND) {
			*mask_p = RSBAC_ACL_DEFAULT_NETOBJ_MASK;
			err = 0;
		}
		/* ready. */
		return err;
#endif

	default:
		err = -RSBAC_EINVALIDTARGET;
	}
	return err;
}

/* rsbac_acl_get_rights
 * Get rights from ACL entry for given target and subject.
 * If entry does not exist and inherit is on, inherited rights are used.
 * If there is no parent, the default rights vector for this target type is returned.
 * This function does NOT add role or group rights to user rights!
 */

int rsbac_acl_get_rights(rsbac_list_ta_number_t ta_number,
			 enum rsbac_target_t target,
			 union rsbac_target_id_t tid,
			 enum rsbac_acl_subject_type_t subj_type,
			 rsbac_acl_subject_id_t subj_id,
			 rsbac_acl_rights_vector_t * rights_p,
			 rsbac_boolean_t inherit)
{
	int err = 0;
	struct rsbac_acl_device_list_item_t *device_p;
	struct rsbac_acl_entry_desc_t desc;
	rsbac_acl_rights_vector_t i_rights = 0;
	rsbac_acl_rights_vector_t mask = -1;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_acl_get_rights(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (!rights_p)
		return -RSBAC_EINVALIDPOINTER;
	if (subj_type >= ACLS_NONE)
		return -RSBAC_EINVALIDVALUE;
#ifdef CONFIG_RSBAC_DEBUG
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_acl_get_rights(): called from interrupt!\n");
	}
#endif
	desc.subj_type = subj_type;
	desc.subj_id = subj_id;

	switch (target) {
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_UNIXSOCK:
		/* default entry? */
		if (RSBAC_IS_ZERO_DEV(tid.file.device) && !tid.file.inode
		    && !tid.file.dentry_p) {
			if (rsbac_ta_list_get_data_ttl
			    (ta_number, default_fd_handle, NULL, &desc,
			     rights_p)) {
				/* last resort: default rights */
				*rights_p = default_fd_rights;
			}
			return 0;
		}
		*rights_p = 0;
		srcu_idx = srcu_read_lock(&device_list_srcu);
		/* use loop for inheritance - used to be recursive calls */
		for (;;) {
			/* lookup device */
			device_p = acl_lookup_device(tid.file.device);
			if (!device_p) {
				rsbac_printk(KERN_WARNING "rsbac_acl_get_rights(): Could not lookup device %02u:%02u!\n",
					     RSBAC_MAJOR(tid.file.
							 device),
					     RSBAC_MINOR(tid.file.
							 device));
				srcu_read_unlock(&device_list_srcu, srcu_idx);
				return -RSBAC_EINVALIDDEV;
			}
			if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							       device_p->handle,
							       NULL,
							       &tid.file.
							       inode,
							       &desc,
							       &i_rights))
			{
				*rights_p |= (i_rights & mask);
				/* leave loop */
				break;
			} else if (inherit) {
				enum rsbac_target_t parent_target;
				union rsbac_target_id_t parent_tid;
				rsbac_acl_rights_vector_t i_mask;

				/* get mask to filter through in next round */
				if (rsbac_ta_list_lol_get_data_ttl
				    (ta_number, device_p->handle,
				     NULL, &tid.file.inode, &i_mask)) {
					/* no mask found, set default */
					i_mask = RSBAC_ACL_DEFAULT_FD_MASK;
				}
				/* mask into cumulative mask */
				mask &= i_mask;

				/* inheritance possible? */
				if (!rsbac_get_parent
				    (target, tid, &parent_target,
				     &parent_tid)) {
					target = parent_target;
					tid = parent_tid;
					/* next round */
					continue;
				} else {
					/* no inheritance possible -> try default_fd_acl */
					if (!rsbac_ta_list_get_data_ttl
					    (ta_number, default_fd_handle,
					     NULL, &desc, &i_rights)) {
						/* found, use it */
						*rights_p |=
						    (i_rights & mask);
					} else {
						/* last resort: default rights */
						*rights_p |=
						    (default_fd_rights &
						     mask);
					}
				}
				/* leave loop */
				break;
			} else {	/* do not inherit */

				/* last resort: default rights */
				*rights_p |= default_fd_rights;
				/* leave loop */
				break;
			}
		}		/* end of for(;;) inheritance loop */
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		return err;

	case T_DEV:
		/* default entry? */

		if (RSBAC_IS_ZERO_DEV_DESC(tid.dev)) {
			if (rsbac_ta_list_get_data_ttl
			    (ta_number, default_dev_handle, NULL, &desc,
			     rights_p)) {
				/* last resort: default rights */
				*rights_p = default_dev_rights;
			}
			return 0;
		}
		if ((tid.dev.type >= D_char_major)
		    || (tid.dev.type == D_block_major)
		    ) {
			tid.dev.type -= (D_block_major - D_block);
			if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							       dev_major_handle,
							       NULL,
							       &tid.dev,
							       &desc,
							       &i_rights))
			{
				*rights_p |= i_rights;
			} else {
				rsbac_acl_rights_vector_t mask2;

				/* get mask to filter through */
				if (rsbac_ta_list_lol_get_data_ttl
				    (ta_number, dev_major_handle, NULL,
				     &tid.dev, &mask2)) {
					/* no mask found, set default */
					mask2 = RSBAC_ACL_DEFAULT_DEV_MASK;
				}
				/* try default_dev_acl */
				if (!rsbac_ta_list_get_data_ttl
				    (ta_number, default_dev_handle, NULL,
				     &desc, rights_p)) {
					*rights_p &= mask2;
				} else {
					/* last resort: default rights */
					*rights_p =
					    default_dev_rights & mask2;
				}
			}
			return 0;
		}
		if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
						       dev_handle,
						       NULL,
						       &tid.dev,
						       &desc, &i_rights)) {
			*rights_p |= i_rights;
		} else {
			rsbac_acl_rights_vector_t mask;

			/* get mask to filter through */
			if (rsbac_ta_list_lol_get_data_ttl(ta_number,
							   dev_handle,
							   NULL,
							   &tid.dev,
							   &mask)) {
				/* no mask found, set default */
				mask = RSBAC_ACL_DEFAULT_DEV_MASK;
			}
			if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							       dev_major_handle,
							       NULL,
							       &tid.dev,
							       &desc,
							       &i_rights))
			{
				i_rights &= mask;
				*rights_p |= i_rights;
			} else {
				rsbac_acl_rights_vector_t mask2;

				/* get mask to filter through */
				if (rsbac_ta_list_lol_get_data_ttl
				    (ta_number, dev_major_handle, NULL,
				     &tid.dev, &mask2)) {
					/* no mask found, set default */
					mask2 = RSBAC_ACL_DEFAULT_DEV_MASK;
				}
				/* try default_dev_acl */
				if (!rsbac_ta_list_get_data_ttl
				    (ta_number, default_dev_handle, NULL,
				     &desc, rights_p)) {
					*rights_p &= mask;
					*rights_p &= mask2;
				} else {
					/* last resort: default rights */
					*rights_p =
					    default_dev_rights & mask &
					    mask2;
				}
			}
		}
		return 0;

	case T_IPC:

		/* Use default ACL */
		if (rsbac_ta_list_get_data_ttl
		    (ta_number, default_ipc_handle, NULL, &desc,
		     rights_p)) {
			/* last resort: default rights */
			*rights_p = default_ipc_rights;
		}
		return 0;

	case T_SCD:
		/* default entry? */
		if ((tid.scd == AST_none)
		    || (tid.scd == ST_none)
		    ) {
			if (rsbac_ta_list_get_data_ttl
			    (ta_number, default_scd_handle, NULL, &desc,
			     rights_p)) {
				/* last resort: default rights */
				*rights_p = default_scd_rights;
			}
			return 0;
		}
		if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
						       scd_handle,
						       NULL,
						       &tid.scd,
						       &desc, &i_rights)) {
			*rights_p |= i_rights;
		} else {
			rsbac_acl_rights_vector_t mask;

			/* get mask to filter through */
			if (rsbac_ta_list_lol_get_data_ttl(ta_number,
							   scd_handle,
							   NULL,
							   &tid.scd,
							   &mask)) {
				/* no mask found, set default */
				mask = RSBAC_ACL_DEFAULT_SCD_MASK;
			}
			/* try default_dev_acl */
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_scd_handle, NULL, &desc,
			     rights_p)) {
				*rights_p &= mask;
			} else {
				/* last resort: default rights */
				*rights_p = default_scd_rights & mask;
			}
		}
		return 0;

	case T_USER:
		/* default entry? */
		if (tid.user == RSBAC_NO_USER) {
			if (rsbac_ta_list_get_data_ttl
			    (ta_number, default_u_handle, NULL, &desc,
			     rights_p)) {
				/* last resort: default rights */
				*rights_p = default_u_rights;
			}
			return 0;
		}
		if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
						       u_handle,
						       NULL,
						       &tid.user,
						       &desc, &i_rights)) {
			*rights_p |= i_rights;
		} else {
			rsbac_acl_rights_vector_t mask;

			/* get mask to filter through */
			if (rsbac_ta_list_lol_get_data_ttl(ta_number,
							   u_handle,
							   NULL,
							   &tid.user,
							   &mask)) {
				/* no mask found, set default */
				mask = RSBAC_ACL_DEFAULT_U_MASK;
			}
			/* try default_u_acl */
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_u_handle, NULL, &desc,
			     rights_p)) {
				*rights_p &= mask;
			} else {
				/* last resort: default rights */
				*rights_p = default_u_rights & mask;
			}
		}
		return 0;

	case T_PROCESS:

		/* Use default entry */
		if (rsbac_ta_list_get_data_ttl(ta_number, default_p_handle,
					       NULL, &desc, rights_p)) {
			/* last resort: default rights */
			*rights_p = default_p_rights;
		}
		return 0;

#ifdef CONFIG_RSBAC_ACL_UM_PROT
	case T_GROUP:
		/* default entry? */
		if (tid.group == RSBAC_NO_GROUP) {
			if (rsbac_ta_list_get_data_ttl
			    (ta_number, default_g_handle, NULL, &desc,
			     rights_p)) {
				/* last resort: default rights */
				*rights_p = default_g_rights;
			}
			return 0;
		}
		if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
						       g_handle,
						       NULL,
						       &tid.group,
						       &desc, &i_rights)) {
			*rights_p |= i_rights;
		} else {
			rsbac_acl_rights_vector_t mask;

			/* get mask to filter through */
			if (rsbac_ta_list_lol_get_data_ttl(ta_number,
							   g_handle,
							   NULL,
							   &tid.group,
							   &mask)) {
				/* no mask found, set default */
				mask = RSBAC_ACL_DEFAULT_G_MASK;
			}
			/* try default_u_acl */
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_g_handle, NULL, &desc,
			     rights_p)) {
				*rights_p &= mask;
			} else {
				/* last resort: default rights */
				*rights_p = default_g_rights & mask;
			}
		}
		return 0;
#endif

#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
	case T_NETDEV:
		/* default entry? */

		if (!tid.netdev[0]) {
			if (rsbac_ta_list_get_data_ttl
			    (ta_number, default_netdev_handle, NULL, &desc,
			     rights_p)) {
				/* last resort: default rights */
				*rights_p = default_netdev_rights;
			}
			return 0;
		}
		if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
						       netdev_handle,
						       NULL,
						       &tid.netdev,
						       &desc, &i_rights)) {
			*rights_p |= i_rights;
		} else {
			rsbac_acl_rights_vector_t mask;

			/* get mask to filter through */
			if (rsbac_ta_list_lol_get_data_ttl(ta_number,
							   netdev_handle,
							   NULL,
							   &tid.netdev,
							   &mask)) {
				/* no mask found, set default */
				mask = RSBAC_ACL_DEFAULT_NETDEV_MASK;
			}
			/* try default_dev_acl */
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_netdev_handle, NULL, &desc,
			     rights_p)) {
				*rights_p &= mask;
			} else {
				/* last resort: default rights */
				*rights_p = default_netdev_rights & mask;
			}
		}
		return 0;
#endif

#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
		/* rights to template itself */
	case T_NETTEMP_NT:
		/* default entry? */

		if (!tid.nettemp) {
			if (rsbac_ta_list_get_data_ttl
			    (ta_number, default_nettemp_nt_handle, NULL,
			     &desc, rights_p)) {
				/* last resort: default rights */
				*rights_p = default_nettemp_nt_rights;
			}
			return 0;
		}
		if (!rsbac_ta_net_template_exist(ta_number, tid.nettemp))
			return -RSBAC_EINVALIDTARGET;
		if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
						       nettemp_nt_handle,
						       NULL,
						       &tid.nettemp,
						       &desc, &i_rights)) {
			*rights_p |= i_rights;
		} else {
			rsbac_acl_rights_vector_t mask;

			/* get mask to filter through */
			if (rsbac_ta_list_lol_get_data_ttl(ta_number,
							   nettemp_nt_handle,
							   NULL,
							   &tid.nettemp,
							   &mask)) {
				/* no mask found, set default */
				mask = RSBAC_ACL_DEFAULT_NETTEMP_MASK;
			}
			/* try default_dev_acl */
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_nettemp_nt_handle, NULL,
			     &desc, rights_p)) {
				*rights_p &= mask;
			} else {
				/* last resort: default rights */
				*rights_p =
				    default_nettemp_nt_rights & mask;
			}
		}
		return 0;

		/* rights to netobjs fitting this template */
	case T_NETTEMP:
		/* default entry? */

		if (!tid.nettemp) {
			if (rsbac_ta_list_get_data_ttl
			    (ta_number, default_netobj_handle, NULL, &desc,
			     rights_p)) {
				/* last resort: default rights */
				*rights_p = default_netobj_rights;
			}
			return 0;
		}
		if (!rsbac_ta_net_template_exist(ta_number, tid.nettemp))
			return -RSBAC_EINVALIDTARGET;
		if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
						       nettemp_handle,
						       NULL,
						       &tid.nettemp,
						       &desc, &i_rights)) {
			*rights_p |= i_rights;
		} else {
			rsbac_acl_rights_vector_t mask;

			/* get mask to filter through */
			if (rsbac_ta_list_lol_get_data_ttl(ta_number,
							   nettemp_handle,
							   NULL,
							   &tid.nettemp,
							   &mask)) {
				/* no mask found, set default */
				mask = RSBAC_ACL_DEFAULT_NETOBJ_MASK;
			}
			/* try default_dev_acl */
			if (!rsbac_ta_list_get_data_ttl
			    (ta_number, default_netobj_handle, NULL, &desc,
			     rights_p)) {
				*rights_p &= mask;
			} else {
				/* last resort: default rights */
				*rights_p = default_netobj_rights & mask;
			}
		}
		return 0;

	case T_NETOBJ:
		/* default entry? */

		if (!tid.nettemp) {
			if (rsbac_ta_list_get_data_ttl
			    (ta_number, default_netobj_handle, NULL, &desc,
			     rights_p)) {
				/* last resort: default rights */
				*rights_p = default_netobj_rights;
			}
			return 0;
		}
		if (!rsbac_ta_list_lol_get_subdata_ttl(ta_number,
						       netobj_handle,
						       NULL,
						       &tid.netobj.sock_p,
						       &desc, &i_rights)) {
			*rights_p |= i_rights;
		} else {
			rsbac_acl_rights_vector_t mask;
			rsbac_net_temp_id_t temp = 0;

			/* get mask to filter through */
			if (rsbac_ta_list_lol_get_data_ttl(ta_number,
							   nettemp_handle,
							   NULL,
							   &temp, &mask)) {
				/* no mask found, set default */
				mask = RSBAC_ACL_DEFAULT_NETOBJ_MASK;
			}
			/* try nettemp_acl */
			if(!ta_number && tid.netobj.local_temp)
				temp = tid.netobj.local_temp;
			else
				rsbac_ta_net_lookup_templates(ta_number,
						      &tid.netobj,
						      &temp, NULL);

			if (temp
			    &&
			    !rsbac_ta_list_lol_get_subdata_ttl(ta_number,
							       nettemp_handle,
							       NULL, &temp,
							       &desc,
							       &i_rights))
			{
				*rights_p |= i_rights;
			} else {
				/* get mask to filter through */
				if (temp
				    &&
				    rsbac_ta_list_lol_get_data_ttl
				    (ta_number, nettemp_handle, NULL,
				     &temp, &mask)) {
					/* no mask found, set default */
					mask =
					    RSBAC_ACL_DEFAULT_NETOBJ_MASK;
				}
				/* try default_netobj_acl */
				if (!rsbac_ta_list_get_data_ttl
				    (ta_number, default_netobj_handle,
				     NULL, &desc, rights_p)) {
					*rights_p &= mask;
				} else {
					/* last resort: default rights */
					*rights_p =
					    default_netobj_rights & mask;
				}
			}
		}
		return 0;
#endif				/* NET_OBJ_PROT */

	default:
		return -RSBAC_EINVALIDTARGET;
	}
}

/* rsbac_acl_get_single_right
 * Show, whether individual right is set for given target and subject.
 * If right is not set, it is checked at all parents, unless it has been
 * masked out. (Special case SUPERVISOR: unless
 * CONFIG_RSBAC_ACL_SUPER_FILTER is set *and* supervisor has been masked out)
 */

int rsbac_acl_get_single_right(enum rsbac_target_t target,
			       union rsbac_target_id_t tid,
			       enum rsbac_acl_subject_type_t subj_type,
			       rsbac_acl_subject_id_t subj_id,
			       enum rsbac_adf_request_t right,
			       rsbac_boolean_t * result)
{
	struct rsbac_acl_device_list_item_t *device_p;
	rsbac_acl_rights_vector_t i_rvec;
	rsbac_acl_rights_vector_t i_rights;
	struct rsbac_acl_entry_desc_t desc;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_acl_get_single_right(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (!result)
		return -RSBAC_EINVALIDPOINTER;
	if ((subj_type >= ACLS_NONE)
	    || (right >= ACLR_NONE)
	    )
		return -RSBAC_EINVALIDVALUE;
#ifdef CONFIG_RSBAC_DEBUG
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_acl_get_single_right(): called from interrupt!\n");
	}
#endif
	i_rvec = (rsbac_acl_rights_vector_t) 1 << right;

	desc.subj_type = subj_type;
	desc.subj_id = subj_id;

	switch (target) {
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_UNIXSOCK:
		/* default entry? */
		if (RSBAC_IS_ZERO_DEV(tid.file.device) && !tid.file.inode
		    && !tid.file.dentry_p) {
			if (!rsbac_ta_list_get_data_ttl
			    (0, default_fd_handle, NULL, &desc,
			     &i_rights)) {
				if (i_rights & i_rvec)
					*result = TRUE;
				else
					*result = FALSE;
			} else {
				if (default_fd_rights & i_rvec)
					*result = TRUE;
				else
					*result = FALSE;
			}
			return 0;
		}
		srcu_idx = srcu_read_lock(&device_list_srcu);
		/* use loop for inheritance - used to be recursive calls */
		for (;;) {
			/* lookup device */
			device_p = acl_lookup_device(tid.file.device);
			if (!device_p) {
				rsbac_printk(KERN_WARNING "rsbac_acl_get_single_right(): Could not lookup device, blindly granting access!\n");
				srcu_read_unlock(&device_list_srcu, srcu_idx);
				*result = TRUE;
				return 0;
			}
			if (!rsbac_ta_list_lol_get_subdata_ttl(0,
							       device_p->handle,
							       NULL,
							       &tid.file.
							       inode,
							       &desc,
							       &i_rights)
			    ) {
				if (i_rights & i_rvec)
					*result = TRUE;
				else
					*result = FALSE;
				srcu_read_unlock(&device_list_srcu, srcu_idx);
				return 0;
			}

			{
				enum rsbac_target_t parent_target;
				union rsbac_target_id_t parent_tid;

#ifndef CONFIG_RSBAC_ACL_SUPER_FILTER
				if (right != ACLR_SUPERVISOR)
#endif
				{
					rsbac_acl_rights_vector_t mask;

					/* get mask to filter through */
					if (!rsbac_ta_list_lol_get_data_ttl
					    (0, device_p->handle,
					     NULL, &tid.file.inode, &mask)
					    && !(mask & i_rvec)
					    ) {
						srcu_read_unlock(&device_list_srcu, srcu_idx);
						*result = FALSE;
						return 0;
					}
				}

				/* inheritance possible? */
				if (!rsbac_get_parent
				    (target, tid, &parent_target,
				     &parent_tid)) {
					target = parent_target;
					tid = parent_tid;
					continue;
				} else {
					/* no inheritance possible -> try default_fd_acl */
					if (!rsbac_ta_list_get_data_ttl
					    (0, default_fd_handle, NULL,
					     &desc, &i_rights)
					    ) {
						if (i_rights & i_rvec)
							*result = TRUE;
						else
							*result = FALSE;
					} else {
						if (default_fd_rights &
						    i_rvec)
							*result = TRUE;
						else
							*result = FALSE;
					}
					/* free access to device_list_head - see above */
					srcu_read_unlock(&device_list_srcu, srcu_idx);
					return 0;
				}
			}
		}		/* end of for(;;) for inheritance */

	case T_DEV:
		if (RSBAC_IS_ZERO_DEV_DESC(tid.dev)) {
			if (!rsbac_ta_list_get_data_ttl
			    (0, default_dev_handle, NULL, &desc,
			     &i_rights)) {
				if (i_rights & i_rvec)
					*result = TRUE;
				else
					*result = FALSE;
			} else {
				if (default_dev_rights & i_rvec)
					*result = TRUE;
				else
					*result = FALSE;
			}
			return 0;
		}

		if (tid.dev.type >= D_block_major) {
			tid.dev.type -= (D_block_major - D_block);
			if (!rsbac_ta_list_lol_get_subdata_ttl
			    (0, dev_major_handle, NULL, &tid.dev, &desc,
			     &i_rights)
			    ) {
				if (i_rights & i_rvec)
					*result = TRUE;
				else
					*result = FALSE;
				return 0;
			}
#ifndef CONFIG_RSBAC_ACL_SUPER_FILTER
			if (right != ACLR_SUPERVISOR)
#endif
			{
				rsbac_acl_rights_vector_t mask;

				/* get mask to filter through */
				if (!rsbac_ta_list_lol_get_data_ttl
				    (0, dev_major_handle, NULL, &tid.dev,
				     &mask)
				    && !(mask & i_rvec)
				    ) {
					*result = FALSE;
					return 0;
				}
			}
			/* no inheritance possible -> try default acl */
			if (!rsbac_ta_list_get_data_ttl
			    (0, default_dev_handle, NULL, &desc, &i_rights)
			    ) {
				if (i_rights & i_rvec)
					*result = TRUE;
				else
					*result = FALSE;
			} else {
				if (default_dev_rights & i_rvec)
					*result = TRUE;
				else
					*result = FALSE;
			}
			return 0;
		}
		if (!rsbac_ta_list_lol_get_subdata_ttl(0, dev_handle,
						       NULL,
						       &tid.dev,
						       &desc, &i_rights)
		    ) {
			if (i_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
			return 0;
		}
#ifndef CONFIG_RSBAC_ACL_SUPER_FILTER
		if (right != ACLR_SUPERVISOR)
#endif
		{
			rsbac_acl_rights_vector_t mask;

			/* get mask to filter through */
			if (!rsbac_ta_list_lol_get_data_ttl(0, dev_handle,
							    NULL,
							    &tid.dev,
							    &mask)
			    && !(mask & i_rvec)
			    ) {
				*result = FALSE;
				return 0;
			}
		}
		if (!rsbac_ta_list_lol_get_subdata_ttl(0, dev_major_handle,
						       NULL,
						       &tid.dev,
						       &desc, &i_rights)
		    ) {
			if (i_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
			return 0;
		}
#ifndef CONFIG_RSBAC_ACL_SUPER_FILTER
		if (right != ACLR_SUPERVISOR)
#endif
		{
			rsbac_acl_rights_vector_t mask;

			/* get mask to filter through */
			if (!rsbac_ta_list_lol_get_data_ttl
			    (0, dev_major_handle, NULL, &tid.dev, &mask)
			    && !(mask & i_rvec)
			    ) {
				*result = FALSE;
				return 0;
			}
		}
		/* no inheritance possible -> try default acl */
		if (!rsbac_ta_list_get_data_ttl(0, default_dev_handle,
						NULL, &desc, &i_rights)
		    ) {
			if (i_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
		} else {
			if (default_dev_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
		}
		return 0;

	case T_IPC:
		/* Use default entry */
		if (!rsbac_ta_list_get_data_ttl(0, default_ipc_handle,
						NULL, &desc, &i_rights)) {
			if (i_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
		} else {
			if (default_ipc_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
		}
		return 0;

	case T_SCD:
		if (tid.scd == AST_none) {
			if (!rsbac_ta_list_get_data_ttl
			    (0, default_scd_handle, NULL, &desc,
			     &i_rights)) {
				if (i_rights & i_rvec)
					*result = TRUE;
				else
					*result = FALSE;
			} else {
				if (default_scd_rights & i_rvec)
					*result = TRUE;
				else
					*result = FALSE;
			}
			return 0;
		}

		if (!rsbac_ta_list_lol_get_subdata_ttl(0, scd_handle,
						       NULL,
						       &tid.scd,
						       &desc, &i_rights)
		    ) {
			if (i_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
			return 0;
		}
#ifndef CONFIG_RSBAC_ACL_SUPER_FILTER
		if (right != ACLR_SUPERVISOR)
#endif
		{
			rsbac_acl_rights_vector_t mask;

			/* get mask to filter through */
			if (!rsbac_ta_list_lol_get_data_ttl(0, scd_handle,
							    NULL,
							    &tid.scd,
							    &mask)
			    && !(mask & i_rvec)
			    ) {
				*result = FALSE;
				return 0;
			}
		}

		/* no inheritance possible -> try default acl */
		if (!rsbac_ta_list_get_data_ttl(0, default_scd_handle,
						NULL, &desc, &i_rights)
		    ) {
			if (i_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
		} else {
			if (default_scd_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
		}
		return 0;

	case T_USER:
		if (tid.user == RSBAC_NO_USER) {
			if (!rsbac_ta_list_get_data_ttl
			    (0, default_u_handle, NULL, &desc,
			     &i_rights)) {
				if (i_rights & i_rvec)
					*result = TRUE;
				else
					*result = FALSE;
			} else {
				if (default_u_rights & i_rvec)
					*result = TRUE;
				else
					*result = FALSE;
			}
			return 0;
		}

		if (!rsbac_ta_list_lol_get_subdata_ttl(0, u_handle,
						       NULL,
						       &tid.user,
						       &desc, &i_rights)
		    ) {
			if (i_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
			return 0;
		}
#ifndef CONFIG_RSBAC_ACL_SUPER_FILTER
		if (right != ACLR_SUPERVISOR)
#endif
		{
			rsbac_acl_rights_vector_t mask;

			/* get mask to filter through */
			if (!rsbac_ta_list_lol_get_data_ttl(0, u_handle,
							    NULL,
							    &tid.user,
							    &mask)
			    && !(mask & i_rvec)
			    ) {
				*result = FALSE;
				return 0;
			}
		}

		/* no inheritance possible -> try default acl */
		if (!rsbac_ta_list_get_data_ttl(0, default_u_handle,
						NULL, &desc, &i_rights)
		    ) {
			if (i_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
		} else {
			if (default_u_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
		}
		return 0;

	case T_PROCESS:
		/* Use default entry */
		if (!rsbac_ta_list_get_data_ttl(0, default_p_handle,
						NULL, &desc, &i_rights)) {
			if (i_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
		} else {
			if (default_p_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
		}
		return 0;

#ifdef CONFIG_RSBAC_ACL_UM_PROT
	case T_GROUP:
		if (tid.group == RSBAC_NO_GROUP) {
			if (!rsbac_ta_list_get_data_ttl
			    (0, default_g_handle, NULL, &desc,
			     &i_rights)) {
				if (i_rights & i_rvec)
					*result = TRUE;
				else
					*result = FALSE;
			} else {
				if (default_g_rights & i_rvec)
					*result = TRUE;
				else
					*result = FALSE;
			}
			return 0;
		}

		if (!rsbac_ta_list_lol_get_subdata_ttl(0, g_handle,
						       NULL,
						       &tid.group,
						       &desc, &i_rights)
		    ) {
			if (i_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
			return 0;
		}
#ifndef CONFIG_RSBAC_ACL_SUPER_FILTER
		if (right != ACLR_SUPERVISOR)
#endif
		{
			rsbac_acl_rights_vector_t mask;

			/* get mask to filter through */
			if (!rsbac_ta_list_lol_get_data_ttl(0, g_handle,
							    NULL,
							    &tid.group,
							    &mask)
			    && !(mask & i_rvec)
			    ) {
				*result = FALSE;
				return 0;
			}
		}

		/* no inheritance possible -> try default acl */
		if (!rsbac_ta_list_get_data_ttl(0, default_g_handle,
						NULL, &desc, &i_rights)
		    ) {
			if (i_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
		} else {
			if (default_g_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
		}
		return 0;
#endif

#if defined(CONFIG_RSBAC_ACL_NET_DEV_PROT)
	case T_NETDEV:
		if (!tid.netdev[0]) {
			if (!rsbac_ta_list_get_data_ttl
			    (0, default_netdev_handle, NULL, &desc,
			     &i_rights)) {
				if (i_rights & i_rvec)
					*result = TRUE;
				else
					*result = FALSE;
			} else {
				if (default_netdev_rights & i_rvec)
					*result = TRUE;
				else
					*result = FALSE;
			}
			return 0;
		}

		if (!rsbac_ta_list_lol_get_subdata_ttl(0, netdev_handle,
						       NULL,
						       &tid.netdev,
						       &desc, &i_rights)
		    ) {
			if (i_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
			return 0;
		}
#ifndef CONFIG_RSBAC_ACL_SUPER_FILTER
		if (right != ACLR_SUPERVISOR)
#endif
		{
			rsbac_acl_rights_vector_t mask;

			/* get mask to filter through */
			if (!rsbac_ta_list_lol_get_data_ttl
			    (0, netdev_handle, NULL, &tid.netdev, &mask)
			    && !(mask & i_rvec)
			    ) {
				*result = FALSE;
				return 0;
			}
		}

		/* no inheritance possible -> try default acl */
		if (!rsbac_ta_list_get_data_ttl(0, default_netdev_handle,
						NULL, &desc, &i_rights)
		    ) {
			if (i_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
		} else {
			if (default_netdev_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
		}
		return 0;
#endif

#if defined(CONFIG_RSBAC_ACL_NET_OBJ_PROT)
	case T_NETTEMP_NT:
	case T_NETTEMP:
		if (!tid.nettemp) {
			if (!rsbac_ta_list_get_data_ttl
			    (0, default_nettemp_nt_handle, NULL, &desc,
			     &i_rights)) {
				if (i_rights & i_rvec)
					*result = TRUE;
				else
					*result = FALSE;
			} else {
				if (default_nettemp_nt_rights & i_rvec)
					*result = TRUE;
				else
					*result = FALSE;
			}
			return 0;
		}

		/* There should be no template, which is to be created, so skip nettemp_nt list */
		if (right != R_CREATE) {
			if (!rsbac_net_template_exist(tid.nettemp))
				return FALSE;
			if (!rsbac_ta_list_lol_get_subdata_ttl
			    (0, nettemp_nt_handle, NULL, &tid.nettemp,
			     &desc, &i_rights)
			    && (i_rights & i_rvec)
			    ) {
				*result = TRUE;
				return 0;
			}
#ifndef CONFIG_RSBAC_ACL_SUPER_FILTER
			if (right != ACLR_SUPERVISOR)
#endif
			{
				rsbac_acl_rights_vector_t mask;

				/* get mask to filter through */
				if (!rsbac_ta_list_lol_get_data_ttl
				    (0, nettemp_nt_handle, NULL,
				     &tid.nettemp, &mask)
				    && !(mask & i_rvec)
				    ) {
					*result = FALSE;
					return 0;
				}
			}
		}

		/* no inheritance possible -> try default acl */
		if (!rsbac_ta_list_get_data_ttl
		    (0, default_nettemp_nt_handle, NULL, &desc, &i_rights)
		    ) {
			if (i_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
		} else {
			if (default_nettemp_nt_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
		}
		return 0;

	case T_NETOBJ:
		if (!tid.netobj.sock_p) {
			if (!rsbac_ta_list_get_data_ttl
			    (0, default_netobj_handle, NULL, &desc,
			     &i_rights)) {
				if (i_rights & i_rvec)
					*result = TRUE;
				else
					*result = FALSE;
			} else {
				if (default_netobj_rights & i_rvec)
					*result = TRUE;
				else
					*result = FALSE;
			}
			return 0;
		}

		if (!rsbac_ta_list_lol_get_subdata_ttl(0, netobj_handle,
						       NULL,
						       &tid.netobj.sock_p,
						       &desc, &i_rights)
		    ) {
			if (i_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
			return 0;
		}
#ifndef CONFIG_RSBAC_ACL_SUPER_FILTER
		if (right != ACLR_SUPERVISOR)
#endif
		{
			rsbac_acl_rights_vector_t mask;

			/* get mask to filter through */
			if (!rsbac_ta_list_lol_get_data_ttl
			    (0, netobj_handle, NULL, &tid.netobj.sock_p,
			     &mask)
			    && !(mask & i_rvec)
			    ) {
				*result = FALSE;
				return 0;
			}
		}
		/* Try net template */
		{
			rsbac_net_temp_id_t temp = 0;

			if (rsbac_net_remote_request(right)) {
				if(tid.netobj.remote_temp)
					temp = tid.netobj.remote_temp;
				else
					rsbac_ta_net_lookup_templates(0,
							      &tid.netobj,
							      NULL, &temp);
			} else {
				if(tid.netobj.local_temp)
					temp = tid.netobj.local_temp;
				else
					rsbac_ta_net_lookup_templates(0,
							      &tid.netobj,
							      &temp, NULL);
			}
			if (temp
			    && !rsbac_ta_list_lol_get_subdata_ttl(0,
								  nettemp_handle,
								  NULL,
								  &temp,
								  &desc,
								  &i_rights)
			    ) {
				if (i_rights & i_rvec)
					*result = TRUE;
				else
					*result = FALSE;
				return 0;
			}
#ifndef CONFIG_RSBAC_ACL_SUPER_FILTER
			if (right != ACLR_SUPERVISOR)
#endif
			{
				rsbac_acl_rights_vector_t mask;

				/* get mask from template to filter through */
				if (!rsbac_ta_list_lol_get_data_ttl
				    (0, nettemp_handle, NULL, &temp, &mask)
				    && !(mask & i_rvec)
				    ) {
					*result = FALSE;
					return 0;
				}
			}
		}

		/* no inheritance possible -> try default acl */
		if (!rsbac_ta_list_get_data_ttl(0, default_netobj_handle,
						NULL, &desc, &i_rights)
		    ) {
			if (i_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
		} else {
			if (default_netobj_rights & i_rvec)
				*result = TRUE;
			else
				*result = FALSE;
		}
		return 0;
#endif				/* NET_OBJ_PROT */

	default:
		return -RSBAC_EINVALIDTARGET;
	}
}

/*************************************************
 * rsbac_acl_get_tlist
 * Get subjects from ACL entries for given target.
 */

int rsbac_acl_get_tlist(rsbac_list_ta_number_t ta_number,
			enum rsbac_target_t target,
			union rsbac_target_id_t tid,
			struct rsbac_acl_entry_t **entry_pp,
			rsbac_time_t ** ttl_pp)
{
	int count = 0;
	struct rsbac_acl_device_list_item_t *device_p;
	int srcu_idx;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_acl_get_tlist(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (!entry_pp)
		return -RSBAC_EINVALIDPOINTER;
#ifdef CONFIG_RSBAC_DEBUG
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_acl_get_tlist(): called from interrupt!\n");
	}
#endif
	switch (target) {
	case T_FD:
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_UNIXSOCK:
		/* default entry? */
		if (RSBAC_IS_ZERO_DEV(tid.file.device) && !tid.file.inode
		    && !tid.file.dentry_p)
			return rsbac_ta_list_get_all_items_ttl(ta_number,
							       default_fd_handle,
							       (void **)
							       entry_pp,
							       ttl_pp);
		srcu_idx = srcu_read_lock(&device_list_srcu);
		/* lookup device */
		device_p = acl_lookup_device(tid.file.device);
		if (!device_p) {
			rsbac_printk(KERN_WARNING "rsbac_acl_get_tlist(): Could not lookup device!\n");
			srcu_read_unlock(&device_list_srcu, srcu_idx);
			return -RSBAC_EINVALIDDEV;
		}
		/* protect this list */
		count = rsbac_ta_list_lol_get_all_subitems_ttl(ta_number,
							       device_p->
							       handle,
							       &tid.file.
							       inode,
							       (void **)
							       entry_pp,
							       ttl_pp);
		srcu_read_unlock(&device_list_srcu, srcu_idx);
		return count;

	case T_DEV:
		if (RSBAC_IS_ZERO_DEV_DESC(tid.dev))
			return rsbac_ta_list_get_all_items_ttl(ta_number,
							       default_dev_handle,
							       (void **)
							       entry_pp,
							       ttl_pp);
		else
			switch (tid.dev.type) {
			case D_char:
			case D_block:
				return
				    rsbac_ta_list_lol_get_all_subitems_ttl
				    (ta_number, dev_handle, &tid.dev,
				     (void **) entry_pp, ttl_pp);

			case D_char_major:
			case D_block_major:
				tid.dev.type -= (D_block_major - D_block);
				return
				    rsbac_ta_list_lol_get_all_subitems_ttl
				    (ta_number, dev_major_handle, &tid.dev,
				     (void **) entry_pp, ttl_pp);

			default:
				return -RSBAC_EINVALIDTARGET;
			}

	case T_IPC:
		/* default entry */
		return rsbac_ta_list_get_all_items_ttl(ta_number,
						       default_ipc_handle,
						       (void **) entry_pp,
						       ttl_pp);

	case T_SCD:
		if ((tid.scd == AST_none)
		    || (tid.scd == ST_none)
		    )
			return rsbac_ta_list_get_all_items_ttl(ta_number,
							       default_scd_handle,
							       (void **)
							       entry_pp,
							       ttl_pp);
		else
			return
			    rsbac_ta_list_lol_get_all_subitems_ttl
			    (ta_number, scd_handle, &tid.scd,
			     (void **) entry_pp, ttl_pp);

	case T_USER:
		if (tid.user == RSBAC_NO_USER)
			return rsbac_ta_list_get_all_items_ttl(ta_number,
							       default_u_handle,
							       (void **)
							       entry_pp,
							       ttl_pp);
		else
			return
			    rsbac_ta_list_lol_get_all_subitems_ttl
			    (ta_number, u_handle, &tid.user,
			     (void **) entry_pp, ttl_pp);

	case T_PROCESS:
		return rsbac_ta_list_get_all_items_ttl(ta_number,
						       default_p_handle,
						       (void **) entry_pp,
						       ttl_pp);

#ifdef CONFIG_RSBAC_ACL_UM_PROT
	case T_GROUP:
		if (tid.group == RSBAC_NO_GROUP)
			return rsbac_ta_list_get_all_items_ttl(ta_number,
							       default_g_handle,
							       (void **)
							       entry_pp,
							       ttl_pp);
		else
			return
			    rsbac_ta_list_lol_get_all_subitems_ttl
			    (ta_number, g_handle, &tid.group,
			     (void **) entry_pp, ttl_pp);
#endif

#if defined(CONFIG_RSBAC_ACL_NET_DEV_PROT)
	case T_NETDEV:
		if (!tid.netdev[0])
			return rsbac_ta_list_get_all_items_ttl(ta_number,
							       default_netdev_handle,
							       (void **)
							       entry_pp,
							       ttl_pp);
		else
			return
			    rsbac_ta_list_lol_get_all_subitems_ttl
			    (ta_number, netdev_handle, &tid.netdev,
			     (void **) entry_pp, ttl_pp);
#endif

#if defined(CONFIG_RSBAC_ACL_NET_OBJ_PROT)
	case T_NETTEMP_NT:
		if (!tid.nettemp)
			return rsbac_ta_list_get_all_items_ttl(ta_number,
							       default_nettemp_nt_handle,
							       (void **)
							       entry_pp,
							       ttl_pp);
		if (!rsbac_ta_net_template_exist(ta_number, tid.nettemp))
			return -RSBAC_EINVALIDTARGET;
		return rsbac_ta_list_lol_get_all_subitems_ttl(ta_number,
							      nettemp_nt_handle,
							      &tid.nettemp,
							      (void **)
							      entry_pp,
							      ttl_pp);

	case T_NETTEMP:
		if (!tid.nettemp)
			return -RSBAC_EINVALIDTARGET;
		if (!rsbac_ta_net_template_exist(ta_number, tid.nettemp))
			return -RSBAC_EINVALIDTARGET;
		return rsbac_ta_list_lol_get_all_subitems_ttl(ta_number,
							      nettemp_handle,
							      &tid.nettemp,
							      (void **)
							      entry_pp,
							      ttl_pp);

	case T_NETOBJ:
		if (!tid.nettemp)
			return rsbac_ta_list_get_all_items_ttl(ta_number,
							       default_netobj_handle,
							       (void **)
							       entry_pp,
							       ttl_pp);
		else
			return
			    rsbac_ta_list_lol_get_all_subitems_ttl
			    (ta_number, netobj_handle, &tid.netobj.sock_p,
			     (void **) entry_pp, ttl_pp);
#endif				/* NET_OBJ_PROT */

	default:
		return -RSBAC_EINVALIDTARGET;
	}
}

/* Remove a subject from all acls (but not from group memberships, see remove_user) */
int rsbac_acl_remove_subject(rsbac_list_ta_number_t ta_number,
			     struct rsbac_acl_entry_desc_t desc)
{
	struct rsbac_acl_device_list_item_t *device_p;
	int srcu_idx;

	if (desc.subj_type >= ACLS_NONE)
		return -RSBAC_EINVALIDVALUE;

	/* remove from default ACLs */
	rsbac_ta_list_remove(ta_number, default_fd_handle, &desc);
	rsbac_ta_list_remove(ta_number, default_dev_handle, &desc);
	rsbac_ta_list_remove(ta_number, default_ipc_handle, &desc);
	rsbac_ta_list_remove(ta_number, default_scd_handle, &desc);
	rsbac_ta_list_remove(ta_number, default_u_handle, &desc);
	rsbac_ta_list_remove(ta_number, default_p_handle, &desc);
#ifdef CONFIG_RSBAC_ACL_UM_PROT
	rsbac_ta_list_remove(ta_number, default_g_handle, &desc);
#endif
#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
	rsbac_ta_list_remove(ta_number, default_netdev_handle, &desc);
#endif
#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
	rsbac_ta_list_remove(ta_number, default_nettemp_nt_handle, &desc);
	rsbac_ta_list_remove(ta_number, default_netobj_handle, &desc);
#endif

	srcu_idx = srcu_read_lock(&device_list_srcu);
	device_p = rcu_dereference(device_list_head_p)->head;
	while (device_p) {
		rsbac_ta_list_lol_subremove_from_all(ta_number,
						     device_p->handle,
						     &desc);
		device_p = device_p->next;
	}
	srcu_read_unlock(&device_list_srcu, srcu_idx);

	/* dev list */
	rsbac_ta_list_lol_subremove_from_all(ta_number, dev_major_handle,
					     &desc);
	rsbac_ta_list_lol_subremove_from_all(ta_number, dev_handle, &desc);

	/* scd list */
	rsbac_ta_list_lol_subremove_from_all(ta_number, scd_handle, &desc);

	/* user list */
	rsbac_ta_list_lol_subremove_from_all(ta_number, u_handle, &desc);

#ifdef CONFIG_RSBAC_ACL_UM_PROT
	/* Linux group list */
	rsbac_ta_list_lol_subremove_from_all(ta_number, g_handle, &desc);
#endif

#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
	/* netdev list */
	rsbac_ta_list_lol_subremove_from_all(ta_number, netdev_handle,
					     &desc);
#endif
#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
	rsbac_ta_list_lol_subremove_from_all(ta_number, nettemp_nt_handle,
					     &desc);
	rsbac_ta_list_lol_subremove_from_all(ta_number, nettemp_handle,
					     &desc);
	rsbac_ta_list_lol_subremove_from_all(ta_number, netobj_handle,
					     &desc);
#endif

	return 0;
}

/* add a group with new id and fill this id into *group_id_p */
/* if old content of group_id_p is 0, make new id, else try given id */
int rsbac_acl_add_group(rsbac_list_ta_number_t ta_number,
			rsbac_uid_t owner,
			enum rsbac_acl_group_type_t type,
			char *name, rsbac_acl_group_id_t * group_id_p)
{
	struct rsbac_acl_group_entry_t entry;
	int err = 0;

	if (type >= ACLG_NONE)
		return -RSBAC_EINVALIDVALUE;
	if (!name || !group_id_p)
		return -RSBAC_EINVALIDPOINTER;
	if (!name[0])
		return -RSBAC_EINVALIDVALUE;
	entry.owner = owner;
	entry.type = type;
	strncpy(entry.name, name, RSBAC_ACL_GROUP_NAMELEN - 1);
	entry.name[RSBAC_ACL_GROUP_NAMELEN - 1] = 0;
	if (!*group_id_p) {
		/* step new group counter */
		group_last_new++;
		/* Just in case the counter has wrapped. It is almost impossible that all IDs are in use. */
		while (!group_last_new
		       || rsbac_ta_list_exist(ta_number, group_handle,
					      &group_last_new))
			group_last_new++;

		entry.id = group_last_new;
	} else {
		if (rsbac_ta_list_exist
		    (ta_number, group_handle, group_id_p)) {
			return -RSBAC_EEXISTS;
		} else
			entry.id = *group_id_p;
	}
	if (rsbac_ta_list_add_ttl
	    (ta_number, group_handle, 0, &entry.id, &entry))
		err = -RSBAC_ECOULDNOTADDITEM;
	else {
		*group_id_p = entry.id;
	}
	return err;
}

int rsbac_acl_change_group(rsbac_list_ta_number_t ta_number,
			   rsbac_acl_group_id_t id,
			   rsbac_uid_t owner,
			   enum rsbac_acl_group_type_t type, char *name)
{
	struct rsbac_acl_group_entry_t entry;

	if (!id)
		return -RSBAC_EINVALIDVALUE;
	if (!rsbac_ta_list_exist(ta_number, group_handle, &id))
		return -RSBAC_ENOTFOUND;
	if (!name)
		return -RSBAC_EINVALIDPOINTER;
	if (!name[0])
		return -RSBAC_EINVALIDVALUE;
	entry.id = id;
	entry.owner = owner;
	entry.type = type;
	strncpy(entry.name, name, RSBAC_ACL_GROUP_NAMELEN);
	entry.name[RSBAC_ACL_GROUP_NAMELEN - 1] = 0;
	return rsbac_ta_list_add_ttl(ta_number, group_handle, 0, &entry.id,
				     &entry);
}

int rsbac_acl_remove_group(rsbac_list_ta_number_t ta_number,
			   rsbac_acl_group_id_t id)
{
	int err = 0;

	if (!id)
		return -RSBAC_EINVALIDVALUE;

	err = rsbac_ta_list_remove(ta_number, group_handle, &id);
	if (!err) {
		struct rsbac_acl_entry_desc_t desc;

		/* cleanup group memberships */
		rsbac_ta_list_lol_subremove_from_all(ta_number, gm_handle,
						     &id);
		desc.subj_type = ACLS_GROUP;
		desc.subj_id = id;
		err = rsbac_acl_remove_subject(ta_number, desc);
	}
	return err;
}

int rsbac_acl_get_group_entry(rsbac_list_ta_number_t ta_number,
			      rsbac_acl_group_id_t group,
			      struct rsbac_acl_group_entry_t *entry_p)
{
	if (!group)
		return -RSBAC_EINVALIDVALUE;
	if (!entry_p)
		return -RSBAC_EINVALIDPOINTER;
	return rsbac_ta_list_get_data_ttl(ta_number, group_handle, NULL,
					  &group, entry_p);
}

int rsbac_acl_list_groups(rsbac_list_ta_number_t ta_number,
			  rsbac_uid_t owner,
			  rsbac_boolean_t include_global,
			  struct rsbac_acl_group_entry_t **entry_pp)
{
	long count;
	struct rsbac_acl_group_entry_t *local_entry_p;

	if (!entry_pp)
		return -RSBAC_EINVALIDPOINTER;
	count =
	    rsbac_ta_list_get_all_data(ta_number, group_handle,
				       (void **) &local_entry_p);
	if (count > 0) {
		long i;
		long rescount = 0;

		*entry_pp = rsbac_kmalloc(count * sizeof(**entry_pp));
		if (!*entry_pp) {
			rsbac_kfree(local_entry_p);
			return -RSBAC_ENOMEM;
		}
		for (i = 0; i < count; i++) {
			if ((local_entry_p[i].owner == owner)
			    || (include_global
				&& (local_entry_p[i].type == ACLG_GLOBAL)
			    )
			    ) {
				memcpy(&(*entry_pp)[rescount],
				       &local_entry_p[i],
				       sizeof(local_entry_p[i]));
				rescount++;
			}
		}
		rsbac_kfree(local_entry_p);
		count = rescount;
	}
	return count;
}

/* check group existence */
rsbac_boolean_t rsbac_acl_group_exist(rsbac_acl_group_id_t group)
{
	if (!group)
		return TRUE;
	return rsbac_ta_list_exist(0, group_handle, &group);
}

int rsbac_acl_add_group_member(rsbac_list_ta_number_t ta_number,
			       rsbac_acl_group_id_t group,
			       rsbac_uid_t user, rsbac_time_t ttl)
{
	int err = 0;

	if (!group)
		return -RSBAC_EINVALIDVALUE;
	if (!rsbac_ta_list_exist(ta_number, group_handle, &group))
		return -RSBAC_EINVALIDVALUE;

	if (!rsbac_ta_list_lol_exist(ta_number, gm_handle, &user)) {
		err =
		    rsbac_ta_list_lol_add_ttl(ta_number, gm_handle, 0,
					      &user, NULL);
		if (err)
			return err;
	}
	return rsbac_ta_list_lol_subadd_ttl(ta_number, gm_handle, ttl,
					    &user, &group, NULL);
}

int rsbac_acl_remove_group_member(rsbac_list_ta_number_t ta_number,
				  rsbac_acl_group_id_t group,
				  rsbac_uid_t user)
{
	int err;

	if (!group)
		return -RSBAC_EINVALIDVALUE;
	if (!rsbac_ta_list_exist(ta_number, group_handle, &group))
		return -RSBAC_EINVALIDVALUE;

	err =
	    rsbac_ta_list_lol_subremove(ta_number, gm_handle, &user,
					&group);
	/* cleanup empty gm items */
	if (!err
	    && !rsbac_ta_list_lol_subcount(ta_number, gm_handle, &user)
	    )
		err =
		    rsbac_ta_list_lol_remove(ta_number, gm_handle, &user);

	return err;
}

/* check membership */
rsbac_boolean_t rsbac_acl_group_member(rsbac_acl_group_id_t group,
				       rsbac_uid_t user)
{
	return rsbac_ta_list_lol_subexist(0, gm_handle, &user, &group);
}

/* build vmalloc'd array of all group memberships of the given user */
/* returns number of groups or negative error */
/* Attention: memory deallocation with rsbac_kfree (if result > 0) must be done by caller! */
int rsbac_acl_get_user_groups(rsbac_list_ta_number_t ta_number,
			      rsbac_uid_t user,
			      rsbac_acl_group_id_t ** group_pp,
			      rsbac_time_t ** ttl_pp)
{
	return rsbac_ta_list_lol_get_all_subdesc_ttl(ta_number,
						     gm_handle,
						     &user,
						     (void **) group_pp,
						     ttl_pp);
}

/* Returns number of members or negative error */
int rsbac_acl_get_group_members(rsbac_list_ta_number_t ta_number,
				rsbac_acl_group_id_t group,
				rsbac_uid_t user_array[],
				rsbac_time_t ttl_array[], int maxnum)
{
	long desc_count;
	long i;
	rsbac_uid_t *user_p;
	int err = 0;

	if (!group || (maxnum <= 0))
		return -RSBAC_EINVALIDVALUE;
	if (!rsbac_ta_list_exist(ta_number, group_handle, &group))
		return -RSBAC_EINVALIDVALUE;
	if (!user_array)
		return -RSBAC_EINVALIDPOINTER;

	/* traverse group memberships */
	desc_count =
	    rsbac_ta_list_lol_get_all_desc(ta_number, gm_handle,
					   (void **) &user_p);
	if (desc_count > 0) {
		rsbac_time_t ttl;

		for (i = 0; i < desc_count; i++) {
			if (!rsbac_ta_list_lol_get_subdata_ttl
			    (ta_number, gm_handle, &ttl, &user_p[i],
			     &group, NULL)) {
				user_array[err] = user_p[i];
				if (ttl_array)
					ttl_array[err] = ttl;
				err++;
				if (err >= maxnum)
					break;
			}
		}
		rsbac_kfree(user_p);
	}
	return err;
}

int rsbac_acl_list_all_dev(rsbac_list_ta_number_t ta_number,
			   struct rsbac_dev_desc_t **id_pp)
{
	if (id_pp)
		return rsbac_ta_list_lol_get_all_desc(ta_number,
						      dev_handle,
						      (void **) id_pp);
	else
		return rsbac_ta_list_lol_count(ta_number, dev_handle);
}

int rsbac_acl_list_all_major_dev(rsbac_list_ta_number_t ta_number,
				 struct rsbac_dev_desc_t **id_pp)
{
	if (id_pp) {
		int count;

		count =
		    rsbac_ta_list_lol_get_all_desc(ta_number,
						   dev_major_handle,
						   (void **) id_pp);
		if (count > 0) {
			u_int i;
			struct rsbac_dev_desc_t *tmp_p;

			tmp_p = *id_pp;
			for (i = 0; i < count; i++)
				tmp_p[i].type += (D_block_major - D_block);
		}
		return count;
	} else
		return rsbac_ta_list_lol_count(ta_number,
					       dev_major_handle);
}

int rsbac_acl_list_all_user(rsbac_list_ta_number_t ta_number,
			    rsbac_uid_t ** id_pp)
{
	if (id_pp)
		return rsbac_ta_list_lol_get_all_desc(ta_number, u_handle,
						      (void **) id_pp);
	else
		return rsbac_ta_list_lol_count(ta_number, u_handle);
}

#ifdef CONFIG_RSBAC_ACL_UM_PROT
int rsbac_acl_list_all_group(rsbac_list_ta_number_t ta_number,
			     rsbac_gid_t ** id_pp)
{
	if (id_pp)
		return rsbac_ta_list_lol_get_all_desc(ta_number, g_handle,
						      (void **) id_pp);
	else
		return rsbac_ta_list_lol_count(ta_number, g_handle);
}
#endif

/********************************************/
/* remove user from all groups and all ACLs */
int rsbac_acl_remove_user(rsbac_list_ta_number_t ta_number,
			  rsbac_uid_t user)
{
	u_long i;
	struct rsbac_acl_group_entry_t *entry_p;
	long desc_count;
	struct rsbac_acl_entry_desc_t desc;

	rsbac_ta_list_lol_remove(ta_number, gm_handle, &user);
	/* traverse groups for this owner */
	desc_count =
	    rsbac_ta_list_get_all_data(ta_number, group_handle,
				       (void **) &entry_p);
	if (desc_count > 0) {
		for (i = 0; i < desc_count; i++) {
			if (entry_p[i].owner == user) {
				rsbac_ta_list_remove(ta_number,
						     group_handle,
						     &entry_p[i].id);
				/* cleanup group memberships */
				rsbac_ta_list_lol_subremove_from_all
				    (ta_number, gm_handle, &entry_p[i].id);
			}
		}
		rsbac_kfree(entry_p);
	}

	desc.subj_type = ACLS_USER;
	desc.subj_id = user;

	return rsbac_acl_remove_subject(ta_number, desc);
}
