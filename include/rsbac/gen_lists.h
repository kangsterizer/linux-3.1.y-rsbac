/*************************************************** */
/* Rule Set Based Access Control                     */
/* Author and (c) 1999-2010: Amon Ott <ao@rsbac.org> */
/* Generic lists - internal structures               */
/* Last modified: 01/Jul/2010                        */
/*************************************************** */

#ifndef __RSBAC_GEN_LISTS_H
#define __RSBAC_GEN_LISTS_H

#include <linux/init.h>
#include <rsbac/rkmem.h>
#include <rsbac/lists.h>
#include <rsbac/repl_lists.h>

/* Sanity limit of list size, regardless of RSBAC_LIST_MAX_NR_ITEMS in lists.h */
#define RSBAC_LIST_MAX_NR_ITEMS_LIMIT 1000000

#define RSBAC_LIST_DISK_VERSION 10003
#define RSBAC_LIST_DISK_OLD_VERSION 10002
#define RSBAC_LIST_NONAME "(no name)"
#define RSBAC_LIST_PROC_NAME "gen_lists"
#define RSBAC_LIST_COUNTS_PROC_NAME "gen_lists_counts"

#define RSBAC_LIST_TA_KEY 0xface99

#define RSBAC_LIST_MAX_OLD_HASH 32
#define RSBAC_LIST_LOL_MAX_OLD_HASH 16

/* If number of items per hashed list is bigger than this and flag
   RSBAC_LIST_AUTO_HASH_RESIZE is set, rehash */
#define RSBAC_LIST_AUTO_REHASH_TRIGGER 30

/* Rehashing interval in s - rehashing is triggered by rsbacd, so might happen
 * less frequently, if rsbacd wakes up later.
 */
#define RSBAC_LIST_REHASH_INTERVAL 60

/* Check lists every n seconds. Also called from rsbacd, so might take longer. */

//#define RSBAC_LIST_CHECK_INTERVAL 1800

/* Prototypes */

/* Init */
#ifdef CONFIG_RSBAC_INIT_DELAY
int rsbac_list_init(void);
#else
int __init rsbac_list_init(void);
#endif

/* Status checking */
int rsbac_check_lists(int correct);

#if defined(CONFIG_RSBAC_AUTO_WRITE)
int rsbac_write_lists(void);
#endif

/* Data Structures */

/* All items will be organized in double linked lists
 * However, we do not know the descriptor or item sizes, so we will access them
   with offsets later and only define the list links here.
 */

struct rsbac_list_item_t {
	struct rsbac_list_item_t *prev;
	struct rsbac_list_item_t *next;
	rsbac_time_t max_age;
};

/* lists of lists ds */
struct rsbac_list_lol_item_t {
	struct rsbac_list_lol_item_t *prev;
	struct rsbac_list_lol_item_t *next;
	struct rsbac_list_item_t *head;
	struct rsbac_list_item_t *tail;
	struct rsbac_list_item_t *curr;
	u_long count;
	rsbac_time_t max_age;
};

typedef __u32 rsbac_list_count_t;

struct rsbac_list_hashed_t {
	struct rsbac_list_item_t *head;
	struct rsbac_list_item_t *tail;
	struct rsbac_list_item_t *curr;
	rsbac_list_count_t count;
#ifdef CONFIG_RSBAC_LIST_TRANS
	rsbac_ta_number_t ta_copied;
	struct rsbac_list_item_t *ta_head;
	struct rsbac_list_item_t *ta_tail;
	struct rsbac_list_item_t *ta_curr;
	rsbac_list_count_t ta_count;
#endif
};

struct rsbac_list_lol_hashed_t {
	struct rsbac_list_lol_item_t *head;
	struct rsbac_list_lol_item_t *tail;
	struct rsbac_list_lol_item_t *curr;
	rsbac_list_count_t count;
#ifdef CONFIG_RSBAC_LIST_TRANS
	rsbac_ta_number_t ta_copied;
	struct rsbac_list_lol_item_t *ta_head;
	struct rsbac_list_lol_item_t *ta_tail;
	struct rsbac_list_lol_item_t *ta_curr;
	rsbac_list_count_t ta_count;
#endif
};

/* Since all registrations will be organized in double linked lists, we must
 * have list items and a list head.
 * The pointer to this item will also be used as list handle. */

struct rsbac_list_reg_item_t {
	struct rsbac_list_info_t info;
	u_int flags;
	rsbac_list_compare_function_t *compare;
	rsbac_list_get_conv_t *get_conv;
	void *def_data;
	char name[RSBAC_LIST_MAX_FILENAME + 1];
	kdev_t device;
	spinlock_t lock;
	struct rsbac_list_rcu_free_head_t * rcu_free;
	rsbac_boolean_t dirty;
	rsbac_boolean_t no_write;
	struct rsbac_nanotime_t lastchange;
#ifdef CONFIG_RSBAC_LIST_STATS
	__u64 read_count;
	__u64 write_count;
#endif
	u_int nr_hashes;
	u_int max_items_per_hash;
	rsbac_list_hash_function_t * hash_function;
	char old_name_base[RSBAC_LIST_MAX_FILENAME + 1];
	struct kmem_cache * slab;
	char * slabname;
#if defined(CONFIG_RSBAC_PROC) && defined(CONFIG_PROC_FS)
	struct proc_dir_entry *proc_entry_p;
#endif
	struct rsbac_list_reg_item_t *prev;
	struct rsbac_list_reg_item_t *next;
	struct rsbac_list_reg_item_t *self;
	/* The hashed list heads are allocated dynamically! */
	struct rsbac_list_hashed_t * hashed;
};

struct rsbac_list_lol_reg_item_t {
	struct rsbac_list_lol_info_t info;
	u_int flags;
	rsbac_list_compare_function_t *compare;
	rsbac_list_compare_function_t *subcompare;
	rsbac_list_get_conv_t *get_conv;
	rsbac_list_get_conv_t *get_subconv;
	void *def_data;
	void *def_subdata;
	char name[RSBAC_LIST_MAX_FILENAME + 1];
	kdev_t device;
	spinlock_t lock;
	struct rsbac_list_rcu_free_head_lol_t * rcu_free;
	rsbac_boolean_t dirty;
	rsbac_boolean_t no_write;
	struct rsbac_nanotime_t lastchange;
#ifdef CONFIG_RSBAC_LIST_STATS
	__u64 read_count;
	__u64 write_count;
#endif
	u_int nr_hashes;
	u_int max_items_per_hash;
	u_int max_subitems;
	rsbac_list_hash_function_t * hash_function;
	char old_name_base[RSBAC_LIST_MAX_FILENAME + 1];
	struct kmem_cache * slab;
	char * slabname;
	struct kmem_cache * subslab;
	char * subslabname;
#if defined(CONFIG_RSBAC_PROC) && defined(CONFIG_PROC_FS)
	struct proc_dir_entry *proc_entry_p;
#endif
	struct rsbac_list_lol_reg_item_t *prev;
	struct rsbac_list_lol_reg_item_t *next;
	struct rsbac_list_lol_reg_item_t *self;
	/* The hashed list heads are allocated dynamically! */
	struct rsbac_list_lol_hashed_t * hashed;
};

/* To provide consistency we use spinlocks for all list accesses. The
   'curr' entry is used to avoid repeated lookups for the same item. */

struct rsbac_list_reg_head_t {
	struct rsbac_list_reg_item_t *head;
	struct rsbac_list_reg_item_t *tail;
	struct rsbac_list_reg_item_t *curr;
	spinlock_t lock;
	struct lock_class_key lock_class;
	u_int count;
};

struct rsbac_list_lol_reg_head_t {
	struct rsbac_list_lol_reg_item_t *head;
	struct rsbac_list_lol_reg_item_t *tail;
	struct rsbac_list_lol_reg_item_t *curr;
	spinlock_t lock;
	struct lock_class_key lock_class;
	u_int count;
};

/* Internal helper list of filled write buffers */

struct rsbac_list_buffer_t {
	struct rsbac_list_buffer_t * next;
	u_int len;
	char data[0];
};

#define RSBAC_LIST_BUFFER_SIZE 8192
#define RSBAC_LIST_BUFFER_DATA_SIZE (RSBAC_LIST_BUFFER_SIZE - sizeof(struct rsbac_list_buffer_t))

struct rsbac_list_write_item_t {
	struct rsbac_list_write_item_t *prev;
	struct rsbac_list_write_item_t *next;
	struct rsbac_list_reg_item_t *list;
	struct rsbac_list_buffer_t *buffer;
	char name[RSBAC_LIST_MAX_FILENAME + 1];
	kdev_t device;
};

struct rsbac_list_write_head_t {
	struct rsbac_list_write_item_t *head;
	struct rsbac_list_write_item_t *tail;
	u_int count;
};

struct rsbac_list_lol_write_item_t {
	struct rsbac_list_lol_write_item_t *prev;
	struct rsbac_list_lol_write_item_t *next;
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_buffer_t *buffer;
	char name[RSBAC_LIST_MAX_FILENAME + 1];
	kdev_t device;
};

struct rsbac_list_lol_write_head_t {
	struct rsbac_list_lol_write_item_t *head;
	struct rsbac_list_lol_write_item_t *tail;
	u_int count;
};


/* Data structs for file timeout book keeping list filelist */
struct rsbac_list_filelist_desc_t {
	char filename[RSBAC_LIST_MAX_FILENAME + 1];
};

struct rsbac_list_filelist_data_t {
	rsbac_time_t timestamp;
	rsbac_time_t max_age;
};

struct rsbac_list_ta_data_t {
	rsbac_time_t start;
	rsbac_time_t timeout;
	rsbac_uid_t commit_uid;
	char name[RSBAC_LIST_TA_MAX_NAMELEN];
	char password[RSBAC_LIST_TA_MAX_PASSLEN];
};

struct rsbac_list_rcu_free_head_t {
	/* rcu _must_ stay first */
	struct rcu_head rcu;
	struct kmem_cache * slab;
	struct rsbac_list_rcu_free_item_t * head;
	struct rsbac_list_item_t * item_chain;
};

struct rsbac_list_rcu_free_head_lol_t {
	/* rcu _must_ stay first */
	struct rcu_head rcu;
	struct kmem_cache * slab;
	struct kmem_cache * subslab;
	struct rsbac_list_rcu_free_item_t * head;
	struct rsbac_list_rcu_free_item_t * subhead;
	struct rsbac_list_lol_item_t * lol_item_chain;
	struct rsbac_list_item_t * lol_item_subchain;
};

struct rsbac_list_rcu_free_item_t {
	struct rsbac_list_rcu_free_item_t * next;
	void * mem;
};

#endif
