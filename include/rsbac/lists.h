/*************************************************** */
/* Rule Set Based Access Control                     */
/* Author and (c) 1999-2010: Amon Ott <ao@rsbac.org> */
/* Generic List Management                           */
/* Last modified: 31/May/2010                        */
/*************************************************** */

/* Note: lol = list of lists, a two-level list structure */

#ifndef __RSBAC_LISTS_H
#define __RSBAC_LISTS_H

#include <linux/init.h>
#include <linux/vmalloc.h>
//#include <rsbac/types.h>
#include <rsbac/rkmem.h>

#define RSBAC_LIST_VERSION 3

typedef void *rsbac_list_handle_t;
typedef __u32 rsbac_list_key_t;

/* Maximum length for list (file)names */
#define RSBAC_LIST_MAX_FILENAME 15

/* Limit for max_age_in_seconds: ca. 10 years */
#define RSBAC_LIST_MAX_AGE_LIMIT (3600 * 24 * 366 * 10)

/* Maximum desc_size + data_size: 8K - some space for metadata */
#define RSBAC_LIST_MAX_ITEM_SIZE (8192 - 64)

#define RSBAC_LIST_MIN_MAX_HASHES 8

/* standard hash functions */
u_int rsbac_list_hash_u32(void * desc, __u32 nr_hashes);
u_int rsbac_list_hash_fd(void * desc, __u32 nr_hashes);
u_int rsbac_list_hash_pid(void * desc, __u32 nr_hashes);
u_int rsbac_list_hash_uid(void * desc, __u32 nr_hashes);
u_int rsbac_list_hash_gid(void * desc, __u32 nr_hashes);
u_int rsbac_list_hash_ipc(void * desc, __u32 nr_hashes);
u_int rsbac_list_hash_dev(void * desc, __u32 nr_hashes);
u_int rsbac_list_hash_nettemp(void * desc, __u32 nr_hashes);
u_int rsbac_list_hash_netobj(void * desc, __u32 nr_hashes);

/****************************/
/* List Registration Flags: */

/* Make persistent, i.e., save to and restore from disk */
#define RSBAC_LIST_PERSIST 1

/* Ignore old list contents (still checks key, if list exists on disk) */
#define RSBAC_LIST_IGNORE_OLD 2

/* Ignore old list contents, if version upconversion is not supported
 * (no get_conv, or get_conv returned NULL) - without this flag, registration fails, if
 * list cannot be converted.
 */
#define RSBAC_LIST_IGNORE_UNSUPP_VERSION 4

/* Temporarily disallow writing list to disk, e.g. for upgrade tests */
#define RSBAC_LIST_NO_WRITE 8

/* Provide a binary backup file as /proc/rsbac-info/backup/filename */
#define RSBAC_LIST_BACKUP 16

/* Use provided default data, return it for unexisting items and
   automatically create and cleanup items with default data as necessary.
   (only items with 0 ttl (unlimited) get removed)
   (lol items with default data only get removed, if they have no subitems) */
#define RSBAC_LIST_DEF_DATA 32

/* Use provided default subitem data, return it for unexisting subitems and
   automatically create and cleanup subitems with default data as necessary.
   (only subitems with 0 ttl (unlimited) get removed) */
#define RSBAC_LIST_DEF_SUBDATA 64

/* Replicate list to replication partners.
   Must be enabled in config. */
#define RSBAC_LIST_REPLICATE 128

/* Allow automatic online resizing of the list hashing table.
   Requires that the provided hash function uses the nr_hashes parameter. */
#define RSBAC_LIST_AUTO_HASH_RESIZE 256

/* Disable limit of RSBAC_LIST_MAX_NR_ITEMS items per single list. */
#define RSBAC_LIST_NO_MAX 512

/* Disable warning if max_entries prevents adding of items */
#define RSBAC_LIST_NO_MAX_WARN 1024

/* Use own slab for this list */
#define RSBAC_LIST_OWN_SLAB 2048

/* Maximum number of items per single list, the total limit is at
 * RSBAC_LIST_MAX_NR_ITEMS * nr_hashes.
 * Limits can be disabled per list with RSBAC_LIST_NO_MAX flag and
 * changed with rsbac_list_max_items() and rsbac_list_lol_max_items().
 */

#define RSBAC_LIST_MAX_NR_ITEMS 50000
#define RSBAC_LIST_MAX_NR_SUBITEMS 50000

/****************************/
/* Function prototypes */

/* Function to compare two descriptors, returns 0, if equal, a negative value,
 * if desc1 < desc2 and a positive value, if desc1 > desc2 (like memcmp).
 * Used for lookup and list optimization.
 * Note: Non-0 values are only used for list optimization and do not necessarily
 * imply a real order of values.
 */
typedef int rsbac_list_compare_function_t(void *desc1, void *desc2);

int rsbac_list_compare_u32(void * desc1, void * desc2);

/* Function to compare two datas, returns 0, if equal, and another value,
 * if not.
 * Used for lookup by data.
 * Note: list optimization is based on descriptors, so data lookup is always
 * linear search from first to last element in list order.
 */
typedef int rsbac_list_data_compare_function_t(void *data1, void *data2);

/* Function to compare two descs with a parameter, returns TRUE,
 * if item is selected, and FALSE, if not.
 * Used for selected lists of descriptors.
 */
typedef int rsbac_list_desc_selector_function_t(void *desc, void * param);

/* conversion function to upconvert old on-disk descs and datas to actual version */
/* must return 0 on success or error otherwise */
/* Attention: if old or new data_size is 0, the respective data pointer is NULL! */
typedef int rsbac_list_conv_function_t(void *old_desc,
				       void *old_data,
				       void *new_desc, void *new_data);

/* callback function to return an upconvert function for on-disk-version, if versions differ */
/* Note: Lists implementation does not assume anything about your version number apart
   from being of type rsbac_version_t. Use it as you like. */
typedef rsbac_list_conv_function_t *rsbac_list_get_conv_t(rsbac_version_t
							  old_version);

/* hash function to return a hash for the descriptor in the range 0 to nr_hashes-1 */
typedef u_int rsbac_list_hash_function_t(void * desc, __u32 nr_hashes);

/* get generic list registration version */
rsbac_version_t rsbac_list_version(void);


/* List info: This struct will be written to disk */
/*
 * list_version: a simple __u32 version number for the list. If old on-disk version is
   different, conversion is tried (depending on flags and get_conv function)
 * key: secret __u32 key, which must be the same as in on-disk version, if persistent
 * desc_size: size of the descriptor (error is returned, if list exists and value differs)
              internally reset to sizeof(__u32) for u32 call variants
 * data_size: size of data (error is returned, if list exists and value differs)
              set to 0 for sets without data
 * subdesc_size: size of the descriptor of the sublist (error is returned, if list exists
              and value differs), internally reset to sizeof(__u32) for u32 call variants
 * subdata_size: size of sublist data (error is returned, if list exists and value differs)
              set to 0 for sets without data
 * max_age: seconds until unchanged list file (no add or remove) will be purged.
   Maximum value is RSBAC_LIST_MAX_AGE_LIMIT (s.a.), use 0 for unlimited lifetime.
   (purging not yet implemented - only reused without key, please cleanup by hand)
 */
struct rsbac_list_info_t {
	rsbac_version_t version;
	rsbac_list_key_t key;
	__u32 desc_size;
	__u32 data_size;
	rsbac_time_t max_age;
};

struct rsbac_list_lol_info_t {
	rsbac_version_t version;
	rsbac_list_key_t key;
	__u32 desc_size;
	__u32 data_size;
	__u32 subdesc_size;
	__u32 subdata_size;
	rsbac_time_t max_age;
};


/* register a new list */
/*
 * If list with same name exists in memory, error -RSBAC_EEXISTS is returned.
 * If list with same name and key exists on device, it is restored depending on
   the flags.
 * If list with same name, but different key exists on disk, access is denied
   (error -EPERM).
 *
 * ds_version: for binary modules, must be RSBAC_LIST_VERSION. If version
   differs, return error.
 * handle_p: for all list accesses, an opaque handle is put into *handle_p.
 * flags: see flag values
 * compare: for lookup and list optimization, can be NULL, then
   memcmp(desc1, desc2, desc_size) is used
 * subcompare: for item lookup and optimization of sublist, can be NULL, then
   memcmp(desc1, desc2, desc_size) is used
 * get_conv: function to deliver conversion function for given version
 * get_subconv: function to deliver sublist item conversion function for given
   version
 * def_data: default data value for flag RSBAC_LIST_DEF_DATA
   (if NULL, flag is cleared)
 * def_subdata: default subdata value for flag RSBAC_LIST_DEF_SUBDATA
   (if NULL, flag is cleared)
 * name: the on-disk name, should be distinct and max. 7 or 8.2 chars
   (maxlen of RSBAC_LIST_MAX_FILENAME supported) (only used for statistics, if
   non-persistent)
 * device: the device to read list from or to save list to - use 0 for root dev
   (ignored, if non-persistent)
 * nr_hashes: Number of hashes for this list, maximum is RSBAC_LIST_MAX_HASHES,
   which is derived from CONFIG_RSBAC_LIST_MAX_HASHES.
   If > maximum, it will be reduced to maximum automatically.
   8 <= RSBAC_LIST_MAX_HASHES <= 256 in all cases, see above.
   Thus,  it is safe to use nr_hashes <= 8 without checks.
   Value may vary between registrations.
 * hash_function: Hash function for desc, must always return a value
   from 0 to nr_hashes-1.
 * old_base_name: If not NULL and persistent list with name cannot be read,
   try to read all old_base_name<n> with n from 0 to 31.
 */

int rsbac_list_register_hashed(rsbac_version_t ds_version,
			rsbac_list_handle_t * handle_p,
			struct rsbac_list_info_t *info_p,
			u_int flags,
			rsbac_list_compare_function_t * compare,
			rsbac_list_get_conv_t * get_conv,
			void *def_data,
			char *name, kdev_t device,
			u_int nr_hashes,
			rsbac_list_hash_function_t hash_function,
			char * old_base_name);

int rsbac_list_lol_register_hashed(rsbac_version_t ds_version,
			rsbac_list_handle_t * handle_p,
			struct rsbac_list_lol_info_t *info_p,
			u_int flags,
			rsbac_list_compare_function_t * compare,
			rsbac_list_compare_function_t * subcompare,
			rsbac_list_get_conv_t * get_conv,
			rsbac_list_get_conv_t * get_subconv,
			void *def_data,
			void *def_subdata,
			char *name, kdev_t device,
			u_int nr_hashes,
			rsbac_list_hash_function_t hash_function,
			char * old_base_name);

/* Old and simpler registration function, sets nr_hashes to 1,
 * hash_function to NULL and old_base_name to NULL.
 */

int rsbac_list_register(rsbac_version_t ds_version,
			rsbac_list_handle_t * handle_p,
			struct rsbac_list_info_t *info_p,
			u_int flags,
			rsbac_list_compare_function_t * compare,
			rsbac_list_get_conv_t * get_conv,
			void *def_data, char *name, kdev_t device);

int rsbac_list_lol_register(rsbac_version_t ds_version,
			    rsbac_list_handle_t * handle_p,
			    struct rsbac_list_lol_info_t *info_p,
			    u_int flags,
			    rsbac_list_compare_function_t * compare,
			    rsbac_list_compare_function_t * subcompare,
			    rsbac_list_get_conv_t * get_conv,
			    rsbac_list_get_conv_t * get_subconv,
			    void *def_data,
			    void *def_subdata, char *name, kdev_t device);

/* destroy list */
/* list is destroyed, disk file is deleted */
/* list must have been opened with register */
int rsbac_list_destroy(rsbac_list_handle_t * handle_p,
		       rsbac_list_key_t key);

int rsbac_list_lol_destroy(rsbac_list_handle_t * handle_p,
			   rsbac_list_key_t key);

/* detach from list */
/* list is saved (if persistent) and removed from memory. Call register for new access. */
/* Must not be called with spinlock held. */

int rsbac_list_detach(rsbac_list_handle_t * handle_p,
		      rsbac_list_key_t key);

int rsbac_list_lol_detach(rsbac_list_handle_t * handle_p,
			  rsbac_list_key_t key);

/* set list's no_write flag */
/* TRUE: do not write to disk, FALSE: writing allowed */
int rsbac_list_no_write
    (rsbac_list_handle_t handle, rsbac_list_key_t key,
     rsbac_boolean_t no_write);

int rsbac_list_lol_no_write
    (rsbac_list_handle_t handle, rsbac_list_key_t key,
     rsbac_boolean_t no_write);

/* Set max_items_per_hash */
int rsbac_list_max_items(rsbac_list_handle_t handle, rsbac_list_key_t key,
			u_int max_items);

int rsbac_list_lol_max_items(rsbac_list_handle_t handle, rsbac_list_key_t key,
			u_int max_items, u_int max_subitems);

/* Single list checking, good for cleanup of items with ttl in the past. */
/* This functionality is also included in the big rsbac_check(). */

int rsbac_list_check(rsbac_list_handle_t handle, int correct);

int rsbac_list_lol_check(rsbac_list_handle_t handle, int correct);

/* Transaction Support */
#ifdef CONFIG_RSBAC_LIST_TRANS
int rsbac_list_ta_begin(rsbac_time_t ttl,
			rsbac_list_ta_number_t * ta_number_p,
			rsbac_uid_t commit_uid,
			char * name, char *password);

int rsbac_list_ta_refresh(rsbac_time_t ttl,
			  rsbac_list_ta_number_t ta_number,
			  char *password);

int rsbac_list_ta_commit(rsbac_list_ta_number_t ta_number, char *password);

int rsbac_list_ta_forget(rsbac_list_ta_number_t ta_number, char *password);

/* Returns TRUE, if transaction ta_number exists, and FALSE, if not. */
int rsbac_list_ta_exist(rsbac_list_ta_number_t ta_number);
#endif

/* add with time-to-live - after this time in seconds the item gets automatically removed */
/* set to 0 for unlimited (default), RSBAC_LIST_TTL_KEEP to keep previous setting */
int rsbac_ta_list_add_ttl(rsbac_list_ta_number_t ta_number,
			  rsbac_list_handle_t handle,
			  rsbac_time_t ttl, void *desc, void *data);

static inline int rsbac_list_add_ttl(rsbac_list_handle_t handle,
		       rsbac_time_t ttl, void *desc, void *data)
{
	return rsbac_ta_list_add_ttl(0, handle, ttl, desc, data);
}

static inline int rsbac_list_add(rsbac_list_handle_t handle, void *desc, void *data)
{
	return rsbac_ta_list_add_ttl(0, handle, RSBAC_LIST_TTL_KEEP, desc,
				     data);
}

/* Add list of lists sublist item, item for desc must exist */
int rsbac_ta_list_lol_subadd_ttl(rsbac_list_ta_number_t ta_number,
				 rsbac_list_handle_t handle,
				 rsbac_time_t ttl,
				 void *desc, void *subdesc, void *subdata);

static inline int rsbac_list_lol_subadd_ttl(rsbac_list_handle_t handle,
			      rsbac_time_t ttl,
			      void *desc, void *subdesc, void *subdata)
{
	return rsbac_ta_list_lol_subadd_ttl(0, handle, ttl, desc, subdesc,
					    subdata);
}

static inline int rsbac_list_lol_subadd(rsbac_list_handle_t handle,
			  void *desc, void *subdesc, void *subdata)
{
	return rsbac_ta_list_lol_subadd_ttl(0, handle, RSBAC_LIST_TTL_KEEP,
					    desc, subdesc, subdata);
}

/* add with time-to-live - after this time in seconds the item gets automatically removed */
int rsbac_ta_list_lol_add_ttl(rsbac_list_ta_number_t ta_number,
			      rsbac_list_handle_t handle,
			      rsbac_time_t ttl, void *desc, void *data);

static inline int rsbac_list_lol_add_ttl(rsbac_list_handle_t handle,
			   rsbac_time_t ttl, void *desc, void *data)
{
	return rsbac_ta_list_lol_add_ttl(0, handle, ttl, desc, data);
}

static inline int rsbac_list_lol_add(rsbac_list_handle_t handle, void *desc, void *data)
{
	return rsbac_ta_list_lol_add_ttl(0, handle, RSBAC_LIST_TTL_KEEP,
					 desc, data);
}

/* remove item */
int rsbac_ta_list_remove(rsbac_list_ta_number_t ta_number,
			 rsbac_list_handle_t handle, void *desc);

static inline int rsbac_list_remove(rsbac_list_handle_t handle, void *desc)
{
	return rsbac_ta_list_remove(0, handle, desc);
}

/* remove all items */
int rsbac_ta_list_remove_all(rsbac_list_ta_number_t ta_number,
			     rsbac_list_handle_t handle);

static inline int rsbac_list_remove_all(rsbac_list_handle_t handle)
{
	return rsbac_ta_list_remove_all(0, handle);
}

/* remove item from sublist - also succeeds, if item for desc or subdesc does not exist */
int rsbac_ta_list_lol_subremove(rsbac_list_ta_number_t ta_number,
				rsbac_list_handle_t handle,
				void *desc, void *subdesc);

static inline int rsbac_list_lol_subremove(rsbac_list_handle_t handle,
			     void *desc, void *subdesc)
{
	return rsbac_ta_list_lol_subremove(0, handle, desc, subdesc);
}

int rsbac_ta_list_lol_subremove_count(rsbac_list_ta_number_t ta_number,
				      rsbac_list_handle_t handle,
				      void *desc, u_long count);


/* remove same subitem from all sublists */
int rsbac_ta_list_lol_subremove_from_all(rsbac_list_ta_number_t ta_number,
					 rsbac_list_handle_t handle,
					 void *subdesc);

static inline int rsbac_list_lol_subremove_from_all(rsbac_list_handle_t handle,
				      void *subdesc)
{
	return rsbac_ta_list_lol_subremove_from_all(0, handle, subdesc);
}

/* remove all subitems from list */
int rsbac_ta_list_lol_subremove_all(rsbac_list_ta_number_t ta_number,
				    rsbac_list_handle_t handle,
				    void *desc);

static inline int rsbac_list_lol_subremove_all(rsbac_list_handle_t handle, void *desc)
{
	return rsbac_ta_list_lol_subremove_all(0, handle, desc);
}

int rsbac_ta_list_lol_remove(rsbac_list_ta_number_t ta_number,
			     rsbac_list_handle_t handle, void *desc);

static inline int rsbac_list_lol_remove(rsbac_list_handle_t handle, void *desc)
{
	return rsbac_ta_list_lol_remove(0, handle, desc);
}

int rsbac_ta_list_lol_remove_all(rsbac_list_ta_number_t ta_number,
				 rsbac_list_handle_t handle);

static inline int rsbac_list_lol_remove_all(rsbac_list_handle_t handle)
{
	return rsbac_ta_list_lol_remove_all(0, handle);
}


/* get item data */
/* Item data is copied - we cannot give a pointer, because item could be
 * removed */
/* also get time-to-live - after this time in seconds the item gets automatically removed */
/* both ttl_p and data can be NULL, they are then simply not returned */
int rsbac_ta_list_get_data_ttl(rsbac_list_ta_number_t ta_number,
			       rsbac_list_handle_t handle,
			       rsbac_time_t * ttl_p,
			       void *desc, void *data);

static inline int rsbac_list_get_data_ttl(rsbac_list_handle_t handle,
			    rsbac_time_t * ttl_p, void *desc, void *data)
{
	return rsbac_ta_list_get_data_ttl(0, handle, ttl_p, desc, data);
}

static inline int rsbac_list_get_data(rsbac_list_handle_t handle, void *desc, void *data)
{
	return rsbac_ta_list_get_data_ttl(0, handle, NULL, desc, data);
}

/* get data from a subitem */
/* also get time-to-live - after this time in seconds the item gets automatically removed */
/* both ttl_p and data can be NULL, they are then simply not returned */
int rsbac_ta_list_lol_get_subdata_ttl(rsbac_list_ta_number_t ta_number,
				      rsbac_list_handle_t handle,
				      rsbac_time_t * ttl_p,
				      void *desc,
				      void *subdesc, void *subdata);

static inline int rsbac_list_lol_get_subdata_ttl(rsbac_list_handle_t handle,
				   rsbac_time_t * ttl_p,
				   void *desc,
				   void *subdesc, void *subdata)
{
	return rsbac_ta_list_lol_get_subdata_ttl(0, handle,
						 ttl_p, desc, subdesc,
						 subdata);
}

static inline int rsbac_list_lol_get_subdata(rsbac_list_handle_t handle,
			       void *desc, void *subdesc, void *subdata)
{
	return rsbac_ta_list_lol_get_subdata_ttl(0, handle, NULL, desc,
						 subdesc, subdata);
}

/* also get time-to-live - after this time in seconds the item gets automatically removed */
/* both ttl_p and data can be NULL, they are then simply not returned */
int rsbac_ta_list_lol_get_data_ttl(rsbac_list_ta_number_t ta_number,
				   rsbac_list_handle_t handle,
				   rsbac_time_t * ttl_p,
				   void *desc, void *data);

static inline int rsbac_list_lol_get_data_ttl(rsbac_list_handle_t handle,
				rsbac_time_t * ttl_p,
				void *desc, void *data)
{
	return rsbac_ta_list_lol_get_data_ttl(0, handle, ttl_p, desc,
					      data);
}

static inline int rsbac_list_lol_get_data(rsbac_list_handle_t handle,
			    void *desc, void *data)
{
	return rsbac_ta_list_lol_get_data_ttl(0, handle, NULL, desc, data);
}

/* get item desc by data */
/* Item desc is copied - we cannot give a pointer, because item could be
 * removed.
 * If no compare function is provided (NULL value), memcmp is used.
 * Note: The data value given here is always used as second parameter to the
 *       compare function, so you can use different types for storage and
 *       lookup.
 */
int rsbac_ta_list_get_desc(rsbac_list_ta_number_t ta_number,
			   rsbac_list_handle_t handle,
			   void *desc,
			   void *data,
			   rsbac_list_data_compare_function_t compare);

static inline int rsbac_list_get_desc(rsbac_list_handle_t handle,
			void *desc,
			void *data,
			rsbac_list_data_compare_function_t compare)
{
	return rsbac_ta_list_get_desc(0, handle, desc, data, compare);
}

int rsbac_ta_list_get_desc_selector(
	rsbac_list_ta_number_t ta_number,
	rsbac_list_handle_t handle,
	void *desc,
	void *data,
	rsbac_list_data_compare_function_t compare,
	rsbac_list_desc_selector_function_t selector,
	void * param);

int rsbac_ta_list_lol_get_desc(rsbac_list_ta_number_t ta_number,
			       rsbac_list_handle_t handle,
			       void *desc,
			       void *data,
			       rsbac_list_data_compare_function_t compare);

static inline int rsbac_list_lol_get_desc(rsbac_list_handle_t handle,
			    void *desc,
			    void *data,
			    rsbac_list_data_compare_function_t compare)
{
	return rsbac_ta_list_lol_get_desc(0, handle, desc, data, compare);
}

int rsbac_ta_list_lol_get_desc_selector(
	rsbac_list_ta_number_t ta_number,
	rsbac_list_handle_t handle,
	void *desc,
	void *data,
	rsbac_list_data_compare_function_t compare,
	rsbac_list_desc_selector_function_t selector,
	void * param);

/* get maximum desc (uses compare function) */
int rsbac_ta_list_get_max_desc(rsbac_list_ta_number_t ta_number,
			       rsbac_list_handle_t handle, void *desc);

static inline int rsbac_list_get_max_desc(rsbac_list_handle_t handle, void *desc)
{
	return rsbac_ta_list_get_max_desc(0, handle, desc);
}

int rsbac_ta_list_lol_get_max_subdesc(rsbac_list_ta_number_t ta_number,
				      rsbac_list_handle_t handle,
				      void *desc, void *subdesc);

/* get next desc (uses compare function) */
int rsbac_ta_list_get_next_desc(rsbac_list_ta_number_t ta_number,
				rsbac_list_handle_t handle,
				void *old_desc, void *next_desc);

static inline int rsbac_list_get_next_desc(rsbac_list_handle_t handle, void *old_desc,
			     void *next_desc)
{
	return rsbac_ta_list_get_next_desc(0, handle, old_desc, next_desc);
}

int rsbac_ta_list_get_next_desc_selector(
		rsbac_list_ta_number_t ta_number,
		rsbac_list_handle_t handle,
		void *old_desc,
		void *next_desc,
		rsbac_list_desc_selector_function_t selector,
		void * param);

int rsbac_ta_list_lol_get_next_desc(rsbac_list_ta_number_t ta_number,
				    rsbac_list_handle_t handle,
				    void *old_desc, void *next_desc);

static inline int rsbac_list_lol_get_next_desc(rsbac_list_handle_t handle,
				 void *old_desc, void *next_desc)
{
	return rsbac_ta_list_lol_get_next_desc(0, handle, old_desc,
					       next_desc);
}

int rsbac_ta_list_lol_get_next_desc_selector(
		rsbac_list_ta_number_t ta_number,
		rsbac_list_handle_t handle,
		void *old_desc,
		void *next_desc,
		rsbac_list_desc_selector_function_t selector,
		void * param);

/* does item exist? */
/* returns TRUE, if item exists, FALSE, if not or error */
int rsbac_ta_list_exist(rsbac_list_ta_number_t ta_number,
			rsbac_list_handle_t handle, void *desc);

static inline int rsbac_list_exist(rsbac_list_handle_t handle, void *desc)
{
	return rsbac_ta_list_exist(0, handle, desc);
}

int rsbac_ta_list_lol_subexist(rsbac_list_ta_number_t ta_number,
			       rsbac_list_handle_t handle,
			       void *desc, void *subdesc);

static inline int rsbac_list_lol_subexist(rsbac_list_handle_t handle,
			    void *desc, void *subdesc)
{
	return rsbac_ta_list_lol_subexist(0, handle, desc, subdesc);
}

int rsbac_ta_list_lol_exist(rsbac_list_ta_number_t ta_number,
			    rsbac_list_handle_t handle, void *desc);

static inline int rsbac_list_lol_exist(rsbac_list_handle_t handle, void *desc)
{
	return rsbac_ta_list_lol_exist(0, handle, desc);
}

/*
 * Note: The subdesc/data value given here is always used as second parameter to the
 *       given subdesc compare function, so you can use different types for storage and
 *       lookup. If compare is NULL, call is forwarded to rsbac_list_lol_subexist.
 * Warning: This function does not use the list optimization when searching the sublist!
 */
int rsbac_ta_list_lol_subexist_compare(rsbac_list_ta_number_t ta_number,
				       rsbac_list_handle_t handle,
				       void *desc,
				       void *subdesc,
				       rsbac_list_compare_function_t
				       compare);

static inline int rsbac_list_lol_subexist_compare(rsbac_list_handle_t handle,
				    void *desc,
				    void *subdesc,
				    rsbac_list_compare_function_t compare)
{
	return rsbac_ta_list_lol_subexist_compare(0, handle,
						  desc, subdesc, compare);
}

/* count number of elements */
/* returns number of elements or negative error code */
long rsbac_ta_list_count(rsbac_list_ta_number_t ta_number,
			 rsbac_list_handle_t handle);

static inline long rsbac_list_count(rsbac_list_handle_t handle)
{
	return rsbac_ta_list_count(0, handle);
}

long rsbac_ta_list_lol_subcount(rsbac_list_ta_number_t ta_number,
				rsbac_list_handle_t handle, void *desc);

static inline long rsbac_list_lol_subcount(rsbac_list_handle_t handle, void *desc)
{
	return rsbac_ta_list_lol_subcount(0, handle, desc);
}

long rsbac_ta_list_lol_all_subcount(rsbac_list_ta_number_t ta_number,
				    rsbac_list_handle_t handle);

static inline long rsbac_list_lol_all_subcount(rsbac_list_handle_t handle)
{
	return rsbac_ta_list_lol_all_subcount(0, handle);
}

long rsbac_ta_list_lol_count(rsbac_list_ta_number_t ta_number,
			     rsbac_list_handle_t handle);

static inline long rsbac_list_lol_count(rsbac_list_handle_t handle)
{
	return rsbac_ta_list_lol_count(0, handle);
}


/* Get array of all descriptors */
/* Returns number of elements or negative error code */
/* If return value > 0, *array_p contains a pointer to a rsbac_kmalloc'd array
   of descs, otherwise *array_p is set to NULL. If *array_p has been set,
   caller must call rsbac_kfree(*array_p) after use! */

long rsbac_ta_list_get_all_desc(rsbac_list_ta_number_t ta_number,
				rsbac_list_handle_t handle,
				void **array_p);

static inline long rsbac_list_get_all_desc(rsbac_list_handle_t handle, void **array_p)
{
	return rsbac_ta_list_get_all_desc(0, handle, array_p);
}

long rsbac_ta_list_get_all_desc_selector (
	rsbac_list_ta_number_t ta_number,
	rsbac_list_handle_t handle, void **array_p,
	rsbac_list_desc_selector_function_t selector,
	void * param);

long rsbac_ta_list_lol_get_all_subdesc_ttl(rsbac_list_ta_number_t
					   ta_number,
					   rsbac_list_handle_t handle,
					   void *desc, void **array_p,
					   rsbac_time_t ** ttl_array_p);

static inline long rsbac_list_lol_get_all_subdesc(rsbac_list_handle_t handle,
				void *desc,
				void **array_p)
{
	return rsbac_ta_list_lol_get_all_subdesc_ttl(0, handle,
						     desc, array_p, NULL);
}

static inline long rsbac_list_lol_get_all_subdesc_ttl(rsbac_list_handle_t handle,
					void *desc,
					void **array_p,
					rsbac_time_t ** ttl_array_p)
{
	return rsbac_ta_list_lol_get_all_subdesc_ttl(0,
						     handle,
						     desc,
						     array_p, ttl_array_p);
}

long rsbac_ta_list_lol_get_all_desc(rsbac_list_ta_number_t ta_number,
				    rsbac_list_handle_t handle,
				    void **array_p);

static inline long rsbac_list_lol_get_all_desc(rsbac_list_handle_t handle,
				 void **array_p)
{
	return rsbac_ta_list_lol_get_all_desc(0, handle, array_p);
}

long rsbac_ta_list_lol_get_all_desc_selector (
        rsbac_list_ta_number_t ta_number,
        rsbac_list_handle_t handle,
        void **array_p,
        rsbac_list_desc_selector_function_t selector,
        void * param);

/* Get array of all datas */
/* Returns number of elements or negative error code */
/* If return value > 0, *array_p contains a pointer to a rsbac_kmalloc'd array
   of datas, otherwise *array_p is set to NULL. If *array_p has been set,
   caller must call rsbac_kfree(*array_p) after use! */

long rsbac_ta_list_get_all_data(rsbac_list_ta_number_t ta_number,
				rsbac_list_handle_t handle,
				void **array_p);

static inline long rsbac_list_get_all_data(rsbac_list_handle_t handle, void **array_p)
{
	return rsbac_ta_list_get_all_data(0, handle, array_p);
}

long rsbac_ta_list_lol_get_all_subdata(rsbac_list_ta_number_t ta_number,
				       rsbac_list_handle_t handle,
				       void *desc, void **array_p);

static inline long rsbac_list_lol_get_all_subdata(rsbac_list_handle_t handle,
				    void *desc, void **array_p)
{
	return rsbac_ta_list_lol_get_all_subdata(0, handle, desc, array_p);
}

long rsbac_ta_list_lol_get_all_data(rsbac_list_ta_number_t ta_number,
				    rsbac_list_handle_t handle,
				    void **array_p);

static inline long rsbac_list_lol_get_all_data(rsbac_list_handle_t handle,
				 void **array_p)
{
	return rsbac_ta_list_lol_get_all_data(0, handle, array_p);
}

/* Get item size */

int rsbac_list_get_item_size(rsbac_list_handle_t handle);

int rsbac_list_lol_get_subitem_size(rsbac_list_handle_t handle);

int rsbac_list_lol_get_item_size(rsbac_list_handle_t handle);

/* Get array of all items */
/* Returns number of items or negative error code */
/* If return value > 0, *array_p contains a pointer to a rsbac_kmalloc'd array
   of items, where desc and data are placed directly behind each other.
   If *array_p has been set, caller must call rsbac_kfree(*array_p) after use! */

long rsbac_ta_list_get_all_items_ttl(rsbac_list_ta_number_t ta_number,
				     rsbac_list_handle_t handle,
				     void **array_p,
				     rsbac_time_t ** ttl_array_p);

static inline long rsbac_list_get_all_items_ttl(rsbac_list_handle_t handle,
				  void **array_p,
				  rsbac_time_t ** ttl_array_p)
{
	return rsbac_ta_list_get_all_items_ttl(0, handle, array_p,
					       ttl_array_p);
}

static inline long rsbac_list_get_all_items(rsbac_list_handle_t handle, void **array_p)
{
	return rsbac_ta_list_get_all_items_ttl(0, handle, array_p, NULL);
}

long rsbac_ta_list_lol_get_all_subitems_ttl(rsbac_list_ta_number_t
					    ta_number,
					    rsbac_list_handle_t handle,
					    void *desc, void **array_p,
					    rsbac_time_t ** ttl_array_p);

static inline long rsbac_list_lol_get_all_subitems_ttl(rsbac_list_handle_t handle,
					 void *desc,
					 void **array_p,
					 rsbac_time_t ** ttl_array_p)
{
	return rsbac_ta_list_lol_get_all_subitems_ttl(0, handle, desc,
						      array_p,
						      ttl_array_p);
}

static inline long rsbac_list_lol_get_all_subitems(rsbac_list_handle_t handle,
				     void *desc, void **array_p)
{
	return rsbac_ta_list_lol_get_all_subitems_ttl(0, handle, desc,
						      array_p, NULL);
}

long rsbac_ta_list_lol_get_all_items(rsbac_list_ta_number_t ta_number,
				     rsbac_list_handle_t handle,
				     void **array_p);

static inline long rsbac_list_lol_get_all_items(rsbac_list_handle_t handle,
				  void **array_p)
{
	return rsbac_ta_list_lol_get_all_items(0, handle, array_p);
}

/* Copy a complete list
 * Both lists must have been registered with same desc and data sizes,
 * nr_hashes may differ. Old target list items are removed before copying.
 * If ta_number is set and transactions are enabled, the complete
 * target list content is in the same transaction. Forgetting the
 * transaction will restore the old to_list.
 */

long rsbac_list_copy(rsbac_list_ta_number_t ta_number,
			rsbac_list_handle_t from_handle,
			rsbac_list_handle_t to_handle);

long rsbac_list_lol_copy(rsbac_list_ta_number_t ta_number,
			rsbac_list_handle_t from_handle,
			rsbac_list_handle_t to_handle);

/* Get the current number of hashes - may vary when resized */
long rsbac_list_get_nr_hashes(rsbac_list_handle_t handle);

long rsbac_list_lol_get_nr_hashes(rsbac_list_handle_t handle);

#endif
/* end of lists.h */
