/************************************* */
/* Rule Set Based Access Control       */
/* Author and (c) 1999-2007: Amon Ott  */
/* Helper functions for all parts      */
/* Last modified:  26/Sep/2007         */
/************************************* */

#ifndef __RSBAC_HELPER_H
#define __RSBAC_HELPER_H

#include <linux/types.h>
#include <rsbac/types.h>
#ifdef __KERNEL__
#include <rsbac/rkmem.h>
#endif

char * inttostr(char[], int);

char * ulongtostr(char[], u_long);

/* convert u_long_long to binary string representation for MAC module */
char * u64tostrmac(char[], __u64);

char * u32tostrcap(char * str, __u32 i);
__u32 strtou32cap(char * str, __u32 * i_p);

int rsbac_get_vset_num(char * sourcename, rsbac_um_set_t * vset_p);

#ifndef __KERNEL__
void locale_init(void);

int rsbac_lib_version(void);
int rsbac_u32_compare(__u32 * a, __u32 * b);
int rsbac_u32_void_compare(const void *a, const void *b);

int rsbac_user_compare(const void * a, const void * b);
int rsbac_group_compare(const void * a, const void * b);
int rsbac_nettemp_id_compare(const void * a, const void * b);

int rsbac_dev_compare(const void * desc1,
                      const void * desc2);

char * get_user_name(rsbac_uid_t user, char * name);

char * get_group_name(rsbac_gid_t group, char * name);

int rsbac_get_uid_name(rsbac_uid_t * uid, char * name, char * sourcename);

int rsbac_get_fullname(char * fullname, rsbac_uid_t uid);

static inline int rsbac_get_uid(rsbac_uid_t * uid, char * sourcename)
  {
    return rsbac_get_uid_name(uid, NULL, sourcename);
  }

int rsbac_get_gid_name(rsbac_gid_t * gid, char * name, char * sourcename);

static inline int rsbac_get_gid(rsbac_gid_t * gid, char * sourcename)
  {
    return rsbac_get_gid_name(gid, NULL, sourcename);
  }

/* covert u_long_long to binary string representation for log array */
char * u64tostrlog(char[], __u64);
/* and back */
__u64 strtou64log(char[], __u64 *);

/* convert u_long_long to binary string representation for MAC module */
/* and back */
__u64 strtou64mac(char[], __u64 *);

/* covert u_long_long to binary string representation for RC module */
char * u64tostrrc(char[], __u64);
/* and back */
__u64 strtou64rc(char[], __u64 *);

/* covert u_long_long to binary string representation for RC module / rights */
char * u64tostrrcr(char[], __u64);
/* and back */
__u64 strtou64rcr(char[], __u64 *);

/* ACL back */
__u64 strtou64acl(char[], __u64 *);

char * devdesctostr(char * str, struct rsbac_dev_desc_t dev);

int strtodevdesc(char * str, struct rsbac_dev_desc_t * dev_p);
#endif

/* covert u_long_long to binary string representation for ACL module */
char * u64tostracl(char[], __u64);

char * longtostr(char[], long);

#ifdef __KERNEL__
#include <asm/uaccess.h>

#ifdef CONFIG_RSBAC_UM_VIRTUAL
rsbac_um_set_t rsbac_get_vset(void);
#else
static inline rsbac_um_set_t rsbac_get_vset(void)
  {
    return 0;
  }
#endif

int rsbac_get_owner(rsbac_uid_t * user_p);

static inline int rsbac_get_user(unsigned char * kern_p, unsigned char * user_p, int size)
  {
    if(kern_p && user_p && (size > 0))
      {
        return copy_from_user(kern_p, user_p, size);
      }
    return 0;
  }


static inline int rsbac_put_user(unsigned char * kern_p, unsigned char * user_p, int size)
  {
    if(kern_p && user_p && (size > 0))
      {
        return copy_to_user(user_p,kern_p,size);
      }
    return 0;
  }

static inline char * rsbac_getname(const char * name)
  {
    return getname(name);
  }

static inline void rsbac_putname(const char * name)
  {
    putname(name);
  }

static inline int clear_user_buf(char * ubuf, int len)
  {
    return clear_user(ubuf,len);
  }

void rsbac_get_attr_error(char * , enum rsbac_adf_request_t);

void rsbac_ds_get_error(const char * function, enum rsbac_attribute_t attr);
void rsbac_ds_get_error_num(const char * function, enum rsbac_attribute_t attr, int err);
void rsbac_ds_set_error(const char * function, enum rsbac_attribute_t attr);
void rsbac_ds_set_error_num(const char * function, enum rsbac_attribute_t attr, int err);

#ifdef CONFIG_RSBAC_RC
void rsbac_rc_ds_get_error(const char * function, enum rsbac_rc_item_t item);
void rsbac_rc_ds_set_error(const char * function, enum rsbac_rc_item_t item);
#endif

#endif /* KERNEL */

#endif
