/************************************* */
/* Rule Set Based Access Control       */
/* Author and (c) 1999-2004:           */
/*   Amon Ott <ao@rsbac.org>           */
/* Network helper functions            */
/* Last modified: 07/Dec/2004          */
/************************************* */

#ifndef __RSBAC_NETWORK_H
#define __RSBAC_NETWORK_H

#include <rsbac/types.h>
#include <rsbac/network_types.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/un.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/af_unix.h>
#include <net/route.h>

/* functions */

int rsbac_ta_net_list_all_netdev(rsbac_list_ta_number_t ta_number, rsbac_netdev_id_t ** id_pp);

static inline int rsbac_net_list_all_netdev(rsbac_netdev_id_t ** id_pp)
  {
    return rsbac_ta_net_list_all_netdev(0, id_pp);
  }

//__u32 rsbac_net_make_mask_u32(__u8 valid_bits);

int rsbac_net_compare_data(void * data1, void * data2);

int rsbac_net_get_id(
         rsbac_list_ta_number_t ta_number,
  struct rsbac_net_description_t * desc_p,
         rsbac_net_temp_id_t * id_p);

// void rsbac_net_obj_cleanup(rsbac_net_obj_id_t netobj);

int rsbac_ta_net_lookup_templates(
         rsbac_list_ta_number_t ta_number,
  struct rsbac_net_obj_desc_t * netobj_p,
         rsbac_net_temp_id_t * local_temp_p,
         rsbac_net_temp_id_t * remote_temp_p);

static inline int rsbac_net_lookup_templates(
  struct rsbac_net_obj_desc_t * netobj_p,
         rsbac_net_temp_id_t * local_temp_p,
         rsbac_net_temp_id_t * remote_temp_p)
  {
    return rsbac_ta_net_lookup_templates(0, netobj_p, local_temp_p, remote_temp_p);
  }

/* Does template exist? Returns TRUE if yes, FALSE if no */
int rsbac_ta_net_template_exists(rsbac_list_ta_number_t ta_number,
	rsbac_net_temp_id_t id);

int rsbac_ta_net_template(
  rsbac_list_ta_number_t ta_number,
  enum rsbac_net_temp_syscall_t call,
  rsbac_net_temp_id_t id,
  union rsbac_net_temp_syscall_data_t * data_p);

static inline int rsbac_net_template(enum rsbac_net_temp_syscall_t call,
                       rsbac_net_temp_id_t id,
                       union rsbac_net_temp_syscall_data_t * data_p)
  {
    return rsbac_ta_net_template(0, call, id, data_p);
  }

int rsbac_ta_net_list_all_template(rsbac_list_ta_number_t ta_number,
                                   rsbac_net_temp_id_t ** id_pp);

static inline int rsbac_net_list_all_template(rsbac_net_temp_id_t ** id_pp)
  {
    return rsbac_ta_net_list_all_template(0, id_pp);
  }

int rsbac_ta_net_template_exist(rsbac_list_ta_number_t ta_number, rsbac_net_temp_id_t temp);

static inline int rsbac_net_template_exist(rsbac_net_temp_id_t temp)
  {
    return rsbac_ta_net_template_exist(0, temp);
  }

/* Whether request should be checked for remote endpoint */
int rsbac_net_remote_request(enum rsbac_adf_request_t request);

#endif
