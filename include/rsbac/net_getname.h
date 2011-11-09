/********************************** */
/* Rule Set Based Access Control    */
/* Author and (c) 1999-2003:        */
/*   Amon Ott <ao@rsbac.org>        */
/* Getname functions for CAP module */
/* Last modified: 22/Dec/2003       */
/********************************** */

#ifndef __RSBAC_NET_GETNAME_H
#define __RSBAC_NET_GETNAME_H

#include <rsbac/types.h>

#define RSBAC_NET_PROTO_MAX 256
#define RSBAC_NET_TYPE_MAX 11

#ifdef __KERNEL__
extern int rsbac_net_str_to_inet(char * str, __u32 * addr);
#else
#ifndef AF_MAX
#define AF_MAX 32
#endif
#endif

extern char * rsbac_get_net_temp_syscall_name(char * name,
                                        enum rsbac_net_temp_syscall_t value);

extern char * rsbac_get_net_family_name(char * name,
                                  u_int value);

extern char * rsbac_get_net_netlink_family_name(char * name,
                                  u_int value);

extern char * rsbac_get_net_protocol_name(char * name,
                                    u_int value);

extern char * rsbac_get_net_type_name(char * name,
                                u_int value);

#ifndef __KERNEL__
enum rsbac_net_temp_syscall_t rsbac_get_net_temp_syscall_nr(const char * name);

int rsbac_get_net_family_nr(const char * name);

int rsbac_get_net_protocol_nr(const char * name);

int rsbac_get_net_type_nr(const char * name);
#endif

#endif
