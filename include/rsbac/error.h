/************************************* */
/* Rule Set Based Access Control       */
/* Author and (c) 1999-2008: Amon Ott  */
/* Helper functions for all parts      */
/* Last modified: 03/Mar/2008          */
/************************************* */

#ifndef __RSBAC_ERROR_H
#define __RSBAC_ERROR_H

#ifdef __KERNEL__
#include <linux/errno.h>
#else
#include <errno.h>
#endif

/* Error values             */

#define RSBAC_EPERM               1001
#define RSBAC_EACCESS             1002
#define RSBAC_EREADFAILED         1003
#define RSBAC_EWRITEFAILED        1004
#define RSBAC_EINVALIDPOINTER     1005
#define RSBAC_ENOROOTDIR          1006
#define RSBAC_EPATHTOOLONG        1007
#define RSBAC_ENOROOTDEV          1008
#define RSBAC_ENOTFOUND           1009
#define RSBAC_ENOTINITIALIZED     1010
#define RSBAC_EREINIT             1011
#define RSBAC_ECOULDNOTADDDEVICE  1012
#define RSBAC_ECOULDNOTADDITEM    1013
#define RSBAC_ECOULDNOTCREATEPATH 1014
#define RSBAC_EINVALIDATTR        1015
#define RSBAC_EINVALIDDEV         1016
#define RSBAC_EINVALIDTARGET      1017
#define RSBAC_EINVALIDVALUE       1018
#define RSBAC_EEXISTS             1019
#define RSBAC_EINTERNONLY         1020
#define RSBAC_EINVALIDREQUEST     1021
#define RSBAC_ENOTWRITABLE        1022
#define RSBAC_EMALWAREDETECTED    1023
#define RSBAC_ENOMEM              1024
#define RSBAC_EDECISIONMISMATCH   1025
#define RSBAC_EINVALIDVERSION     1026
#define RSBAC_EINVALIDMODULE      1027
#define RSBAC_EEXPIRED            1028
#define RSBAC_EMUSTCHANGE         1029
#define RSBAC_EBUSY               1030
#define RSBAC_EINVALIDTRANSACTION 1031
#define RSBAC_EWEAKPASSWORD       1032
#define RSBAC_EINVALIDLIST        1033
#define RSBAC_EFROMINTERRUPT      1034

#define RSBAC_EMAX 1034

#define RSBAC_ERROR( res ) ((res <= -RSBAC_EPERM) && (res >= -RSBAC_EMAX))

#ifndef __KERNEL__
/* exit on error */
void error_exit(int error);

/* show error */
void show_error(int error);
#endif

#endif
