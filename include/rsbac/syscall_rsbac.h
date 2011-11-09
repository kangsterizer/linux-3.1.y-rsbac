/************************************ */
/* Rule Set Based Access Control      */
/*                                    */
/* Author and (c) 1999-2004:          */
/*   Amon Ott <ao@rsbac.org>          */
/*                                    */
/* System Calls                       */
/*                                    */
/* Last modified: 13/Apr/2004         */
/************************************ */

#ifndef __RSBAC_SYSCALL_RSBAC_H
#define __RSBAC_SYSCALL_RSBAC_H

/* to keep include/asm-alpha/unistd.h happy */
//#define __LIBRARY__

#include <linux/unistd.h>
#include <rsbac/types.h>
#include <rsbac/syscalls.h>

#ifdef __PIC__
#undef _syscall3
#define _syscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
        type name(type1 arg1,type2 arg2,type3 arg3) \
{\
                return syscall(__NR_##name, arg1, arg2, arg3);\
}
#endif

static inline _syscall3(int, rsbac,
		rsbac_version_t, version,
		enum rsbac_syscall_t, call,
		union rsbac_syscall_arg_t *, arg_p);

#define sys_rsbac(a,b,c) rsbac(a,b,c)
#endif
