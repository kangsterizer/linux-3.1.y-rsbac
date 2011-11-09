/************************************* */
/* Rule Set Based Access Control       */
/* Author and (c) 1999-2001: Amon Ott  */
/* proc fs functions                   */
/* Last modified: 17/Jul/2001          */
/************************************* */

#ifndef __RSBAC_PROC_FS_H
#define __RSBAC_PROC_FS_H

#include <linux/proc_fs.h>

#ifndef PROC_BLOCK_SIZE
#define PROC_BLOCK_SIZE	(3*1024)  /* 4K page size but our output routines use some slack for overruns */
#endif

extern struct proc_dir_entry * proc_rsbac_root_p;
extern struct proc_dir_entry * proc_rsbac_backup_p;

#endif
