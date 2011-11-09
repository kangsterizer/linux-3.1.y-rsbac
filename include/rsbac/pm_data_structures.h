/**************************************/
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2009: Amon Ott */
/* Data structures / PM               */
/* Last modified: 26/Mar/2009         */
/**************************************/

#ifndef __RSBAC_PM_DATA_STRUC_H
#define __RSBAC_PM_DATA_STRUC_H

#include <linux/types.h>
#include <rsbac/aci.h>
#include <rsbac/types.h>
#include <rsbac/pm_types.h>

#define RSBAC_PM_TASK_SET_LIST_NAME "pm_ta_s"
#define RSBAC_PM_TASK_SET_LIST_PROC_NAME "task_set"

#define RSBAC_PM_TP_SET_LIST_NAME   "pm_tp_s"
#define RSBAC_PM_TP_SET_LIST_PROC_NAME   "tp_set"

#define RSBAC_PM_RU_SET_LIST_NAME   "pm_ru_s"
#define RSBAC_PM_RU_SET_LIST_PROC_NAME   "responsible_user_set"

#define RSBAC_PM_PP_SET_LIST_NAME   "pm_pp_s"
#define RSBAC_PM_PP_SET_LIST_PROC_NAME   "purpose_set"

#define RSBAC_PM_IN_PP_SET_LIST_NAME "input_pp_set"
#define RSBAC_PM_IN_PP_SET_LIST_PROC_NAME "input_purpose_set"

#define RSBAC_PM_OUT_PP_SET_LIST_NAME "output_pp_set"
#define RSBAC_PM_OUT_PP_SET_LIST_PROC_NAME "output_purpose_set"


#define RSBAC_PM_TASK_LIST_NAME     "pm_task"
#define RSBAC_PM_TASK_LIST_PROC_NAME     "task"

#define RSBAC_PM_CLASS_LIST_NAME    "pm_clas"
#define RSBAC_PM_CLASS_LIST_PROC_NAME    "object_class"

#define RSBAC_PM_NA_LIST_NAME       "pm_na"
#define RSBAC_PM_NA_LIST_PROC_NAME       "necessary_accesses"

#define RSBAC_PM_CS_LIST_NAME       "pm_cs"
#define RSBAC_PM_CS_LIST_PROC_NAME       "consent"

#define RSBAC_PM_TP_LIST_NAME       "pm_tp"
#define RSBAC_PM_TP_LIST_PROC_NAME       "tp"

#define RSBAC_PM_PP_LIST_NAME       "pm_pp"
#define RSBAC_PM_PP_LIST_PROC_NAME       "purpose"

#define RSBAC_PM_TKT_LIST_NAME      "pm_tkt"
#define RSBAC_PM_TKT_LIST_PROC_NAME      "ticket"


#define RSBAC_PM_NO_VERSION 1

#define RSBAC_PM_TASK_SET_LIST_VERSION   1
#define RSBAC_PM_TP_SET_LIST_VERSION     1
#define RSBAC_PM_RU_SET_LIST_VERSION     2
#define RSBAC_PM_PP_SET_LIST_VERSION     1

#define RSBAC_PM_TASK_LIST_VERSION       1
#define RSBAC_PM_CLASS_LIST_VERSION      1
#define RSBAC_PM_NA_LIST_VERSION         1
#define RSBAC_PM_CS_LIST_VERSION         1
#define RSBAC_PM_TP_LIST_VERSION         1
#define RSBAC_PM_PP_LIST_VERSION         1
#define RSBAC_PM_TKT_LIST_VERSION        2

#define RSBAC_PM_LIST_KEY 19990820

#define RSBAC_PM_PROC_STATS_NAME "stats_pm"
#define RSBAC_PM_PROC_DIR_NAME "pm"

#endif
