/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of PM data structures              */
/* Author and (c) 1999-2009: Amon Ott <ao@rsbac.org> */
/*                                                   */
/* Last modified: 15/Oct/2009                        */
/*************************************************** */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/file.h>
#include <linux/init.h>
#include <rsbac/types.h>
#include <rsbac/pm_types.h>
#include <rsbac/pm_data_structures.h>
#include <rsbac/getname.h>
#include <rsbac/pm_getname.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/fs.h>
#include <rsbac/adf.h>
#include <rsbac/adf_main.h>
#include <rsbac/debug.h>
#include <rsbac/proc_fs.h>
#include <rsbac/rkmem.h>
#include <rsbac/lists.h>
#include <linux/string.h>
#include <linux/seq_file.h>
#include <linux/module.h>

/************************************************************************** */
/*                          Global Variables                                */
/************************************************************************** */

/* The following global variables are needed for access to PM data.         */

static rsbac_list_handle_t task_set_handle = NULL;
static rsbac_list_handle_t tp_set_handle = NULL;
static rsbac_list_handle_t ru_set_handle = NULL;
static rsbac_list_handle_t pp_set_handle = NULL;
static rsbac_list_handle_t in_pp_set_handle = NULL;
static rsbac_list_handle_t out_pp_set_handle = NULL;

static rsbac_list_handle_t task_handle = NULL;
static rsbac_list_handle_t class_handle = NULL;
static rsbac_list_handle_t na_handle = NULL;
static rsbac_list_handle_t cs_handle = NULL;
static rsbac_list_handle_t tp_handle = NULL;
static rsbac_list_handle_t pp_handle = NULL;
static rsbac_list_handle_t tkt_handle = NULL;

/**************************************************/
/*       Declarations of external functions       */
/**************************************************/

int sys_write(u_int, char *, u_int);

/**************************************************/
/*       Declarations of internal functions       */
/**************************************************/

/* As some function use later defined functions, we declare those here.   */

/************************************************* */
/*               Internal Help functions           */
/************************************************* */


/************************************************* */
/*               proc functions                    */
/************************************************* */

#if defined(CONFIG_RSBAC_PROC)
static int
stats_pm_proc_show(struct seq_file *m, void *v)
{
	u_long tmp_count;
	u_long tmp_member_count;
	u_long all_set_count = 0;
	u_long all_member_count = 0;
	u_long all_count = 0;

#if !defined(CONFIG_RSBAC_MAINT)
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;
#endif

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "stats_pm_proc_info(): RSBAC not initialized\n");
		return (-RSBAC_ENOTINITIALIZED);
	}
#if !defined(CONFIG_RSBAC_MAINT)
	rsbac_pr_debug(aef_pm, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
#if defined(CONFIG_RSBAC_SOFTMODE)
		if (!rsbac_softmode)
#endif
			return -EPERM;
	}
#endif

	seq_printf(m, "PM Status\n---------\n");

/****************/
/* Helper lists */
/****************/

	tmp_count = rsbac_list_lol_count(task_set_handle);
	tmp_member_count = rsbac_list_lol_all_subcount(task_set_handle);
	seq_printf(m,
		    "%lu task-set-items, sum of %lu members\n", tmp_count,
		    tmp_member_count);
	all_set_count += tmp_count;
	all_member_count += tmp_member_count;

	tmp_count = rsbac_list_lol_count(tp_set_handle);
	tmp_member_count = rsbac_list_lol_all_subcount(tp_set_handle);
	seq_printf(m, "%lu tp-set-items, sum of %lu members\n",
		    tmp_count, tmp_member_count);
	all_set_count += tmp_count;
	all_member_count += tmp_member_count;

	tmp_count = rsbac_list_lol_count(ru_set_handle);
	tmp_member_count = rsbac_list_lol_all_subcount(ru_set_handle);
	seq_printf(m, "%lu ru-set-items, sum of %lu members\n",
		    tmp_count, tmp_member_count);
	all_set_count += tmp_count;
	all_member_count += tmp_member_count;

	tmp_count = rsbac_list_lol_count(pp_set_handle);
	tmp_member_count = rsbac_list_lol_all_subcount(pp_set_handle);
	seq_printf(m, "%lu pp-set-items, sum of %lu members\n",
		    tmp_count, tmp_member_count);
	all_set_count += tmp_count;
	all_member_count += tmp_member_count;

	tmp_count = rsbac_list_lol_count(in_pp_set_handle);
	tmp_member_count = rsbac_list_lol_all_subcount(in_pp_set_handle);
	seq_printf(m,
		    "%lu in_pp-set-items, sum of %lu members\n", tmp_count,
		    tmp_member_count);
	all_set_count += tmp_count;
	all_member_count += tmp_member_count;

	tmp_count = rsbac_list_lol_count(out_pp_set_handle);
	tmp_member_count = rsbac_list_lol_all_subcount(out_pp_set_handle);
	seq_printf(m,
		    "%lu out_pp-set-items, sum of %lu members\n",
		    tmp_count, tmp_member_count);
	all_set_count += tmp_count;
	all_member_count += tmp_member_count;

	seq_printf(m,
		    "Total of %lu registered rsbac-pm-set-items, %lu members\n",
		    all_set_count, all_member_count);

/**************/
/* Main lists */
/**************/

	tmp_count = rsbac_list_count(task_handle);
	seq_printf(m, "%lu task-items\n", tmp_count);
	all_count += tmp_count;

	tmp_count = rsbac_list_count(class_handle);
	seq_printf(m, "%lu class-items\n", tmp_count);
	all_count += tmp_count;

	tmp_count = rsbac_list_count(na_handle);
	seq_printf(m, "%lu necessary access items\n",
		       tmp_count);
	all_count += tmp_count;

	tmp_count = rsbac_list_count(cs_handle);
	seq_printf(m, "%lu consent items\n", tmp_count);
	all_count += tmp_count;

	tmp_count = rsbac_list_count(tp_handle);
	seq_printf(m, "%lu tp items\n", tmp_count);
	all_count += tmp_count;

	tmp_count = rsbac_list_count(pp_handle);
	seq_printf(m, "%lu purpose items\n", tmp_count);
	all_count += tmp_count;

	tmp_count = rsbac_list_count(tkt_handle);
	seq_printf(m, "%lu tkt items\n", tmp_count);
	all_count += tmp_count;

	seq_printf(m,
		    "Total of %lu registered rsbac-pm-items\n", all_count);
	return 0;
}

static ssize_t stats_pm_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, stats_pm_proc_show, NULL);
}

static const struct file_operations stats_pm_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= stats_pm_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static struct proc_dir_entry *stats_pm;

/* list_proc_read() */
/* Generic readable list generation function */
static int pm_list_proc_read(char *buffer, char **start, off_t offset,
			     int length, int *eof, void *data)
{
	int len = 0;
	off_t pos = 0;
	off_t begin = 0;
	long count;
	long subcount;
	u_long i, j;
	enum rsbac_pm_list_t list;

	if (!rsbac_is_initialized())
		return (-ENOSYS);
	list = (enum rsbac_pm_all_list_t) data;

#if !defined(CONFIG_RSBAC_MAINT)
	/* access control */
#if defined(CONFIG_RSBAC_SWITCH_PM)
	if (rsbac_switch_pm)
#endif
	{
		int error;
		union rsbac_target_id_t tid;
		union rsbac_attribute_value_t attr_val;

		rsbac_get_owner(&tid.user);
		error =
		    rsbac_get_attr(SW_PM, T_USER, tid, A_pm_role, &attr_val,
				   TRUE);
		if (error) {
			char *tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

			if (tmp) {
				get_error_name(tmp, error);
				rsbac_printk(KERN_WARNING "pm_list_proc_read(): rsbac_get_attr() for pm_role returned error %s",
					     tmp);
				rsbac_kfree(tmp);
			}
			return (error);	/* something weird happened */
		}
		if ((attr_val.pm_role != PR_security_officer)
		    && (attr_val.pm_role != PR_data_protection_officer)
		    && (attr_val.pm_role != PR_tp_manager)) {
			char *tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

			if (tmp) {
				get_pm_all_list_name(tmp, list);
				rsbac_printk(KERN_WARNING "pm_list_proc_read(): access to list %s denied\n",
					     tmp);
				rsbac_kfree(tmp);
			}
#if defined(CONFIG_RSBAC_SOFTMODE)
			if (!rsbac_softmode)
#endif
				return (-EPERM);
		}
		if ((attr_val.pm_role == PR_tp_manager)
		    && (list != PA_tp)) {
			rsbac_printk(KERN_WARNING "pm_list_proc_read(): access to list tp denied\n");
#if defined(CONFIG_RSBAC_SOFTMODE)
			if (!rsbac_softmode)
#endif
				return (-EPERM);
		}
	}
#endif				/* !MAINT */

	switch (list) {
	case PA_task_set:
		{
			rsbac_pm_task_set_id_t *set_array;
			rsbac_pm_task_id_t *member_array;

			count =
			    rsbac_list_lol_get_all_desc(task_set_handle,
							(void **)
							&set_array);
			if (count < 0) {
				return count;
			}
			len +=
			    sprintf(buffer + len, "task-set\tmembers\n");
			for (i = 0; i < count; i++) {
				len += sprintf(buffer + len, "%u\t\t",
					       set_array[i]);
				pos = begin + len;
				if (pos < offset) {
					len = 0;
					begin = pos;
				}
				if (pos > offset + length) {
					rsbac_kfree(set_array);
					goto out;
				}

				subcount =
				    rsbac_list_lol_get_all_subdesc
				    (task_set_handle, &set_array[i],
				     (void **) &member_array);
				if (subcount < 0) {
					rsbac_kfree(set_array);
					goto out;
				}
				for (j = 0; j < subcount; j++) {
					len += sprintf(buffer + len, "%u ",
						       member_array[j]);
					pos = begin + len;
					if (pos < offset) {
						len = 0;
						begin = pos;
					}
					if (pos > offset + length) {
						rsbac_kfree(set_array);
						rsbac_kfree(member_array);
						goto out;
					}
				};
				if (subcount > 0)
					rsbac_kfree(member_array);
				len += sprintf(buffer + len, "\n");
				pos = begin + len;
				if (pos < offset) {
					len = 0;
					begin = pos;
				}
				if (pos > offset + length) {
					rsbac_kfree(set_array);
					goto out;
				}
			};
			if (count > 0)
				rsbac_kfree(set_array);
			break;
		}

	case PA_tp_set:
		{
			rsbac_pm_tp_set_id_t *set_array;
			rsbac_pm_tp_id_t *member_array;

			count =
			    rsbac_list_lol_get_all_desc(tp_set_handle,
							(void **)
							&set_array);
			if (count < 0) {
				return count;
			}
			len +=
			    sprintf(buffer + len, "tp-set\t\tmembers\n");
			for (i = 0; i < count; i++) {
				len += sprintf(buffer + len, "%u\t\t",
					       set_array[i]);
				pos = begin + len;
				if (pos < offset) {
					len = 0;
					begin = pos;
				}
				if (pos > offset + length) {
					rsbac_kfree(set_array);
					goto out;
				}

				subcount =
				    rsbac_list_lol_get_all_subdesc
				    (tp_set_handle, &set_array[i],
				     (void **) &member_array);
				if (subcount < 0) {
					rsbac_kfree(set_array);
					goto out;
				}
				for (j = 0; j < subcount; j++) {
					len += sprintf(buffer + len, "%u ",
						       member_array[j]);
					pos = begin + len;
					if (pos < offset) {
						len = 0;
						begin = pos;
					}
					if (pos > offset + length) {
						rsbac_kfree(set_array);
						rsbac_kfree(member_array);
						goto out;
					}
				};
				if (subcount > 0)
					rsbac_kfree(member_array);
				len += sprintf(buffer + len, "\n");
				pos = begin + len;
				if (pos < offset) {
					len = 0;
					begin = pos;
				}
				if (pos > offset + length) {
					rsbac_kfree(set_array);
					goto out;
				}
			};
			if (count > 0)
				rsbac_kfree(set_array);
			break;
		}

	case PA_ru_set:
		{
			rsbac_pm_ru_set_id_t *set_array;
			rsbac_uid_t *member_array;

			count =
			    rsbac_list_lol_get_all_desc(ru_set_handle,
							(void **)
							&set_array);
			if (count < 0) {
				return count;
			}
			len +=
			    sprintf(buffer + len, "ru-set\t\tmembers\n");
			for (i = 0; i < count; i++) {
				len += sprintf(buffer + len, "%u\t\t",
					       set_array[i]);
				pos = begin + len;
				if (pos < offset) {
					len = 0;
					begin = pos;
				}
				if (pos > offset + length) {
					rsbac_kfree(set_array);
					goto out;
				}

				subcount =
				    rsbac_list_lol_get_all_subdesc
				    (ru_set_handle, &set_array[i],
				     (void **) &member_array);
				if (subcount < 0) {
					rsbac_kfree(set_array);
					goto out;
				}
				for (j = 0; j < subcount; j++) {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
					if (RSBAC_UID_SET(member_array[j]))
						len += sprintf(buffer + len, "%u/%u ",
						       RSBAC_UID_SET(member_array[j]),
						       RSBAC_UID_NUM(member_array[j]));
					else
#endif
					len += sprintf(buffer + len, "%u ",
						       RSBAC_UID_NUM(member_array[j]));
					pos = begin + len;
					if (pos < offset) {
						len = 0;
						begin = pos;
					}
					if (pos > offset + length) {
						rsbac_kfree(set_array);
						rsbac_kfree(member_array);
						goto out;
					}
				};
				if (subcount > 0)
					rsbac_kfree(member_array);
				len += sprintf(buffer + len, "\n");
				pos = begin + len;
				if (pos < offset) {
					len = 0;
					begin = pos;
				}
				if (pos > offset + length) {
					rsbac_kfree(set_array);
					goto out;
				}
			};
			if (count > 0)
				rsbac_kfree(set_array);
			break;
		}

	case PA_pp_set:
		{
			rsbac_pm_pp_set_id_t *set_array;
			rsbac_pm_purpose_id_t *member_array;

			count =
			    rsbac_list_lol_get_all_desc(pp_set_handle,
							(void **)
							&set_array);
			if (count < 0) {
				return count;
			}
			len +=
			    sprintf(buffer + len, "pp-set\t\tmembers\n");
			for (i = 0; i < count; i++) {
				len += sprintf(buffer + len, "%u\t\t",
					       set_array[i]);
				pos = begin + len;
				if (pos < offset) {
					len = 0;
					begin = pos;
				}
				if (pos > offset + length) {
					rsbac_kfree(set_array);
					goto out;
				}

				subcount =
				    rsbac_list_lol_get_all_subdesc
				    (pp_set_handle, &set_array[i],
				     (void **) &member_array);
				if (subcount < 0) {
					rsbac_kfree(set_array);
					goto out;
				}
				for (j = 0; j < subcount; j++) {
					len += sprintf(buffer + len, "%u ",
						       member_array[j]);
					pos = begin + len;
					if (pos < offset) {
						len = 0;
						begin = pos;
					}
					if (pos > offset + length) {
						rsbac_kfree(set_array);
						rsbac_kfree(member_array);
						goto out;
					}
				};
				if (subcount > 0)
					rsbac_kfree(member_array);
				len += sprintf(buffer + len, "\n");
				pos = begin + len;
				if (pos < offset) {
					len = 0;
					begin = pos;
				}
				if (pos > offset + length) {
					rsbac_kfree(set_array);
					goto out;
				}
			};
			if (count > 0)
				rsbac_kfree(set_array);
			break;
		}

	case PA_in_pp_set:
		{
			rsbac_pm_in_pp_set_id_t *set_array;
			rsbac_pm_purpose_id_t *member_array;

			count =
			    rsbac_list_lol_get_all_desc(in_pp_set_handle,
							(void **)
							&set_array);
			if (count < 0) {
				return count;
			}

			len +=
			    sprintf(buffer + len, "in-pp-set\tmembers\n");
			for (i = 0; i < count; i++) {
				len += sprintf(buffer + len, "%u\t\t",
					       pid_vnr(set_array[i]));
				pos = begin + len;
				if (pos < offset) {
					len = 0;
					begin = pos;
				}
				if (pos > offset + length) {
					rsbac_kfree(set_array);
					goto out;
				}

				subcount =
				    rsbac_list_lol_get_all_subdesc
				    (in_pp_set_handle, &set_array[i],
				     (void **) &member_array);
				if (subcount < 0) {
					rsbac_kfree(set_array);
					goto out;
				}
				for (j = 0; j < subcount; j++) {
					len += sprintf(buffer + len, "%u ",
						       member_array[j]);
					pos = begin + len;
					if (pos < offset) {
						len = 0;
						begin = pos;
					}
					if (pos > offset + length) {
						rsbac_kfree(set_array);
						rsbac_kfree(member_array);
						goto out;
					}
				};
				if (subcount > 0)
					rsbac_kfree(member_array);
				len += sprintf(buffer + len, "\n");
				pos = begin + len;
				if (pos < offset) {
					len = 0;
					begin = pos;
				}
				if (pos > offset + length) {
					rsbac_kfree(set_array);
					goto out;
				}
			};
			if (count > 0)
				rsbac_kfree(set_array);
			break;
		}

	case PA_out_pp_set:
		{
			rsbac_pm_out_pp_set_id_t *set_array;
			rsbac_pm_purpose_id_t *member_array;

			count =
			    rsbac_list_lol_get_all_desc(out_pp_set_handle,
							(void **)
							&set_array);
			if (count < 0) {
				return count;
			}

			len +=
			    sprintf(buffer + len, "out-pp-set\tmembers\n");
			for (i = 0; i < count; i++) {
				len += sprintf(buffer + len, "%u\t\t",
					       pid_vnr(set_array[i]));
				pos = begin + len;
				if (pos < offset) {
					len = 0;
					begin = pos;
				}
				if (pos > offset + length) {
					rsbac_kfree(set_array);
					goto out;
				}

				subcount =
				    rsbac_list_lol_get_all_subdesc
				    (out_pp_set_handle, &set_array[i],
				     (void **) &member_array);
				if (subcount < 0) {
					rsbac_kfree(set_array);
					goto out;
				}
				for (j = 0; j < subcount; j++) {
					len += sprintf(buffer + len, "%u ",
						       member_array[j]);
					pos = begin + len;
					if (pos < offset) {
						len = 0;
						begin = pos;
					}
					if (pos > offset + length) {
						rsbac_kfree(set_array);
						rsbac_kfree(member_array);
						goto out;
					}
				};
				if (subcount > 0)
					rsbac_kfree(member_array);
				len += sprintf(buffer + len, "\n");
				pos = begin + len;
				if (pos < offset) {
					len = 0;
					begin = pos;
				}
				if (pos > offset + length) {
					rsbac_kfree(set_array);
					goto out;
				}
			};
			if (count > 0)
				rsbac_kfree(set_array);
			break;
		}

/***********/

	case PA_task:
		{
			rsbac_pm_task_id_t *desc_array;

			count =
			    rsbac_list_get_all_desc(task_handle,
						    (void **) &desc_array);
			if (count < 0) {
				return count;
			}

			len += sprintf(buffer + len, "task-id\n");
			for (i = 0; i < count; i++) {
				len += sprintf(buffer + len, "%u\n",
					       desc_array[i]);
				pos = begin + len;
				if (pos < offset) {
					len = 0;
					begin = pos;
				}
				if (pos > offset + length) {
					rsbac_kfree(desc_array);
					goto out;
				}
			};
			if (count > 0)
				rsbac_kfree(desc_array);
			break;
		}

	case PA_class:
		{
			rsbac_pm_object_class_id_t *desc_array;

			count =
			    rsbac_list_get_all_desc(class_handle,
						    (void **) &desc_array);
			if (count < 0) {
				return count;
			}

			len += sprintf(buffer + len, "class-id\n");
			for (i = 0; i < count; i++) {
				len += sprintf(buffer + len, "%u\n",
					       desc_array[i]);
				pos = begin + len;
				if (pos < offset) {
					len = 0;
					begin = pos;
				}
				if (pos > offset + length) {
					rsbac_kfree(desc_array);
					goto out;
				}
			};
			if (count > 0)
				rsbac_kfree(desc_array);
			break;
		}

	case PA_na:
		{
			struct rsbac_pm_na_data_t *data_array;

			count =
			    rsbac_list_get_all_data(na_handle,
						    (void **) &data_array);
			if (count < 0) {
				return count;
			}
			len +=
			    sprintf(buffer + len,
				    "task\tclass\ttp\taccesses\n");
			for (i = 0; i < count; i++) {
				len +=
				    sprintf(buffer + len,
					    "%u\t%u\t%u\t%u\n",
					    data_array[i].task,
					    data_array[i].object_class,
					    data_array[i].tp,
					    data_array[i].accesses);
				pos = begin + len;
				if (pos < offset) {
					len = 0;
					begin = pos;
				}
				if (pos > offset + length) {
					rsbac_kfree(data_array);
					goto out;
				}
			};
			if (count > 0)
				rsbac_kfree(data_array);
			break;
		}

	case PA_cs:
		{
			struct rsbac_pm_cs_id_t *desc_array;

			count =
			    rsbac_list_get_all_desc(cs_handle,
						    (void **) &desc_array);
			if (count < 0) {
				return count;
			}
			len +=
			    sprintf(buffer + len,
				    "purpose\tdevice\tinode\n");
			for (i = 0; i < count; i++) {
				len +=
				    sprintf(buffer + len,
					    "%u\t%02u:02%u\t%u\n",
					    desc_array[i].purpose,
					    RSBAC_MAJOR(desc_array[i].file.
							device),
					    RSBAC_MINOR(desc_array[i].file.
							device),
					    desc_array[i].file.inode);
				pos = begin + len;
				if (pos < offset) {
					len = 0;
					begin = pos;
				}
				if (pos > offset + length) {
					rsbac_kfree(desc_array);
					goto out;
				}
			};
			if (count > 0)
				rsbac_kfree(desc_array);
			break;
		}

	case PA_tp:
		{
			rsbac_pm_tp_id_t *desc_array;

			count =
			    rsbac_list_get_all_desc(tp_handle,
						    (void **) &desc_array);
			if (count < 0) {
				return count;
			}

			len += sprintf(buffer + len, "tp-id\n");
			for (i = 0; i < count; i++) {
				len += sprintf(buffer + len, "%u\n",
					       desc_array[i]);
				pos = begin + len;
				if (pos < offset) {
					len = 0;
					begin = pos;
				}
				if (pos > offset + length) {
					rsbac_kfree(desc_array);
					goto out;
				}
			};
			if (count > 0)
				rsbac_kfree(desc_array);
			break;
		}

	case PA_pp:
		{
			struct rsbac_pm_pp_data_t *data_array;

			count =
			    rsbac_list_get_all_data(pp_handle,
						    (void **) &data_array);
			if (count < 0) {
				return count;
			}
			len +=
			    sprintf(buffer + len, "purpose\tdef-class\n");
			for (i = 0; i < count; i++) {
				len += sprintf(buffer + len, "%u\t%u\n",
					       data_array[i].id,
					       data_array[i].def_class);
				pos = begin + len;
				if (pos < offset) {
					len = 0;
					begin = pos;
				}
				if (pos > offset + length) {
					rsbac_kfree(data_array);
					goto out;
				}
			};
			if (count > 0)
				rsbac_kfree(data_array);
			break;
		}

	case PA_tkt:
		{
			struct rsbac_pm_tkt_data_t *data_array;

			count =
			    rsbac_list_get_all_data(tkt_handle,
						    (void **) &data_array);
			if (count < 0) {
				return count;
			}
			len +=
			    sprintf(buffer + len,
				    "tkt-id\tvalid-for\tfunction-type\n");
			for (i = 0; i < count; i++) {
				char tmp1[RSBAC_MAXNAMELEN];
				char tmp2[RSBAC_MAXNAMELEN];
				struct timespec now = CURRENT_TIME;

				tmp2[0] = 0;
				if (data_array[i].valid_until < now.tv_sec)
				{
					strcpy(tmp2,
					       "\t(removed on cleanup)");
				}
				len +=
				    sprintf(buffer + len,
					    "%u\t%li\t\t%s%s\n",
					    data_array[i].id,
					    data_array[i].valid_until -
					    now.tv_sec,
					    get_pm_function_type_name(tmp1,
								      data_array
								      [i].
								      function_type),
					    tmp2);
				pos = begin + len;
				if (pos < offset) {
					len = 0;
					begin = pos;
				}
				if (pos > offset + length) {
					rsbac_kfree(data_array);
					goto out;
				}
			};
			if (count > 0)
				rsbac_kfree(data_array);
			break;
		}

	default:
		rsbac_printk(KERN_WARNING "pm_list_proc_read(): access to unknown list %i\n",
			     list);
		return (-RSBAC_EINVALIDTARGET);
	}

      out:
	if (len <= offset + length)
		*eof = 1;
	*start = buffer + (offset - begin);
	len -= (offset - begin);

	if (len > length)
		len = length;
	return len;
};				/* end of list_proc_read */

#endif				/* CONFIG_PROC_FS && CONFIG_RSBAC_PROC */

/************************************************* */
/*               Init functions                    */
/************************************************* */

#ifdef CONFIG_RSBAC_INIT_DELAY
static void registration_error(int err, char *listname)
#else
static void __init registration_error(int err, char *listname)
#endif
{
	if (err) {
		char *tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

		if (tmp) {
			rsbac_printk(KERN_WARNING "rsbac_init_pm(): Registering PM %s list failed with error %s\n",
				     listname, get_error_name(tmp, err));
			rsbac_kfree(tmp);
		}
	}
}

/* All functions return 0, if no error occurred, and a negative error code  */
/* otherwise. The error codes are defined in rsbac/error.h.                 */

/************************************************************************** */
/* Initialization of all PM data structures. After this call, all PM data   */
/* is kept in memory for performance reasons, but is written to disk on     */
/* every change.    */

#ifdef CONFIG_RSBAC_INIT_DELAY
int rsbac_init_pm(void)
#else
int __init rsbac_init_pm(void)
#endif
{
	int err = 0;
	struct proc_dir_entry *tmp_entry_p;
	struct proc_dir_entry *pm_entry_p;
	struct rsbac_list_lol_info_t lol_info;
	struct rsbac_list_info_t list_info;

	if (rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_init_pm(): RSBAC already initialized\n");
		return (-RSBAC_EREINIT);
	}

	rsbac_printk(KERN_INFO "rsbac_init_pm(): Initializing RSBAC: PM subsystem\n");

/* Helper lists */
	lol_info.version = RSBAC_PM_TASK_SET_LIST_VERSION;
	lol_info.key = RSBAC_PM_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_pm_task_set_id_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_pm_task_id_t);
	lol_info.subdata_size = 0;
	lol_info.max_age = 0;
	err = rsbac_list_lol_register(RSBAC_LIST_VERSION,
				      &task_set_handle,
				      &lol_info,
				      RSBAC_LIST_PERSIST |
				      RSBAC_LIST_BACKUP,
				      NULL,
				      NULL, NULL, NULL,
				      NULL, NULL,
				      RSBAC_PM_TASK_SET_LIST_NAME,
				      RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "task set");
		return err;
	}

	lol_info.version = RSBAC_PM_TP_SET_LIST_VERSION;
	lol_info.key = RSBAC_PM_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_pm_tp_set_id_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_pm_tp_id_t);
	lol_info.subdata_size = 0;
	lol_info.max_age = 0;
	err = rsbac_list_lol_register(RSBAC_LIST_VERSION,
				      &tp_set_handle,
				      &lol_info,
				      RSBAC_LIST_PERSIST |
				      RSBAC_LIST_BACKUP,
				      NULL,
				      NULL, NULL, NULL,
				      NULL, NULL,
				      RSBAC_PM_TP_SET_LIST_NAME,
				      RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "tp set");
		return err;
	}

	lol_info.version = RSBAC_PM_RU_SET_LIST_VERSION;
	lol_info.key = RSBAC_PM_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_pm_ru_set_id_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_uid_t);
	lol_info.subdata_size = 0;
	lol_info.max_age = 0;
	err = rsbac_list_lol_register(RSBAC_LIST_VERSION,
				      &ru_set_handle,
				      &lol_info,
				      RSBAC_LIST_PERSIST |
				      RSBAC_LIST_BACKUP,
				      NULL,
				      NULL, NULL, NULL,
				      NULL, NULL,
				      RSBAC_PM_RU_SET_LIST_NAME,
				      RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "ru set");
		return err;
	}

	lol_info.version = RSBAC_PM_PP_SET_LIST_VERSION;
	lol_info.key = RSBAC_PM_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_pm_pp_set_id_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_pm_purpose_id_t);
	lol_info.subdata_size = 0;
	lol_info.max_age = 0;
	err = rsbac_list_lol_register(RSBAC_LIST_VERSION,
				      &pp_set_handle,
				      &lol_info,
				      RSBAC_LIST_PERSIST |
				      RSBAC_LIST_BACKUP,
				      NULL,
				      NULL, NULL, NULL,
				      NULL, NULL,
				      RSBAC_PM_PP_SET_LIST_NAME,
				      RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "pp set");
		return err;
	}

	lol_info.version = RSBAC_PM_NO_VERSION;
	lol_info.key = RSBAC_PM_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_pm_in_pp_set_id_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_pm_purpose_id_t);
	lol_info.subdata_size = 0;
	lol_info.max_age = 0;
	err = rsbac_list_lol_register(RSBAC_LIST_VERSION,
				      &in_pp_set_handle,
				      &lol_info,
				      0,
				      NULL,
				      NULL,
				      NULL,
				      NULL,
				      NULL,
				      NULL,
				      RSBAC_PM_IN_PP_SET_LIST_NAME,
				      RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "in_pp set");
		return err;
	}

	lol_info.version = RSBAC_PM_NO_VERSION;
	lol_info.key = RSBAC_PM_LIST_KEY;
	lol_info.desc_size = sizeof(rsbac_pm_out_pp_set_id_t);
	lol_info.data_size = 0;
	lol_info.subdesc_size = sizeof(rsbac_pm_purpose_id_t);
	lol_info.subdata_size = 0;
	lol_info.max_age = 0;
	err = rsbac_list_lol_register(RSBAC_LIST_VERSION,
				      &out_pp_set_handle,
				      &lol_info,
				      0,
				      NULL,
				      NULL,
				      NULL,
				      NULL,
				      NULL,
				      NULL,
				      RSBAC_PM_OUT_PP_SET_LIST_NAME,
				      RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "out_pp set");
		return err;
	}

/* Main lists */
	list_info.version = RSBAC_PM_TASK_LIST_VERSION;
	list_info.key = RSBAC_PM_LIST_KEY;
	list_info.desc_size = sizeof(rsbac_pm_task_id_t);
	list_info.data_size = sizeof(struct rsbac_pm_task_data_t);
	list_info.max_age = 0;
	err = rsbac_list_register(RSBAC_LIST_VERSION,
				  &task_handle,
				  &list_info,
				  RSBAC_LIST_PERSIST | RSBAC_LIST_BACKUP,
				  NULL,
				  NULL,
				  NULL,
				  RSBAC_PM_TASK_LIST_NAME, RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "task");
		return err;
	}

	list_info.version = RSBAC_PM_CLASS_LIST_VERSION;
	list_info.key = RSBAC_PM_LIST_KEY;
	list_info.desc_size = sizeof(rsbac_pm_object_class_id_t);
	list_info.data_size = sizeof(struct rsbac_pm_class_data_t);
	list_info.max_age = 0;
	err = rsbac_list_register(RSBAC_LIST_VERSION,
				  &class_handle,
				  &list_info,
				  RSBAC_LIST_PERSIST | RSBAC_LIST_BACKUP,
				  NULL,
				  NULL,
				  NULL,
				  RSBAC_PM_CLASS_LIST_NAME,
				  RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "class");
		return err;
	}

	list_info.version = RSBAC_PM_NA_LIST_VERSION;
	list_info.key = RSBAC_PM_LIST_KEY;
	list_info.desc_size = sizeof(struct rsbac_pm_na_id_t);
	list_info.data_size = sizeof(struct rsbac_pm_na_data_t);
	list_info.max_age = 0;
	err = rsbac_list_register(RSBAC_LIST_VERSION,
				  &na_handle,
				  &list_info,
				  RSBAC_LIST_PERSIST | RSBAC_LIST_BACKUP,
				  NULL,
				  NULL,
				  NULL,
				  RSBAC_PM_NA_LIST_NAME, RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "na");
		return err;
	}

	list_info.version = RSBAC_PM_CS_LIST_VERSION;
	list_info.key = RSBAC_PM_LIST_KEY;
	list_info.desc_size = sizeof(struct rsbac_pm_cs_id_t);
	list_info.data_size = sizeof(struct rsbac_pm_cs_data_t);
	list_info.max_age = 0;
	err = rsbac_list_register(RSBAC_LIST_VERSION,
				  &cs_handle,
				  &list_info,
				  RSBAC_LIST_PERSIST | RSBAC_LIST_BACKUP,
				  NULL,
				  NULL,
				  NULL,
				  RSBAC_PM_CS_LIST_NAME, RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "cs");
		return err;
	}

	list_info.version = RSBAC_PM_TP_LIST_VERSION;
	list_info.key = RSBAC_PM_LIST_KEY;
	list_info.desc_size = sizeof(rsbac_pm_tp_id_t);
	list_info.data_size = sizeof(struct rsbac_pm_tp_data_t);
	list_info.max_age = 0;
	err = rsbac_list_register(RSBAC_LIST_VERSION,
				  &tp_handle,
				  &list_info,
				  RSBAC_LIST_PERSIST | RSBAC_LIST_BACKUP,
				  NULL,
				  NULL,
				  NULL,
				  RSBAC_PM_TP_LIST_NAME, RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "tp");
		return err;
	}

	list_info.version = RSBAC_PM_PP_LIST_VERSION;
	list_info.key = RSBAC_PM_LIST_KEY;
	list_info.desc_size = sizeof(rsbac_pm_purpose_id_t);
	list_info.data_size = sizeof(struct rsbac_pm_pp_data_t);
	list_info.max_age = 0;
	err = rsbac_list_register(RSBAC_LIST_VERSION,
				  &pp_handle,
				  &list_info,
				  RSBAC_LIST_PERSIST | RSBAC_LIST_BACKUP,
				  NULL,
				  NULL,
				  NULL,
				  RSBAC_PM_PP_LIST_NAME, RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "pp");
		return err;
	}

	list_info.version = RSBAC_PM_TKT_LIST_VERSION;
	list_info.key = RSBAC_PM_LIST_KEY;
	list_info.desc_size = sizeof(rsbac_pm_tkt_id_t);
	list_info.data_size = sizeof(struct rsbac_pm_tkt_data_t);
	list_info.max_age = 0;
	err = rsbac_list_register(RSBAC_LIST_VERSION,
				  &tkt_handle,
				  &list_info,
				  RSBAC_LIST_PERSIST | RSBAC_LIST_BACKUP,
				  NULL,
				  NULL,
				  NULL,
				  RSBAC_PM_TKT_LIST_NAME, RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "tkt");
		return err;
	}
#if defined(CONFIG_RSBAC_PROC)
	stats_pm = proc_create(RSBAC_PM_PROC_STATS_NAME,
					S_IFREG | S_IRUGO,
					proc_rsbac_root_p, &stats_pm_proc_fops);

	pm_entry_p = create_proc_entry(RSBAC_PM_PROC_DIR_NAME,
				       S_IFDIR | S_IRUGO | S_IXUGO,
				       proc_rsbac_root_p);
	if (pm_entry_p) {
		tmp_entry_p =
		    create_proc_entry(RSBAC_PM_TASK_SET_LIST_PROC_NAME,
				      S_IFREG | S_IRUGO, pm_entry_p);
		if (tmp_entry_p) {
			tmp_entry_p->read_proc = pm_list_proc_read;
			tmp_entry_p->data = (void *) PA_task_set;
		}
		tmp_entry_p =
		    create_proc_entry(RSBAC_PM_TP_SET_LIST_PROC_NAME,
				      S_IFREG | S_IRUGO, pm_entry_p);
		if (tmp_entry_p) {
			tmp_entry_p->read_proc = pm_list_proc_read;
			tmp_entry_p->data = (void *) PA_tp_set;
		}
		tmp_entry_p =
		    create_proc_entry(RSBAC_PM_RU_SET_LIST_PROC_NAME,
				      S_IFREG | S_IRUGO, pm_entry_p);
		if (tmp_entry_p) {
			tmp_entry_p->read_proc = pm_list_proc_read;
			tmp_entry_p->data = (void *) PA_ru_set;
		}
		tmp_entry_p =
		    create_proc_entry(RSBAC_PM_PP_SET_LIST_PROC_NAME,
				      S_IFREG | S_IRUGO, pm_entry_p);
		if (tmp_entry_p) {
			tmp_entry_p->read_proc = pm_list_proc_read;
			tmp_entry_p->data = (void *) PA_pp_set;
		}
		tmp_entry_p =
		    create_proc_entry(RSBAC_PM_IN_PP_SET_LIST_PROC_NAME,
				      S_IFREG | S_IRUGO, pm_entry_p);
		if (tmp_entry_p) {
			tmp_entry_p->read_proc = pm_list_proc_read;
			tmp_entry_p->data = (void *) PA_in_pp_set;
		}
		tmp_entry_p =
		    create_proc_entry(RSBAC_PM_OUT_PP_SET_LIST_PROC_NAME,
				      S_IFREG | S_IRUGO, pm_entry_p);
		if (tmp_entry_p) {
			tmp_entry_p->read_proc = pm_list_proc_read;
			tmp_entry_p->data = (void *) PA_out_pp_set;
		}

		tmp_entry_p =
		    create_proc_entry(RSBAC_PM_TASK_LIST_PROC_NAME,
				      S_IFREG | S_IRUGO, pm_entry_p);
		if (tmp_entry_p) {
			tmp_entry_p->read_proc = pm_list_proc_read;
			tmp_entry_p->data = (void *) PA_task;
		}
		tmp_entry_p =
		    create_proc_entry(RSBAC_PM_CLASS_LIST_PROC_NAME,
				      S_IFREG | S_IRUGO, pm_entry_p);
		if (tmp_entry_p) {
			tmp_entry_p->read_proc = pm_list_proc_read;
			tmp_entry_p->data = (void *) PA_class;
		}
		tmp_entry_p = create_proc_entry(RSBAC_PM_NA_LIST_PROC_NAME,
						S_IFREG | S_IRUGO,
						pm_entry_p);
		if (tmp_entry_p) {
			tmp_entry_p->read_proc = pm_list_proc_read;
			tmp_entry_p->data = (void *) PA_na;
		}
		tmp_entry_p = create_proc_entry(RSBAC_PM_CS_LIST_PROC_NAME,
						S_IFREG | S_IRUGO,
						pm_entry_p);
		if (tmp_entry_p) {
			tmp_entry_p->read_proc = pm_list_proc_read;
			tmp_entry_p->data = (void *) PA_cs;
		}
		tmp_entry_p = create_proc_entry(RSBAC_PM_TP_LIST_PROC_NAME,
						S_IFREG | S_IRUGO,
						pm_entry_p);
		if (tmp_entry_p) {
			tmp_entry_p->read_proc = pm_list_proc_read;
			tmp_entry_p->data = (void *) PA_tp;
		}
		tmp_entry_p = create_proc_entry(RSBAC_PM_PP_LIST_PROC_NAME,
						S_IFREG | S_IRUGO,
						pm_entry_p);
		if (tmp_entry_p) {
			tmp_entry_p->read_proc = pm_list_proc_read;
			tmp_entry_p->data = (void *) PA_pp;
		}
		tmp_entry_p =
		    create_proc_entry(RSBAC_PM_TKT_LIST_PROC_NAME,
				      S_IFREG | S_IRUGO, pm_entry_p);
		if (tmp_entry_p) {
			tmp_entry_p->read_proc = pm_list_proc_read;
			tmp_entry_p->data = (void *) PA_tkt;
		}
	}

#endif
	rsbac_pr_debug(ds_pm, "Ready.\n");
	return (err);
};

/***************************************************/
/* We also need some status information...         */

int rsbac_stats_pm(void)
{
	u_long tmp_count;
	u_long tmp_member_count;
	u_long all_set_count = 0;
	u_long all_member_count = 0;
	u_long all_count = 0;

	if (!rsbac_is_initialized()) {
		rsbac_printk(KERN_WARNING "rsbac_stats_pm(): RSBAC not initialized\n");
		return (-RSBAC_ENOTINITIALIZED);
	}

/****************/
/* Helper lists */
/****************/

	tmp_count = rsbac_list_lol_count(task_set_handle);
	tmp_member_count = rsbac_list_lol_all_subcount(task_set_handle);
	rsbac_printk(KERN_INFO "rsbac_stats_pm(): %lu task-set-items, sum of %lu members\n",
		     tmp_count, tmp_member_count);
	all_set_count += tmp_count;
	all_member_count += tmp_member_count;

	tmp_count = rsbac_list_lol_count(tp_set_handle);
	tmp_member_count = rsbac_list_lol_all_subcount(tp_set_handle);
	rsbac_printk(KERN_INFO "rsbac_stats_pm(): %lu tp set items, sum of %lu members\n",
		     tmp_count, tmp_member_count);
	all_set_count += tmp_count;
	all_member_count += tmp_member_count;

	tmp_count = rsbac_list_lol_count(ru_set_handle);
	tmp_member_count = rsbac_list_lol_all_subcount(ru_set_handle);
	rsbac_printk(KERN_INFO "rsbac_stats_pm(): %lu ru set items, sum of %lu members\n",
		     tmp_count, tmp_member_count);
	all_set_count += tmp_count;
	all_member_count += tmp_member_count;

	tmp_count = rsbac_list_lol_count(pp_set_handle);
	tmp_member_count = rsbac_list_lol_all_subcount(pp_set_handle);
	rsbac_printk(KERN_INFO "rsbac_stats_pm(): %lu pp set items, sum of %lu members\n",
		     tmp_count, tmp_member_count);
	all_set_count += tmp_count;
	all_member_count += tmp_member_count;

	tmp_count = rsbac_list_lol_count(in_pp_set_handle);
	tmp_member_count = rsbac_list_lol_all_subcount(in_pp_set_handle);
	rsbac_printk(KERN_INFO "rsbac_stats_pm(): %lu input purpose set items, sum of %lu members\n",
		     tmp_count, tmp_member_count);
	all_set_count += tmp_count;
	all_member_count += tmp_member_count;

	tmp_count = rsbac_list_lol_count(out_pp_set_handle);
	tmp_member_count = rsbac_list_lol_all_subcount(out_pp_set_handle);
	rsbac_printk(KERN_INFO "rsbac_stats_pm(): %lu output purpose set items, sum of %lu members\n",
		     tmp_count, tmp_member_count);
	all_set_count += tmp_count;
	all_member_count += tmp_member_count;

	rsbac_printk(KERN_INFO "rsbac_stats_pm(): Total of %lu registered rsbac-pm-set-items, %lu members\n",
		     all_set_count, all_member_count);

/**************/
/* Main lists */
/**************/
	tmp_count = rsbac_list_count(task_handle);
	rsbac_printk(KERN_INFO "rsbac_stats_pm(): %lu task items\n",
		     tmp_count);
	all_count += tmp_count;

	tmp_count = rsbac_list_count(class_handle);
	rsbac_printk(KERN_INFO "rsbac_stats_pm(): %lu class items\n",
		     tmp_count);
	all_count += tmp_count;

	tmp_count = rsbac_list_count(na_handle);
	rsbac_printk(KERN_INFO "rsbac_stats_pm(): %lu na items\n",
		     tmp_count);
	all_count += tmp_count;

	tmp_count = rsbac_list_count(cs_handle);
	rsbac_printk(KERN_INFO "rsbac_stats_pm(): %lu cs items\n",
		     tmp_count);
	all_count += tmp_count;

	tmp_count = rsbac_list_count(tp_handle);
	rsbac_printk(KERN_INFO "rsbac_stats_pm(): %lu tp items\n",
		     tmp_count);
	all_count += tmp_count;

	tmp_count = rsbac_list_count(pp_handle);
	rsbac_printk(KERN_INFO "rsbac_stats_pm(): %lu pp items\n",
		     tmp_count);
	all_count += tmp_count;

	tmp_count = rsbac_list_count(tkt_handle);
	rsbac_printk(KERN_INFO "rsbac_stats_pm(): %lu tkt items\n",
		     tmp_count);
	all_count += tmp_count;

	rsbac_printk(KERN_INFO "rsbac_stats_pm(): Total of %lu registered rsbac-pm-items\n",
		     all_count);
	return 0;
}

/************************************************* */
/*               Access functions                  */
/************************************************* */

/***********************/
/* Helper lists / sets */
/***********************/

/* Trying to access a never created or removed set returns an error!        */


/* rsbac_pm_add_to_set */
/* Add a set member to a set sublist. Set behaviour: also returns success, */
/* if member was already in set! */

int rsbac_pm_add_to_set(rsbac_list_ta_number_t ta_number,
			enum rsbac_pm_set_t set,
			union rsbac_pm_set_id_t id,
			union rsbac_pm_set_member_t member)
{
	switch (set) {
	case PS_TASK:
		return (rsbac_ta_list_lol_subadd_ttl
			(ta_number, task_set_handle, 0, &id.task_set,
			 &member.task, NULL));
	case PS_TP:
		return (rsbac_ta_list_lol_subadd_ttl
			(ta_number, tp_set_handle, 0, &id.tp_set,
			 &member.tp, NULL));
	case PS_RU:
		return (rsbac_ta_list_lol_subadd_ttl
			(ta_number, ru_set_handle, 0, &id.ru_set,
			 &member.ru, NULL));
	case PS_PP:
		return (rsbac_ta_list_lol_subadd_ttl
			(ta_number, pp_set_handle, 0, &id.pp_set,
			 &member.pp, NULL));
	case PS_IN_PP:
		return (rsbac_ta_list_lol_subadd_ttl
			(ta_number, in_pp_set_handle, 0, &id.in_pp_set,
			 &member.pp, NULL));
	case PS_OUT_PP:
		return (rsbac_ta_list_lol_subadd_ttl
			(ta_number, out_pp_set_handle, 0, &id.out_pp_set,
			 &member.pp, NULL));
	default:
		return (-RSBAC_EINVALIDTARGET);
	}
}

/* rsbac_pm_remove_from_set */
/* Remove a set member from a sublist. Set behaviour: Returns no error, if */
/* member is not in list.                                                  */
/* Caution: Writing to disk is not done in the remove functions!               */

int rsbac_pm_remove_from_set(rsbac_list_ta_number_t ta_number,
			     enum rsbac_pm_set_t set,
			     union rsbac_pm_set_id_t id,
			     union rsbac_pm_set_member_t member)
{
	switch (set) {
	case PS_TASK:
		return (rsbac_ta_list_lol_subremove
			(ta_number, task_set_handle, &id.task_set,
			 &member.task));
	case PS_TP:
		return (rsbac_ta_list_lol_subremove
			(ta_number, tp_set_handle, &id.tp_set,
			 &member.tp));
	case PS_RU:
		return (rsbac_ta_list_lol_subremove
			(ta_number, ru_set_handle, &id.ru_set,
			 &member.ru));
	case PS_PP:
		return (rsbac_ta_list_lol_subremove
			(ta_number, pp_set_handle, &id.pp_set,
			 &member.pp));
	case PS_IN_PP:
		return (rsbac_ta_list_lol_subremove
			(ta_number, in_pp_set_handle, &id.in_pp_set,
			 &member.pp));
	case PS_OUT_PP:
		return (rsbac_ta_list_lol_subremove
			(ta_number, out_pp_set_handle, &id.out_pp_set,
			 &member.pp));
	default:
		return (-RSBAC_EINVALIDTARGET);
	}
}

/* rsbac_pm_clear_set */
/* Remove all set members from a sublist. Set behaviour: Returns no error, */
/* if list is empty.                                                       */
/* Caution: Writing to disk is not done in the remove functions!               */

int rsbac_pm_clear_set(rsbac_list_ta_number_t ta_number,
		       enum rsbac_pm_set_t set, union rsbac_pm_set_id_t id)
{
	switch (set) {
	case PS_TASK:
		return (rsbac_ta_list_lol_subremove_all
			(ta_number, task_set_handle, &id.task_set));
	case PS_TP:
		return (rsbac_ta_list_lol_subremove_all
			(ta_number, tp_set_handle, &id.tp_set));
	case PS_RU:
		return (rsbac_ta_list_lol_subremove_all
			(ta_number, ru_set_handle, &id.ru_set));
	case PS_PP:
		return (rsbac_ta_list_lol_subremove_all
			(ta_number, pp_set_handle, &id.pp_set));
	case PS_IN_PP:
		return (rsbac_ta_list_lol_subremove_all
			(ta_number, in_pp_set_handle, &id.in_pp_set));
	case PS_OUT_PP:
		return (rsbac_ta_list_lol_subremove_all
			(ta_number, out_pp_set_handle, &id.out_pp_set));
	default:
		return (-RSBAC_EINVALIDTARGET);
	}
}

/* rsbac_pm_set_member */
/* Return truth value, whether member is in set */

rsbac_boolean_t rsbac_pm_set_member(rsbac_list_ta_number_t ta_number,
				    enum rsbac_pm_set_t set,
				    union rsbac_pm_set_id_t id,
				    union rsbac_pm_set_member_t member)
{
	switch (set) {
	case PS_TASK:
		return (rsbac_ta_list_lol_subexist
			(ta_number, task_set_handle, &id.task_set,
			 &member.task));
	case PS_TP:
		return (rsbac_ta_list_lol_subexist
			(ta_number, tp_set_handle, &id.tp_set,
			 &member.tp));
	case PS_RU:
		return (rsbac_ta_list_lol_subexist
			(ta_number, ru_set_handle, &id.ru_set,
			 &member.ru));
	case PS_PP:
		return (rsbac_ta_list_lol_subexist
			(ta_number, pp_set_handle, &id.pp_set,
			 &member.pp));
	case PS_IN_PP:
		return (rsbac_ta_list_lol_subexist
			(ta_number, in_pp_set_handle, &id.in_pp_set,
			 &member.pp));
	case PS_OUT_PP:
		return (rsbac_ta_list_lol_subexist
			(ta_number, out_pp_set_handle, &id.out_pp_set,
			 &member.pp));
	default:
		return (FALSE);
	}
}

/* rsbac_pm_pp_subset */
/* Return truth value, whether pp_set is subset of in_pp_set */

rsbac_boolean_t rsbac_pm_pp_subset(rsbac_pm_pp_set_id_t pp_set,
				   rsbac_pm_in_pp_set_id_t in_pp_set)
{
	rsbac_pm_purpose_id_t *pp_array;
	long count;
	u_long i;
	rsbac_boolean_t result = TRUE;

	if (!pp_set || !in_pp_set)
		return (FALSE);

	/* get all pp_set members */
	count =
	    rsbac_list_lol_get_all_subdesc(pp_set_handle, &pp_set,
					   (void **) &pp_array);
	if (count < 0)
		return FALSE;
	if (!count)
		return TRUE;
	if (!rsbac_list_lol_exist(in_pp_set_handle, &in_pp_set)) {
		rsbac_kfree(pp_array);
		return TRUE;
	}
	/* check all members in in_pp_set */
	for (i = 0; i < count; i++) {
		if (!rsbac_list_lol_subexist
		    (in_pp_set_handle, &in_pp_set, &pp_array[i])) {
			result = FALSE;
			break;
		}
	}
	rsbac_kfree(pp_array);
	return result;
}

/* rsbac_pm_pp_superset */
/* Return truth value, whether pp_set is superset of out_pp_set */

rsbac_boolean_t rsbac_pm_pp_superset(rsbac_pm_pp_set_id_t pp_set,
				     rsbac_pm_out_pp_set_id_t out_pp_set)
{
	rsbac_pm_purpose_id_t *pp_array;
	long count;
	u_long i;
	rsbac_boolean_t result = TRUE;

	if (!pp_set)
		return (FALSE);
	if (!out_pp_set)
		return (TRUE);
	if (!rsbac_list_lol_exist(pp_set_handle, &pp_set))
		return FALSE;

	/* get all pp_set members */
	count =
	    rsbac_list_lol_get_all_subdesc(out_pp_set_handle, &out_pp_set,
					   (void **) &pp_array);
	if (count <= 0)
		return TRUE;
	/* check all members in in_pp_set */
	for (i = 0; i < count; i++) {
		if (!rsbac_list_lol_subexist
		    (pp_set_handle, &pp_set, &pp_array[i])) {
			result = FALSE;
			break;
		}
	}
	rsbac_kfree(pp_array);
	return result;
}

/* rsbac_pm_pp_only */
/* Return truth value, if there is no other item in out_pp_set than purpose */

rsbac_boolean_t rsbac_pm_pp_only(rsbac_pm_purpose_id_t purpose,
				 rsbac_pm_out_pp_set_id_t out_pp_set)
{
	long count;

	if (!out_pp_set)
		return (TRUE);

	/* get number of pp_set members */
	count = rsbac_list_lol_subcount(out_pp_set_handle, &out_pp_set);
	if (count <= 0)
		return TRUE;
	if (count == 1)
		return rsbac_list_lol_subexist(out_pp_set_handle,
					       &out_pp_set, &purpose);
	else
		return FALSE;
}

/* rsbac_pm_pp_intersec */
/* Create intersection of pp_set and in_pp_set in in_pp_set */
/* If in_pp_set does not exist, it is created with all members of pp_set */
/* If pp_set does not exist or one of them is invalid, an error is returned */

int rsbac_pm_pp_intersec(rsbac_pm_pp_set_id_t pp_set,
			 rsbac_pm_in_pp_set_id_t in_pp_set)
{
	rsbac_pm_purpose_id_t *pp_array;
	long count;
	u_long i;

	if (!rsbac_list_lol_exist(pp_set_handle, &pp_set))
		return -RSBAC_EINVALIDVALUE;

	if (!rsbac_list_lol_exist(in_pp_set_handle, &in_pp_set)) {	/* in_pp_set not found -> try to create and fill with pp_set */
		if ((count =
		     rsbac_list_lol_add(in_pp_set_handle, &in_pp_set,
					NULL)))
			return count;
		/* creation successful -> copy list */
		/* get all pp_set members */
		count =
		    rsbac_list_lol_get_all_subdesc(pp_set_handle, &pp_set,
						   (void **) &pp_array);
		if (count <= 0)
			return count;
		for (i = 0; i < count; i++) {
			rsbac_list_lol_subadd(in_pp_set_handle, &in_pp_set,
					      &pp_array[i], NULL);
		}
		rsbac_kfree(pp_array);
	} else {		/* in_pp_set exists -> remove all members not in pp_set */
		/* get all in_pp_set members */
		count =
		    rsbac_list_lol_get_all_subdesc(in_pp_set_handle,
						   &in_pp_set,
						   (void **) &pp_array);
		if (count <= 0)
			return count;
		for (i = 0; i < count; i++) {
			if (!rsbac_list_lol_subexist
			    (pp_set_handle, &pp_set, &pp_array[i]))
				rsbac_list_lol_subremove(in_pp_set_handle,
							 &in_pp_set,
							 &pp_array[i]);
		}
		rsbac_kfree(pp_array);
	}
	return 0;
}

/* rsbac_pm_pp_union */
/* Create union of pp_set and out_pp_set in out_pp_set
 * If out_pp_set does not exist, it is created with all members of pp_set
 * If pp_set does not exist or one of them is invalid, an error is returned */

int rsbac_pm_pp_union(rsbac_pm_pp_set_id_t pp_set,
		      rsbac_pm_out_pp_set_id_t out_pp_set)
{
	rsbac_pm_purpose_id_t *pp_array;
	long count;
	u_long i;

	/* check, whether set-id pp_set exists */
	if (!rsbac_list_lol_exist(pp_set_handle, &pp_set))
		return -RSBAC_EINVALIDVALUE;

	if (!rsbac_list_lol_exist(out_pp_set_handle, &out_pp_set)) {	/* out_pp_set not found -> try to create */
		count =
		    rsbac_list_lol_add(out_pp_set_handle, &out_pp_set,
				       NULL);
		if (count)
			return count;
	}
	/* out_pp_set exists -> add all members in pp_set */
	/* get all pp_set members */
	count =
	    rsbac_list_lol_get_all_subdesc(pp_set_handle, &pp_set,
					   (void **) &pp_array);
	if (count <= 0)
		return count;
	for (i = 0; i < count; i++) {
		rsbac_list_lol_subadd(out_pp_set_handle, &out_pp_set,
				      &pp_array[i], NULL);
	}
	rsbac_kfree(pp_array);
	return 0;
}

/* rsbac_pm_create_set */
/* Create a new set of given type set, using id id. Using any other set */
/* function for a set id without creating this set returns an error.    */
/* To empty an existing set use rsbac_pm_clear_set.                     */

int rsbac_pm_create_set(rsbac_list_ta_number_t ta_number,
			enum rsbac_pm_set_t set,
			union rsbac_pm_set_id_t id)
{
	switch (set) {
	case PS_TASK:
/*
		rsbac_pr_debug(ds_pm, "Creating task set\n");
*/
		if (rsbac_ta_list_lol_exist
		    (ta_number, task_set_handle, &id.task_set))
			return -RSBAC_EEXISTS;
		return rsbac_ta_list_lol_add_ttl(ta_number,
						 task_set_handle, 0,
						 &id.task_set, NULL);
	case PS_TP:
/*
		rsbac_pr_debug(ds_pm, "Creating tp set\n");
*/
		if (rsbac_ta_list_lol_exist
		    (ta_number, tp_set_handle, &id.tp_set))
			return -RSBAC_EEXISTS;
		return rsbac_ta_list_lol_add_ttl(ta_number, tp_set_handle,
						 0, &id.tp_set, NULL);
	case PS_RU:
/*
		rsbac_pr_debug(ds_pm, "Creating ru set\n");
*/
		if (rsbac_ta_list_lol_exist
		    (ta_number, ru_set_handle, &id.ru_set))
			return -RSBAC_EEXISTS;
		return rsbac_ta_list_lol_add_ttl(ta_number, ru_set_handle,
						 0, &id.ru_set, NULL);
	case PS_PP:
/*
		rsbac_pr_debug(ds_pm, "Creating pp set\n");
*/
		if (rsbac_ta_list_lol_exist
		    (ta_number, pp_set_handle, &id.pp_set))
			return -RSBAC_EEXISTS;
		return rsbac_ta_list_lol_add_ttl(ta_number, pp_set_handle,
						 0, &id.pp_set, NULL);
	case PS_IN_PP:
/*
		rsbac_pr_debug(ds_pm, "Creating in_pp set\n");
*/
		if (rsbac_ta_list_lol_exist
		    (ta_number, in_pp_set_handle, &id.in_pp_set))
			return -RSBAC_EEXISTS;
		return rsbac_ta_list_lol_add_ttl(ta_number,
						 in_pp_set_handle, 0,
						 &id.in_pp_set, NULL);
	case PS_OUT_PP:
/*
		rsbac_pr_debug(ds_pm, "Creating out_pp set\n");
*/
		if (rsbac_ta_list_lol_exist
		    (ta_number, out_pp_set_handle, &id.out_pp_set))
			return -RSBAC_EEXISTS;
		return rsbac_ta_list_lol_add_ttl(ta_number,
						 out_pp_set_handle, 0,
						 &id.out_pp_set, NULL);

	default:
		return (-RSBAC_EINVALIDTARGET);
	}
}

/* rsbac_pm_set_exist */
/* Return rsbac_boolean_t value whether set exists */

rsbac_boolean_t rsbac_pm_set_exist(rsbac_list_ta_number_t ta_number,
				   enum rsbac_pm_set_t set,
				   union rsbac_pm_set_id_t id)
{
	switch (set) {
	case PS_TASK:
		return rsbac_ta_list_lol_exist(ta_number, task_set_handle,
					       &id.task_set);
	case PS_TP:
		return rsbac_ta_list_lol_exist(ta_number, tp_set_handle,
					       &id.tp_set);
	case PS_RU:
		return rsbac_ta_list_lol_exist(ta_number, ru_set_handle,
					       &id.ru_set);
	case PS_PP:
		return rsbac_ta_list_lol_exist(ta_number, pp_set_handle,
					       &id.pp_set);
	case PS_IN_PP:
		return rsbac_ta_list_lol_exist(ta_number, in_pp_set_handle,
					       &id.in_pp_set);
	case PS_OUT_PP:
		return rsbac_ta_list_lol_exist(ta_number,
					       out_pp_set_handle,
					       &id.out_pp_set);

	default:
		return FALSE;
	}
}

/* rsbac_pm_remove_set */
/* Remove a full set. After this call the given id can only be used for */
/* creating a new set, anything else returns an error.                  */
/* To empty an existing set use rsbac_pm_clear_set.                     */
/* Caution: Writing to disk is done in the remove_item functions!       */

int rsbac_pm_remove_set(rsbac_list_ta_number_t ta_number,
			enum rsbac_pm_set_t set,
			union rsbac_pm_set_id_t id)
{
	switch (set) {
	case PS_TASK:
		return rsbac_ta_list_lol_remove(ta_number, task_set_handle,
						&id.task_set);
	case PS_TP:
		return rsbac_ta_list_lol_remove(ta_number, tp_set_handle,
						&id.tp_set);
	case PS_RU:
		return rsbac_ta_list_lol_remove(ta_number, ru_set_handle,
						&id.ru_set);
	case PS_PP:
		return rsbac_ta_list_lol_remove(ta_number, pp_set_handle,
						&id.pp_set);
	case PS_IN_PP:
		return rsbac_ta_list_lol_remove(ta_number,
						in_pp_set_handle,
						&id.in_pp_set);
	case PS_OUT_PP:
		return rsbac_ta_list_lol_remove(ta_number,
						out_pp_set_handle,
						&id.out_pp_set);

	default:
		return -RSBAC_EINVALIDTARGET;
	}
}

/**************/
/* Main lists */
/**************/

/* rsbac_pm_get_data() and rsbac_pm_set_data() change single data values.   */
/* rsbac_pm_add_target() adds a new list item and sets all data values as   */
/* given. rsbac_pm_remove_target() removes an item.                         */

/* A rsbac_pm_[sg]et_data() call for a non-existing target will return an   */
/* error.*/
/* Invalid parameter combinations return an error.                          */

int rsbac_pm_get_data(rsbac_list_ta_number_t ta_number,
		      enum rsbac_pm_target_t target,
		      union rsbac_pm_target_id_t tid,
		      enum rsbac_pm_data_t data,
		      union rsbac_pm_data_value_t *value)
{
	int err = 0;

	if (!value)
		return (-RSBAC_EINVALIDVALUE);

	switch (target) {
	case PMT_TASK:
		{
			struct rsbac_pm_task_data_t all_data;

/*
			rsbac_pr_debug(ds_pm, "Getting task data\n");
*/
			err =
			    rsbac_ta_list_get_data_ttl(ta_number,
						       task_handle, NULL,
						       &tid.task,
						       &all_data);
			if (err)
				return err;

			switch (data) {
			case PD_purpose:
				value->purpose = all_data.purpose;
				break;
			case PD_tp_set:
				value->tp_set = all_data.tp_set;
				break;
			case PD_ru_set:
				value->ru_set = all_data.ru_set;
				break;
			default:
				return -RSBAC_EINVALIDATTR;
			}
			return 0;
		}

	case PMT_CLASS:
		{
			struct rsbac_pm_class_data_t all_data;

/*
			rsbac_pr_debug(ds_pm, "Getting class data\n");
*/
			err =
			    rsbac_ta_list_get_data_ttl(ta_number,
						       class_handle, NULL,
						       &tid.object_class,
						       &all_data);
			if (err)
				return err;

			switch (data) {
			case PD_pp_set:
				value->pp_set = all_data.pp_set;
				break;
			default:
				return -RSBAC_EINVALIDATTR;
			}
			return 0;
		}

	case PMT_NA:
		{
			struct rsbac_pm_na_data_t all_data;

/*
			rsbac_pr_debug(ds_pm, "Getting na data\n");
*/
			err =
			    rsbac_ta_list_get_data_ttl(ta_number,
						       na_handle, NULL,
						       &tid.na, &all_data);
			if (err)
				return err;

			switch (data) {
			case PD_task:
				value->task = all_data.task;
				break;
			case PD_class:
				value->object_class =
				    all_data.object_class;
				break;
			case PD_tp:
				value->tp = all_data.tp;
				break;
			case PD_accesses:
				value->accesses = all_data.accesses;
				break;
			default:
				return -RSBAC_EINVALIDATTR;
			}
			return 0;
		}

	case PMT_CS:
		{
			struct rsbac_pm_cs_data_t all_data;

/*
			rsbac_pr_debug(ds_pm, "Getting cs data\n");
*/
			err =
			    rsbac_ta_list_get_data_ttl(ta_number,
						       cs_handle, NULL,
						       &tid.cs, &all_data);
			if (err)
				return err;

			switch (data) {
			case PD_purpose:
				value->purpose = all_data.purpose;
				break;
			case PD_file:
				value->file = all_data.file;
				break;
			default:
				return -RSBAC_EINVALIDATTR;
			}
			return 0;
		}

	case PMT_TP:
		{
			struct rsbac_pm_tp_data_t all_data;

/*
			rsbac_pr_debug(ds_pm, "Getting tp data\n");
*/
			err =
			    rsbac_ta_list_get_data_ttl(ta_number,
						       tp_handle, NULL,
						       &tid.tp, &all_data);
			if (err)
				return err;

			switch (data) {
			case PD_tp:
				value->tp = all_data.id;
				break;
			default:
				return -RSBAC_EINVALIDATTR;
			}
			return 0;
		}

	case PMT_PP:
		{
			struct rsbac_pm_pp_data_t all_data;

/*
			rsbac_pr_debug(ds_pm, "Getting pp data\n");
*/
			err =
			    rsbac_ta_list_get_data_ttl(ta_number,
						       pp_handle, NULL,
						       &tid.pp, &all_data);
			if (err)
				return err;

			switch (data) {
			case PD_purpose:
				value->purpose = all_data.id;
				break;
			case PD_def_class:
				value->def_class = all_data.def_class;
				break;
			default:
				return -RSBAC_EINVALIDATTR;
			}
			return 0;
		}

	case PMT_TKT:
		{
			struct rsbac_pm_tkt_data_t all_data;

/*
			rsbac_pr_debug(ds_pm, "Getting tkt data\n");
*/
			err =
			    rsbac_ta_list_get_data_ttl(ta_number,
						       tkt_handle, NULL,
						       &tid.tkt,
						       &all_data);
			if (err)
				return err;

			switch (data) {
			case PD_issuer:
				value->issuer = all_data.issuer;
				break;
			case PD_function_type:
				value->function_type =
				    all_data.function_type;
				break;
			case PD_function_param:
				value->function_param =
				    all_data.function_param;
				break;
			case PD_valid_until:
				value->valid_until = all_data.valid_until;
				break;
			default:
				return -RSBAC_EINVALIDATTR;
			}
			return 0;
		}

		/* switch target: no valid target */
	default:
		return (-RSBAC_EINVALIDTARGET);
	}
};				/* end of rsbac_pm_get_data() */

/************************************************************************** */

int rsbac_pm_get_all_data(rsbac_list_ta_number_t ta_number,
			  enum rsbac_pm_target_t target,
			  union rsbac_pm_target_id_t tid,
			  union rsbac_pm_all_data_value_t *value)
{
	if (!value)
		return (-RSBAC_EINVALIDVALUE);
	switch (target) {
	case PMT_TASK:
/*
		rsbac_pr_debug(ds_pm, "Getting task data\n");
*/
		return rsbac_ta_list_get_data_ttl(ta_number, task_handle,
						  NULL, &tid.task,
						  &value->task);

	case PMT_CLASS:
/*
		rsbac_pr_debug(ds_pm, "Getting class data\n");
*/
		return rsbac_ta_list_get_data_ttl(ta_number, class_handle,
						  NULL, &tid.object_class,
						  &value->object_class);

	case PMT_NA:
/*
		rsbac_pr_debug(ds_pm, "Getting na data\n");
*/
		return rsbac_ta_list_get_data_ttl(ta_number, na_handle,
						  NULL, &tid.na,
						  &value->na);

	case PMT_CS:
/*
		rsbac_pr_debug(ds_pm, "Getting cs data\n");
*/
		return rsbac_ta_list_get_data_ttl(ta_number, cs_handle,
						  NULL, &tid.cs,
						  &value->cs);

	case PMT_TP:
/*
		rsbac_pr_debug(ds_pm, "Getting tp data\n");
*/
		return rsbac_ta_list_get_data_ttl(ta_number, tp_handle,
						  NULL, &tid.tp,
						  &value->tp);

	case PMT_PP:
/*
		rsbac_pr_debug(ds_pm, "Getting pp data\n");
*/
		return rsbac_ta_list_get_data_ttl(ta_number, pp_handle,
						  NULL, &tid.pp,
						  &value->pp);

	case PMT_TKT:
/*
		rsbac_pr_debug(ds_pm, "Getting tkt data\n");
*/
		return rsbac_ta_list_get_data_ttl(ta_number, tkt_handle,
						  NULL, &tid.tkt,
						  &value->tkt);

		/* switch target: no valid target */
	default:
		return (-RSBAC_EINVALIDTARGET);
	}
}				/* end of rsbac_pm_get_all_data() */

/************************************************************************** */

rsbac_boolean_t rsbac_pm_exists(rsbac_list_ta_number_t ta_number,
				enum rsbac_pm_target_t target,
				union rsbac_pm_target_id_t tid)
{
	switch (target) {
	case PMT_TASK:
		return rsbac_ta_list_exist(ta_number, task_handle,
					   &tid.task);

	case PMT_CLASS:
		/* IPC and DEV classes always exist */
		if ((tid.object_class == RSBAC_PM_IPC_OBJECT_CLASS_ID)
		    || (tid.object_class == RSBAC_PM_DEV_OBJECT_CLASS_ID))
			return (TRUE);
		return rsbac_ta_list_exist(ta_number, class_handle,
					   &tid.object_class);

	case PMT_NA:
		return rsbac_ta_list_exist(ta_number, na_handle, &tid.na);

	case PMT_CS:
		return rsbac_ta_list_exist(ta_number, cs_handle, &tid.cs);

	case PMT_TP:
		return rsbac_ta_list_exist(ta_number, tp_handle, &tid.tp);

	case PMT_PP:
		return rsbac_ta_list_exist(ta_number, pp_handle, &tid.pp);

	case PMT_TKT:
		{
			struct rsbac_pm_tkt_data_t all_data;

			if (rsbac_ta_list_get_data_ttl
			    (ta_number, tkt_handle, NULL, &tid.tkt,
			     &all_data))
				return FALSE;

			/* ticket too old? -> remove it and return FALSE */
			{
				if (all_data.valid_until <
				    RSBAC_CURRENT_TIME) {
					rsbac_pm_pp_set_id_t pp_set =
					    -tid.tkt;

					if (rsbac_ta_list_lol_exist
					    (ta_number, pp_set_handle,
					     &pp_set))
						rsbac_ta_list_lol_remove
						    (ta_number,
						     pp_set_handle,
						     &pp_set);
					rsbac_ta_list_remove(ta_number,
							     tkt_handle,
							     &tid.tkt);
					return (FALSE);
				} else
					return TRUE;
			}
		}
		/* switch target: no valid target */
	default:
		rsbac_printk(KERN_WARNING "rsbac_pm_exists(): Invalid target!\n");
		return FALSE;
	}
}				/* end of rsbac_pm_exists() */

/************************************************************************** */

int rsbac_pm_set_data(rsbac_list_ta_number_t ta_number,
		      enum rsbac_pm_target_t target,
		      union rsbac_pm_target_id_t tid,
		      enum rsbac_pm_data_t data,
		      union rsbac_pm_data_value_t value)
{
	switch (target) {
	case PMT_TASK:
		{
			struct rsbac_pm_task_data_t all_data;
			int err;

/*
			rsbac_pr_debug(ds_pm, "Setting task data\n");
*/
			err =
			    rsbac_ta_list_get_data_ttl(ta_number,
						       task_handle, NULL,
						       &tid.task,
						       &all_data);
			if (err)
				return err;

			switch (data) {
			case PD_purpose:
				all_data.purpose = value.purpose;
				break;
			case PD_tp_set:
				all_data.tp_set = value.tp_set;
				break;
			case PD_ru_set:
				all_data.ru_set = value.ru_set;
				break;
			default:
				return -RSBAC_EINVALIDATTR;
			}
			err =
			    rsbac_ta_list_add_ttl(ta_number, task_handle,
						  0, &tid.task, &all_data);
			return err;
		}

	case PMT_CLASS:
		{
			struct rsbac_pm_class_data_t all_data;
			int err;

/*
			rsbac_pr_debug(ds_pm, "Setting class data\n");
*/
			err =
			    rsbac_ta_list_get_data_ttl(ta_number,
						       class_handle, NULL,
						       &tid.object_class,
						       &all_data);
			if (err)
				return err;

			switch (data) {
			case PD_pp_set:
				all_data.pp_set = value.pp_set;
				break;
			default:
				return -RSBAC_EINVALIDATTR;
			}
			err =
			    rsbac_ta_list_add_ttl(ta_number, class_handle,
						  0, &tid.object_class,
						  &all_data);
			return err;
		}

	case PMT_NA:
		{
			struct rsbac_pm_na_data_t all_data;
			int err;

/*
			rsbac_pr_debug(ds_pm, "Setting na data\n");
*/
			err =
			    rsbac_ta_list_get_data_ttl(ta_number,
						       na_handle, NULL,
						       &tid.na, &all_data);
			if (err)
				return err;

			switch (data) {
			case PD_task:
				all_data.task = value.task;
				break;
			case PD_class:
				all_data.object_class = value.object_class;
				break;
			case PD_tp:
				all_data.tp = value.tp;
				break;
			case PD_accesses:
				all_data.accesses = value.accesses;
				break;
			default:
				return -RSBAC_EINVALIDATTR;
			}
			err =
			    rsbac_ta_list_add_ttl(ta_number, na_handle, 0,
						  &tid.na, &all_data);
			return err;
		}

	case PMT_CS:
		{
			struct rsbac_pm_cs_data_t all_data;
			int err;

/*
			rsbac_pr_debug(ds_pm, "Setting cs data\n");
*/
			err =
			    rsbac_ta_list_get_data_ttl(ta_number,
						       cs_handle, NULL,
						       &tid.cs, &all_data);
			if (err)
				return err;

			switch (data) {
			case PD_purpose:
				all_data.purpose = value.purpose;
				break;
			case PD_file:
				all_data.file = value.file;
				break;
			default:
				return -RSBAC_EINVALIDATTR;
			}
			err =
			    rsbac_ta_list_add_ttl(ta_number, cs_handle, 0,
						  &tid.cs, &all_data);
			return err;
		}

	case PMT_TP:
		return -RSBAC_EINVALIDATTR;

	case PMT_PP:
		{
			struct rsbac_pm_pp_data_t all_data;
			int err;

/*
			rsbac_pr_debug(ds_pm, "Setting pp data\n");
*/
			err =
			    rsbac_ta_list_get_data_ttl(ta_number,
						       pp_handle, NULL,
						       &tid.pp, &all_data);
			if (err)
				return err;

			switch (data) {
			case PD_def_class:
				all_data.def_class = value.def_class;
				break;
			default:
				return -RSBAC_EINVALIDATTR;
			}
			err =
			    rsbac_ta_list_add_ttl(ta_number, pp_handle, 0,
						  &tid.pp, &all_data);
			return err;
		}

	case PMT_TKT:
		{
			struct rsbac_pm_tkt_data_t all_data;
			int err;

/*
			rsbac_pr_debug(ds_pm, "Setting tkt data\n");
*/
			err =
			    rsbac_ta_list_get_data_ttl(ta_number,
						       tkt_handle, NULL,
						       &tid.tkt,
						       &all_data);
			if (err)
				return err;

			switch (data) {
			case PD_issuer:
				all_data.issuer = value.issuer;
				break;
			case PD_function_type:
				all_data.function_type =
				    value.function_type;
				break;
			case PD_function_param:
				all_data.function_param =
				    value.function_param;
				break;
			case PD_valid_until:
				all_data.valid_until = value.valid_until;
				break;
			default:
				return -RSBAC_EINVALIDATTR;
			}
			err =
			    rsbac_ta_list_add_ttl(ta_number, tkt_handle, 0,
						  &tid.tkt, &all_data);
			return err;
		}

		/* switch target: no valid target */
	default:
		return (-RSBAC_EINVALIDTARGET);
	}
}				/* end of rsbac_pm_set_data() */

/************************************************************************** */

int rsbac_pm_add_target(rsbac_list_ta_number_t ta_number,
			enum rsbac_pm_target_t target,
			union rsbac_pm_all_data_value_t data)
{
	switch (target) {
	case PMT_TASK:
/*
		rsbac_pr_debug(ds_pm, "Adding task item\n");
*/
		return rsbac_ta_list_add_ttl(ta_number, task_handle, 0,
					     &data.task.id, &data.task);

	case PMT_CLASS:
/*
		rsbac_pr_debug(ds_pm, "Adding class item\n");
*/
		return rsbac_ta_list_add_ttl(ta_number, class_handle, 0,
					     &data.object_class.id,
					     &data.object_class);

	case PMT_NA:
		{
			struct rsbac_pm_na_id_t na_id;

/*
			rsbac_pr_debug(ds_pm, "Adding na item\n");
*/
			na_id.task = data.na.task;
			na_id.object_class = data.na.object_class;
			na_id.tp = data.na.tp;
			return rsbac_ta_list_add_ttl(ta_number, na_handle,
						     0, &na_id, &data.na);
		}

	case PMT_CS:
		{
			struct rsbac_pm_cs_id_t cs_id;

/*
			rsbac_pr_debug(ds_pm, "Adding cs item\n");
*/
			cs_id.purpose = data.cs.purpose;
			cs_id.file = data.cs.file;
			return rsbac_ta_list_add_ttl(ta_number, cs_handle,
						     0, &cs_id, &data.cs);
		}

	case PMT_TP:
/*
		rsbac_pr_debug(ds_pm, "Adding tp item\n");
*/
		return rsbac_ta_list_add_ttl(ta_number, tp_handle, 0,
					     &data.tp.id, &data.tp);

	case PMT_PP:
/*
		rsbac_pr_debug(ds_pm, "Adding pp item\n");
*/
		return rsbac_ta_list_add_ttl(ta_number, pp_handle, 0,
					     &data.pp.id, &data.pp);

	case PMT_TKT:
/*
		rsbac_pr_debug(ds_pm, "Adding tkt item\n");
*/
		return rsbac_ta_list_add_ttl(ta_number, tkt_handle, 0,
					     &data.tkt.id, &data.tkt);

		/* switch target: no valid target */
	default:
		return (-RSBAC_EINVALIDTARGET);
	}
}				/* end of rsbac_pm_add_target() */

/************************************************************************** */

int rsbac_pm_remove_target(rsbac_list_ta_number_t ta_number,
			   enum rsbac_pm_target_t target,
			   union rsbac_pm_target_id_t tid)
{
	switch (target) {
	case PMT_TASK:
/*
		rsbac_pr_debug(ds_pm, "Removing task data\n");
*/
		return rsbac_ta_list_remove(ta_number, task_handle,
					    &tid.task);

	case PMT_CLASS:
/*
		rsbac_pr_debug(ds_pm, "Removing class data\n");
*/
		return rsbac_ta_list_remove(ta_number, class_handle,
					    &tid.object_class);

	case PMT_NA:
/*
		rsbac_pr_debug(ds_pm, "Removing tp data\n");
*/
		return rsbac_ta_list_remove(ta_number, na_handle, &tid.na);

	case PMT_CS:
/*
		rsbac_pr_debug(ds_pm, "Removing cs data\n");
*/
		return rsbac_ta_list_remove(ta_number, cs_handle, &tid.cs);

	case PMT_TP:
/*
		rsbac_pr_debug(ds_pm, "Removing tp data\n");
*/
		return rsbac_ta_list_remove(ta_number, tp_handle, &tid.tp);

	case PMT_PP:
/*
		rsbac_pr_debug(ds_pm, "Removing pp data\n");
*/
		return rsbac_ta_list_remove(ta_number, pp_handle, &tid.pp);

	case PMT_TKT:
		{
			rsbac_pm_pp_set_id_t pp_set = -tid.tkt;

/*
			rsbac_pr_debug(ds_pm, "Removing tkt data\n");
*/
			if (rsbac_ta_list_lol_exist
			    (ta_number, pp_set_handle, &pp_set))
				rsbac_ta_list_lol_remove(ta_number,
							 pp_set_handle,
							 &pp_set);
			return rsbac_ta_list_remove(ta_number, tkt_handle,
						    &tid.tkt);
		}

	default:
		return (-RSBAC_EINVALIDTARGET);
	}
};				/* end of rsbac_remove_target() */

