// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022-2023 Advanced Micro Devices, Inc. All rights reserved.
 */

#include <linux/init.h>
#include <linux/err.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/smu_protocol.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>

#ifdef CONFIG_ML_GSM
#include <linux/cvip/gsm.h>
#include <linux/cvip/gsm_cvip.h>
#include <linux/cvip/gsm_spinlock.h>

#define GSM_NOVA_FCLK_STATE (GSM_RESERVED_FCLK_STATE)
#define GSM_CVIP_FCLK_STATE (GSM_NOVA_FCLK_STATE + 4)

static struct gsm_spinlock_context fclk_spinlock;
#endif

struct kobject *fclkdpmlevel_kobject;

DEFINE_MUTEX(fclkctl_mutex);
static uint32_t fclkctl_cnt;

static int smu_force_fclkdpmlevel(u32 pstate);
static int smu_unforce_fclkdpmlevel(void);

static int fclkctl_open(struct inode *inode, struct file *filp)
{
	int ret = 0;

	mutex_lock(&fclkctl_mutex);

	if (!fclkctl_cnt)
		//force fclk 800 MHz/LPDDR5500
		ret = smu_force_fclkdpmlevel(0);

	if (!ret)
		++fclkctl_cnt;

	mutex_unlock(&fclkctl_mutex);
	return ret;
}

static int fclkctl_release(struct inode *inode, struct file *filp)
{
	int ret = 0;

	mutex_lock(&fclkctl_mutex);

	if (fclkctl_cnt == 1)
		// restore fclk switching
		ret = smu_unforce_fclkdpmlevel();

	if (!ret)
		--fclkctl_cnt;

	mutex_unlock(&fclkctl_mutex);
	return ret;
}

int fclkctl_disable_switching(void)
{
	return fclkctl_open(NULL, NULL);
}
EXPORT_SYMBOL(fclkctl_disable_switching);

int fclkctl_enable_switching(void)
{
	return fclkctl_release(NULL, NULL);
}
EXPORT_SYMBOL(fclkctl_enable_switching);

const struct file_operations fclkctl_fops = {
	.open = fclkctl_open,
	.release = fclkctl_release,
};

struct miscdevice fclkctl_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "fclkctl",
	.fops = &fclkctl_fops,
};

static int smu_force_fclkdpmlevel(u32 pstate)
{
	struct smu_msg msg;
	__maybe_unused int err;
	__maybe_unused uint32_t nova_fclk_state;

	if (pstate != 0 && pstate != 1)
		return -1;

#ifdef CONFIG_ML_GSM
	err = gsm_spin_lock(&fclk_spinlock);
	if (err) {
		pr_err("fclk gsm_spin_lock() failed (%d)\n", err);
		return -1;
	}

	/* check nova fclk switching state, don't do anything if it's disabled */
	nova_fclk_state = gsm_raw_read_32(GSM_NOVA_FCLK_STATE);

	if (nova_fclk_state) {
#endif

		smu_msg(&msg, CVSMC_MSG_forcefclkdpmlevel, pstate);
		if (unlikely(!smu_send_single_msg(&msg))) {
			pr_err("Failed to send smu msg of ForceFclkDpmLevel\n");
#ifdef CONFIG_ML_GSM
			gsm_spin_unlock(&fclk_spinlock);
#endif
			return -1;
		}
#ifdef CONFIG_ML_GSM
	}
	/* update cvip fclk switching state */
	gsm_raw_write_32(GSM_CVIP_FCLK_STATE, 0);
	gsm_spin_unlock(&fclk_spinlock);
#endif
	return 0;
}

static int smu_unforce_fclkdpmlevel(void)
{
	struct smu_msg msg;
	__maybe_unused int err;
	__maybe_unused uint32_t nova_fclk_state;

#ifdef CONFIG_ML_GSM
	err = gsm_spin_lock(&fclk_spinlock);
	if (err) {
		pr_err("fclk gsm_spin_lock() failed (%d)\n", err);
		return -1;
	}

	/* check nova fclk switching state, don't do anything if it's disabled */
	nova_fclk_state = gsm_raw_read_32(GSM_NOVA_FCLK_STATE);

	if (nova_fclk_state) {
#endif
		smu_msg(&msg, CVSMC_MSG_unforcefclkdpmlevel, 0);
		if (unlikely(!smu_send_single_msg(&msg))) {
			pr_err("Failed to send smu msg of UnforceFclkDpmLevel\n");
#ifdef CONFIG_ML_GSM
			gsm_spin_unlock(&fclk_spinlock);
#endif
			return -1;
		}
#ifdef CONFIG_ML_GSM
	}
	/* update cvip fclk switching state */
	gsm_raw_write_32(GSM_CVIP_FCLK_STATE, 1);
	gsm_spin_unlock(&fclk_spinlock);
#endif

	return 0;
}

static ssize_t force_fclkdpmlevel_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t n)
{
	u32 val;
	int ret;

	ret = kstrtou32(buf, 0, &val);
	if (unlikely(ret))
		return ret;

	ret = smu_force_fclkdpmlevel(val);
	if (ret)
		return ret;

	return n;
}

static ssize_t unforce_fclkdpmlevel_store(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  const char *buf, size_t n)
{
	int ret;

	ret = smu_unforce_fclkdpmlevel();
	if (ret)
		return ret;

	return n;
}

static struct kobj_attribute force_fclkdpmlevel_attr = {
	.attr	= {
		.name = __stringify(force_fclkdpmlevel),
		.mode = 0200,
	},
	.store	= force_fclkdpmlevel_store,
};

static struct kobj_attribute unforce_fclkdpmlevel_attr = {
	.attr	= {
		.name = __stringify(unforce_fclkdpmlevel),
		.mode = 0200,
	},
	.store	= unforce_fclkdpmlevel_store,
};

struct attribute *fclkdpmlevel_attrs[] = {
	&force_fclkdpmlevel_attr.attr,
	&unforce_fclkdpmlevel_attr.attr,
	NULL,
};

struct attribute_group fclkdpmlevel_attr_group = {
	.attrs = fclkdpmlevel_attrs,
};

static int __init fclkdpmlevel_module_init(void)
{
	int ret;

	fclkdpmlevel_kobject = kobject_create_and_add("fclkdpmlevel", NULL);
	if (!fclkdpmlevel_kobject) {
		pr_err("Cannot create fclkdpmlevel kobject\n");
		goto err_kobj;
	}

	if (sysfs_create_group(fclkdpmlevel_kobject,
			       &fclkdpmlevel_attr_group)) {
		pr_err("Cannot create sysfs file\n");
		goto err_sysfs;
	}

	ret = misc_register(&fclkctl_dev);
	if (ret) {
		pr_err("Failed to register fclkctl misc device.\n");
		return ret;
	}

#ifdef CONFIG_ML_GSM
	fclk_spinlock.nibble_addr = GSM_RESERVED_PREDEF_CVCORE_LOCKS_X86;
	fclk_spinlock.nibble_id = GSM_PREDEF_FCLK_STATE_LOCK_NIBBLE;
	gsm_spin_unlock(&fclk_spinlock);

	gsm_raw_write_32(GSM_RESERVED_FCLK_STATE, fclk_spinlock.nibble_addr);
	gsm_raw_write_32(GSM_RESERVED_FCLK_STATE + sizeof(fclk_spinlock.nibble_addr),
		fclk_spinlock.nibble_id);

	/* assume fclk switching is disabled on nova side until it updates its state */
	gsm_raw_write_32(GSM_NOVA_FCLK_STATE, 0);
	gsm_raw_write_32(GSM_CVIP_FCLK_STATE, 1);
#endif

	return 0;

err_sysfs:
	kobject_put(fclkdpmlevel_kobject);
err_kobj:
	return -1;
}

static void __exit fclkdpmlevel_module_exit(void)
{
	misc_deregister(&fclkctl_dev);

	if (!fclkdpmlevel_kobject)
		return;

	sysfs_remove_group(fclkdpmlevel_kobject, &fclkdpmlevel_attr_group);
	kobject_put(fclkdpmlevel_kobject);
}

module_init(fclkdpmlevel_module_init);
module_exit(fclkdpmlevel_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Wenyou Yang <wenyou.yang@amd.com>");
MODULE_DESCRIPTION("Force/Unfore fclkdpmlevel");
