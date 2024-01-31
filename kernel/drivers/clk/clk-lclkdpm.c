// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Advanced Micro Devices, Inc. All rights reserved.
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

#define GSM_NOVA_LCLK_STATE (GSM_RESERVED_LCLK_STATE)
#define GSM_CVIP_LCLK_STATE (GSM_NOVA_LCLK_STATE + 4)

static struct gsm_spinlock_context lclk_spinlock;
#endif

#define DISABLE_LCLK_SWITCHING 0
#define ENABLE_LCLK_SWITCHING  1

struct kobject *lclkdpm_kobject;

DEFINE_MUTEX(lclkctl_mutex);
static uint32_t lclkctl_cnt;

static int smu_calculatelclkbusy(u32 value);

static int lclkctl_open(struct inode *inode, struct file *filp)
{
	int ret = 0;

	mutex_lock(&lclkctl_mutex);

	if (!lclkctl_cnt)
		// send smu message to disable lclk switching
		ret = smu_calculatelclkbusy(DISABLE_LCLK_SWITCHING);

	if (!ret)
		++lclkctl_cnt;

	mutex_unlock(&lclkctl_mutex);
	return ret;
}

static int lclkctl_release(struct inode *inode, struct file *filp)
{
	int ret = 0;

	mutex_lock(&lclkctl_mutex);

	if (lclkctl_cnt == 1)
		// send smu message to enable lclk switching
		ret = smu_calculatelclkbusy(ENABLE_LCLK_SWITCHING);

	if (!ret)
		--lclkctl_cnt;

	mutex_unlock(&lclkctl_mutex);
	return ret;
}

const struct file_operations lclkctl_fops = {
	.open = lclkctl_open,
	.release = lclkctl_release,
};

struct miscdevice lclkctl_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "lclkctl",
	.fops = &lclkctl_fops,
};

static int smu_calculatelclkbusy(u32 value)
{
	struct smu_msg msg;
	__maybe_unused int err;
	__maybe_unused uint32_t nova_lclk_state;

	if (value != 0 && value != 1)
		return -1;

#ifdef CONFIG_ML_GSM
	err = gsm_spin_lock(&lclk_spinlock);
	if (err) {
		pr_err("lclk gsm_spin_lock() failed (%d)\n", err);
		return -1;
	}

	/* check nova lclk switching state, don't do anything if it's disabled */
	nova_lclk_state = gsm_raw_read_32(GSM_NOVA_LCLK_STATE);

	if (nova_lclk_state) {
#endif
		smu_msg(&msg, CVSMC_MSG_calculatelclkbusyfromiohconly, value);
		if (unlikely(!smu_send_single_msg(&msg))) {
			pr_err("Failed to send smu msg of CalculateLclkBusyfromIohcOnly\n");
#ifdef CONFIG_ML_GSM
			gsm_spin_unlock(&lclk_spinlock);
#endif
			return -1;
		}
#ifdef CONFIG_ML_GSM
	}
	/* update cvip lclk switching state */
	gsm_raw_write_32(GSM_CVIP_LCLK_STATE, value);
	gsm_spin_unlock(&lclk_spinlock);
#endif
	return 0;
}

static int smu_updatelclkdpmconstants(u32 value)
{
	struct smu_msg msg;

	smu_msg(&msg, CVSMC_MSG_updatelclkdpmconstants, value);
	if (unlikely(!smu_send_single_msg(&msg))) {
		pr_err("Failed to send smu msg of UpdateLclkDpmConstants\n");
		return -1;
	}

	return 0;
}

static ssize_t calculatelclkbusy_store(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       const char *buf, size_t n)
{
	u32 val;
	int ret;

	ret = kstrtou32(buf, 0, &val);
	if (unlikely(ret))
		return ret;

	ret = smu_calculatelclkbusy(val);
	if (ret)
		return ret;

	return n;
}

static ssize_t updatelclkdpmconstants_store(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    const char *buf, size_t n)
{
	u32 val;
	u32 update, threshold;
	int ret;

	if (sscanf(buf, "%x %x", &update, &threshold) != 2)
		return -EINVAL;

	if (update != 1 && update != 2 && update != 3)
		return -EINVAL;

	val = (update << 30) | threshold;

	ret = smu_updatelclkdpmconstants(val);
	if (ret)
		return ret;

	return n;
}

static struct kobj_attribute calculatelclkbusy_attr = {
	.attr	= {
		.name = __stringify(calculatelclkbusy),
		.mode = 0200,
	},
	.store	= calculatelclkbusy_store,
};

static struct kobj_attribute updatelclkdpmconstants_attr = {
	.attr	= {
		.name = __stringify(updatelclkdpmconstants),
		.mode = 0200,
	},
	.store	= updatelclkdpmconstants_store,
};

struct attribute *lclkdpm_attrs[] = {
	&calculatelclkbusy_attr.attr,
	&updatelclkdpmconstants_attr.attr,
	NULL,
};

struct attribute_group lclkdpm_attr_group = {
	.attrs = lclkdpm_attrs,
};

static int __init lclkdpm_module_init(void)
{
	int ret;

	lclkdpm_kobject = kobject_create_and_add("lclkdpm", NULL);
	if (!lclkdpm_kobject) {
		pr_err("Cannot create lclkdpm kobject\n");
		goto err_kobj;
	}

	if (sysfs_create_group(lclkdpm_kobject,
			       &lclkdpm_attr_group)) {
		pr_err("Cannot create sysfs file\n");
		goto err_sysfs;
	}

	ret = misc_register(&lclkctl_dev);
	if (ret) {
		pr_err("Failed to register lclkctl misc device.\n");
		return ret;
	}

#ifdef CONFIG_ML_GSM
	lclk_spinlock.nibble_addr = GSM_RESERVED_PREDEF_CVCORE_LOCKS_X86;
	lclk_spinlock.nibble_id = GSM_PREDEF_LCLK_STATE_LOCK_NIBBLE;
	gsm_spin_unlock(&lclk_spinlock);

	gsm_raw_write_32(GSM_RESERVED_LCLK_STATE, lclk_spinlock.nibble_addr);
	gsm_raw_write_32(GSM_RESERVED_LCLK_STATE + sizeof(lclk_spinlock.nibble_addr),
		lclk_spinlock.nibble_id);

	/* assume lclk switching is disabled on nova side until it updates its state */
	gsm_raw_write_32(GSM_NOVA_LCLK_STATE, 0);
	gsm_raw_write_32(GSM_CVIP_LCLK_STATE, 1);
#endif

	return 0;

err_sysfs:
	kobject_put(lclkdpm_kobject);
err_kobj:
	return -1;
}

static void __exit lclkdpm_module_exit(void)
{
	misc_deregister(&lclkctl_dev);

	if (!lclkdpm_kobject)
		return;

	sysfs_remove_group(lclkdpm_kobject, &lclkdpm_attr_group);
	kobject_put(lclkdpm_kobject);
}

module_init(lclkdpm_module_init);
module_exit(lclkdpm_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Wenyou Yang <wenyou.yang@amd.com>");
MODULE_DESCRIPTION("Allow enabling/disabling the LCLK switching");
