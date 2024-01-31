// SPDX-License-Identifier: GPL-2.0+
//
// AMD ACP PCI Driver
//
// Copyright (C) 2020 Advanced Micro Devices, Inc. All rights reserved.

#include <linux/pci.h>
#include <linux/module.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/pm_runtime.h>
#include <linux/delay.h>

#include "acp5x.h"

struct acp5x_dev_data {
	void __iomem *acp5x_base;
	bool acp5x_audio_mode;
	struct resource *res;
	struct platform_device *pdev[5];
};

static int acp5x_power_on(void __iomem *acp5x_base)
{
	u32 val;
	int timeout;

	val = acp_readl(acp5x_base + ACP_PGFSM_STATUS);

	if (val == 0)
		return val;

	if ((val & ACP_PGFSM_STATUS_MASK) !=
				ACP_POWER_ON_IN_PROGRESS)
		acp_writel(ACP_PGFSM_CNTL_POWER_ON_MASK,
			   acp5x_base + ACP_PGFSM_CONTROL);
	timeout = 0;
	while (++timeout < 500) {
		val = acp_readl(acp5x_base + ACP_PGFSM_STATUS);
		if (!val)
			return 0;
		udelay(1);
	}
	return -ETIMEDOUT;
}

static int acp5x_power_off(void __iomem *acp5x_base)
{
	u32 val;
	int timeout;

	acp_writel(ACP_PGFSM_CNTL_POWER_OFF_MASK,
		   acp5x_base + ACP_PGFSM_CONTROL);
	timeout = 0;
	while (++timeout < 500) {
		val = acp_readl(acp5x_base + ACP_PGFSM_STATUS);
		if ((val & ACP_PGFSM_STATUS_MASK) == ACP_POWERED_OFF)
			return 0;
		udelay(1);
	}
	return -ETIMEDOUT;
}

static int acp5x_reset(void __iomem *acp5x_base)
{
	u32 val;
	int timeout;

	acp_writel(1, acp5x_base + ACP_SOFT_RESET);
	timeout = 0;
	while (++timeout < 500) {
		val = acp_readl(acp5x_base + ACP_SOFT_RESET);
		if (val & ACP_SOFT_RESET_SOFTRESET_AUDDONE_MASK)
			break;
		cpu_relax();
	}
	acp_writel(0, acp5x_base + ACP_SOFT_RESET);
	timeout = 0;
	while (++timeout < 500) {
		val = acp_readl(acp5x_base + ACP_SOFT_RESET);
		if (!val)
			return 0;
		cpu_relax();
	}
	return -ETIMEDOUT;
}

static int acp5x_init(void __iomem *acp5x_base)
{
	int ret;

	/* power on */
	ret = acp5x_power_on(acp5x_base);
	if (ret) {
		pr_err("ACP5x power on failed\n");
		return ret;
	}
	/* Reset */
	ret = acp5x_reset(acp5x_base);
	if (ret) {
		pr_err("ACP5x reset failed\n");
		return ret;
	}
	return 0;
}

static int acp5x_deinit(void __iomem *acp5x_base)
{
	int ret;

	/* Reset */
	ret = acp5x_reset(acp5x_base);
	if (ret) {
		pr_err("ACP5x reset failed\n");
		return ret;
	}
	/* power off */
	ret = acp5x_power_off(acp5x_base);
	if (ret) {
		pr_err("ACP5x power off failed\n");
		return ret;
	}
	return 0;
}

static int snd_acp5x_probe(struct pci_dev *pci,
			   const struct pci_device_id *pci_id)
{
	struct acp5x_dev_data *adata;
	struct platform_device_info pdevinfo[6];
	unsigned int irqflags;
	int ret, i;
	u32 addr, val;

	if (pci_enable_device(pci)) {
		dev_err(&pci->dev, "pci_enable_device failed\n");
		return -ENODEV;
	}

	ret = pci_request_regions(pci, "AMD ACP5x audio");
	if (ret < 0) {
		dev_err(&pci->dev, "pci_request_regions failed\n");
		goto disable_pci;
	}

	adata = devm_kzalloc(&pci->dev, sizeof(struct acp5x_dev_data),
			     GFP_KERNEL);
	if (!adata) {
		ret = -ENOMEM;
		goto release_regions;
	}

	/* check for msi interrupt support */
	ret = pci_enable_msi(pci);
	if (ret)
		/* msi is not enabled */
		irqflags = IRQF_SHARED;
	else
		/* msi is enabled */
		irqflags = 0;

	addr = pci_resource_start(pci, 0);
	adata->acp5x_base = devm_ioremap(&pci->dev, addr,
					 pci_resource_len(pci, 0));
	if (!adata->acp5x_base) {
		ret = -ENOMEM;
		goto disable_msi;
	}
	pci_set_master(pci);
	pci_set_drvdata(pci, adata);
	ret = acp5x_init(adata->acp5x_base);
	if (ret)
		goto disable_msi;

	val = acp_readl(adata->acp5x_base + ACP_PIN_CONFIG);
	switch (val) {
	case I2S_MODE:
		adata->res = devm_kzalloc(&pci->dev,
					  sizeof(struct resource) * 4,
					  GFP_KERNEL);
		if (!adata->res) {
			ret = -ENOMEM;
			goto de_init;
		}

		adata->res[0].name = "acp5x_i2s_iomem";
		adata->res[0].flags = IORESOURCE_MEM;
		adata->res[0].start = addr;
		adata->res[0].end = addr + (ACP5x_REG_END - ACP5x_REG_START);

		adata->res[1].name = "acp5x_i2s_sp";
		adata->res[1].flags = IORESOURCE_MEM;
		adata->res[1].start = addr + ACP5x_I2STDM_REG_START;
		adata->res[1].end = addr + ACP5x_I2STDM_REG_END;

		adata->res[2].name = "acp5x_i2s_bt";
		adata->res[2].flags = IORESOURCE_MEM;
		adata->res[2].start = addr + ACP5x_BT_TDM_REG_START;
		adata->res[2].end = addr + ACP5x_BT_TDM_REG_END;

		adata->res[3].name = "acp5x_i2s_irq";
		adata->res[3].flags = IORESOURCE_IRQ;
		adata->res[3].start = pci->irq;
		adata->res[3].end = adata->res[3].start;

		adata->acp5x_audio_mode = ACP5x_I2S_MODE;

		memset(&pdevinfo, 0, sizeof(pdevinfo));
		pdevinfo[0].name = "acp5x_i2s_dma";
		pdevinfo[0].id = 0;
		pdevinfo[0].parent = &pci->dev;
		pdevinfo[0].num_res = 4;
		pdevinfo[0].res = &adata->res[0];
		pdevinfo[0].data = &irqflags;
		pdevinfo[0].size_data = sizeof(irqflags);

		pdevinfo[1].name = "acp5x_i2s_playcap";
		pdevinfo[1].id = 0;
		pdevinfo[1].parent = &pci->dev;
		pdevinfo[1].num_res = 1;
		pdevinfo[1].res = &adata->res[1];

		pdevinfo[2].name = "acp5x_i2s_playcap";
		pdevinfo[2].id = 1;
		pdevinfo[2].parent = &pci->dev;
		pdevinfo[2].num_res = 1;
		pdevinfo[2].res = &adata->res[2];

		pdevinfo[3].name = "dummy_w5102";
		pdevinfo[3].id = 0;
		pdevinfo[3].parent = &pci->dev;

		pdevinfo[4].name = "acp5x_w5102_mach";
		pdevinfo[4].id = 0;
		pdevinfo[4].parent = &pci->dev;
		for (i = 0; i < ACP5x_DEVS; i++) {
			adata->pdev[i] =
				platform_device_register_full(&pdevinfo[i]);
			if (IS_ERR(adata->pdev[i])) {
				dev_err(&pci->dev, "cannot register %s device\n",
					pdevinfo[i].name);
				ret = PTR_ERR(adata->pdev[i]);
				goto unregister_devs;
		}
		/* create dummy mach device */
		}
		break;
	default:
		dev_err(&pci->dev, "Invalid ACP audio mode : %d\n", val);
		ret = -ENODEV;
		goto disable_msi;
	}
	pm_runtime_set_autosuspend_delay(&pci->dev, 2000);
	pm_runtime_use_autosuspend(&pci->dev);
	pm_runtime_put_noidle(&pci->dev);
	pm_runtime_allow(&pci->dev);
	return 0;

unregister_devs:
	if (val == I2S_MODE)
		for (i = 0; i < ACP5x_DEVS; i++)
			platform_device_unregister(adata->pdev[i]);
de_init:
	if (acp5x_deinit(adata->acp5x_base))
		dev_err(&pci->dev, "ACP de-init failed\n");
disable_msi:
	pci_disable_msi(pci);
release_regions:
	pci_release_regions(pci);
disable_pci:
	pci_disable_device(pci);

	return ret;
}

static int snd_acp5x_suspend(struct device *dev)
{
	int ret;
	struct acp5x_dev_data *adata;

	adata = dev_get_drvdata(dev);
	ret = acp5x_deinit(adata->acp5x_base);
	if (ret)
		dev_err(dev, "ACP de-init failed\n");
	else
		dev_dbg(dev, "ACP de-initialized\n");

	return ret;
}

static int snd_acp5x_resume(struct device *dev)
{
	int ret;
	struct acp5x_dev_data *adata;

	adata = dev_get_drvdata(dev);
	ret = acp5x_init(adata->acp5x_base);
	if (ret) {
		dev_err(dev, "ACP init failed\n");
		return ret;
	}
	return 0;
}

static const struct dev_pm_ops acp5x_pm = {
	.runtime_suspend = snd_acp5x_suspend,
	.runtime_resume =  snd_acp5x_resume,
	.resume =	snd_acp5x_resume,
};

static void snd_acp5x_remove(struct pci_dev *pci)
{
	struct acp5x_dev_data *adata;
	int i, ret;

	adata = pci_get_drvdata(pci);
	if (adata->acp5x_audio_mode == ACP5x_I2S_MODE) {
		for (i = 0; i < ACP5x_DEVS; i++)
			platform_device_unregister(adata->pdev[i]);
	}
	ret = acp5x_deinit(adata->acp5x_base);
	if (ret)
		dev_err(&pci->dev, "ACP de-init failed\n");
	pm_runtime_forbid(&pci->dev);
	pm_runtime_get_noresume(&pci->dev);
	pci_disable_msi(pci);
	pci_release_regions(pci);
	pci_disable_device(pci);
}

static const struct pci_device_id snd_acp5x_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, 0x15e2),
	.class = PCI_CLASS_MULTIMEDIA_OTHER << 8,
	.class_mask = 0xffffff },
	{ 0, },
};
MODULE_DEVICE_TABLE(pci, snd_acp5x_ids);

static struct pci_driver acp5x_driver  = {
	.name = KBUILD_MODNAME,
	.id_table = snd_acp5x_ids,
	.probe = snd_acp5x_probe,
	.remove = snd_acp5x_remove,
	.driver = {
		.pm = &acp5x_pm,
	}
};

module_pci_driver(acp5x_driver);

MODULE_DESCRIPTION("AMD ACP5x PCI driver");
MODULE_LICENSE("GPL v2");
