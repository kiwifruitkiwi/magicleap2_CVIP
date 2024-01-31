/*
 * Copyright (C) 2019-2020 Magic Leap, Inc. All rights reserved.
 */

#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/debugfs.h>
#include <linux/clk.h>
#include <linux/cvip_event_logger.h>
#include <linux/dma-buf.h>
#include <linux/fdtable.h>
#include <linux/sched/task.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/poll.h>
#include <linux/debugfs.h>
#include <linux/vcam_isp_dev.h>
#include <asm/cacheflush.h>
#include <linux/sched/clock.h>
#include <linux/timekeeping.h>
#include "ipc_types.h"
#include "ipc_vcam_isp.h"
#include "ipc_messageid.h"
#include "ipc_core.h"
#include "ipc_sensor.h"

#define IPC_VCAM_ISP_CTRL_MINOR_NUM     0
#define IPC_VCAM_ISP_DATA_IN_MINOR_NUM  1
#define IPC_VCAM_ISP_DATA_OUT_MINOR_NUM 2

//TODO(bknottek): increase when other virtual devs are added.
#define IPC_VCAM_ISP_MAX_DEVS 3
#define IPC_VCAM_ISP_NUM_EVTS 16
#define IPC_VCAM_ISP_NUM_IO_EVTS 48

struct ipc_vcam_isp_cam_ctrl {
	struct platform_device *pdev;
	struct device *dev;
	struct cdev cdev;
	dev_t devno;
	char name[64];
	ktime_t last_wdma_ktime;
	struct reg_wdma_report last_wdma_status;

	wait_queue_head_t waitq;

	struct ctrl_event {
		struct vcam_isp_ctrl_req req;
		struct list_head list;
	} ctrl_event_array[IPC_VCAM_ISP_NUM_EVTS];

	spinlock_t        rd_evt_lock;
	struct list_head  ready_evts;
	spinlock_t        free_evt_lock;
	struct list_head  free_evts;
};

struct ipc_vcam_isp_input_io {
	struct platform_device *pdev;
	struct device *dev;
	struct cdev cdev;
	dev_t devno;
	char name[64];
	u64 input_base;
	u64 prepost_base;
	u32 prepost_size;

	wait_queue_head_t waitq;

	struct inputio_event {
		struct vcam_isp_input_io_release rel;
		struct list_head list;
	} inputio_event_array[IPC_VCAM_ISP_NUM_IO_EVTS];

	spinlock_t        rd_evt_lock;
	struct list_head  ready_evts;
	spinlock_t        free_evt_lock;
	struct list_head  free_evts;
};

struct ipc_vcam_isp_output_io {
	struct platform_device *pdev;
	struct device *dev;
	struct cdev cdev;
	dev_t devno;
	char name[64];
	u64 stats_base;
	u32 stats_size;

	wait_queue_head_t waitq;

	struct outputio_event {
		struct vcam_isp_output_io_data out_io;
		struct list_head list;
	} outputio_event_array[IPC_VCAM_ISP_NUM_IO_EVTS];

	spinlock_t        rd_evt_lock;
	struct list_head  ready_evts;
	spinlock_t        free_evt_lock;
	struct list_head  free_evts;
};

static struct ipc_vcam_isp_cam_ctrl  g_vcam_cam_ctrl;
static struct ipc_vcam_isp_input_io  g_vcam_input_io;
static struct ipc_vcam_isp_output_io g_vcam_output_io;
struct class *g_vcam_isp_class;

static ssize_t prepost_mem_write(struct file *filp, struct kobject *kobj,
				 struct bin_attribute *attr,
				 char *buf, loff_t off, size_t count)
{
	// Check that we're not accessing past the end of the structure.
	if ((off + count) > attr->size) {
		pr_err("%s: %s: illegal write: off=%lld, size=%ld\n",
			   VCAM_ISP_DEV_NAME, __func__, off, attr->size);
		return -1;
	}

	memcpy((uint8_t *)g_vcam_input_io.prepost_base + off, buf, count);

	return count;
}

static ssize_t prepost_mem_read(struct file *filp, struct kobject *kobj,
				struct bin_attribute *attr,
				char *buf, loff_t off, size_t count)
{
	// Check that we're not accessing past the end of the region.
	if ((off + count) > attr->size) {
		pr_err("%s: %s: illegal read: off=%lld, size=%lu\n",
			   VCAM_ISP_DEV_NAME, __func__, off, attr->size);
		return -EFAULT;
	}

	memcpy(buf, (uint8_t *)g_vcam_input_io.prepost_base + off, count);

	return count;
}

static int prepost_mem_mmap(struct file *filp, struct kobject *kobj,
			    struct bin_attribute *attr,
			    struct vm_area_struct *vma)
{
	struct page *page = NULL;
	int length_pg;

	// Make sure we got a page-aligned length.
	if (((vma->vm_end - vma->vm_start) % PAGE_SIZE) != 0) {
		pr_err("%s: %s: bad length\n", VCAM_ISP_DEV_NAME, __func__);
		return -EINVAL;
	}

	// Make sure the user isn't trying to get more than they're entitled to.
	length_pg = ((attr->size - 1) >> PAGE_SHIFT) + 1;
	if (vma->vm_pgoff + vma_pages(vma) > length_pg) {
		pr_err("%s: %s: illegal prepost_mem size (%ld) vs (%d)\n",
			   VCAM_ISP_DEV_NAME, __func__,
			   vma->vm_pgoff + vma_pages(vma), length_pg);
		return -EPERM;
	}

	pr_info("%s: %s: length=%d, physaddr=%llx\n",
			VCAM_ISP_DEV_NAME, __func__, length_pg,
			g_vcam_input_io.prepost_base);

	page = virt_to_page((unsigned long) g_vcam_input_io.prepost_base +
						(vma->vm_pgoff << PAGE_SHIFT));
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP | VM_SHARED;
	if (remap_pfn_range(vma,
						vma->vm_start,
						page_to_pfn(page),
						vma->vm_end - vma->vm_start,
						vma->vm_page_prot)) {
		pr_err("%s: %s: remap_pfn_range: failed\n",
			   VCAM_ISP_DEV_NAME, __func__);
		return -EAGAIN;
	}

	return 0;
}

static struct bin_attribute attr_prepost_mem = {
	.attr.name = VCAM_ISP_PREPOST_MEM,
	.attr.mode = 0666,
	.write = prepost_mem_write,
	.read = prepost_mem_read,
	.mmap = prepost_mem_mmap,
	.size = 0
};

static ssize_t stats_mem_read(struct file *filp, struct kobject *kobj,
			      struct bin_attribute *attr,
			      char *buf, loff_t off, size_t count)
{
	// Check that we're not accessing past the end of the region.
	if ((off + count) > attr->size) {
		pr_err("%s: %s: illegal read: off=%lld, size=%lu\n",
			   VCAM_ISP_DEV_NAME, __func__, off, attr->size);
		return -EFAULT;
	}

	memcpy(buf, (uint8_t *)g_vcam_output_io.stats_base + off, count);

	return count;
}

static int stats_mem_mmap(struct file *filp, struct kobject *kobj,
						  struct bin_attribute *attr,
						  struct vm_area_struct *vma)
{
	struct page *page = NULL;
	int length_pg;

	// Make sure we got a page-aligned length.
	if (((vma->vm_end - vma->vm_start) % PAGE_SIZE) != 0) {
		pr_err("%s: %s: bad length\n", VCAM_ISP_DEV_NAME, __func__);
		return -EINVAL;
	}

	// Make sure the user isn't trying to get more than they're entitled to.
	length_pg = ((attr->size - 1) >> PAGE_SHIFT) + 1;
	if (vma->vm_pgoff + vma_pages(vma) > length_pg) {
		pr_err("%s: %s: illegal stats_mem size (%ld) vs (%d)\n",
			   VCAM_ISP_DEV_NAME, __func__,
			   vma->vm_pgoff + vma_pages(vma), length_pg);
		return -EPERM;
	}

	pr_info("%s: %s: length=%d, physaddr=%llx\n",
			VCAM_ISP_DEV_NAME, __func__, length_pg,
			g_vcam_output_io.stats_base);

	page = virt_to_page((unsigned long) g_vcam_output_io.stats_base +
						(vma->vm_pgoff << PAGE_SHIFT));
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP | VM_SHARED;
	if (remap_pfn_range(vma,
						vma->vm_start,
						page_to_pfn(page),
						vma->vm_end - vma->vm_start,
						vma->vm_page_prot)) {
		pr_err("%s: %s: remap_pfn_range: failed\n",
			   VCAM_ISP_DEV_NAME, __func__);
		return -EAGAIN;
	}

	return 0;
}

static struct bin_attribute attr_stats_mem = {
	.attr.name = VCAM_ISP_STATS_MEM,
	.attr.mode = 0666,
	.read = stats_mem_read,
	.mmap = stats_mem_mmap,
	.size = 0
};

void ipc_vcam_isp_store_input_base(u64 input_base)
{
	pr_info("%s: %s base=0x%llx\n", VCAM_ISP_DEV_NAME,
		__func__, input_base);
	g_vcam_input_io.input_base = input_base;
}

static char *ipc_vcam_isp_devnode(struct device *dev, umode_t *mode)
{
	if (!mode)
		return NULL;
	*mode = 0666;

	return kasprintf(GFP_KERNEL, "%s/%s", VCAM_ISP_DEV_NAME, dev_name(dev));
}

static int vcam_cam_ctrl_open(struct inode *inode, struct file *filp)
{
	pr_info("%s: %s open enter\n", VCAM_ISP_DEV_NAME, __func__);

	if (inode == NULL || filp == NULL)
		return -EINVAL;

	//TODO(bknottek): Only allow one process to read/write?

	//TODO(bknottek): possibly remove global?
	filp->private_data = &g_vcam_cam_ctrl;

	return 0;
}

static int vcam_cam_ctrl_release(struct inode *inode, struct file *filp)
{
	pr_info("%s: %s release enter\n", VCAM_ISP_DEV_NAME, __func__);
	return 0;
}

static ssize_t vcam_cam_ctrl_read(struct file *filp, char __user *buff,
				  size_t count, loff_t *offp)
{
	ssize_t retval = count;
	struct ctrl_event *rd_evt = NULL;
	unsigned long flags = 0;

	pr_debug("%s: %s read enter count=%ld\n", VCAM_ISP_DEV_NAME, __func__,
			 count);

	if (wait_event_interruptible(g_vcam_cam_ctrl.waitq,
			     !(list_empty(&g_vcam_cam_ctrl.ready_evts)))) {
		return -ERESTARTSYS;
	}

	spin_lock_irqsave(&g_vcam_cam_ctrl.rd_evt_lock, flags);
	if (!(list_empty(&g_vcam_cam_ctrl.ready_evts))) {
		rd_evt = list_first_entry(&g_vcam_cam_ctrl.ready_evts,
					  struct ctrl_event, list);
		list_del_init(&rd_evt->list);
	}
	spin_unlock_irqrestore(&g_vcam_cam_ctrl.rd_evt_lock, flags);

	if (copy_to_user(buff, &rd_evt->req,
			 sizeof(struct vcam_isp_ctrl_req))) {
		retval = -EFAULT;
	}

	flags = 0;
	spin_lock_irqsave(&g_vcam_cam_ctrl.free_evt_lock, flags);
	list_add_tail(&rd_evt->list, &g_vcam_cam_ctrl.free_evts);
	spin_unlock_irqrestore(&g_vcam_cam_ctrl.free_evt_lock, flags);

	return retval;
}

static ssize_t vcam_cam_ctrl_write(struct file *filp, const char __user *buff,
				   size_t count, loff_t *offp)
{
	int cam_id = 0;
	struct vcam_isp_ctrl_resp ursp;
	struct reg_cam_ctrl_resp resp;
	struct isp_ipc_device *isp_dev;
	struct camera *cam;

	pr_debug("%s: %s write enter count=%ld\n", VCAM_ISP_DEV_NAME, __func__,
			 count);

	if (count != sizeof(struct vcam_isp_ctrl_resp))
		return -EINVAL;

	if (copy_from_user(&ursp, buff, sizeof(struct vcam_isp_ctrl_resp)))
		return -EFAULT;

	memset(&resp, 0, sizeof(struct reg_cam_ctrl_resp));
	resp.resp_id = ursp.req_id;
	resp.resp.value = ursp.resp;
	resp.strm.value = ursp.info_data.strm;
	resp.res.value = ursp.info_data.res;
	resp.fpks = ursp.info_data.fps;
	resp.again0 = ursp.info_data.again;
	resp.dgain0 = ursp.info_data.dgain;
	resp.itime0 = ursp.info_data.exposure;
	resp.frame_duration = ursp.info_data.frame_dur;
	resp.af_p0.value = ursp.info_data.af0;
	resp.af_p1.value = ursp.info_data.af1;
	resp.af_p2.value = ursp.info_data.af2;
	resp.oslice_sync.value = ursp.info_data.slice_sync;
	resp.oslice_param.value = ursp.info_data.slice_parm;

	isp_dev = platform_get_drvdata(g_vcam_cam_ctrl.pdev);
	cam = &isp_dev->camera[cam_id];

	cam_ctrl_response(isp_dev, cam_id, &resp);

	// TODO(bknottek): following is needed for AMD's frame injection code...
	if (ursp.info_data.res_mode != VCAM_ISP_CTRL_RES_UNTOUCHED) {
		cam->cam_ctrl_info.res.width = ursp.info_data.width;
		cam->cam_ctrl_info.res.height = ursp.info_data.height;
		cam->cam_ctrl_info.strm.value |= ursp.info_data.strm;
	}

	if (ursp.info_data.rq_fps_op && ursp.info_data.rq_fps_wr)
		cam->cam_ctrl_info.fpks = ursp.info_data.fps;

	if (ursp.info_data.rq_strm_op && ursp.info_data.rq_strm_wr) {
		cam->cam_ctrl_info.strm.value |= ursp.info_data.strm;
		if (ursp.rsp_strm == 0 &&
		    ursp.info_data.strm == VCAM_ISP_CTRL_STREAM_ON) {
			pr_info("%s: request stream on\n", VCAM_ISP_DEV_NAME);
		} else if (ursp.rsp_strm == 0 &&
			   ursp.info_data.strm == VCAM_ISP_CTRL_STREAM_OFF) {
			// ISP doesn't send WDMA status update when stream
			// is stopped, so clear globals here.
			g_vcam_cam_ctrl.last_wdma_ktime = 0;
			g_vcam_cam_ctrl.last_wdma_status.value = 0;
		} else {
			pr_info("%s: request stream 0x%08x\n",
				VCAM_ISP_DEV_NAME, ursp.info_data.strm);
		}
	}

	return count;
}

static long vcam_cam_ctrl_ioctl(struct file *filp, unsigned int cmd,
				unsigned long arg)
{
	pr_info("%s: %s ioctl enter\n", VCAM_ISP_DEV_NAME, __func__);
	return 0;
}

static unsigned int vcam_cam_ctrl_poll(struct file *filp, poll_table *wait)
{
	pr_info("%s: %s poll enter\n", VCAM_ISP_DEV_NAME, __func__);
	return 0;
}

static struct file_operations const fops_vcam_cam_ctrl = {
	.owner          = THIS_MODULE,
	.open           = vcam_cam_ctrl_open,
	.release        = vcam_cam_ctrl_release,
	.read           = vcam_cam_ctrl_read,
	.write          = vcam_cam_ctrl_write,
	.unlocked_ioctl = vcam_cam_ctrl_ioctl,
	.poll           = vcam_cam_ctrl_poll,
};

void ipc_vcam_isp_ctrl_notification(struct isp_ipc_device *isp_dev, u32 msg_id,
				    void *msg)
{
	struct reg_cam_ctrl_info  ctrl_info;
	unsigned long             flags = 0;
	struct ctrl_event         *ctrl_event = NULL;
	struct vcam_isp_ctrl_req  *ctrl_req;
	int                       ret;
	struct camera             *cam = &isp_dev->camera[0];

	if (msg == NULL || isp_dev == NULL) {
		pr_err("%s: %s - NULL Input!\n", VCAM_ISP_DEV_NAME, __func__);
		return;
	}

	log_payload("vcam-isp: Camera control", (u32 *)msg,
		    sizeof(struct reg_cam_ctrl_info) / sizeof(u32));

	memcpy(&ctrl_info, msg, sizeof(struct reg_cam_ctrl_info));

	// get next available free slot in event list
	spin_lock_irqsave(&g_vcam_cam_ctrl.free_evt_lock, flags);
	if (!list_empty(&g_vcam_cam_ctrl.free_evts)) {
		ctrl_event = list_first_entry(&g_vcam_cam_ctrl.free_evts,
					      struct ctrl_event, list);
		list_del_init(&ctrl_event->list);
	}
	spin_unlock_irqrestore(&g_vcam_cam_ctrl.free_evt_lock, flags);

	if (ctrl_event == NULL) {
		pr_err("%s: %s - ctrl_event is NULL! req:0x%08x\n",
		       VCAM_ISP_DEV_NAME, __func__, ctrl_info.req_id);
		return;
	}

	ctrl_req = &ctrl_event->req;
	memset(ctrl_req, 0, sizeof(struct vcam_isp_ctrl_req));

	ctrl_req->type = VCAM_ISP_CTRL_REQ_TYPE_INFO_DATA;
	ctrl_req->req_id = ctrl_info.req_id;
	ctrl_req->info_data.req = ctrl_info.req.value;
	ctrl_req->info_data.strm = ctrl_info.strm.value;
	ctrl_req->info_data.res = ctrl_info.res.value;
	ctrl_req->info_data.fps = ctrl_info.fpks;
	ctrl_req->info_data.again = ctrl_info.again0;
	ctrl_req->info_data.dgain = ctrl_info.dgain0;
	ctrl_req->info_data.exposure = ctrl_info.itime0;
	ctrl_req->info_data.frame_dur = ctrl_info.frame_duration;
	ctrl_req->info_data.af0 = ctrl_info.af_p0.value;
	ctrl_req->info_data.af1 = ctrl_info.af_p1.value;
	ctrl_req->info_data.af2 = ctrl_info.af_p2.value;
	ctrl_req->info_data.slice_sync = ctrl_info.oslice_sync.value;
	ctrl_req->info_data.slice_parm = ctrl_info.oslice_param.value;
	ctrl_req->prepost_mem.hi = ctrl_info.prepost_hi;
	ctrl_req->prepost_mem.lo = ctrl_info.prepost_lo;
	ctrl_req->prepost_mem.size = ctrl_info.prepost_size;
	ctrl_req->stats_mem.hi = ctrl_info.stats_hi;
	ctrl_req->stats_mem.lo = ctrl_info.stats_lo;
	ctrl_req->stats_mem.size = ctrl_info.stats_size;

	if (ctrl_req->info_data.rq_ppmem_op &&
	    ctrl_req->info_data.rq_ppmem_wr) {
		// call function to set data_base values
		cam->cam_ctrl_info.prepost_hi = ctrl_info.prepost_hi;
		cam->cam_ctrl_info.prepost_lo = ctrl_info.prepost_lo;
		cam->cam_ctrl_info.prepost_size = ctrl_info.prepost_size;
		get_prepost_mem(isp_dev, 0);
		g_vcam_input_io.prepost_base = (u64)cam->data_base;
		g_vcam_input_io.prepost_size = ctrl_req->prepost_mem.size;
		if (attr_prepost_mem.size == 0) {
			attr_prepost_mem.size = g_vcam_input_io.prepost_size;
			ret = sysfs_create_bin_file(&g_vcam_input_io.dev->kobj,
						    &attr_prepost_mem);
			if (ret < 0) {
				pr_err("bad bin_file prepost_mem (%d)\n", ret);
				sysfs_remove_bin_file(
					&g_vcam_input_io.dev->kobj,
					&attr_prepost_mem);
			}
		}

	}

	if (ctrl_req->info_data.rq_statmem_op &&
	    ctrl_req->info_data.rq_statmem_wr) {
		// call function to set stats_base values
		cam->cam_ctrl_info.stats_hi = ctrl_info.stats_hi;
		cam->cam_ctrl_info.stats_lo = ctrl_info.stats_lo;
		cam->cam_ctrl_info.stats_size = ctrl_info.stats_size;
		get_stats_mem(isp_dev, 0);
		g_vcam_output_io.stats_base = (u64)cam->stats_base;
		g_vcam_output_io.stats_size = ctrl_req->stats_mem.size;
		if (attr_stats_mem.size == 0) {
			attr_stats_mem.size = g_vcam_output_io.stats_size;
			ret = sysfs_create_bin_file(
				&g_vcam_output_io.dev->kobj, &attr_stats_mem);
			if (ret < 0) {
				pr_err("bad bin_file stats_mem (%d)\n", ret);
				sysfs_remove_bin_file(
					&g_vcam_output_io.dev->kobj,
					&attr_stats_mem);
			}
		}
	}

	// Pass event to reader.
	flags = 0;
	spin_lock_irqsave(&g_vcam_cam_ctrl.rd_evt_lock, flags);
	list_add_tail(&ctrl_event->list, &g_vcam_cam_ctrl.ready_evts);
	spin_unlock_irqrestore(&g_vcam_cam_ctrl.rd_evt_lock, flags);

	// Wake up waiting reader.
	wake_up_interruptible(&g_vcam_cam_ctrl.waitq);
}

void ipc_vcam_isp_dma_status_notification(struct isp_ipc_device *isp_dev,
					  u32 msg_id,  void *msg)
{
	struct reg_wdma_report    *wdma_status = NULL;
	struct ctrl_event         *ctrl_event = NULL;
	struct vcam_isp_ctrl_req  *ctrl_req = NULL;
	unsigned long             flags = 0;
	ktime_t                   curr_ktime = ktime_get();
	bool                      entry_found = false;
	struct reg_wdma_report    send_wdma_status;

	if (msg == NULL || isp_dev == NULL) {
		pr_err("%s: %s - NULL Input!\n", VCAM_ISP_DEV_NAME, __func__);
		return;
	}

	log_payload("vcam-isp: WDMA status", (u32 *)msg,
		    sizeof(struct reg_wdma_report) / sizeof(u32));

	wdma_status = (struct reg_wdma_report *)msg;

	if ((g_vcam_cam_ctrl.last_wdma_status.value == wdma_status->value) ||
		(curr_ktime - g_vcam_cam_ctrl.last_wdma_ktime) <
		    (5 * NSEC_PER_SEC)) {
		pr_debug("%s: %s - Ignore DMA status! ktime=%lld status=0x%08x\n",
			VCAM_ISP_DEV_NAME, __func__, curr_ktime,
			wdma_status->value);
		g_vcam_cam_ctrl.last_wdma_status.value = wdma_status->value;
		return;
	}

	if ((curr_ktime - g_vcam_cam_ctrl.last_wdma_ktime) <
	    (10 * NSEC_PER_SEC)) {
		// getting updates quickly, so assume we are in a situation
		// with multiple clients, but different frame rates.
		// bitwise OR the current and previous status when updating
		// userspace thread.
		send_wdma_status.value = wdma_status->value |
					 g_vcam_cam_ctrl.last_wdma_status.value;
		pr_warn("%s: %s - OR DMA status! ktime=%lld status=0x%08x\n",
			VCAM_ISP_DEV_NAME, __func__, curr_ktime,
			wdma_status->value);
	} else {
		send_wdma_status.value = wdma_status->value;
	}

	// check if there is an existing WDMA status
	// already in the list. If so, replace with new one.
	// Don't expect this to happen with timing checks above, but
	// will help prevent list from filling up with WDMA status events.
	spin_lock_irqsave(&g_vcam_cam_ctrl.rd_evt_lock, flags);
	if (!list_empty(&g_vcam_cam_ctrl.ready_evts)) {
		list_for_each_entry(ctrl_event, &g_vcam_cam_ctrl.ready_evts, list) {
			if (ctrl_event != NULL && ctrl_event->req.type ==
			    VCAM_ISP_CTRL_REQ_TYPE_DMA_STATUS) {
				// found DMA Status entry. replace with new data
				ctrl_event->req.dma_status.report =
					send_wdma_status.value;
				entry_found = true;
				break;
			}
		}
	}
	spin_unlock_irqrestore(&g_vcam_cam_ctrl.rd_evt_lock, flags);

	if (entry_found == false) {
		// get next available free slot in event list
		flags = 0;
		spin_lock_irqsave(&g_vcam_cam_ctrl.free_evt_lock, flags);
		if (!list_empty(&g_vcam_cam_ctrl.free_evts)) {
			ctrl_event =
				list_first_entry(&g_vcam_cam_ctrl.free_evts,
						 struct ctrl_event, list);
			list_del_init(&ctrl_event->list);
		}
		spin_unlock_irqrestore(&g_vcam_cam_ctrl.free_evt_lock, flags);

		if (ctrl_event == NULL) {
			pr_err("%s: %s - ctrl_event is NULL!\n",
			       VCAM_ISP_DEV_NAME, __func__);
			return;
		}

		ctrl_req = &ctrl_event->req;
		memset(ctrl_req, 0, sizeof(struct vcam_isp_ctrl_req));

		ctrl_req->type = VCAM_ISP_CTRL_REQ_TYPE_DMA_STATUS;
		ctrl_req->dma_status.report = send_wdma_status.value;

		// Pass event to reader.
		flags = 0;
		spin_lock_irqsave(&g_vcam_cam_ctrl.rd_evt_lock, flags);
		list_add_tail(&ctrl_event->list, &g_vcam_cam_ctrl.ready_evts);
		spin_unlock_irqrestore(&g_vcam_cam_ctrl.rd_evt_lock, flags);
	} else {
		pr_debug("%s: %s - Found DMA status! ktime=%lld status=0x%08x\n",
			VCAM_ISP_DEV_NAME, __func__, curr_ktime,
			wdma_status->value);
	}

	g_vcam_cam_ctrl.last_wdma_ktime = curr_ktime;
	g_vcam_cam_ctrl.last_wdma_status.value = wdma_status->value;

	/* acknowledge wdma status */
	/* no need for wdma status acknowledge */
	/* acknowledge is done through PL320 driver */

	// Wake up waiting reader.
	wake_up_interruptible(&g_vcam_cam_ctrl.waitq);
}

// Create the virtual device for the control interface
static int ipc_vcam_isp_dev_camctrl_create(struct device *dev, dev_t maj_num)
{
	int ret;
	int i;

	memset(&g_vcam_cam_ctrl, 0, sizeof(struct ipc_vcam_isp_cam_ctrl));

	init_waitqueue_head(&g_vcam_cam_ctrl.waitq);

	// initialize event lists
	spin_lock_init(&g_vcam_cam_ctrl.rd_evt_lock);
	INIT_LIST_HEAD(&g_vcam_cam_ctrl.ready_evts);
	spin_lock_init(&g_vcam_cam_ctrl.free_evt_lock);
	INIT_LIST_HEAD(&g_vcam_cam_ctrl.free_evts);
	for (i = 0; i < IPC_VCAM_ISP_NUM_EVTS; i++) {
		INIT_LIST_HEAD(&g_vcam_cam_ctrl.ctrl_event_array[i].list);
		list_add_tail(&g_vcam_cam_ctrl.ctrl_event_array[i].list,
			      &g_vcam_cam_ctrl.free_evts);
	}

	g_vcam_cam_ctrl.pdev = to_platform_device(dev);
	g_vcam_cam_ctrl.devno = MKDEV(maj_num, IPC_VCAM_ISP_CTRL_MINOR_NUM);

	cdev_init(&g_vcam_cam_ctrl.cdev, &fops_vcam_cam_ctrl);
	g_vcam_cam_ctrl.cdev.owner = THIS_MODULE;
	ret = cdev_add(&g_vcam_cam_ctrl.cdev, g_vcam_cam_ctrl.devno, 1);
	if (ret) {
		pr_err("%s: cdev_add failed (%d)\n", VCAM_ISP_DEV_NAME, ret);
		return ret;
	}

	g_vcam_cam_ctrl.dev = device_create(g_vcam_isp_class, NULL,
					    g_vcam_cam_ctrl.devno,
					    &g_vcam_cam_ctrl,
					    VCAM_ISP_CAM_CTRL_NAME);
	if (IS_ERR(g_vcam_cam_ctrl.dev)) {
		pr_err("%s: bad cam_ctrl dev create.\n", VCAM_ISP_DEV_NAME);
		cdev_del(&g_vcam_cam_ctrl.cdev);
		return -1;
	}

	dev_set_drvdata(g_vcam_cam_ctrl.dev, &g_vcam_cam_ctrl);

	strcpy(g_vcam_cam_ctrl.name, VCAM_ISP_CAM_CTRL_NAME);

	return 0;
}

static int vcam_input_io_open(struct inode *inode, struct file *filp)
{
	pr_info("%s: %s open enter\n", VCAM_ISP_DEV_NAME, __func__);

	if (inode == NULL || filp == NULL)
		return -EINVAL;

	//TODO(bknottek): Only allow one process to read/write?

	//TODO(bknottek): possibly remove global?
	filp->private_data = &g_vcam_input_io;

	return 0;
}

static int vcam_input_io_release(struct inode *inode, struct file *filp)
{
	pr_info("%s: %s release enter\n", VCAM_ISP_DEV_NAME, __func__);
	return 0;
}

static ssize_t vcam_input_io_read(struct file *filp, char __user *buff,
				  size_t count, loff_t *offp)
{
	ssize_t retval = count;
	struct inputio_event *io_evt = NULL;
	unsigned long flags = 0;

	pr_debug("%s: %s read enter count=%ld\n",
		 VCAM_ISP_DEV_NAME, __func__, count);

	if (count < sizeof(struct vcam_isp_input_io_release))
		return -EINVAL;

	//TODO(bknottek): remove this if we don't need blocking read...
	//if (wait_event_interruptible(g_vcam_input_io.waitq,
	//    !(list_empty(&g_vcam_input_io.ready_evts)))) {
	//    return -ERESTARTSYS;
	//}

	//TODO(bknottek): consider looping through all release events
	// and return array to reader

	spin_lock_irqsave(&g_vcam_input_io.rd_evt_lock, flags);
	if (list_empty(&g_vcam_input_io.ready_evts)) {
		spin_unlock_irqrestore(&g_vcam_input_io.rd_evt_lock, flags);
		return -EINPROGRESS;
	}
	io_evt = list_first_entry(&g_vcam_input_io.ready_evts,
				  struct inputio_event, list);
	list_del_init(&io_evt->list);
	spin_unlock_irqrestore(&g_vcam_input_io.rd_evt_lock, flags);

	if (io_evt == NULL) {
		pr_err("%s: %s io event is NULL!\n",
		       VCAM_ISP_DEV_NAME, __func__);
		retval = -EFAULT;
	} else {
		pr_debug("%s: %s type:%d frame_id:%d status:%d\n",
			 VCAM_ISP_DEV_NAME, __func__,
			 io_evt->rel.type, io_evt->rel.id.frame,
			 io_evt->rel.id.status);
		if (copy_to_user(buff, &io_evt->rel,
				 sizeof(struct vcam_isp_input_io_release))) {
			retval = -EFAULT;
		}

		flags = 0;
		spin_lock_irqsave(&g_vcam_input_io.free_evt_lock, flags);
		list_add_tail(&io_evt->list, &g_vcam_input_io.free_evts);
		spin_unlock_irqrestore(&g_vcam_input_io.free_evt_lock, flags);
	}

	return retval;
}

static ssize_t vcam_input_io_write(struct file *filp, const char __user *buff,
				   size_t count, loff_t *offp)
{
	int id = 0;
	struct vcam_isp_input_io_frame frame;
	u32 exp0_offset, postdata_offset;
	struct isp_ipc_device *isp_dev;
	struct camera *cam;
	enum reg_bit_width reg_bpp;

	pr_debug("%s: %s enter count=%ld\n",
		 VCAM_ISP_DEV_NAME, __func__, count);

	if (count != sizeof(struct vcam_isp_input_io_frame)) {
		pr_err("%s: %s - Invalid count %ld (expect %ld)!\n",
		       VCAM_ISP_DEV_NAME, __func__,
		       count, sizeof(struct vcam_isp_input_io_frame));
		return -EINVAL;
	}

	if (copy_from_user(&frame, buff,
			   sizeof(struct vcam_isp_input_io_frame))) {
		pr_err("%s: %s - copy_from_user Failed!\n",
		       VCAM_ISP_DEV_NAME, __func__);
		return -EFAULT;
	}

	isp_dev = platform_get_drvdata(g_vcam_cam_ctrl.pdev);
	cam = &isp_dev->camera[id];

	switch (frame.bit_width) {
	case 8:
		reg_bpp = BW_8BIT;
		break;
	case 10:
		reg_bpp = BW_10BIT;
		break;
	case 12:
		reg_bpp = BW_12BIT;
		break;
	case 14:
		reg_bpp = BW_14BIT;
		break;
	case 16:
		reg_bpp = BW_16BIT;
		break;
	default:
		pr_err("%s: %s - Invalid bit_width %d!\n",
		       VCAM_ISP_DEV_NAME, __func__, frame.bit_width);
		return -EINVAL;
	}

	exp0_offset = frame.frm_start - g_vcam_input_io.input_base;
	pr_debug("%s: %s frame_id:%d base:%llx frm_start:0x%llx exp:0x%x\n",
		 VCAM_ISP_DEV_NAME, __func__, frame.frame_id,
		 g_vcam_input_io.input_base, frame.frm_start, exp0_offset);

	// FIRST slice, so setup info for frame and predata...
	if (frame.cur_slice == 0) {
		pr_debug("%s: %s init frm:%d offset:0x%04x %dx%d bw:%d slice:0x%08x\n",
			 VCAM_ISP_DEV_NAME, __func__, frame.frame_id,
			 exp0_offset, frame.width, frame.height,
			 frame.bit_width, frame.slice_info);
		// setup initial frame info
		writel_relaxed(exp0_offset, isp_dev->base
					   + id * CAM_INBUFF_PIXEL_REG_SIZE
					   + CAM0_CVP_INBUF_EXP0_ADDR_OFFSET);
		writel_relaxed((BW_10BIT << 28)
					   + (frame.height << 14) + frame.width,
					   isp_dev->base
					   + id * CAM_INBUFF_PIXEL_REG_SIZE
					   + CAM0_CVP_INBUF_IMG_SIZE);
		writel_relaxed(frame.slice_info,
					   isp_dev->base +
					   id * CAM_INBUFF_PIXEL_REG_SIZE +
					   CAM0_CVP_INBUF_SLICE_INFO);

		// set predata
		if (cam->data_base != NULL) {
			__flush_dcache_area(
				cam->data_base + frame.predata_offset,
				PREDATA_SIZE);
			pr_debug("%s: %s predat frm:%d offset:0x%04x\n",
					 VCAM_ISP_DEV_NAME, __func__,
					 frame.frame_id, frame.predata_offset);
			writel_relaxed(frame.predata_offset,
				       isp_dev->base + id *
				       CAM_INBUFF_DATA_REG_SIZE +
				       CAM0_CVP_PREDAT_ADDR_OFFSET);
			writel_relaxed(frame.frame_id,
				       isp_dev->base + id *
				       CAM_INBUFF_DATA_REG_SIZE +
				       CAM0_CVP_PREDAT_FRM_ID);
		}
		smp_wmb(); /* memory barrier */
	}

	// For each slice, write that frame data is ready...
	if (frame.cur_slice < frame.total_slices) {
		pr_debug("%s: %s data frm:%d value:0x%08x\n",
			 VCAM_ISP_DEV_NAME, __func__, frame.frame_id,
			 (frame.cur_slice << 28) + frame.frame_id);
		writel_relaxed((frame.cur_slice << 28) + frame.frame_id,
			       isp_dev->base + id *
			       CAM_INBUFF_PIXEL_REG_SIZE +
			       CAM0_CVP_INBUF_EXP0_FRM_SLICE);
		smp_wmb(); /* memory barrier */
	}

	// LAST slice, so finish with frame and write postdata...
	if ((frame.cur_slice + 1) >= frame.total_slices &&
	    cam->data_base != NULL) {
		// set postdata
		postdata_offset = frame.predata_offset + PREDATA_SIZE;
		__flush_dcache_area(cam->data_base + postdata_offset,
				    POSTDATA_SIZE);
		pr_debug("%s: %s postdat frm:%d offset:0x%04x\n",
			 VCAM_ISP_DEV_NAME, __func__, frame.frame_id,
			 postdata_offset);
		writel_relaxed(postdata_offset, isp_dev->base
					   + id * CAM_INBUFF_DATA_REG_SIZE
					   + CAM0_CVP_POSTDAT_ADDR_OFFSET);
		writel_relaxed(frame.frame_id, isp_dev->base
					   + id * CAM_INBUFF_DATA_REG_SIZE
					   + CAM0_CVP_POSTDAT_FRM_ID);
		smp_wmb(); /* memory barrier */
	}

	return count;
}

static long vcam_input_io_ioctl(struct file *filp, unsigned int cmd,
				unsigned long arg)
{
	int ret = 0;
	struct isp_ipc_device *isp_dev;
	struct camera *cam;
	struct vcam_isp_io_mem_layout mem;

	pr_info("%s: %s ioctl enter cmd=0x%x\n",
		VCAM_ISP_DEV_NAME, __func__, cmd);

	if (!access_ok((void *)arg, sizeof(mem))) {
		pr_err("%s: %s bad arg!\n", VCAM_ISP_DEV_NAME, __func__);
		return -EPERM;
	}

	isp_dev = platform_get_drvdata(g_vcam_cam_ctrl.pdev);
	cam = &isp_dev->camera[0];

	if (cmd == VCAM_ISP_GET_INPUT_BASE) {
		mem.addr = (u64)cam->input_base;
		mem.size = 0xC000000;
		pr_info("%s: %s Get input base - 0x%llx\n",
			VCAM_ISP_DEV_NAME, __func__, (u64)cam->input_base);
		pr_info("%s: %s phy_input_base res_in:0x%llx size:%d\n",
			VCAM_ISP_DEV_NAME, __func__, mem.addr, mem.size);
		if (copy_to_user((void __user *)arg, &mem, sizeof(mem))) {
			pr_err("%s: %s Unable to copy to user!\n",
			       VCAM_ISP_DEV_NAME, __func__);
			ret = -EINVAL;
		}
	} else {
		pr_err("%s: %s Invalid cmd!\n", VCAM_ISP_DEV_NAME, __func__);
		ret = -EINVAL;
	}

	return ret;
}

static unsigned int vcam_input_io_poll(struct file *filp, poll_table *wait)
{
	pr_info("%s: %s poll enter\n", VCAM_ISP_DEV_NAME, __func__);
	return 0;
}

static struct file_operations const fops_vcam_input_io = {
	.owner          = THIS_MODULE,
	.open           = vcam_input_io_open,
	.release        = vcam_input_io_release,
	.read           = vcam_input_io_read,
	.write          = vcam_input_io_write,
	.unlocked_ioctl = vcam_input_io_ioctl,
	.compat_ioctl   = vcam_input_io_ioctl,
	.poll           = vcam_input_io_poll,
};

void ipc_vcam_isp_inputio_notification(struct isp_ipc_device *isp_dev,
				       u32 msg_id,  void *msg)
{
	struct reg_inbuf_release          *io_inbuf;
	unsigned long                     flags = 0;
	struct inputio_event              *io_event = NULL;
	struct vcam_isp_input_io_release  *io_rel;
	ktime_t                           curr_ktime;
	struct reg_wdma_report            send_wdma_status;

	if (msg == NULL || isp_dev == NULL) {
		pr_err("%s: %s - NULL Input!\n", VCAM_ISP_DEV_NAME, __func__);
		return;
	}

	log_payload("vcam-isp: Pixel input buff", (u32 *)msg,
		    sizeof(struct reg_inbuf_release) / sizeof(u32));

	io_inbuf = (struct reg_inbuf_release *)msg;

	// get next available free slot in event list
	spin_lock_irqsave(&g_vcam_input_io.free_evt_lock, flags);
	if (!list_empty(&g_vcam_input_io.free_evts)) {
		io_event = list_first_entry(&g_vcam_input_io.free_evts,
					    struct inputio_event, list);
		list_del_init(&io_event->list);
	}
	spin_unlock_irqrestore(&g_vcam_input_io.free_evt_lock, flags);

	if (io_event == NULL) {
		pr_err("%s: %s - inputio_event is NULL!\n",
		       VCAM_ISP_DEV_NAME, __func__);
		return;
	}

	io_rel = &io_event->rel;
	memset(io_event, 0, sizeof(struct inputio_event));

	switch (msg_id & 0xfffffffe) {
	case CAM0_INPUT_BUFF:
		io_rel->type = VCAM_ISP_IP_TYPE_PIXEL_BUF;
		break;
	case CAM0_PRE_DATA_BUFF:
		io_rel->type = VCAM_ISP_IP_TYPE_PRE_BUF;
		break;
	case CAM0_POST_DATA_BUFF:
		io_rel->type = VCAM_ISP_IP_TYPE_POST_BUF;
		break;
	default:
		pr_err("%s: %s unsupported msg_id 0x%x\n",
		       VCAM_ISP_DEV_NAME, __func__, msg_id);
		return;
	}
	io_rel->id.value = io_inbuf->id.value;

	pr_debug("%s: %s type:%d frame_id:%d status:%d\n",
		 VCAM_ISP_DEV_NAME, __func__, io_rel->type,
		 io_rel->id.frame, io_rel->id.status);

	// Pass event to reader.
	flags = 0;
	spin_lock_irqsave(&g_vcam_input_io.rd_evt_lock, flags);
	list_add_tail(&io_event->list, &g_vcam_input_io.ready_evts);
	spin_unlock_irqrestore(&g_vcam_input_io.rd_evt_lock, flags);

	//TODO(bknottek): remove this if we don't need blocking read...
	// Wake up waiting reader.
	//wake_up_interruptible(&g_vcam_input_io.waitq);

	// Bit of a hack to work around WDMA Status updates...
	// if current ktime is greater than 10 seconds since last
	// WDMA Status was received, assume a client has stopped, so
	// send last status up to userspace.
	curr_ktime = ktime_get();
	if (g_vcam_cam_ctrl.last_wdma_ktime != 0 &&
	    ((curr_ktime - g_vcam_cam_ctrl.last_wdma_ktime) >
	    (10 * NSEC_PER_SEC))) {
		pr_warn("%s: %s - HACK DMA status! ktime=%lld status=0x%08x\n",
			VCAM_ISP_DEV_NAME, __func__, curr_ktime,
			g_vcam_cam_ctrl.last_wdma_status.value);
		send_wdma_status.value = g_vcam_cam_ctrl.last_wdma_status.value;
		// force status to be sent by clearing "last" value
		g_vcam_cam_ctrl.last_wdma_status.value = 0;
		ipc_vcam_isp_dma_status_notification(isp_dev, msg_id,
						     &send_wdma_status);
		g_vcam_cam_ctrl.last_wdma_ktime = 0;
	}
}

// Create the virtual device for the input_io interface
static int ipc_vcam_isp_dev_inputio_create(struct device *dev, dev_t maj_num)
{
	int ret;
	int i;

	memset(&g_vcam_input_io, 0, sizeof(struct ipc_vcam_isp_input_io));

	init_waitqueue_head(&g_vcam_input_io.waitq);

	// initialize event lists
	spin_lock_init(&g_vcam_input_io.rd_evt_lock);
	INIT_LIST_HEAD(&g_vcam_input_io.ready_evts);
	spin_lock_init(&g_vcam_input_io.free_evt_lock);
	INIT_LIST_HEAD(&g_vcam_input_io.free_evts);
	for (i = 0; i < IPC_VCAM_ISP_NUM_IO_EVTS; i++) {
		INIT_LIST_HEAD(&g_vcam_input_io.inputio_event_array[i].list);
		list_add_tail(&g_vcam_input_io.inputio_event_array[i].list,
			      &g_vcam_input_io.free_evts);
	}

	g_vcam_input_io.pdev = to_platform_device(dev);
	g_vcam_input_io.devno = MKDEV(maj_num, IPC_VCAM_ISP_DATA_IN_MINOR_NUM);

	cdev_init(&g_vcam_input_io.cdev, &fops_vcam_input_io);
	g_vcam_input_io.cdev.owner = THIS_MODULE;
	ret = cdev_add(&g_vcam_input_io.cdev, g_vcam_input_io.devno, 1);
	if (ret) {
		pr_err("%s: cdev_add failed (%d)\n", VCAM_ISP_DEV_NAME, ret);
		return ret;
	}

	g_vcam_input_io.dev = device_create(g_vcam_isp_class, NULL,
					    g_vcam_input_io.devno,
					    &g_vcam_input_io,
					    VCAM_ISP_INPUT_IO_NAME);
	if (IS_ERR(g_vcam_input_io.dev)) {
		pr_err("%s: bad input_io dev create.\n", VCAM_ISP_DEV_NAME);
		cdev_del(&g_vcam_input_io.cdev);
		return -1;
	}

	dev_set_drvdata(g_vcam_input_io.dev, &g_vcam_input_io);

	strcpy(g_vcam_input_io.name, VCAM_ISP_INPUT_IO_NAME);

	return 0;
}

static int vcam_output_io_open(struct inode *inode, struct file *filp)
{
	pr_info("%s: %s open enter\n", VCAM_ISP_DEV_NAME, __func__);

	if (inode == NULL || filp == NULL)
		return -EINVAL;

	//TODO(bknottek): Only allow one process to read/write?

	//TODO(bknottek): possibly remove global?
	filp->private_data = &g_vcam_output_io;

	return 0;
}

static int vcam_output_io_release(struct inode *inode, struct file *filp)
{
	pr_info("%s: %s release enter\n", VCAM_ISP_DEV_NAME, __func__);
	return 0;
}

static ssize_t vcam_output_io_read(struct file *filp, char __user *buff,
				   size_t count, loff_t *offp)
{
	ssize_t retval = count;
	struct outputio_event *io_evt = NULL;
	unsigned long flags = 0;

	pr_debug("%s: %s read enter count=%ld\n",
		 VCAM_ISP_DEV_NAME, __func__, count);

	if (count != sizeof(struct vcam_isp_output_io_data))
		return -EINVAL;

	if (wait_event_interruptible(
		g_vcam_output_io.waitq,
		!(list_empty(&g_vcam_output_io.ready_evts))))
		return -ERESTARTSYS;

	spin_lock_irqsave(&g_vcam_output_io.rd_evt_lock, flags);
	if (list_empty(&g_vcam_output_io.ready_evts)) {
		spin_unlock_irqrestore(&g_vcam_output_io.rd_evt_lock, flags);
		return -EINPROGRESS;
	}
	io_evt = list_first_entry(&g_vcam_output_io.ready_evts,
				  struct outputio_event, list);
	list_del_init(&io_evt->list);
	spin_unlock_irqrestore(&g_vcam_output_io.rd_evt_lock, flags);

	if (io_evt == NULL) {
		pr_err("%s: %s io event is NULL!\n",
		       VCAM_ISP_DEV_NAME, __func__);
		retval = -EFAULT;
	} else {
		pr_debug("%s: %s frame_id:%d status:%d addr:%x\n",
			 VCAM_ISP_DEV_NAME, __func__, io_evt->out_io.id.frame,
			 io_evt->out_io.id.status, io_evt->out_io.addr);
		if (copy_to_user(buff, &io_evt->out_io,
				 sizeof(struct vcam_isp_output_io_data))) {
			retval = -EFAULT;
		}

		flags = 0;
		spin_lock_irqsave(&g_vcam_output_io.free_evt_lock, flags);
		list_add_tail(&io_evt->list, &g_vcam_output_io.free_evts);
		spin_unlock_irqrestore(&g_vcam_output_io.free_evt_lock, flags);
	}

	return retval;
}

static ssize_t vcam_output_io_write(struct file *filp,
				    const char __user *buff, size_t count,
				    loff_t *offp)
{
	ssize_t retval = count;
	int cam_id = 0;
	struct vcam_isp_output_io_data io_data;
	struct isp_ipc_device *isp_dev = NULL;

	pr_debug("%s: %s write enter count=%ld\n",
		 VCAM_ISP_DEV_NAME, __func__, count);

	if (count != sizeof(struct vcam_isp_output_io_data))
		return -EINVAL;

	if (copy_from_user(&io_data, buff,
			   sizeof(struct vcam_isp_output_io_data)))
		return -EFAULT;

	isp_dev = platform_get_drvdata(g_vcam_output_io.pdev);

	if (io_data.type == VCAM_ISP_OUTPUT_IO_TYPE_STATS) {
		stats_buff_release(isp_dev, cam_id, RGBSTATS,
				   io_data.id.frame);
	} else if (io_data.type == VCAM_ISP_OUTPUT_IO_TYPE_YUV) {
		out_buff_release(isp_dev, cam_id, io_data.stream,
				 io_data.id.frame);
	}

	return retval;
}

static long vcam_output_io_ioctl(struct file *filp, unsigned int cmd,
				 unsigned long arg)
{
	pr_info("%s: %s ioctl enter\n", VCAM_ISP_DEV_NAME, __func__);
	return 0;
}

static unsigned int vcam_output_io_poll(struct file *filp, poll_table *wait)
{
	pr_info("%s: %s poll enter\n", VCAM_ISP_DEV_NAME, __func__);
	return 0;
}

static struct file_operations const fops_vcam_output_io = {
	.owner          = THIS_MODULE,
	.open           = vcam_output_io_open,
	.release        = vcam_output_io_release,
	.read           = vcam_output_io_read,
	.write          = vcam_output_io_write,
	.unlocked_ioctl = vcam_output_io_ioctl,
	.compat_ioctl   = vcam_output_io_ioctl,
	.poll           = vcam_output_io_poll,
};

void ipc_vcam_isp_stats_notification(struct isp_ipc_device *isp_dev,
				     u32 msg_id,  void *msg)
{
	int                               cam_id = msg_id & ISP_CAM_ID_MASK;
	struct reg_stats_buf              *stats_buf = NULL;
	unsigned long                     flags = 0;
	struct outputio_event             *io_event = NULL;
	struct vcam_isp_output_io_data    *io_stats = NULL;

	if (msg == NULL || isp_dev == NULL) {
		pr_err("%s: %s - NULL Input!\n", VCAM_ISP_DEV_NAME, __func__);
		return;
	}

	stats_buf = (struct reg_stats_buf *)msg;

	if (msg_id == CAM0_IR_STAT || msg_id == CAM1_IR_STAT) {
		// ignore, just release buffer
		stats_buff_release(isp_dev, cam_id, IRSTATS,
				   stats_buf->id.frame);
		return;
	}

	log_payload("vcam-isp: RGB stat", (u32 *)msg,
		    sizeof(struct reg_stats_buf) / sizeof(u32));

	// get next available free slot in event list
	spin_lock_irqsave(&g_vcam_output_io.free_evt_lock, flags);
	if (!list_empty(&g_vcam_output_io.free_evts)) {
		io_event = list_first_entry(&g_vcam_output_io.free_evts,
					    struct outputio_event, list);
		list_del_init(&io_event->list);
	}
	spin_unlock_irqrestore(&g_vcam_output_io.free_evt_lock, flags);

	if (io_event == NULL) {
		pr_err("%s: %s - outputio_event is NULL!\n",
		       VCAM_ISP_DEV_NAME, __func__);
		pr_info("%s: %s frame_id:%d status:%d addr:%x\n",
			VCAM_ISP_DEV_NAME, __func__, stats_buf->id.frame,
			stats_buf->id.field, stats_buf->addr);
		stats_buff_release(isp_dev, cam_id, RGBSTATS,
				   stats_buf->id.frame);
		return;
	}

	io_stats = &io_event->out_io;
	memset(io_event, 0, sizeof(struct outputio_event));
	io_stats->type = VCAM_ISP_OUTPUT_IO_TYPE_STATS;
	io_stats->stream = STREAM0;
	io_stats->id.value = stats_buf->id.value;
	io_stats->addr = stats_buf->addr;

	pr_debug("%s: %s frame_id:%d status:%d addr:0x%04x\n",
		VCAM_ISP_DEV_NAME, __func__, io_stats->id.frame,
		io_stats->id.status, io_stats->addr);

	// Pass event to reader.
	flags = 0;
	spin_lock_irqsave(&g_vcam_output_io.rd_evt_lock, flags);
	list_add_tail(&io_event->list, &g_vcam_output_io.ready_evts);
	spin_unlock_irqrestore(&g_vcam_output_io.rd_evt_lock, flags);

	wake_up_interruptible(&g_vcam_output_io.waitq);
}

void ipc_vcam_isp_outputio_notification(struct isp_ipc_device *isp_dev,
	u32 msg_id,  void *msg, enum isp_stream_type stream)
{
	int                            cam_id = msg_id & ISP_CAM_ID_MASK;
	struct reg_outbuf              *outbuf = NULL;
	unsigned long                  flags = 0;
	struct outputio_event          *io_event = NULL;
	struct vcam_isp_output_io_data *io_yuv = NULL;

	if (msg == NULL || isp_dev == NULL) {
		pr_err("%s: %s - NULL Input!\n", VCAM_ISP_DEV_NAME, __func__);
		return;
	}

	outbuf = (struct reg_outbuf *)msg;

	log_payload("vcam-isp: YUV output stream", (u32 *)outbuf,
		    sizeof(struct reg_outbuf) / sizeof(u32));

	// get next available free slot in event list
	spin_lock_irqsave(&g_vcam_output_io.free_evt_lock, flags);
	if (!list_empty(&g_vcam_output_io.free_evts)) {
		io_event = list_first_entry(&g_vcam_output_io.free_evts,
					    struct outputio_event, list);
		list_del_init(&io_event->list);
	}
	spin_unlock_irqrestore(&g_vcam_output_io.free_evt_lock, flags);
	if (io_event == NULL) {
		pr_err("%s: %s - outputio_event is NULL!\n",
			   VCAM_ISP_DEV_NAME, __func__);
		pr_info("%s: %s frame_id:%d status:%d y_addr:%x\n",
				VCAM_ISP_DEV_NAME, __func__, outbuf->id.frame,
				outbuf->id.field, outbuf->y_addr);
		out_buff_release(isp_dev, cam_id, stream, outbuf->id.frame);
		return;
	}

	io_yuv = &io_event->out_io;
	memset(io_event, 0, sizeof(struct outputio_event));
	io_yuv->type = VCAM_ISP_OUTPUT_IO_TYPE_YUV;
	io_yuv->stream = stream;
	io_yuv->id.value = outbuf->id.value;
	io_yuv->y_addr = outbuf->y_addr;
	io_yuv->u_addr = outbuf->u_addr;
	io_yuv->v_addr = outbuf->v_addr;

	pr_debug("%s: %s frame_id:%d slice:%d y_addr:0x%04x stream:%d\n",
		 VCAM_ISP_DEV_NAME, __func__, io_yuv->id.frame,
		 io_yuv->id.status, io_yuv->y_addr, io_yuv->stream);

	// Pass event to reader.
	flags = 0;
	spin_lock_irqsave(&g_vcam_output_io.rd_evt_lock, flags);
	list_add_tail(&io_event->list, &g_vcam_output_io.ready_evts);
	spin_unlock_irqrestore(&g_vcam_output_io.rd_evt_lock, flags);

	wake_up_interruptible(&g_vcam_output_io.waitq);
}

// Create the virtual device for the output_io interface
static int ipc_vcam_isp_dev_outputio_create(struct device *dev, dev_t maj_num)
{
	int ret;
	int i;

	memset(&g_vcam_output_io, 0, sizeof(struct ipc_vcam_isp_output_io));

	init_waitqueue_head(&g_vcam_output_io.waitq);

	// initialize event lists
	spin_lock_init(&g_vcam_output_io.rd_evt_lock);
	INIT_LIST_HEAD(&g_vcam_output_io.ready_evts);
	spin_lock_init(&g_vcam_output_io.free_evt_lock);
	INIT_LIST_HEAD(&g_vcam_output_io.free_evts);
	for (i = 0; i < IPC_VCAM_ISP_NUM_IO_EVTS; i++) {
		INIT_LIST_HEAD(&g_vcam_output_io.outputio_event_array[i].list);
		list_add_tail(&g_vcam_output_io.outputio_event_array[i].list,
			      &g_vcam_output_io.free_evts);
	}

	g_vcam_output_io.pdev = to_platform_device(dev);
	g_vcam_output_io.devno = MKDEV(maj_num,
				       IPC_VCAM_ISP_DATA_OUT_MINOR_NUM);

	cdev_init(&g_vcam_output_io.cdev, &fops_vcam_output_io);
	g_vcam_output_io.cdev.owner = THIS_MODULE;
	ret = cdev_add(&g_vcam_output_io.cdev, g_vcam_output_io.devno, 1);
	if (ret) {
		pr_err("%s: cdev_add failed (%d)\n", VCAM_ISP_DEV_NAME, ret);
		return ret;
	}

	g_vcam_output_io.dev = device_create(g_vcam_isp_class, NULL,
					     g_vcam_output_io.devno,
					     &g_vcam_output_io,
					     VCAM_ISP_OUTPUT_IO_NAME);
	if (IS_ERR(g_vcam_output_io.dev)) {
		pr_err("%s: bad output_io dev create.\n", VCAM_ISP_DEV_NAME);
		cdev_del(&g_vcam_output_io.cdev);
		return -1;
	}

	dev_set_drvdata(g_vcam_output_io.dev, &g_vcam_output_io);

	strcpy(g_vcam_output_io.name, VCAM_ISP_OUTPUT_IO_NAME);

	return 0;
}

int ipc_vcam_isp_init(struct device *dev)
{
	int result;
	dev_t devs;

	result = alloc_chrdev_region(&devs, 0, IPC_VCAM_ISP_MAX_DEVS,
				     "ipc_vcam_isp");
	if (result < 0) {
		pr_err("%s: can't allocate major dev num (%d)\n",
		       VCAM_ISP_DEV_NAME, result);
		return result;
	}

	pr_info("%s: create class %s\n", VCAM_ISP_DEV_NAME, VCAM_ISP_DEV_NAME);
	g_vcam_isp_class = class_create(THIS_MODULE, VCAM_ISP_DEV_NAME);
	if (IS_ERR(g_vcam_isp_class)) {
		pr_err("%s: class_create failed\n", VCAM_ISP_DEV_NAME);
		return -EPERM;
	}
	g_vcam_isp_class->devnode = ipc_vcam_isp_devnode;

	pr_info("%s: create dev %s\n",
		VCAM_ISP_DEV_NAME, VCAM_ISP_CAM_CTRL_NAME);
	result = ipc_vcam_isp_dev_camctrl_create(dev, MAJOR(devs));
	if (result < 0) {
		pr_err("%s: can't create cam_ctrl(%d)\n",
		       VCAM_ISP_DEV_NAME, result);
		return result;
	}

	pr_info("%s: create dev %s\n",
		VCAM_ISP_DEV_NAME, VCAM_ISP_INPUT_IO_NAME);
	result = ipc_vcam_isp_dev_inputio_create(dev, MAJOR(devs));
	if (result < 0) {
		pr_err("%s: can't create input_io(%d)\n",
		       VCAM_ISP_DEV_NAME, result);
		return result;
	}

	pr_info("%s: create dev %s\n",
		VCAM_ISP_DEV_NAME, VCAM_ISP_OUTPUT_IO_NAME);
	result = ipc_vcam_isp_dev_outputio_create(dev, MAJOR(devs));
	if (result < 0) {
		pr_err("%s: can't create output_io(%d)\n",
		       VCAM_ISP_DEV_NAME, result);
		return result;
	}

	return result;
}
