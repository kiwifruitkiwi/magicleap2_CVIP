/*
 * Header for IPC ISP Sensor Core Interface
 *
 * Copyright (C) 2019-2020 Magic Leap, Inc. All rights reserved.
 */

#ifndef __IPC_VCAM_ISP_H__
#define __IPC_VCAM_ISP_H__

#include <linux/types.h>
#include "ipc_types.h"
#include "ipc_isp.h"

void ipc_vcam_isp_store_input_base(u64 input_base);
void ipc_vcam_isp_ctrl_notification(struct isp_ipc_device *ipc,
					u32 msg_id,  void *msg);
void ipc_vcam_isp_dma_status_notification(struct isp_ipc_device *ipc,
					u32 msg_id,  void *msg);

void ipc_vcam_isp_inputio_notification(struct isp_ipc_device *ipc,
					u32 msg_id,  void *msg);
void ipc_vcam_isp_stats_notification(struct isp_ipc_device *isp_dev,
					u32 msg_id,  void *msg);
void ipc_vcam_isp_outputio_notification(struct isp_ipc_device *isp_dev,
					u32 msg_id,  void *msg,
					enum isp_stream_type stream);

int ipc_vcam_isp_init(struct device *dev);

#endif //__IPC_VCAM_ISP_H__
