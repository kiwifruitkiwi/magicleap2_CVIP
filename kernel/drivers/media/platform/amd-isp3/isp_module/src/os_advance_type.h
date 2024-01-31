/*
 * Copyright (C) 2019-2020 Advanced Micro Devices, Inc. All rights reserved.
 */

#ifndef OS_ADVANCE_TYPE_H
#define OS_ADVANCE_TYPE_H

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/semaphore.h>

#include "isp_module_cfg.h"

#define MAX_ISP_TIME_TICK 0x7fffffffffffffff

struct isp_spin_lock {
	spinlock_t lock;
};

/*a count of 100-nanosecond intervals since january 1, 1601 */
//typedef long long long long;

struct isp_event {
	int automatic;
	int event;
	unsigned int result;
};

struct thread_handler {
	int stop_flag;
	struct isp_event wakeup_evt;
	struct task_struct *thread;
	struct mutex mutex;
};

typedef int(*work_thread_prototype) (void *start_context);

#define os_read_reg32(address) (*((unsigned int *)address))
#define os_write_reg32(address, value) \
	(*((unsigned int *)address) = value)

#define isp_sys_mem_alloc(size) kmalloc(size, GFP_KERNEL)
#define isp_sys_mem_free(p) kfree(p)

#define isp_mutex_init(PM)	mutex_init(PM)
#define isp_mutex_destroy(PM)	mutex_destroy(PM)
#define isp_mutex_unlock(PM)	mutex_unlock(PM)

#define isp_spin_lock_init(s_lock)	spin_lock_init(&s_lock.lock)
#define isp_spin_lock_lock(s_lock)	spin_lock(&((s_lock).lock))
#define isp_spin_lock_unlock(s_lock)	spin_unlock(&((s_lock).lock))

int isp_mutex_lock(struct mutex *p_mutex);

int isp_event_init(struct isp_event *p_event,
		int auto_matic,
		int init_state);
int isp_event_signal(unsigned int result,
		struct isp_event *p_event);
int isp_event_reset(struct isp_event *p_event);
int isp_event_wait(struct isp_event *p_event,
		unsigned int timeout_ms);
void isp_get_cur_time_tick(long long *ptimetick);
int isp_is_timeout(long long *start, long long *end,
		unsigned int timeout_ms);
int create_work_thread(struct thread_handler *handle,
			work_thread_prototype working_thread, void *context);
void stop_work_thread(struct thread_handler *handle);
int thread_should_stop(struct thread_handler *handle);

int polling_thread_wrapper(void *context);
int idle_detect_thread_wrapper(void *context);

int isp_write_file_test(struct file *fp, void *buf, ulong *len);
void NV12ToRGB565(void *nv21, void *rgb, int width, int height);

#endif
