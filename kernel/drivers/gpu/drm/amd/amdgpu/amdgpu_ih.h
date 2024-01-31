/*
 * Copyright 2014 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef __AMDGPU_IH_H__
#define __AMDGPU_IH_H__

/* Maximum number of IVs processed at once */
#define AMDGPU_IH_MAX_NUM_IVS	32

struct amdgpu_device;
enum amdgpu_ih_clientid {
	AMDGPU_IH_CLIENTID_IH		= 0x00,
	AMDGPU_IH_CLIENTID_ACP		= 0x01,
	AMDGPU_IH_CLIENTID_ATHUB	= 0x02,
	AMDGPU_IH_CLIENTID_BIF		= 0x03,
	AMDGPU_IH_CLIENTID_DCE		= 0x04,
	AMDGPU_IH_CLIENTID_ISP		= 0x05,
	AMDGPU_IH_CLIENTID_PCIE0	= 0x06,
	AMDGPU_IH_CLIENTID_RLC		= 0x07,
	AMDGPU_IH_CLIENTID_SDMA0	= 0x08,
	AMDGPU_IH_CLIENTID_SDMA1	= 0x09,
	AMDGPU_IH_CLIENTID_SE0SH	= 0x0a,
	AMDGPU_IH_CLIENTID_SE1SH	= 0x0b,
	AMDGPU_IH_CLIENTID_SE2SH	= 0x0c,
	AMDGPU_IH_CLIENTID_SE3SH	= 0x0d,
	AMDGPU_IH_CLIENTID_SYSHUB	= 0x0e,
	AMDGPU_IH_CLIENTID_THM		= 0x0f,
	AMDGPU_IH_CLIENTID_UVD		= 0x10,
	AMDGPU_IH_CLIENTID_VCE0		= 0x11,
	AMDGPU_IH_CLIENTID_VMC		= 0x12,
	AMDGPU_IH_CLIENTID_XDMA		= 0x13,
	AMDGPU_IH_CLIENTID_GRBM_CP	= 0x14,
	AMDGPU_IH_CLIENTID_ATS		= 0x15,
	AMDGPU_IH_CLIENTID_ROM_SMUIO	= 0x16,
	AMDGPU_IH_CLIENTID_DF		= 0x17,
	AMDGPU_IH_CLIENTID_VCE1		= 0x18,
	AMDGPU_IH_CLIENTID_PWR		= 0x19,
	AMDGPU_IH_CLIENTID_UTCL2	= 0x1b,
	AMDGPU_IH_CLIENTID_EA		= 0x1c,
	AMDGPU_IH_CLIENTID_UTCL2LOG	= 0x1d,
	AMDGPU_IH_CLIENTID_MP0		= 0x1e,
	AMDGPU_IH_CLIENTID_MP1		= 0x1f,

	AMDGPU_IH_CLIENTID_MAX,

	AMDGPU_IH_CLIENTID_VCN		= AMDGPU_IH_CLIENTID_UVD
};
struct amdgpu_iv_entry;

/*
 * R6xx+ IH ring
 */
struct amdgpu_ih_ring {
	unsigned		ring_size;
	uint32_t		ptr_mask;
	u32			doorbell_index;
	bool			use_doorbell;
	bool			use_bus_addr;

	struct amdgpu_bo	*ring_obj;
	volatile uint32_t	*ring;
	uint64_t		gpu_addr;

	uint64_t		wptr_addr;
	volatile uint32_t	*wptr_cpu;

	uint64_t		rptr_addr;
	volatile uint32_t	*rptr_cpu;

	bool                    enabled;
	unsigned		rptr;
	atomic_t		lock;
};

/* provided by the ih block */
struct amdgpu_ih_funcs {
	/* ring read/write ptr handling, called from interrupt context */
	u32 (*get_wptr)(struct amdgpu_device *adev, struct amdgpu_ih_ring *ih);
	void (*decode_iv)(struct amdgpu_device *adev, struct amdgpu_ih_ring *ih,
			  struct amdgpu_iv_entry *entry);
	void (*set_rptr)(struct amdgpu_device *adev, struct amdgpu_ih_ring *ih);
};

#define amdgpu_ih_get_wptr(adev, ih) (adev)->irq.ih_funcs->get_wptr((adev), (ih))
#define amdgpu_ih_decode_iv(adev, iv) \
	(adev)->irq.ih_funcs->decode_iv((adev), (ih), (iv))
#define amdgpu_ih_set_rptr(adev, ih) (adev)->irq.ih_funcs->set_rptr((adev), (ih))

int amdgpu_ih_ring_init(struct amdgpu_device *adev, struct amdgpu_ih_ring *ih,
			unsigned ring_size, bool use_bus_addr);
void amdgpu_ih_ring_fini(struct amdgpu_device *adev, struct amdgpu_ih_ring *ih);
int amdgpu_ih_process(struct amdgpu_device *adev, struct amdgpu_ih_ring *ih);

#endif