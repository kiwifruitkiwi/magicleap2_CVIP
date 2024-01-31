/*
 * Copyright (C) 2015-2022 Advanced Micro Devices, Inc. All rights reserved.
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
 * Authors: AMD
 *
 */

#ifndef __AMDGPU_DM_H__
#define __AMDGPU_DM_H__

#include <drm/drm_atomic.h>
#include <drm/drm_connector.h>
#include <drm/drm_crtc.h>
#include <drm/drm_dp_mst_helper.h>
#include <drm/drm_plane.h>

/*
 * This file contains the definition for amdgpu_display_manager
 * and its API for amdgpu driver's use.
 * This component provides all the display related functionality
 * and this is the only component that calls DAL API.
 * The API contained here intended for amdgpu driver use.
 * The API that is called directly from KMS framework is located
 * in amdgpu_dm_kms.h file
 */

#define AMDGPU_DM_MAX_DISPLAY_INDEX 31

#ifdef CONFIG_DRM_AMD_VSYNC_STB_LOGGING
#define ROOT_DEVICE_PCI_VID 0x1022
#define ROOT_DEVICE_PCI_PID 0x1645
#define NB_SMN_INDEX_0 0x60
#define NB_SMN_DATA_0 0x64
#define INDEX_VAL 0x59600
#define DATA_VAL 0xd0001234
#endif

/*
#include "include/amdgpu_dal_power_if.h"
#include "amdgpu_dm_irq.h"
*/

#include "irq_types.h"
#include "signal_types.h"
#include "amdgpu_dm_crc.h"

#include "amdgpu_dm_cv_driver.h"

/* Forward declarations */
struct amdgpu_device;
struct drm_device;
struct amdgpu_dm_irq_handler_data;
struct dc;
struct amdgpu_bo;
struct dmub_srv;

struct common_irq_params {
	struct amdgpu_device *adev;
	enum dc_irq_source irq_src;
};

/**
 * struct irq_list_head - Linked-list for low context IRQ handlers.
 *
 * @head: The list_head within &struct handler_data
 * @work: A work_struct containing the deferred handler work
 */
struct irq_list_head {
	struct list_head head;
	/* In case this interrupt needs post-processing, 'work' will be queued*/
	struct work_struct work;
};

/**
 * struct dm_compressor_info - Buffer info used by frame buffer compression
 * @cpu_addr: MMIO cpu addr
 * @bo_ptr: Pointer to the buffer object
 * @gpu_addr: MMIO gpu addr
 */
struct dm_comressor_info {
	void *cpu_addr;
	struct amdgpu_bo *bo_ptr;
	uint64_t gpu_addr;
};

/**
 * struct amdgpu_dm_backlight_caps - Usable range of backlight values from ACPI
 * @min_input_signal: minimum possible input in range 0-255
 * @max_input_signal: maximum possible input in range 0-255
 * @caps_valid: true if these values are from the ACPI interface
 */
struct amdgpu_dm_backlight_caps {
	int min_input_signal;
	int max_input_signal;
	bool caps_valid;
};

/**
 * for_each_oldnew_plane_in_state_reverse - iterate over all planes in an atomic
 * update in reverse order
 * @__state: &struct drm_atomic_state pointer
 * @plane: &struct drm_plane iteration cursor
 * @old_plane_state: &struct drm_plane_state iteration cursor for the old state
 * @new_plane_state: &struct drm_plane_state iteration cursor for the new state
 * @__i: int iteration cursor, for macro-internal use
 *
 * This iterates over all planes in an atomic update in reverse order,
 * tracking both old and  new state. This is useful in places where the
 * state delta needs to be considered, for example in atomic check functions.
 */
#if !defined(for_each_oldnew_plane_in_state_reverse) && \
	defined(for_each_oldnew_plane_in_state)
#define for_each_oldnew_plane_in_state_reverse(__state, plane, old_plane_state, new_plane_state, __i) \
	for ((__i) = ((__state)->dev->mode_config.num_total_plane - 1);	\
	     (__i) >= 0;						\
	     (__i)--)							\
		for_each_if ((__state)->planes[__i].ptr &&		\
			     ((plane) = (__state)->planes[__i].ptr,	\
			      (old_plane_state) = (__state)->planes[__i].old_state,\
			      (new_plane_state) = (__state)->planes[__i].new_state, 1))
#endif

#ifdef CONFIG_DRM_AMD_DC_DCN3_0
struct dal_allocation {
	struct list_head list;
	struct amdgpu_bo *bo;
	void *cpu_ptr;
	u64 gpu_addr;
};
#endif

/**
 * struct amdgpu_display_manager - Central amdgpu display manager device
 *
 * @dc: Display Core control structure
 * @adev: AMDGPU base driver structure
 * @ddev: DRM base driver structure
 * @display_indexes_num: Max number of display streams supported
 * @irq_handler_list_table_lock: Synchronizes access to IRQ tables
 * @backlight_dev: Backlight control device
 * @backlight_link: Link on which to control backlight
 * @backlight_caps: Capabilities of the backlight device
 * @freesync_module: Module handling freesync calculations
 * @fw_dmcu: Reference to DMCU firmware
 * @dmcu_fw_version: Version of the DMCU firmware
 * @soc_bounding_box: SOC bounding box values provided by gpu_info FW
 * @cached_state: Caches device atomic state for suspend/resume
 * @compressor: Frame buffer compression buffer. See &struct dm_comressor_info
 */
struct amdgpu_display_manager {

	struct dc *dc;

	/**
	 * @dmub_srv:
	 *
	 * DMUB service, used for controlling the DMUB on hardware
	 * that supports it. The pointer to the dmub_srv will be
	 * NULL on hardware that does not support it.
	 */
	struct dmub_srv *dmub_srv;

	/**
	 * @dmub_fb_info:
	 *
	 * Framebuffer regions for the DMUB.
	 */
	struct dmub_srv_fb_info *dmub_fb_info;

	/**
	 * @dmub_fw:
	 *
	 * DMUB firmware, required on hardware that has DMUB support.
	 */
	const struct firmware *dmub_fw;

	/**
	 * @dmub_bo:
	 *
	 * Buffer object for the DMUB.
	 */
	struct amdgpu_bo *dmub_bo;

	/**
	 * @dmub_bo_gpu_addr:
	 *
	 * GPU virtual address for the DMUB buffer object.
	 */
	u64 dmub_bo_gpu_addr;

	/**
	 * @dmub_bo_cpu_addr:
	 *
	 * CPU address for the DMUB buffer object.
	 */
	void *dmub_bo_cpu_addr;

	/**
	 * @dmcub_fw_version:
	 *
	 * DMCUB firmware version.
	 */
	uint32_t dmcub_fw_version;

	/**
	 * @cgs_device:
	 *
	 * The Common Graphics Services device. It provides an interface for
	 * accessing registers.
	 */
	struct cgs_device *cgs_device;

	struct amdgpu_device *adev;
	struct drm_device *ddev;
	u16 display_indexes_num;

#if DRM_VERSION_CODE >= DRM_VERSION(4, 14, 0)
	/**
	 * @atomic_obj:
	 *
	 * In combination with &dm_atomic_state it helps manage
	 * global atomic state that doesn't map cleanly into existing
	 * drm resources, like &dc_context.
	 */
	struct drm_private_obj atomic_obj;

#endif

	/**
	 * @dc_lock:
	 *
	 * Guards access to DC functions that can issue register write
	 * sequences.
	 */
	struct mutex dc_lock;

#if defined(HAVE_DRM_AUDIO_COMPONENT_HEADER)
	/**
	 * @audio_lock:
	 *
	 * Guards access to audio instance changes.
	 */
	struct mutex audio_lock;

	/**
	 * @audio_component:
	 *
	 * Used to notify ELD changes to sound driver.
	 */
	struct drm_audio_component *audio_component;

	/**
	 * @audio_registered:
	 *
	 * True if the audio component has been registered
	 * successfully, false otherwise.
	 */
	bool audio_registered;
#endif

	/**
	 * @irq_handler_list_low_tab:
	 *
	 * Low priority IRQ handler table.
	 *
	 * It is a n*m table consisting of n IRQ sources, and m handlers per IRQ
	 * source. Low priority IRQ handlers are deferred to a workqueue to be
	 * processed. Hence, they can sleep.
	 *
	 * Note that handlers are called in the same order as they were
	 * registered (FIFO).
	 */
	struct irq_list_head irq_handler_list_low_tab[DAL_IRQ_SOURCES_NUMBER];

	/**
	 * @irq_handler_list_high_tab:
	 *
	 * High priority IRQ handler table.
	 *
	 * It is a n*m table, same as &irq_handler_list_low_tab. However,
	 * handlers in this table are not deferred and are called immediately.
	 */
	struct list_head irq_handler_list_high_tab[DAL_IRQ_SOURCES_NUMBER];

	/**
	 * @pflip_params:
	 *
	 * Page flip IRQ parameters, passed to registered handlers when
	 * triggered.
	 */
	struct common_irq_params
	pflip_params[DC_IRQ_SOURCE_PFLIP_LAST - DC_IRQ_SOURCE_PFLIP_FIRST + 1];

	/**
	 * @vblank_params:
	 *
	 * Vertical blanking IRQ parameters, passed to registered handlers when
	 * triggered.
	 */
	struct common_irq_params
	vblank_params[DC_IRQ_SOURCE_VBLANK6 - DC_IRQ_SOURCE_VBLANK1 + 1];

	/**
	 * @vupdate_params:
	 *
	 * Vertical update IRQ parameters, passed to registered handlers when
	 * triggered.
	 */
	struct common_irq_params
	vupdate_params[DC_IRQ_SOURCE_VUPDATE6 - DC_IRQ_SOURCE_VUPDATE1 + 1];

	/**
	 * @vline0_params:
	 *
	 * Vertical interrupt 0 IRQ parameters, passed to registered handlers when
	 * triggered.
	 */
	struct common_irq_params
	vline0_params[DC_IRQ_SOURCE_DC6_VLINE0 - DC_IRQ_SOURCE_DC1_VLINE0 + 1];

	/**
	 * @dmub_trace_params:
	 *
	 * DMUB trace event IRQ parameters, passed to registered handlers when
	 * triggered.
	 */
	struct common_irq_params
	dmub_trace_params[1];

	spinlock_t irq_handler_list_table_lock;

	struct backlight_device *backlight_dev;

	const struct dc_link *backlight_link;
	struct amdgpu_dm_backlight_caps backlight_caps;

	struct mod_freesync *freesync_module;
#ifdef CONFIG_DRM_AMD_DC_HDCP
	struct hdcp_workqueue *hdcp_workqueue;
#endif

	struct drm_atomic_state *cached_state;

	struct dm_comressor_info compressor;

	const struct firmware *fw_dmcu;
	uint32_t dmcu_fw_version;
	/**
	 * @soc_bounding_box:
	 *
	 * gpu_info FW provided soc bounding box struct or 0 if not
	 * available in FW
	 */
	const struct gpu_info_soc_bounding_box_v1_0 *soc_bounding_box;

	enum amdgpu_dm_cv_driver_event cv_driver_state;
	amdgpu_dm_cv_driver_callback cv_driver_callback;
	int vs1_connector;
	struct work_struct dark_mode_work;
	struct workqueue_struct *dark_mode_process_wq;
	bool force_timing_sync;
	bool disable_hpd_irq;
	bool dmcub_trace_event_en;
#ifdef CONFIG_DRM_AMD_VSYNC_STB_LOGGING
	struct pci_dev *mr_root_pci_dev;
	spinlock_t stb_spinlock; /* spinlock for STB logging */
#endif
#ifdef CONFIG_DRM_AMD_DC_DCN3_0
	struct list_head da_list;
#endif
};

enum dsc_clock_force_state {
	DSC_CLK_FORCE_DEFAULT = 0,
	DSC_CLK_FORCE_ENABLE,
	DSC_CLK_FORCE_DISABLE,
};

struct dsc_preferred_settings {
	enum dsc_clock_force_state dsc_force_enable;
	uint32_t dsc_num_slices_v;
	uint32_t dsc_num_slices_h;
	uint32_t dsc_bits_per_pixel;
};

struct amdgpu_dm_connector {

	struct drm_connector base;
	uint32_t connector_id;

	/* we need to mind the EDID between detect
	   and get modes due to analog/digital/tvencoder */
	struct edid *edid;

	/* shared with amdgpu */
	struct amdgpu_hpd hpd;

	/* number of modes generated from EDID at 'dc_sink' */
	int num_modes;

	/* The 'old' sink - before an HPD.
	 * The 'current' sink is in dc_link->sink. */
	struct dc_sink *dc_sink;
	struct dc_link *dc_link;
	struct dc_sink *dc_em_sink;

	/* DM only */
	struct drm_dp_mst_topology_mgr mst_mgr;
	struct amdgpu_dm_dp_aux dm_dp_aux;
	struct drm_dp_mst_port *port;
	struct amdgpu_dm_connector *mst_port;
	struct amdgpu_encoder *mst_encoder;
	struct drm_dp_aux *dsc_aux;

	/* TODO see if we can merge with ddc_bus or make a dm_connector */
	struct amdgpu_i2c_adapter *i2c;

	/* Monitor range limits */
	int min_vfreq ;
	int max_vfreq ;
	int pixel_clock_mhz;

#if defined(HAVE_DRM_AUDIO_COMPONENT_HEADER)
	/* Audio instance - protected by audio_lock. */
	int audio_inst;
#endif

	struct mutex hpd_lock;
	struct mutex sink_mutex;

	bool fake_enable;
#if DRM_VERSION_CODE < DRM_VERSION(4, 7, 0)
	bool mst_connected;
#endif
#ifdef CONFIG_DEBUG_FS
	uint32_t debugfs_dpcd_address;
	uint32_t debugfs_dpcd_size;
#endif
	bool force_yuv420_output;
	struct dsc_preferred_settings dsc_settings;
};

#define to_amdgpu_dm_connector(x) container_of(x, struct amdgpu_dm_connector, base)

extern const struct amdgpu_ip_block_version dm_ip_block;

struct amdgpu_framebuffer;
struct amdgpu_display_manager;
struct dc_validation_set;
struct dc_plane_state;

struct dm_plane_state {
	struct drm_plane_state base;
	struct dc_plane_state *dc_state;
};

struct dm_crtc_state {
	struct drm_crtc_state base;
	struct dc_stream_state *stream;

	bool cm_has_degamma;
	bool cm_is_degamma_srgb;

	int update_type;
	int active_planes;
	bool interrupts_enabled;

	int crc_skip_count;
	enum amdgpu_dm_pipe_crc_source crc_src;

#if DRM_VERSION_CODE < DRM_VERSION(5, 0, 0)
	bool base_vrr_enabled;
#endif

	bool freesync_timing_changed;
	bool freesync_vrr_info_changed;

	bool dsc_force_changed;
	bool vrr_supported;
	uint8_t dark_mode;
	bool is_vs1;
	bool is_vs2;
	int num_active_lines;
	int num_offset_lines;
	struct mod_freesync_config freesync_config;
	struct dc_info_packet vrr_infopacket;

	int abm_level;
};

#define to_dm_crtc_state(x) container_of(x, struct dm_crtc_state, base)

struct dm_atomic_state {
#if DRM_VERSION_CODE >= DRM_VERSION(4, 14, 0)
	struct drm_private_state base;
#else
	struct drm_atomic_state base;
#endif

	struct dc_state *context;
};

#define to_dm_atomic_state(x) container_of(x, struct dm_atomic_state, base)

struct dm_connector_state {
	struct drm_connector_state base;

	enum amdgpu_rmx_type scaling;
	uint8_t underscan_vborder;
	uint8_t underscan_hborder;
#if DRM_VERSION_CODE < DRM_VERSION(5, 0, 0)
	uint8_t max_bpc;
#endif
	bool underscan_enable;
	bool freesync_enable;
	bool freesync_capable;
#ifdef CONFIG_DRM_AMD_DC_HDCP
	bool update_hdcp;
#endif
	uint8_t abm_level;
#if defined(HAVE_DRM_CONNECTOR_HELPER_FUNCS_ATOMIC_CHECK_ARG_DRM_ATOMIC_STATE)
	int vcpi_slots;
	uint64_t pbn;
#endif
	uint32_t dmdata_fb_id;
	struct drm_framebuffer *dmdatafb;
};

#define to_dm_connector_state(x)\
	container_of((x), struct dm_connector_state, base)

void amdgpu_dm_connector_funcs_reset(struct drm_connector *connector);
struct drm_connector_state *
amdgpu_dm_connector_atomic_duplicate_state(struct drm_connector *connector);
int amdgpu_dm_connector_atomic_set_property(struct drm_connector *connector,
					    struct drm_connector_state *state,
					    struct drm_property *property,
					    uint64_t val);

int amdgpu_dm_connector_atomic_get_property(struct drm_connector *connector,
					    const struct drm_connector_state *state,
					    struct drm_property *property,
					    uint64_t *val);

int amdgpu_dm_crtc_atomic_set_property(struct drm_crtc *crtc,
					struct drm_crtc_state *state,
					struct drm_property *property,
					uint64_t val);

int amdgpu_dm_crtc_atomic_get_property(struct drm_crtc *crtc,
					const struct drm_crtc_state *state,
					struct drm_property *property,
					uint64_t *val);

int amdgpu_dm_get_encoder_crtc_mask(struct amdgpu_device *adev);

void amdgpu_dm_connector_init_helper(struct amdgpu_display_manager *dm,
				     struct amdgpu_dm_connector *aconnector,
				     int connector_type,
				     struct dc_link *link,
				     int link_index);

enum drm_mode_status amdgpu_dm_connector_mode_valid(struct drm_connector *connector,
				   struct drm_display_mode *mode);

void dm_restore_drm_connector_state(struct drm_device *dev,
				    struct drm_connector *connector);

void amdgpu_dm_update_freesync_caps(struct drm_connector *connector,
					struct edid *edid);

void amdgpu_dm_trigger_timing_sync(struct drm_device *dev);

#define MAX_COLOR_LUT_ENTRIES 4096
/* Legacy gamm LUT users such as X doesn't like large LUT sizes */
#define MAX_COLOR_LEGACY_LUT_ENTRIES 256

#if DRM_VERSION_CODE >= DRM_VERSION(4, 6, 0)
void amdgpu_dm_init_color_mod(void);
#endif
int amdgpu_dm_update_crtc_color_mgmt(struct dm_crtc_state *crtc);
int amdgpu_dm_update_plane_color_mgmt(struct dm_crtc_state *crtc,
				      struct dc_plane_state *dc_plane_state);
bool amdgpu_dm_is_cm_bypassed(struct dm_crtc_state *crtc);

int amdgpu_dm_get_vs1_connector_index(struct amdgpu_dm_connector *amdgpu_dm_connector);

void amdgpu_dm_update_connector_after_detect(struct amdgpu_dm_connector *aconnector);

extern const struct drm_encoder_helper_funcs amdgpu_dm_encoder_helper_funcs;

#endif /* __AMDGPU_DM_H__ */
