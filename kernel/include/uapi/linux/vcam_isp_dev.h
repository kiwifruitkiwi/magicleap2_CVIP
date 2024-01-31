/*
 * Defines for interface to vcam isp driver
 *
 * Copyright (C) 2022 Magic Leap, Inc. All rights reserved.
 */

#ifndef _UAPI_LINUX_VCAM_ISP_DEV_H_
#define _UAPI_LINUX_VCAM_ISP_DEV_H_

#include <linux/ioctl.h>
#include <linux/types.h>

#if defined(cplusplus)
extern "C" {
#endif

#define VCAM_ISP_DEV_NAME       "vcam-isp"
#define VCAM_ISP_CAM_CTRL_NAME  "cam_ctrl"
#define VCAM_ISP_INPUT_IO_NAME  "input_io"
#define VCAM_ISP_OUTPUT_IO_NAME "output_io"
#define VCAM_ISP_PREPOST_PATH   "/sys/devices/virtual/vcam-isp/input_io/"
#define VCAM_ISP_PREPOST_MEM    "prepost_mem"
#define VCAM_ISP_STATS_PATH     "/sys/devices/virtual/vcam-isp/output_io/"
#define VCAM_ISP_STATS_MEM      "stats_mem"

enum vcam_isp_ctrl_stream_state {
	VCAM_ISP_CTRL_STREAM_UNTOUCHED    = 0,
	VCAM_ISP_CTRL_STREAM_OFF          = 1,
	VCAM_ISP_CTRL_STREAM_STANDBY      = 2,
	VCAM_ISP_CTRL_STREAM_ON           = 3,
	VCAM_ISP_CTRL_STREAM_RESERVED     = 4,
};

enum vcam_isp_ctrl_resolution_mode {
	VCAM_ISP_CTRL_RES_UNTOUCHED       = 0,
	VCAM_ISP_CTRL_RES_FULL            = 1,
	VCAM_ISP_CTRL_RES_V2_BINNING      = 2,
	VCAM_ISP_CTRL_RES_H2V2_BINNING    = 3,
	VCAM_ISP_CTRL_RES_H4V4_BINNING    = 4,
	VCAM_ISP_CTRL_RES_4K2K_BINNING    = 5,
	VCAM_ISP_CTRL_RES_RESERVED        = 6,
};

enum vcam_isp_ctrl_hdr_mode {
	VCAM_ISP_CTRL_HDR_UNTOUCHED       = 0,
	VCAM_ISP_CTRL_HDR_NO              = 1,
	VCAM_ISP_CTRL_HDR_ZIGZAG          = 2,
	VCAM_ISP_CTRL_HDR_2FRAME          = 3,
	VCAM_ISP_CTRL_HDR_3FRAME          = 4,
	VCAM_ISP_CTRL_HDR_RESERVED        = 5,
};

enum vcam_isp_ctrl_test_pattern {
	VCAM_ISP_CTRL_TP_UNTOUCHED        = 0,
	VCAM_ISP_CTRL_TP_NO               = 1,
	VCAM_ISP_CTRL_TP_1                = 2,
	VCAM_ISP_CTRL_TP_2                = 3,
	VCAM_ISP_CTRL_TP_3                = 4,
	VCAM_ISP_CTRL_TP_RESERVED         = 5,
};

enum vcam_isp_ctrl_bit_depth {
	VCAM_ISP_CTRL_BD_UNTOUCHED        = 0,
	VCAM_ISP_CTRL_BD_8BIT             = 1,
	VCAM_ISP_CTRL_BD_10BIT            = 2,
	VCAM_ISP_CTRL_BD_12BIT            = 3,
	VCAM_ISP_CTRL_BD_RESERVED         = 4,
};

enum vcam_isp_ctrl_resp_status {
	VCAM_ISP_CTRL_RESP_SUCCEED         = 0,
	VCAM_ISP_CTRL_RESP_UNSUPPORT       = 1,
	VCAM_ISP_CTRL_RESP_STREAM_NOT_RES  = 1,
	VCAM_ISP_CTRL_RESP_STREAM_NOT_HDR  = 2,
	VCAM_ISP_CTRL_RESP_STREAM_NOT_TP   = 3,
	VCAM_ISP_CTRL_RESP_RES_NOT_WIDTH   = 1,
	VCAM_ISP_CTRL_RESP_RES_NOT_HEIGHT  = 2,
};

enum vcam_isp_ctrl_dma_vid {
	VCAM_ISP_CTRL_DMA_VID_DISABLED = 0,
	VCAM_ISP_CTRL_DMA_VID_CVIP     = 1,
	VCAM_ISP_CTRL_DMA_VID_X86      = 2,
	VCAM_ISP_CTRL_DMA_VID_X86_CV   = 3,
};

enum vcam_isp_ctrl_swr_vid {
	VCAM_ISP_CTRL_SWR_VID_DISABLED = 0,
	VCAM_ISP_CTRL_SWR_VID_X86_IR   = 1,
	VCAM_ISP_CTRL_SWR_VID_X86_RAW  = 2,
};

enum vcam_isp_ctrl_req_type {
	VCAM_ISP_CTRL_REQ_TYPE_INFO_DATA  = 0,
	VCAM_ISP_CTRL_REQ_TYPE_DMA_STATUS = 1,
};

struct vcam_isp_ctrl_req_resolution {
	u8  res_mode;
	u16 width;
	u16 height;
};

struct vcam_isp_ctrl_req_streaming {
	u8                                  state;
	struct vcam_isp_ctrl_req_resolution res;
	u8                                  hdr;
	u8                                  test_pattern;
	u8                                  bit_depth;
};

struct vcam_isp_ctrl_req_mem_layout {
	u32 hi;
	u32 lo;
	u32 size;
};

struct vcam_isp_ctrl_req_dma_status {
	union {
		u32 report;
		struct {
			u8 dma0_en:  1;
			u8 dma1_en:  1;
			u8 dma2_en:  1;
			u8 dma3_en:  1;
			u8 swr_en:   1;
			u8 dma0_vid: 3;
			u8 dma1_vid: 3;
			u8 dma2_vid: 3;
			u8 dma3_vid: 3;
			u8 swr_vid:  3;
			u16 rsvd:   12;
		};
	};
};

struct vcam_isp_ctrl_info_data {
	union {
		u32 req;
		struct {
			u8 rq_strm_op:    1;
			u8 rq_strm_wr:    1;
			u8 rq_res_op:     1;
			u8 rq_res_wr:     1;
			u8 rq_fps_op:     1;
			u8 rq_fps_wr:     1;
			u8 rq_ana_op:     1;
			u8 rq_ana_wr:     1;
			u8 rq_dig_op:     1;
			u8 rq_dig_wr:     1;
			u8 rq_exp_op:     1;
			u8 rq_exp_wr:     1;
			u8 rq_syn_op:     1;
			u8 rq_syn_wr:     1;
			u8 rq_rsvd0:      2;
			u8 rq_lrange_op:  1;
			u8 rq_lrange_wr:  1;
			u8 rq_lpos_op:    1;
			u8 rq_lpos_wr:    1;
			u8 rq_af_mode_op: 1;
			u8 rq_af_mode_wr: 1;
			u8 rq_frm_dur_op: 1;
			u8 rq_frm_dur_wr: 1;
			u8 rq_ppmem_op:   1;
			u8 rq_ppmem_wr:   1;
			u8 rq_statmem_op: 1;
			u8 rq_statmem_wr: 1;
			u8 rq_af_trig_op: 1;
			u8 rq_af_trig_wr: 1;
			u8 rq_rsvd1:      1;
			u8 rq_resp_nd:    1;
		};
	};
	union {
		u32 strm;
		struct {
			u8 strm_state:    3;
			u8 res_mode:      3;
			u8 hdr_mode:      3;
			u8 test_pattern:  3;
			u8 bit_depth:     3;
			u32 strm_rsvd:   17;
		};
	};
	union {
		u32 res;
		struct {
			u16 width;
			u16 height;
		};
	};
	u32 fps;
	u32 again;
	u32 dgain;
	u32 exposure;
	u32 frame_dur;
	union {
		u32 af0;
		struct {
			u32 lens_pos:  24;
			u8  af0_rsvd:   2;
			u8  af_trigger: 2;
			u8  af_mode:    4;
		};
	};
	union {
		u32 af1;
		struct {
			u32 dist_far:  24;
			u8  af1_rsvd:   8;
		};
	};
	union {
		u32 af2;
		struct {
			u32 dist_near: 24;
			u8  af2_rsvd:   8;
		};
	};
	union {
		u32 slice_sync;
		struct {
			u32 sync_frm_id:   28;
			u8  sync_trn_type:  4;
		};
	};
	union {
		u32 slice_parm;
		struct {
			u16 slice0_height:   12;
			u16 slice1_n_height: 12;
			u8  slice_rsvd:       3;
			u8  slice_num:        5;
		};
	};
};

struct vcam_isp_ctrl_req {
	enum vcam_isp_ctrl_req_type type;
	u32 req_id;
	struct vcam_isp_ctrl_info_data info_data;
	struct vcam_isp_ctrl_req_mem_layout prepost_mem;
	struct vcam_isp_ctrl_req_mem_layout stats_mem;
	struct vcam_isp_ctrl_req_dma_status dma_status;
};

struct vcam_isp_ctrl_resp {
	u32 req_id;
	union {
		u32 resp;
		struct {
			u8 rsp_strm:    2;
			u8 rsp_res:     2;
			u8 rsp_fps:     2;
			u8 rsp_ana:     2;
			u8 rsp_dig:     2;
			u8 rsp_exp:     2;
			u8 rsp_syn:     2;
			u8 rsp_rsvd0:   2;
			u8 rsp_lrange:  2;
			u8 rsp_lpos:    2;
			u8 rsp_af_mode: 2;
			u8 rsp_fdur:    2;
			u8 rsp_ppmem:   2;
			u8 rsp_stmem:   2;
			u8 rsp_af_trig: 2;
			u8 rsp_rsvd1:   2;
		};
	};
	struct vcam_isp_ctrl_info_data info_data;
};

enum vcam_isp_frame_status {
	VCAM_ISP_FRAME_PROCESSED = 0,
	VCAM_ISP_FRAME_DROPPED   = 1,
};

enum vcam_isp_input_io_type {
	VCAM_ISP_IP_TYPE_PIXEL_BUF = 0,
	VCAM_ISP_IP_TYPE_PRE_BUF   = 1,
	VCAM_ISP_IP_TYPE_POST_BUF  = 2,
};

union vcam_isp_io_frame_info {
	u32 value;
	struct {
		u32 frame        :28;
		u32 status        :4;
	};
};

struct vcam_isp_input_io_release {
	enum vcam_isp_input_io_type  type;
	union vcam_isp_io_frame_info id;
};

struct vcam_isp_input_io_frame {
	u32 width;
	u32 height;
	u8  bit_width;
	u64 frm_start;
	u32 frm_size;
	u32 slice_info;
	u32 frame_id;
	u8  cur_slice;
	u8  total_slices;
	u32 predata_offset;
};

struct vcam_isp_io_mem_layout {
	u64 addr;
	u32 size;
};

/******************************************************************************/
/* PRE/POST DATA */

enum vcam_isp_cviplensstate_t {
	VCAM_ISP_CVIP_LENS_STATE_INVALID      = 0,
	VCAM_ISP_CVIP_LENS_STATE_SEARCHING    = 1,
	VCAM_ISP_CVIP_LENS_STATE_CONVERGED    = 2,
	VCAM_ISP_CVIP_LENS_STATE_MAX,
};

struct vcam_isp_cvipexpdata_t {
	u32 itime;
	u32 again;
	u32 dgain;
};

struct vcam_isp_cviptimestampinpre_t {
	u64 readoutstarttimestampus;
	u64 centroidtimestampus;
	u64 seqWintimestampus;
};

#define VCAM_ISP_AF_ROI_MAX_NUMBER 3

struct vcam_isp_cvipafroiwindow_t {
	u32 xmin;
	u32 ymin;
	u32 xmax;
	u32 ymax;
	u32 weight;
};

struct vcam_isp_cvipafroi_t {
	u32 numRoi;
	struct vcam_isp_cvipafroiwindow_t roi_af[VCAM_ISP_AF_ROI_MAX_NUMBER];
};

enum vcam_isp_cvipafmode_t {
	VCAM_ISP_CVIP_AF_CONTROL_MODE_OFF = 0x0,
	VCAM_ISP_CVIP_AF_CONTROL_MODE_AUTO = 0x1,
	VCAM_ISP_CVIP_AF_CONTROL_MODE_MACRO = 0x2,
	VCAM_ISP_CVIP_AF_CONTROL_MODE_CONTINUOUS_VIDEO = 0x4,
	VCAM_ISP_CVIP_AF_CONTROL_MODE_CONTINUOUS_PICTURE = 0x8,
};

enum vcam_isp_cvipaftrigger_t {
	VCAM_ISP_CVIP_AF_CONTROL_TRIGGER_IDLE,
	VCAM_ISP_CVIP_AF_CONTROL_TRIGGER_START,
	VCAM_ISP_CVIP_AF_CONTROL_TRIGGER_CANCEL,
};

enum vcam_isp_cvipafstate_t {
	VCAM_ISP_CVIP_AF_STATE_INACTIVE,
	VCAM_ISP_CVIP_AF_STATE_PASSIVE_SCAN,
	VCAM_ISP_CVIP_AF_STATE_PASSIVE_FOCUSED,
	VCAM_ISP_CVIP_AF_STATE_ACTIVE_SCAN,
	VCAM_ISP_CVIP_AF_STATE_FOCUSED_LOCKED,
	VCAM_ISP_CVIP_AF_STATE_NOT_FOCUSED_LOCKED,
	VCAM_ISP_CVIP_AF_STATE_PASSIVE_UNFOCUSED,
};

enum vcam_isp_cvipafscenechange_t {
	VCAM_ISP_CVIP_AF_SCENE_CHANGE_NOT_DETECTED,
	VCAM_ISP_CVIP_AF_SCENE_CHANGE_DETECTED,
};

struct vcam_isp_cvipmetaaf_t {
	//Af
	uint32_t                          mode;
	enum vcam_isp_cvipaftrigger_t     trigger;
	enum vcam_isp_cvipafstate_t       state;
	enum vcam_isp_cvipafscenechange_t scene_change;
	struct vcam_isp_cvipafroi_t       cvipafroi;
	u32                               afframeid;

	//lens
	enum vcam_isp_cviplensstate_t lensState;
	float                         distance;
	float                         distancenear;
	float                         distancefar;
	float                         focusrangenear;
	float                         focusrangefar;
};

struct vcam_isp_predata_t {
	//SensorEmbData_t sensorEmbData;
	struct vcam_isp_cvipexpdata_t         expdata;
	struct vcam_isp_cviptimestampinpre_t  timestampinpre;
	struct vcam_isp_cvipmetaaf_t          afmetadata;
};

struct vcam_isp_cviptimestampinpost_t {
	u64 readoutendtimestampus;
};

struct vcam_isp_postdata_t {
	struct vcam_isp_cviptimestampinpost_t  timestampinpost;
};

/******************************************************************************/
/* register payload definition : output buffer, stats buffer */

enum vcam_isp_output_io_type {
	VCAM_ISP_OUTPUT_IO_TYPE_STATS  = 0,
	VCAM_ISP_OUTPUT_IO_TYPE_YUV    = 1,
};

struct vcam_isp_output_io_data {
	enum vcam_isp_output_io_type type;
	u32                          stream;
	union vcam_isp_io_frame_info id;
	union {
		u32 addr;
		struct {
			u32 y_addr;
			u32 u_addr;
			u32 v_addr;
		};
	};
};

// struct copied from AMD's x86 kernel files...
// drivers/media/platform/amd-isp3/isp_module/inc/os_base_type.h
// drivers/media/platform/amd-isp3/isp_module/src/isp_fw_if/AaaStats.h
#define IDMA_COPY_START_ADDRESS_ALIGNED_WITH   256

//Use these macros when allocating copy buffers to avoid sharing cache lines:
#define IDMA_COPY_ADDR_ALIGN \
	__attribute__((__aligned__(IDMA_COPY_START_ADDRESS_ALIGNED_WITH)))

#define PREP_AE_METER_MAX_SIZE              (128 * 128 * 4)

//128x128 (zones) x 4 (1 register for each zone, 4 bytes), zone number up to
//128x128 and down to 12x9, FW set to 128x128 in AeMgr



#define PREP_AE_HIST_LONG_STATS_SIZE        (1024 * 2 * 3)

//1024 (hist bin number) x 2 (2 bytes for each bin, 1 register for 2 bins) x 3
//(R&G&B channel), IR will reuse the long G channel



#define PREP_AE_HIST_SHORT_STATS_SIZE       (1024 * 2 * 3)

//1024 (hist bin number) x 2 (2 bytes for each bin, 1 register for 2 bins) x 3
//(R&G&B channel)



#define PREP_AWB_METER_MAX_SIZE             (32 * 32 * 2 * 3)

//32x32 (zones) x 2 (2 bytes for each zone, 1 register for 2 zones) x 3
//(R&G&B channel), zone number is fixed 32x32



#define COMMON_IRIDIX_HIST_STATS_SIZE       (1024 * 4)

//1024 (hist bin number) x 4 (1 register for each bin, 4 bytes)



#define COMMON_AEXP_HIST_STATS_SIZE         (1024 * 4)

//1024 (hist bin number) x 4 (1 register for each bin, 4 bytes)



#define PING_PONG_AF_STATS_SIZE             (33 * 33 * 8)

//33x33 (zones) x 2 (2 registers for each zone) x 4 (4 bytes), zone number up
//to 33x33 and configurable, Ryan advices to set 33x33 and FW set to 33x33
//by hard code



#define PING_PONG_AWB_STATS_SIZE            (33 * 33 * 8)

#define PING_PONG_LUMVAR_STATS_SIZE		    (512 * 4)
/* 32x16 (zones) x  4 (4 bytes), zone number fixed to 32 * 16;
 * Each location contains 10-bit (LSBs) of mean information and 12 bit (MSBs)
 * of the variance of the luminance mean information for each zone
 * Minimum frame resolution required for this stat module to give usable result
 * is 512x256.
 */

#define PING_PONG_PD_TYPE_1_STATS_SIZE (2048)
//Type1 PD data size

//The total size is 109584 bytes

struct vcam_isp_output_io_stats_data {

	//PRE AE block metering

	u32 aeMetering
		[PREP_AE_METER_MAX_SIZE / 4] IDMA_COPY_ADDR_ALIGN;

	//PRE AE long histogram

	u32 aeLongHist
		[PREP_AE_HIST_LONG_STATS_SIZE / 4] IDMA_COPY_ADDR_ALIGN;

	//PRE AE short histogram

	u32 aeShortHist
		[PREP_AE_HIST_SHORT_STATS_SIZE / 4] IDMA_COPY_ADDR_ALIGN;

	//PRE AWB metering

	u32 preAwbMetering
		[PREP_AWB_METER_MAX_SIZE / 4] IDMA_COPY_ADDR_ALIGN;

	//3rd party AF metering
	u32 afMetering
		[PING_PONG_AF_STATS_SIZE / 4] IDMA_COPY_ADDR_ALIGN;

	//3rd party AWB metering
	u32 awbMetering
		[PING_PONG_AWB_STATS_SIZE / 4] IDMA_COPY_ADDR_ALIGN;

	//3rd party IRIDIX histogram

	u32 iridixHist
		[COMMON_IRIDIX_HIST_STATS_SIZE / 4] IDMA_COPY_ADDR_ALIGN;

	//3rd party AE HIST

	u32 aeHist
		[COMMON_AEXP_HIST_STATS_SIZE / 4] IDMA_COPY_ADDR_ALIGN;

	u32  lumvarMetering
		[PING_PONG_LUMVAR_STATS_SIZE / 4] IDMA_COPY_ADDR_ALIGN;

	u32 pdType1Metering
		[PING_PONG_PD_TYPE_1_STATS_SIZE / 4] IDMA_COPY_ADDR_ALIGN;
};

/******************************************************************************/

#define VCAM_ISP_IOC_MAGIC 'I'
#define VCAM_ISP_GET_INPUT_BASE \
		_IOWR(VCAM_ISP_IOC_MAGIC, 41, struct vcam_isp_io_mem_layout)

#if defined(cplusplus)
}
#endif

#endif // _UAPI_LINUX_VCAM_ISP_DEV_H_
