/*
 * Copyright (C) 2019-2021 Advanced Micro Devices, Inc. All rights reserved.
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


#include "dm_services.h"
#include "dc.h"

#include "dcn301_init.h"

#include "resource.h"
#include "include/irq_service_interface.h"
#include "dcn30/dcn30_resource.h"
#include "dcn301_resource.h"

#include "dcn20/dcn20_resource.h"

#include "dcn10/dcn10_ipp.h"
#include "dcn30/dcn30_hubbub.h"
#include "dcn30/dcn30_mpc.h"
#include "dcn30/dcn30_hubp.h"
#include "irq/dcn30/irq_service_dcn30.h"
#include "dcn30/dcn30_dpp.h"
#include "dcn30/dcn30_optc.h"
#include "dcn20/dcn20_hwseq.h"
#include "dcn30/dcn30_hwseq.h"
#include "dce110/dce110_hw_sequencer.h"
#include "dcn30/dcn30_opp.h"
#include "dcn20/dcn20_dsc.h"
#include "dcn30/dcn30_vpg.h"
#include "dcn30/dcn30_afmt.h"
#include "dce/dce_clock_source.h"
#include "dce/dce_audio.h"
#include "dce/dce_hwseq.h"
#include "clk_mgr.h"
#include "virtual/virtual_stream_encoder.h"
#include "dce110/dce110_resource.h"
#include "dml/display_mode_vba.h"
#include "dcn301/dcn301_dccg.h"
#include "dcn10/dcn10_resource.h"
#include "dcn30/dcn30_dio_stream_encoder.h"
#include "dcn301/dcn301_dio_link_encoder.h"
#include "dcn301_panel.h"

#include "mero_ip_offset.h"

#include "dcn30/dcn30_dwb.h"
#include "dcn30/dcn30_mmhubbub.h"

#include "dcn/dcn_3_0_1_offset.h"
#include "dcn/dcn_3_0_1_sh_mask.h"
#include "dpcs/dpcs_3_0_1_offset.h"
#include "dpcs/dpcs_3_0_1_sh_mask.h"

#include "nbio/nbio_7_2_0_offset.h"
#include "mmhub/mmhub_2_3_0_offset.h"
#include "mmhub/mmhub_2_3_0_sh_mask.h"

#include "reg_helper.h"
#include "dce/dce_abm.h"
#include "dce/dce_dmcu.h"
#include "dce/dce_aux.h"
#include "dce/dce_i2c.h"

/* DMUB darkmode is enabled for Mero */
#include "dce/dmub_dkmd.h"

#include "dml/dcn30/display_mode_vba_30.h"
#include "vm_helper.h"
#include "dcn20/dcn20_vmid.h"

#define TO_DCN301_RES_POOL(pool)\
	container_of(pool, struct dcn301_resource_pool, base)

#define DC_LOGGER_INIT(logger)

/*Based on: //vidip/dc/dcn3/doc/architecture/DCN3x_Display_Mode.xlsm#83 */
struct _vcs_dpi_ip_params_st dcn3_01_ip = {
	.odm_capable = 1,
	.gpuvm_enable = 1,
	.hostvm_enable = 0,
	.gpuvm_max_page_table_levels = 1,
	.hostvm_max_page_table_levels = 2,
	.hostvm_cached_page_table_levels = 0,
	.pte_group_size_bytes = 2048,
	.num_dsc = 3,
	.rob_buffer_size_kbytes = 184,
	.det_buffer_size_kbytes = 184,
	.dpte_buffer_size_in_pte_reqs_luma = 64,
	.dpte_buffer_size_in_pte_reqs_chroma = 32,
	.pde_proc_buffer_size_64k_reqs = 48,
	.dpp_output_buffer_pixels = 2560,
	.opp_output_buffer_lines = 1,
	.pixel_chunk_size_kbytes = 8,
	.meta_chunk_size_kbytes = 2,
	.writeback_chunk_size_kbytes = 8,
	.line_buffer_size_bits = 789504,
	.is_line_buffer_bpp_fixed = 0,  // ?
	.line_buffer_fixed_bpp = 48,     // ?
	.dcc_supported = true,
	.writeback_interface_buffer_size_kbytes = 90,
	.writeback_line_buffer_buffer_size = 656640,
	.max_line_buffer_lines = 32,
	.writeback_luma_buffer_size_kbytes = 12,  // writeback_line_buffer_buffer_size = 656640
	.writeback_chroma_buffer_size_kbytes = 8,
	.writeback_chroma_line_buffer_width_pixels = 4,
	.writeback_max_hscl_ratio = 1,
	.writeback_max_vscl_ratio = 1,
	.writeback_min_hscl_ratio = 1,
	.writeback_min_vscl_ratio = 1,
	.writeback_max_hscl_taps = 1,
	.writeback_max_vscl_taps = 1,
	.writeback_line_buffer_luma_buffer_size = 0,
	.writeback_line_buffer_chroma_buffer_size = 14643,
	.cursor_buffer_size = 8,
	.cursor_chunk_size = 2,
	.max_num_otg = 4,
	.max_num_dpp = 4,
	.max_num_wb = 1,
	.max_dchub_pscl_bw_pix_per_clk = 4,
	.max_pscl_lb_bw_pix_per_clk = 2,
	.max_lb_vscl_bw_pix_per_clk = 4,
	.max_vscl_hscl_bw_pix_per_clk = 4,
	.max_hscl_ratio = 6,
	.max_vscl_ratio = 6,
	.hscl_mults = 4,
	.vscl_mults = 4,
	.max_hscl_taps = 8,
	.max_vscl_taps = 8,
	.dispclk_ramp_margin_percent = 1,
	.underscan_factor = 1.11,
	.min_vblank_lines = 32,
	.dppclk_delay_subtotal = 46,
	.dynamic_metadata_vm_enabled = true,
	.dppclk_delay_scl_lb_only = 16,
	.dppclk_delay_scl = 50,
	.dppclk_delay_cnvc_formatter = 27,
	.dppclk_delay_cnvc_cursor = 6,
	.dispclk_delay_subtotal = 119,
	.dcfclk_cstate_latency = 5.2, // SRExitTime
	.max_inter_dcn_tile_repeaters = 8,
	.max_num_hdmi_frl_outputs = 0,
	.odm_combine_4to1_supported = true,

	.xfc_supported = false,
	.xfc_fill_bw_overhead_percent = 10.0,
	.xfc_fill_constant_bytes = 0,
	.gfx7_compat_tiling_supported = 0,
	.number_of_cursors = 1,
};

struct _vcs_dpi_soc_bounding_box_st dcn3_01_soc = {
	.clock_limits = {
			/*TODO: fill out defaults once wm plociy is settled*/
			{
				.state = 0,
				.dcfclk_mhz = 810.0,
				.fabricclk_mhz = 1200.0,
				.dispclk_mhz = 672.0,
				.dppclk_mhz = 672.0,
				.phyclk_mhz = 810.0,
				.socclk_mhz = 1000.0,
				.dscclk_mhz = 338.0,
				.dram_speed_mts = 4266.0,
			},
			{
				.state = 1,
				.dcfclk_mhz = 810.0,
				.fabricclk_mhz = 1200.0,
				.dispclk_mhz = 672.0,
				.dppclk_mhz = 672.0,
				.phyclk_mhz = 810.0,
				.socclk_mhz = 1000.0,
				.dscclk_mhz = 338.0,
				.dram_speed_mts = 4266.0,
			}
		},

	.sr_exit_time_us = 9.0,
	.sr_enter_plus_exit_time_us = 11.0,
	.urgent_latency_us = 4.0,
	.urgent_latency_pixel_data_only_us = 4.0,
	.urgent_latency_pixel_mixed_with_vm_data_us = 4.0,
	.urgent_latency_vm_data_only_us = 4.0,
	.urgent_out_of_order_return_per_channel_pixel_only_bytes = 4096,
	.urgent_out_of_order_return_per_channel_pixel_and_vm_bytes = 4096,
	.urgent_out_of_order_return_per_channel_vm_only_bytes = 4096,
	.pct_ideal_dram_sdp_bw_after_urgent_pixel_only = 80.0,
	.pct_ideal_dram_sdp_bw_after_urgent_pixel_and_vm = 75.0,
	.pct_ideal_dram_sdp_bw_after_urgent_vm_only = 40.0,
	.max_avg_sdp_bw_use_normal_percent = 60.0,
	.max_avg_dram_bw_use_normal_percent = 60.0,
	.writeback_latency_us = 12.0,
	.max_request_size_bytes = 256,
	.dram_channel_width_bytes = 4,
	.fabric_datapath_to_dcn_data_return_bytes = 32,
	.dcn_downspread_percent = 0.5,
	.downspread_percent = 0.38,
	.dram_page_open_time_ns = 50.0,
	.dram_rw_turnaround_time_ns = 17.5,
	.dram_return_buffer_per_channel_bytes = 8192,
	.round_trip_ping_latency_dcfclk_cycles = 191,
	.urgent_out_of_order_return_per_channel_bytes = 4096,
	.channel_interleave_bytes = 256,
	.num_banks = 8,
	.num_chans = 4,
	.gpuvm_min_page_size_bytes = 4096,
	.hostvm_min_page_size_bytes = 4096,
	.dram_clock_change_latency_us = 23.84,
	.writeback_dram_clock_change_latency_us = 23.0,
	.return_bus_width_bytes = 64,
	.dispclk_dppclk_vco_speed_mhz = 3550,
	.xfc_bus_transport_time_us = 20,      // ?
	.xfc_xbuf_latency_tolerance_us = 4,  // ?
	.use_urgent_burst_bw = 1,            // ?
	.num_states = 2,
	.do_urgent_latency_adjustment = false,
	.urgent_latency_adjustment_fabric_clock_component_us = 0,
	.urgent_latency_adjustment_fabric_clock_reference_mhz = 0,
};

enum dcn301_clk_src_array_id {
	DCN301_CLK_SRC_PLL0,
	DCN301_CLK_SRC_PLL1,
	DCN301_CLK_SRC_PLL2,
	DCN301_CLK_SRC_PLL3,
	DCN301_CLK_SRC_TOTAL
};

/* begin *********************
 * macros to expend register list macro defined in HW object header file
 */

/* DCN */
/* TODO awful hack. fixup dcn20_dwb.h */
#undef BASE_INNER
#define BASE_INNER(seg) DCN_BASE__INST0_SEG ## seg

#define BASE(seg) BASE_INNER(seg)

#define SR(reg_name)\
		.reg_name = BASE(mm ## reg_name ## _BASE_IDX) +  \
					mm ## reg_name

#define SRI(reg_name, block, id)\
	.reg_name = BASE(mm ## block ## id ## _ ## reg_name ## _BASE_IDX) + \
					mm ## block ## id ## _ ## reg_name

#define SRI2(reg_name, block, id)\
	.reg_name = BASE(mm ## reg_name ## _BASE_IDX) + \
					mm ## reg_name

#define SRIR(var_name, reg_name, block, id)\
	.var_name = BASE(mm ## block ## id ## _ ## reg_name ## _BASE_IDX) + \
					mm ## block ## id ## _ ## reg_name

#define SRII(reg_name, block, id)\
	.reg_name[id] = BASE(mm ## block ## id ## _ ## reg_name ## _BASE_IDX) + \
					mm ## block ## id ## _ ## reg_name

#define SRII2(reg_name_pre, reg_name_post, id)\
	.reg_name_pre ## _ ##  reg_name_post[id] = BASE(mm ## reg_name_pre \
			## id ## _ ## reg_name_post ## _BASE_IDX) + \
			mm ## reg_name_pre ## id ## _ ## reg_name_post

#define SRII_MPC_RMU(reg_name, block, id)\
	.RMU##_##reg_name[id] = BASE(mm ## block ## id ## _ ## reg_name ## _BASE_IDX) + \
					mm ## block ## id ## _ ## reg_name

#define SRII_DWB(reg_name, temp_name, block, id)\
	.reg_name[id] = BASE(mm ## block ## id ## _ ## temp_name ## _BASE_IDX) + \
					mm ## block ## id ## _ ## temp_name

#define DCCG_SRII(reg_name, block, id)\
	.block ## _ ## reg_name[id] = BASE(mm ## block ## id ## _ ## reg_name ## _BASE_IDX) + \
					mm ## block ## id ## _ ## reg_name

#define VUPDATE_SRII(reg_name, block, id)\
	.reg_name[id] = BASE(mm ## reg_name ## _ ## block ## id ## _BASE_IDX) + \
					mm ## reg_name ## _ ## block ## id

/* NBIO */
#define NBIO_BASE_INNER(seg) \
	NBIO_BASE__INST0_SEG ## seg

#define NBIO_BASE(seg) \
	NBIO_BASE_INNER(seg)

#define NBIO_SR(reg_name)\
		.reg_name = NBIO_BASE(regBIF_BX0_ ## reg_name ## _BASE_IDX) + \
					regBIF_BX0_ ## reg_name

/* MMHUB */
#define MMHUB_BASE_INNER(seg) \
	MMHUB_BASE__INST0_SEG ## seg

#define MMHUB_BASE(seg) \
	MMHUB_BASE_INNER(seg)

#define MMHUB_SR(reg_name)\
		.reg_name = MMHUB_BASE(regMM ## reg_name ## _BASE_IDX) + \
					regMM ## reg_name

/* CLOCK */
#define CLK_BASE_INNER(seg) \
	CLK_BASE__INST0_SEG ## seg

#define CLK_BASE(seg) \
	CLK_BASE_INNER(seg)

#define CLK_SRI(reg_name, block, inst)\
	.reg_name = CLK_BASE(mm ## block ## _ ## inst ## _ ## reg_name ## _BASE_IDX) + \
					mm ## block ## _ ## inst ## _ ## reg_name

static const struct bios_registers bios_regs = {
		NBIO_SR(BIOS_SCRATCH_3),
		NBIO_SR(BIOS_SCRATCH_6)
};

#define clk_src_regs(index, pllid)\
[index] = {\
	CS_COMMON_REG_LIST_DCN3_01(index, pllid),\
}

static const struct dce110_clk_src_regs clk_src_regs[] = {
	clk_src_regs(0, A),
	clk_src_regs(1, B),
	clk_src_regs(2, C),
	clk_src_regs(3, D)
};

static const struct dce110_clk_src_shift cs_shift = {
		CS_COMMON_MASK_SH_LIST_DCN2_0(__SHIFT)
};

static const struct dce110_clk_src_mask cs_mask = {
		CS_COMMON_MASK_SH_LIST_DCN2_0(_MASK)
};



static const struct dce_dmcu_registers dmcu_regs = {
		DMCU_DCN10_REG_LIST()
};

static const struct dce_dmcu_shift dmcu_shift = {
		DMCU_MASK_SH_LIST_DCN10(__SHIFT)
};

static const struct dce_dmcu_mask dmcu_mask = {
		DMCU_MASK_SH_LIST_DCN10(_MASK)
};

//static const struct dce_abm_registers abm_regs = {
//		ABM_DCN20_REG_LIST()
//};

//static const struct dce_abm_shift abm_shift = {
//		ABM_MASK_SH_LIST_DCN20(__SHIFT)
//};

//static const struct dce_abm_mask abm_mask = {
//		ABM_MASK_SH_LIST_DCN20(_MASK)
//};



#define audio_regs(id)\
[id] = {\
		AUD_COMMON_REG_LIST(id)\
}

static const struct dce_audio_registers audio_regs[] = {
	audio_regs(0),
	audio_regs(1),
	audio_regs(2),
	audio_regs(3),
	audio_regs(4),
	audio_regs(5),
	audio_regs(6)
};

#define DCE120_AUD_COMMON_MASK_SH_LIST(mask_sh)\
		SF(AZF0ENDPOINT0_AZALIA_F0_CODEC_ENDPOINT_INDEX, AZALIA_ENDPOINT_REG_INDEX, mask_sh),\
		SF(AZF0ENDPOINT0_AZALIA_F0_CODEC_ENDPOINT_DATA, AZALIA_ENDPOINT_REG_DATA, mask_sh),\
		AUD_COMMON_MASK_SH_LIST_BASE(mask_sh)

static const struct dce_audio_shift audio_shift = {
		DCE120_AUD_COMMON_MASK_SH_LIST(__SHIFT)
};

static const struct dce_audio_mask audio_mask = {
		DCE120_AUD_COMMON_MASK_SH_LIST(_MASK)
};

#define vpg_regs(id)\
[id] = {\
	VPG_DCN3_REG_LIST(id)\
}

static const struct dcn30_vpg_registers vpg_regs[] = {
	vpg_regs(0),
	vpg_regs(1),
	vpg_regs(2),
	vpg_regs(3),
};

static const struct dcn30_vpg_shift vpg_shift = {
	DCN3_VPG_MASK_SH_LIST(__SHIFT)
};

static const struct dcn30_vpg_mask vpg_mask = {
	DCN3_VPG_MASK_SH_LIST(_MASK)
};

#define afmt_regs(id)\
[id] = {\
	AFMT_DCN3_REG_LIST(id)\
}

static const struct dcn30_afmt_registers afmt_regs[] = {
	afmt_regs(0),
	afmt_regs(1),
	afmt_regs(2),
	afmt_regs(3),
};

static const struct dcn30_afmt_shift afmt_shift = {
	DCN3_AFMT_MASK_SH_LIST(__SHIFT)
};

static const struct dcn30_afmt_mask afmt_mask = {
	DCN3_AFMT_MASK_SH_LIST(_MASK)
};

#define stream_enc_regs(id)\
[id] = {\
	SE_DCN3_REG_LIST(id)\
}

static const struct dcn10_stream_enc_registers stream_enc_regs[] = {
	stream_enc_regs(0),
	stream_enc_regs(1),
	stream_enc_regs(2),
	stream_enc_regs(3),
};

static const struct dcn10_stream_encoder_shift se_shift = {
		SE_COMMON_MASK_SH_LIST_DCN30(__SHIFT)
};

static const struct dcn10_stream_encoder_mask se_mask = {
		SE_COMMON_MASK_SH_LIST_DCN30(_MASK)
};


#define aux_regs(id)\
[id] = {\
	DCN2_AUX_REG_LIST(id)\
}

static const struct dcn10_link_enc_aux_registers link_enc_aux_regs[] = {
		aux_regs(0),
		aux_regs(1),
		aux_regs(2),
		aux_regs(3),
};

#define hpd_regs(id)\
[id] = {\
	HPD_REG_LIST(id)\
}

static const struct dcn10_link_enc_hpd_registers link_enc_hpd_regs[] = {
		hpd_regs(0),
		hpd_regs(1),
		hpd_regs(2),
		hpd_regs(3),
};

#define link_regs(id, phyid)\
[id] = {\
	LE_DCN301_REG_LIST(id), \
	UNIPHY_DCN2_REG_LIST(phyid), \
	DPCS_DCN2_REG_LIST(id), \
	SRI(DP_DPHY_INTERNAL_CTRL, DP, id) \
}

static const struct dce110_aux_registers_shift aux_shift = {
	DCN_AUX_MASK_SH_LIST(__SHIFT)
};

static const struct dce110_aux_registers_mask aux_mask = {
	DCN_AUX_MASK_SH_LIST(_MASK)
};

static const struct dcn10_link_enc_registers link_enc_regs[] = {
	link_regs(0, A),
	link_regs(1, B),
	link_regs(2, C),
	link_regs(3, D),
};

static const struct dcn10_link_enc_shift le_shift = {
	LINK_ENCODER_MASK_SH_LIST_DCN301(__SHIFT),\
	DPCS_DCN2_MASK_SH_LIST(__SHIFT)
};

static const struct dcn10_link_enc_mask le_mask = {
	LINK_ENCODER_MASK_SH_LIST_DCN301(_MASK),\
	DPCS_DCN2_MASK_SH_LIST(_MASK)
};

#define panel_regs(id)\
[id] = {\
	DCN301_PANEL_REG_LIST(id),\
}

static const struct dce_panel_registers panel_regs[] = {
	panel_regs(0),
	panel_regs(1),
};

static const struct dcn301_panel_shift panel_shift = {
	DCN301_PANEL_MASK_SH_LIST(__SHIFT)
};

static const struct dcn301_panel_mask panel_mask = {
	DCN301_PANEL_MASK_SH_LIST(_MASK)
};

#define dpp_regs(id)\
[id] = {\
	DPP_REG_LIST_DCN30(id),\
}

static const struct dcn3_dpp_registers dpp_regs[] = {
	dpp_regs(0),
	dpp_regs(1),
	dpp_regs(2),
	dpp_regs(3),
};

static const struct dcn3_dpp_shift tf_shift = {
		DPP_REG_LIST_SH_MASK_DCN30(__SHIFT)
};

static const struct dcn3_dpp_mask tf_mask = {
		DPP_REG_LIST_SH_MASK_DCN30(_MASK)
};

#define opp_regs(id)\
[id] = {\
	OPP_REG_LIST_DCN30(id),\
}

static const struct dcn20_opp_registers opp_regs[] = {
	opp_regs(0),
	opp_regs(1),
	opp_regs(2),
	opp_regs(3),
};

static const struct dcn20_opp_shift opp_shift = {
	OPP_MASK_SH_LIST_DCN20(__SHIFT)
};

static const struct dcn20_opp_mask opp_mask = {
	OPP_MASK_SH_LIST_DCN20(_MASK)
};

#define aux_engine_regs(id)\
[id] = {\
	AUX_COMMON_REG_LIST0(id), \
	.AUXN_IMPCAL = 0, \
	.AUXP_IMPCAL = 0, \
	.AUX_RESET_MASK = DP_AUX0_AUX_CONTROL__AUX_RESET_MASK, \
}

static const struct dce110_aux_registers aux_engine_regs[] = {
		aux_engine_regs(0),
		aux_engine_regs(1),
		aux_engine_regs(2),
		aux_engine_regs(3),
};

#define dwbc_regs_dcn3(id)\
[id] = {\
	DWBC_COMMON_REG_LIST_DCN30(id),\
}

static const struct dcn30_dwbc_registers dwbc30_regs[] = {
	dwbc_regs_dcn3(0),
};

static const struct dcn30_dwbc_shift dwbc30_shift = {
	DWBC_COMMON_MASK_SH_LIST_DCN30(__SHIFT)
};

static const struct dcn30_dwbc_mask dwbc30_mask = {
	DWBC_COMMON_MASK_SH_LIST_DCN30(_MASK)
};

#define mcif_wb_regs_dcn3(id)\
[id] = {\
	MCIF_WB_COMMON_REG_LIST_DCN30(id),\
}

static const struct dcn30_mmhubbub_registers mcif_wb30_regs[] = {
	mcif_wb_regs_dcn3(0)
};

static const struct dcn30_mmhubbub_shift mcif_wb30_shift = {
	MCIF_WB_COMMON_MASK_SH_LIST_DCN30(__SHIFT)
};

static const struct dcn30_mmhubbub_mask mcif_wb30_mask = {
	MCIF_WB_COMMON_MASK_SH_LIST_DCN30(_MASK)
};

#define dsc_regsDCN20(id)\
[id] = {\
	DSC_REG_LIST_DCN20(id)\
}

static const struct dcn20_dsc_registers dsc_regs[] = {
	dsc_regsDCN20(0),
	dsc_regsDCN20(1),
	dsc_regsDCN20(2),
};

static const struct dcn20_dsc_shift dsc_shift = {
	DSC_REG_LIST_SH_MASK_DCN20(__SHIFT)
};

static const struct dcn20_dsc_mask dsc_mask = {
	DSC_REG_LIST_SH_MASK_DCN20(_MASK)
};

static const struct dcn30_mpc_registers mpc_regs = {
		MPC_REG_LIST_DCN3_0(0),
		MPC_REG_LIST_DCN3_0(1),
		MPC_REG_LIST_DCN3_0(2),
		MPC_REG_LIST_DCN3_0(3),
		MPC_OUT_MUX_REG_LIST_DCN3_0(0),
		MPC_OUT_MUX_REG_LIST_DCN3_0(1),
		MPC_OUT_MUX_REG_LIST_DCN3_0(2),
		MPC_OUT_MUX_REG_LIST_DCN3_0(3),
		MPC_RMU_GLOBAL_REG_LIST_DCN3AG,
		MPC_RMU_REG_LIST_DCN3AG(0),
		MPC_RMU_REG_LIST_DCN3AG(1),
		MPC_DWB_MUX_REG_LIST_DCN3_0(0),
};

static const struct dcn30_mpc_shift mpc_shift = {
	MPC_COMMON_MASK_SH_LIST_DCN30(__SHIFT)
};

static const struct dcn30_mpc_mask mpc_mask = {
	MPC_COMMON_MASK_SH_LIST_DCN30(_MASK)
};

#define optc_regs(id)\
[id] = {OPTC_COMMON_REG_LIST_DCN3_0(id)}


static const struct dcn_optc_registers optc_regs[] = {
	optc_regs(0),
	optc_regs(1),
	optc_regs(2),
	optc_regs(3),
};

static const struct dcn_optc_shift optc_shift = {
	OPTC_COMMON_MASK_SH_LIST_DCN30(__SHIFT)
};

static const struct dcn_optc_mask optc_mask = {
	OPTC_COMMON_MASK_SH_LIST_DCN30(_MASK)
};

#define hubp_regs(id)\
[id] = {\
	HUBP_REG_LIST_DCN30(id)\
}

static const struct dcn_hubp2_registers hubp_regs[] = {
		hubp_regs(0),
		hubp_regs(1),
		hubp_regs(2),
		hubp_regs(3),
};

static const struct dcn_hubp2_shift hubp_shift = {
		HUBP_MASK_SH_LIST_DCN30(__SHIFT)
};

static const struct dcn_hubp2_mask hubp_mask = {
		HUBP_MASK_SH_LIST_DCN30(_MASK)
};

static const struct dcn_hubbub_registers hubbub_reg = {
		HUBBUB_REG_LIST_DCN30(0)
};

static const struct dcn_hubbub_shift hubbub_shift = {
		HUBBUB_MASK_SH_LIST_DCN30(__SHIFT)
};

static const struct dcn_hubbub_mask hubbub_mask = {
		HUBBUB_MASK_SH_LIST_DCN30(_MASK)
};

static const struct dccg_registers dccg_regs = {
		DCCG_REG_LIST_DCN301()
};

static const struct dccg_shift dccg_shift = {
		DCCG_MASK_SH_LIST_DCN301(__SHIFT)
};

static const struct dccg_mask dccg_mask = {
		DCCG_MASK_SH_LIST_DCN301(_MASK)
};

static const struct dce_hwseq_registers hwseq_reg = {
		HWSEQ_DCN301_REG_LIST()
};

static const struct dce_hwseq_shift hwseq_shift = {
		HWSEQ_DCN301_MASK_SH_LIST(__SHIFT)
};

static const struct dce_hwseq_mask hwseq_mask = {
		HWSEQ_DCN301_MASK_SH_LIST(_MASK)
};
#define vmid_regs(id)\
[id] = {\
		DCN20_VMID_REG_LIST(id)\
}

static const struct dcn_vmid_registers vmid_regs[] = {
	vmid_regs(0),
	vmid_regs(1),
	vmid_regs(2),
	vmid_regs(3),
	vmid_regs(4),
	vmid_regs(5),
	vmid_regs(6),
	vmid_regs(7),
	vmid_regs(8),
	vmid_regs(9),
	vmid_regs(10),
	vmid_regs(11),
	vmid_regs(12),
	vmid_regs(13),
	vmid_regs(14),
	vmid_regs(15)
};

static const struct dcn20_vmid_shift vmid_shifts = {
		DCN20_VMID_MASK_SH_LIST(__SHIFT)
};

static const struct dcn20_vmid_mask vmid_masks = {
		DCN20_VMID_MASK_SH_LIST(_MASK)
};

static const struct resource_caps res_cap_dcn301 = {
	.num_timing_generator = 4,
	.num_opp = 4,
	.num_video_plane = 4,
	.num_audio = 4,
	.num_stream_encoder = 4,
	.num_pll = 4,
	.num_dwb = 1,
	.num_ddc = 4,
	.num_vmid = 16,
	.num_mpc_3dlut = 2,
	.num_dsc = 3,
};

static const struct dc_plane_cap plane_cap = {
	.type = DC_PLANE_TYPE_DCN_UNIVERSAL,
	.blends_with_above = true,
	.blends_with_below = true,
	.per_pixel_alpha = true,

	.pixel_format_support = {
			.argb8888 = true,
			.nv12 = true,
			.fp16 = true,
			.p010 = false,
			.ayuv = false,
	},

	.max_upscale_factor = {
			.argb8888 = 16000,
			.nv12 = 16000,
			.fp16 = 16000
	},

	.max_downscale_factor = {
			.argb8888 = 600,
			.nv12 = 600,
			.fp16 = 600
	}
};

static const struct dc_debug_options debug_defaults_drv = {
	.disable_dmcu = true,
	.force_abm_enable = false,
	.timing_trace = false,
	.clock_trace = true,
	.disable_pplib_clock_request = true,
	.pipe_split_policy = MPC_SPLIT_DYNAMIC,
	.force_single_disp_pipe_split = false,
	.disable_dcc = DCC_ENABLE,
	.vsr_support = true,
	.performance_trace = false,
	.max_downscale_src_width = 7680,/*upto 8K*/
	.scl_reset_length10 = true,
	.sanity_checks = false,
	.disable_tri_buf = true,
	.underflow_assert_delay_us = 0xFFFFFFFF,
	.dwb_fi_phase = -1, // -1 = disable
	.dmub_command_table = true,
	.use_max_lb = true,
};

static const struct dc_debug_options debug_defaults_diags = {
	.disable_dmcu = true,
	.force_abm_enable = false,
	.timing_trace = true,
	.clock_trace = true,
	.disable_dpp_power_gate = true,
	.disable_hubp_power_gate = true,
	.disable_mem_low_power = true,
	.disable_clock_gate = true,
	.disable_pplib_clock_request = true,
	.disable_stutter = true,
	.scl_reset_length10 = true,
	.dwb_fi_phase = -1, // -1 = disable
	.dmub_command_table = true,
};

void dcn301_dpp_destroy(struct dpp **dpp)
{
	kfree(TO_DCN20_DPP(*dpp));
	*dpp = NULL;
}

struct dpp *dcn301_dpp_create(
	struct dc_context *ctx,
	uint32_t inst)
{
	struct dcn3_dpp *dpp =
		kzalloc(sizeof(struct dcn3_dpp), GFP_KERNEL);

	if (!dpp)
		return NULL;

	if (dpp3_construct(dpp, ctx, inst,
			&dpp_regs[inst], &tf_shift, &tf_mask))
		return &dpp->base;

	BREAK_TO_DEBUGGER();
	kfree(dpp);
	return NULL;
}
struct output_pixel_processor *dcn301_opp_create(
	struct dc_context *ctx, uint32_t inst)
{
	struct dcn20_opp *opp =
		kzalloc(sizeof(struct dcn20_opp), GFP_KERNEL);

	if (!opp) {
		BREAK_TO_DEBUGGER();
		return NULL;
	}

	dcn20_opp_construct(opp, ctx, inst,
			&opp_regs[inst], &opp_shift, &opp_mask);
	return &opp->base;
}

struct dce_aux *dcn301_aux_engine_create(
	struct dc_context *ctx,
	uint32_t inst)
{
	struct aux_engine_dce110 *aux_engine =
		kzalloc(sizeof(struct aux_engine_dce110), GFP_KERNEL);

	if (!aux_engine)
		return NULL;

	dce110_aux_engine_construct(aux_engine, ctx, inst,
				    SW_AUX_TIMEOUT_PERIOD_MULTIPLIER * AUX_TIMEOUT_PERIOD,
				    &aux_engine_regs[inst],
					&aux_mask,
					&aux_shift,
					ctx->dc->caps.extended_aux_timeout_support);

	return &aux_engine->base;
}
#define i2c_inst_regs(id) { I2C_HW_ENGINE_COMMON_REG_LIST(id) }

static const struct dce_i2c_registers i2c_hw_regs[] = {
		i2c_inst_regs(1),
		i2c_inst_regs(2),
		i2c_inst_regs(3),
		i2c_inst_regs(4),
};

static const struct dce_i2c_shift i2c_shifts = {
		I2C_COMMON_MASK_SH_LIST_DCN2(__SHIFT)
};

static const struct dce_i2c_mask i2c_masks = {
		I2C_COMMON_MASK_SH_LIST_DCN2(_MASK)
};

struct dce_i2c_hw *dcn301_i2c_hw_create(
	struct dc_context *ctx,
	uint32_t inst)
{
	struct dce_i2c_hw *dce_i2c_hw =
		kzalloc(sizeof(struct dce_i2c_hw), GFP_KERNEL);

	if (!dce_i2c_hw)
		return NULL;

	dcn2_i2c_hw_construct(dce_i2c_hw, ctx, inst,
				    &i2c_hw_regs[inst], &i2c_shifts, &i2c_masks);

	return dce_i2c_hw;
}
static struct mpc *dcn301_mpc_create(
		struct dc_context *ctx,
		int num_mpcc,
		int num_rmu)
{
	struct dcn30_mpc *mpc30 = kzalloc(sizeof(struct dcn30_mpc),
					  GFP_KERNEL);

	if (!mpc30)
		return NULL;

	dcn30_mpc_construct(mpc30, ctx,
			&mpc_regs,
			&mpc_shift,
			&mpc_mask,
			num_mpcc,
			num_rmu);

	return &mpc30->base;
}

struct hubbub *dcn301_hubbub_create(struct dc_context *ctx)
{
	int i;

	struct dcn20_hubbub *hubbub3 = kzalloc(sizeof(struct dcn20_hubbub),
					  GFP_KERNEL);

	if (!hubbub3)
		return NULL;

	hubbub3_construct(hubbub3, ctx,
			&hubbub_reg,
			&hubbub_shift,
			&hubbub_mask);


	for (i = 0; i < res_cap_dcn301.num_vmid; i++) {
		struct dcn20_vmid *vmid = &hubbub3->vmid[i];

		vmid->ctx = ctx;

		vmid->regs = &vmid_regs[i];
		vmid->shifts = &vmid_shifts;
		vmid->masks = &vmid_masks;
	}

	return &hubbub3->base;
}

struct timing_generator *dcn301_timing_generator_create(
		struct dc_context *ctx,
		uint32_t instance)
{
	struct optc *tgn10 =
		kzalloc(sizeof(struct optc), GFP_KERNEL);

	if (!tgn10)
		return NULL;

	tgn10->base.inst = instance;
	tgn10->base.ctx = ctx;

	tgn10->tg_regs = &optc_regs[instance];
	tgn10->tg_shift = &optc_shift;
	tgn10->tg_mask = &optc_mask;

	dcn30_timing_generator_init(tgn10);

	return &tgn10->base;
}

static const struct encoder_feature_support link_enc_feature = {
		.max_hdmi_deep_color = COLOR_DEPTH_121212,
		.max_hdmi_pixel_clock = 600000,
		.hdmi_ycbcr420_supported = true,
		.dp_ycbcr420_supported = true,
		.flags.bits.IS_HBR2_CAPABLE = true,
		.flags.bits.IS_HBR3_CAPABLE = true,
		.flags.bits.IS_TPS3_CAPABLE = true,
		.flags.bits.IS_TPS4_CAPABLE = true
};

struct link_encoder *dcn301_link_encoder_create(
	const struct encoder_init_data *enc_init_data)
{
	struct dcn20_link_encoder *enc20 =
		kzalloc(sizeof(struct dcn20_link_encoder), GFP_KERNEL);

	if (!enc20)
		return NULL;

	dcn301_link_encoder_construct(enc20,
			enc_init_data,
			&link_enc_feature,
			&link_enc_regs[enc_init_data->transmitter],
			&link_enc_aux_regs[enc_init_data->channel - 1],
			&link_enc_hpd_regs[enc_init_data->hpd_source],
			&le_shift,
			&le_mask);

	return &enc20->enc10.base;
}

#define CTX ctx

#define REG(reg_name) \
	(DCN_BASE.instance[0].segment[mm ## reg_name ## _BASE_IDX] + mm ## reg_name)

static uint32_t read_pipe_fuses(struct dc_context *ctx)
{
	uint32_t value = REG_READ(CC_DC_PIPE_DIS);
	/* RV1 support max 4 pipes */
	value = value & 0xf;
	return value;
}


static void read_dce_straps(
	struct dc_context *ctx,
	struct resource_straps *straps)
{
	generic_reg_get(ctx, mmDC_PINSTRAPS + BASE(mmDC_PINSTRAPS_BASE_IDX),
		FN(DC_PINSTRAPS, DC_PINSTRAPS_AUDIO), &straps->dc_pinstraps_audio);

}

static struct audio *dcn301_create_audio(
		struct dc_context *ctx, unsigned int inst)
{
	return dce_audio_create(ctx, inst,
			&audio_regs[inst], &audio_shift, &audio_mask);
}

static struct vpg *dcn301_vpg_create(
	struct dc_context *ctx,
	uint32_t inst)
{
	struct dcn30_vpg *vpg3 = kzalloc(sizeof(struct dcn30_vpg), GFP_KERNEL);

	if (!vpg3)
		return NULL;

	vpg3_construct(vpg3, ctx, inst,
			&vpg_regs[inst],
			&vpg_shift,
			&vpg_mask);

	return &vpg3->base;
}

static struct afmt *dcn301_afmt_create(
	struct dc_context *ctx,
	uint32_t inst)
{
	struct dcn30_afmt *afmt3 = kzalloc(sizeof(struct dcn30_afmt), GFP_KERNEL);

	if (!afmt3)
		return NULL;

	afmt3_construct(afmt3, ctx, inst,
			&afmt_regs[inst],
			&afmt_shift,
			&afmt_mask);

	return &afmt3->base;
}

struct stream_encoder *dcn301_stream_encoder_create(
	enum engine_id eng_id,
	struct dc_context *ctx)
{
	struct dcn10_stream_encoder *enc1;
	struct vpg *vpg;
	struct afmt *afmt;
	int vpg_inst;
	int afmt_inst;

	/* Mapping of VPG, AFMT, DME register blocks to DIO block instance */
	if (eng_id <= ENGINE_ID_DIGF) {
		vpg_inst = eng_id;
		afmt_inst = eng_id;
	} else
		return NULL;

	enc1 = kzalloc(sizeof(struct dcn10_stream_encoder), GFP_KERNEL);
	vpg = dcn301_vpg_create(ctx, vpg_inst);
	afmt = dcn301_afmt_create(ctx, afmt_inst);

	if (!enc1 || !vpg || !afmt)
		return NULL;

	dcn30_dio_stream_encoder_construct(enc1, ctx, ctx->dc_bios,
					eng_id, vpg, afmt,
					&stream_enc_regs[eng_id],
					&se_shift, &se_mask);

	return &enc1->base;
}

struct dce_hwseq *dcn301_hwseq_create(
	struct dc_context *ctx)
{
	struct dce_hwseq *hws = kzalloc(sizeof(struct dce_hwseq), GFP_KERNEL);

	if (hws) {
		hws->ctx = ctx;
		hws->regs = &hwseq_reg;
		hws->shifts = &hwseq_shift;
		hws->masks = &hwseq_mask;
	}
	return hws;
}
static const struct resource_create_funcs res_create_funcs = {
	.read_dce_straps = read_dce_straps,
	.create_audio = dcn301_create_audio,
	.create_stream_encoder = dcn301_stream_encoder_create,
	.create_hwseq = dcn301_hwseq_create,
};

static const struct resource_create_funcs res_create_maximus_funcs = {
	.read_dce_straps = NULL,
	.create_audio = NULL,
	.create_stream_encoder = NULL,
	.create_hwseq = dcn301_hwseq_create,
};

static void dcn301_destruct(struct dcn301_resource_pool *pool)
{
	unsigned int i;

	for (i = 0; i < pool->base.stream_enc_count; i++) {
		if (pool->base.stream_enc[i] != NULL) {
			if (pool->base.stream_enc[i]->vpg != NULL) {
				kfree(DCN30_VPG_FROM_VPG(pool->base.stream_enc[i]->vpg));
				pool->base.stream_enc[i]->vpg = NULL;
			}
			if (pool->base.stream_enc[i]->afmt != NULL) {
				kfree(DCN30_AFMT_FROM_AFMT(pool->base.stream_enc[i]->afmt));
				pool->base.stream_enc[i]->afmt = NULL;
			}
			kfree(DCN10STRENC_FROM_STRENC(pool->base.stream_enc[i]));
			pool->base.stream_enc[i] = NULL;
		}
	}

	for (i = 0; i < pool->base.res_cap->num_dsc; i++) {
		if (pool->base.dscs[i] != NULL)
			dcn20_dsc_destroy(&pool->base.dscs[i]);
	}

	if (pool->base.mpc != NULL) {
		kfree(TO_DCN20_MPC(pool->base.mpc));
		pool->base.mpc = NULL;
	}
	if (pool->base.hubbub != NULL) {
		kfree(pool->base.hubbub);
		pool->base.hubbub = NULL;
	}
	for (i = 0; i < pool->base.pipe_count; i++) {
		if (pool->base.dpps[i] != NULL)
			dcn301_dpp_destroy(&pool->base.dpps[i]);

		if (pool->base.ipps[i] != NULL)
			pool->base.ipps[i]->funcs->ipp_destroy(&pool->base.ipps[i]);

		if (pool->base.hubps[i] != NULL) {
			kfree(TO_DCN20_HUBP(pool->base.hubps[i]));
			pool->base.hubps[i] = NULL;
		}

		if (pool->base.irqs != NULL) {
			dal_irq_service_destroy(&pool->base.irqs);
		}
	}

	for (i = 0; i < pool->base.res_cap->num_ddc; i++) {
		if (pool->base.engines[i] != NULL)
			dce110_engine_destroy(&pool->base.engines[i]);
		if (pool->base.hw_i2cs[i] != NULL) {
			kfree(pool->base.hw_i2cs[i]);
			pool->base.hw_i2cs[i] = NULL;
		}
		if (pool->base.sw_i2cs[i] != NULL) {
			kfree(pool->base.sw_i2cs[i]);
			pool->base.sw_i2cs[i] = NULL;
		}
	}

	for (i = 0; i < pool->base.res_cap->num_opp; i++) {
		if (pool->base.opps[i] != NULL)
			pool->base.opps[i]->funcs->opp_destroy(&pool->base.opps[i]);
	}

	for (i = 0; i < pool->base.res_cap->num_timing_generator; i++) {
		if (pool->base.timing_generators[i] != NULL)	{
			kfree(DCN10TG_FROM_TG(pool->base.timing_generators[i]));
			pool->base.timing_generators[i] = NULL;
		}
	}

	for (i = 0; i < pool->base.res_cap->num_dwb; i++) {
		if (pool->base.dwbc[i] != NULL) {
			kfree(TO_DCN30_DWBC(pool->base.dwbc[i]));
			pool->base.dwbc[i] = NULL;
		}
		if (pool->base.mcif_wb[i] != NULL) {
			kfree(TO_DCN30_MMHUBBUB(pool->base.mcif_wb[i]));
			pool->base.mcif_wb[i] = NULL;
		}
	}

	for (i = 0; i < pool->base.audio_count; i++) {
		if (pool->base.audios[i])
			dce_aud_destroy(&pool->base.audios[i]);
	}

	for (i = 0; i < pool->base.clk_src_count; i++) {
		if (pool->base.clock_sources[i] != NULL) {
			dcn20_clock_source_destroy(&pool->base.clock_sources[i]);
			pool->base.clock_sources[i] = NULL;
		}
	}

	for (i = 0; i < pool->base.res_cap->num_mpc_3dlut; i++) {
		if (pool->base.mpc_lut[i] != NULL) {
			dc_3dlut_func_release(pool->base.mpc_lut[i]);
			pool->base.mpc_lut[i] = NULL;
		}
		if (pool->base.mpc_shaper[i] != NULL) {
			dc_transfer_func_release(pool->base.mpc_shaper[i]);
			pool->base.mpc_shaper[i] = NULL;
		}
	}

	if (pool->base.dp_clock_source != NULL) {
		dcn20_clock_source_destroy(&pool->base.dp_clock_source);
		pool->base.dp_clock_source = NULL;
	}

	/* destroy of dmub darkmode obj */
	if (pool->base.dkmd != NULL) {
		dmub_dkmd_destroy(&pool->base.dkmd);
		pr_debug("[DMUB_DKMD] DCN301 DMUB DKMD module destroyed\n");
	}

	if (pool->base.abm != NULL)
		dce_abm_destroy(&pool->base.abm);

	if (pool->base.dmcu != NULL)
		dce_dmcu_destroy(&pool->base.dmcu);

	if (pool->base.dccg != NULL)
		dcn_dccg_destroy(&pool->base.dccg);
}

struct hubp *dcn301_hubp_create(
	struct dc_context *ctx,
	uint32_t inst)
{
	struct dcn20_hubp *hubp2 =
		kzalloc(sizeof(struct dcn20_hubp), GFP_KERNEL);

	if (!hubp2)
		return NULL;

	if (hubp3_construct(hubp2, ctx, inst,
			&hubp_regs[inst], &hubp_shift, &hubp_mask))
		return &hubp2->base;

	BREAK_TO_DEBUGGER();
	kfree(hubp2);
	return NULL;
}

bool dcn301_dwbc_create(struct dc_context *ctx, struct resource_pool *pool)
{
	int i;
	uint32_t pipe_count = pool->res_cap->num_dwb;

	for (i = 0; i < pipe_count; i++) {
		struct dcn30_dwbc *dwbc30 = kzalloc(sizeof(struct dcn30_dwbc),
						    GFP_KERNEL);

		if (!dwbc30) {
			dm_error("DC: failed to create dwbc30!\n");
			return false;
		}

		dcn30_dwbc_construct(dwbc30, ctx,
				&dwbc30_regs[i],
				&dwbc30_shift,
				&dwbc30_mask,
				i);

		pool->dwbc[i] = &dwbc30->base;
	}
	return true;
}

bool dcn301_mmhubbub_create(struct dc_context *ctx, struct resource_pool *pool)
{
	int i;
	uint32_t pipe_count = pool->res_cap->num_dwb;

	for (i = 0; i < pipe_count; i++) {
		struct dcn30_mmhubbub *mcif_wb30 = kzalloc(sizeof(struct dcn30_mmhubbub),
						    GFP_KERNEL);

		if (!mcif_wb30) {
			dm_error("DC: failed to create mcif_wb30!\n");
			return false;
		}

		dcn30_mmhubbub_construct(mcif_wb30, ctx,
				&mcif_wb30_regs[i],
				&mcif_wb30_shift,
				&mcif_wb30_mask,
				i);

		pool->mcif_wb[i] = &mcif_wb30->base;
	}
	return true;
}

static struct display_stream_compressor *dcn301_dsc_create(
	struct dc_context *ctx, uint32_t inst)
{
	struct dcn20_dsc *dsc =
		kzalloc(sizeof(struct dcn20_dsc), GFP_KERNEL);

	if (!dsc) {
		BREAK_TO_DEBUGGER();
		return NULL;
	}

	dsc2_construct(dsc, ctx, inst, &dsc_regs[inst], &dsc_shift, &dsc_mask);
	return &dsc->base;
}


static void dcn301_destroy_resource_pool(struct resource_pool **pool)
{
	struct dcn301_resource_pool *dcn301_pool = TO_DCN301_RES_POOL(*pool);

	dcn301_destruct(dcn301_pool);
	kfree(dcn301_pool);
	*pool = NULL;
}

static struct clock_source *dcn301_clock_source_create(
		struct dc_context *ctx,
		struct dc_bios *bios,
		enum clock_source_id id,
		const struct dce110_clk_src_regs *regs,
		bool dp_clk_src)
{
	struct dce110_clk_src *clk_src =
		kzalloc(sizeof(struct dce110_clk_src), GFP_KERNEL);

	if (!clk_src)
		return NULL;

	if (dcn301_clk_src_construct(clk_src, ctx, bios, id,
			regs, &cs_shift, &cs_mask)) {
		clk_src->base.dp_clk_src = dp_clk_src;
		return &clk_src->base;
	}

	BREAK_TO_DEBUGGER();
	return NULL;
}

static struct dc_cap_funcs cap_funcs = {
	.get_dcc_compression_cap = dcn20_get_dcc_compression_cap
};

#define fixed16_to_double(x) (((double) x) / ((double) (1 << 16)))
#define fixed16_to_double_to_cpu(x) fixed16_to_double(le32_to_cpu(x))

static bool is_soc_bounding_box_valid(struct dc *dc)
{
	uint32_t hw_internal_rev = dc->ctx->asic_id.hw_internal_rev;

	if (ASICREV_IS_MERO(hw_internal_rev))
		return true;

	return false;
}

static bool init_soc_bounding_box(struct dc *dc,
				  struct dcn301_resource_pool *pool)
{
	const struct gpu_info_soc_bounding_box_v1_0 *bb = dc->soc_bounding_box;
	struct _vcs_dpi_soc_bounding_box_st *loaded_bb = &dcn3_01_soc;
	struct _vcs_dpi_ip_params_st *loaded_ip = &dcn3_01_ip;

	DC_LOGGER_INIT(dc->ctx->logger);

	if (!bb && !is_soc_bounding_box_valid(dc)) {
		DC_LOG_ERROR("%s: not valid soc bounding box/n", __func__);
		return false;
	}

	if (bb && !is_soc_bounding_box_valid(dc)) {
		int i;

		dcn3_01_soc.sr_exit_time_us =
				fixed16_to_double_to_cpu(bb->sr_exit_time_us);
		dcn3_01_soc.sr_enter_plus_exit_time_us =
				fixed16_to_double_to_cpu(bb->sr_enter_plus_exit_time_us);
		dcn3_01_soc.urgent_latency_us =
				fixed16_to_double_to_cpu(bb->urgent_latency_us);
		dcn3_01_soc.urgent_latency_pixel_data_only_us =
				fixed16_to_double_to_cpu(bb->urgent_latency_pixel_data_only_us);
		dcn3_01_soc.urgent_latency_pixel_mixed_with_vm_data_us =
				fixed16_to_double_to_cpu(bb->urgent_latency_pixel_mixed_with_vm_data_us);
		dcn3_01_soc.urgent_latency_vm_data_only_us =
				fixed16_to_double_to_cpu(bb->urgent_latency_vm_data_only_us);
		dcn3_01_soc.urgent_out_of_order_return_per_channel_pixel_only_bytes =
				le32_to_cpu(bb->urgent_out_of_order_return_per_channel_pixel_only_bytes);
		dcn3_01_soc.urgent_out_of_order_return_per_channel_pixel_and_vm_bytes =
				le32_to_cpu(bb->urgent_out_of_order_return_per_channel_pixel_and_vm_bytes);
		dcn3_01_soc.urgent_out_of_order_return_per_channel_vm_only_bytes =
				le32_to_cpu(bb->urgent_out_of_order_return_per_channel_vm_only_bytes);
		dcn3_01_soc.pct_ideal_dram_sdp_bw_after_urgent_pixel_only =
				fixed16_to_double_to_cpu(bb->pct_ideal_dram_sdp_bw_after_urgent_pixel_only);
		dcn3_01_soc.pct_ideal_dram_sdp_bw_after_urgent_pixel_and_vm =
				fixed16_to_double_to_cpu(bb->pct_ideal_dram_sdp_bw_after_urgent_pixel_and_vm);
		dcn3_01_soc.pct_ideal_dram_sdp_bw_after_urgent_vm_only =
				fixed16_to_double_to_cpu(bb->pct_ideal_dram_sdp_bw_after_urgent_vm_only);
		dcn3_01_soc.max_avg_sdp_bw_use_normal_percent =
				fixed16_to_double_to_cpu(bb->max_avg_sdp_bw_use_normal_percent);
		dcn3_01_soc.max_avg_dram_bw_use_normal_percent =
				fixed16_to_double_to_cpu(bb->max_avg_dram_bw_use_normal_percent);
		dcn3_01_soc.writeback_latency_us =
				fixed16_to_double_to_cpu(bb->writeback_latency_us);
		dcn3_01_soc.ideal_dram_bw_after_urgent_percent =
				fixed16_to_double_to_cpu(bb->ideal_dram_bw_after_urgent_percent);
		dcn3_01_soc.max_request_size_bytes =
				le32_to_cpu(bb->max_request_size_bytes);
		dcn3_01_soc.dram_channel_width_bytes =
				le32_to_cpu(bb->dram_channel_width_bytes);
		dcn3_01_soc.fabric_datapath_to_dcn_data_return_bytes =
				le32_to_cpu(bb->fabric_datapath_to_dcn_data_return_bytes);
		dcn3_01_soc.dcn_downspread_percent =
				fixed16_to_double_to_cpu(bb->dcn_downspread_percent);
		dcn3_01_soc.downspread_percent =
				fixed16_to_double_to_cpu(bb->downspread_percent);
		dcn3_01_soc.dram_page_open_time_ns =
				fixed16_to_double_to_cpu(bb->dram_page_open_time_ns);
		dcn3_01_soc.dram_rw_turnaround_time_ns =
				fixed16_to_double_to_cpu(bb->dram_rw_turnaround_time_ns);
		dcn3_01_soc.dram_return_buffer_per_channel_bytes =
				le32_to_cpu(bb->dram_return_buffer_per_channel_bytes);
		dcn3_01_soc.round_trip_ping_latency_dcfclk_cycles =
				le32_to_cpu(bb->round_trip_ping_latency_dcfclk_cycles);
		dcn3_01_soc.urgent_out_of_order_return_per_channel_bytes =
				le32_to_cpu(bb->urgent_out_of_order_return_per_channel_bytes);
		dcn3_01_soc.channel_interleave_bytes =
				le32_to_cpu(bb->channel_interleave_bytes);
		dcn3_01_soc.num_banks =
				le32_to_cpu(bb->num_banks);
		dcn3_01_soc.num_chans =
				le32_to_cpu(bb->num_chans);
		dcn3_01_soc.gpuvm_min_page_size_bytes =
				le32_to_cpu(bb->vmm_page_size_bytes);
		dcn3_01_soc.dram_clock_change_latency_us =
				fixed16_to_double_to_cpu(bb->dram_clock_change_latency_us);
		dcn3_01_soc.writeback_dram_clock_change_latency_us =
				fixed16_to_double_to_cpu(bb->writeback_dram_clock_change_latency_us);
		dcn3_01_soc.return_bus_width_bytes =
				le32_to_cpu(bb->return_bus_width_bytes);
		dcn3_01_soc.dispclk_dppclk_vco_speed_mhz =
				le32_to_cpu(bb->dispclk_dppclk_vco_speed_mhz);
		dcn3_01_soc.xfc_bus_transport_time_us =
				le32_to_cpu(bb->xfc_bus_transport_time_us);
		dcn3_01_soc.xfc_xbuf_latency_tolerance_us =
				le32_to_cpu(bb->xfc_xbuf_latency_tolerance_us);
		dcn3_01_soc.use_urgent_burst_bw =
				le32_to_cpu(bb->use_urgent_burst_bw);
		dcn3_01_soc.num_states =
				le32_to_cpu(bb->num_states);

		for (i = 0; i < dcn3_01_soc.num_states; i++) {
			dcn3_01_soc.clock_limits[i].state =
					le32_to_cpu(bb->clock_limits[i].state);
			dcn3_01_soc.clock_limits[i].dcfclk_mhz =
					fixed16_to_double_to_cpu(bb->clock_limits[i].dcfclk_mhz);
			dcn3_01_soc.clock_limits[i].fabricclk_mhz =
					fixed16_to_double_to_cpu(bb->clock_limits[i].fabricclk_mhz);
			dcn3_01_soc.clock_limits[i].dispclk_mhz =
					fixed16_to_double_to_cpu(bb->clock_limits[i].dispclk_mhz);
			dcn3_01_soc.clock_limits[i].dppclk_mhz =
					fixed16_to_double_to_cpu(bb->clock_limits[i].dppclk_mhz);
			dcn3_01_soc.clock_limits[i].phyclk_mhz =
					fixed16_to_double_to_cpu(bb->clock_limits[i].phyclk_mhz);
			dcn3_01_soc.clock_limits[i].socclk_mhz =
					fixed16_to_double_to_cpu(bb->clock_limits[i].socclk_mhz);
			dcn3_01_soc.clock_limits[i].dscclk_mhz =
					fixed16_to_double_to_cpu(bb->clock_limits[i].dscclk_mhz);
			dcn3_01_soc.clock_limits[i].dram_speed_mts =
					fixed16_to_double_to_cpu(bb->clock_limits[i].dram_speed_mts);
		}
	}

	loaded_ip->max_num_otg = pool->base.res_cap->num_timing_generator;
	loaded_ip->max_num_dpp = pool->base.pipe_count;
	dcn20_patch_bounding_box(dc, loaded_bb);

	if (!bb && dc->ctx->dc_bios->funcs->get_soc_bb_info) {
		struct bp_soc_bb_info bb_info = {0};

		if (dc->ctx->dc_bios->funcs->get_soc_bb_info(dc->ctx->dc_bios, &bb_info) == BP_RESULT_OK) {
			if (bb_info.dram_clock_change_latency_100ns > 0)
				dcn3_01_soc.dram_clock_change_latency_us = bb_info.dram_clock_change_latency_100ns * 10;

			if (bb_info.dram_sr_enter_exit_latency_100ns > 0)
				dcn3_01_soc.sr_enter_plus_exit_time_us = bb_info.dram_sr_enter_exit_latency_100ns * 10;

			if (bb_info.dram_sr_exit_latency_100ns > 0)
				dcn3_01_soc.sr_exit_time_us = bb_info.dram_sr_exit_latency_100ns * 10;
		}
	}

	return true;
}

static void dcn301_update_bw_bounding_box(struct dc *dc, struct clk_bw_params *bw_params)
{
	struct dcn301_resource_pool *pool = TO_DCN301_RES_POOL(dc->res_pool);
	struct clk_limit_table *clk_table = &bw_params->clk_table;
	struct _vcs_dpi_voltage_scaling_st clock_limits[DC__VOLTAGE_STATES];
	unsigned int i, closest_clk_lvl;
	int j;

	DC_FP_START();

	// Default clock levels are used for diags, which may lead to overclocking.
	if (!IS_DIAG_DC(dc->ctx->dce_environment)) {
		dcn3_01_ip.max_num_otg = pool->base.res_cap->num_timing_generator;
		dcn3_01_ip.max_num_dpp = pool->base.pipe_count;
		dcn3_01_soc.num_chans = bw_params->num_channels;

		ASSERT(clk_table->num_entries);
		for (i = 0; i < clk_table->num_entries; i++) {
			/* loop backwards*/
			for (closest_clk_lvl = 0, j = dcn3_01_soc.num_states - 1; j >= 0; j--) {
				if ((unsigned int) dcn3_01_soc.clock_limits[j].dcfclk_mhz <=
				    clk_table->entries[i].dcfclk_mhz) {
					closest_clk_lvl = j;
					break;
				}
			}

			clock_limits[i].state = i;
			clock_limits[i].dcfclk_mhz = clk_table->entries[i].dcfclk_mhz;
			clock_limits[i].fabricclk_mhz = clk_table->entries[i].fclk_mhz;
			clock_limits[i].socclk_mhz = clk_table->entries[i].socclk_mhz;
			clock_limits[i].dram_speed_mts = clk_table->entries[i].memclk_mhz * 2;

			clock_limits[i].dispclk_mhz = dcn3_01_soc.clock_limits[closest_clk_lvl].dispclk_mhz;
			clock_limits[i].dppclk_mhz = dcn3_01_soc.clock_limits[closest_clk_lvl].dppclk_mhz;
			clock_limits[i].dram_bw_per_chan_gbps =
				dcn3_01_soc.clock_limits[closest_clk_lvl].dram_bw_per_chan_gbps;
			clock_limits[i].dscclk_mhz = dcn3_01_soc.clock_limits[closest_clk_lvl].dscclk_mhz;
			clock_limits[i].dtbclk_mhz = dcn3_01_soc.clock_limits[closest_clk_lvl].dtbclk_mhz;
			clock_limits[i].phyclk_d18_mhz = dcn3_01_soc.clock_limits[closest_clk_lvl].phyclk_d18_mhz;
			clock_limits[i].phyclk_mhz = dcn3_01_soc.clock_limits[closest_clk_lvl].phyclk_mhz;
		}
		for (i = 0; i < clk_table->num_entries; i++)
			dcn3_01_soc.clock_limits[i] = clock_limits[i];
		if (clk_table->num_entries) {
			dcn3_01_soc.num_states = clk_table->num_entries;
			/* duplicate last level */
			dcn3_01_soc.clock_limits[dcn3_01_soc.num_states] =
				dcn3_01_soc.clock_limits[dcn3_01_soc.num_states - 1];
			dcn3_01_soc.clock_limits[dcn3_01_soc.num_states].state = dcn3_01_soc.num_states;
		}
	}

	dcn3_01_soc.dispclk_dppclk_vco_speed_mhz = dc->clk_mgr->dentist_vco_freq_khz / 1000.0;
	dc->dml.soc.dispclk_dppclk_vco_speed_mhz = dc->clk_mgr->dentist_vco_freq_khz / 1000.0;

	DC_FP_END();

	dml_init_instance(&dc->dml, &dcn3_01_soc, &dcn3_01_ip, DML_PROJECT_DCN30);
}

static void calculate_wm_set_for_vlevel(
		int vlevel,
		struct wm_range_table_entry *table_entry,
		struct dcn_watermarks *wm_set,
		struct display_mode_lib *dml,
		display_e2e_pipe_params_st *pipes,
		int pipe_cnt)
{
	double dram_clock_change_latency_cached = dml->soc.dram_clock_change_latency_us;

	ASSERT(vlevel < dml->soc.num_states);
	/* only pipe 0 is read for voltage and dcf/soc clocks */
	pipes[0].clks_cfg.voltage = vlevel;
	pipes[0].clks_cfg.dcfclk_mhz = dml->soc.clock_limits[vlevel].dcfclk_mhz;
	pipes[0].clks_cfg.socclk_mhz = dml->soc.clock_limits[vlevel].socclk_mhz;

	dml->soc.dram_clock_change_latency_us = table_entry->pstate_latency_us;
	dml->soc.sr_exit_time_us = table_entry->sr_exit_time_us;
	dml->soc.sr_enter_plus_exit_time_us = table_entry->sr_enter_plus_exit_time_us;

	DC_FP_START();
	wm_set->urgent_ns = get_wm_urgent(dml, pipes, pipe_cnt) * 1000;
	wm_set->cstate_pstate.cstate_enter_plus_exit_ns = get_wm_stutter_enter_exit(dml, pipes, pipe_cnt) * 1000;
	wm_set->cstate_pstate.cstate_exit_ns = get_wm_stutter_exit(dml, pipes, pipe_cnt) * 1000;
	wm_set->cstate_pstate.pstate_change_ns = get_wm_dram_clock_change(dml, pipes, pipe_cnt) * 1000;
	wm_set->pte_meta_urgent_ns = get_wm_memory_trip(dml, pipes, pipe_cnt) * 1000;
	wm_set->frac_urg_bw_nom = get_fraction_of_urgent_bandwidth(dml, pipes, pipe_cnt) * 1000;
	wm_set->frac_urg_bw_flip = get_fraction_of_urgent_bandwidth_imm_flip(dml, pipes, pipe_cnt) * 1000;
	wm_set->urgent_latency_ns = get_urgent_latency(dml, pipes, pipe_cnt) * 1000;
	dml->soc.dram_clock_change_latency_us = dram_clock_change_latency_cached;
	DC_FP_END();
}

static void dcn301_calculate_wm(
		struct dc *dc, struct dc_state *context,
		display_e2e_pipe_params_st *pipes,
		int pipe_cnt,
		int vlevel_req)
{
	int i, pipe_idx;
	int vlevel, vlevel_max;
	struct wm_range_table_entry *table_entry;
	struct clk_bw_params *bw_params = dc->clk_mgr->bw_params;

	ASSERT(bw_params);

	DC_FP_START();

	vlevel_max = bw_params->clk_table.num_entries - 1;

	/* WM Set D */
	table_entry = &bw_params->wm_table.entries[WM_D];
	if (table_entry->wm_type == WM_TYPE_RETRAINING)
		vlevel = 0;
	else
		vlevel = vlevel_max;
	calculate_wm_set_for_vlevel(vlevel, table_entry, &context->bw_ctx.bw.dcn.watermarks.d,
						&context->bw_ctx.dml, pipes, pipe_cnt);
	/* WM Set C */
	table_entry = &bw_params->wm_table.entries[WM_C];
	vlevel = min(max(vlevel_req, 2), vlevel_max);
	calculate_wm_set_for_vlevel(vlevel, table_entry, &context->bw_ctx.bw.dcn.watermarks.c,
						&context->bw_ctx.dml, pipes, pipe_cnt);
	/* WM Set B */
	table_entry = &bw_params->wm_table.entries[WM_B];
	vlevel = min(max(vlevel_req, 1), vlevel_max);
	calculate_wm_set_for_vlevel(vlevel, table_entry, &context->bw_ctx.bw.dcn.watermarks.b,
						&context->bw_ctx.dml, pipes, pipe_cnt);

	/* WM Set A */
	table_entry = &bw_params->wm_table.entries[WM_A];
	vlevel = min(vlevel_req, vlevel_max);
	calculate_wm_set_for_vlevel(vlevel, table_entry, &context->bw_ctx.bw.dcn.watermarks.a,
						&context->bw_ctx.dml, pipes, pipe_cnt);

	for (i = 0, pipe_idx = 0; i < dc->res_pool->pipe_count; i++) {
		if (!context->res_ctx.pipe_ctx[i].stream)
			continue;

		pipes[pipe_idx].clks_cfg.dispclk_mhz = get_dispclk_calculated(&context->bw_ctx.dml, pipes, pipe_cnt);
		pipes[pipe_idx].clks_cfg.dppclk_mhz = get_dppclk_calculated(&context->bw_ctx.dml, pipes, pipe_cnt, pipe_idx);

		if (dc->config.forced_clocks) {
			pipes[pipe_idx].clks_cfg.dispclk_mhz = context->bw_ctx.dml.soc.clock_limits[0].dispclk_mhz;
			pipes[pipe_idx].clks_cfg.dppclk_mhz = context->bw_ctx.dml.soc.clock_limits[0].dppclk_mhz;
		}
		if (dc->debug.min_disp_clk_khz > pipes[pipe_idx].clks_cfg.dispclk_mhz * 1000)
			pipes[pipe_idx].clks_cfg.dispclk_mhz = dc->debug.min_disp_clk_khz / 1000.0;
		if (dc->debug.min_dpp_clk_khz > pipes[pipe_idx].clks_cfg.dppclk_mhz * 1000)
			pipes[pipe_idx].clks_cfg.dppclk_mhz = dc->debug.min_dpp_clk_khz / 1000.0;

		pipe_idx++;
	}

	DC_FP_END();
}

static struct resource_funcs dcn301_res_pool_funcs = {
	.destroy = dcn301_destroy_resource_pool,
	.link_enc_create = dcn301_link_encoder_create,
	.validate_bandwidth = dcn30_validate_bandwidth,
	.calculate_wm = dcn301_calculate_wm,
	.populate_dml_pipes = dcn30_populate_dml_pipes_from_context,
	.acquire_idle_pipe_for_layer = dcn20_acquire_idle_pipe_for_layer,
	.add_stream_to_ctx = dcn30_add_stream_to_ctx,
	.remove_stream_from_ctx = dcn20_remove_stream_from_ctx,
	.populate_dml_writeback_from_context = dcn30_populate_dml_writeback_from_context,
	.set_mcif_arb_params = dcn30_set_mcif_arb_params,
	.find_first_free_match_stream_enc_for_link = dcn10_find_first_free_match_stream_enc_for_link,
	.acquire_post_bldn_3dlut = dcn30_acquire_post_bldn_3dlut,
	.release_post_bldn_3dlut = dcn30_release_post_bldn_3dlut,
	.update_bw_bounding_box = dcn301_update_bw_bounding_box
};

static bool dcn301_resource_construct(
	uint8_t num_virtual_links,
	struct dc *dc,
	struct dcn301_resource_pool *pool)
{
	int i, j;
	struct dc_context *ctx = dc->ctx;
	struct irq_service_init_data init_data;
	uint32_t pipe_fuses = read_pipe_fuses(ctx);
	uint32_t num_pipes = 0;

	DC_FP_START();

	ctx->dc_bios->regs = &bios_regs;

	pool->base.res_cap = &res_cap_dcn301;

	pool->base.funcs = &dcn301_res_pool_funcs;

	/*************************************************
	 *  Resource + asic cap harcoding                *
	 *************************************************/

	/* Our code currently assumes we have the same TGs as OPPs */
	ASSERT(pool->base.res_cap->num_timing_generator == pool->base.res_cap->num_opp &&
	       pool->base.res_cap->num_timing_generator == dcn3_01_ip.max_num_otg &&
	       dcn3_01_ip.max_num_dpp == dcn3_01_ip.max_num_otg);

	pool->base.underlay_pipe_index = NO_UNDERLAY_PIPE;
	pool->base.pipe_count = pool->base.res_cap->num_timing_generator;
	pool->base.mpcc_count = pool->base.res_cap->num_timing_generator;
	dc->caps.max_downscale_ratio = 600;
	dc->caps.i2c_speed_in_khz = 100;
	dc->caps.max_cursor_size = 256;
	dc->caps.dmdata_alloc_size = 2048;
	dc->caps.max_slave_planes = 1;
	dc->caps.is_apu = true;
	dc->caps.post_blend_color_processing = true;
	dc->caps.force_dp_tps4_for_cp2520 = true;
	dc->caps.extended_aux_timeout_support = true;
#ifdef CONFIG_DRM_AMD_DC_DMUB
	dc->caps.dmcub_support = true;
#endif

	/* Color pipeline capabilities */
	dc->caps.color.dpp.dcn_arch = 1;
	dc->caps.color.dpp.input_lut_shared = 0;
	dc->caps.color.dpp.icsc = 1;
	dc->caps.color.dpp.dgam_ram = 0; // must use gamma_corr
	dc->caps.color.dpp.dgam_rom_caps.srgb = 1;
	dc->caps.color.dpp.dgam_rom_caps.bt2020 = 1;
	dc->caps.color.dpp.dgam_rom_caps.gamma2_2 = 1;
	dc->caps.color.dpp.dgam_rom_caps.pq = 1;
	dc->caps.color.dpp.dgam_rom_caps.hlg = 1;
	dc->caps.color.dpp.post_csc = 1;
	dc->caps.color.dpp.gamma_corr = 1;

	dc->caps.color.dpp.hw_3d_lut = 1;
	dc->caps.color.dpp.ogam_ram = 1;
	// no OGAM ROM on DCN301
	dc->caps.color.dpp.ogam_rom_caps.srgb = 0;
	dc->caps.color.dpp.ogam_rom_caps.bt2020 = 0;
	dc->caps.color.dpp.ogam_rom_caps.gamma2_2 = 0;
	dc->caps.color.dpp.ogam_rom_caps.pq = 0;
	dc->caps.color.dpp.ogam_rom_caps.hlg = 0;
	dc->caps.color.dpp.ocsc = 0;

	dc->caps.color.mpc.gamut_remap = 1;
	dc->caps.color.mpc.num_3dluts = pool->base.res_cap->num_mpc_3dlut; //2
	dc->caps.color.mpc.ogam_ram = 1;
	dc->caps.color.mpc.ogam_rom_caps.srgb = 0;
	dc->caps.color.mpc.ogam_rom_caps.bt2020 = 0;
	dc->caps.color.mpc.ogam_rom_caps.gamma2_2 = 0;
	dc->caps.color.mpc.ogam_rom_caps.pq = 0;
	dc->caps.color.mpc.ogam_rom_caps.hlg = 0;
	dc->caps.color.mpc.ocsc = 1;

	if (dc->ctx->dce_environment == DCE_ENV_PRODUCTION_DRV)
		dc->debug = debug_defaults_drv;
	else if (dc->ctx->dce_environment == DCE_ENV_FPGA_MAXIMUS) {
		dc->debug = debug_defaults_diags;
	} else
		dc->debug = debug_defaults_diags;
	// Init the vm_helper
	if (dc->vm_helper)
		vm_helper_init(dc->vm_helper, 16);

	/*************************************************
	 *  Create resources                             *
	 *************************************************/

	/* Clock Sources for Pixel Clock*/
	pool->base.clock_sources[DCN301_CLK_SRC_PLL0] =
			dcn301_clock_source_create(ctx, ctx->dc_bios,
				CLOCK_SOURCE_COMBO_PHY_PLL0,
				&clk_src_regs[0], false);
	pool->base.clock_sources[DCN301_CLK_SRC_PLL1] =
			dcn301_clock_source_create(ctx, ctx->dc_bios,
				CLOCK_SOURCE_COMBO_PHY_PLL1,
				&clk_src_regs[1], false);
	pool->base.clock_sources[DCN301_CLK_SRC_PLL2] =
			dcn301_clock_source_create(ctx, ctx->dc_bios,
				CLOCK_SOURCE_COMBO_PHY_PLL2,
				&clk_src_regs[2], false);
	pool->base.clock_sources[DCN301_CLK_SRC_PLL3] =
			dcn301_clock_source_create(ctx, ctx->dc_bios,
				CLOCK_SOURCE_COMBO_PHY_PLL3,
				&clk_src_regs[3], false);

	pool->base.clk_src_count = DCN301_CLK_SRC_TOTAL;

	/* todo: not reuse phy_pll registers */
	pool->base.dp_clock_source =
			dcn301_clock_source_create(ctx, ctx->dc_bios,
				CLOCK_SOURCE_ID_DP_DTO,
				&clk_src_regs[0], true);

	for (i = 0; i < pool->base.clk_src_count; i++) {
		if (pool->base.clock_sources[i] == NULL) {
			dm_error("DC: failed to create clock sources!\n");
			BREAK_TO_DEBUGGER();
			goto create_fail;
		}
	}

	/* DCCG */
	pool->base.dccg = dccg301_create(ctx, &dccg_regs, &dccg_shift, &dccg_mask);
	if (pool->base.dccg == NULL) {
		dm_error("DC: failed to create dccg!\n");
		BREAK_TO_DEBUGGER();
		goto create_fail;
	}

	init_soc_bounding_box(dc, pool);

	num_pipes = dcn3_01_ip.max_num_dpp;

	for (i = 0; i < dcn3_01_ip.max_num_dpp; i++)
		if (pipe_fuses & 1 << i)
			num_pipes--;
	dcn3_01_ip.max_num_dpp = num_pipes;
	dcn3_01_ip.max_num_otg = num_pipes;


	dml_init_instance(&dc->dml, &dcn3_01_soc, &dcn3_01_ip, DML_PROJECT_DCN30);

	/* IRQ */
	init_data.ctx = dc->ctx;
	pool->base.irqs = dal_irq_service_dcn30_create(&init_data);
	if (!pool->base.irqs)
		goto create_fail;

	/* HUBBUB */
	pool->base.hubbub = dcn301_hubbub_create(ctx);
	if (pool->base.hubbub == NULL) {
		BREAK_TO_DEBUGGER();
		dm_error("DC: failed to create hubbub!\n");
		goto create_fail;
	}

	j = 0;
	/* HUBPs, DPPs, OPPs and TGs */
	for (i = 0; i < pool->base.pipe_count; i++) {

		/* if pipe is disabled, skip instance of HW pipe,
		 * i.e, skip ASIC register instance
		 */
		if ((pipe_fuses & (1 << i)) != 0) {
			DC_LOG_DEBUG("%s: fusing pipe %d\n", __func__, i);
			continue;
		}

		pool->base.hubps[j] = dcn301_hubp_create(ctx, i);
		if (pool->base.hubps[j] == NULL) {
			BREAK_TO_DEBUGGER();
			dm_error(
				"DC: failed to create hubps!\n");
			goto create_fail;
		}

		pool->base.dpps[j] = dcn301_dpp_create(ctx, i);
		if (pool->base.dpps[j] == NULL) {
			BREAK_TO_DEBUGGER();
			dm_error(
				"DC: failed to create dpps!\n");
			goto create_fail;
		}

		pool->base.opps[j] = dcn301_opp_create(ctx, i);
		if (pool->base.opps[j] == NULL) {
			BREAK_TO_DEBUGGER();
			dm_error(
				"DC: failed to create output pixel processor!\n");
			goto create_fail;
		}

		pool->base.timing_generators[j] = dcn301_timing_generator_create(ctx, i);
		if (pool->base.timing_generators[j] == NULL) {
			BREAK_TO_DEBUGGER();
			dm_error("DC: failed to create tg!\n");
			goto create_fail;
		}
		j++;
	}
	pool->base.timing_generator_count = j;
	pool->base.pipe_count = j;
	pool->base.mpcc_count = j;

	/* ABM (or ABMs for NV2x) */
	/* TODO: */
//	pool->base.abm = dce_abm_create(ctx,
//			&abm_regs,
//			&abm_shift,
//			&abm_mask);
//	if (pool->base.abm == NULL) {
//		dm_error("DC: failed to create abm!\n");
//		BREAK_TO_DEBUGGER();
//		goto create_fail;
//	}

	/* DMUB-Darkmode for DCN301 */
	pool->base.dkmd = dmub_dkmd_create(ctx);

	if (!pool->base.dkmd) {
		dm_error("DC: failed to create dmub dark-mode obj!\n");
		BREAK_TO_DEBUGGER();
		goto create_fail;
	}
	pr_debug("[DMUB_DKMD] DCN301 DMUB DKMD module created.\n");

	/* MPC and DSC */
	pool->base.mpc = dcn301_mpc_create(ctx, pool->base.mpcc_count, pool->base.res_cap->num_mpc_3dlut);
	if (pool->base.mpc == NULL) {
		BREAK_TO_DEBUGGER();
		dm_error("DC: failed to create mpc!\n");
		goto create_fail;
	}

	for (i = 0; i < pool->base.res_cap->num_dsc; i++) {
		pool->base.dscs[i] = dcn301_dsc_create(ctx, i);
		if (pool->base.dscs[i] == NULL) {
			BREAK_TO_DEBUGGER();
			dm_error("DC: failed to create display stream compressor %d!\n", i);
			goto create_fail;
		}
	}

	/* DWB and MMHUBBUB */
	if (!dcn301_dwbc_create(ctx, &pool->base)) {
		BREAK_TO_DEBUGGER();
		dm_error("DC: failed to create dwbc!\n");
		goto create_fail;
	}

	if (!dcn301_mmhubbub_create(ctx, &pool->base)) {
		BREAK_TO_DEBUGGER();
		dm_error("DC: failed to create mcif_wb!\n");
		goto create_fail;
	}

	/* AUX and I2C */
	for (i = 0; i < pool->base.res_cap->num_ddc; i++) {
		pool->base.engines[i] = dcn301_aux_engine_create(ctx, i);
		if (pool->base.engines[i] == NULL) {
			BREAK_TO_DEBUGGER();
			dm_error(
				"DC:failed to create aux engine!!\n");
			goto create_fail;
		}
		pool->base.hw_i2cs[i] = dcn301_i2c_hw_create(ctx, i);
		if (pool->base.hw_i2cs[i] == NULL) {
			BREAK_TO_DEBUGGER();
			dm_error(
				"DC:failed to create hw i2c!!\n");
			goto create_fail;
		}
		pool->base.sw_i2cs[i] = NULL;
	}

	/* Audio, Stream Encoders including HPO and virtual, MPC 3D LUTs */
	if (!resource_construct(num_virtual_links, dc, &pool->base,
			(!IS_FPGA_MAXIMUS_DC(dc->ctx->dce_environment) ?
			&res_create_funcs : &res_create_maximus_funcs)))
			goto create_fail;

	/* HW Sequencer and Plane caps */
	dcn301_hw_sequencer_construct(dc);

	dc->caps.max_planes =  pool->base.pipe_count;

	for (i = 0; i < dc->caps.max_planes; ++i)
		dc->caps.planes[i] = plane_cap;

	dc->cap_funcs = cap_funcs;

	DC_FP_END();

	return true;

create_fail:

	dcn301_destruct(pool);

	DC_FP_END();

	return false;
}

struct resource_pool *dcn301_create_resource_pool(
		const struct dc_init_data *init_data,
		struct dc *dc)
{
	struct dcn301_resource_pool *pool =
		kzalloc(sizeof(struct dcn301_resource_pool), GFP_KERNEL);

	if (!pool)
		return NULL;

	if (dcn301_resource_construct(init_data->num_virtual_links, dc, pool))
		return &pool->base;

	BREAK_TO_DEBUGGER();
	kfree(pool);
	return NULL;
}
