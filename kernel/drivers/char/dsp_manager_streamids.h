/* SPDX-License-Identifier: GPL-2.0
 *
 * (C) Copyright 2022
 * Magic Leap, Inc. (COMPANY)
 */

#ifndef _DSP_MANAGER_STREAMIDS_H
#define _DSP_MANAGER_STREAMIDS_H


/* Changes to this file, specifically related to DSP_MAX_NUM_STREAM_IDS
 * and CVCORE_DSP_STREAM_IDS, must be reflected in the user API file
 * cvcore_stream_ids.h located in the common drivers directory and the
 * file located at kernel/cvip/include/mero_smmu_private.h
 */

#define TOTAL_NR_OF_STREAM_IDS	(24)

static const uint16_t cvcore_stream_ids[TOTAL_NR_OF_STREAM_IDS] = {
	0x0,
	0x100,
	0x101,
	0x102,
	0x103,
	0x104,
	0x105,
	0x106,
	0x107,
	0x108,
	0x109,
	0x7,
	0x8000,
	0x8001,
	0x8002,
	0x8003,
	0x8004,
	0x8005,
	0x8006,
	0x8007,
	0x8008,
	0x800C,
	0x800D,
	0x800E
};

#endif
