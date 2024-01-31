/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Shared structure definitions between nova and cvip.
 *
 * Copyright (C) 2022 Magic Leap, Inc. All rights reserved.
 */
#ifndef __CVIP_NOVA_COMMON_H__
#define __CVIP_NOVA_COMMON_H__

/* keep in sync with enum in nova repo in cvip.c */
enum cvip_buffer_type {
	shared,
	x86,
	mlnet,
	dump,
};

#endif
