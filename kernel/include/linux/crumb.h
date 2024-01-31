/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Headers for crumb logging.
 *
 * Copyright (C) 2022 Magic Leap, Inc. All rights reserved.
 */
#ifndef _CRUMB_H
#define _CRUMB_H

extern void __init crumb_log_mem_map_early_pages(void);
extern void __init crumb_log_mem_unmap_early_pages(void *addr);
extern void __init crumb_log_remap_memories(void);

#endif
