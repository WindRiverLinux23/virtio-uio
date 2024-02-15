/*
 * Copyright (c) 2024, Wind River Systems, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * Vistual Display for VMs
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/*
modification history
--------------------
28jan24,qsn  ported from ACRN project
*/

#ifndef _VDISPLAY_H_
#define _VDISPLAY_H_

#include <stdbool.h>
#include <sys/queue.h>
#include <pixman-1/pixman.h>

typedef void (*bh_task_func)(void *data);

/* bh task is still pending */
#define ACRN_BH_PENDING (1 << 0)
/* bh task is done */
#define ACRN_BH_DONE	(1 << 1)
/* free vdpy_display_bh after executing bh_cb */
#define ACRN_BH_FREE    (1 << 2)

struct vdpy_display_bh {
	TAILQ_ENTRY(vdpy_display_bh) link;
	bh_task_func task_cb;
	void *data;
	uint32_t bh_flag;
};

struct edid_info {
	char *vendor;
	char *name;
	char *sn;
	uint32_t prefx;
	uint32_t prefy;
	uint32_t maxx;
	uint32_t maxy;
	uint32_t refresh_rate;
};

struct display_info {
	/* geometry */
	int xoff;
	int yoff;
	uint32_t width;
	uint32_t height;
};

enum surface_type {
	SURFACE_PIXMAN = 1,
	SURFACE_DMABUF,
};

struct surface {
	enum surface_type surf_type;
	/* use pixman_format as the intermediate-format */
	pixman_format_code_t surf_format;
	uint32_t x;
	uint32_t y;
	uint32_t width;
	uint32_t height;
	uint32_t bpp;
	uint32_t stride;
	void *pixel;
	struct  {
		int dmabuf_fd;
		uint32_t surf_fourcc;
		uint32_t dmabuf_offset;
	} dma_info;
};

struct cursor {
	enum surface_type surf_type;
	/* use pixman_format as the intermediate-format */
	pixman_format_code_t surf_format;
	uint32_t x;
	uint32_t y;
	uint32_t hot_x;
	uint32_t hot_y;
	uint32_t width;
	uint32_t height;
	void *data;
};

int vdpy_parse_cmd_option(const char *opts, uint32_t channelId);
int gfx_ui_init(char *dispMode, uint32_t channelId);
int vdpy_init(int *num_vscreens);
int vdpy_get_display_info(int handle, int scanout_id, uint32_t channelId, struct display_info *info);
void vdpy_surface_set(int handle, int scanout_id, struct surface *surf);
void vdpy_surface_update(int handle, int scanout_id, struct surface *surf);
bool vdpy_submit_bh(int handle, struct vdpy_display_bh *bh);
void vdpy_get_edid(int handle, int scanout_id, uint8_t *edid, size_t size);
void vdpy_cursor_define(int handle, int scanout_id, struct cursor *cur);
void vdpy_cursor_move(int handle, int scanout_id, uint32_t x, uint32_t y);
int vdpy_deinit(int handle);
bool vdpy_blob_support(void);
void gfx_ui_deinit();
void *vdpy_create_context(void *opaque, int scanout_idx,
                          int major_ver, int minor_ver);
void vdpy_destroy_context(void *opaque, void *ctx);
int  vdpy_make_context_current(void *opaque, int scanout_idx, void *ctx);

#endif /* _VDISPLAY_H_ */
