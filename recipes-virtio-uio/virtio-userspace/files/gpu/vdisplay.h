/*
 * Copyright (C) 2022 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Vistual Display for VMs
 *
 */

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

#ifndef _VDISPLAY_H_
#define _VDISPLAY_H_

#include <stdbool.h>
#include <sys/queue.h>
#include <SDL2/SDL.h>
#include <SDL2/SDL_syswm.h>
#include <EGL/egl.h>
#include <pixman-1/pixman.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include "timer.h"
#include "virtio_host_gpu_cfg.h"

typedef void (*bh_task_func)(void *data);

/* bh task is still pending */
#define ACRN_BH_PENDING (1 << 0)
/* bh task is done */
#define ACRN_BH_DONE	(1 << 1)
/* free vdpy_display_bh after executing bh_cb */
#define ACRN_BH_FREE    (1 << 2)

#define VDPY_MAX_WIDTH 1920
#define VDPY_MAX_HEIGHT 1080
#define VDPY_DEFAULT_WIDTH 1024
#define VDPY_DEFAULT_HEIGHT 768
#define VDPY_MIN_WIDTH 640
#define VDPY_MIN_HEIGHT 480

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

struct state {
        bool is_ui_realized;
        bool is_active;
        bool is_wayland;
        bool is_x11;
        bool is_fullscreen;
        uint64_t updates;
        int n_connect;
};

struct egl_display_ops {
        PFNEGLCREATEIMAGEKHRPROC eglCreateImageKHR;
        PFNEGLDESTROYIMAGEKHRPROC eglDestroyImageKHR;
        PFNGLEGLIMAGETARGETTEXTURE2DOESPROC glEGLImageTargetTexture2DOES;
};

#ifdef INCLUDE_VIRGLRENDERER_SUPPORT
typedef struct v_dma_buf {
    int       fd;
    uint32_t  x;
    uint32_t  y;
    uint32_t  width;
    uint32_t  height;
#if 0
    uint32_t  stride;
    uint32_t  fourcc;
    uint64_t  modifier;
    uint32_t  texture;
    uint32_t  backing_width;
    uint32_t  backing_height;
    bool      y0_top;
    void      *sync;
    int       fence_fd;
    bool      allow_fences;
    bool      draw_submitted;
#endif
} VDmaBuf;

typedef struct egl_fb {
    int w;
    int h;
    GLuint tex;
    GLuint framebuffer;
    bool delete_tex;
    VDmaBuf *dmabuf;
} EGL_FB;
#endif

struct vscreen {
        struct display_info info;
        int pscreen_id;
        SDL_Rect pscreen_rect;
        bool is_fullscreen;
        int org_x;
        int org_y;
        int width;
        int height;
        int guest_width;
        int guest_height;
        uint32_t channelId;
        struct surface surf;
        struct cursor cur;
        SDL_Texture *surf_tex;
        SDL_Texture *cur_tex;
        SDL_Texture *bogus_tex;
        int surf_updates;
        int cur_updates;
        SDL_Window *win;
        SDL_Renderer *renderer;
        pixman_image_t *img;
        EGLImage egl_img;
        /* Record the update_time that is activated from guest_vm */
        struct timespec last_time;
#ifdef INCLUDE_VIRGLRENDERER_SUPPORT
        SDL_GLContext winctx;
        int x, y, w, h;
        EGL_FB guest_fb;
        EGL_FB win_fb;
        bool flag_y_0_top;
#endif
};

struct display {
        struct state s;
        struct vscreen *vscrs;
        int vscrs_num;
        pthread_t tid;
        /* Add one UI_timer(33ms) to render the buffers from guest_vm */
        struct acrn_timer ui_timer;
        struct vdpy_display_bh ui_timer_bh;
        // protect the request_list
        pthread_mutex_t vdisplay_mutex;
        // receive the signal that request is submitted
        pthread_cond_t  vdisplay_signal;
        TAILQ_HEAD(display_list, vdpy_display_bh) request_list;
        /* add the below two fields for calling eglAPI directly */
        bool egl_dmabuf_supported;
        SDL_GLContext eglContext;
        EGLDisplay eglDisplay;
        struct egl_display_ops gl_ops;
};

int pthread_setname_np(pthread_t *thread, const char *name);
int pthread_getname_np(pthread_t *thread,
                       const char *name, size_t len);
char *strcasestr(const char *haystack, const char *needle);

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

#ifdef INCLUDE_VIRGLRENDERER_SUPPORT
struct display *vdisplay(void);
void vdpy_gl_scanout_disable(int handle, int scanout_id);
void vdpy_gl_scanout_tex_setup(int handle,
                               int scanout_id,
                               uint32_t tex_id,
                               bool flag_y_0_top,
                               uint32_t width,
                               uint32_t height,
                               uint32_t x, uint32_t y,
                               uint32_t w, uint32_t h);
void vdpy_egl_scanout_flush(int handle,
                            int scanout_id,
                            uint32_t x0,
                            uint32_t y0,
                            uint32_t w0,
                            uint32_t h0);
#endif /* INCLUDE_VIRGLRENDERER_SUPPORT */

#endif /* _VDISPLAY_H_ */
