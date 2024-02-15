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

#include <stdlib.h>
#include <string.h>
#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include "vdisplay.h"
#include "../virtioHostLib.h"
#include "virtio_host_gpu.h"

#ifdef INCLUDE_VIRGLRENDERER_SUPPORT
void glBlitFramebuffer(	GLint srcX0,
 	GLint srcY0,
 	GLint srcX1,
 	GLint srcY1,
 	GLint dstX0,
 	GLint dstY0,
 	GLint dstX1,
 	GLint dstY1,
 	GLbitfield mask,
 	GLenum filter);

inline static void vdpy_gl_err_warn(uint32_t ln)
{
    GLenum status = glGetError();
    if (status != GL_NO_ERROR) {
        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "%u *** glGetError(0x%x)\n", ln, status);
    }
}

/*******************************************************************************
 *
 * vdpy_vscreen - get the screen structure corresponding to a given scanout id
 *
 * This routine gets the screen structure corresponding to a given scanout id.
 *
 * RETURNS: pointer to the screen structure, or NULL upon error
 *
 * ERRNO: N/A
 */

static struct vscreen * 
vdpy_vscreen(int handle, 
             int scanout_id)
{
    struct vscreen *vscr;
    struct display *pdsp = vdisplay();

    if (handle != pdsp->s.n_connect) {
        return NULL;
    }

    if ( pdsp->tid != pthread_self()) {
        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "unexpected code path as unsafe 3D ops in multi-threads env.\n");
        return NULL;
    }

    if (scanout_id >= pdsp->vscrs_num) {
        return NULL;
    }

    vscr = pdsp->vscrs + scanout_id;
    return vscr;
}

/*******************************************************************************
 *
 * vdpy_create_context - create context
 *
 * This routine creates context
 *
 * RETURNS: the created context, or NULL upon error
 *
 * ERRNO: N/A
 */

void *
vdpy_create_context(void *opaque, int scanout_idx,
                    int major_ver, int minor_ver)
{
    SDL_GLContext ctx;

    struct vscreen *vscr;
    struct display *pdsp = vdisplay();

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"scanout_idx=%u (major_ver=%d, minor_ver=%d)\n", scanout_idx, major_ver, minor_ver);

    if (scanout_idx >= pdsp->vscrs_num) {
        return NULL;
    }
    vscr = pdsp->vscrs + scanout_idx;

    SDL_GL_MakeCurrent(vscr->win, vscr->winctx);

    SDL_GL_SetAttribute(SDL_GL_SHARE_WITH_CURRENT_CONTEXT, 1);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK,
                        SDL_GL_CONTEXT_PROFILE_ES);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, major_ver);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, minor_ver);

    ctx = SDL_GL_CreateContext(vscr->win);
    if (!ctx) {
        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "Failed to create SDL context\n");
    }

    return (void *)ctx;
}

/*******************************************************************************
 *
 * vdpy_destroy_context - destroy context
 *
 * This routine destroys context
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

void 
vdpy_destroy_context(void *opaque, void *ctx)
{
    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"ctx=%p\n", ctx);

    SDL_GL_DeleteContext((SDL_GLContext)ctx);
}

/*******************************************************************************
 *
 * vdpy_make_context_current - make context current
 *
 * This routine makes context current
 *
 * RETURNS: 0 on success or a negative error code on failure
 *
 * ERRNO: N/A
 */

int 
vdpy_make_context_current(void *opaque, int scanout_idx,
                              void *ctx)
{
    SDL_GLContext sctx;
    SDL_Window* cur_window;

    struct vscreen *vscr;
    struct display *pdsp = vdisplay();

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"scanout_idx=%u, ctx=%p\n", scanout_idx, ctx);

    if (scanout_idx >= pdsp->vscrs_num) {
        return -1;
    }
    vscr = pdsp->vscrs + scanout_idx;
    cur_window = vscr->win;

    sctx = (SDL_GLContext)ctx;
    return SDL_GL_MakeCurrent(cur_window, sctx);
}

/*******************************************************************************
 *
 * vdpy_gl_scanout_disable - disable scanout
 *
 * This routine disables scanout
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

void 
vdpy_gl_scanout_disable(int handle, int scanout_id)
{
    pixman_image_t *src_img;
    struct vscreen *vscr;

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"scanout_id=%u\n", scanout_id);

    vscr = vdpy_vscreen(handle, scanout_id);
    if (!vscr) {
        return;
    }

    vscr->surf.width = 0;
    vscr->surf.height = 0;
    if (!vscr->img) {
        vscr->guest_width = VDPY_MIN_WIDTH;
        vscr->guest_height = VDPY_MIN_HEIGHT;
    }
    src_img = pixman_image_create_bits(PIXMAN_a8r8g8b8,
                                       vscr->guest_width, vscr->guest_height,
                                       (uint32_t *)NULL,
                                       vscr->guest_width * 4);
    if (src_img == NULL) {
        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "failed to create pixman_image\n");
        return;
    }

    if (vscr->img)
        pixman_image_unref(vscr->img);

    SDL_SetWindowTitle(vscr->win,
                       "Not activate display yet!");

    /* Replace the cur_img with the created_img */
    vscr->img = src_img;

    vscr->w = 0;
    vscr->h = 0;

    if (vscr->guest_fb.framebuffer) {
        if (vscr->guest_fb.delete_tex) {
            glDeleteTextures(1, &vscr->guest_fb.tex);
            vscr->guest_fb.delete_tex = false;
        }

        glDeleteFramebuffers(1, &vscr->guest_fb.framebuffer);

        vscr->guest_fb.w = 0;
        vscr->guest_fb.h = 0;
        vscr->guest_fb.tex = 0;
        vscr->guest_fb.framebuffer = 0;
    }
}

/*******************************************************************************
 *
 * vdpy_egl_text_fb_setup - set up framebuffer and attach texture image
 *
 * This routine sets up framebuffer and attaches texture image
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void 
vdpy_egl_text_fb_setup(struct vscreen *vscr,
                            int width, 
                            int height,
                            GLuint tex,
                            bool del)
{
    GLenum status;

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"%dx%d, tex=0x%x\n",
                       width, height, tex);

    if (vscr->guest_fb.delete_tex) {
        glDeleteTextures(1, &vscr->guest_fb.tex);
        vscr->guest_fb.delete_tex = false;
    }

    vscr->guest_fb.w = width;
    vscr->guest_fb.h = height;
    vscr->guest_fb.tex = tex;
    vscr->guest_fb.delete_tex = del;

    if (!vscr->guest_fb.framebuffer) {
        glGenFramebuffers(1, &vscr->guest_fb.framebuffer);
        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"glGenFramebuffers: 0x%x\n", vscr->guest_fb.framebuffer);
    }

    glBindFramebuffer(GL_FRAMEBUFFER, vscr->guest_fb.framebuffer);
    vdpy_gl_err_warn(__LINE__);

    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                              GL_TEXTURE_2D, vscr->guest_fb.tex, 0);
    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "glFramebufferTexture2D\n");
    vdpy_gl_err_warn(__LINE__);
}

/*******************************************************************************
 *
 * vdpy_egl_text_fb_setup - set up texture for a scanout
 *
 * This routine sets up texture for a scanout
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

void 
vdpy_gl_scanout_tex_setup(int handle,
                               int scanout_id,
                               uint32_t tex_id,
                               bool flag_y_0_top,
                               uint32_t width,
                               uint32_t height,
                               uint32_t x, uint32_t y,
                               uint32_t w, uint32_t h)
{
    struct vscreen *vscr;

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, 
                   "scanout_id=%d, tex_id=0x%x, %dx%d, x=%u, y=%u, w=%u, h=%u\n",
                   scanout_id, tex_id, width, height, x, y, w, h);

    vscr = vdpy_vscreen(handle, scanout_id);
    if (!vscr) {
        return;
    }

    vscr->x = x;
    vscr->y = y;
    vscr->w = w;
    vscr->h = h;
    vscr->flag_y_0_top = flag_y_0_top;

    SDL_GL_MakeCurrent(vscr->win, vscr->winctx);

    vdpy_egl_text_fb_setup(vscr, width, height, tex_id, false);
}

/*******************************************************************************
 *
 * vdpy_egl_scanout_flush - flush scanout
 *
 * This routine flushed the given scanout
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

void 
vdpy_egl_scanout_flush(int handle, 
                            int scanout_id,
                            uint32_t x0, 
                            uint32_t y0, 
                            uint32_t w0, 
                            uint32_t h0)
{
    struct vscreen *vscr;
    int win_w;
    int win_h;
    GLuint x1;
    GLuint y1;
    GLuint x2;
    GLuint y2;
    GLuint w;
    GLuint h;

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "scanout_id=%d\n", scanout_id);

    vscr = vdpy_vscreen(handle, scanout_id);
    if (!vscr) {
        return;
    }

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "scanout_id=%d: %u, %u, %u, %u\n", scanout_id, x0, y0, w0, h0);

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "guest_fb.framebuffer:%u, win_fb.framebuffer:%u\n", vscr->guest_fb.framebuffer, vscr->win_fb.framebuffer);

    if (!vscr->guest_fb.framebuffer) {
        return;
    }

    SDL_GL_MakeCurrent(vscr->win, vscr->winctx);

    SDL_GetWindowSize(vscr->win, &win_w, &win_h);
    vscr->win_fb.w = win_w;
    vscr->win_fb.h = win_h;
    vscr->win_fb.framebuffer = 0;

    x1 = 0;
    y1 = 0;
    w = vscr->guest_fb.w;
    h = vscr->guest_fb.h;
   
    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "w=%d, h=%d\n", w, h);
 
    glBindFramebuffer(GL_READ_FRAMEBUFFER_NV, vscr->guest_fb.framebuffer);
    glBindFramebuffer(GL_DRAW_FRAMEBUFFER_NV, vscr->win_fb.framebuffer);
    vdpy_gl_err_warn(__LINE__);

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "glViewport: win_fb.w=%u, win_fb.h=%u\n", vscr->win_fb.w, vscr->win_fb.h);
    glViewport(0, 0, vscr->win_fb.w, vscr->win_fb.h);
    vdpy_gl_err_warn(__LINE__);

    if (vscr->guest_fb.dmabuf) {
        x1 = (vscr->guest_fb.dmabuf)->x;
        y1 = (vscr->guest_fb.dmabuf)->y;
        w = (vscr->guest_fb.dmabuf)->width;
        h = (vscr->guest_fb.dmabuf)->height;
    }

    w = (x1 + w) > vscr->guest_fb.w ? vscr->guest_fb.w - x1 : w;
    h = (y1 + h) > vscr->guest_fb.h ? vscr->guest_fb.h - y1 : h;

    y2 = (!vscr->flag_y_0_top) ? y1 : h + y1;
    y1 = (!vscr->flag_y_0_top) ? h + y1 : y1;
    x2 = x1 + w;

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "glBlitFramebuffer(%u, %u, %u, %u, 0, 0, %u, %u)\n", x1, y1, x2, y2, vscr->win_fb.w, vscr->win_fb.h);
    glBlitFramebuffer(x1, y1, x2, y2,
                      0, 0, vscr->win_fb.w, vscr->win_fb.h,
                      GL_COLOR_BUFFER_BIT, GL_LINEAR);

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "SDL_GL_SwapWindow\n");
    SDL_GL_SwapWindow(vscr->win);
}

#endif /*INCLUDE_VIRGLRENDERER_SUPPORT */
