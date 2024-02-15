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

#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdbool.h>
#include <libdrm/drm_fourcc.h>
#include <linux/udmabuf.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <stdio.h>
#include "vdisplay.h"
#include "atomic.h"
#include "timer.h"
#include "../virtioHostLib.h"
#include "virtio_host_gpu.h"

#ifdef INCLUDE_VIRGLRENDERER_SUPPORT

#include <virgl/virglrenderer.h>

#define FENCE_TIME_POLL_PERIOD (10 * 1000000)

struct fenceq_entry {
    TAILQ_ENTRY(fenceq_entry) entries;
    struct virtioHostQueue *pQueue;
    uint16_t idx;
    struct virtio_gpu_command *cmd;
};
static TAILQ_HEAD(tailhead, fenceq_entry) fenceq_head;

static void virgl_write_fence(void *opaque, uint32_t fence);
static virgl_renderer_gl_context
virgl_create_context(void *opaque, int scanout_idx,
                     struct virgl_renderer_gl_ctx_param *params);
static void virgl_destroy_context(void *opaque, virgl_renderer_gl_context ctx);
static int virgl_make_context_current(void *opaque, int scanout_idx,
                                      virgl_renderer_gl_context ctx);

static struct virgl_renderer_callbacks virtio_gpu_3d_callbacks = {
    .version             = 1,
    .write_fence         = virgl_write_fence,
    .create_gl_context   = virgl_create_context,
    .destroy_gl_context  = virgl_destroy_context,
    .make_current        = virgl_make_context_current,
};

static struct acrn_timer fence_poll_timer;

/*******************************************************************************
 *
 * virtio_gpu_cmd_gl_response - return response after executing the command
 *
 * This routine returns the response after executing the given gpu command
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void
virtio_gpu_cmd_gl_response(struct virtioHostQueue *pQueue,
			   uint16_t idx,
			   struct virtio_gpu_command *cmd)
{
    struct virtio_gpu_ctrl_hdr resp;

    memset(&resp, 0, sizeof(resp));
    resp.type = cmd->resp_type;

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"resp.type=0x%x\n", resp.type);

    cmd->iolen = sizeof(resp);
    virtio_gpu_update_resp_fence(&cmd->hdr, &resp);
    memcpy(cmd->iov[1].iov_base, &resp, sizeof(resp));

    /* release the buffers to virtio FE driver */
    (void)virtioHostQueueRelBuf(pQueue, idx, cmd->iolen);

    /* send an interrupt to virtio FE driver */
    (void)virtioHostQueueNotify(pQueue);
}

/*******************************************************************************
 *
 * virgl_write_fence - write fence
 *
 * This routine writes fence.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void 
virgl_write_fence(void *opaq, uint32_t fence)
{
    struct fenceq_entry *np;
    struct virtio_gpu_command *cmd;

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"fence=%u\n", fence);

    for (np = fenceq_head.tqh_first; np != NULL; np = np->entries.tqe_next) {
	cmd = np->cmd;
	if (cmd->hdr.fence_id > fence) {
            continue;
        }

	cmd->resp_type = VIRTIO_GPU_RESP_OK_NODATA;
	virtio_gpu_cmd_gl_response(np->pQueue, np->idx, cmd);

	TAILQ_REMOVE(&fenceq_head, np, entries);
        free(cmd);
        free(np);
    }
}

/*******************************************************************************
 *
 * virgl_create_context - create context
 *
 * This routine creates context.
 *
 * RETURNS: the created render context, or NULL if the creation fails.
 *
 * ERRNO: N/A
 */

static virgl_renderer_gl_context
virgl_create_context(void *opaque, int scanout_idx,
                     struct virgl_renderer_gl_ctx_param *params)
{
    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"scanout_idx=%u\n", scanout_idx);

    return (virgl_renderer_gl_context)
           vdpy_create_context(opaque, scanout_idx, params->major_ver, params->minor_ver);
}

/*******************************************************************************
 *
 * virgl_destroy_context - destroy context
 *
 * This routine destroys context.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void 
virgl_destroy_context(void *opaque, virgl_renderer_gl_context ctx)
{
    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"ctx=%p\n", ctx);

    vdpy_destroy_context(opaque, (void *)ctx);
}

/*******************************************************************************
 *
 * virgl_make_context_current - make context current
 *
 * This routine makes the specified context current.
 *
 * RETURNS: 0 on success or a negative error code on failure
 *
 * ERRNO: N/A
 */

static int 
virgl_make_context_current(void *opaque, int scanout_idx,
                                      virgl_renderer_gl_context ctx)
{
    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"scanout_idx=%u, ctx=%p\n", 
                       scanout_idx, ctx);

    return vdpy_make_context_current(opaque, scanout_idx, (void *)ctx);
}

/*******************************************************************************
 *
 * fence_timer_cb_call - call virgl_renderer_poll and re-enable timer
 *
 * This routine calls virgl_renderer_poll and re-enable timer if necessary.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void
fence_timer_cb_call(void *data, uint64_t parm2)
{
    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "fenceq_head.tqh_first=%p\n", 
                       fenceq_head.tqh_first);

    virgl_renderer_poll();

    if (fenceq_head.tqh_first != NULL) {
	acrn_timer_enable(&fence_poll_timer);
    }
}

/*******************************************************************************
 *
 * virtio_gpu_virgl_init - initialize the virgl library
 *
 * This routine initializes the virgl library.
 *
 * RETURNS: 0 on success or a negative error code on failure
 *
 * ERRNO: N/A
 */

int 
virtio_gpu_virgl_init(void *g)
{
    uint32_t flags = 0;
    uint32_t capset2_max_ver, capset2_max_size;
    struct itimerspec fence_poll_timer_spec;
    int ret;

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "\n");

    virgl_renderer_get_cap_set(VIRTIO_GPU_CAPSET_VIRGL2,
                              &capset2_max_ver,
                              &capset2_max_size);
    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_INFO, "capset2_max_ver=%u, capset2_max_size=%u\n", capset2_max_ver, capset2_max_size);

#if VIRGL_RENDERER_CALLBACKS_VERSION >= 4
    virtio_gpu_3d_callbacks.version = 4;
#endif

    /* we may add more flags in the future */

    ret = virgl_renderer_init(g, flags, &virtio_gpu_3d_callbacks);
    if (ret != 0) {
        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "virgl initialization failed: %d\n", ret);
        return ret;
    }

    /*
     * virglrenderer requires virgl_renderer_poll() to be called often 
     * to carry out periodic work.
     */
    fence_poll_timer.clockid = CLOCK_MONOTONIC;
    ret = acrn_timer_init(&fence_poll_timer, fence_timer_cb_call, &fence_poll_timer);
    if (ret != 0) {
        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "timer initialization failed: %d\n", ret);
        return ret;
    }
    fence_poll_timer_spec.it_interval.tv_sec = 0;
    fence_poll_timer_spec.it_interval.tv_nsec = FENCE_TIME_POLL_PERIOD;
    fence_poll_timer_spec.it_value.tv_sec = 1;
    fence_poll_timer_spec.it_value.tv_nsec = 0;
    ret = acrn_timer_settime(&fence_poll_timer, &fence_poll_timer_spec);
    if (ret != 0) {
        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "timer setting failed: %d\n", ret);
        return ret;
    }
    acrn_timer_disable(&fence_poll_timer);

    TAILQ_INIT(&fenceq_head);

    return 0;
}

/*******************************************************************************
 *
 * virtio_gpu_gl_update_cursor_data - update cursor data
 *
 * This routine updates the cursor data.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void 
virtio_gpu_gl_update_cursor_data(struct virtio_gpu_scanout *s,
                                             uint32_t resource_id)
{
    uint32_t width;
    uint32_t height;
    uint32_t pixels;
    uint32_t *data;

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "resource_id=%u\n", resource_id);

    data = virgl_renderer_get_cursor_data(resource_id, &width, &height);
    if (!data) {
        return;
    }

    if (width != s->cur_cursor->width ||
        height != s->cur_cursor->height) {
        free(data);
        return;
    }

    pixels = s->cur_cursor->width * s->cur_cursor->height;
    memcpy(s->cur_cursor->data, data, pixels * sizeof(uint32_t));
    free(data);
}

/*******************************************************************************
 *
 * virtio_gpu_cmd_gl_context_create - create gl context
 *
 * This routine creates gl context.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void
virtio_gpu_cmd_gl_context_create(struct virtio_gpu_command *cmd)
{
    struct virtio_gpu_ctx_create req;
    int ret;

    memcpy(&req, cmd->iov[0].iov_base, sizeof(req));

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "hdr.ctx_id=0x%x\n", req.hdr.ctx_id);

    ret = virgl_renderer_context_create(req.hdr.ctx_id, req.nlen,
                                        req.debug_name);

    if (ret == -ENOMEM) {
	VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "%s: memory allocation failed.\n", __func__);
        cmd->resp_type = VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY;
        goto response;
    } else if (ret) {
        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "%s: invalid parameter(s) specified.\n", __func__);
        cmd->resp_type = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
        goto response;
    }

    return;

response:
    cmd->done = true;
}

/*******************************************************************************
 *
 * virtio_gpu_cmd_gl_context_destroy - destroy gl context
 *
 * This routine destroys gl context.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void
virtio_gpu_cmd_gl_context_destroy(struct virtio_gpu_command *cmd)
{
    struct virtio_gpu_ctx_destroy req;

    memcpy(&req, cmd->iov[0].iov_base, sizeof(req));

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "hdr.ctx_id=0x%x\n", req.hdr.ctx_id);

    virgl_renderer_context_destroy(req.hdr.ctx_id);
}

/*******************************************************************************
 *
 * virtio_gpu_cmd_gl_resource_2d_create - create 2d gl resource
 *
 * This routine creates 2d gl resource.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void
virtio_gpu_cmd_gl_resource_2d_create(struct virtio_gpu_command *cmd)
{
    struct virtio_gpu_resource_create_2d req;
    struct virgl_renderer_resource_create_args args;
    int ret;

    memcpy(&req, cmd->iov[0].iov_base, sizeof(req));

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "resource_id=0x%x\n", req.resource_id);

    args.handle = req.resource_id;
    args.target = 2;
    args.format = req.format;
    args.bind = (1 << 1);
    args.width = req.width;
    args.height = req.height;
    args.depth = 1;
    args.array_size = 1;
    args.last_level = 0;
    args.nr_samples = 0;
    args.flags = VIRTIO_GPU_RESOURCE_FLAG_Y_0_TOP;
    ret = virgl_renderer_resource_create(&args, NULL, 0);
    if (ret == -ENOMEM) {
        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "%s: memory allocation failed.\n", __func__);
        cmd->resp_type = VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY;
        goto response;
    } else if (ret) {
        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "%s: invalid parameter(s) specified.\n", __func__);
        cmd->resp_type = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
        goto response;
    }

    return;

response:
    cmd->done = true;
}

/*******************************************************************************
 *
 * virtio_gpu_cmd_gl_resource_3d_create - create 3d gl resource
 *
 * This routine creates 3d gl resource.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void
virtio_gpu_cmd_gl_resource_3d_create(struct virtio_gpu_command *cmd)
{
    struct virtio_gpu_resource_create_3d req;
    struct virgl_renderer_resource_create_args args;
    int ret;

    memcpy(&req, cmd->iov[0].iov_base, sizeof(req));

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "resource_id=0x%x\n", req.resource_id);

    args.handle = req.resource_id;
    args.target = req.target;
    args.format = req.format;
    args.bind = req.bind;
    args.width = req.width;
    args.height = req.height;
    args.depth = req.depth;
    args.array_size = req.array_size;
    args.last_level = req.last_level;
    args.nr_samples = req.nr_samples;
    args.flags = req.flags;
    ret = virgl_renderer_resource_create(&args, NULL, 0);
    if (ret == -ENOMEM) {
        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "%s: memory allocation failed.\n", __func__);
        cmd->resp_type = VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY;
        goto response;
    } else if (ret) {
        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "%s: invalid parameter(s) specified.\n", __func__);
        cmd->resp_type = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
        goto response;
    }

    return;

response:
    cmd->done = true;
}

/*******************************************************************************
 *
 * virtio_gpu_cmd_gl_resource_flush - flush gl resource
 *
 * This routine flushes gl resource.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void
virtio_gpu_cmd_gl_resource_flush(struct virtio_gpu_command *cmd)
{
    struct virtio_gpu_resource_flush req;
    struct virtioGpuHostCtx *gpu;
    int i;
    struct virtio_gpu_scanout *gpu_scanout;

    gpu = cmd->gpu;
    memcpy(&req, cmd->iov[0].iov_base, sizeof(req));

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "resource_id=0x%x\n", req.resource_id);

    for (i = 0; i < gpu->scanout_num; i++) {
        gpu_scanout = gpu->gpu_scanouts + i;
        if (req.resource_id != gpu_scanout->resource_id)
            continue;

        vdpy_egl_scanout_flush(gpu->vdpy_handle, i,
                               req.r.x, req.r.y, req.r.width, req.r.height);
    }
}

/*******************************************************************************
 *
 * virtio_gpu_cmd_gl_resource_unref - unref gl resource
 *
 * This routine unrefs gl resource.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void 
virtio_gpu_cmd_gl_resource_unref(struct virtio_gpu_command *cmd)
{
    struct virtio_gpu_resource_unref req;
    struct iovec *res_iovs = NULL;
    int num_iovs = 0;

    memcpy(&req, cmd->iov[0].iov_base, sizeof(req));

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "resource_id=0x%x\n", req.resource_id);

    virgl_renderer_resource_detach_iov(req.resource_id,
                                       &res_iovs,
                                       &num_iovs);
    if (res_iovs != NULL && num_iovs != 0) {
        free(res_iovs);
    }
    virgl_renderer_resource_unref(req.resource_id);

}

/*******************************************************************************
 *
 * virtio_gpu_cmd_gl_scanout_set - set gl scanout
 *
 * This routine sets gl scanout.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void
virtio_gpu_cmd_gl_scanout_set(struct virtio_gpu_command *cmd)
{
    struct virtio_gpu_set_scanout req;
    struct virtio_gpu_resource_2d *r2d;
    struct surface surf;
    struct virtioGpuHostCtx *gpu;
    struct virtio_gpu_scanout *gpu_scanout;
    int bytes_pp;
    struct virgl_renderer_resource_info info;
    int ret;

    gpu = cmd->gpu;
    memcpy(&req, cmd->iov[0].iov_base, sizeof(req));

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "resource_id=0x%x, scanout_id=0x%x\n",
                       req.resource_id, req.scanout_id);

    if (req.scanout_id >= gpu->scanout_num) {
        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "%s: Invalid scanout_id %d\n", __func__, req.scanout_id);
        cmd->resp_type = VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID;
        cmd->done = true;
        return;
    }
    gpu_scanout = gpu->gpu_scanouts + req.scanout_id;
    gpu_scanout->scanout_id = req.scanout_id;

    if ((req.resource_id == 0) || (req.r.width == 0) || (req.r.height == 0)) {
        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "disbale scanout\n");
        vdpy_gl_scanout_disable(gpu->vdpy_handle, gpu_scanout->scanout_id);
    } else {
        memset(&info, 0, sizeof(info));
        ret = virgl_renderer_resource_get_info(req.resource_id, &info);
        if (ret) {
            VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR,
                               "illegal resource specified %d\n", req.resource_id);
            cmd->resp_type = VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;
	    cmd->done = true;
            return;
        }
        virgl_renderer_force_ctx_0();
        vdpy_gl_scanout_tex_setup(gpu->vdpy_handle,
                                  gpu_scanout->scanout_id,
                                  info.tex_id,
                                  info.flags & VIRTIO_GPU_RESOURCE_FLAG_Y_0_TOP,
                                  info.width, info.height,
                                  req.r.x, req.r.y, req.r.width, req.r.height);
    }

    gpu_scanout->resource_id = req.resource_id;
}

/*******************************************************************************
 *
 * virtio_gpu_cmd_gl_transfer_to_host_2d - transfer 2d content to host
 *
 * This routine transfers 2d content to host.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void
virtio_gpu_cmd_gl_transfer_to_host_2d(struct virtio_gpu_command *cmd)
{
    struct virtio_gpu_transfer_to_host_2d req;
    struct virtio_gpu_box box;

    memcpy(&req, cmd->iov[0].iov_base, sizeof(req));

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "resource_id=0x%x\n", req.resource_id);

    box.x = req.r.x;
    box.y = req.r.y;
    box.z = 0;
    box.w = req.r.width;
    box.h = req.r.height;
    box.d = 1;

    virgl_renderer_transfer_write_iov(req.resource_id,
                                      0,
                                      0,
                                      0,
                                      0,
                                      (struct virgl_box *)&box,
                                      req.offset, NULL, 0);
}

/*******************************************************************************
 *
 * virtio_gpu_cmd_gl_transfer_to_host_3d - transfer 3d content to host 
 *
 * This routine transfers 3d content to host.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void
virtio_gpu_cmd_gl_transfer_to_host_3d(struct virtio_gpu_command *cmd)
{
    struct virtio_gpu_transfer_host_3d req;

    memcpy(&req, cmd->iov[0].iov_base, sizeof(req));

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "resource_id=0x%x, ctx_id=0x%x\n", 
                       req.resource_id, req.hdr.ctx_id);

    virgl_renderer_transfer_write_iov(req.resource_id,
                                      req.hdr.ctx_id,
                                      req.level,
                                      req.stride,
                                      req.layer_stride,
                                      (struct virgl_box *)&req.box,
                                      req.offset, NULL, 0);
}

/*******************************************************************************
 *
 * virtio_gpu_cmd_gl_transfer_from_host_3d - transfer 3d content from host
 *
 * This routine transfers 3d content from host.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void
virtio_gpu_cmd_gl_transfer_from_host_3d(struct virtio_gpu_command *cmd)
{
    struct virtio_gpu_transfer_host_3d req;

    memcpy(&req, cmd->iov[0].iov_base, sizeof(req));

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "resource_id=0x%x, ctx_id=0x%x\n",
                       req.resource_id, req.hdr.ctx_id);

    virgl_renderer_transfer_read_iov(req.resource_id,
                                     req.hdr.ctx_id,
                                     req.level,
                                     req.stride,
                                     req.layer_stride,
                                     (struct virgl_box *)&req.box,
                                     req.offset, NULL, 0);
}

/*******************************************************************************
 *
 * virtio_gpu_cmd_gl_3d_submit - submit gl 3d comand
 *
 * This routine submits gl 3d comand.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void
virtio_gpu_cmd_gl_3d_submit(struct virtio_gpu_command *cmd)
{
    struct virtio_gpu_cmd_submit req;
    void *buf;
    size_t s;

    memcpy(&req, cmd->iov[0].iov_base, sizeof(req));

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "size=0x%x\n", req.size);

    buf = malloc(req.size);
    memcpy(buf, ((char *)&req) + sizeof(struct virtio_gpu_cmd_submit), req.size);

    virgl_renderer_submit_cmd(buf, req.hdr.ctx_id, req.size / 4);
}

/*******************************************************************************
 *
 * virtio_gpu_cmd_gl_resource_backing_attach - attach backing for gl resource
 *
 * This routine attaches backing for gl resource.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void 
virtio_gpu_cmd_gl_resource_backing_attach(struct virtio_gpu_command *cmd)
{
    struct virtioGpuHostCtx *gpu;
    struct virtio_gpu_resource_attach_backing req;
    struct virtio_gpu_mem_entry *entries;

    struct iovec *iov;
    struct iovec *res_iovs;
    uint32_t res_niov;
    uint8_t *pbuf;
    int i;
    int ret;
    VIRT_ADDR hvaddr;
    gpu = cmd->gpu;

    memcpy(&req, cmd->iov[0].iov_base, sizeof(req));

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "resource_id=0x%x\n", req.resource_id);

    if (cmd->iovcnt < 2) {
        cmd->resp_type = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "invalid memory entry.\n");
        goto exit;
    }

    if (req.nr_entries > 16384) {
        cmd->resp_type = VIRTIO_GPU_RESP_ERR_UNSPEC;
        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "nr_entries is too big.\n");
        goto exit;
    }

    if (req.nr_entries > 0) {
        iov = malloc(req.nr_entries * sizeof(struct iovec));
        if (!iov) {
            cmd->resp_type = VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY;
            goto exit;
        }
        res_iovs = iov;
	res_niov = req.nr_entries;
        entries = calloc(req.nr_entries, sizeof(struct virtio_gpu_mem_entry));
        if (!entries) {
            free(iov);
            cmd->resp_type = VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY;
            goto exit;
        }
        pbuf = (uint8_t*)entries;
        for (i = 1; i < (cmd->iovcnt - 1); i++) {
            memcpy(pbuf, cmd->iov[i].iov_base, cmd->iov[i].iov_len);
            pbuf += cmd->iov[i].iov_len;
        }
        for (i = 0; i < req.nr_entries; i++) {
            if (virtioHostTranslate(
                                    &gpu->vhost,
                                    entries[i].addr,
                                    &hvaddr)) {
                free(iov);
                cmd->resp_type = VIRTIO_GPU_RESP_ERR_UNSPEC;
                goto exit;
            }

            iov[i].iov_base = hvaddr;
            iov[i].iov_len = entries[i].length;
        }
        free(entries);
    }

    ret = virgl_renderer_resource_attach_iov(req.resource_id,
                                             res_iovs, res_niov);

    if (ret != 0) {
       free(iov);
       cmd->resp_type = VIRTIO_GPU_RESP_ERR_UNSPEC;
       goto exit;
    }

    return;

exit:
    cmd->done = true;
}

/*******************************************************************************
 *
 * virtio_gpu_cmd_gl_resource_backing_detach - detach backing for gl resource
 *
 * This routine detaches backing for gl resource.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void
virtio_gpu_cmd_gl_resource_backing_detach(struct virtio_gpu_command *cmd)
{
    struct virtio_gpu_resource_detach_backing req;
    struct iovec *res_iovs = NULL;
    int num_iovs = 0;

    memcpy(&req, cmd->iov[0].iov_base, sizeof(req));

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "resource_id=0x%x\n", req.resource_id);

    virgl_renderer_resource_detach_iov(req.resource_id,
                                       &res_iovs,
                                       &num_iovs);
    if (res_iovs == NULL || num_iovs == 0) {
       cmd->resp_type = VIRTIO_GPU_RESP_ERR_UNSPEC;
       goto exit;
    }

    free(res_iovs);

    return;

exit:
    cmd->done = true;
}

/*******************************************************************************
 *
 * virtio_gpu_cmd_gl_resource_attach - attach gl resource
 *
 * This routine attaches gl resource.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void
virtio_gpu_cmd_gl_resource_attach(struct virtio_gpu_command *cmd)
{
    struct virtio_gpu_ctx_resource req;

    memcpy(&req, cmd->iov[0].iov_base, sizeof(req));

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "resource_id=0x%x\n", req.resource_id);

    virgl_renderer_ctx_attach_resource(req.hdr.ctx_id, req.resource_id);

}

/*******************************************************************************
 *
 * virtio_gpu_cmd_gl_resource_detach - detach gl resource
 *
 * This routine detaches gl resource.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void
virtio_gpu_cmd_gl_resource_detach(struct virtio_gpu_command *cmd)
{
    struct virtio_gpu_ctx_resource req;

    memcpy(&req, cmd->iov[0].iov_base, sizeof(req));

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "resource_id=0x%x\n", req.resource_id);

    virgl_renderer_ctx_detach_resource(req.hdr.ctx_id, req.resource_id);
}

/*******************************************************************************
 *
 * virtio_gpu_cmd_gl_capset_info_get - get gl capset info
 *
 * This routine gets gl capset info.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void
virtio_gpu_cmd_gl_capset_info_get(struct virtio_gpu_command *cmd)
{
    struct virtio_gpu_get_capset_info req;
    struct virtio_gpu_resp_capset_info res;

    memcpy(&req, cmd->iov[0].iov_base, sizeof(req));

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "capset_index=%d\n", req.capset_index);

    memset(&res, 0, sizeof(res));
    if (req.capset_index == 0) {
        res.capset_id = VIRTIO_GPU_CAPSET_VIRGL;
        virgl_renderer_get_cap_set(res.capset_id,
                                   &res.capset_max_version,
                                   &res.capset_max_size);
    } else if (req.capset_index == 1) {
        res.capset_id = VIRTIO_GPU_CAPSET_VIRGL2;
        virgl_renderer_get_cap_set(res.capset_id,
                                   &res.capset_max_version,
                                   &res.capset_max_size);
    } else {
        res.capset_max_version = 0;
        res.capset_max_size = 0;
    }

    cmd->resp_type = VIRTIO_GPU_RESP_OK_CAPSET_INFO;

exit:
    cmd->done = true;

}

/*******************************************************************************
 *
 * virtio_gpu_cmd_gl_capset_get - get gl capset
 *
 * This routine gets gl capset.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void
virtio_gpu_cmd_gl_capset_get(struct virtio_gpu_command *cmd)
{
    struct virtio_gpu_get_capset req;
    struct virtio_gpu_resp_capset *res;
    uint32_t max_ver, max_size;
    char *p = (char *)(cmd->iov[cmd->iovcnt - 1].iov_base);

    memcpy(&req, cmd->iov[0].iov_base, sizeof(req));

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "capset_id=0x%x\n", req.capset_id);

    virgl_renderer_get_cap_set(req.capset_id, &max_ver,
                               &max_size);
    if (!max_size) {
        cmd->resp_type = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
        goto exit;
    }

    res = (struct virtio_gpu_resp_capset *) cmd->iov[cmd->iovcnt - 1].iov_base;

    virgl_renderer_fill_caps(req.capset_id,
                             req.capset_version,
                             (void *)res->capset_data);

    cmd->resp_type = VIRTIO_GPU_RESP_OK_CAPSET;
exit:
    cmd->done = true;
}

/*******************************************************************************
 *
 * virtio_gpu_cmd_gl_process - process gl command
 *
 * This routine processes the gl command.
 *
 * RETURNS: true on success or false on failure
 *
 * ERRNO: N/A
 */

void
virtio_gpu_cmd_gl_process(struct virtioHostQueue *pQueue,
			  uint16_t idx,
			  struct virtio_gpu_command *cmd)
{
    struct fenceq_entry *pfent;
    struct virtio_gpu_command *qcmd;

    cmd->done = false;
    cmd->resp_type = 0;

    switch (cmd->hdr.type) {

        case VIRTIO_GPU_CMD_CTX_CREATE:
            virtio_gpu_cmd_gl_context_create(cmd);
            break;

        case VIRTIO_GPU_CMD_CTX_DESTROY:
            virtio_gpu_cmd_gl_context_destroy(cmd);
            break;

        case VIRTIO_GPU_CMD_RESOURCE_CREATE_2D:
            virtio_gpu_cmd_gl_resource_2d_create(cmd);
            break;

        case VIRTIO_GPU_CMD_RESOURCE_CREATE_3D:
            virtio_gpu_cmd_gl_resource_3d_create(cmd);
            break;

        case VIRTIO_GPU_CMD_SUBMIT_3D:
            virtio_gpu_cmd_gl_3d_submit(cmd);
            break;

        case VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D:
            virtio_gpu_cmd_gl_transfer_to_host_2d(cmd);
            break;

        case VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D:
            virtio_gpu_cmd_gl_transfer_to_host_3d(cmd);
            break;

        case VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D:
            virtio_gpu_cmd_gl_transfer_from_host_3d(cmd);
            break;

        case VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING:
            virtio_gpu_cmd_gl_resource_backing_attach(cmd);
            break;

        case VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING:
            virtio_gpu_cmd_gl_resource_backing_detach(cmd);
            break;

        case VIRTIO_GPU_CMD_SET_SCANOUT:
            virtio_gpu_cmd_gl_scanout_set(cmd);
            break;

        case VIRTIO_GPU_CMD_RESOURCE_FLUSH:
            virtio_gpu_cmd_gl_resource_flush(cmd);
            break;

        case VIRTIO_GPU_CMD_RESOURCE_UNREF:
            virtio_gpu_cmd_gl_resource_unref(cmd);
            break;

        case VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE:
            virtio_gpu_cmd_gl_resource_attach(cmd);
            break;

        case VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE:
            virtio_gpu_cmd_gl_resource_detach(cmd);
            break;

        case VIRTIO_GPU_CMD_GET_CAPSET_INFO:
            virtio_gpu_cmd_gl_capset_info_get(cmd);
            break;

        case VIRTIO_GPU_CMD_GET_CAPSET:
            virtio_gpu_cmd_gl_capset_get(cmd);
            break;

        default:
	    cmd->resp_type = VIRTIO_GPU_RESP_ERR_UNSPEC;
            break;
        }

    if (!(cmd->hdr.flags & VIRTIO_GPU_FLAG_FENCE)) {
        cmd->resp_type = VIRTIO_GPU_RESP_OK_NODATA;
    }

    if ((cmd->done) || (cmd->resp_type)) {
        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_INFO, "hdr type 0x%x, response 0x%x\n", cmd->hdr.type, cmd->resp_type);
        virtio_gpu_cmd_gl_response(pQueue, idx, cmd);
        return;
    }

    /* command is queued in virgl */
    qcmd = malloc(sizeof(struct virtio_gpu_command));
    pfent = malloc(sizeof(struct fenceq_entry));
    if (!qcmd || !pfent) {
        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "%s: memory allocation failed\n", __func__);
        if (qcmd) free(qcmd);
	if (pfent) free(pfent);
        return;
    }
    memcpy(qcmd, cmd, sizeof(struct virtio_gpu_command));
    pfent->pQueue = pQueue;
    pfent->idx = idx;
    pfent->cmd = qcmd;
    TAILQ_INSERT_TAIL(&fenceq_head, pfent, entries);

    VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "creaye fence: fence_id=0x%lx\n", cmd->hdr.fence_id);

    virgl_renderer_create_fence(cmd->hdr.fence_id, cmd->hdr.type);
    acrn_timer_enable(&fence_poll_timer);
}

#endif /* INCLUDE_VIRGLRENDERER_SUPPORT */
