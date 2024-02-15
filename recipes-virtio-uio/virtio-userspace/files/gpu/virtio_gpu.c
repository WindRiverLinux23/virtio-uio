/*
 * Copyright (C) OASIS Open 2018. All rights reserved.
 * Copyright (C) 2022 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * virtio-gpu device
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

#include <sys/ioctl.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <linux/fcntl.h>
#include <stdbool.h>
#include <libdrm/drm_fourcc.h>
#include <linux/udmabuf.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <linux/memfd.h>
#include <stdio.h>

#include "vdisplay.h"
#include "atomic.h"
#include "../mevent.h"
#include "../virtioHostLib.h"
#include "virtio_host_gpu.h"
#ifdef INCLUDE_VIRGLRENDERER_SUPPORT
#include <virgl/virglrenderer.h>
#endif
int fcntl(int __fd, int __cmd, ...);
int open(const char *pathname, int flags, ...);
int memfd_create(const char *name, unsigned int flags);

static void virtio_gpu_cmd_update_cursor(struct virtio_gpu_command *cmd);
static void virtio_gpu_cmd_move_cursor(struct virtio_gpu_command *cmd);

static int mem_fd;
static bool virtio_gpu_init_once = false;
static int scanout_num = 0;
static pthread_t mevent_dispatch_td;

#ifdef INCLUDE_VIRGLRENDERER_SUPPORT
static bool virgl_supported = false;
#endif

void* mevent_dispatch_thread(void *my_unused)
{
        mevent_init();
        mevent_dispatch();
}

static inline bool virtio_gpu_blob_supported(struct virtioGpuHostCtx *gpu)
{
	return gpu->is_blob_supported;
}

static void virtio_gpu_dmabuf_ref(struct dma_buf_info *info)
{
	if (!info)
		return;

	atomic_add_fetch(&info->ref_count, 1);
}

static void virtio_gpu_dmabuf_destroy(struct dma_buf_info *info)
{
	int i;
	for (i = 0; i < info->nr_entries; i++) {
		if (info->plist[i].fd > 0) {
			close(info->plist[i].fd);
			munmap(info->plist[i].mapped_addr,
				info->plist[i].len);
		}
	}
	free(info->plist);
}

static void virtio_gpu_dmabuf_unref(struct dma_buf_info *info)
{
	if (!info)
		return;

	if (atomic_sub_fetch(&info->ref_count, 1) == 0) {
		if (info->dmabuf_fd > 0) {
			virtio_gpu_dmabuf_destroy(info);
			close(info->dmabuf_fd);
		}
		free(info);
	}
}

static bool virtio_gpu_dmabuf_map_addr(struct virtioHost *vHost,
			uint64_t gaddr,
			uint32_t length,
			int *pfd,
			__u64 *poffset,
			void **mapped_addr)
			
{
	VIRT_ADDR hvaddr;
	int fd;
	void *addr;

	if ((!vHost) || (!pfd) || (!poffset))
		return false;

	/* convert guest physical ADDR to host virtual ADDR */
	if (virtioHostTranslate(vHost, (PHYS_ADDR)gaddr, &hvaddr)) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "virtioHostTranslate failed.\n");
		return false;
	}

	/* create an anonymous file living in memory */
	fd = memfd_create("blob_file", MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (fd == -1) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "memfd_create failed.\n");
		return false;
	}

	/* set the file size */
	if (ftruncate(fd, length) == -1) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "ftruncate failed.\n");
		close(fd);
		return false;
	}

	/* add seal */
	if (fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK) < 0) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "F_ADD_SEALS failed.\n");
		close(fd);
		return false;
	}

	/* create a mapping */
	addr = mmap(hvaddr, length, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_FIXED, fd, 0);
	if (addr == MAP_FAILED) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "mmap failed.\n");
		close(fd);
		return false;
	}
	VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "mmap [0x%lx, 0x%lx]\n", (uint64_t)hvaddr, (uint64_t)length);

	*pfd = fd;
	*poffset = 0;
	*mapped_addr = addr;
	return true;
}

void
virtio_gpu_reset(void *vdev)
{
	struct virtioGpuHostCtx *gpu;
	struct virtio_gpu_resource_2d *r2d;

	VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "Resetting virtio-gpu device.\n");
	gpu = vdev;
	while (LIST_FIRST(&gpu->r2d_list)) {
		r2d = LIST_FIRST(&gpu->r2d_list);
		if (r2d) {
			if (r2d->image) {
				pixman_image_unref(r2d->image);
				r2d->image = NULL;
			}
			if (r2d->blob) {
				virtio_gpu_dmabuf_unref(r2d->dma_info);
				r2d->dma_info = NULL;
				r2d->blob = false;
			}
			LIST_REMOVE(r2d, link);
			if (r2d->iov) {
				free(r2d->iov);
				r2d->iov = NULL;
			}
			free(r2d);
		}
	}
	LIST_INIT(&gpu->r2d_list);

#ifdef INCLUDE_VIRGLRENDERER_SUPPORT
        virgl_renderer_reset();
#endif
}

void
virtio_gpu_update_resp_fence(struct virtio_gpu_ctrl_hdr *hdr,
		struct virtio_gpu_ctrl_hdr *resp)
{
	if ((hdr == NULL ) || (resp == NULL))
		return;

	if(hdr->flags & VIRTIO_GPU_FLAG_FENCE) {
		resp->flags |= VIRTIO_GPU_FLAG_FENCE;
		resp->fence_id = hdr->fence_id;
		resp->ctx_id = hdr->ctx_id;
	}
}

static void
virtio_gpu_cmd_unspec(struct virtio_gpu_command *cmd)
{
	struct virtio_gpu_ctrl_hdr resp;

	VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"VIRTIO_GPU_CMD_RESOURCE_UNREF\n");

	memset(&resp, 0, sizeof(resp));
	cmd->iolen = sizeof(resp);
	resp.type = VIRTIO_GPU_RESP_ERR_UNSPEC;
	virtio_gpu_update_resp_fence(&cmd->hdr, &resp);
	memcpy(cmd->iov[cmd->iovcnt - 1].iov_base, &resp, sizeof(resp));
}

static void
virtio_gpu_cmd_get_edid(struct virtio_gpu_command *cmd)
{
	struct virtio_gpu_get_edid req;
	struct virtio_gpu_resp_edid resp;
	struct virtioGpuHostCtx *gpu;

	VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"VIRTIO_GPU_CMD_GET_EDID\n");
	
	gpu = cmd->gpu;
	memcpy(&req, cmd->iov[0].iov_base, sizeof(req));
	cmd->iolen = sizeof(resp);
	memset(&resp, 0, sizeof(resp));
	virtio_gpu_update_resp_fence(&cmd->hdr, &resp.hdr);
	if (req.scanout >= gpu->scanout_num) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "Invalid scanout_id %d\n", req.scanout);
		resp.hdr.type = VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID;
		memcpy(cmd->iov[1].iov_base, &resp, sizeof(resp));
		return;
	}
	/* Only one EDID block is enough, or using sizeof(resp.edid) */
	resp.size = 128;
	resp.hdr.type = VIRTIO_GPU_RESP_OK_EDID;
	vdpy_get_edid(gpu->vdpy_handle, req.scanout, resp.edid, resp.size);
	memcpy(cmd->iov[1].iov_base, &resp, sizeof(resp));
}

static void
virtio_gpu_cmd_get_display_info(struct virtio_gpu_command *cmd)
{
	struct virtio_gpu_resp_display_info resp;
	struct display_info info;
	struct virtioGpuHostCtx *gpu;
	struct virtioGpuHostDev *pGpuDev;
	int i;
	int j;

	VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"VIRTIO_GPU_CMD_GET_DISPLAY_INFO\n");
	
	gpu = cmd->gpu;
	pGpuDev = (struct virtioGpuHostDev *)(cmd->gpu);
	cmd->iolen = sizeof(resp);
	memset(&resp, 0, sizeof(resp));
	resp.hdr.type = VIRTIO_GPU_RESP_OK_DISPLAY_INFO;
	virtio_gpu_update_resp_fence(&cmd->hdr, &resp.hdr);
	i = 0;
	for (j = 0; j < gpu->scanout_num; j++) {
		if (vdpy_get_display_info(gpu->vdpy_handle, j, 
				pGpuDev->beDevArgs.channel->channelId, &info) < 0)
			continue;

		resp.pmodes[i].enabled = 1;
		resp.pmodes[i].r.x = 0;
		resp.pmodes[i].r.y = 0;
		resp.pmodes[i].r.width = info.width;
		resp.pmodes[i].r.height = info.height;
		i++;
	}
	memcpy(cmd->iov[1].iov_base, &resp, sizeof(resp));
}

static struct virtio_gpu_resource_2d *
virtio_gpu_find_resource_2d(struct virtioGpuHostCtx *gpu, uint32_t resource_id)
{
	struct virtio_gpu_resource_2d *r2d;

	LIST_FOREACH(r2d, &gpu->r2d_list, link) {
		if (r2d->resource_id == resource_id) {
			return r2d;
		}
	}

	return NULL;
}

static pixman_format_code_t
virtio_gpu_get_pixman_format(uint32_t format)
{
	switch (format) {
	case VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM:
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "format B8G8R8X8.\n");
		return PIXMAN_x8r8g8b8;
	case VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM:
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "format B8G8R8A8.\n");
		return PIXMAN_a8r8g8b8;
	case VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM:
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "format X8R8G8B8.\n");
		return PIXMAN_b8g8r8x8;
	case VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM:
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "format A8R8G8B8.\n");
		return PIXMAN_b8g8r8a8;
	case VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM:
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "format R8G8B8X8.\n");
		return PIXMAN_x8b8g8r8;
	case VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM:
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "format R8G8B8A8.\n");
		return PIXMAN_a8b8g8r8;
	case VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM:
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "format X8B8G8R8.\n");
		return PIXMAN_r8g8b8x8;
	case VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM:
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "format A8B8G8R8.\n");
		return PIXMAN_r8g8b8a8;
	default:
		return 0;
	}
}

static void
virtio_gpu_update_scanout(struct virtioGpuHostCtx *gpu, int scanout_id, int resource_id,
			  struct virtio_gpu_rect *scan_rect)
{
	struct virtio_gpu_scanout *gpu_scanout;
	struct virtio_gpu_resource_2d *r2d;

	/* as it is already checked, this is not checked again */
	gpu_scanout = gpu->gpu_scanouts + scanout_id;
	if (gpu_scanout->dma_buf) {
		virtio_gpu_dmabuf_unref(gpu_scanout->dma_buf);
		gpu_scanout->dma_buf = NULL;
	}
	if (gpu_scanout->cur_img) {
		pixman_image_unref(gpu_scanout->cur_img);
		gpu_scanout->cur_img = NULL;
	}
	gpu_scanout->resource_id = resource_id;
	r2d = virtio_gpu_find_resource_2d(gpu, resource_id);
	if (r2d) {
		gpu_scanout->is_active = true;
		if (r2d->blob) {
			virtio_gpu_dmabuf_ref(r2d->dma_info);
			gpu_scanout->dma_buf = r2d->dma_info;
		} else {
			pixman_image_ref(r2d->image);
			gpu_scanout->cur_img = r2d->image;
		}
	} else {
		gpu_scanout->is_active = false;
	}
	memcpy(&gpu_scanout->scanout_rect, scan_rect, sizeof(*scan_rect));
}

static void
virtio_gpu_cmd_resource_create_2d(struct virtio_gpu_command *cmd)
{
	struct virtio_gpu_resource_create_2d req;
	struct virtio_gpu_ctrl_hdr resp;
	struct virtio_gpu_resource_2d *r2d;

	VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"VIRTIO_GPU_CMD_RESOURCE_CREATE_2D\n");

	memcpy(&req, cmd->iov[0].iov_base, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	r2d = virtio_gpu_find_resource_2d(cmd->gpu, req.resource_id);
	if ((req.resource_id == 0) || (r2d)) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_INFO, "resource %d already exists.\n", req.resource_id);
		resp.type = VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;
		goto response;
	}
	r2d = (struct virtio_gpu_resource_2d*)calloc(1, \
			sizeof(struct virtio_gpu_resource_2d));
	if (!r2d) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "memory allocation for r2d failed.\n");
		resp.type = VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY;
		goto response;
	}

	r2d->resource_id = req.resource_id;
	r2d->width = req.width;
	r2d->height = req.height;
	r2d->format = virtio_gpu_get_pixman_format(req.format);
	if (!r2d->format) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "couldn't handle format %d.\n", req.format);
		resp.type = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
		goto response;
	}
	r2d->image = pixman_image_create_bits(
			r2d->format, r2d->width, r2d->height, NULL, 0);
	if (!r2d->image) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "could not create resource %d (%d,%d).\n",
				r2d->resource_id,
				r2d->width,
				r2d->height);
		free(r2d);
		resp.type = VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY;
	} else {
		resp.type = VIRTIO_GPU_RESP_OK_NODATA;
		LIST_INSERT_HEAD(&cmd->gpu->r2d_list, r2d, link);
	}

response:
	cmd->iolen = sizeof(resp);
	virtio_gpu_update_resp_fence(&cmd->hdr, &resp);
	memcpy(cmd->iov[1].iov_base, &resp, sizeof(resp));
}

static void
virtio_gpu_cmd_resource_unref(struct virtio_gpu_command *cmd)
{
	struct virtio_gpu_resource_unref req;
	struct virtio_gpu_ctrl_hdr resp;
	struct virtio_gpu_resource_2d *r2d;

        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"VIRTIO_GPU_CMD_RESOURCE_UNREF\n");

	memcpy(&req, cmd->iov[0].iov_base, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	r2d = virtio_gpu_find_resource_2d(cmd->gpu, req.resource_id);
	if (r2d) {
		/* disable scanout(s) first? */

		if (r2d->image) {
			pixman_image_unref(r2d->image);
			r2d->image = NULL;
		}
		if (r2d->blob) {
			virtio_gpu_dmabuf_unref(r2d->dma_info);
			r2d->dma_info = NULL;
			r2d->blob = false;
		}
		LIST_REMOVE(r2d, link);
		if (r2d->iov) {
			free(r2d->iov);
			r2d->iov = NULL;
		}
		free(r2d);
		resp.type = VIRTIO_GPU_RESP_OK_NODATA;
	} else {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "Illegal resource id %d\n", req.resource_id);
		resp.type = VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;
	}

	cmd->iolen = sizeof(resp);
	virtio_gpu_update_resp_fence(&cmd->hdr, &resp);
	memcpy(cmd->iov[1].iov_base, &resp, sizeof(resp));
}

static void
virtio_gpu_cmd_resource_attach_backing(struct virtio_gpu_command *cmd)
{
	struct virtioGpuHostCtx *gpu;
	struct virtio_gpu_resource_attach_backing req;
	struct virtio_gpu_mem_entry *entries;
	struct virtio_gpu_resource_2d *r2d;
	struct virtio_gpu_ctrl_hdr resp;
	int i;
	uint8_t *pbuf;
	struct iovec *iov;
	VIRT_ADDR hvaddr;

        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING\n");

	gpu = cmd->gpu;

	memcpy(&req, cmd->iov[0].iov_base, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	/*
	 * 1. Per VIRTIO GPU specification,
	 *    'cmd->iovcnt' = 'nr_entries' of 'struct virtio_gpu_resource_attach_backing' + 2,
	 *    where 'nr_entries' is number of instance of 'struct virtio_gpu_mem_entry'.
	 *    case 'cmd->iovcnt < 3' means above 'nr_entries' is zero, which is invalid
	 *    and ignored.
	 *    2. Function 'virtio_gpu_bh(void *data)' guarantees cmd->iovcnt >=1.
	 */
	if (cmd->iovcnt < 2) {
		resp.type = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
		memcpy(cmd->iov[cmd->iovcnt - 1].iov_base, &resp, sizeof(resp));
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "invalid memory entry.\n");
		return;
	}

	r2d = virtio_gpu_find_resource_2d(cmd->gpu, req.resource_id);
	if ((r2d->iov) || (req.nr_entries > 16384)) {
		resp.type = VIRTIO_GPU_RESP_ERR_UNSPEC;
		memcpy(cmd->iov[cmd->iovcnt - 1].iov_base, &resp, sizeof(resp));
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "backing exists or nr_entries is too big.\n");
		return;
	}
	if (r2d && req.nr_entries > 0) {
		iov = malloc(req.nr_entries * sizeof(struct iovec));
		if (!iov) {
			resp.type = VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY;
			goto exit;
		}

		r2d->iov = iov;
		r2d->iovcnt = req.nr_entries;
		entries = calloc(req.nr_entries, sizeof(struct virtio_gpu_mem_entry));
		if (!entries) {
			free(iov);
			resp.type = VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY;
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
				resp.type = VIRTIO_GPU_RESP_ERR_UNSPEC;
				goto exit;
			}
			r2d->iov[i].iov_base = hvaddr;
			r2d->iov[i].iov_len = entries[i].length;
		}
		free(entries);
		resp.type = VIRTIO_GPU_RESP_OK_NODATA;
	} else {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "Illegal resource id %d\n", req.resource_id);
		resp.type = VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;
	}
exit:
	cmd->iolen = sizeof(resp);
	virtio_gpu_update_resp_fence(&cmd->hdr, &resp);
	memcpy(cmd->iov[cmd->iovcnt - 1].iov_base, &resp, sizeof(resp));
}

static void
virtio_gpu_cmd_resource_detach_backing(struct virtio_gpu_command *cmd)
{
	struct virtio_gpu_resource_detach_backing req;
	struct virtio_gpu_resource_2d *r2d;
	struct virtio_gpu_ctrl_hdr resp;

        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING\n");

	memcpy(&req, cmd->iov[0].iov_base, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	r2d = virtio_gpu_find_resource_2d(cmd->gpu, req.resource_id);
	if (r2d && r2d->iov) {
		free(r2d->iov);
		r2d->iov = NULL;
	}

	if (r2d->blob) {
		/* fini_udmabuf */
	}

	cmd->iolen = sizeof(resp);
	resp.type = VIRTIO_GPU_RESP_OK_NODATA;
	virtio_gpu_update_resp_fence(&cmd->hdr, &resp);
	memcpy(cmd->iov[1].iov_base, &resp, sizeof(resp));
}

static void
virtio_gpu_cmd_set_scanout(struct virtio_gpu_command *cmd)
{
	struct virtio_gpu_set_scanout req;
	struct virtio_gpu_resource_2d *r2d;
	struct virtio_gpu_ctrl_hdr resp;
	struct surface surf;
	struct virtioGpuHostCtx *gpu;
	struct virtio_gpu_scanout *gpu_scanout;
	int bytes_pp;

        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "VIRTIO_GPU_CMD_SET_SCANOUT\n");

	gpu = cmd->gpu;
	memcpy(&req, cmd->iov[0].iov_base, sizeof(req));
	memset(&resp, 0, sizeof(resp));
	virtio_gpu_update_resp_fence(&cmd->hdr, &resp);

	if (req.scanout_id >= gpu->scanout_num) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "Invalid scanout_id %d\n", req.scanout_id);
		resp.type = VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID;
		memcpy(cmd->iov[1].iov_base, &resp, sizeof(resp));
		return;
	}
	gpu_scanout = gpu->gpu_scanouts + req.scanout_id;
	gpu_scanout->scanout_id = req.scanout_id;

	r2d = virtio_gpu_find_resource_2d(gpu, req.resource_id);
	if ((req.resource_id == 0) || (r2d == NULL)) {
		virtio_gpu_update_scanout(gpu, req.scanout_id, 0, &req.r);
		vdpy_surface_set(gpu->vdpy_handle, req.scanout_id, NULL);
		resp.type = VIRTIO_GPU_RESP_OK_NODATA;
		memcpy(cmd->iov[1].iov_base, &resp, sizeof(resp));
		return;
	}
	if ((req.r.x > r2d->width) ||
	    (req.r.y > r2d->height) ||
	    (req.r.width > r2d->width) ||
	    (req.r.height > r2d->height) ||
	    (req.r.x + req.r.width) > (r2d->width) ||
	    (req.r.y + req.r.height) > (r2d->height)) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "Scanout bound out of underlying resource.\n");
		resp.type = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
	} else {
		virtio_gpu_update_scanout(gpu, req.scanout_id, req.resource_id, &req.r);
		bytes_pp = PIXMAN_FORMAT_BPP(r2d->format) / 8;
		pixman_image_ref(r2d->image);
		surf.pixel = pixman_image_get_data(r2d->image);
		surf.x = req.r.x;
		surf.y = req.r.y;
		surf.width = req.r.width;
		surf.height = req.r.height;
		surf.stride = pixman_image_get_stride(r2d->image);
		surf.surf_format = r2d->format;
		surf.surf_type = SURFACE_PIXMAN;
		surf.pixel += bytes_pp * surf.x + surf.y * surf.stride;
		vdpy_surface_set(gpu->vdpy_handle, req.scanout_id, &surf);
		pixman_image_unref(r2d->image);
		resp.type = VIRTIO_GPU_RESP_OK_NODATA;
	}

	cmd->iolen = sizeof(resp);
	memcpy(cmd->iov[1].iov_base, &resp, sizeof(resp));
}

static void
virtio_gpu_cmd_transfer_to_host_2d(struct virtio_gpu_command *cmd)
{
	struct virtio_gpu_transfer_to_host_2d req;
	struct virtio_gpu_resource_2d *r2d;
	struct virtio_gpu_ctrl_hdr resp;
	uint32_t src_offset, dst_offset, stride, bpp, h;
	pixman_format_code_t format;
	void *img_data, *dst, *src;
	int i, done, bytes, total;
	int width, height;

        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D\n");

	memcpy(&req, cmd->iov[0].iov_base, sizeof(req));
	memset(&resp, 0, sizeof(resp));
	virtio_gpu_update_resp_fence(&cmd->hdr, &resp);

	r2d = virtio_gpu_find_resource_2d(cmd->gpu, req.resource_id);
	if (r2d == NULL) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "Illegal resource id %d\n", 
				req.resource_id);
		resp.type = VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;
		memcpy(cmd->iov[1].iov_base, &resp, sizeof(resp));
		return;
	}

	if (r2d->blob) {
		resp.type = VIRTIO_GPU_RESP_OK_NODATA;
		memcpy(cmd->iov[1].iov_base, &resp, sizeof(resp));
		return;
	}

	if ((req.r.x > r2d->width) ||
	    (req.r.y > r2d->height) ||
	    (req.r.width > r2d->width) ||
	    (req.r.height > r2d->height) ||
	    (req.r.x + req.r.width > r2d->width) ||
	    (req.r.y + req.r.height > r2d->height)) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "transfer bounds outside resource.\n");
		resp.type = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
	} else {
		pixman_image_ref(r2d->image);
		stride = pixman_image_get_stride(r2d->image);
		format = pixman_image_get_format(r2d->image);
		bpp = PIXMAN_FORMAT_BPP(format) / 8;
		img_data = pixman_image_get_data(r2d->image);
		width = (req.r.width < r2d->width) ? req.r.width : r2d->width;
		height = (req.r.height < r2d->height) ? req.r.height : r2d->height;
		for (h = 0; h < height; h++) {
			src_offset = req.offset + stride * h;
			dst_offset = (req.r.y + h) * stride + (req.r.x * bpp);
			dst = img_data + dst_offset;
			done = 0;
			total = width * bpp;
			for (i = 0; i < r2d->iovcnt; i++) {
				if ((r2d->iov[i].iov_base == 0) || (r2d->iov[i].iov_len == 0)) {
					continue;
				}

				if (src_offset < r2d->iov[i].iov_len) {
					src = r2d->iov[i].iov_base + src_offset;
					bytes = ((total - done) < (r2d->iov[i].iov_len - src_offset)) ?
						 (total - done) : (r2d->iov[i].iov_len - src_offset);
					memcpy((dst + done), src, bytes);
					src_offset = 0;
					done += bytes;
					if (done >= total) {
						break;
					}
				} else {
					src_offset -= r2d->iov[i].iov_len;
				}
			}
		}
		pixman_image_unref(r2d->image);
		resp.type = VIRTIO_GPU_RESP_OK_NODATA;
	}

	cmd->iolen = sizeof(resp);
	memcpy(cmd->iov[1].iov_base, &resp, sizeof(resp));
}

static bool
virtio_gpu_scanout_needs_flush(struct virtioGpuHostCtx *gpu,
			      int scanout_id,
			      int resource_id,
			      struct virtio_gpu_rect *flush_rect)
{
	struct virtio_gpu_scanout *gpu_scanout;
	pixman_region16_t flush_region, final_region, scanout_region;

	/* the scanout_id is already checked. So it is ignored in this function */
	gpu_scanout = gpu->gpu_scanouts + scanout_id;

	/* if the different resource_id is used, flush can be skipped */
	if (resource_id != gpu_scanout->resource_id)
		return false;

	pixman_region_init(&final_region);
	pixman_region_init_rect(&scanout_region,
				gpu_scanout->scanout_rect.x,
				gpu_scanout->scanout_rect.y,
				gpu_scanout->scanout_rect.width,
				gpu_scanout->scanout_rect.height);
	pixman_region_init_rect(&flush_region,
				flush_rect->x, flush_rect->y,
				flush_rect->width, flush_rect->height);

	/* Check intersect region to determine whether scanout_region
	 * needs to be flushed.
	 */
	pixman_region_intersect(&final_region, &scanout_region, &flush_region);

	/* if intersection_region is empty, it means that the scanout_region is not
	 * covered by the flushed_region. And it is unnecessary to update
	 */
	if (pixman_region_not_empty(&final_region))
		return true;
	else
		return false;
}

static void
virtio_gpu_cmd_resource_flush(struct virtio_gpu_command *cmd)
{
	struct virtio_gpu_resource_flush req;
	struct virtio_gpu_ctrl_hdr resp;
	struct virtio_gpu_resource_2d *r2d;
	struct surface surf;
	struct virtioGpuHostCtx *gpu;
	int i;
	struct virtio_gpu_scanout *gpu_scanout;
	int bytes_pp;

        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"VIRTIO_GPU_CMD_RESOURCE_FLUSH\n");

	gpu = cmd->gpu;
	memcpy(&req, cmd->iov[0].iov_base, sizeof(req));
	memset(&resp, 0, sizeof(resp));
	virtio_gpu_update_resp_fence(&cmd->hdr, &resp);

	r2d = virtio_gpu_find_resource_2d(gpu, req.resource_id);
	if (r2d == NULL) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "Illegal resource id %d\n", 
				req.resource_id);
		resp.type = VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;
		memcpy(cmd->iov[1].iov_base, &resp, sizeof(resp));
		return;
	}
	if (r2d->blob) {
		virtio_gpu_dmabuf_ref(r2d->dma_info);
		for (i = 0; i < gpu->scanout_num; i++) {
			if (!virtio_gpu_scanout_needs_flush(gpu, i, req.resource_id, &req.r))
				continue;

			surf.dma_info.dmabuf_fd = r2d->dma_info->dmabuf_fd;
			surf.surf_type = SURFACE_DMABUF;
			vdpy_surface_update(gpu->vdpy_handle, i, &surf);
		}
		virtio_gpu_dmabuf_unref(r2d->dma_info);
		resp.type = VIRTIO_GPU_RESP_OK_NODATA;
		memcpy(cmd->iov[1].iov_base, &resp, sizeof(resp));
		return;
	}
	pixman_image_ref(r2d->image);
	bytes_pp = PIXMAN_FORMAT_BPP(r2d->format) / 8;
	for (i = 0; i < gpu->scanout_num; i++) {
		if (!virtio_gpu_scanout_needs_flush(gpu, i, req.resource_id, &req.r))
			continue;

		gpu_scanout = gpu->gpu_scanouts + i;
		surf.pixel = pixman_image_get_data(r2d->image);
		surf.x = gpu_scanout->scanout_rect.x;
		surf.y = gpu_scanout->scanout_rect.y;
		surf.width = gpu_scanout->scanout_rect.width;
		surf.height = gpu_scanout->scanout_rect.height;
		surf.stride = pixman_image_get_stride(r2d->image);
		surf.surf_format = r2d->format;
		surf.surf_type = SURFACE_PIXMAN;
		surf.pixel += bytes_pp * surf.x + surf.y * surf.stride;
		vdpy_surface_update(gpu->vdpy_handle, i, &surf);
	}
	pixman_image_unref(r2d->image);

	cmd->iolen = sizeof(resp);
	resp.type = VIRTIO_GPU_RESP_OK_NODATA;
	memcpy(cmd->iov[1].iov_base, &resp, sizeof(resp));
}

static int udmabuf_fd(void)
{
	static bool first = true;
	static int udmabuf;

	if (!first)
		return udmabuf;

	first = false;

	udmabuf = open("/dev/udmabuf", O_RDWR);
	if (udmabuf < 0) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "Could not open /dev/udmabuf: %s.", strerror(errno));
	}
	return udmabuf;
}

static struct dma_buf_info *virtio_gpu_create_udmabuf(struct virtioGpuHostCtx *gpu,
					struct virtio_gpu_mem_entry *entries,
					int nr_entries)
{
	struct udmabuf_create_list *list;
	int udmabuf, i, dmabuf_fd;
	bool fail_flag;
	struct dma_buf_info *info;
	struct dma_buf_info_list *plist;

	udmabuf = udmabuf_fd();
	if (udmabuf < 0) {
		return NULL;
	}

	fail_flag = false;
	list = malloc(sizeof(*list) + sizeof(struct udmabuf_create_item) * nr_entries);
	plist = malloc(sizeof(struct dma_buf_info_list) * nr_entries);
	info = malloc(sizeof(*info));
	if ((info == NULL) || (list == NULL) || (plist == NULL)) {
		free(list);
		free(plist);
		free(info);
		return NULL;
	}
	for (i = 0; i < nr_entries; i++)
		plist[i].fd = -1;
	info->plist = plist;
	info->nr_entries = nr_entries;

	for (i = 0; i < nr_entries; i++) {
		if (virtio_gpu_dmabuf_map_addr((struct virtioHost *)gpu,
					entries[i].addr,
					entries[i].length,
					&list->list[i].memfd,
					&list->list[i].offset,
					&plist[i].mapped_addr) == false) {
			fail_flag = true;
			VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "Failed to find memfd for %lx.\n", entries[i].addr);
			break;
		}
		list->list[i].size   = entries[i].length;
		plist[i].fd          = list->list[i].memfd;
		plist[i].len         = list->list[i].size;
	}
	list->count = nr_entries;
	list->flags = UDMABUF_FLAGS_CLOEXEC;
	if (fail_flag) {
		dmabuf_fd = -1;
	} else {
		dmabuf_fd = ioctl(udmabuf, UDMABUF_CREATE_LIST, list);
	}
	if (dmabuf_fd < 0) {
		virtio_gpu_dmabuf_destroy(info);
		free(info);
		info = NULL;
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "Failed to create the dmabuf. %s\n", strerror(errno));
	}
	if (info) {
		info->dmabuf_fd = dmabuf_fd;
		atomic_store(&info->ref_count, 1);
	}
	free(list);
	return info;
}

static void
virtio_gpu_cmd_create_blob(struct virtio_gpu_command *cmd)
{
	struct virtioGpuHostCtx *gpu;
	struct virtio_gpu_resource_create_blob req;
	struct virtio_gpu_mem_entry *entries;
	struct virtio_gpu_resource_2d *r2d;
	struct virtio_gpu_ctrl_hdr resp;
	int i;
	uint8_t *pbuf;
	struct iovec *iov;
	PHYS_ADDR hvaddr;

        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"VIRTIO_GPU_CMD_RESOURCE_CREATE_BLOB\n");

	gpu = cmd->gpu;

	memcpy(&req, cmd->iov[0].iov_base, sizeof(req));
	cmd->iolen = sizeof(resp);
	memset(&resp, 0, sizeof(resp));
	virtio_gpu_update_resp_fence(&cmd->hdr, &resp);

	if (req.resource_id == 0) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_INFO, "invalid resource id in cmd.\n");
		resp.type = VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;
		memcpy(cmd->iov[cmd->iovcnt - 1].iov_base, &resp, sizeof(resp));
		return;
	}

	/*
	 * 1. Per VIRTIO GPU specification,
	 *    'cmd->iovcnt' = 'nr_entries' of 'struct virtio_gpu_resource_create_blob' + 2,
	 *    where 'nr_entries' is number of instance of 'struct virtio_gpu_mem_entry'.
	 *    2. Function 'virtio_gpu_bh(void *data)' guarantees cmd->iovcnt >=1.
	 */
	if (cmd->iovcnt < 2) {
		resp.type = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
		memcpy(cmd->iov[cmd->iovcnt - 1].iov_base, &resp, sizeof(resp));
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "invalid memory entry.\n");
		return;
	}

	if ((req.blob_mem != VIRTIO_GPU_BLOB_MEM_GUEST) ||
		(req.blob_flags != VIRTIO_GPU_BLOB_FLAG_USE_SHAREABLE)) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_INFO, "invalid create_blob parameter for %d.\n", req.resource_id);
		resp.type = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
		memcpy(cmd->iov[cmd->iovcnt - 1].iov_base, &resp, sizeof(resp));
		return;

	}
	r2d = virtio_gpu_find_resource_2d(cmd->gpu, req.resource_id);
	if (r2d) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_INFO, "resource %d already exists.\n", req.resource_id);
		resp.type = VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;
		memcpy(cmd->iov[cmd->iovcnt - 1].iov_base, &resp, sizeof(resp));
		return;
	}

	r2d = (struct virtio_gpu_resource_2d *)calloc(1,
			sizeof(struct virtio_gpu_resource_2d));
	if (!r2d) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "memory allocation for r2d failed.\n");
		resp.type = VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY;
		memcpy(cmd->iov[cmd->iovcnt - 1].iov_base, &resp, sizeof(resp));
		return;
	}

	r2d->resource_id = req.resource_id;

	if (req.nr_entries > 0) {
		entries = calloc(req.nr_entries, sizeof(struct virtio_gpu_mem_entry));
		if (!entries) {
			VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "memory allocation for entries failed.\n");
			free(r2d);
			resp.type = VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY;
			memcpy(cmd->iov[cmd->iovcnt - 1].iov_base, &resp, sizeof(resp));
			return;
		}
		pbuf = (uint8_t *)entries;
		for (i = 1; i < (cmd->iovcnt - 1); i++) {
			memcpy(pbuf, cmd->iov[i].iov_base, cmd->iov[i].iov_len);
			pbuf += cmd->iov[i].iov_len;
		}
		if (req.size > CURSOR_BLOB_SIZE) {
			/* Try to create the dma buf */
			VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"create the dma buf\n");

			r2d->dma_info = virtio_gpu_create_udmabuf(cmd->gpu,
					entries,
					req.nr_entries);
			if (r2d->dma_info == NULL) {
				VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR,"dma buf creation failed\n");

				free(entries);
				resp.type = VIRTIO_GPU_RESP_ERR_UNSPEC;
				memcpy(cmd->iov[cmd->iovcnt - 1].iov_base, &resp, sizeof(resp));
				return;
			}
			r2d->blob = true;
		} else {
			/* Cursor resource with 64x64 and PIXMAN_a8r8g8b8 format.
			 * Or when it fails to create dmabuf
			 */
			VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"create cursor resource\n");

			r2d->width = 64;
			r2d->height = 64;
			r2d->format = PIXMAN_a8r8g8b8;
			r2d->image = pixman_image_create_bits(
					r2d->format, r2d->width, r2d->height, NULL, 0);

			iov = malloc(req.nr_entries * sizeof(struct iovec));
			if (!iov) {
				VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR,"memory alloc failed\n");
				free(entries);
				free(r2d);
				resp.type = VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY;
				memcpy(cmd->iov[cmd->iovcnt - 1].iov_base, &resp, sizeof(resp));
				return;
			}
			r2d->iov = iov;

			r2d->iovcnt = req.nr_entries;
			for (i = 0; i < req.nr_entries; i++) {
				if (virtioHostPhyaddrG2H(
						&gpu->vhost,
						entries[i].addr,
						&hvaddr)) {
					VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR,"failed to translate guest addr (0x%lx) to host\n", entries[i].addr);

				    	free(iov);
					free(entries);
					free(r2d);
					resp.type = VIRTIO_GPU_RESP_ERR_UNSPEC;
					memcpy(cmd->iov[cmd->iovcnt - 1].iov_base, &resp, sizeof(resp));
					return;
				}

				r2d->iov[i].iov_base = (void *)hvaddr;
				r2d->iov[i].iov_len = entries[i].length;
			}
		}

		free(entries);
	}
	resp.type = VIRTIO_GPU_RESP_OK_NODATA;
	LIST_INSERT_HEAD(&cmd->gpu->r2d_list, r2d, link);
	memcpy(cmd->iov[cmd->iovcnt - 1].iov_base, &resp, sizeof(resp));
}

static void
virtio_gpu_cmd_set_scanout_blob(struct virtio_gpu_command *cmd)
{
	struct virtio_gpu_set_scanout_blob req;
	struct virtio_gpu_resource_2d *r2d;
	struct virtio_gpu_ctrl_hdr resp;
	struct surface surf;
	uint32_t drm_fourcc;
	struct virtioGpuHostCtx *gpu;
	struct virtio_gpu_scanout *gpu_scanout;
	int bytes_pp;

        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"VIRTIO_GPU_CMD_SET_SCANOUT_BLOB\n");

	gpu = cmd->gpu;
	memset(&surf, 0, sizeof(surf));
	memcpy(&req, cmd->iov[0].iov_base, sizeof(req));
	cmd->iolen = sizeof(resp);
	memset(&resp, 0, sizeof(resp));
	virtio_gpu_update_resp_fence(&cmd->hdr, &resp);

	if (req.scanout_id >= gpu->scanout_num) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "Invalid scanout_id %d\n", req.scanout_id);
		resp.type = VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID;
		memcpy(cmd->iov[cmd->iovcnt - 1].iov_base, &resp, sizeof(resp));
		return;
	}
	gpu_scanout = gpu->gpu_scanouts + req.scanout_id;
	gpu_scanout->scanout_id = req.scanout_id;
	if (req.resource_id == 0) {
		virtio_gpu_update_scanout(gpu, req.scanout_id, 0, &req.r);
		resp.type = VIRTIO_GPU_RESP_OK_NODATA;
		memcpy(cmd->iov[cmd->iovcnt - 1].iov_base, &resp, sizeof(resp));
		vdpy_surface_set(gpu->vdpy_handle, req.scanout_id, NULL);
		return;
	}
	r2d = virtio_gpu_find_resource_2d(cmd->gpu, req.resource_id);
	if (r2d == NULL) {
		resp.type = VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;
		memcpy(cmd->iov[cmd->iovcnt - 1].iov_base, &resp, sizeof(resp));
		return;
	}
	if (r2d->blob == false) {
		/* Maybe the resource  is not blob, fallback to set_scanout */
		virtio_gpu_cmd_set_scanout(cmd);
		return;
	}

	virtio_gpu_update_scanout(gpu, req.scanout_id, req.resource_id, &req.r);
	virtio_gpu_dmabuf_ref(r2d->dma_info);
	surf.width = req.r.width;
	surf.height = req.r.height;
	surf.x = req.r.x;
	surf.y = req.r.y;
	surf.stride = req.strides[0];
	surf.dma_info.dmabuf_fd = r2d->dma_info->dmabuf_fd;
	surf.surf_type = SURFACE_DMABUF;
	bytes_pp = 4;
	switch (req.format) {
	case VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM:
		drm_fourcc = DRM_FORMAT_XRGB8888;
		break;
	case VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM:
		drm_fourcc = DRM_FORMAT_ARGB8888;
		break;
	case VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM:
		drm_fourcc = DRM_FORMAT_ABGR8888;
		break;
	case VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM:
		drm_fourcc = DRM_FORMAT_XBGR8888;
		break;
	default:
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "unuspported surface format %d.\n", req.format);
		drm_fourcc = DRM_FORMAT_ARGB8888;
		break;
	}
	surf.dma_info.dmabuf_offset = req.offsets[0] + bytes_pp * surf.x + surf.y * surf.stride;
	surf.dma_info.surf_fourcc = drm_fourcc;
	vdpy_surface_set(gpu->vdpy_handle, req.scanout_id, &surf);
	resp.type = VIRTIO_GPU_RESP_OK_NODATA;
	memcpy(cmd->iov[cmd->iovcnt - 1].iov_base, &resp, sizeof(resp));
	virtio_gpu_dmabuf_unref(r2d->dma_info);
	return;
}

static void
virtio_gpu_bh(void *data)
{
	struct virtioHost *vhost;
	struct virtioGpuHostCtx *vGpuHostCtx;
	struct virtio_gpu_command cmd;
	struct iovec iov[VIRTIO_GPU_MAXSEGS];
	struct virtioHostBuf bufList[VIRTIO_GPU_MAXSEGS];
	int n;
	int i;
	uint16_t idx;
	bool bsprocessed;
        struct virtioHostQueue *pQueue = (struct virtioHostQueue *)data;
        int n_to_get = MIN(pQueue->vRing.num, VIRTIO_GPU_MAXSEGS);

	vGpuHostCtx = (struct virtioGpuHostCtx *)(pQueue->vHost);
	vhost = (struct virtioHost *)vGpuHostCtx;
	cmd.gpu = vGpuHostCtx;
	cmd.iolen = 1;

	while (1) {
		n = virtioHostQueueGetBuf(pQueue, &idx, bufList, n_to_get);;
		if (n < 0) {
			VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "virtio-gpu: invalid descriptors or too many buffers\n");

			/* 
			 * the virtio host library seems to also return -1 when
			 * it finds that the number of available buffers in
			 * the buf chain exceeds maxBuf.
			 */
			if (errno == ENOSPC) {
				virtio_gpu_cmd_unspec(&cmd);
				continue;
			}
			return;
		}
		if (n == 0) {
			VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG, "virtio-gpu: no available descriptors\n");
			return;
		}

		for (i = 0; i < n; i++) {
			iov[i].iov_base = bufList[i].buf;
			iov[i].iov_len = bufList[i].len;
		}
		cmd.iovcnt = n;
		cmd.iov = iov;
		memcpy(&cmd.hdr, iov[0].iov_base,
			sizeof(struct virtio_gpu_ctrl_hdr));

		bsprocessed = true;
		switch (cmd.hdr.type) {

		case VIRTIO_GPU_CMD_UPDATE_CURSOR:
			virtio_gpu_cmd_update_cursor(&cmd);
			break;

		case VIRTIO_GPU_CMD_MOVE_CURSOR:
			virtio_gpu_cmd_move_cursor(&cmd);
			break;

		case VIRTIO_GPU_CMD_GET_EDID:
			virtio_gpu_cmd_get_edid(&cmd);
			break;

		case VIRTIO_GPU_CMD_GET_DISPLAY_INFO:
			virtio_gpu_cmd_get_display_info(&cmd);
			break;

                case VIRTIO_GPU_CMD_RESOURCE_CREATE_BLOB:
                        if (!virtio_gpu_blob_supported(vGpuHostCtx)) {
                                virtio_gpu_cmd_unspec(&cmd);
                                break;
                        }
                        virtio_gpu_cmd_create_blob(&cmd);
                        break;

                case VIRTIO_GPU_CMD_SET_SCANOUT_BLOB:
                        if (!virtio_gpu_blob_supported(vGpuHostCtx)) {
                                virtio_gpu_cmd_unspec(&cmd);
                                break;
                        }
                        virtio_gpu_cmd_set_scanout_blob(&cmd);
                        break;

                default:
			bsprocessed = false;
                        break;
                }

		if (bsprocessed) {
			/* release the buffer and send INT to virtio FE driver */
                	(void)virtioHostQueueRelBuf(pQueue, idx, cmd.iolen);
			(void)virtioHostQueueNotify(pQueue);
			continue;
		}

#ifdef INCLUDE_VIRGLRENDERER_SUPPORT
		virtio_gpu_cmd_gl_process(pQueue, idx, &cmd);
#else

                switch (cmd.hdr.type) {

		case VIRTIO_GPU_CMD_RESOURCE_CREATE_2D:
			virtio_gpu_cmd_resource_create_2d(&cmd);
			break;

		case VIRTIO_GPU_CMD_RESOURCE_UNREF:
			virtio_gpu_cmd_resource_unref(&cmd);
			break;

		case VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING:
			virtio_gpu_cmd_resource_attach_backing(&cmd);
			break;

		case VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING:
			virtio_gpu_cmd_resource_detach_backing(&cmd);
			break;

		case VIRTIO_GPU_CMD_SET_SCANOUT:
			virtio_gpu_cmd_set_scanout(&cmd);
			break;

		case VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D:
			virtio_gpu_cmd_transfer_to_host_2d(&cmd);
			break;

		case VIRTIO_GPU_CMD_RESOURCE_FLUSH:
			virtio_gpu_cmd_resource_flush(&cmd);
			break;

		default:
			/* VIRTIO_GPU_CMD_RESOURCE_UNREF */
			virtio_gpu_cmd_unspec(&cmd);
			break;
		}

		/* release the buffer and send INT to virtio FE driver */
		(void)virtioHostQueueRelBuf(pQueue, idx, cmd.iolen);
		(void)virtioHostQueueNotify(pQueue);

#endif /* INCLUDE_VIRGLRENDERER_SUPPORT */

	}
}

void
virtio_gpu_notify_queue(struct virtioHostQueue *pQueue)
{
        struct virtioGpuHostCtx *gpu;

	gpu = (struct virtioGpuHostCtx *)(pQueue->vHost);
	gpu->bh.data = pQueue;
	vdpy_submit_bh(gpu->vdpy_handle, &gpu->bh);
}

static void
virtio_gpu_cmd_update_cursor(struct virtio_gpu_command *cmd)
{
	struct virtio_gpu_update_cursor req;
	struct virtio_gpu_resource_2d *r2d;
	struct cursor cur;
	struct virtioGpuHostCtx *gpu;

        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"VIRTIO_GPU_CMD_UPDATE_CURSOR\n");

	gpu = cmd->gpu;
	memcpy(&req, cmd->iov[0].iov_base, sizeof(req));
	if (req.resource_id > 0) {
		r2d = virtio_gpu_find_resource_2d(cmd->gpu, req.resource_id);
		if (r2d == NULL) {
			VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "Illegal resource id %d\n", req.resource_id);
			return;
		}
		cur.x = req.pos.x;
		cur.y = req.pos.y;
		cur.hot_x = req.hot_x;
		cur.hot_y = req.hot_y;
		cur.width = r2d->width;
		cur.height = r2d->height;
		pixman_image_ref(r2d->image);
		cur.data = pixman_image_get_data(r2d->image);
		vdpy_cursor_define(gpu->vdpy_handle, req.pos.scanout_id, &cur);
		pixman_image_unref(r2d->image);
	}
}

static void
virtio_gpu_cmd_move_cursor(struct virtio_gpu_command *cmd)
{
	struct virtio_gpu_update_cursor req;
	struct virtioGpuHostCtx *gpu;

        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_DBUG,"VIRTIO_GPU_CMD_MOVE_CURSOR\n");

	gpu = cmd->gpu;
	memcpy(&req, cmd->iov[0].iov_base, sizeof(req));
	vdpy_cursor_move(gpu->vdpy_handle, req.pos.scanout_id, req.pos.x, req.pos.y);
}

int
virtio_gpu_init(struct virtioGpuHostDev *pGpuHostDev)
{
	struct virtioGpuHostCtx *gpu;
	int rc = 0;
	struct display_info info;
	int prot;
	int vscrs_num_added;

        gpu = (struct virtioGpuHostCtx *)pGpuHostDev;

        gpu->feature = (1UL << VIRTIO_F_VERSION_1) |
                        (1UL << VIRTIO_RING_F_INDIRECT_DESC) |
                        (1UL << VIRTIO_GPU_F_EDID);

        gpu->is_blob_supported = vdpy_blob_support();
        if (gpu->is_blob_supported) {
                gpu->feature |= (1UL << VIRTIO_GPU_F_RESOURCE_BLOB);
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_INFO, "VIRTIO_GPU_F_RESOURCE_BLOB supported\n");
	} else {
                VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_INFO, "VIRTIO_GPU_F_RESOURCE_BLOB not supported\n");
	}

        if (!virtio_gpu_init_once) {
		gpu->gpu_scanouts = calloc(VSCREEN_MAX_NUM, sizeof(struct virtio_gpu_scanout));
		if (gpu->gpu_scanouts == NULL) {
			VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "out of memory for gpu_scanouts\n");
			return -1;
		}

		/* create a thread for mevent_dispatch */
		if (pthread_create(&mevent_dispatch_td, NULL,
			mevent_dispatch_thread, NULL)) {
			VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "failed to create mevent dispatch thread\n");
			free(gpu->gpu_scanouts);
			return -1;
		}

		/* Initialize the ctrl/cursor_bh_task */
		gpu->bh.task_cb = virtio_gpu_bh;

		/* prepare the config space */
		gpu->cfg.events_read = 0;
		gpu->cfg.events_clear = 0;
		gpu->cfg.num_scanouts = 0;
		gpu->cfg.num_capsets = 0;

		LIST_INIT(&gpu->r2d_list);
	}

	/* initialize gfx ui */
	vscrs_num_added = gfx_ui_init(pGpuHostDev->beDevArgs.bePath,
				      pGpuHostDev->beDevArgs.channel->channelId);
	if (vscrs_num_added < 0) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "gfx ui initialize failed\n");
		goto init_fail;
        }

	gpu->vdpy_handle = vdpy_init(&scanout_num);
	if ((!gpu->vdpy_handle) || (scanout_num == 0)) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "vdpy_init failed\n");
		goto init_fail;
	}

	gpu->scanout_num += vscrs_num_added;
	gpu->cfg.num_scanouts = gpu->scanout_num;

	VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_INFO, "gpu->scanout_num=%d\n",  gpu->scanout_num);

        if (!virtio_gpu_init_once) {
#ifdef INCLUDE_VIRGLRENDERER_SUPPORT
                rc = virtio_gpu_virgl_init(gpu);
                if (rc) {
                        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "virgl init failed: %d.\n", rc);
                        goto init_fail;
                }
                virgl_supported = true;
#endif
		virtio_gpu_init_once = true;
	}

#ifdef INCLUDE_VIRGLRENDERER_SUPPORT
	if (virgl_supported) {
		gpu->feature |= 1 << VIRTIO_GPU_F_VIRGL;
	}
#endif

	return 0;

init_fail:
	free(gpu->gpu_scanouts);
	return -1;
}
