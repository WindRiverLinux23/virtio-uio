/* virtio_host_gpu.h - virtio GPU host driver header */

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

/*
modification history
--------------------
28jan24,qsn  written
*/

#ifndef __INCvirtioHostGpuh
#define __INCvirtioHostGpuh

#include <sys/uio.h>
#include <pthread.h>

#include "virtio_gpu.h"
#include "vdisplay.h"

#define MIN(a,b) (((a)<(b))?(a):(b))

/*
 * Virtqueue buf chain size.
 */
#define VIRTIO_GPU_MAXSEGS      256

#define CHANNELS_MAX_NUM 16

#define VSCREEN_MAX_NUM 16

#define VIRTIO_GPU_NM_QUEUES      2     /* virtio gpu device has 2 queues */
#define VIRTIO_GPU_CONTROLQ       0
#define VIRTIO_GPU_CURSORQ        1

#define VIRTIO_GPU_QUEUE_MAX_NUM  256

#define VIRTIO_GPU_EDID_SIZE    384

/* If the blob size is less than 16K, it is regarded as the
 * cursor_buffer.
 * So it is not mapped as dma-buf.
 */
#define CURSOR_BLOB_SIZE        (16 * 1024)

#define VIRTIO_GPU_DEV_DBG_ON
#ifdef VIRTIO_GPU_DEV_DBG_ON

#define VIRTIO_GPU_DEV_DBG_OFF             0x00000000
#define VIRTIO_GPU_DEV_DBG_ISR             0x00000001
#define VIRTIO_GPU_DEV_DBG_ARGS            0x00000002
#define VIRTIO_GPU_DEV_DBG_ERR             0x00000004
#define VIRTIO_GPU_DEV_DBG_INFO            0x00000008
#define VIRTIO_GPU_DEV_DBG_DBUG            0x00000010
#define VIRTIO_GPU_DEV_DBG_ALL             0xffffffff

static uint32_t virtioGpuDevDbgMask = VIRTIO_GPU_DEV_DBG_ERR | VIRTIO_GPU_DEV_DBG_INFO;

#undef VIRTIO_GPU_DEV_DBG
#define VIRTIO_GPU_DEV_DBG(mask, fmt, ...)                              \
        do {                                                            \
                if ((virtioGpuDevDbgMask & (mask)) ||                   \
                    ((mask) == VIRTIO_GPU_DEV_DBG_ALL)) {               \
                        printf("%d: %s: " fmt, __LINE__, __func__,     \
                               ##__VA_ARGS__);                          \
                }                                                       \
        }                                                               \
while ((false))
#else
#define VIRTIO_GPU_DEV_DBG(...)
#endif  /* VIRTIO_GPU_DEV_DBG_ON */

struct dma_buf_info_list {
        int fd;
	void *mapped_addr;
	size_t len;
};

struct dma_buf_info {
        int32_t ref_count;
        int dmabuf_fd;

	struct dma_buf_info_list *plist;
	int nr_entries;
};

struct virtio_gpu_resource_2d {
        uint32_t resource_id;
        uint32_t width;
        uint32_t height;
        uint32_t format;
        pixman_image_t *image;
        struct iovec *iov;
        uint32_t iovcnt;
        bool blob;
        struct dma_buf_info *dma_info;
        LIST_ENTRY(virtio_gpu_resource_2d) link;
};

struct virtio_gpu_scanout {
        int scanout_id;
        uint32_t resource_id;
        struct virtio_gpu_rect scanout_rect;
        pixman_image_t *cur_img;
        struct dma_buf_info *dma_buf;
        bool is_active;
};

struct virtio_gpu_command {
        struct virtio_gpu_ctrl_hdr hdr;
        struct virtioGpuHostCtx *gpu;
        struct virtioHostBuf *bufList;
        struct iovec *iov;
        uint32_t iovcnt;
        bool     done;
	uint32_t resp_type;	
        uint32_t iolen;
};

struct virtioGpuHostDev {
        struct virtioGpuHostCtx {
                struct virtioHost vhost;
                struct virtio_gpu_config cfg;
                uint64_t feature;

		int vdpy_handle;
		LIST_HEAD(,virtio_gpu_resource_2d) r2d_list;
		struct vdpy_display_bh bh;
		uint8_t edid[VIRTIO_GPU_EDID_SIZE];
		bool is_blob_supported;
		int scanout_num;
		struct virtio_gpu_scanout *gpu_scanouts;
        } gpuHostCtx;

        struct virtioGpuBeDevArgs {
                char bePath[PATH_MAX + 1];     /* backend path     */
                struct virtioChannel channel[1];
        } beDevArgs;

};

extern int  virtio_gpu_init(struct virtioGpuHostDev *pGpuHostDev);
extern void virtio_gpu_notify_queue(struct virtioHostQueue *pQueue);
extern void virtio_gpu_reset(void *vdev);
extern void virtio_gpu_update_resp_fence(struct virtio_gpu_ctrl_hdr *hdr,
                                         struct virtio_gpu_ctrl_hdr *resp);
extern int virtioHostPhyaddrG2H(struct virtioHost *vHost,
                                PHYS_ADDR gpaddr, PHYS_ADDR *hpaddr);

#endif /* __INCvirtioHostGpuh */

