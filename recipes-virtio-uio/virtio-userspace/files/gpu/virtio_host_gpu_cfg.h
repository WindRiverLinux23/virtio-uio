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

#ifndef __INCvirtioHostGpuCfgh
#define __INCvirtioHostGpuCfgh

#if 0
#define INCLUDE_VIRGLRENDERER_SUPPORT
#endif

#define VIRTIO_GPU_MAXSEGS 256

#define CHANNELS_MAX_NUM 16

#define VSCREEN_MAX_NUM 16

#define VIRTIO_GPU_QUEUE_MAX_NUM 256

#define VIRTIO_GPU_EDID_SIZE 384

#define XDG_RUNTIME_DIR_NAME "/run/user/root"

#undef VIRTIO_GPU_DEV_DBG_ON
#ifdef VIRTIO_GPU_DEV_DBG_ON

#define VIRTIO_GPU_DEV_DBG_OFF             0x00000000
#define VIRTIO_GPU_DEV_DBG_ISR             0x00000001
#define VIRTIO_GPU_DEV_DBG_ARGS            0x00000002
#define VIRTIO_GPU_DEV_DBG_ERR             0x00000004
#define VIRTIO_GPU_DEV_DBG_INFO            0x00000008
#define VIRTIO_GPU_DEV_DBG_DBUG            0x00000010
#define VIRTIO_GPU_DEV_DBG_ALL             0xffffffff

static uint32_t virtioGpuDevDbgMask = VIRTIO_GPU_DEV_DBG_ALL;

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

#endif /* __INCvirtioHostGpuCfgh */
