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
 * The VirtIO uio driver sample
 */

#ifndef _UIO_VIRTIO_H_
#define _UIO_VIRTIO_H_

#include <linux/ioctl.h>
#include <linux/vhost.h>
#include <linux/types.h>

struct virtio_region {
        uint32_t indx;
        uint32_t offs;
        uint64_t addr;
        uint64_t phys_addr;
        uint64_t size;
};

#define VHOST_VIRTIO_ADD_REGION _IOWR(VHOST_VIRTIO, 0x90, struct virtio_region)
#define VHOST_VIRTIO_GET_REGION _IOWR(VHOST_VIRTIO, 0x91, struct virtio_region)
#define VHOST_VIRTIO_ALLOC_REGION _IOWR(VHOST_VIRTIO, 0x92, struct virtio_region)

#define VIRTIO_CTRL_NAME "virtio_ctrl"

#endif /* _UIO_VIRTIO_H_ */
