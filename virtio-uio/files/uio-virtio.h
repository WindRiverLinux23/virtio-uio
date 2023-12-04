/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2023 Wind River Systems
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
        uint64_t size;
};

#define VHOST_VIRTIO_ADD_REGION _IOWR(VHOST_VIRTIO, 0x90, struct virtio_region)
#define VHOST_VIRTIO_GET_REGION _IOWR(VHOST_VIRTIO, 0x91, struct virtio_region)

#define VIRTIO_CTRL_NAME "virtio_ctrl"

#endif /* _UIO_VIRTIO_H_ */
