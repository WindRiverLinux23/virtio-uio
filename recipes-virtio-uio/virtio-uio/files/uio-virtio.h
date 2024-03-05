/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Wind River Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */

/*
 * The VirtIO uio device driver
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
