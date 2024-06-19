/* virtioShowLib.h - virtio show routines header file */

/*
 * Copyright (c) 2024 Wind River Systems, Inc.
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
DESCRIPTION

This library provides the Virtio show routines.
*/

#ifndef __INCvirtioShowLibh
#define __INCvirtioShowLibh

/* defines */

/* virtio show output format */

#define VIRTIO_DESC_RING_SHOW   "index       addr          len        flags  next"
#define VIRTIO_AVAIL_RING_SHOW  "availIdx ringIdx"
#define VIRTIO_USED_RING_SHOW   "usedIdx ringIdx    bufferLen"
#define OUT(indent, fmt, ...)						\
	do {								\
		printf("%*s" fmt, (indent * 3), "", ##__VA_ARGS__);	\
	}								\
	while(false)

/* typedefs */

typedef struct virtioShowParam
    {
    struct virtio_device *   vDev;
    int                     indent;
    } VIRTIO_SHOW_PARAM;

/* Show virtio device/driver information */

void virtioDevShow (struct virtio_device* pVirtioDev, int indent);
void virtioHostDevShow (void);
#endif /* __INCvirtioShowLibh */
