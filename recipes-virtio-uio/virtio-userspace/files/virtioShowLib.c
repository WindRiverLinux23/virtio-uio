/* virtioShowLib.c - Virtio subsystem source file */

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
This library provides the interfaces which can be used for displaying
information about the elements in the Virtio subsystem.

The Virtio show facility is configured into VxWorks using either of the
following methods:
\is
\i 'Using Workbench'
With the kernel configurator include the INCLUDE_VIRTIO_LIB_SHOW component
under the FOLDER_VIRTIO_DRV folder.

\i 'Using the vxprj Command Line Tool'
Use the <add> command to include the INCLUDE_VIRTIO_LIB_SHOW component.
\ie

INCLUDE FILES:virtioLib.h virtioShowLib.h

SEE ALSO: virtioLib
*/
/* includes */

#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "virtioLib.h"
#include "virtioShowLib.h"

/* Virtio driver feature names */

typedef struct virtioDrvFeatures
{
	uint64_t    featureVal;
	char *      featureName;
} VIRTIO_DRV_FEATURE;

/* Virtio common feature name */

static VIRTIO_DRV_FEATURE virtioCommFeatureNames[] =
{
	{VIRTIO_F_VERSION_1,        "VIRTIO_F_VERSION_1"},
	{VIRTIO_F_RING_PACKED,      "VIRTIO_F_RING_PACKED"},
	{0,                         NULL                }
};


/*******************************************************************************
*
* virtioDescRingShow - show virtio queue descriptors
*
* This routine shows the details of descriptors present in a virtio queue.
*
* RETURNS: N/A
*
* ERRNO: N/A
*
* \NOMANUAL
*/
static void virtioDescRingShow(struct virtqueue* pQueue,
			       uint32_t size, int indent, int verbose)
{
	uint32_t idx;

	if (pQueue == NULL) {
		return;
        }

	if (size > pQueue->vRing.num) {
		printf("size must less that queue nums.\n");
		return;
        }

	struct vring_desc* desc = pQueue->vRing.desc;

	OUT(indent, "Descriptor ring: (%p)\n", pQueue->vRing.desc);
	OUT(indent, "nums = %d\n", pQueue->vRing.num);
	if (verbose > 1) {
		OUT(indent, "%s\n", VIRTIO_DESC_RING_SHOW);
		for (idx = 0; idx < size; idx++) {
			OUT(indent, "%04d   0x%016llx 0x%08x 0x%04x 0x%04x\n",
			    idx, desc->addr, desc->len, desc->flags,
			    desc->next);
			desc++;
		}
        }
}


/*******************************************************************************
*
* virtioAvailRingShow - show virtio queue avail ring information
*
* This routine shows the available ring information for a virtio queue.  It
* only prints the flags, index, and event registers unless verbose > 1, in
* which case it then also prints the ring entries as well.
*
* RETURNS: N/A
*
* ERRNO: N/A
*
* \NOMANUAL
*/

static void virtioAvailRingShow(struct virtqueue* pQueue, uint32_t size,
				int indent, int verbose)
{
	uint32_t idx;

	if (pQueue == NULL) {
		return;
        }

	if (size > pQueue->vRing.num) {
		printf("size must less that queue nums.\n");
		return;
        }

	struct vring_avail *avail = pQueue->vRing.avail;
	OUT(indent, "Avail ring: (%p)\n", avail);
	OUT(indent, "Flags = 0x%04x\n", avail->flags);
	OUT(indent, "Index = 0x%04x\n", avail->idx);
	OUT(indent, "Cached Index = 0x%04x\n", pQueue->availIdx);
	OUT(indent, "Event = 0x%04x\n", avail->ring[size]);

	if (verbose > 0) {
		OUT(indent, "Ring:\n");
		OUT(indent, "%s\n", VIRTIO_AVAIL_RING_SHOW);
		for (idx = 0; idx < size; idx++) {
			OUT(indent + 1, "%04d    0x%04x\n", idx, avail->ring[idx]);
		}
        }
}

/*******************************************************************************
*
* virtioUsedRingShow - show virtio queue used ring information
*
* This routine shows the used ring information for a virtio queue.  It
* only prints the flags, index, and event registers unless verbose > 1, in
* which case it then also prints the ring entries as well.
*
* RETURNS: N/A
*
* ERRNO: N/A
*
* \NOMANUAL
*/

static void virtioUsedRingShow(struct virtqueue* pQueue, uint32_t size,
			       int indent, int verbose)
{
	uint32_t idx;

	if (pQueue == NULL) {
		return;
        }

	if (size > pQueue->vRing.num) {
		printf("size must less that queue nums.\n");
		return;
        }

	struct vring_used *used = pQueue->vRing.used;

	OUT(indent, "Used ring: (%p)\n", used);
	OUT(indent, "Flags = 0x%04x\n",used->flags);
	OUT(indent, "Index = 0x%04x\n",used->idx);
	OUT(indent, "Cached Index = 0x%04x\n", pQueue->usedIdx);

	if (verbose > 0) {
		OUT(indent + 1, "Ring:\n");
		OUT(indent + 1, "%s\n", VIRTIO_USED_RING_SHOW);
		for (idx = 0; idx < size ; idx++) {
			OUT(indent + 1, "%04d    0x%08x 0x%08x\n",
			    idx, used->ring[idx].id,
			    used->ring[idx].len);
		}
        }
}

/*****************************************************************************
*
* virtioQueueShow - show virtio queue information
*
* This routine shows virtio queue information.
*
* RETURNS: N/A.
*
* ERRNO: N/A
*
*/

void virtioQueueShow(struct virtqueue* pQueue, uint32_t idx, int indent)
{
	const int verbose = 0;
	if (pQueue == NULL) {
		return;
        }

	OUT(indent, "Queue [%d]:[%s]\n", idx, pQueue->name);
	OUT(indent + 1, "queue addr [%p]\n", pQueue);

	/* show desc */
	OUT(indent + 1, "desc num [%d]\n", pQueue->vRing.num);
	OUT(indent + 1, "desc addr [%p]\n", pQueue->vRing.desc);
	virtioDescRingShow(pQueue, pQueue->vRing.num, indent + 2, verbose);
	OUT(indent + 1, "\n");

	/* show avail */
	OUT(indent + 1, "avail idx [%d]\n", pQueue->vRing.avail->idx);
	OUT(indent + 1, "cached avail idx [%d]\n", pQueue->availIdx);
	OUT(indent + 1, "avail flags [%d]\n", pQueue->vRing.avail->flags);
	OUT(indent + 1, "avail Flag Shadow [%d]\n", pQueue->availFlagShadow);
	OUT(indent + 1, "free DESC count [%d]\n", pQueue->num_free);
	virtioAvailRingShow(pQueue, pQueue->vRing.num, indent + 2, verbose);
	OUT(indent + 1, "\n");

	/* show used */
	OUT(indent + 1, "used idx [%d]\n", pQueue->vRing.used->idx);
	OUT(indent + 1, "cached used idx [%d]\n", pQueue->usedIdx);
	OUT(indent + 1, "used flags [%d]\n", pQueue->vRing.used->flags);
	virtioUsedRingShow(pQueue, pQueue->vRing.num, indent + 2, verbose);
	OUT(indent + 1, "\n");
}

/*****************************************************************************
*
* virtioDevShowInternal - show virtio device information
*
* This routine shows virtio device information.
*
* RETURNS: N/A.
*
* ERRNO: N/A
*
*/

static void virtioDevShowInternal(struct virtio_device* vDev, void* pArg)
{
	const char* pDrvName = NULL;
	char drvName[VIRTIO_NAME_LEN];
	uint32_t idx = 0U;
	VIRTIO_SHOW_PARAM* vDevParm = NULL;
	int indent;
	size_t arraySize;
	struct virtioVsm *pDrvCtrl;

	if ((pArg == NULL) || (vDev == NULL)) {
		return;
        }

	pDrvCtrl = vDev->priv;
	vDevParm = (VIRTIO_SHOW_PARAM *)pArg;
	if ((vDevParm->vDev == NULL) || (vDevParm->vDev == vDev)) {
		indent = vDevParm->indent;

		printf("---------- Virtio Device Information ----------\n");

		/* show PCI or MMIO virtio device and address */
#if 0
		if (vDev->func->devShow != NULL) {
			vDev->func->devShow (vDev, indent);
		}
#endif
		/* show more virtio device information */

		OUT(indent + 1, "device id [%d]\n", vDev->id.device);
		OUT(indent + 1, "vendor id [0x%x]\n", vDev->id.vendor);
		OUT(indent + 1, "device features [0x%lx]\n", vDev->features);

		/* check matched virtio driver */

		if (vDev->priv == NULL) {
			OUT(indent + 1, "matched driver [%s]\n", "orphan");
			return;
		}

		/* show virtio queue information */

		OUT(indent + 1, "queue numbers [0x%08x]\n", vDev->nVqs);
		for (idx = 0U; idx < vDev->nVqs; idx++) {
			virtioQueueShow(vDev->queues[idx], idx, indent);
		}
		printf("\n");
        }
}

/*****************************************************************************
*
* virtioDevShow - show virtio device information
*
* This routine shows virtio device information.
*
* RETURNS: N/A.
*
* ERRNO: N/A
*
*/

void virtioDevShow(struct virtio_device* pVirtioDev, int indent)
{
	VIRTIO_SHOW_PARAM vDevParm;

	vDevParm.vDev = pVirtioDev;
	vDevParm.indent = indent;
	virtioDevShowInternal(pVirtioDev, &vDevParm);

	return;
}

