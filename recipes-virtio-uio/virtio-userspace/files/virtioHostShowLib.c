/* virtioHostShowLib.c - Virtio host show library */

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
With the kernel configurator include the INCLUDE_VIRTIO_HOST_SHOW component
under the FOLDER_VIRTIO_DRV folder.

\i 'Using the vxprj Command Line Tool'
Use the <add> command to include the INCLUDE_VIRTIO_HOST_SHOW component.
\ie

INCLUDE FILES:virtioHostLib.h virtioHostShowLib.h

SEE ALSO: virtioHostLib
*/

/* includes */

#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "virtioHostLib.h"
#include "virtioShowLib.h"

/*******************************************************************************
*
* virtioHostDescRingShow - show virtio host queue descriptors
*
* This routine shows the details of descriptors present in a virtio host queue.
*
* RETURNS: N/A
*
* ERRNO: N/A
*
* \NOMANUAL
*/

static void virtioHostDescRingShow(struct virtioHostQueue* pQueue,
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

	OUT(indent, "Descriptor ring: (%p) \n", pQueue->vRing.desc);
	OUT(indent, "nums = %d\n", pQueue->vRing.num);
	if (verbose > 0) {
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
* virtioHostAvailRingShow - show virtio host queue avail ring information
*
* This routine shows the available ring information for a virtio host queue.
* It only prints the flags, index, and event registers unless verbose > 1, in
* which case it then also prints the ring entries as well.
*
* RETURNS: N/A
*
* ERRNO: N/A
*
* \NOMANUAL
*/

static void virtioHostAvailRingShow(struct virtioHostQueue* pQueue,
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

	struct vring_avail *avail = pQueue->vRing.avail;
	OUT(indent, "Avail ring: (%p)\n", avail);
	OUT(indent, "Flags = 0x%04x\n", avail->flags);
	OUT(indent, "Index = 0x%04x\n", avail->idx);
	OUT(indent, "Cached Index = 0x%04x\n", pQueue->availIdx);
	OUT(indent , "Event = 0x%04x\n", avail->ring[size]);

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
* virtioHostUsedRingShow - show virtio host queue used ring information
*
* This routine shows the used ring information for a virtio host queue.  It
* only prints the flags, index, and event registers unless verbose > 1, in
* which case it then also prints the ring entries as well.
*
* RETURNS: N/A
*
* ERRNO: N/A
*
* \NOMANUAL
*/

static void virtioHostUsedRingShow(struct virtioHostQueue* pQueue,
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


/*******************************************************************************
*
* virtioHostDevQueueShow - show virtio host queue information
*
* This routine shows virtio queue information.
*
* RETURNS: N/A.
*
* ERRNO: N/A
*
*/

static void virtioHostDevQueueShow(struct virtioHostQueue* pQueue, uint32_t indent)
{
	const int verbosity = 0;

	if (pQueue == NULL) {
		return;
        }

	OUT(indent, "queue : addr [%p]\n", pQueue);

	if (!virtioHostQueueReady (pQueue)) {
		OUT(indent, "queue not ready\n");
		return;
        }

	/* show desc */

	OUT(indent, "desc num [%d]\n", pQueue->vRing.num);
	OUT(indent, "desc addr [%p]\n\n", pQueue->vRing.desc);
	virtioHostDescRingShow(pQueue, pQueue->vRing.num, indent, verbosity);

	/* show avail */

	OUT(indent, "driver avail idx [%d]\n", pQueue->vRing.avail->idx);
	OUT(indent, "device avail idx [%d]\n", pQueue->availIdx);
	OUT(indent, "device avail flags [%d]\n\n", pQueue->vRing.avail->flags);
	virtioHostAvailRingShow(pQueue, pQueue->vRing.num, indent, verbosity);

	/* show used */

	OUT(indent, "driver used idx [%d]\n", pQueue->vRing.used->idx);
	OUT(indent, "device used idx [%d]\n", pQueue->usedIdx);
	OUT(indent, "device last used idx [%d]\n", pQueue->lastUsedIdx);
	OUT(indent, "driver used flags [%d]\n", pQueue->vRing.used->flags);
	OUT(indent, "device used flags shadow [%d]\n\n",pQueue->usedFlagShadow);
	virtioHostUsedRingShow(pQueue, pQueue->vRing.num, indent, verbosity);
}

/*******************************************************************************
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

static void virtioHostDevShowInternal(struct virtioHost* vHost, void* pArgs)
{
	uint32_t i;
	uint32_t indent = 0;

	OUT(indent + 1, "channel Id   [%d]\n", vHost->channelId);

	OUT(indent + 1, "vHost        [%p]\n", vHost);

	OUT(indent + 1, "host queue\n");
	for (i = 0; i < vHost->queueMax; i++) {
		OUT(indent + 1, "- queue[%d]  [%p]\n", i, &vHost->pQueue[i]);
		virtioHostDevQueueShow(&vHost->pQueue[i], indent + 2);
		OUT(indent + 1, "\n");
        }

	/* Memory map from guest VM to host VM */

	OUT(indent + 1, "memory map [%s]\n", vHost->pMaps->name);
	for (i = 0; i < vHost->pMaps->count; i++) {
		OUT(indent + 1, " - entry [%d]\n", i);

		OUT(indent + 2, " - host physical addr  [0x%016lx]\n",
		    vHost->pMaps->entry[i].hpaddr);
		OUT(indent + 2, " - host virtual addr   [%p]\n",
		    vHost->pMaps->entry[i].hvaddr);
		OUT(indent + 2, " - guest physical addr [0x%016lx]\n",
		    vHost->pMaps->entry[i].gpaddr);
		OUT(indent + 2, " - CPU real addr       [0x%016lx]\n",
		    vHost->pMaps->entry[i].cpaddr);
		OUT(indent + 2, " - memory size         [0x%016lx]\n",
		    vHost->pMaps->entry[i].size);
        }

	/* Shared memory map from host VM to guest VM */

	OUT(indent + 1, "shared memory map\n");
	for (i = 0; i < vHost->shmMax; i++) {
		OUT(indent + 1, " - entry [%d]\n", i);
		OUT(indent + 2, " - host physical addr  [0x%08x%08x]\n",
		    vHost->pHostShmReg[i].addr[1],
		    vHost->pHostShmReg[i].addr[0]);
		OUT(indent + 2, " - memory size         [0x%08x%08x]\n",
		    vHost->pHostShmReg[i].len[1],
		    vHost->pHostShmReg[i].len[0]);
        }

	OUT(indent + 1, "\n");
}

/*******************************************************************************
*
* virtioHostDevShow - show all virtio host devices
*
* This function displays information about virtio host device nodes, it shows
* all device nodes in the virtio host device list.
*
* RETURNS: N/A
*
* ERRNO: N/A
*
*/

void virtioHostDevShow(void)
{
	printf("-------- Virtio Host Device Information --------\n");
	virtioHostDevTravel(virtioHostDevShowInternal, NULL);
}
