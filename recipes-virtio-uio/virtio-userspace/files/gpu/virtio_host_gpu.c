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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <pthread.h>
#include <semaphore.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include "../virtioHostLib.h"
#include "virtio_host_gpu.h"

static int virtioHostGpuReset(struct virtioHost *);
static void virtioHostGpuNotify(struct virtioHostQueue *);
static int virtioHostGpuCfgRead(struct virtioHost *, uint64_t, uint64_t size, uint32_t *);
static int virtioHostGpuCfgWrite(struct virtioHost *, uint64_t, uint64_t, uint32_t);
static int virtioHostGpuCreate(struct virtioHostDev *);
static void virtioHostGpuShow(struct virtioHost *, uint32_t);

struct virtioHostOps virtioGpuHostOps = {
        .reset    = virtioHostGpuReset,
        .kick     = virtioHostGpuNotify,
        .reqRead  = virtioHostGpuCfgRead,
        .reqWrite = virtioHostGpuCfgWrite,
        .show     = virtioHostGpuShow,
};

static struct virtioHostDrvInfo virtioGpuHostDrvInfo =
{
        .typeId = VIRTIO_TYPE_GPU,
        .create = virtioHostGpuCreate,
};

static struct virtioGpuHostDev *gpuHostDevs[CHANNELS_MAX_NUM];
static uint32_t gpuHostDevNums = 0;

/*******************************************************************************
 *
 * virtioHostGpuDrvInit - initialize virtio-gpu host device driver
 *
 * This routine initializes the virtio-gpu host device driver.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

void virtioHostGpuDrvInit(void)
{
        virtioHostDrvRegister((struct virtioHostDrvInfo *)&virtioGpuHostDrvInfo);
}

/*******************************************************************************
 *
 * virtioHostGpuDrvRelease - release the virtio-gpu host device driver
 *
 * This routine releasees the virtio-gpu host device driver.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

void virtioHostGpuDrvRelease(void)
{
	struct virtioGpuHostCtx *pGpuHostCtx;
	int i;

	for (i = 0; i < gpuHostDevNums; i++) {
		pGpuHostCtx = (struct virtioGpuHostCtx *)gpuHostDevs[i];
		virtioHostRelease(&pGpuHostCtx->vhost);
		free(gpuHostDevs[i]);
	}
	gpuHostDevNums = 0;
}


/*******************************************************************************
 *
 * virtioHostGpuReset - reset virtio GPU device
 *
 * This routine is used to reset the virtio GPU device. All the configuration
 * settings set by customer driver will be cleared and all the backend
 * driver software flags are reset to initial status.
 *
 * RETURNS: 0, or -1 if failure raised in process of restarting the device.
 *
 * ERRNO: N/A
 */

static int virtioHostGpuReset(struct virtioHost *vHost)
{
        struct virtioGpuHostCtx *vGpuHostCtx;

        vGpuHostCtx = (struct virtioGpuHostCtx *)vHost;
        if (!vGpuHostCtx) {
                VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR,
                                "null vGpuHostCtx\n");
                return -1;
        }

	virtio_gpu_reset(vGpuHostCtx);

        return 0;
}

/*******************************************************************************
 *
 * virtioHostGpuNotify - notify there is a new arrived io-request
 *
 * This routine is used to notify the handler that an new recieved io-request
 * in virtio queue.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void virtioHostGpuNotify(struct virtioHostQueue *pQueue)
{
	uint32_t queue;

        if (!pQueue) {
                VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "null pQueue\n");
                return;
        }

	queue = (uint32_t)(pQueue - pQueue->vHost->pQueue);
	VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_INFO,
			"channelId(%u), queue(%u)\n", pQueue->vHost->channelId, queue);

	virtio_gpu_notify_queue(pQueue);

        return;
}

/*******************************************************************************
 *
 * virtioHostGpuCfgRead - read virtio block specific configuration register
 *
 * This routine is used to read virtio block specific configuration register,
 * the value read out is stored in the request buffer.
 *
 * RETURN: 0, or errno if the to be read register is non-existed.
 *
 * ERRNO: N/A
 */

static int virtioHostGpuCfgRead(struct virtioHost *vHost, uint64_t address,
                uint64_t size, uint32_t *pValue)
{
        struct virtioGpuHostCtx *pGpuHostCtx;
        uint8_t *cfgAddr;

        if (!vHost) {
                VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "null vHost\n");
                return -EINVAL;
        }

        pGpuHostCtx = (struct virtioGpuHostCtx *)vHost;

        cfgAddr = (uint8_t *)&pGpuHostCtx->cfg + address;

        (void)memcpy((void *)pValue, (void *)cfgAddr, (size_t)size);

        return 0;
}

/*******************************************************************************
 *
 * virtioHostGpuCfgWrite - set virtio block specific configuration register
 *
 * This routine is used to set virtio block specific configuration register,
 * the setting value is stored in the request buffer.
 *
 * RETURN: 0, or errno if the to be read register is non-existed.
 *
 * ERRNO: N/A
 */

static int virtioHostGpuCfgWrite(struct virtioHost *vHost, uint64_t address,
                uint64_t size, uint32_t value)
{
        struct virtioGpuHostCtx *pGpuHostCtx;
        uint8_t *cfgAddr;

        if (!vHost) {
                VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "null vHost\n");
                return -EINVAL;
        }

        if (address == offsetof(struct virtio_gpu_config, events_clear)) {
		pGpuHostCtx = (struct virtioGpuHostCtx *)vHost;
		cfgAddr = (uint8_t *)&pGpuHostCtx->cfg + address;
                (void)memcpy((void *)cfgAddr, (void *)&value, (size_t)size);
		pGpuHostCtx->cfg.events_read &= ~value;
		pGpuHostCtx->cfg.events_clear &= ~value;
                return 0;
        }

        VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR,
                        "failed to write to read-only register %ld\n",
                        host_virtio64_to_cpu(vHost, address));

        return -EINVAL;
}

/*******************************************************************************
 *
 * virtioHostGpuShow - virtio block host device show
 *
 * This routine shows the virtio GPU host device info.
 *
 * RETURN: 0 aleays.
 *
 * ERRNO: N/A
 */

static void virtioHostGpuShow(struct virtioHost * vHost, uint32_t indent)
{
}

/*******************************************************************************
*
* virtioHostPhyaddrG2H - convert guest physical ADDR to host physical ADDR
*
* This routine converts the guest VM view physical address specified by
* <gpaddr> to the host VM view physical address and fills to <vhaddr>.
*
* RETURNS: 0 when translate successfully.
*          -EINVAL when either of the two conditions is satisfied:
*            - <vHost> equals to NULL.
*            - <[vhaddr> equals to NULL.
*          -ENOENT when there is not an available memory map that could
*          be translate the guest physical address specified by <gpaddr>.
*
* ERRNO: N/A
*/

int virtioHostPhyaddrG2H(struct virtioHost *vHost,
                        PHYS_ADDR gpaddr,
                        PHYS_ADDR *hpaddr)
{
        struct virtio_map_entry *entry;
        uint32_t i;

        if (!vHost || !hpaddr) {
                VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR,
                                    "invalid input parameter\n");
                errno = EINVAL;
                return -1;
        }

        for (i = 0; i < vHost->pMaps->count; i++) {
                entry = &vHost->pMaps->entry[i];
                if ((gpaddr >= entry->gpaddr) &&
                    (gpaddr < entry->gpaddr + entry->size)) {
                        *hpaddr = (PHYS_ADDR)((gpaddr - entry->gpaddr)
                                              + entry->hpaddr);

                        return 0;
                }
        }

        errno = ENOENT;
        return -1;
}

/*******************************************************************************
 *
 * virtioHostGpuDevCreate - create virtio GPU device instance
 *
 * This routine creates and initializes virtio GPU device instance.
 *
 * RETURNS: 0, or -1 if any error is raised in process of the GPU device
 * context creation.
 *
 * ERRNO: N/A
 */

static int virtioHostGpuDevCreate(struct virtioGpuHostDev *pGpuHostDev)
{
	struct virtioGpuHostCtx *pGpuHostCtx;
	struct virtioGpuBeDevArgs *pGpuBeDevArgs;
	struct virtioHost *vhost;
	uint32_t devNum;
	int ret;

	vhost         = (struct virtioHost *)pGpuHostDev;
	pGpuHostCtx   = (struct virtioGpuHostCtx *)pGpuHostDev;
	pGpuBeDevArgs = &pGpuHostDev->beDevArgs;

        /* initialize the host gpu device */
        ret = virtio_gpu_init(pGpuHostDev);
        if (ret) {
                VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR,
                                "virtio host GPU device initialization failed %d\n",
                                ret);
                goto err;
        }

	vhost->channelId = pGpuBeDevArgs->channel->channelId;
	vhost->pMaps = pGpuBeDevArgs->channel->pMap;

	ret = virtioHostCreate(vhost,
			VIRTIO_DEV_ANY_ID,
			VIRTIO_TYPE_GPU,
			&pGpuHostCtx->feature,
			VIRTIO_GPU_NM_QUEUES,
			VIRTIO_GPU_QUEUE_MAX_NUM,
			0, NULL,
			&virtioGpuHostOps);
	if (ret) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR,
				"virtio GPU host context creation failed %d\n",
				ret);
		goto err;
	}

	gpuHostDevs[gpuHostDevNums++] = pGpuHostDev;
	return 0;

err:
        virtioHostGpuDrvRelease();
        return -1;
}


/*******************************************************************************
 *
 * virtioHostGpuCreate - create a virtio GPU device
 *
 * This routine creates the virtio GPU device backend driver.
 *
 * RETURNS: 0, or negative value of errno number if any error is raised
 * in process of the GPU device creation.
 *
 * ERRNO: N/A
 */

static int virtioHostGpuCreate(struct virtioHostDev *pHostDev)
{
	struct virtioGpuHostDev *pGpuHostDev;
        struct virtioGpuBeDevArgs *pBeDevArgs;
	int ret;

	VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_INFO, "virtioHostGpuCreate start\n");

	if (!pHostDev) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR,
				"pHostDev is NULL!\n");
		return -EINVAL;
	}

	/* the virtio channel number is always one */
	if (pHostDev->channelNum > 1) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "channel number is %d " \
                	"only one channel is supported\n", pHostDev->channelNum);
		return -EINVAL;
        }

	VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_INFO, "\n"
			"  typeId = %d args %s channelNum = %d\n" \
			"    - channel ID = %d \n"  \
			"      hpaddr = 0x%lx \n" \
			"      gpaddr = 0x%lx \n" \
			"      cpaddr = 0x%lx \n" \
			"      size   = 0x%lx \n",
			pHostDev->typeId, pHostDev->args, pHostDev->channelNum,
			pHostDev->channels[0].channelId,
			pHostDev->channels[0].pMap->entry->hpaddr,
			pHostDev->channels[0].pMap->entry->gpaddr,
			pHostDev->channels[0].pMap->entry->cpaddr,
			pHostDev->channels[0].pMap->entry->size);

	pGpuHostDev = calloc(1, sizeof(struct virtioGpuHostDev));
        if (!pGpuHostDev) {
                VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR,
                                "allocation of memory failed for virtio GPU !\n");
                return -ENOMEM;
        }

        /* allocate a buffer and copy the argument list to it */
        pBeDevArgs = &pGpuHostDev->beDevArgs;
	memcpy((void *)pBeDevArgs->bePath, pHostDev->args, PATH_MAX);
        memcpy((void *)pBeDevArgs->channel, (void *)pHostDev->channels, sizeof(struct virtioChannel));

        ret = virtioHostGpuDevCreate(pGpuHostDev);
        if (ret) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR,
				"virtioHostGpuDevCreate failed for virtio GPU !\n");
        } else {
        	VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_INFO, "virtioHostGpuCreate done\n");
	}

        return ret;
}
