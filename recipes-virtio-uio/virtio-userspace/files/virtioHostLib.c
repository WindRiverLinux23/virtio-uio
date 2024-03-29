/* virtio host library */

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
DESCRIPTION

This is the virtio host library, it connect the virtio device simulator
and host service module, the host service module provide low level
communications, such as the ioreq from guest VM, and also could help
the virtio host device simulator send interrupt to guest OS. This library also
help the device simulator to handle virtio common things, such as virtio
device state, queue management, the BE driver only need to focuse on business
logic, such as configuration handling or queue handling.

*/

/* includes */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h>
#include <sys/mman.h>
#include <sched.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <linux/virtio_mmio.h>
#include "virtioHostLib.h"
#include "virtio_host_parser.h"
#include <syslog.h>

/* defines */
#define VIRTIO_STATUS_RESET       0x00u //zhe not defined in linux?

#undef VIRTIO_HOST_DBG
#ifdef VIRTIO_HOST_DBG

#define VIRTIO_HOST_DBG_OFF             0x00000000
#define VIRTIO_HOST_DBG_ERR             0x00000001
#define VIRTIO_HOST_DBG_IOREQ           0x00000002
#define VIRTIO_HOST_DBG_IRQREQ          0x00000004
#define VIRTIO_HOST_DBG_QUEUE           0x00000008
#define VIRTIO_HOST_DBG_CFG             0x00000010
#define VIRTIO_HOST_DBG_INFO            0x00000020
#define VIRTIO_HOST_DBG_ALL             0xffffffff

static uint32_t virtioHostDbgMask = VIRTIO_HOST_DBG_ERR;

#define VIRTIO_HOST_DBG_MSG(mask, fmt, ...)				\
	do {								\
		if ((virtioHostDbgMask & (mask)) ||			\
		    ((mask) == VIRTIO_HOST_DBG_ALL)) {			\
		    printf("%d: %s() " fmt, __LINE__, __func__,		\
			       ##__VA_ARGS__);				\
			fflush(stdout);					\
		}							\
	}								\
while ((false));
#define log_err(fmt, ...)					\
	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_ERR, fmt,		\
			   ##__VA_ARGS__)
#else
#undef VIRTIO_HOST_DBG_MSG
#define VIRTIO_HOST_DBG_MSG(...)
#define log_err(fmt, ...)					\
	syslog(LOG_ERR, "%d: %s() " fmt, __LINE__, __func__,	\
	       ##__VA_ARGS__)
#endif  /* VIRTIO_HOST_DBG */

#define VIRTIO_MMIO_MODERN_REG_VER          0x2

#define VIRTIO_MMIO_INT_VRING               (1 << 0)
#define VIRTIO_MMIO_INT_CONFIG              (1 << 1)

#define DEFINE_SPINLOCK(mutex) pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER
#define DEFINE_MUTEX(mutex) pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER

/*
 * The number of times to wait for vring data synchronizes.
 * Used only in development. Should be removed from production
 * code.
 */
#define FAKE_KICK_DEBUG_CYCLE 10

/* forward declarations */

static int virtioHostReset(struct virtioHost *);
static int virtioHostNotify(struct virtioHost *);
static int virtioHostQueueEnable(struct virtioHost *, uint32_t);
static int virtioHostSetStatus(struct virtioHost *, uint32_t);
static int virtioHostMapSetup(VIRTIO_VSM_ID, struct virtioMap *);

/* locals */
static TAILQ_HEAD(drvList, virtioHostDrvInfo) vHostCreateRtnList;
static TAILQ_HEAD(devList, virtioHost) vHostDeviceList;

static DEFINE_SPINLOCK(vHostDeviceLock);
static DEFINE_MUTEX(vHostDeviceMapLock);

static struct virtioHostVsm *pgVirtioHostVsm = NULL;
static VIRTIO_HOST_CFG_PARSER *pVirtioHostParser = NULL;
static VIRTIO_HOST_CFG_INFO virtioHostCfgInfo = {
	.pVirtioHostDev = NULL,
	.pMaps = NULL,
	.mapNum = 0
};

/*******************************************************************************
*
* virtioHostParserConnect - connect configuration parser handler
*
* This routine connects virtio host configuration parser handler
*
* RETURNS: 0 when the virtio host configuration parser connected successfully.
*          -1 when virtio host configuration parser already connected.
*          -EINVAL when any of the following condition are satisfied.
*            - <pCfgParser> is equal to NULL.
*            - the name field of <pCfgParser> is empty.
*            - the parserFn filed of <pCfgParser> is empty.
*            - the freeDevCfgsFn filed of <pCfgParser> is empty.
*            - the freeDevMapsFn of <pCfgParser> is empty.
*
* ERRNO: N/A
*
* \NOMANUAL
*/

int virtioHostParserConnect(VIRTIO_HOST_CFG_PARSER *pCfgParser)
{
	if (!pCfgParser) {
	    log_err( "null pCfgParser\n");
		errno = EINVAL;
		return -1;
	}

	if (!pCfgParser->name || !pCfgParser->parserFn ||
	    !pCfgParser->freeDevCfgsFn || !pCfgParser->freeDevMapsFn) {
		log_err("invalid pCfgParser\n");
		errno = EINVAL;
		return -1;
	}

	if (pVirtioHostParser) {
		log_err("virtio host parser already exists\n");
		return -1;
	}

	pVirtioHostParser = pCfgParser;

	return 0;
}


/*******************************************************************************
*
* virtioHostCfgParse - parser virtio host configuration data
*
* This routine parser the virtio host configuration data. All the available
* parsers are registered and listed in the global list vHostParserList.
* YAML parser is the first registered node as default.
*
* RETURNS: 0 when the virtio host configuration is parsed successfully.
*         -1 when configuration data can't be resolved.
*         -EINVAL when any of the following condition are satisfied.
*            - <pBuf> is equal to NULL.
*            - <bufLen> is equal to zero.
*            - <pVhostCfg> is equal to NULL.
*          -ENOTSUPP no parser is connected.
*
* ERRNO: N/A
*/
static int virtioHostCfgParse(char *pBuf, size_t bufLen,
		VIRTIO_HOST_CFG_INFO *pVhostCfg)
{
	if (!pBuf || (bufLen == 0) || !pVhostCfg) {
		log_err("input invalid!\n");
	        errno = EINVAL;
		return -1;
	}

	if (!pVirtioHostParser || !pVirtioHostParser->parserFn) {
		log_err("parser interface not connected!\n");
		errno = ENOTSUP;
		return -1;
	}

	if (pVirtioHostParser->parserFn(pBuf, bufLen, pVhostCfg) != 0) {
		log_err("configuration can't be resolved!\n");
		return -1;
	}

	return 0;
}

int virtioHostCfgFree(void)
{
	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO, "start\n");
	if (!pVirtioHostParser || !pVirtioHostParser->freeDevCfgsFn ||
			!pVirtioHostParser->freeDevMapsFn) {
		log_err("parser interface not connected\n");
		errno = EINVAL;
		return -1;
	}

	pVirtioHostParser->freeDevCfgsFn(virtioHostCfgInfo.pVirtioHostDev);
	pVirtioHostParser->freeDevMapsFn(virtioHostCfgInfo.pMaps,
					 virtioHostCfgInfo.mapNum);
	virtioHostCfgInfo.pVirtioHostDev = NULL;
	virtioHostCfgInfo.pMaps = NULL;
	virtioHostCfgInfo.mapNum = 0;
	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO, "done\n");
	return 0;
}


/*******************************************************************************
*
* virtioHostVsmShmRegionRelease - release virtio VSM share memory region
*
* This routine releases the given virtio VSM share memory region.
*
* RETURNS: N/A.
*
* ERRNO: N/A
*/

static void virtioHostVsmShmRegionRelease(struct virtioHostVsm *pVirtioHostVsm,
	struct virtioVsmShmRegion *pRegion)
{
	pVirtioHostVsm->vsmOps.shmRegionRelease(pVirtioHostVsm->vsmId,
			pRegion);
}

/*******************************************************************************
*
* virtioHostVsmShmRegionGet - get VSM device share memory
*
* This routine gets VSM share memory and map the memory to the kernel space.
* The share memory region ID of VSM is always is zero.
*
* RETURNS: 0, or -1 if getting the share memory or mapping failed.
*
* ERRNO: N/A
*/

static int virtioHostVsmShmRegionGet(struct virtioHostVsm *pVirtioHostVsm,
		struct virtioVsmShmRegion * pRegion)
{
	return (pVirtioHostVsm->vsmOps.shmRegionGet(pVirtioHostVsm->vsmId,
				pRegion));
}

/*******************************************************************************
*
* virtioHostVsmSetMap - set the given guest VM memory map
*
* This routine sets the given guest VM memory map to system.
*
* RETURNS: N/A.
*
* ERRNO: N/A
*/

static void virtioHostVsmSetGuestMap(struct virtioHostVsm *pVirtioHostVsm,
		struct virtioMap **pMaps, uint32_t mapNum)
{
	pVirtioHostVsm->pMaps  = pMaps;
	pVirtioHostVsm->mapNum = mapNum;
}

/*******************************************************************************
*
* virtioHostVsmGetMap - set guest VM memory map
*
* This routine gets guest VM memory map.
*
* RETURNS: N/A.
*
* ERRNO: N/A
*/

static void virtioHostVsmGetGuestMap(struct virtioHostVsm *pVirtioHostVsm,
		struct virtioMap ***ppMaps, uint32_t *pMapNum)
{
	*ppMaps  = pVirtioHostVsm->pMaps;
	*pMapNum = pVirtioHostVsm->mapNum;
}

/*******************************************************************************
*
* virtioHostHpaConvertToCpa - convert host physical address to CPU address
*
* This routine converts the host VM physical address to CPU real address.
*
* RETURNS: 0 when the host VM physical address to CPU real address successfully.
*          -EINVAL when <pCpuAddr> is equal to NULL.
*          -ENOTSUPP any of the following conditions are satisfied
*            - VSM driver is not initialized.
*            - there is no guest VM memory map initialized.
*          -ENOENT when the host physical address is not in the guest memory
*                  map regions.
*
* ERRNO: N/A
*
* \NOMANUAL
*/

int virtioHostHpaConvertToCpa(PHYS_ADDR hostPhysAddr, PHYS_ADDR *pCpuAddr)
{
	struct virtioMap **pMaps;
	uint32_t mapNum;
	uint32_t i;
	uint32_t j;
	PHYS_ADDR hpBase;
	PHYS_ADDR hpEnd;
	PHYS_ADDR cpBase;

	if (!pCpuAddr) {
		errno = EINVAL;
		return -1;
	}

	if (!pgVirtioHostVsm) {
		log_err("virtio VSM is not initialized!\n");
		errno = ENOTSUP;
		return -1;
	}

	virtioHostVsmGetGuestMap(pgVirtioHostVsm, &pMaps, &mapNum);
	if (!pMaps || (mapNum == 0)) {
		errno = ENOTSUP;
		return -1;
	}

	for (i = 0; i < mapNum; i++) {
		if (pMaps[i]->refCnt == 0)
			continue; /* the map entry has no guest map */

		for (j = 0; j < pMaps[i]->count; j++) {
			hpBase = pMaps[i]->entry[j].hpaddr;
			hpEnd  = hpBase + pMaps[i]->entry[j].size - 1;
			cpBase = pMaps[i]->entry[j].cpaddr;

			if ((hostPhysAddr >= hpBase) &&
			    (hostPhysAddr <= hpEnd)) {
				*pCpuAddr = cpBase + (hostPhysAddr - hpBase);
				return  0;
			}
		}
	}

	log_err("the address not in any guest map region!\n");

	errno = ENOENT;
	return -1;
}


/*******************************************************************************
*
* virtioHostDrvRegister - register virtio host device driver
*
* This routine registers the virtio host device creating driver
*
* RETURNS: 0 if the virtio host device creating driver registered successfully.
*          -EINVAL when any of the following conditions are satisfied:
*            - <vHostdrvInfo> equals to NULL.
*            - <vHostdrvInfo->create> equals to NULL.
*
* ERRNO: N/A
*/

int virtioHostDrvRegister(struct virtioHostDrvInfo *vHostdrvInfo)
{
	if (!vHostdrvInfo) {
		log_err("vHostdrvInfo is NULL!\n");
		errno = EINVAL;
		return -1;
	}

	if (!vHostdrvInfo->create) {
		log_err("the create RTN is NULL\n");
	        errno = EINVAL;
		return -1;
	}

	TAILQ_INSERT_TAIL(&vHostCreateRtnList, vHostdrvInfo, node);

	return 0;
}


/*******************************************************************************
*
* virtioHostDevicesCreate - create virtio host devices
*
* This routine creates virtio host devices with the given virtual channel.
* infomation.
*
* RETURNS: N/A
*
* ERRNO: N/A
*/

static void virtioHostDevicesCreate(struct virtioHostDev *pHostDev,
				    uint32_t devNum)
{
	struct virtioHostDrvInfo *pHostDrvInfo;
	bool match;
	uint32_t i;
	int ret;

	if (TAILQ_EMPTY(&vHostCreateRtnList)) {
		log_err("no back-end driver registered!\n");
		return;
	}

	for (i = 0; i < devNum; i++) {
		match = false;
		/* find merge context in global list */
		TAILQ_FOREACH(pHostDrvInfo, &vHostCreateRtnList, node) {
			VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO,
					    "0x%lx, %d, %d, channelNum:%d\n",
					    (unsigned long)pHostDrvInfo,
					    pHostDrvInfo->typeId,
					    pHostDev[i].typeId,
					    pHostDev[i].channelNum);
			if (pHostDrvInfo->typeId == pHostDev[i].typeId) {
				match = true;
				break;
			}
		}

		if (!match) {
			log_err("%d is unsupported virtio device\n",
				pHostDev[i].typeId);
			continue;
		}

		ret = pHostDrvInfo->create(&pHostDev[i]);
		if (ret) {
			log_err("failed to initialize %d\n",
				ret);
			continue;
		}
	}
}

/*
 * Initialize static structures
 */
void virtioHostInit(void)
{
	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO, "start\n");
	TAILQ_INIT(&vHostCreateRtnList);
	TAILQ_INIT(&vHostDeviceList);
	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO, "done\n");
}

/*******************************************************************************
*
* virtioHostDevicesInit - create and initialize virtio host devices
*
* This routine gets the virtio host device configuration info from the VSM
* share memory region and parses it, creates and initialize all the virtio host
* devices on the VxWorks host VM.
*
* RETURNS: N/A
*
* ERRNO: N/A
*/
extern void virtioHostYamlConnect(void);
void virtioHostDevicesInit(void)
{
	struct virtioVsmShmRegion vShmRegion;
	struct virtioHostDev *pHostDev = NULL;
	struct virtioMap **pMaps = NULL;
	uint32_t devNum;
	uint32_t mapNum;
	size_t dataLen;
	const char  *shmBuf;
	char* yamlBuf;
	int i;
	int r = -1;

	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO, "start\n");

	if (!pgVirtioHostVsm) {
		log_err("VSM driver not initialized!\n");
		return;
	}

	memset((void *)&virtioHostCfgInfo, 0, sizeof(VIRTIO_HOST_CFG_INFO));

	/* get VSM share memory region */

	if (virtioHostVsmShmRegionGet(pgVirtioHostVsm, &vShmRegion) != 0) {
		log_err("unable to get the shared memory %s\n",
			strerror(errno));
		return;
	}

	shmBuf = (const char *)vShmRegion.vaddr;
	dataLen = strnlen(shmBuf, (size_t)vShmRegion.region.len); //zhe
	if (dataLen == 0) {
		log_err("share memory is empty!\n");
		virtioHostVsmShmRegionRelease(pgVirtioHostVsm, &vShmRegion);
		return;
	}
	yamlBuf = malloc(dataLen + 1);
	if (yamlBuf == NULL) {
		log_err("config buffer allocation error\n");
		return;
	}
	for (i = 0; i < dataLen; i++) {
		yamlBuf[i] = shmBuf[i];
	}
	yamlBuf[i] = 0;

	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_CFG, "%s\n", yamlBuf);

	virtioHostYamlConnect();

	/* parse the virtio host devices configuration */
	r = virtioHostCfgParse(yamlBuf, dataLen, &virtioHostCfgInfo);
	if (r != 0) {
		log_err("virtio host configuraton can't "
			"be parsed!\n");
		free(yamlBuf);
		return;
	}
	free(yamlBuf);

	pMaps    = virtioHostCfgInfo.pMaps;
	mapNum   = virtioHostCfgInfo.mapNum;
	devNum   = virtioHostCfgInfo.devNum;
	pHostDev = virtioHostCfgInfo.pVirtioHostDev;

	virtioHostVsmSetGuestMap(pgVirtioHostVsm, pMaps, mapNum);

	/* create virtio host devices */
	virtioHostDevicesCreate(pHostDev, devNum);

	virtioHostVsmShmRegionRelease(pgVirtioHostVsm, &vShmRegion);

	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO, "done\n");

	return;
}


/*******************************************************************************
*
* virtioHostVsmRegister - register virtio VSM driver
*
* This routine registers virtio VSM driver.
*
* RETURNS: 0 when the VSM driver register successfully.
*          -EINVAL when <pVirtioHostVsm> equals to NULL.
*          -EEXIST when the VSM driver has been registered.
*
* ERRNO: N/A
*
* \NOMANUAL
*/

int virtioHostVsmRegister(struct virtioHostVsm *pVirtioHostVsm)
{
	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO, "start\n");

	if (!pVirtioHostVsm) {
		log_err("input invalid!\n");
	        errno = EINVAL;
		return -1;
	}

	if (pgVirtioHostVsm) {
		log_err("VSM is already registered!\n");
		errno = EEXIST;
		return -1;
	}

	pgVirtioHostVsm = pVirtioHostVsm;

	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO, "done\n");

	return 0;
}


/*******************************************************************************
*
* virtioHostVsmReqKick - handle I/O notify request
*
* This routine handles the virtio device I/O notify event from guest OS.
* It calls the corresponding virtio host device emulator notify handler.
* In this case hypervisor doesn't expect the reply if the queue isn't full.
*
* RETURNS: 0 when the notidy envent handled successfully.
*          -EINVAL when <vHost> equals to NULL.
*          -EINVAL when <vHost->pQueue> equals to NULL.
*          -EINVAL when <queueId> is a illegal value.
*
* ERRNO: N/A
*
* \NOMANUAL
*/
int virtioHostVsmReqKick(struct virtioHost *vHost, uint32_t queueId)
{
	uint32_t offset;
	unsigned char *pavail;
	volatile __virtio16 *pidx;
	volatile __virtio16 idx;
	int i;

	if (!vHost || !vHost->pQueue || queueId >= vHost->queueMax) {
		log_err("invalid parameters!\n");
		errno = EINVAL;
		return -1;
	}

	virtio_rmb();

	offset = offsetof(struct vring_avail, idx);
	pavail = (unsigned char *)vHost->pQueue[queueId].vRing.avail;
	pidx = (unsigned short *)(pavail + offset);
	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO,
			    "addr: %p, offset: 0x%x, -> %p\n",
			    pavail, offset, pidx);

	/* FIXME: remove the cycle after the testing */
	for (i = 0; i < FAKE_KICK_DEBUG_CYCLE; i++) {
		virtio_rmb();
		idx = host_virtio16_to_cpu(vHost, host_readw(pidx));
		if (idx != vHost->pQueue[queueId].availIdx) {
			break;
		}
		usleep(1000);
	}

	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_IOREQ,
			    "kick queue(%u) %u:%u (%d)\n",
			    queueId, vHost->pQueue[queueId].availIdx,
			    idx, i);

	if (vHost->pQueue[queueId].availIdx != idx) {
		VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_IOREQ, "real kick\n");
		vHost->pHostOps->kick(&vHost->pQueue[queueId]);
	} else {
		VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_IOREQ, "fake kick\n");
	}

	return 0;
}


/*******************************************************************************
*
* virtioHostVsmReqRead - handle virtio device CFG read request
*
* This routine handles the virtio device CFG read request from guest OS, if the
* registers are device specific configuration register, it will reroute to
* host device emulator.
*
* RETURNS: 0 when getting the content from desired register successfully.
*          -EINVAL when <vHost> or <pValue> equals to NULL.
*          -ENOTSUPP when <address> can not be resolved.
*
* ERRNO: N/A
*
* \NOMANUAL
*/

int virtioHostVsmReqRead(struct virtioHost *vHost,
			 uint64_t address, uint64_t size, uint32_t* pValue)
{
	int ret = 0;

	if (!vHost || !pValue) {
		log_err("invalid input parameter\n");
		errno = EINVAL;
		return -1;
	}

	if (address >= VIRTIO_MMIO_CONFIG) {
		ret = vHost->pHostOps->reqRead(vHost,
				address - VIRTIO_MMIO_CONFIG,
				size, pValue);
		goto done;
	}

	switch (address)
	{
		case VIRTIO_MMIO_MAGIC_VALUE:
			*pValue = VIRTIO_MMIO_MAGIC_VALUE_LE;
			break;
		case VIRTIO_MMIO_VERSION:
			*pValue = VIRTIO_MMIO_MODERN_REG_VER;
			break;
		case VIRTIO_MMIO_DEVICE_ID:
			*pValue = vHost->deviceId;
			break;
		case VIRTIO_MMIO_VENDOR_ID:
			*pValue = vHost->vendorId;
			break;
		case VIRTIO_MMIO_DEVICE_FEATURES:
			*pValue = vHost->devFeature[vHost->devFeatureSel];
			break;
		case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
			*pValue = vHost->devFeatureSel;
			break;
		case VIRTIO_MMIO_DRIVER_FEATURES:
			*pValue = vHost->drvFeature[vHost->drvFeatureSel];
			break;
		case VIRTIO_MMIO_DRIVER_FEATURES_SEL:
			*pValue = vHost->drvFeatureSel;
			break;
		case VIRTIO_MMIO_QUEUE_SEL:
			*pValue = vHost->queueSel;
			break;
		case VIRTIO_MMIO_QUEUE_NUM_MAX:
			*pValue = vHost->queueMaxNum;
			break;
		case VIRTIO_MMIO_QUEUE_NUM:
			*pValue = vHost->pHostQueueReg[vHost->queueSel].queueNum;
			break;
		case VIRTIO_MMIO_QUEUE_READY:
			*pValue = vHost->pHostQueueReg[vHost->queueSel].queueReady;
			break;
		case VIRTIO_MMIO_INTERRUPT_STATUS:
			*pValue = vHost->intStatus;
			break;
		case VIRTIO_MMIO_INTERRUPT_ACK:
			ret = ENOTSUP;
			break;
		case VIRTIO_MMIO_STATUS:
			*pValue = vHost->status;
			break;
		case VIRTIO_MMIO_QUEUE_DESC_LOW:
			*pValue = vHost->pHostQueueReg[vHost->queueSel].desc[0];
			break;
		case VIRTIO_MMIO_QUEUE_DESC_HIGH:
			*pValue = vHost->pHostQueueReg[vHost->queueSel].desc[1];
			break;
		case VIRTIO_MMIO_QUEUE_AVAIL_LOW:
			*pValue = vHost->pHostQueueReg[vHost->queueSel].avail[0];
			break;
		case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:
			*pValue = vHost->pHostQueueReg[vHost->queueSel].avail[1];
			break;
		case VIRTIO_MMIO_QUEUE_USED_LOW:
			*pValue = vHost->pHostQueueReg[vHost->queueSel].used[0];
			break;
		case VIRTIO_MMIO_QUEUE_USED_HIGH:
			*pValue = vHost->pHostQueueReg[vHost->queueSel].used[1];
			break;
		case VIRTIO_MMIO_SHM_LEN_LOW:
			if (vHost->shmSel < vHost->shmMax)
				*pValue = vHost->pHostShmReg[vHost->shmSel].len[0];
			else
				*pValue = ~(uint32_t)0UL;
			break;
		case VIRTIO_MMIO_SHM_LEN_HIGH:
			if (vHost->shmSel < vHost->shmMax)
				*pValue = vHost->pHostShmReg[vHost->shmSel].len[1];
			else
				*pValue = ~(uint32_t)0UL;
			break;
		case VIRTIO_MMIO_SHM_BASE_LOW:
			if (vHost->shmSel < vHost->shmMax)
				*pValue = vHost->pHostShmReg[vHost->shmSel].addr[0];
			else
				*pValue = 0xffffffffUL;
			break;
		case VIRTIO_MMIO_SHM_BASE_HIGH:
			if (vHost->shmSel < vHost->shmMax)
				*pValue = vHost->pHostShmReg[vHost->shmSel].addr[1];
			else
				*pValue = 0xffffffffUL;
			break;
		case VIRTIO_MMIO_CONFIG_GENERATION:
			break;
		default:
			log_err("unsupport address %08lx\n", address);
			ret = ENOTSUP;
			break;
	}

done:
	if (!ret)
		VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO,
				    "address(0x%lx) size(0x%lx) value(0x%x)\n",
				    address, size, *pValue);

	return ret;
}


/*******************************************************************************
*
* virtioHostVsmReqWrite - handle virtio device CFG write request
*
* This routine handles the virtio device CFG write request from guest OS,
* if the registers are device specific configuration register,
* it will be rerouted to host device emulator.
*
* RETURNS: 0 when writting the CFG register successfully.
*          -EINVAL when <vHost> or <pValue> equals to NULL.
*          -ENOTSUPP when <address> can not be resolved.
*
* ERRNO: N/A
*
* \NOMANUAL
*/

int virtioHostVsmReqWrite(struct virtioHost *vHost,
			  uint64_t address, uint64_t size,
			  uint32_t value)
{
	int ret = 0;

	if (vHost == NULL) {
		log_err("invalid input parameter!\n");
		errno = EINVAL;
		return -1;
	}

	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO,
			    "address(0x%lx) size(0x%lx) value(0x%x)\n",
			    address, size, value);

	if (address >= VIRTIO_MMIO_CONFIG) {
		return vHost->pHostOps->reqWrite(vHost,
						 address -
						 VIRTIO_MMIO_CONFIG,
						 size, value);
	}

	switch (address)
	{
		case VIRTIO_MMIO_MAGIC_VALUE:
		case VIRTIO_MMIO_VERSION:
		case VIRTIO_MMIO_DEVICE_ID:
		case VIRTIO_MMIO_VENDOR_ID:
		case VIRTIO_MMIO_QUEUE_NUM_MAX:
		case VIRTIO_MMIO_INTERRUPT_STATUS:
		case VIRTIO_MMIO_DEVICE_FEATURES:
			ret = ENOTSUP;
			break;
		case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
			if (value < 2)
				vHost->devFeatureSel = value;
			else
				ret = ENOTSUP;
			break;
		case VIRTIO_MMIO_DRIVER_FEATURES:
			vHost->drvFeature[vHost->drvFeatureSel] = value;
			break;
		case VIRTIO_MMIO_DRIVER_FEATURES_SEL:
			if (value < 2)
				vHost->drvFeatureSel = value;
			else
				ret = ENOTSUP;
			break;
		case VIRTIO_MMIO_QUEUE_SEL:
			if (value >= vHost->queueMax)
				ret = ENOTSUP;
			else
				vHost->queueSel = value;
			break;
		case VIRTIO_MMIO_QUEUE_NUM:
			vHost->pHostQueueReg[vHost->queueSel].queueNum = value;
			break;
		case VIRTIO_MMIO_QUEUE_READY:
			vHost->pHostQueueReg[vHost->queueSel].queueReady = value;
			(void)virtioHostQueueEnable(vHost, vHost->queueSel);
			break;
		case VIRTIO_MMIO_INTERRUPT_ACK:
			vHost->intStatus &= ~value;
			break;
		case VIRTIO_MMIO_STATUS:
			value &= 0xff;
			if (value == VIRTIO_STATUS_RESET) {
				ret = virtioHostVsmReqReset(vHost);
				break;
			}

			vHost->status |= ((value)                    &
					(VIRTIO_CONFIG_S_ACKNOWLEDGE |
					 VIRTIO_CONFIG_S_DRIVER      |
					 VIRTIO_CONFIG_S_FEATURES_OK |
					 VIRTIO_CONFIG_S_DRIVER_OK   |
					 VIRTIO_CONFIG_S_FAILED));

			if ((value & VIRTIO_CONFIG_S_FEATURES_OK) &&
			    (((vHost->devFeature[0] | vHost->drvFeature[0]) !=
			      vHost->devFeature[0]) ||
			     ((vHost->devFeature[1] | vHost->drvFeature[1]) !=
			      vHost->devFeature[1])))
				vHost->status &= ~VIRTIO_CONFIG_S_FEATURES_OK;

			(void)virtioHostSetStatus(vHost, vHost->status);
			break;
		case VIRTIO_MMIO_QUEUE_DESC_LOW:
			vHost->pHostQueueReg[vHost->queueSel].desc[0] = value;
			break;
		case VIRTIO_MMIO_QUEUE_DESC_HIGH:
			vHost->pHostQueueReg[vHost->queueSel].desc[1] = value;
			break;
		case VIRTIO_MMIO_QUEUE_AVAIL_LOW:
			vHost->pHostQueueReg[vHost->queueSel].avail[0] = value;
			break;
		case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:
			vHost->pHostQueueReg[vHost->queueSel].avail[1] = value;
			break;
		case VIRTIO_MMIO_QUEUE_USED_LOW:
			vHost->pHostQueueReg[vHost->queueSel].used[0] = value;
			break;
		case VIRTIO_MMIO_QUEUE_USED_HIGH:
			vHost->pHostQueueReg[vHost->queueSel].used[1] = value;
			break;
		case VIRTIO_MMIO_SHM_SEL:
			vHost->shmSel = value;
			break;
		default:
			log_err("unsupport address %08lx\n",
				address);
			ret = ENOTSUP;
			break;
	}

	if (ret != 0) {
		errno = ret;
		return -1;
	}
	return ret;
}


/*******************************************************************************
*
* virtioHostVsmReqReset - reset virtio host device
*
* This routine handles the virtio device reset request from guest OS.
* The reset request is rerouted to the virtio host device driver specified
* by <vHost>.
*
* RETURNS: 0 when reset request handled successfully.
*          -EINVAL when <vHost> equals to NULL.
*
* ERRNO: N/A
*
* \NOMANUAL
*/

int virtioHostVsmReqReset(struct virtioHost *vHost)
{
	uint32_t vq;

	if (!vHost) {
		log_err("invalid input parameter\n");
		errno = EINVAL;
		return -1;
	}

	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO, "start\n");

	if (vHost->status != VIRTIO_STATUS_RESET) {
		for (vq = 0; vq < vHost->queueMax; vq++)
			vHost->pHostQueueReg[vq].queueReady = 0;

		if (vHost->pHostOps->reset)
			vHost->pHostOps->reset(vHost);

		virtioHostReset(vHost);

		vHost->status = VIRTIO_STATUS_RESET;
	}

	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO, "done\n");

	return 0;
}


/*******************************************************************************
*
* virtioHostCreate - create virtio host device
*
* This routine creates virtio host device, that is called by virtio device
* simulator. It helps the simulator to bind one or more virtio host instances
* to host service module with specified queueId, and the virtio device
* information are requered such as device ID, feature, queue number and so on.
*
* RETURNS: 0 when create virtio host devices successfully with the given
*            arguments.
*          -EINVAL when any of the following conditions are satisfied:
*            - [vHost] is equal to [NULL].
*            - [devFeature] is equal to [NULL].
*            - [pHostOps] is equal to [NULL].
*            - any of the entries in [pDevFeature] contains
*              [VIRTIO_F_RING_PACKED].
*          -EEXIST when VSM driver is not installed or
*            [pgVirtioHostVsm->vsmOps.getQueue] is equal to [NULL].
*          -ENOENT when [queueId] is equal to or greater than the maximum
*            number of the VSM request queue number.
*          -EACCES when the got VSM request queue enabled failed.
*          -ENOSPC when any of the following conditions are satisfied:
*            - allocating memory for the host device configuration registers
*              failed.
*            - getting the memory map of the host device failed.
*            - allocating memory for the host device virtual queues failed.
*
* ERRNO: N/A
*/

int virtioHostCreate
    (
    struct virtioHost *vHost,
    uint32_t vendorId,
    uint32_t deviceId,
    uint64_t *devFeature,
    uint32_t queueMax,
    uint32_t queueMaxNum,
    uint32_t shmMax,
    struct virtioShmRegion *pShmRegions,
    struct virtioHostOps *pHostOps
    )
{
	VIRTIO_VSM_QUEUE_ID pVsmQueue;
	uint32_t i;
	int ret = 0;

	if (!vHost || !pHostOps || !devFeature ||
			queueMax == 0 || queueMaxNum == 0) {
		log_err("invalid input parameter\n");
		errno = EINVAL;
		return -1;
	}

	/* check if VSM has been registered or not */
	if (!pgVirtioHostVsm || !pgVirtioHostVsm->vsmOps.getQueue) {
		log_err("VSM not found\n");
		errno = EEXIST;
		return -1;
	}

	if (*devFeature & (1ULL << VIRTIO_F_RING_PACKED)) {
		log_err("packed virtqueue is "
			"not supported devFeature:0x%lx\n",
			*devFeature);
		/* FIXME: add support for packed virtqueues */
		errno = ENOTSUP;
		return -1;
	}

	pVsmQueue = pgVirtioHostVsm->vsmOps.getQueue(pgVirtioHostVsm->vsmId,
			vHost->channelId);
	if (!pVsmQueue) {
		log_err("failed to get the channel\n");
		errno = ENOENT;
		return -1;
	}

	vHost->pVsmQueue = pVsmQueue;
	vHost->pVsmOps   = &pgVirtioHostVsm->vsmOps;
	vHost->pHostOps  = pHostOps;

	if (virtioHostMapSetup(pgVirtioHostVsm->vsmId,
			       vHost->pMaps) != 0) {
		log_err("failed to get map\n");
		ret = ENOSPC;
		goto failed;
	}

	vHost->deviceId      = deviceId;
	vHost->vendorId      = vendorId;
	vHost->devFeature[0] = (uint32_t)(*devFeature & 0xffffffffUL);
	vHost->devFeature[1] = (uint32_t)(*devFeature >> 32);
	vHost->queueMaxNum   = queueMaxNum;
	vHost->queueMax      = queueMax;
	vHost->pHostQueueReg = (struct virtioHostQueueReg *)zmalloc(
		queueMax * sizeof (struct virtioHostQueueReg));
	if (vHost->pHostQueueReg == NULL) {
		log_err("queue allocation failed\n");
		ret = ENOMEM;
		goto failed;
	}
	vHost->shmMax = shmMax;
	if (shmMax > 0) {
		vHost->pHostShmReg = (struct virtioHostShmReg *)zmalloc(
			shmMax * sizeof (struct virtioHostShmReg));
		if (vHost->pHostShmReg == NULL) {
			log_err("failed to allocate memory mappings\n");
			ret = ENOMEM;
			goto failed;
		}

		for (i = 0; i < shmMax; ++i) {
			vHost->pHostShmReg[i].len[0]  = (uint32_t)
				(pShmRegions[i].len & 0xffffffffUL);
			vHost->pHostShmReg[i].len[1]  = (uint32_t)
				(pShmRegions[i].len >> 32);
			vHost->pHostShmReg[i].addr[0] = (uint32_t)
				(pShmRegions[i].paddr & 0xffffffffUL);
			vHost->pHostShmReg[i].addr[1] = (uint32_t)
				(pShmRegions[i].paddr >> 32);
		}
	}

	vHost->pQueue = (struct virtioHostQueue *)zmalloc(
		queueMax * sizeof (struct virtioHostQueue));
	if (!vHost->pQueue) {
		log_err("failed to allocate queue\n");
		ret = ENOSPC;
		goto failed;
	}

	pthread_mutex_lock(&vHostDeviceLock);

	TAILQ_INSERT_TAIL(&vHostDeviceList, vHost, node);

	pthread_mutex_unlock(&vHostDeviceLock);

	if (pgVirtioHostVsm->vsmOps.init(pVsmQueue, vHost) != 0) {
		log_err("failed to initialize channel\n");
		ret = EACCES;
		goto failed;
	}

	return ret;

failed:

	if (vHost->pQueue)
		free(vHost->pQueue);

	if (vHost->pHostShmReg)
		free(vHost->pHostShmReg);

	if (vHost->pHostQueueReg)
		free(vHost->pHostQueueReg);

	errno = ret;
	return -1;
}

void virtioHostRelease(struct virtioHost *vHost)
{
	int i;
	int ret = 0;

	if (!vHost)
		return;

	if (vHost->pQueue)
		free(vHost->pQueue);

	if (vHost->pHostShmReg)
		free(vHost->pHostShmReg);

	if (vHost->pHostQueueReg)
		free(vHost->pHostQueueReg);

	if (vHost->pMaps) {
		vHost->pMaps->refCnt--;
		if (vHost->pMaps->refCnt != 0) {
			return;
		}
		for (i = 0; i < vHost->pMaps->count; i++) {
			if (vHost->pMaps->entry[i].hvaddr) {
				ret = munmap(vHost->pMaps->entry[i].hvaddr,
					     vHost->pMaps->entry[i].size);
				if (ret != 0) {
					log_err("memory unmap failed %s\n",
						strerror(errno));
					return;
				}
			}
		}
		/* mapped memory will be freed in virtioHostCfgFree() */
	}
}


/*******************************************************************************
*
* virtioHostMapSetup - setup a guest map
*
* This routine setups host VM to guest VM memory map.
*
* RETURNS: map pointer, NULL when get map failed
*
* ERRNO: N/A
*/

static int virtioHostMapSetup(VIRTIO_VSM_ID vsmId, struct virtioMap *pMap)
{
	uint32_t i;
	int ret = 0;
	int uio_fd;
	int ctrl_fd;

	if (!pMap) {
		log_err("invalid input parameter\n");
		errno = EINVAL;
		return -1;
	}

	pthread_mutex_lock(&vHostDeviceMapLock);

	if (pMap->refCnt > 0) {
		VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO,
				"memory is mapped already\n");
		pthread_mutex_unlock(&vHostDeviceMapLock);
		return 0;
	}

	ctrl_fd = virtioVsmGetCtrl(vsmId);
	if (ctrl_fd < 0) {
		log_err("failed to get control file: %s\n",
			strerror(errno));
		errno = ENOSPC;
		return -1;
	}
	uio_fd = virtioVsmGetUIO(vsmId);
	if (uio_fd < 0) {
		log_err("failed to get UIO file: %s\n",
			strerror(errno));
		close(ctrl_fd);
		errno = ENOSPC;
		return -1;
	}

	/* map the host physcial to virtial space */
	for (i = 0; i < pMap->count; i++) {
		size_t align = getpagesize();
		size_t alignedSize = (pMap->entry[i].size +
				      align - 1) & ~(align -1);
		VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO,
				    "map %d hpaddr:0x%lx, 0x%lx(0x%lx), "
				    "offset: 0x%x\n",
				    i, pMap->entry[i].hpaddr,
				    pMap->entry[i].size, alignedSize,
				    pMap->entry[i].offset);
		ret = virtioRegionGet(ctrl_fd,
				      pMap->entry[i].hpaddr,
				      alignedSize,
				      &pMap->entry[i].offset);
		if (ret != 0) {
			log_err("failed to create region 0x%lx: %s\n",
				pMap->entry[i].hpaddr,
				strerror(errno));
			errno = ENOSPC;
			ret = -1;
			break;
		}
		pMap->entry[i].hvaddr = mmap(NULL, alignedSize,
					     PROT_READ | PROT_WRITE,
					     MAP_SHARED, uio_fd,
					     pMap->entry[i].offset);
		if (pMap->entry[i].hvaddr == MAP_FAILED) {
			log_err("failed to map region 0x%lx: %s\n",
				pMap->entry[i].hpaddr,
				strerror(errno));
			errno = ENOSPC;
			ret = -1;
			break;
		}

		VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO,
				"entry:%d:0x%lx->%p\n", i,
				pMap->entry[i].hpaddr, pMap->entry[i].hvaddr);
	}
	close(uio_fd);
	close(ctrl_fd);

	if (ret == 0) {
		pMap->refCnt++;
	} else {

		for (i = 0; i < pMap->count; i++) {
			if (pMap->entry[i].hvaddr) {
				munmap(pMap->entry[i].hvaddr,
				       pMap->entry[i].size);
				pMap->entry[i].hvaddr = 0;
			}
		}

		pMap->refCnt = 0;
	}

	pthread_mutex_unlock(&vHostDeviceMapLock);

	return ret;
}


/*******************************************************************************
*
* vritioHostHasFeature - test feature for virtio host device
*
* This routine tests features for virtio host device.
*
* RETURNS: virtio device feature bits
*
* ERRNO: N/A
*/

//zhe Linux virtio16_to_cpu requires vdev that we don't have here, use vHost instead
//should use devFeatures but drvFeatures may be OK
uint64_t vritioHostHasFeature(struct virtioHost *vHost, uint64_t feature)
{
	uint64_t drvFeature;

	if (!vHost) {
		log_err("invalid input parameter\n");
		errno = EINVAL;
		return 0;
	}

	drvFeature = (uint64_t)vHost->drvFeature[1] << 32 | vHost->drvFeature[0];

	return (drvFeature & (1 << feature));//zhe <<
}

uint16_t host_virtio16_to_cpu(struct virtioHost *vHost, __virtio16 val)
{
	return __virtio16_to_cpu(
		vritioHostHasFeature(vHost, VIRTIO_F_VERSION_1) ||
		virtioVsmLegacyIsLittleEndian(pgVirtioHostVsm->vsmId), val);
}

uint32_t host_virtio32_to_cpu(struct virtioHost *vHost, __virtio32 val)
{
	return __virtio32_to_cpu(
		vritioHostHasFeature(vHost, VIRTIO_F_VERSION_1) ||
		virtioVsmLegacyIsLittleEndian(pgVirtioHostVsm->vsmId), val);
}

uint64_t host_virtio64_to_cpu(struct virtioHost *vHost, __virtio64 val)
{
	return __virtio64_to_cpu(
		vritioHostHasFeature(vHost, VIRTIO_F_VERSION_1) ||
		virtioVsmLegacyIsLittleEndian(pgVirtioHostVsm->vsmId), val);
}

__virtio16 host_cpu_to_virtio16(struct virtioHost *vHost, uint16_t val)
{
	return __cpu_to_virtio16(
		vritioHostHasFeature(vHost, VIRTIO_F_VERSION_1) ||
		virtioVsmLegacyIsLittleEndian(pgVirtioHostVsm->vsmId), val);
}

__virtio32 host_cpu_to_virtio32(struct virtioHost *vHost, uint32_t val)
{
	return __cpu_to_virtio32(
		vritioHostHasFeature(vHost, VIRTIO_F_VERSION_1) ||
		virtioVsmLegacyIsLittleEndian(pgVirtioHostVsm->vsmId), val);
}

__virtio64 host_cpu_to_virtio64(struct virtioHost *vHost, uint64_t val)
{
	return __cpu_to_virtio64(
		vritioHostHasFeature(vHost, VIRTIO_F_VERSION_1) ||
		virtioVsmLegacyIsLittleEndian(pgVirtioHostVsm->vsmId), val);
}


/*******************************************************************************
*
* virtioHostConfigNotify - notify host virtio device config change
*
* This routine sets the configuration change notification bit of the virtio
* device interrupt status register and pushes a request to the VSM IRQ queue
* to notice the hypervisor trigger an interrupt to the virtio FE driver.
*
* RETURNS: 0 if notify host virtio device config change successful.
*          -1 if pushing a request to the VSM IRQ queue failed.
*          -EINVAL when any of the following conditions are satisfied:
*            - [vHost] is equal to [NULL].
*            - [vHost->pVsmOps] is equal to [NULL].
*            - [vHost->pVsmOps->notify] is equal to [NULL].
*            - [vHost->pVsmQueue] is equal to [NULL].
*            - [vHost->pVsmQueue->pDrvCtrl] is equal to [NULL].
*            -EACCES when taking the semaphore
*             [vHost->pVsmQueue->pDrvCtrl ->irqMtx] failed.
*
* ERRNO: N/A
*/

int virtioHostConfigNotify(struct virtioHost *vHost)
{
	if (vHost == NULL) {
		log_err("invalid input parameter\n");
		errno = EINVAL;
		return -1;
	}

	vHost->intStatus = VIRTIO_MMIO_INT_CONFIG;
	return virtioHostNotify(vHost);
}


/*******************************************************************************
*
* virtioHostNeedReset - tell the driver we need to reset
*
* This routine tells the virtio FE driver that it neede to reset.
*
* RETURNS: 0 when pushing request reset successfully.
*          -EINVAL when <vHost> equals to NULL.
*
* ERRNO: N/A
*/

int virtioHostNeedReset(struct virtioHost *vHost)
{
	if (vHost == NULL) {
		log_err("invalid input parameter\n");
		errno = EINVAL;
		return -1;
	}

	vHost->status |= VIRTIO_CONFIG_S_NEEDS_RESET;
	return virtioHostConfigNotify(vHost);
}

/*******************************************************************************
*
* virtioHostReset - reset virtio host device
*
* This routine resets virtio host device resource.
*
* RETURNS: 0 when reset successfully, otherwise fail.
*
* ERRNO: N/A
*/

static int virtioHostReset(struct virtioHost *vHost)
{
	uint32_t vq;

	if (!vHost || !vHost->pHostQueueReg) {
		log_err("invalid input parametr\n");
		errno = EINVAL;
		return -1;
	}

	for (vq = 0; vq < vHost->queueMax; vq++) {
		vHost->pHostQueueReg[vq].queueReady = 0;
		vHost->pHostQueueReg[vq].queueNum = 0;
		vHost->pHostQueueReg[vq].desc[0] = 0;
		vHost->pHostQueueReg[vq].desc[1] = 0;
		vHost->pHostQueueReg[vq].avail[0] = 0;
		vHost->pHostQueueReg[vq].avail[1] = 0;
		vHost->pHostQueueReg[vq].used[0] = 0;
		vHost->pHostQueueReg[vq].used[1] = 0;

		//zhe, pHostShmReg?
	}

	vHost->devFeatureSel = 0;
	vHost->drvFeatureSel = 0;
	vHost->intStatus = 0;
	vHost->queueSel = 0;
	vHost->shmSel = 0;

	return 0;
}


/*******************************************************************************
*
* virtioHostTranslate - convert guest physical ADDR to host virtual ADDR
*
* This routine converts the guest VM view physical address specified by
* <gpaddr> to the host VM view virtual address and fills to <vhaddr>.
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

int virtioHostTranslate(struct virtioHost *vHost,
			PHYS_ADDR gpaddr,
			VIRT_ADDR *hvaddr)
{
	struct virtio_map_entry *entry;
	uint32_t i;

	if (!vHost || !hvaddr) {
		log_err("invalid input parameter\n");
		errno = EINVAL;
		return -1;
	}

	for (i = 0; i < vHost->pMaps->count; i++) {
		entry = &vHost->pMaps->entry[i];
		if ((gpaddr >= entry->gpaddr) &&
		    (gpaddr < entry->gpaddr + entry->size)) {
			*hvaddr = (VIRT_ADDR)((gpaddr - entry->gpaddr)
					      + entry->hvaddr);

			VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO,
					    "0x%lx->%p\n", gpaddr, *hvaddr);
			return 0;
		}
	}

	log_err("address 0x%lx is out of boundary!\n",
		gpaddr);
	errno = ENOENT;
	return -1;
}


/*******************************************************************************
*
* virtioHostNotify - notify queue buffer updated to virtio device
*
* This routine sets the used buffer notification bit of the virtio device
* interrupt status register and pushes a request to the VSM IRQ queue to
* notice the hypervisor triggers an interrupt to the virtio FE driver.
*
* RETURNS: 0 when pushing the kick event successfully.
*          -1 when pushing a request to the VSM IRQ queue failed.
*          -EINVAL when any of the following conditions are satisfied:
*            - <pQueue> is equal to NULL.
*            - <pQueue->vHost> is equal to NULL.
*            - <pQueue->vHost->pVsmOps> is equal to NULL.
*            - <pQueue->vHost->pVsmOps->notify> is equal to NULL.
*            - <pQueue->vHost->pVsmQueue> is equal to NULL.
*            - <pQueue->vHost->pVsmQueue->pDrvCtrl> is equal to NULL.
*          -EACCES when taking the semaphore
*                  <pQueue->vHost->pVsmQueue->pDrvCtrl ->irqMtx> failed.
*
* ERRNO: N/A
*/

static int virtioHostNotify(struct virtioHost *vHost)
{
	if (!vHost || !vHost->pVsmOps || !vHost->pVsmOps->notify ||
			!vHost->pVsmQueue) {
		log_err("invalid input parameter\n");
		errno = EINVAL;
		return -1;
	}

	return vHost->pVsmOps->notify(vHost->pVsmQueue, vHost, vHost->intStatus);
}

/*******************************************************************************
*
* virtioHostQueueEnable - enable the virtio host queue
*
* This routine enables the given virtio host queue specified by <queueIdx>.
*
* RETURNS: 0 when enabling the virtqueue successfully.
*          -EINVAL when <vHost> is equal to NULL.
*          -EFAULT when any of the following conditions are satisfied:
*            - The base address of the virtual queue descriptor area can not
*              be unresolved.
*            - The base address of the virtual queue available ring can not
*              be unresolved.
*            - The base address of the virtual queue used ring can not
*              be unresolved.
*
* ERRNO: N/A
*/

static int virtioHostQueueEnable(struct virtioHost *vHost,
				 uint32_t queueIdx)
{
	struct virtioHostQueue* pQueue;
	PHYS_ADDR               gpaddr;
	VIRT_ADDR               hvaddr;

	if (!vHost) {
		log_err("invalid input parameter\n");
		errno = EINVAL;
		return -1;
	}

	pQueue = &vHost->pQueue[queueIdx];
	pQueue->vHost = vHost;
	pQueue->availIdx = 0;
	pQueue->usedIdx = 0;
	pQueue->lastUsedIdx = 0;

	pQueue->vRing.num = vHost->pHostQueueReg[queueIdx].queueNum;

	gpaddr = (PHYS_ADDR)(vHost->pHostQueueReg[queueIdx].desc[1]) << 32 |
		(PHYS_ADDR)(vHost->pHostQueueReg[queueIdx].desc[0]);
	if (virtioHostTranslate(vHost, gpaddr, &hvaddr)) {
		errno = EFAULT;
		return -1;
	}

	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO,
			    "desc:0x%lx->%p\n", gpaddr, hvaddr);

	pQueue->vRing.desc = (struct vring_desc *)hvaddr;

	gpaddr = (PHYS_ADDR)(vHost->pHostQueueReg[queueIdx].avail[1]) << 32 |
		(PHYS_ADDR)(vHost->pHostQueueReg[queueIdx].avail[0]);
	if (virtioHostTranslate(vHost, gpaddr, &hvaddr)) {
		errno = EFAULT;
		return -1;
	}

	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO,
			    "avail:0x%lx->%p\n", gpaddr, hvaddr);

	pQueue->vRing.avail = (struct vring_avail *)hvaddr;

	gpaddr = (PHYS_ADDR)(vHost->pHostQueueReg[queueIdx].used[1]) << 32 |
		(PHYS_ADDR)(vHost->pHostQueueReg[queueIdx].used[0]);
	if (virtioHostTranslate(vHost, gpaddr, &hvaddr)) {
		errno = EFAULT;
		return -1;
	}

	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO,
			"used:0x%lx->%p\n", gpaddr, hvaddr);

	pQueue->vRing.used = (struct vring_used *)hvaddr;

	/* reset used flags */
	pQueue->usedFlagShadow = 0;
	pQueue->vRing.used->flags = host_cpu_to_virtio16(
		pQueue->vHost, pQueue->usedFlagShadow);
	virtio_wmb();

	return 0;
}


/*******************************************************************************
*
* virtioHostSetStatus - set virtio host device status
*
* This routine sets virtio host device status
*
* RETURNS: 0 when set the virtqueue status successfully.
*          -EINVAL if any of the following conditions are statisfied:
*            - <vHost> is equal to NULL.
*            - <vHost->pHostOps> is equal to NULL.
*
* ERRNO: N/A
*/

static int virtioHostSetStatus(struct virtioHost *vHost,
			       uint32_t status)
{
	if (!vHost || !vHost->pHostOps) {
		log_err("invalid input parameter\n");
		errno = EINVAL;
		return -1;
	}

	if (vHost->pHostOps->setStatus) {
		return vHost->pHostOps->setStatus(vHost, status);
	}

	return 0;
}

/*******************************************************************************
*
* virtioHostQueueReady - get virtio host queue ready status
*
* This routine returns virtio host queue status, ready or not ready.
*
* RETUENS: ture, if the virtual queue is ready.
*          false, if the virtual queue is not ready.
*
* ERRNO: N/A
*/
inline bool virtioHostQueueReady(struct virtioHostQueue *pQueue)
{
	uint32_t idx;

	idx = (uint32_t)(pQueue - pQueue->vHost->pQueue);

	if (pQueue->vHost->pHostQueueReg[idx].queueReady)
		return true;
	else
		return false;
}

/*******************************************************************************
*
* virtioHostQueueHasBuf - check avail ring has new buffer
*
* This function checks whether there has buffer list in the available ring.
*
* RETURNS: number of the got chain buffers.
*          0 when there is no new request in the available ring.
*          1 when there is request in the available ring.
*
* ERRNO: N/A
*/
bool virtioHostQueueHasBuf(struct virtioHostQueue *pQueue)
{
	uint16_t availIdx;

	if (!virtioHostQueueReady(pQueue)) {
		log_err("virtual queue is not ready\n");
		return false;
	}

	/* get the FE avail index */
	availIdx = (uint16_t)host_virtio16_to_cpu(pQueue->vHost,
						  pQueue->vRing.avail->idx);

	if (pQueue->availIdx != availIdx)
		return true;

	return false;
}


/*******************************************************************************
*
* virtioHostQueueGetBuf - get buffer chain from avail ring
*
* This function returns the buffer number when getting a buffer list from
* the available ring successfully.
*
* RETURNS: number of the got chain buffers.
*          0 when there is no new request in the available ring.
*          -1 when any of the following conditions are satisfied:
*            - The index of the descriptor got from the available ring equals
*              or exceeds the virtual queue length.
*            - The descriptor list in the available ring is the indirect type
*              and some of the descriptors contain VIRTQ_DESC_F_INDIRECT.
*            - The descriptor list in the available ring is the indirect type
*              and the list length is equal to 0.
*          -EINVAL when either of the following conditions are satisfied:
*            - <pQueue> is equal to NULL.
*            - <pIdx> is equal to NULL.
*            - <bufList> is equal to NULL.
*            - <maxBuf> is equal to zero.
*          -ENOSPC the buffers in the given buffer list is not enough.
*
* ERRNO: N/A
*/
int virtioHostQueueGetBuf(struct virtioHostQueue *pQueue,
			  uint16_t *pIdx,
			  struct virtioHostBuf *bufList,
			  uint16_t maxBuf)
{
	volatile struct vring_desc *desc;
	struct vring_desc *inDesc;
	struct vring_desc *descList;
	uint16_t availIdx, descIdx;
	uint32_t queueMaxNum;
	VIRT_ADDR virtAddr;
	uint16_t flags;
	int idx = 0;
	uint32_t i;
	uint32_t inDescNum;
	uint32_t len;

	uint32_t offset;
	unsigned char *pa;
	volatile __virtio16 *pi;
	__virtio16 *pr;
	__virtio64 *paddr;
	__virtio32 *plen;
	__virtio16 *pflags;
	__virtio16 *pnext;

	if (!pQueue || !pIdx || !bufList|| !maxBuf) {
		log_err("invalid input parameter\n");
		errno = EINVAL;
		return -1;
	}

	if (!virtioHostQueueReady(pQueue)) {
		log_err("virtual queue not ready\n");
		errno = EACCES;
		return -1;
	}

	virtio_mb();

	/* get the FE avail index */
	offset = offsetof(struct vring_avail, idx);
	pa = (unsigned char *)pQueue->vRing.avail;
	pi = (unsigned short *)(pa + offset);
	availIdx = host_virtio16_to_cpu(pQueue->vHost, host_readw(pi));

	if (pQueue->availIdx == availIdx) {
		VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO,
				    "pQueue->availIdx == availIdx %d\n",
				    availIdx);
		return 0;
	}

	/* get the head */
	offset = offsetof(struct vring_avail, ring);
	pr = (unsigned short *)(pa + offset);
	pr += pQueue->availIdx++ & (pQueue->vRing.num - 1);
	*pIdx = descIdx = host_virtio16_to_cpu(pQueue->vHost, host_readw(pr));

	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO, "descId(%d):0x%x\n",
			    pQueue->availIdx - 1, descIdx);

	/* update the avail event idx */
	if ((pQueue->usedFlagShadow & VRING_USED_F_NO_NOTIFY) == 0) {
		vring_avail_event(&pQueue->vRing) =
			host_cpu_to_virtio16(pQueue->vHost, pQueue->availIdx);
	}

	queueMaxNum = pQueue->vRing.num;

	for (i = 0, idx = 0; i < queueMaxNum; descIdx = host_readw(pnext), i++) {
		if (descIdx >= queueMaxNum) {
			log_err("descriptor index %u is out of range\n",
				descIdx);
			return -1;
		}

		desc   = &pQueue->vRing.desc[descIdx];
		paddr  = (__virtio64 *)((unsigned char*)desc +
					offsetof(struct vring_desc, addr));
		plen   = (__virtio32 *)((unsigned char*)desc +
					offsetof(struct vring_desc, len));
		pflags = (__virtio16 *)((unsigned char*)desc +
					offsetof(struct vring_desc, flags));
		pnext  = (__virtio16 *)((unsigned char*)desc +
					offsetof(struct vring_desc, next));

		if ((host_virtio16_to_cpu(pQueue->vHost, host_readw(pflags)) &
		     VRING_DESC_F_INDIRECT) == 0) {
			VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO,
					"direct\n");

			if (virtioHostTranslate(
				    pQueue->vHost,
				    host_virtio64_to_cpu(
					    pQueue->vHost,
					    host_readq((uint64_t*)paddr)),
				    &virtAddr)) {
				log_err("failed to translate address 0x%lx\n",
					host_readq((uint64_t*)paddr));
				errno = EFAULT;
				return -1;
			}

			bufList[idx].buf = (void *)virtAddr;
			bufList[idx].len = host_virtio32_to_cpu(
				pQueue->vHost, host_readl(plen));
			bufList[idx].flags = (uint16_t)host_virtio16_to_cpu(
				pQueue->vHost, host_readw(pflags));

			if (++idx == maxBuf) {
				VIRTIO_HOST_DBG_MSG(
					VIRTIO_HOST_DBG_INFO,
					"reached maxBuf\n");
				break;
			}

		} else if (!vritioHostHasFeature(pQueue->vHost,
						 VIRTIO_RING_F_INDIRECT_DESC)) {
			log_err("descriptor is indirect while "
				"host device does not support\n");
			errno = EFAULT;
			return -1;
		} else {
			VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO,
					    "indirect\n");

			VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO,
					    "desc:%lx, addr:0x%llx, len:0x%x, "
					    "flags:0x%x, next:0x%x\n",
					    (unsigned long)desc,
					    desc->addr, desc->len,
					    desc->flags, desc->next);

			len = host_virtio32_to_cpu(pQueue->vHost, desc->len);

			inDescNum = len / sizeof(struct vring_desc);

			if ((len & (sizeof(struct vring_desc) - 1))
			    || inDescNum == 0) {
				log_err("indirect descs length 0x%x "
					"is 0 or not aligned\n",
					len);
				errno = EFAULT;
				return -1;
			}

			if (virtioHostTranslate(
				    pQueue->vHost,
				    host_virtio64_to_cpu(pQueue->vHost,
							 desc->addr),
				    &virtAddr)) {
				log_err("failed to translate "
					"address 0x%llx:0x%lx\n",
					desc->addr,
					host_virtio64_to_cpu(
						pQueue->vHost,
						desc->addr));
				errno = EFAULT;
				return -1;
			}

			/*
			 * Indirects start at the 0th, then follow their
			 * own embedded "next"s until those run out.
			 * Each one's indirect flag must be off (we don't
			 * really have to check, could just ignore errors...).
			 */
			descList = (struct vring_desc *)virtAddr;

			for (descIdx = 0; ; ) {
				inDesc = &descList[descIdx];

				VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO,
						    "indesc:%lx, addr:0x%llx, "
						    "len:0x%x, flags:0x%x, "
						    "next:0x%x\n",
						    (unsigned long)inDesc,
						    inDesc->addr, inDesc->len,
						    inDesc->flags, inDesc->next);
				inDesc->flags = host_virtio16_to_cpu(pQueue->vHost,
								     inDesc->flags);
				if (inDesc->flags & VRING_DESC_F_INDIRECT) {
					log_err("second level indirect "
						"descriptor is not "
						"supported\n");
					errno = EFAULT;
					return -1;
				}

				if (virtioHostTranslate(pQueue->vHost,
						host_virtio64_to_cpu(pQueue->vHost,
								     inDesc->addr),
							&virtAddr)) {
					log_err("failed to translate "
						"address 0x%llx:"
						"0x%lx\n",
						inDesc->addr,
						host_virtio64_to_cpu(
							pQueue->vHost,
							inDesc->addr));
					errno = EFAULT;
					return -1;
				}

				bufList[idx].buf = (void *)virtAddr;
				bufList[idx].len =
					host_virtio32_to_cpu(pQueue->vHost,
							     inDesc->len);
				flags = bufList[idx].flags = inDesc->flags;
				descIdx =
					host_virtio16_to_cpu(pQueue->vHost,
							     inDesc->next);
				if (++idx == maxBuf)
					break;

				if (!(flags & VRING_DESC_F_NEXT))
					break;

				if (descIdx >= inDescNum) {
					log_err("invalid next %u > "
						"%u the indirect "
						"desc can contain\n",
						descIdx,
						inDescNum);
					errno = EFAULT;
					return -1;
				}
			}
		}

		if ((host_readw(pflags) & VRING_DESC_F_NEXT) == 0) {
			break;
		}

		if (idx == maxBuf) {
			log_err("got %d buffers, no space "
				"to get more\n",
				idx);
			errno = ENOSPC;
			return -1;
		}
	}

	VIRTIO_HOST_DBG_MSG (VIRTIO_HOST_DBG_QUEUE,
			"got %d buffers\n", idx);

	return idx;
}


/*******************************************************************************
 *
 * virtioHostQueueRetBuf - return buffer chain to avail ring
 *
 * This function returns the buffer chain via decreasing the available
 * descriptor list index of the queue specified by <pQueue>.
 *
 * RETURNS: 0 if returns the buffer chain successfully.
 *          -EINVAL if <pQueue> is equal to NULL.
 *
 * ERRNO: N/A
 *
 */

int virtioHostQueueRetBuf(struct virtioHostQueue *pQueue)
{
	if (!pQueue) {
		log_err("invalid input parameter\n");
		errno = EINVAL;
		return -1;
	}

	if (!virtioHostQueueReady(pQueue)) {
		log_err("virtual queue not ready\n");
		return -EACCES;
	}

	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_QUEUE,
			    "return buf\n");

	pQueue->availIdx--;

	return 0;
}


/*******************************************************************************
 *
 * virtioHostQueueRelBuf - release the buffers to virtio FE driver
 *
 * This routine releases the descriptor list to the virtio used ring, fills
 * the descriptor list index specified by <descIdx> to the id field of
 * the used ring, and fills the value of <len> to the length field
 * of the used ring.
 *
 * RETURNS: 0 if returns the buffer chain successfully.
 *          -EINVAL if [pQueue] is equal to NULL.
 *
 * ERRNO: N/A
 */

int virtioHostQueueRelBuf(struct virtioHostQueue *pQueue, uint16_t descIdx,
			  uint32_t len)
{
	uint16_t usedIdx;

	volatile struct vring_used *used;
	vring_used_elem_t *pring;
	__virtio32 *pringid;
	__virtio32 *pringlen;
	__virtio16 *pidx;

	if (!pQueue) {
		log_err("invalid input parameter\n");
		errno = EINVAL;
		return -1;
	}

	if (!virtioHostQueueReady(pQueue)) {
		log_err("virtual queue not ready\n");
		errno = EACCES;
		return -1;
	}

	usedIdx = pQueue->usedIdx;
	used     = pQueue->vRing.used;
	pring    = (vring_used_elem_t *)((unsigned char*)used +
					 offsetof(struct vring_used, ring));
	pring   += pQueue->usedIdx & (pQueue->vRing.num - 1);
	pringid  = (__virtio32 *)((unsigned char*)pring +
				  offsetof(vring_used_elem_t, id));
	pringlen = (__virtio32 *)((unsigned char*)pring +
				  offsetof(vring_used_elem_t, len));
	pidx     = (__virtio16 *)((unsigned char*)used +
				  offsetof(struct vring_used, idx));

	host_writel(host_cpu_to_virtio32(pQueue->vHost, (uint32_t)descIdx),
		    pringid);
	host_writel(host_cpu_to_virtio32(pQueue->vHost, len),
		    pringlen);
	host_writew(host_cpu_to_virtio16(pQueue->vHost, ++pQueue->usedIdx),
		    pidx);

	virtio_mb();

	VIRTIO_HOST_DBG_MSG (VIRTIO_HOST_DBG_QUEUE,
			     "release buf usedIdx(%d) desc index(%d)\n",
			     usedIdx, descIdx);
	return 0;
}


/*******************************************************************************
 *
 * virtioHostQueueNotify - notify used ring buffer updated
 *
 * This function sets the used buffer notification bit of the virtio device
 * interrupt status register and pushes a request to the VSM IRQ queue to notice
 * the hypervisor to trigger an interrupt to the virtio FE driver.
 *
 * RETURNS: 0 if pushing notify request successfully.
 *          -1 if pushing request to the VSM IRQ queue failed.
 *          -EINVAL when any of the following conditions are satisfied:
 *            - <pQueue> is equal to NULL.
 *            - <pQueue->vHost> is equal to NULL.
 *            - <pQueue->vHost->pVsmOps> is equal to NULL.
 *            - <pQueue->vHost->pVsmOps->notify> is equal to NULL.
 *            - <pQueue->vHost->pVsmQueue> is equal to NULL.
 *            - <pQueue->vHost->pVsmQueue->pDrvCtrl> is equal to NULL.
 *          -EACCES if taking the semaphore
 *                  <pQueue->vHost->pVsmQueue->pDrvCtrl->irqMtx> failed.
 *
 * ERRNO: N/A
 */

int virtioHostQueueNotify(struct virtioHostQueue *pQueue)
{
	struct virtioHost *vHost;
	uint16_t flags;
	uint16_t old, new;
	volatile uint16_t eventIdx;
	bool needKick = false;
	int ret = 0;

	if (!pQueue) {
		log_err("invalid input parameter\n");
		errno = EINVAL;
		return -1;
	}

	vHost = pQueue->vHost;
	if (!vHost) {
		log_err("vHost is NULL\n");
		errno = EINVAL;
		return -1;
	}

	if (!virtioHostQueueReady(pQueue)) {
		log_err("virtual queue not ready\n");
		errno = EACCES;
		return -1;
	}

	vHost->intStatus = VIRTIO_MMIO_INT_VRING;

	virtio_mb();

	if (vritioHostHasFeature(vHost, VIRTIO_F_NOTIFY_ON_EMPTY) &&
	    host_virtio16_to_cpu(pQueue->vHost, pQueue->vRing.avail->idx) ==
	    pQueue->availIdx) {
		VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO, "1 %u:%u\n",
				    host_virtio16_to_cpu(
					    pQueue->vHost,
					    pQueue->vRing.avail->idx),
				    pQueue->availIdx);
		needKick = true;
	} else if (vritioHostHasFeature(vHost, VIRTIO_RING_F_EVENT_IDX)) {
		old = pQueue->lastUsedIdx;
		new = pQueue->lastUsedIdx =
			(uint16_t)host_virtio16_to_cpu(
				pQueue->vHost, pQueue->vRing.used->idx);
		eventIdx = vring_used_event(&pQueue->vRing);
		VIRTIO_HOST_DBG_MSG(
			VIRTIO_HOST_DBG_INFO,
			"eventIdx = %u, old= %u, new = %u\n",
			eventIdx, old, new);
		if (vring_need_event(eventIdx, new, old)) {
			needKick = true;
		}
	} else {
		flags = (uint16_t)host_virtio16_to_cpu(
			pQueue->vHost, pQueue->vRing.avail->flags);
		if ((flags & VRING_AVAIL_F_NO_INTERRUPT) == 0) {
			VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO,
					    "3 %x\n",
					    flags);
			needKick = true;
		}
	}

	if (needKick) {
		VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_INFO, "kick\n");
		virtio_mb();
		ret = virtioHostNotify(vHost);
	}

	return ret;
}


/*******************************************************************************
 *
 * virtioHostQueueIntrEnable - enable virtio device queue interrupt
 *
 * This function enables the event interrupt of the virtio host device queue
 * specified by <pQueue>.
 *
 * RETURNS: 0 if enabling the event interrupt successfully.
 *          -EINVAL if <pQueue> is equal to NULL.
 *          -EACCES if <pQueue->vHost> is equal to NULL.
 *
 * ERRNO: N/A
 */

int virtioHostQueueIntrEnable(struct virtioHostQueue *pQueue)
{
	struct virtioHost *vHost;

	if (!pQueue) {
		log_err("invalid input parameter\n");
		errno = EINVAL;
		return -1;
	}

	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_QUEUE, "start\n");

	vHost = pQueue->vHost;
	if (!vHost) {
		log_err("vHost is NULL\n");
		errno = EACCES;
		return -1;
	}

	if (!virtioHostQueueReady(pQueue)) {
		log_err("virtual queue not ready\n");
		errno = EACCES;
		return -1;
	}

	if (vritioHostHasFeature(vHost, VIRTIO_RING_F_EVENT_IDX)) {
		vring_avail_event(&pQueue->vRing) =
			host_cpu_to_virtio16(pQueue->vHost, pQueue->availIdx);
	} else if (pQueue->usedFlagShadow & VRING_USED_F_NO_NOTIFY) {
		/* when interupt is disabled, enable it */

		pQueue->usedFlagShadow &= (uint16_t)(~VRING_USED_F_NO_NOTIFY);
		pQueue->vRing.used->flags = host_cpu_to_virtio16(
			pQueue->vHost, pQueue->usedFlagShadow);

	}

	virtio_wmb();
	return 0;
}


/*****************************************************************************
 *
 * virtioHostQueueIntrDisable - disable virtio host device queue interrupt
 *
 * This function disables event interrupt of the virtio host device queue
 * specified by <pQueue>.
 *
 * RETURNS: 0 if disableing the event interrupt successfully.
 *          -EINVAL if <pQueue> is equal to NULL.
 *          -EACCES if <pQueue->vHost> is equal to NULL.
 *
 * ERRNO: N/A
 */

int virtioHostQueueIntrDisable(struct virtioHostQueue *pQueue)
{
	struct virtioHost *vHost;

	if (!pQueue) {
		log_err("null pQueue\n");
		errno = EINVAL;
		return -1;
	}

	VIRTIO_HOST_DBG_MSG(VIRTIO_HOST_DBG_QUEUE, "%s \n", __FUNCTION__);

	vHost = pQueue->vHost;
	if (!vHost) {
		log_err("%s null vHost\n",
				__FUNCTION__);
		return -EACCES;
	}

	if (!virtioHostQueueReady(pQueue)) {
		log_err("virtual queue not ready\n");
		errno = EACCES;
		return -1;
	}

	if (vritioHostHasFeature(vHost, VIRTIO_RING_F_EVENT_IDX)) {
		vring_avail_event(&pQueue->vRing) =
			host_cpu_to_virtio16(pQueue->vHost, pQueue->availIdx);
	} else if (!(pQueue->usedFlagShadow & VRING_USED_F_NO_NOTIFY)) {
		/* when interupt is enabled, disable it */

		pQueue->usedFlagShadow |= VRING_USED_F_NO_NOTIFY;
		pQueue->vRing.used->flags =
			host_cpu_to_virtio16(pQueue->vHost,
					     pQueue->usedFlagShadow);
	}

	return 0;
}

/*******************************************************************************
 *
 * virtioHostDevTravel - travel virtio driver list and perform callback function
 *
 * This routine travels virtio driver list and performs the callback whose
 * first parameter is virtio driver.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 *
 * \NOMANUAL
 */

void virtioHostDevTravel(vHostDevCallbackFn pFunc, void *pArg)
{
	struct virtioHost *vHost;

	pthread_mutex_lock(&vHostDeviceLock);

	TAILQ_FOREACH(vHost, &vHostDeviceList, node) {
		pFunc(vHost, pArg);
	}

	pthread_mutex_unlock(&vHostDeviceLock);

	return;
}

/*
 * Stop thread and return it's status
 */
int virtioHostStopThread(pthread_t thread)
{
	int res = pthread_cancel(thread);
	void* pth_result;

	if (res != 0) {
		log_err("Unable to cancel thread 0x%lx: %s\n",
			thread, strerror(errno));
		return -1;
	}
	res = pthread_join(thread, &pth_result);
	if (res != 0 || pth_result != PTHREAD_CANCELED) {
		log_err("Unable to get cancel thread 0x%lx: %s\n",
			thread, strerror(errno));
		return -1;
	}
	return 0;
}
