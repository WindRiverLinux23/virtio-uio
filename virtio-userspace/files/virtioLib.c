/* virtio library */

/*
 * Copyright (c) 2024 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

/*
DESCRIPTION

This is the virtio library that provides basic VirtIO functions
*/

#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <malloc.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/virtio_mmio.h>
#include "virtioLib.h"

#undef VIRTIO_LIB_DBG
#ifdef VIRTIO_LIB_DBG

#define VIRTIO_LIB_DBG_OFF             0x00000000
#define VIRTIO_LIB_DBG_ERR             0x00000001
#define VIRTIO_LIB_DBG_IOREQ           0x00000002
#define VIRTIO_LIB_DBG_IRQREQ          0x00000004
#define VIRTIO_LIB_DBG_QUEUE           0x00000008
#define VIRTIO_LIB_DBG_CFG             0x00000010
#define VIRTIO_LIB_DBG_INFO            0x00000020
#define VIRTIO_LIB_DBG_ALL             0xffffffff

static uint32_t virtiolIBDbgMask = VIRTIO_LIB_DBG_ERR | VIRTIO_LIB_DBG_INFO;

#define VIRTIO_LIB_DBG_MSG(mask, fmt, ...)                              \
        do {                                                            \
                if ((virtiolIBDbgMask & (mask)) ||			\
                    ((mask) == VIRTIO_LIB_DBG_ERR)) {                   \
                        printf("%d: %s() " fmt, __LINE__, __func__,     \
                               ##__VA_ARGS__);                          \
                }                                                       \
        }                                                               \
while ((false));
#else
#undef VIRTIO_LIB_DBG_MSG
#define VIRTIO_LIB_DBG_MSG(...)
#endif  /* VIRTIO_LIB_DBG */

/* virtio features */
#define VIRTIO_F_RING_INDIRECT_DESC    28
#define VIRTIO_F_RING_EVENT_IDX        29

typedef struct {
	uint64_t pfn : 55;
	unsigned int soft_dirty : 1;
	unsigned int file_page : 1;
	unsigned int swapped : 1;
	unsigned int present : 1;
} virtioPagemapEntry;

static int vmTranslate(uintptr_t vaddr, uintptr_t* paddr);

/**
 * virtqueue_get_vring_size - return the size of the virtqueue's vring
 * @vq: the struct virtqueue containes the vring of interest.
 *
 * Returns the size of the vring.  This is mainly used for boasting to
 * userspace.  Unlike other operations, this need not be serialized.
 */
unsigned int virtqueue_get_vring_size(struct virtqueue *vq)
{
	return vq->vRing.num;
}


void virtio_write(struct virtio_device *vdev,
			 uint32_t reg,
			 uint32_t val)
{
        host_writel(htole32(val), (uint32_t*)(vdev->dev.base + reg));
	__mb();
}

uint32_t virtio_read(struct virtio_device *vdev,
			    uint32_t reg)
{
	__mb();
	return le32toh(host_readl((uint32_t*)(vdev->dev.base + reg)));
}

static bool virtioNeedConvert(const struct virtio_device * vdev)
{
#ifdef __LITTLE_ENDIAN__
        return false;
#else
        return virtio_legacy_is_little_endian();
#endif
}

uint16_t virtio16_to_cpu(struct virtio_device *vdev, __virtio16 val)
{
	if (virtioNeedConvert(vdev)) {
		return le16toh(val);
	} else {
		return (uint16_t)val;
	}
}

uint32_t virtio32_to_cpu(struct virtio_device *vdev, __virtio32 val)
{
	if (virtioNeedConvert(vdev)) {
		return le32toh(val);
	} else {
		return (uint32_t)val;
	}
}

uint64_t virtio64_to_cpu(struct virtio_device *vdev, __virtio64 val)
{
	if (virtioNeedConvert(vdev)) {
		return le64toh(val);
	} else {
		return (uint64_t)val;
	}
}

__virtio16 cpu_to_virtio16(struct virtio_device *vdev, uint16_t val)
{
	if (virtioNeedConvert(vdev)) {
		return htole16(val);
	} else {
		return (__virtio16)val;
	}
}

__virtio32 cpu_to_virtio32(struct virtio_device *vdev, uint32_t val)
{
	if (virtioNeedConvert(vdev)) {
		return htole32(val);
	} else {
		return (__virtio32)val;
	}
}

__virtio64 cpu_to_virtio64(struct virtio_device *vdev, uint64_t val)
{
	if (virtioNeedConvert(vdev)) {
		return htole64(val);
	} else {
		return (__virtio64)val;
	}
}

/*
 * Allocate and zero buffer of the provided size
 * Returns buffer pointer on success and NULL on error
 */
void *zmalloc(size_t size)
{
	void* ptr = malloc(size);
	if (ptr != 0) {
		bzero(ptr, size);
	}
	return ptr;
}

/**
 * Enable or disable virtqueue
 * @vdev: virtual device pointer
 * @queueId: virtqueue number
 * @enable: flag indicating if the queue should be enabled
 */
void virtioVsmVirtqueueEnable(struct virtio_device* vdev,
			      int queueId, bool enable)
{
	virtio_write(vdev, VIRTIO_MMIO_QUEUE_SEL, queueId);
	virtio_write(vdev, VIRTIO_MMIO_QUEUE_READY,
		     (enable == true)? 1: 0);
}

/*
 * Obtain VirtIO shared memory region
 * regs - VirtIO registers address
 * region - region descriptor structure
 * idx - region index
 */

void virtioReadShmRegion(struct virtio_device* vdev,
			 struct virtio_region* region, int idx)
{
	/* Select memory region */
        virtio_write(vdev, VIRTIO_MMIO_SHM_SEL, idx);

	/* Get address and length */
	region->addr = (uint64_t)virtio_read(vdev, VIRTIO_MMIO_SHM_BASE_LOW) |
		((uint64_t)virtio_read(vdev, VIRTIO_MMIO_SHM_BASE_HIGH)) << 32;
	region->size = (uint64_t)virtio_read(vdev, VIRTIO_MMIO_SHM_LEN_LOW) |
		((uint64_t)virtio_read(vdev, VIRTIO_MMIO_SHM_LEN_HIGH)) << 32;
}

/*
 *
 * virtioHasFeatures - test feature for virtio device
 *
 * This routine tests features for virtio device.
 *
 * RETURNS: feature bits
 *
 * ERRNO: N/A
 */

uint64_t virtioHasFeatures(const struct virtio_device* vdev,
			   uint64_t feature)
{
	return vdev->features & (1UL << feature);
}


/*****************************************************************************
 *
 * virtqueueIntrEnable - enable Virtio queue interrupt
 *
 * This routine enables Virtio queue interrupt.
 *
 * RETURNS: TRUE if usedIdx recycled by Front-end equals to usedIdx from
 *          Back-end, otherwise FALSE.
 *
 * ERRNO: N/A
 *
 */

bool virtqueueIntrEnable(struct virtqueue* pQueue)
{
	uint16_t usedIdx;

	if ((pQueue->availFlagShadow &
	     (uint16_t)VRING_AVAIL_F_NO_INTERRUPT) != 0U) {
		pQueue->availFlagShadow &=
			(~(uint16_t)VRING_AVAIL_F_NO_INTERRUPT);
		if (virtioHasFeatures(pQueue->vdev,
				      VIRTIO_F_RING_EVENT_IDX) == 0UL) {
			pQueue->vRing.avail->flags =
				cpu_to_virtio16(pQueue->vdev,
						pQueue->availFlagShadow);
		}
        }

	vring_used_event(&pQueue->vRing) =
		cpu_to_virtio16(pQueue->vdev, pQueue->usedIdx);
	__mb();

	usedIdx = virtio16_to_cpu(pQueue->vdev, pQueue->vRing.used->idx);

	return (usedIdx == pQueue->usedIdx);
}

/*****************************************************************************
 *
 * virtqueueIntrDisable - disable Virtio queue interrupt
 *
 * This routine disables Virtio queue interrupt.
 *
 * RETURNS: N/A.
 *
 * ERRNO: N/A
 *
 */

void virtqueueIntrDisable(struct virtqueue* pQueue)
{
	if ((pQueue->availFlagShadow &
	     (uint16_t)VRING_AVAIL_F_NO_INTERRUPT) == 0U) {
		pQueue->availFlagShadow |=
			(uint16_t)VRING_AVAIL_F_NO_INTERRUPT;
		if (virtioHasFeatures(pQueue->vdev,
				      VIRTIO_F_RING_EVENT_IDX) != 0UL) {
			vring_used_event(&pQueue->vRing) =
				cpu_to_virtio16 (pQueue->vdev,
						 pQueue->usedIdx - 1U);
		} else {
			pQueue->vRing.avail->flags =
				cpu_to_virtio16 (pQueue->vdev,
						 pQueue->availFlagShadow);
		}
	}
	return;
}

/*******************************************************************************
*
* virtqueueInitIndirect - Initialize a virtqueue for indirect operation
*
* This function determines if indirect descriptors have been negotiated, and if
* so, it initializes the descriptors for indirect operation and initializes
* the indirect descriptor lists.
*
* RETURNS:
* \is
* \i '-EINVAL' if indirect number is equal to 1 or greater than queue size
* \i '-ENOMEM' if there is not enough memory for the list
* \i 'OK' if successful
* \ie
*
* ERRNO: None
*
* NOTE: does nothing for now
*/

static int virtqueueInitIndirect(struct virtqueue* pQueue,
				 size_t idrNum)
{
	struct vqDescExtra* pQueueDescx;
	size_t totalSize;
	uint32_t idx, j;
	VIRT_ADDR idrTbl;
	PHYS_ADDR idrTblPhy;

	VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_INFO, "start\n");
	if ((virtioHasFeatures(pQueue->vdev,
			       VIRTIO_F_RING_INDIRECT_DESC) == 0UL) ||
	    (idrNum == 0U)) {
		VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_INFO, "indirect DISABLED\n");
		pQueue->indirect = false;
		return 0;
        }

	if ((idrNum == 1U) ||
	    ((uint32_t)idrNum > pQueue->vRing.num)) {
		VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_INFO, "invalid params\n");
		return -EINVAL;
        }

	pQueue->indirect = true;
	pQueue->idrNum = idrNum;

	totalSize = idrNum * sizeof(struct vring_desc) * pQueue->vRing.num;

	idrTbl = zmalloc(totalSize);
	if (idrTbl == NULL) {
		VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_INFO,
				   "idrTbl allocation failed\n");
		return -ENOMEM;
        }

	vmTranslate((uintptr_t)idrTbl, &idrTblPhy);

	/* initialize the data structure for indirect feature */

	for (idx = 0; idx < pQueue->vRing.num; idx++) {
		pQueueDescx = &pQueue->vqDescx[idx];

		pQueueDescx->idrTbl =
			(struct vring_desc *)(idrTbl +
					      (idx * (sizeof(struct vring_desc)
						      * idrNum)));
		pQueueDescx->idrTblPhy = idrTblPhy +
			(idx * (sizeof(struct vring_desc)
				* idrNum));

		for (j = 0; j < (pQueue->idrNum - 1UL); j++) {
			pQueueDescx->idrTbl[j].next = (uint16_t) (j + 1U);
		}
	}
	VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_INFO, "done\n");
	return 0;
}

/*******************************************************************************
 *
 * virtqueueDeinitIndirect - Free a virtqueues indirect descriptor lists
 *
 * RETURNS: N/A
 *
 * ERRNO: None
 */

static void virtqueueDeinitIndirect(struct virtqueue* pQueue)
{
	struct vqDescExtra* pQueueDescx;
	uint32_t idx;

	VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_INFO, "start\n");
	for (idx = 0; idx < pQueue->vRing.num; idx++) {
		pQueueDescx = &pQueue->vqDescx[idx];

		if (pQueueDescx->idrTbl == NULL) {
			break;
		}

		free(pQueueDescx->idrTbl);
		pQueueDescx->idrTbl = NULL;
		pQueueDescx->idrTblPhy = 0;
        }
	VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_INFO, "done\n");
}

/*
 *
 * virtioVqNotify - perform send for virtio queue
 *
 * This function perform send operation for virtio queue <pVirtQueue>.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void virtioVqNotify(const struct virtqueue* pvq)
{
	if (pvq == NULL) {
		return;
        }
	virtio_write(pvq->vdev, VIRTIO_MMIO_QUEUE_NOTIFY, pvq->index);
}


/*****************************************************************************
 *
 * virtqueueRingInit - initialize Virtio queue
 *
 * This routine initializes a Virtio queue.
 *
 * RETURNS: 0 if allocate successful. -1 if failed.
 *
 * ERRNO: N/A
 *
 */

int virtqueueRingInit(struct virtqueue* pQueue,
		      struct virtio_device* vDev,
		      const struct virtqueueInfo* pVirtqueueInfo,
		      uint32_t num, void* pAddr,
		      size_t align,
		      vqKickFn pKick)
{
	uint32_t    idx;
	int         ret = -1;
	size_t      idrNum;

	VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_INFO, "start\n");
	if ((pQueue == NULL) || (vDev == NULL) ||
	    (pAddr == NULL) || (pVirtqueueInfo == NULL)) {
		errno = EINVAL;
		return -1;
        }
	bzero(pAddr, vring_size(num, align));
	vring_init((struct vring*)&pQueue->vRing, num, pAddr, align);

	pQueue->vdev = vDev;
	pQueue->num_free = num;
	pQueue->func.kick = pKick;
	pQueue->func.cb = pVirtqueueInfo->cb;
	pQueue->usedIdx = 0;
	pQueue->availIdx = 0;
	pQueue->lastAvailIdx = 0;
	pQueue->availFlagShadow = 0;
	pQueue->isBroken = false;
	pQueue->name = pVirtqueueInfo->name;

	idrNum = min(num, pVirtqueueInfo->idrNum);
	ret = virtqueueInitIndirect (pQueue, idrNum);
	if (ret < 0) {
		return ret;
        }

	/* if pCb isn't NULL, the interrupt is enabled by default */

	if (pQueue->func.cb == NULL) {
		virtqueueIntrDisable(pQueue);
        }

	for (idx = 0; idx < (num - 1U); idx++) {
		pQueue->vRing.desc[idx].next = (uint16_t) (idx + 1U);
        }

	pthread_mutex_lock(&vDev->vqs_list_lock);
	TAILQ_INSERT_TAIL(&vDev->queueList, pQueue, node);
	pthread_mutex_unlock(&vDev->vqs_list_lock);

	VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_INFO, "done\n");
	return 0;
}

/*
 *
 * virtqueueGetDescAddr - get queue desc addr
 *
 * This routine get queue desc addr.
 *
 * RETURNS: desc addr.
 *
 * ERRNO: N/A
 *
 */

void* virtqueueGetDescAddr(const struct virtqueue* pQueue)
{
	return (void*)pQueue->vRing.desc;
}

/*
 *
 * virtqueueGetAvailAddr - get queue avail addr
 *
 * This routine get queue avail addr.
 *
 * RETURNS: avail addr.
 *
 * ERRNO: N/A
 *
 */

void* virtqueueGetAvailAddr(const struct virtqueue* pQueue)
{
	return (void*)pQueue->vRing.avail;
}

/*
 *
 * virtqueueGetUsedAddr - get queue used addr
 *
 * This routine get queue used addr.
 *
 * RETURNS: used addr.
 *
 * ERRNO: N/A
 *
 */

void* virtqueueGetUsedAddr(const struct virtqueue* pQueue)
{
	return (void*)pQueue->vRing.used;
}

/*
 * Parse the pagemap entry for the given virtual address.
 *
 * param[out] entry      the parsed entry
 * param[in]  pagemap_fd file descriptor to an open /proc/pid/pagemap file
 * param[in]  vaddr      virtual address to get entry for
 * return 0 for success, 1 for failure
 */
static int pagemap_get_entry(virtioPagemapEntry *entry,
		      int pagemap_fd, uintptr_t vaddr)
{
	size_t nread;
	ssize_t ret;
	uint64_t data;
	uintptr_t vpn;

	vpn = vaddr / getpagesize();
	nread = 0;
	while (nread < sizeof(data)) {
		ret = pread(pagemap_fd, ((uint8_t*)&data) + nread,
			    sizeof(data) - nread,
			    vpn * sizeof(data) + nread);
		nread += ret;
		if (ret <= 0) {
			return -1;
		}
	}
	entry->pfn = data & (((uint64_t)1 << 55) - 1);
	entry->soft_dirty = (data >> 55) & 1;
	entry->file_page = (data >> 61) & 1;
	entry->swapped = (data >> 62) & 1;
	entry->present = (data >> 63) & 1;
	return 0;
}

/* Convert the given virtual address to physical using /proc/PID/pagemap.
 *
 * param[out] paddr physical address
 * param[in]  pid   process to convert for
 * param[in] vaddr virtual address to get entry for
 * return 0 for success, -1 for failure
 */
static int virt_to_phys_user(uintptr_t *paddr, pid_t pid,
			     uintptr_t vaddr)
{
	char pagemap_file[BUFSIZ];
	int pagemap_fd;
	virtioPagemapEntry entry;

	snprintf(pagemap_file, sizeof(pagemap_file),
		 "/proc/%ju/pagemap", (uintmax_t)pid);
	pagemap_fd = open(pagemap_file, O_RDONLY);
	if (pagemap_fd < 0) {
		return -1;
	}
	if (pagemap_get_entry(&entry, pagemap_fd, vaddr)) {
		return -1;
	}
	close(pagemap_fd);
	*paddr = (entry.pfn * sysconf(_SC_PAGE_SIZE)) +
		(vaddr % getpagesize());
	return 0;
}

static int vmTranslate(uintptr_t vaddr, uintptr_t *paddr)
{
	return virt_to_phys_user(paddr, getpid(), vaddr);
}

/*
 *
 * virtqueueAddBuffer - expose buffers to other side
 *
 * This routine exposes buffers to other side.
 *
 * RETURNS: 0 if successful, otherwise -1 if failed.
 *
 * ERRNO: N/A
 *
 */
int virtqueueAddBuffer(struct virtqueue* pQueue,
		       const struct virtqueueBuf* bufList,
		       uint32_t readable,
		       uint32_t writable,
		       void* cookie)
{
	uint32_t idx;
	uint16_t flag;
	uint32_t bufCnt = readable + writable;
	uint16_t descIndex;
	uint16_t availIdx;
	uint16_t firstAvailIdx;
	PHYS_ADDR bufPhysAddr;
	struct vring_desc* pQueueDesc;
	struct vring_desc* pQueueCommDesc;
	const struct vqDescExtra* pQueueDescx;
	bool indirect = false;

	if ((bufCnt == 0U) || (pQueue == NULL) ||
	    (bufList == NULL) || (cookie == NULL)) {
		errno = EINVAL;
		return -EINVAL;
        }

	if (pQueue->num_free == 0) {
		VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_INFO,
				   "num_free == 0, no buffers\n");
		errno = ENOSPC;
		return -ENOSPC;
        }

	/*
	 * use temporary availIdx to allow update
	 * availIdx after preparing all the desc
	 */
	availIdx = pQueue->availIdx;

	/* record the firstAvailIdx index */
	firstAvailIdx = pQueue->availIdx & (uint16_t)(pQueue->vRing.num - 1U);

	if ((pQueue->indirect) &&
	    (bufCnt >= 2U) &&
	    (pQueue->idrNum >= bufCnt)) {
		pQueueDesc = &pQueue->vRing.desc[firstAvailIdx];
		pQueueDescx = &pQueue->vqDescx[firstAvailIdx];
		pQueueDesc->addr = virtio64_to_cpu(
			pQueue->vdev,
			(uint64_t)pQueueDescx->idrTblPhy);
		pQueueDesc->len = virtio32_to_cpu(
			pQueue->vdev,
			bufCnt * (uint32_t)sizeof(struct vring_desc));
		pQueueDesc->flags = virtio16_to_cpu(pQueue->vdev,
						    VRING_DESC_F_INDIRECT);
		pQueueCommDesc = pQueueDescx->idrTbl;
		availIdx = 0;
		indirect = true;
        }
	else {
		if (pQueue->num_free < (uint32_t)bufCnt) {
			VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_INFO,
					   "num_free (%d) < bufCnt(%d), "
					   "no buffers\n",
					   pQueue->num_free, (uint32_t)bufCnt);
			errno = ENOSPC;
			return -ENOSPC;
		}

		pQueueCommDesc = pQueue->vRing.desc;
		indirect = false;
        }
	for (idx = 0; idx < bufCnt; idx++) {
		if (vmTranslate((uintptr_t)bufList[idx].buf,
				 &bufPhysAddr) != 0) {
			VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_ERR,
					   "translate buf fail\n");
			errno = EINVAL;
			return -EINVAL;
		}

		descIndex = availIdx++ & (uint16_t) (pQueue->vRing.num - 1U);

		flag = 0;
		if (idx >= readable) {
			flag |= (uint16_t)VRING_DESC_F_WRITE;
		}

		if (idx < (bufCnt - 1U)) {
			flag |= (uint16_t)VRING_DESC_F_NEXT;
		}

		pQueueCommDesc[descIndex].addr = cpu_to_virtio64(
			pQueue->vdev,
			(uint64_t)bufPhysAddr);

		pQueueCommDesc[descIndex].len = cpu_to_virtio32(
			pQueue->vdev, bufList[idx].len);
		pQueueCommDesc[descIndex].flags = cpu_to_virtio16(
			pQueue->vdev, flag);
        }

	/* update the free desc count and record the data */
	if (indirect) {
		pQueue->vqDescx[firstAvailIdx].cookie = cookie;
		pQueue->vqDescx[firstAvailIdx].ndescs = 1;
		pQueue->num_free--;
		pQueue->availIdx = pQueueDesc->next;
        }
	else {
		pQueue->vqDescx[firstAvailIdx].cookie = cookie;
		pQueue->vqDescx[firstAvailIdx].ndescs = (uint16_t)bufCnt;
		pQueue->num_free -= bufCnt;
		pQueue->availIdx = availIdx;
        }

	/* get the avail index and move forward one */
	availIdx = virtio16_to_cpu(pQueue->vdev, pQueue->vRing.avail->idx);

	/* when avail as index, index must not exceed the ring number */
	pQueue->vRing.avail->ring[availIdx & (pQueue->vRing.num - 1U)] =
		cpu_to_virtio16(pQueue->vdev, firstAvailIdx);

	/* idx always increments, and wraps naturally at 65536 */
	availIdx++;
	pQueue->vRing.avail->idx = cpu_to_virtio16(pQueue->vdev, availIdx);
	__mb();
	return 0;
}

/*
 *
 * virtqueueKick - kick the other side
 *
 * This routine kicks the other side.
 *
 * RETURNS: 0 or -EINVAL if failed.
 *
 * ERRNO: N/A
 *
 */

int virtqueueKick(struct virtqueue* pQueue)
{
	uint16_t new;
	uint16_t old;
	uint16_t eventIdx;

	if ((pQueue == NULL) || (pQueue->func.kick == NULL)) {
		errno = EINVAL;
		return -EINVAL;
        }

	__mb();

	if (virtioHasFeatures(pQueue->vdev,
			      VIRTIO_F_RING_EVENT_IDX) != 0UL) {
		old = pQueue->lastAvailIdx;
		pQueue->lastAvailIdx = virtio16_to_cpu(
			pQueue->vdev,
			pQueue->vRing.avail->idx);
		new = pQueue->lastAvailIdx;
		eventIdx = vring_avail_event(&pQueue->vRing);
		if (vring_need_event (eventIdx, new, old) == 1) {
			pQueue->func.kick(pQueue);
		}
	} else {
		if ((virtio16_to_cpu(
			     pQueue->vdev,
			     pQueue->vRing.used->flags) &
		     (uint16_t)VRING_USED_F_NO_NOTIFY) == 0U) {
			pQueue->func.kick (pQueue);
		}
	}
	return 0;
}

/*****************************************************************************
 *
 * virtqueueNotification - Virtio interrupt service function
 *
 * This routine is Virtio interrupt handle.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 *
 */

void virtqueueNotification(struct virtqueue* pQueue)
{
	if ((pQueue == NULL) || (pQueue->func.cb == NULL)) {
		return;
        }

	pQueue->func.cb (pQueue);
}

/**
 * Setup the virtqueue
 * @vdev: virtual device pointer
 * @index: virtqueue number
 * @vqInfo: virtqueue initialization info structure
 */
int setup_vq(struct virtio_device *vdev, unsigned int index,
	     struct virtqueueInfo* vqInfo)
{
	uint32_t vq_ready;
	uint32_t num;
	size_t align = getpagesize();
	int ret;
	PHYS_ADDR pAddr;
	PHYS_ADDR pfn;
	PHYS_ADDR descAddr;
	PHYS_ADDR availAddr;
	PHYS_ADDR usedAddr;
        uintptr_t vAddr;

	VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_INFO, "start\n");
	/* Select the queue we're interested in */
	virtio_write(vdev, VIRTIO_MMIO_QUEUE_SEL, index);

	num = virtio_read(vdev, VIRTIO_MMIO_QUEUE_NUM_MAX);
	if (num == 0) {
		VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_ERR,
				   "Queue %d is not supported\n",
				   index);
		errno = ENOTSUP;
		return -1;
	}

	vdev->ringAddr[index] = (VIRT_ADDR)memalign(align,
						    vring_size(num, align));
	if (vdev->ringAddr[index] == (VIRT_ADDR)NULL) {
		VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_ERR,
				   "failed to allocate ring %x\n",
				   index);
		errno = ENOMEM;
		return -1;
        }
	vdev->queues[index] = zmalloc(sizeof(struct virtqueue)
				     + sizeof(struct vqDescExtra) * num);
	if (vdev->queues[index] == NULL) {
		VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_ERR,
				   "virtqueue %d mem alloc error\n",
				   index);
		errno = ENOMEM;
		return -1;
	}
	vdev->queues[index]->index = index;
	ret = virtqueueRingInit (vdev->queues[index], vdev,
				 vqInfo, num,
				 (void *)vdev->ringAddr[index], getpagesize(),
				 virtioVqNotify);
	if (ret != 0) {
		VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_ERR,
				   "failed to initialize "
				   "virtqueueRingInit %x\n", index);
		return -1;
        }
	virtio_write(vdev, VIRTIO_MMIO_QUEUE_NUM, num);

	if (vdev->dev.version == 1) {
		if (vmTranslate((uintptr_t)vdev->ringAddr[index],
				&pAddr) != 0) {
			VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_ERR,
					   "failed to translate "
					   "address %x: %s\n",
					   index, strerror(errno));
			return -1;
		}
		pfn = pAddr / align;
		if (pfn > 0xffffffffUL) {
			VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_ERR,
					   "fdtVirtioVqSetup ring address"
					   "exceed support range %x\n", index);
			errno = ENOTSUP;
			return -1;
		}
		virtio_write(vdev, VIRTIO_MMIO_QUEUE_ALIGN, (uint32_t)align);
		virtio_write(vdev, VIRTIO_MMIO_QUEUE_PFN, (uint32_t)pfn);

		VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_INFO,
				   "ring %x queue(%p)"
				   "max queue size(0x%x) "
				   "align(0x%lx) virtual (%p)\n",
				   index, vdev->queues[index],
				   num, align, vdev->ringAddr[index]);
	} else {
		/* descriptors*/
		vAddr = (uintptr_t)virtqueueGetDescAddr(vdev->queues[index]);
		if (vmTranslate(vAddr, &descAddr) < 0) {
			VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_ERR,
					   "desc addr translation "
					   "failed %s\n",
					   strerror(errno));
			return -1;
		}
		VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_INFO,
				   "vring %d desc 0c%lx -> 0x%lx\n",
				   index, vAddr, descAddr);
		virtio_write(vdev, VIRTIO_MMIO_QUEUE_DESC_LOW,
			     (uint32_t)descAddr);
		virtio_write(vdev, VIRTIO_MMIO_QUEUE_DESC_HIGH,
			     (uint32_t)((uint64_t)descAddr >> 32));

		/* available buffers */
		vAddr = (uintptr_t)virtqueueGetAvailAddr(vdev->queues[index]);
		if (vmTranslate(vAddr, &availAddr) < 0) {
			VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_ERR,
					   "available addr translation "
					   "failed %s\n",
					   strerror(errno));
			return -1;
		}
		VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_INFO,
				   "vring %d available 0x%lx -> 0x%lx\n",
				   index, vAddr, availAddr);
		virtio_write(vdev, VIRTIO_MMIO_QUEUE_AVAIL_LOW,
			     (uint32_t)availAddr);
		virtio_write(vdev, VIRTIO_MMIO_QUEUE_AVAIL_HIGH,
			     (uint32_t)((uint64_t)availAddr >> 32));

		/* used buffers */
		vAddr = (uintptr_t)virtqueueGetUsedAddr(vdev->queues[index]);
		if (vmTranslate(vAddr, &usedAddr) < 0) {
			VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_ERR,
					   "used addr translation "
					   "failed %s\n",
					   strerror(errno));
			return -1;
		}
		VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_INFO,
				   "vring %d used 0x%lx -> 0x%lx, len: %d\n",
				   index, vAddr, usedAddr, num);
		virtio_write(vdev, VIRTIO_MMIO_QUEUE_USED_LOW,
			     (uint32_t)usedAddr);
		virtio_write(vdev, VIRTIO_MMIO_QUEUE_USED_HIGH,
			     (uint32_t)((uint64_t)usedAddr >> 32));
	}
	return 0;
}


/*
 * Get 32-bit unsigned value from config space
 * Assumed that VirtIO device base address is set to VirtIO shared space
 * that has been mapped to user space.
 */
uint32_t virtio_cread32(struct virtio_device *vdev, unsigned int offset)
{
        uint32_t* cfg;

        if (vdev == NULL || vdev->dev.base == NULL) {
                VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_ERR,
                                   "invalid input parameter\n");
                errno = EINVAL;
                return -1;
        }
        cfg = (uint32_t*)(vdev->dev.base + VIRTIO_MMIO_CONFIG + offset);
        return *cfg;
}

/*
 *
 * virtioSetStatus - set status for virtio device
 *
 * This routine sets status for virtio device.
 *
 * RETURNS: N/A.
 *
 * ERRNO: N/A
 */

static void virtioSetStatus(struct virtio_device* vdev,
                            uint8_t status)
{
        virtio_write(vdev, VIRTIO_MMIO_STATUS, status);
}

/**
 * virtioGetStatus - get status from virtio device
 *
 * This routine gets status from virtio device.
 *
 * RETURNS: N/A.
 *
 * ERRNO: N/A
 */

static uint8_t virtioGetStatus(struct virtio_device* vdev)
{
	return (uint8_t)(virtio_read(vdev, VIRTIO_MMIO_STATUS) & 0xffU);
}

void virtio_add_status(struct virtio_device* vdev, uint8_t status)
{
        uint8_t l_status = virtioGetStatus(vdev);
        virtioSetStatus(vdev, (l_status | status));
}

void* virtqueueGetBuffer(struct virtqueue* pQueue,
			 unsigned int *pLen,
			 uint32_t* pToken)
{
	uint16_t usedIdx;
	uint32_t getToken;
	void* cookie;

	if (pQueue == NULL) {
		VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_ERR,
				   "null queue pointer\n");
		return NULL;
        }

	__mb();
	VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_QUEUE,
			   "start\n");

	if (pQueue->usedIdx == virtio16_to_cpu(pQueue->vdev,
					       pQueue->vRing.used->idx)) {
		return NULL;
	}

	/* idx always increments, and wraps naturally at 65536 */
	usedIdx = pQueue->usedIdx++ & (uint16_t) (pQueue->vRing.num - 1U);
	getToken = virtio32_to_cpu(pQueue->vdev,
				   pQueue->vRing.used->ring[usedIdx].id);

	if (getToken >= pQueue->vRing.num) {
		VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_ERR,
				   "ERR head:%d,num:%d\n",
				   getToken, pQueue->vRing.num);
		return NULL;
	}

	if (pLen != NULL) {
		*pLen = virtio32_to_cpu(pQueue->vdev,
					pQueue->vRing.used->ring[usedIdx].len);
        }

	if (pToken != NULL) {
		*pToken = getToken;
	}

	cookie = pQueue->vqDescx[getToken].cookie;
	/* increase the free desc cnt */

	pQueue->num_free += pQueue->vqDescx[getToken].ndescs;
	pQueue->vqDescx[getToken].cookie = NULL;
	pQueue->vqDescx[getToken].ndescs = 0;

	if ((pQueue->availFlagShadow &
	     (uint16_t)VRING_AVAIL_F_NO_INTERRUPT) == 0U) {
		vring_used_event(&pQueue->vRing) =
			cpu_to_virtio16(pQueue->vdev, pQueue->usedIdx);
	}

	__mb();

	VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_QUEUE,
			   "done\n");
	return cookie;
}

bool virtqueue_is_broken(struct virtqueue *_vq)
{
	return _vq->isBroken;
}

const volatile struct vring* virtqueue_get_vring(struct virtqueue *vq)
{
	return &vq->vRing;
}

/*
 * VirtIO device functions
 */

/**
 * Initialize VirtIO device internal structures
 * @vdev: virtual device pointer
 */
void virtioDevInit(struct virtio_device* vdev)
{
	TAILQ_INIT(&vdev->queueList);
	pthread_mutex_init(&vdev->config_lock, NULL);
	pthread_mutex_init(&vdev->vqs_list_lock, NULL);
}

/**
 * Deallocate VirtIO device virtual queues
 * @vdev: virtual device pointer
 */
void virtioDevFree(struct virtio_device* vdev)
{
	int i;

	VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_INFO, "start\n");
	VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_INFO, "vdev\n");
	VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_INFO, "freeing vqueues and vrings\n");

	for (i = 0; i < vdev->nVqs; i++) {
		if (vdev->ringAddr[i] != NULL) {
			free(vdev->ringAddr[i]);
		}
		if (vdev->queues[i] != NULL) {
			virtqueueDeinitIndirect(vdev->queues[i]);
				free(vdev->queues[i]);
		}
	}
	vdev->nVqs = 0;
	VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_INFO, "freeing vqueues and vrings ptrs\n");
	if (vdev->ringAddr != NULL) {
		free(vdev->ringAddr);
		vdev->ringAddr = NULL;
	}
	if (vdev->queues != NULL) {
		free(vdev->queues);
		vdev->queues = NULL;
	}
	VIRTIO_LIB_DBG_MSG(VIRTIO_LIB_DBG_INFO, "done\n");
}

/**
 * Obtain or create memory region
 * @ctrl_fd: control device file descriptor
 * @addr: host physical address
 * @size: memory size
 * @offset: returning parameter, region offset
 *
 * @return: 0 on success, -1 on error
 */
size_t virtioRegionGet(int ctrl_fd, PHYS_ADDR addr, size_t size,
		       uint32_t* offset)
{
	int err;
	struct virtio_region region = {
                .addr = addr,
		.size = size
        };

	if (offset == NULL) {
		errno = EINVAL;
		return -1;
	}
	err = ioctl(ctrl_fd, VHOST_VIRTIO_ADD_REGION, &region);
	if (err != 0) {
		VIRTIO_LIB_DBG_MSG(
			VIRTIO_LIB_DBG_ERR,
			"Adding VirtIO memory region failed: %s\n",
			strerror(errno));
                        return -1;
	}
	*offset = region.offs;
	return 0;
}
