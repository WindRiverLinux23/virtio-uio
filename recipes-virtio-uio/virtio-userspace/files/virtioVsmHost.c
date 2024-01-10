/* virtio host VSM functions */

/*
 * Copyright (c) 2022-2023 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

/*
DESCRIPTION

This is the virtio host service module that implements the low-level functions
required by VirtIO host.

*/

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <malloc.h>
#include <sys/queue.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/virtio_mmio.h>
#include <pthread.h>
#include <semaphore.h>
#include "uio-virtio.h"
#include "virtio_host_lib.h"

/* defines */

#define VIRTIO_VSM_DBG
#ifdef VIRTIO_VSM_DBG

#define VIRTIO_VSM_DBG_OFF             0x00000000
#define VIRTIO_VSM_DBG_ERR             0x00000001
#define VIRTIO_VSM_DBG_IOREQ           0x00000002
#define VIRTIO_VSM_DBG_IRQREQ          0x00000004
#define VIRTIO_VSM_DBG_QUEUE           0x00000008
#define VIRTIO_VSM_DBG_CFG             0x00000010
#define VIRTIO_VSM_DBG_INFO            0x00000020
#define VIRTIO_VSM_DBG_ALL             0xffffffff

static uint32_t virtioHostDbgMask = VIRTIO_VSM_DBG_INFO;

#define VIRTIO_VSM_DBG_MSG(mask, fmt, ...)				\
	do {								\
		if ((virtioHostDbgMask & (mask)) ||			\
		    ((mask) == VIRTIO_VSM_DBG_ERR)) {			\
			printf("%d: %s() " fmt, __LINE__, __func__,	\
			       ##__VA_ARGS__);				\
		}							\
	}								\
while ((false));
#else
#undef VIRTIO_VSM_DBG_MSG
#define VIRTIO_VSM_DBG_MSG(...)
#endif  /* VIRTIO_VSM_DBG */

#define VIRTIO_VSM_COMP_QUEUE           (pDrvCtrl->channelMax)
#define VIRTIO_VSM_IRQ_QUEUE            (pDrvCtrl->channelMax + 1)
#define VIRTIO_VSM_REQ_QUEUE(queueId)   (queueId)

#define VIRTIO_QUEUE_NAME_LEN     256

#define container_of(ptr, type, member) ({				\
		        typeof( ((type *)0)->member ) *__mptr = (ptr); \
			(type *)( (char *)__mptr - offsetof(type,member) );})

/* local declarations */

struct virtqueueBuf
{
	void *buf;
	uint32_t len;
};

/* virtio vsm io request */
struct virtioVsmReq
{
        uint32_t channelId;
        uint32_t type;
        uint64_t address;
        uint64_t size;
        uint32_t value;
        uint32_t pad;
        uint8_t status;
};

/* virtio vsm irq request */
struct virtioVsmIrq
{
	uint32_t channelId;
	uint32_t value;
};

/* virtque callback function */
typedef void (*vqCallbackFn) (struct virtqueue *);
typedef void (*vqKickFn) (const struct virtqueue *);

/* Virtio queue info */

struct virtqueueInfo
{
	char         name [VIRTIO_QUEUE_NAME_LEN];
	vqCallbackFn cb;
	size_t       idrNum;
};

struct virtioOps
{
	/* the Virtio device interrupt callback */
	vqCallbackFn     cb;

	/* used to notify remote Virtio device */
	vqKickFn         kick;
};


/**
 * struct virtqueue - a queue to register buffers for sending or receiving.
 * @list: the chain of virtqueues for this device
 * @callback: the function to call when buffers are consumed (can be NULL).
 * @name: the name of this virtqueue (mainly for debugging)
 * @vdev: the virtio device this queue was created for.
 * @priv: a pointer for the virtqueue implementation to use.
 * @index: the zero-based ordinal number for this queue.
 * @num_free: number of elements we expect to be able to fit.
 * @num_max: the maximum number of elements supported by the device.
 * @reset: vq is in reset state or not.
 * @availIdx: the next desc to add buf
 * @usedIdx: the next used to get buf
 * @lastAvailIdx: last avail when do kick
 * @indirect: if the buffers are indirect
 * @vqDescx: internal data structure
 *
 * A note on @num_free: with indirect buffers, each buffer needs one
 * element in the queue, otherwise a buffer will need one element per
 * sg element.
 */
struct virtqueue {
	TAILQ_ENTRY(virtqueue) node;
	struct vring vRing;
	struct virtioOps func;
	const char *name;
	struct virtio_device *vdev;
	unsigned int index;
	unsigned int num_free;
	unsigned int num_max;
	bool reset;
	uint16_t availIdx;
	uint16_t usedIdx;
	uint16_t lastAvailIdx;
	bool indirect;
	size_t idrNum;
	struct vqDescExtra {
		void* data;
		struct vring_desc* idrTbl;
		PHYS_ADDR idrTblPhy;
		uint16_t ndescs;
        } vqDescx[0];
};

struct vring_virtqueue {
	struct virtqueue vq;

	/*
	 * Last written value to avail->idx in
	 * guest byte order.
	 */
	uint16_t avail_idx;

	/* Head of free buffer list. */
	unsigned int free_head;

	/* Number we've added since last sync. */
	unsigned int num_added;
	struct vring vring;
};

/* virtio vsm virtual queue */
struct virtioVsmQueue
{
	struct virtioVsm *pDrvCtrl;
	struct virtioHost *vHost;
	uint32_t channelId;
	bool int_pending;
	pthread_mutex_t int_lock;
	struct virtqueue *pReqQueue;
	pthread_t* req_thread;
	sem_t req_sem;
	struct virtioVsmReq *req;
};

struct virtioVsm
{
	uint32_t queueNum;
	uint32_t reqQueueNum;
	uint32_t channelMax; /* max channel */

	pthread_t* irq_job;
        pthread_t* comp_job;

	int virtioVsmUnit;
	struct virtio_device *vdev;
	uint64_t features;

	/* virt queue */
	struct virtqueue **pQueue;

	/* virt queue info */
	struct virtqueueInfo* pVirtqueueInfo;

	/* irq queue array */

	pthread_mutex_t irq_lock;
	uint32_t irqProd;
	struct virtioVsmIrq *pIrq;

	/* virtio host channel */
	struct virtioVsmQueue pVsmQueue[0];
};

/* virtio vsm config */
struct virtioVsmConfig
{
	uint32_t channelMax;
	uint32_t channelId[1];
};

typedef struct {
	uint64_t pfn : 55;
	unsigned int soft_dirty : 1;
	unsigned int file_page : 1;
	unsigned int swapped : 1;
	unsigned int present : 1;
} virtioPagemapEntry;



/* forward declarations */

static struct virtioVsmQueue *virtioVsmGetQueue(struct virtioVsm *pVsm,
						uint32_t channelId);
static int virtioVsmQueueInit(struct virtioVsmQueue *pVsmQueue,
			      struct virtioHost *vHost);
static int virtioVsmNotify(struct virtioVsmQueue *pVsmQueue,
			   struct virtioHost *vHost,
			   uint32_t status);
static int virtioVsmShmRegionGet(struct virtioVsm *pVsm,
				 struct virtioVsmShmRegion * pVsmRegion);
static void virtioVsmShmRegionRelease(struct virtioVsm *pVsm,
				      struct virtioVsmShmRegion *pVsmRegion);
static void virtioVsmQueueDone (struct virtqueue *);

/* locals */

#define to_vvq(_vq) container_of(_vq, struct vring_virtqueue, vq)

/**
 * virtqueue_get_vring_size - return the size of the virtqueue's vring
 * @_vq: the struct virtqueue contained in the vring of interest.
 *
 * Returns the size of the vring.  This is mainly used for boasting to
 * userspace.  Unlike other operations, this need not be serialized.
 */
unsigned int virtqueue_get_vring_size(struct virtqueue *vq)
{
	return vq->vRing.num;
}


static void virtio_write(struct virtio_device *vdev,
			 uint32_t reg,
			 uint32_t val)
{
        host_writel(htole32(val), (uint32_t*)(vdev->dev.base + reg));
	__mb();
}

static uint32_t virtio_read(struct virtio_device *vdev,
			    uint32_t reg)
{
	__mb();
	return le32toh(host_readl((uint32_t*)(vdev->dev.base + reg)));
}

/* FIXME: assume that virtio stores little endian data */
uint16_t virtio16_to_cpu(struct virtio_device *vdev, __virtio16 val)
{
	return le16toh(val);
}

uint32_t virtio32_to_cpu(struct virtio_device *vdev, __virtio32 val)
{
	return le32toh(val);
}

uint64_t virtio64_to_cpu(struct virtio_device *vdev, __virtio64 val)
{
	return le64toh(val);
}

__virtio16 cpu_to_virtio16(struct virtio_device *vdev, uint16_t val)
{
	return htole16(val);
}

__virtio32 cpu_to_virtio32(struct virtio_device *vdev, uint32_t val)
{
	return htole32(val);
}

__virtio64 cpu_to_virtio64(struct virtio_device *vdev, uint64_t val)
{
	return htole64(val);
}


static struct virtioHostVsm virtioHostVsmDev = {
	.vsmId = NULL,
	.vsmOps =  {
		.getQueue         = virtioVsmGetQueue,
		.init             = virtioVsmQueueInit,
		.notify           = virtioVsmNotify,
		.shmRegionGet     = virtioVsmShmRegionGet,
		.shmRegionRelease = virtioVsmShmRegionRelease,
	}
};

/* functions */

static void virtioVsmVirtqueueEnable(struct virtio_device* vdev,
				     int queueId, bool enable)
{
	virtio_write(vdev, VIRTIO_MMIO_QUEUE_SEL, queueId);
	virtio_write(vdev, VIRTIO_MMIO_QUEUE_READY,
		     (enable == true)? 1: 0);
}

static int virtioVsmQueueInit(struct virtioVsmQueue *pVsmQueue,
			      struct virtioHost *vHost)
{
	struct virtioVsm *pDrvCtrl;
	uint32_t queueId;

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
			"start\n");

	if (!pVsmQueue) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				"pVsmQueue is NULL\n");
		errno = EINVAL;
		return -1;
	}

	if (!pVsmQueue->pDrvCtrl) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				"pVsmQueue->pDrvCtrl is NULL\n");
		errno = EINVAL;
		return -1;
	}

	if (!vHost) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				"vHost is NULL\n");
		errno = EINVAL;
		return -1;
	}

	pDrvCtrl = pVsmQueue->pDrvCtrl;

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
			   "pDrvCtrl->pVsmQueue:0x%lx pVsmQueue:"
			   "0x%lx vHost:0x%lx\n",
			   (unsigned long)pDrvCtrl->pVsmQueue,
			   (unsigned long)pVsmQueue,
			   (unsigned long)vHost);

	queueId = (uint32_t)(pVsmQueue - pDrvCtrl->pVsmQueue);
	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
			   "queueId:%u\n", queueId);

	pVsmQueue->vHost = vHost;

	pVsmQueue->int_pending = false;

	virtioVsmVirtqueueEnable((pDrvCtrl->pQueue[queueId])->vdev,
				 queueId, true);
	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "done\n");

	return 0;
}

static struct virtioVsmQueue *virtioVsmGetQueue(struct virtioVsm *pVsm,
						uint32_t channelId)
{
	bool found = false;
	uint32_t i;

	if (!pVsm)
		return NULL;

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "start\n");

	for (i = 0; i < pVsm->channelMax; i++)
		if (pVsm->pVsmQueue[i].channelId == channelId) {
			found = true;
			break;
		}

	if (!found) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				"invalid channel ID (%d)\n",
				channelId);
		return NULL;
	}

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
		"got queue (%d)\n", i);

	return (&pVsm->pVsmQueue[VIRTIO_VSM_REQ_QUEUE(i)]);
}


/*
 * Very limited and simplified function that adds irq to the VirtIO buffer
 */
static int virtqueueAddIrqBuf(struct virtioHost *vHost,
			      struct virtqueue* _vq,
			      struct virtioVsmIrq* irq)
{
	unsigned int i;
	unsigned int head;
	unsigned int avail;
	unsigned int descs_used = 1; /* we use only one buffer */
	struct vring_desc *desc;
	struct vring_virtqueue *vq = to_vvq(_vq);
	VIRT_ADDR* buf; /* virtual buffer address */
	struct virtioVsmIrq* irqBuf;

	desc = vq->vring.desc;
	if (desc == NULL) {
		return -1;
	}
	head = vq->free_head;
	/* convert buffer address from guest-physical to virtual */
	if (virtioHostTranslate(vHost,
		host_virtio64_to_cpu(vHost, desc[head].addr), buf) != 0) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				   "address 0x%llx conversion error\n",
				   desc[i].addr);
		return -1;
	}
	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				   "address 0x%llx converted to %p\n",
			   desc[head].addr, buf);

	/*
	 * Copy data. Assume that the buffer is in the mapped memory.
	 */
	irqBuf = (struct virtioVsmIrq*)buf;
	irqBuf->channelId = irq->channelId;
	irqBuf->value = irq->value;

	/* fill in the required structures */
	i = head;
	desc[i].len = sizeof(struct virtioVsmIrq);
	desc[i].flags = 0;
	head = desc[i].next;

	/*
	 * Put entry in available array (but don't update avail->idx until they
	 * do sync).
	 */
	avail = vq->avail_idx & (vq->vring.num - 1);
	vq->vring.avail->ring[avail] = host_cpu_to_virtio16(vHost, head);

	__mb();
	vq->avail_idx++;
	vq->vring.avail->idx = host_cpu_to_virtio16(vHost,
						    vq->avail_idx);
	vq->num_added++;

	return 0;
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


/*
 * Notify Hypervisor that the new buffer is available
 */
static int virtioVsmKick(struct virtioHost *vHost, struct virtqueue *vq)
{
	uint16_t old, new;
	bool needs_kick;

	/*
	 * We need to expose available array entries before checking avail
	 * event. (We do not do it now, but may do in the future).
	 */
	__mb();

	needs_kick = !(vq->vRing.used->flags &
		       host_cpu_to_virtio16(vHost,
					    VRING_USED_F_NO_NOTIFY));
	if (!needs_kick) {
		return 0;
	}

	virtio_write(vq->vdev, VIRTIO_MMIO_QUEUE_NOTIFY, vq->index);

	return 0;
}

static int virtioVsmNotify(struct virtioVsmQueue *pVsmQueue,
			   struct virtioHost *vHost,
			   uint32_t status)
{
	struct virtioVsm *pDrvCtrl;
	struct virtqueueBuf bufList[1];
	struct virtqueue *pIrqQueue;
	struct virtioVsmIrq *irq;
	uint32_t num;
	int rc;

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "start\n");

	if (!pVsmQueue || !pVsmQueue->pDrvCtrl || !vHost) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "invalid input parameter\n");
		errno = EINVAL;
		return -1;
	}

	pDrvCtrl = pVsmQueue->pDrvCtrl;

	pthread_mutex_lock(&pDrvCtrl->irq_lock);

	pIrqQueue = pDrvCtrl->pQueue[VIRTIO_VSM_IRQ_QUEUE];

	if (pIrqQueue->num_free == 0) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "no irq resource available\n");
	}

	irq = &pDrvCtrl->pIrq[pDrvCtrl->irqProd];

	/* take along the status */
	irq->channelId = vHost->channelId;
	irq->value = status;

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
			   "channelId:%u value:0x%x\n",
			   irq->channelId, irq->value);

	num = virtqueue_get_vring_size(pIrqQueue);
	pDrvCtrl->irqProd = (pDrvCtrl->irqProd + 1) % num;

	// TODO modify with virtqueueAddBuffer
	rc = virtqueueAddIrqBuf(vHost, pIrqQueue, irq);
	if (rc) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "virtqueue_add_inbuf_ctx failed %d\n",
				   rc);
		pthread_mutex_unlock(&pDrvCtrl->irq_lock);
		return rc;
	}

	virtioVsmKick(vHost, pIrqQueue);

	pthread_mutex_unlock(&pDrvCtrl->irq_lock);

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "done\n");

	return 0;
}

/*
 * Obtain VirtIO shared memory region
 * regs - VirtIO registers address
 * region - region descriptor structure
 * idx - region index
 */

static void virtioReadShmRegion(struct virtio_device* vdev,
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
 * Obtain memory region info by ID and fill in the region
 * structure
 *
 * Returns true if the region is present and false otherwise
 */
static bool virtio_get_shm_region(struct virtioVsm *pVsm,
				  struct virtioShmRegion* vregion,
				  int id)
{
	/*
	 * Original code gets shared memory region from the Hypervisor
	 * directly. Once we obtained the GuestOS memory regions
	 * information from the YAML configuration ot dtb, we can
	 * directly ask the kernel for this information
	 */
	struct virtio_region region = {
		.indx = id,
	};

	int err;
	int ctrl_fd; /* control device file descriptor */

	if (pVsm == NULL || vregion == NULL) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "invalid input parameters\n");
		errno = EINVAL;
		return false;
	}
	if (pVsm->vdev == NULL) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "VSM virtio device not initialized\n");
		errno = EINVAL;
		return false;
	}
	if (pVsm->vdev->virtio_ctrl_device == NULL) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "VSM virtio control device name is NULL\n");
		errno = EINVAL;
		return false;
	}
	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
			   "Obtaining %d memory region\n", region.indx);
	ctrl_fd = open(pVsm->vdev->virtio_ctrl_device, O_RDWR | O_SYNC);
	if (ctrl_fd < 0) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "opening control device failed: %s\n",
				   strerror(errno));
		return false;
	}
	err = ioctl(ctrl_fd, VHOST_VIRTIO_GET_REGION, &region);
	if (err != 0) {
		/*
		 * The UIO driver holds region 0 as a region of virtio
		 * registers and a configuration region as region 1
		 * while other VirtIO components start with configuration
		 * region. For this reason we need to subtract the config.
		 * region number in VirtIO requests.
		 */
		virtioReadShmRegion(pVsm->vdev, &region,
				    region.indx - VIRTIO_VSM_CFG_REGION);
                err = ioctl(ctrl_fd, VHOST_VIRTIO_ADD_REGION, &region);
                if (err != 0) {
                        printf("Adding VirtIO memory region failed: %s\n",
                               strerror(errno));
                        return -1;
                }
	}
	close(ctrl_fd);
	vregion->paddr = region.addr;
	vregion->len = region.size;
	vregion->id = region.indx;
	vregion->offset = region.offs;
	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "done\n");
	return true;
}


static int virtioVsmShmRegionGet(struct virtioVsm *pVsm,
				 struct virtioVsmShmRegion * pVsmRegion)
{
	int uio_fd;

	if (!pVsm || !pVsmRegion) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				"invalid input parameters\n");
		errno = EINVAL;
		return -1;
	}
	if (pVsm->vdev == NULL) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "VSM virtio device not initialized\n");
		errno = EINVAL;
		return false;
	}
	if (pVsm->vdev->uio_device == NULL) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "VSM virtio UIO device name is NULL\n");
		errno = EINVAL;
		return false;
	}

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
			"start\n");

	if (!virtio_get_shm_region(pVsm, &(pVsmRegion->region),
		VIRTIO_VSM_CFG_REGION)) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				"virtio_get_shm_region failed\n");
		errno = ENOMEM;
		return -1;
	}
	uio_fd = open(pVsm->vdev->uio_device, O_RDWR | O_SYNC);
	if (uio_fd < 0) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "UIO device error: %s\n",
				   strerror(errno));
		return -1;
	}
	pVsmRegion->vaddr = mmap(NULL, pVsmRegion->region.len,
				 PROT_READ | PROT_WRITE,
				 MAP_SHARED, uio_fd,
				 pVsmRegion->region.offset);
	if (pVsmRegion->vaddr == MAP_FAILED) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "memory map failed\n");
		close(uio_fd);
		errno = ENOSPC;
		return -1;
	}
	close(uio_fd);
	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
			   "region phys addr:0x%lx, len 0x%lx ->virtual: %p\n",
			   pVsmRegion->region.paddr,
			   pVsmRegion->region.len, pVsmRegion->vaddr);

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "done\n");

	return 0;
}

static void virtioVsmShmRegionRelease(struct virtioVsm *pVsm,
				      struct virtioVsmShmRegion *pVsmRegion)
{
	struct virtio_shm_region *region = (struct virtio_shm_region *)pVsmRegion;

	if (!pVsm || !pVsmRegion)
		return;

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
			   "start\n");

	munmap(pVsmRegion->vaddr, pVsmRegion->region.len);

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
			   "done\n");

	return;
}

extern void virtioHostBlkDrvInit(uint32_t mountTimeout);
extern void virtioHostBlkDrvRelease(void);

/*
 * Get maximum number of channels from the VirtIO configuration space
 * Assumed that VirtIO device base address is set to VirtIO shared space
 * that has been mapped to user space.
 */
static int virtioGetChannelMax(struct virtio_device *vdev,
			       uint32_t* channelMax)
{
	struct virtioVsmConfig* cfg;

	if (vdev == NULL || vdev->dev.base == NULL || channelMax == NULL) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "invalid input parameter\n");
		errno = EINVAL;
		return -1;
	}
	cfg = (struct virtioVsmConfig*)(vdev->dev.base + VIRTIO_MMIO_CONFIG);
	*channelMax = cfg->channelMax;
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
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "invalid input parameter\n");
		errno = EINVAL;
		return -1;
	}
	cfg = (uint32_t*)(vdev->dev.base + VIRTIO_MMIO_CONFIG + offset);
	return *cfg;
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
	    pQueue->idrNum = 0;
	    return 0;
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

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "start\n");
	if ((pQueue == NULL) || (vDev == NULL) ||
	    (pAddr == NULL) || (pVirtqueueInfo == NULL)) {
		errno = EINVAL;
		return -1;
        }
	bzero(pAddr, vring_size(num, align));
	vring_init(&pQueue->vRing, num, pAddr, align);

	pQueue->vdev = vDev;
	pQueue->num_free = num;
	pQueue->func.kick = pKick;
	pQueue->func.cb = pVirtqueueInfo->cb;
	pQueue->usedIdx = 0;
	pQueue->availIdx = 0;
	pQueue->lastAvailIdx = 0;
#if 0   /// for now
	pQueue->availFlagShadow = 0;
	pQueue->name = pVirtqueueInfo->name;
#endif

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

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "done\n");
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
		       void* data)
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
	    (bufList == NULL) || (data == NULL)) {
		errno = EINVAL;
		return -1;
        }

	if (pQueue->num_free == 0)
        {
		errno = ENOSPC;
		return -1;
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
			errno = ENOSPC;
			return -1;
		}

		pQueueCommDesc = pQueue->vRing.desc;
		indirect = false;
        }
	if (indirect) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "Indirect queues are not supported\n");
		errno = ENOTSUP;
		return -1;
	}
	for (idx = 0; idx < bufCnt; idx++) {
		if (vmTranslate((uintptr_t)bufList[idx].buf,
				 &bufPhysAddr) != 0) {
			VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
					   "translate buf fail\n");
			errno = EINVAL;
			return -1;
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
		pQueue->vqDescx[firstAvailIdx].data = data;
		pQueue->vqDescx[firstAvailIdx].ndescs = 1;
		pQueue->num_free--;
		pQueue->availIdx = pQueueDesc->next;
        }
	else {
		pQueue->vqDescx[firstAvailIdx].data = data;
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
		return -1;
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


static int setup_vq(struct virtio_device *vdev, unsigned int index,
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

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "start\n");
	/* Select the queue we're interested in */
	virtio_write(vdev, VIRTIO_MMIO_QUEUE_SEL, index);

	num = virtio_read(vdev, VIRTIO_MMIO_QUEUE_NUM_MAX);
	if (num == 0) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "Queue %d is not supported\n",
				   index);
		errno = ENOTSUP;
		return -1;
	}

	vdev->ringAddr[index] = (VIRT_ADDR)memalign(align,
						    vring_size(num, align));
	if (vdev->ringAddr[index] == (VIRT_ADDR)NULL) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "failed to allocate ring %x\n",
				   index);
		errno = ENOMEM;
		return -1;
        }
	vdev->queues[index] = zmalloc(sizeof(struct virtqueue)
				     + sizeof(struct vqDescExtra) * num);
	if (vdev->queues[index] == NULL) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
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
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "failed to initialize "
				   "virtqueueRingInit %x\n", index);
		return -1;
        }
	virtio_write(vdev, VIRTIO_MMIO_QUEUE_NUM, num);

	if (vdev->dev.version == 1) {
		if (vmTranslate((uintptr_t)vdev->ringAddr[index],
				&pAddr) != 0) {
			VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
					   "failed to translate "
					   "address %x: %s\n",
					   index, strerror(errno));
			return -1;
		}
		pfn = pAddr / align;
		if (pfn > 0xffffffffUL) {
			VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
					   "fdtVirtioVqSetup ring address"
					   "exceed support range %x\n", index);
			errno = ENOTSUP;
			return -1;
		}
		virtio_write(vdev, VIRTIO_MMIO_QUEUE_ALIGN, (uint32_t)align);
		virtio_write(vdev, VIRTIO_MMIO_QUEUE_PFN, (uint32_t)pfn);

		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				   "ring %x queue(%p)"
				   "max queue size(0x%x) "
				   "align(0x%lx) virtual (%p)\n",
				   index, vdev->queues[index],
				   num, align, vdev->ringAddr[index]);
	} else {
		/* descriptors*/
		vAddr = (uintptr_t)virtqueueGetDescAddr(vdev->queues[index]);
		if (vmTranslate(vAddr, &descAddr) < 0) {
			VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
					   "desc addr translation "
					   "failed %s\n",
					   strerror(errno));
			return -1;
		}
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				   "vring %d desc 0c%lx -> 0x%lx\n",
				   index, vAddr, descAddr);
		virtio_write(vdev, VIRTIO_MMIO_QUEUE_DESC_LOW,
			     (uint32_t)descAddr);
		virtio_write(vdev, VIRTIO_MMIO_QUEUE_DESC_HIGH,
			     (uint32_t)((uint64_t)descAddr >> 32));

		/* available buffers */
		vAddr = (uintptr_t)virtqueueGetAvailAddr(vdev->queues[index]);
		if (vmTranslate(vAddr, &availAddr) < 0) {
			VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
					   "available addr translation "
					   "failed %s\n",
					   strerror(errno));
			return -1;
		}
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				   "vring %d available 0x%lx -> 0x%lx\n",
				   index, vAddr, availAddr);
		virtio_write(vdev, VIRTIO_MMIO_QUEUE_AVAIL_LOW,
			     (uint32_t)availAddr);
		virtio_write(vdev, VIRTIO_MMIO_QUEUE_AVAIL_HIGH,
			     (uint32_t)((uint64_t)availAddr >> 32));

		/* used buffers */
		vAddr = (uintptr_t)virtqueueGetUsedAddr(vdev->queues[index]);
		if (vmTranslate(vAddr, &usedAddr) < 0) {
			VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
					   "used addr translation "
					   "failed %s\n",
					   strerror(errno));
			return -1;
		}
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				   "vring %d used 0x%lx -> 0x%lx\n",
				   index, vAddr, usedAddr);
		virtio_write(vdev, VIRTIO_MMIO_QUEUE_USED_LOW,
			     (uint32_t)usedAddr);
		virtio_write(vdev, VIRTIO_MMIO_QUEUE_USED_HIGH,
			     (uint32_t)((uint64_t)usedAddr >> 32));
	}
	return 0;
}

/*
 * Initialize Virtqueues
 */

static int init_vq(struct virtioVsm *pDrvCtrl)
{
	uint32_t queueId;
	int err;

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "start\n");

	/* create callback and name array */

	pDrvCtrl->pVirtqueueInfo = zmalloc(pDrvCtrl->queueNum *
					    sizeof(struct virtqueueInfo));
	if (pDrvCtrl->pVirtqueueInfo == NULL) {
		VIRTIO_VSM_DBG_MSG (VIRTIO_VSM_DBG_ERR,
                           "virtio queue info mem alloc failed\n");
		return -1;
        }

	for (queueId = 0; queueId < pDrvCtrl->queueNum; queueId++) {
		/* setup callback and name array */

		pDrvCtrl->pVirtqueueInfo[queueId].cb = virtioVsmQueueDone;

		if (queueId == VIRTIO_VSM_COMP_QUEUE) {
			snprintf (pDrvCtrl->pVirtqueueInfo[queueId].name,
				  VIRTIO_QUEUE_NAME_LEN,
				  "virtio-host complete queue(%d)", queueId);
		}
		else if (queueId == (VIRTIO_VSM_IRQ_QUEUE)) {
			snprintf (pDrvCtrl->pVirtqueueInfo[queueId].name,
				  VIRTIO_QUEUE_NAME_LEN,
				  "virtio-host irq queue(%d)", queueId);
		}
		else {
			snprintf (pDrvCtrl->pVirtqueueInfo[queueId].name,
				  VIRTIO_QUEUE_NAME_LEN,
				  "virtio-host req queue(%d)", queueId);
		}
        }

	pDrvCtrl->vdev->nVqs = pDrvCtrl->queueNum;
	pDrvCtrl->vdev->queues = zmalloc(sizeof(struct virtqueues *) *
					 pDrvCtrl->vdev->nVqs);
	pDrvCtrl->vdev->ringAddr = zmalloc(sizeof(VIRT_ADDR *) *
					   pDrvCtrl->vdev->nVqs);
	if (pDrvCtrl->vdev->queues == NULL ||
	    pDrvCtrl->vdev->ringAddr == NULL) {
		VIRTIO_VSM_DBG_MSG (VIRTIO_VSM_DBG_ERR,
				    "device virtqueue and vring "
				    "pointers setup failed\n");
		return -1;
	}

	/* allocates VirtIO queues */
	for (queueId = 0; queueId < pDrvCtrl->queueNum; queueId++) {
		if (setup_vq(pDrvCtrl->vdev, queueId,
			     &pDrvCtrl->pVirtqueueInfo[queueId]) != 0) {
			VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
					   "virtqueue %d setup FAILED\n",
					   queueId);
			break;
		}
	}
	if (queueId != pDrvCtrl->queueNum) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "failed\n");
		return -1;
	}

	pDrvCtrl->pQueue = pDrvCtrl->vdev->queues;
	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "done\n");
	return 0;
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

/*
 *
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


/*
 * VirtIO service module initialization function
 *
 * Note: we call this function after we map VirtIO address space to user space
 * and assign VirtIO device base address to the mapped address.
 */
int virtvsm_init(struct virtio_device *vdev)
{
	uint32_t channelMax = 0;
	uint32_t queueNum = 0;
	struct virtioVsm *pDrvCtrl = NULL;
	int i;
	uint32_t status; /* VirtIO status */
	uint32_t devId;
	uint32_t vendorId;
	uint32_t offset;
	uint32_t queueId;
	struct virtioVsmQueue* pVsmQueue;
	uint32_t num;
	uint64_t reqAddr;
	struct virtqueueBuf bufList[1];

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "start\n");

	/* Initialize the device */
	TAILQ_INIT(&vdev->queueList);
	pthread_mutex_init(&vdev->config_lock, NULL);
	pthread_mutex_init(&vdev->vqs_list_lock, NULL);

	/* Verify magic number */
	if (virtio_read(vdev, VIRTIO_MMIO_MAGIC_VALUE) !=
	    VIRTIO_MMIO_MAGIC_VALUE_LE) {
                VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "Virtio MMIO magic value is not "
				   "recongnized\n");
		return -1;
	}

	/* get the version */
	vdev->dev.version = virtio_read(vdev, VIRTIO_MMIO_VERSION);
	if (vdev->dev.version == 0x1U) {
		virtio_write(vdev, VIRTIO_MMIO_GUEST_PAGE_SIZE,
			     getpagesize());
	}

	/* check device id */
	devId = virtio_read(vdev, VIRTIO_MMIO_DEVICE_ID);
	if (devId == 0U) {
		return -1;;
        }

	/* get vendor ID */
	vendorId = virtio_read(vdev, VIRTIO_MMIO_VENDOR_ID);

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
			   "Probe Virtio "
			   "device (deviceId %x, vendor %x, version %x)\n",
			   devId, vendorId, vdev->dev.version);

	/* Get max channels */
	if (virtioGetChannelMax(vdev, &channelMax) != 0) {
		return -1;
	}

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "channelMax = %d\n",
		channelMax);

	queueNum = channelMax + 2;

	pDrvCtrl = zmalloc(sizeof(*pDrvCtrl) +
			   queueNum * sizeof(struct virtioVsmQueue));

	if (pDrvCtrl == NULL) {
                VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "virtioVsm memory allocation failed\n");
                return -1;
        }

        pDrvCtrl->channelMax = channelMax;
        pDrvCtrl->queueNum = queueNum;
        pDrvCtrl->reqQueueNum = channelMax;

	//TODO: start the servicing threads

	/* set virtio device private data */
        vdev->priv = pDrvCtrl;

        /* save vDev to driver control */
        pDrvCtrl->vdev = vdev;

	if (init_vq(pDrvCtrl) != 0) {
		goto failed;
	}

	/* setup the queue data for complete queue */
        virtioVsmVirtqueueEnable((pDrvCtrl->pQueue[VIRTIO_VSM_COMP_QUEUE])->vdev,
				 VIRTIO_VSM_COMP_QUEUE, true);

        /* setup the queue data for irq queue */
	virtioVsmVirtqueueEnable((pDrvCtrl->pQueue[VIRTIO_VSM_IRQ_QUEUE])->vdev,
				 VIRTIO_VSM_IRQ_QUEUE, true);

	VIRTIO_VSM_DBG_MSG (VIRTIO_VSM_DBG_INFO,
			    "setup the io req queue - start\n");

	/* setup the io req queue */
	offset = offsetof(struct virtioVsmConfig, channelId[0]);

	for (queueId = 0; queueId < pDrvCtrl->reqQueueNum; queueId++) {

		/* setup queue */
		pVsmQueue = pDrvCtrl->pVsmQueue + queueId;
		pVsmQueue->channelId = virtio_cread32(vdev, offset + queueId * 4);
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				   "queue[%d]: channelId: %d\n",
				   queueId, pVsmQueue->channelId);
		pVsmQueue->pReqQueue = pDrvCtrl->pQueue[queueId];
		pVsmQueue->pDrvCtrl  = pDrvCtrl;
		// later
		//pVsmQueue->qReqJob.func = (QJOB_FUNC)virtioVsmReqHandle;

		num = virtqueue_get_vring_size(pVsmQueue->pReqQueue);

		pVsmQueue->req = (struct virtioVsmReq*)calloc(
			num, sizeof(struct virtioVsmReq));
		if (pVsmQueue->req == NULL) {
			VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
					   "allocate buffer for request "
					   "queue[%d] failed\n",
					   queueId);
			goto failed;
		}

		/* add buf to desc ring */
		for (i = 0; i < num; i++) {
			reqAddr = (uint64_t)pVsmQueue->req +
				i * sizeof(struct virtioVsmReq);
			bufList[0].buf = (void *)reqAddr;
			bufList[0].len = sizeof(struct virtioVsmReq);
			(void) virtqueueAddBuffer(pVsmQueue->pReqQueue,
						  bufList, 0, 1,
						  (void *)reqAddr);
			(void) virtqueueKick(pVsmQueue->pReqQueue);
		}
		pthread_mutex_init(&pVsmQueue->int_lock, NULL);
		status = sem_init(&pVsmQueue->req_sem, 0, 0);
		if (status < 0) {
			VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "Failed to create VSM request queue "
					   "%d sem(%s)\n", queueId,
					   strerror(errno));
                        goto failed;
                }
	}

	VIRTIO_VSM_DBG_MSG (VIRTIO_VSM_DBG_INFO,
			    "setup the io req queue - done\n");

	VIRTIO_VSM_DBG_MSG (VIRTIO_VSM_DBG_INFO,
			    "mutex setup - start\n");

	pthread_mutex_init(&pDrvCtrl->pVsmQueue[VIRTIO_VSM_COMP_QUEUE].int_lock, NULL);
        pthread_mutex_init(&pDrvCtrl->pVsmQueue[VIRTIO_VSM_IRQ_QUEUE].int_lock, NULL);

        pthread_mutex_init(&pDrvCtrl->irq_lock, NULL);

	VIRTIO_VSM_DBG_MSG (VIRTIO_VSM_DBG_INFO,
			    "mutex setup - done\n");

	num = virtqueue_get_vring_size(pDrvCtrl->pQueue[pDrvCtrl->queueNum - 1]);
        pDrvCtrl->pIrq = calloc(num, sizeof(struct virtioVsmIrq));
        if (!pDrvCtrl->pIrq) {
                VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
                                "allocate IRQ buffer failed\n");
                goto failed;
        }

        pDrvCtrl->irqProd = 0;

        /* register VSM to virtio host library */
        virtioHostVsmDev.vsmId = pDrvCtrl;
        if (virtioHostVsmRegister(&virtioHostVsmDev)) {
                VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
                                "register to host library failed\n");
                goto failed;
        }
	virtioHostInit();

	VIRTIO_VSM_DBG_MSG (VIRTIO_VSM_DBG_INFO,
			    "virtioHostBlkDrvInit - enter\n");
        /* Init host block driver */
        virtioHostBlkDrvInit(10);
	VIRTIO_VSM_DBG_MSG (VIRTIO_VSM_DBG_INFO,
			    "virtioHostBlkDrvInit - exit\n");

	/* Init host lib */
	VIRTIO_VSM_DBG_MSG (VIRTIO_VSM_DBG_INFO,
			    "virtioHostDevicesInit - enter\n");
        virtioHostDevicesInit();
	VIRTIO_VSM_DBG_MSG (VIRTIO_VSM_DBG_INFO,
			    "virtioHostDevicesInit - exit\n");

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "done\n");
	return 0;
failed:
	virtvsm_deinit(vdev);
	return -1;
}

/*******************************************************************************
*
* vsm_deinit - destroy a virtio VSM device
*
* This routine destroys a  virtio VSM device.
*
* RETURNS: 0 when destroy successfully, otherwise fail.
*
* ERRNO: N/A
*/

void virtvsm_deinit(struct virtio_device *vdev)
{
        struct virtioVsm *pDrvCtrl = vdev->priv;
	int i;

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "start\n");
	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "vdev\n");
	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "freeing vqueues and vrings\n");
	for (i = 0; i < vdev->nVqs; i++) {
		if (vdev->ringAddr[i] != NULL) {
			free(vdev->ringAddr[i]);
		}
		if (vdev->queues[i] != NULL) {
			free(vdev->queues[i]);
		}
	}
	vdev->nVqs = 0;
	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "freeing vqueues and vrings ptrs\n");
	if (vdev->ringAddr != NULL) {
		free(vdev->ringAddr);
		vdev->ringAddr = NULL;
	}
	if (vdev->queues != NULL) {
		free(vdev->queues);
		vdev->queues = NULL;
	}
	if (!pDrvCtrl) {
                VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR, "null pDrvCtrl\n");
                return;
        }
	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "pDrvCtrl\n");
	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "freeing VirtqueueInfo\n");
	if (pDrvCtrl->pVirtqueueInfo != NULL) {
		free(pDrvCtrl->pVirtqueueInfo);
		pDrvCtrl->pVirtqueueInfo = NULL;
	}
	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "freeing pDrvCtrl\n");
	if (pDrvCtrl != NULL) {
		free(pDrvCtrl);
		vdev->priv = NULL;
	}
	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "done\n");
}

/*******************************************************************************
*
* virtioVsmQueueDone - vsm transmit done routine
*
* This routine is transmision done routine.
*
* RETURNS: N/A
*
* ERRNO: N/A
*/

static void virtioVsmQueueDone(struct virtqueue* pQueue)
{
	return;
}
