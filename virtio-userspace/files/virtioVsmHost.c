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
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/virtio_mmio.h>
#include <pthread.h>
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

static uint32_t virtioHostDbgMask = VIRTIO_VSM_DBG_ERR;

#define VIRTIO_VSM_DBG_MSG(mask, fmt, ...)				\
	do {								\
		if ((virtioHostDbgMask & (mask)) ||			\
		    ((mask) == VIRTIO_VSM_DBG_ALL)) {			\
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

#define container_of(ptr, type, member) ({				\
		        typeof( ((type *)0)->member ) *__mptr = (ptr); \
			(type *)( (char *)__mptr - offsetof(type,member) );})

/* local declarations */

struct virtqueueBuf
{
	void *buf;
	uint32_t len;
};

/* virtio vsm irq request */
struct virtioVsmIrq
{
	uint32_t channelId;
	uint32_t value;
};

struct virtio_device_id {
	uint32_t device;
	uint32_t vendor;
};

struct device {
	void* base; /* device base address */
};

/**
 * struct virtio_device - representation of a device using virtio
 * @index: unique position on the virtio bus
 * @failed: saved value for VIRTIO_CONFIG_S_FAILED bit (for restore)
 * @config_enabled: configuration change reporting enabled
 * @config_change_pending: configuration change reported while disabled
 * @config_lock: protects configuration change reporting
 * @vqs_list_lock: protects @vqs.
 * @dev: underlying device.
 * @id: the device type identification (used to match it with a driver).
 * @config: the configuration ops for this device.
 * @vringh_config: configuration ops for host vrings.
 * @vqs: the list of virtqueues for this device.
 * @features: the features supported by both driver and device.
 * @priv: private pointer for the driver's use.
 */
struct virtio_device {
	int index;
	bool failed;
	bool config_enabled;
	bool config_change_pending;
	pthread_mutex_t config_lock;
	pthread_mutex_t vqs_list_lock;
	struct device dev;
	struct virtio_device_id id;
	const struct virtio_config_ops *config;
	const struct vringh_config_ops *vringh_config;
	TAILQ_HEAD(vqList, virtqueue) vqs;
	uint64_t features;
	void *priv;
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
 *
 * A note on @num_free: with indirect buffers, each buffer needs one
 * element in the queue, otherwise a buffer will need one element per
 * sg element.
 */
struct virtqueue {
	TAILQ_HEAD(virtqueueList, virtqueue) list;
	void (*callback)(struct virtqueue *vq);
	const char *name;
	struct virtio_device *vdev;
	unsigned int index;
	unsigned int num_free;
	unsigned int num_max;
	bool reset;
	void *priv;
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
	pthread_t* req_job;
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

	/* irq queue array */

	pthread_mutex_t irq_lock;
	uint32_t irqProd;
	struct virtioVsmIrq *pIrq;

	/* UIO file descriptor */
	int uio_fd;
	/* UIO control file descriptor */
	int ctrl_fd;

	/* virtio host channel */
	struct virtioVsmQueue pVsmQueue[0];
};


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


/* locals */

#define to_vvq(_vq) container_of(_vq, struct vring_virtqueue, vq)

/**
 * virtqueue_get_vring_size - return the size of the virtqueue's vring
 * @_vq: the struct virtqueue contained in the vring of interest.
 *
 * Returns the size of the vring.  This is mainly used for boasting to
 * userspace.  Unlike other operations, this need not be serialized.
 */
unsigned int virtqueue_get_vring_size(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	return vq->vring.num;
}


static void virtio_write(struct virtio_device *vdev,
			 uint32_t reg,
			 uint32_t val)
{
        host_writel(val, (uint32_t*)vdev->dev.base + reg);
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

	virtio_write((pDrvCtrl->pQueue[queueId])->vdev,
			VIRTIO_MMIO_QUEUE_SEL, VIRTIO_VSM_COMP_QUEUE);
	virtio_write((pDrvCtrl->pQueue[queueId])->vdev,
			VIRTIO_MMIO_QUEUE_READY, 1);

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
 * Notify Hypervisor that the new buffer is available
 */
static int virtioVsmKick(struct virtioHost *vHost, struct virtqueue *_vq)
{
	uint16_t old, new;
	struct vring_virtqueue *vq = to_vvq(_vq);
	bool needs_kick;

	/*
	 * We need to expose available array entries before checking avail
	 * event. (We do not do it now, but may do in the future).
	 */
	__mb();

	needs_kick = !(vq->vring.used->flags &
		       host_cpu_to_virtio16(vHost,
					    VRING_USED_F_NO_NOTIFY));
	if (!needs_kick) {
		return 0;
	}

	virtio_write(_vq->vdev, VIRTIO_MMIO_QUEUE_NOTIFY, _vq->index);

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

	if (pVsm == NULL || vregion == NULL) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "invalid input parameters\n");
		errno = EINVAL;
		return false;
	}
	err = ioctl(pVsm->ctrl_fd, VHOST_VIRTIO_GET_REGION, &region);
	if (err != 0) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "obtaining region with id %d failed: %s\n",
				   id, strerror(errno));
		return false;
	}
	vregion->paddr = region.addr;
	vregion->len = region.size;
	vregion->id = region.indx;
	vregion->offset = region.offs;
	return true;
}


static int virtioVsmShmRegionGet(struct virtioVsm *pVsm,
				 struct virtioVsmShmRegion * pVsmRegion)
{
	if (!pVsm || !pVsmRegion) {
		errno = EINVAL;
		return -1;
	}

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
			"start\n");

	if (!virtio_get_shm_region(pVsm, &(pVsmRegion->region), 0)) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				"virtio_get_shm_region failed\n");
		errno = ENOMEM;
		return -1;
	}

	pVsmRegion->vaddr = mmap(NULL, pVsmRegion->region.len,
				 PROT_READ | PROT_WRITE,
				 MAP_SHARED, pVsm->uio_fd,
				 pVsmRegion->region.offset);
	if (pVsmRegion->vaddr == MAP_FAILED) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR,
				   "memory map failed\n");
		errno = ENOSPC;
		return -1;
	}

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
			   "hpaddr:0x%lx,0x%lx->%p\n",
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
