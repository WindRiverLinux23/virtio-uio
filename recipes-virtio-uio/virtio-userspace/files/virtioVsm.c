/* virtio service module */

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

This is a virtio class driver that supplies a virtio host service model,
it creates virtio host service instance, the virtio host is a collection
of virtio devices created by the service VM (it could be Linux or
VxWorks), the device number is reported by the device configuration space.

Every virtio backend device has its private queue when the guest virtio FE
driver write/read register, it will create an I/O request in the I/O request
queue, the virtio device simulator needs to handle the request and reply to it,
if the request type is notification, it doesn't require a reply period.

The virtio host device could be presented on MMIO or PCI device, currently,
only MMIO device is supported.

*/

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include "virtioHostLib.h"
#include <syslog.h>

#undef VIRTIO_VSM_DBG
#ifdef VIRTIO_VSM_DBG

#define VIRTIO_VSM_DBG_OFF             0x00000000
#define VIRTIO_VSM_DBG_ERR             0x00000001
#define VIRTIO_VSM_DBG_IOREQ           0x00000002
#define VIRTIO_VSM_DBG_IRQREQ          0x00000004
#define VIRTIO_VSM_DBG_QUEUE           0x00000008
#define VIRTIO_VSM_DBG_CFG             0x00000010
#define VIRTIO_VSM_DBG_INFO            0x00000020
#define VIRTIO_VSM_DBG_ALL             0xffffffff

static uint32_t virtioVsmDbgMask = VIRTIO_VSM_DBG_ERR;

#define VIRTIO_VSM_DBG_MSG(mask, fmt, ...)                              \
        do {                                                            \
                if ((virtioVsmDbgMask & (mask)) ||			\
                    ((mask) == VIRTIO_VSM_DBG_ERR)) {                   \
                        printf("%d: %s() " fmt, __LINE__, __func__,     \
                               ##__VA_ARGS__);                          \
			fflush(stdout);					\
                }                                                       \
        }                                                               \
while ((false));
#define log_err(fmt, ...)					\
	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_ERR, fmt,		\
			   ##__VA_ARGS__)
#else
#undef VIRTIO_VSM_DBG_MSG
#define VIRTIO_VSM_DBG_MSG(...)
#define log_err(fmt, ...)					\
	syslog(LOG_ERR, "%d: %s() " fmt, __LINE__, __func__,	\
	       ##__VA_ARGS__)
#endif  /* VIRTIO_VSM_DBG */

/* feature */

#define VIRTIO_VSM_F_SERIALIZED_QUEUES  0x1

#define VIRTIO_VSM_T_IN                 0
#define VIRTIO_VSM_T_OUT                1
#define VIRTIO_VSM_T_NOTIFY             2
#define VIRTIO_VSM_T_VERSION            3
#define VIRTIO_VSM_T_RESET              4

#define VIRTIO_VSM_S_OK                 0
#define VIRTIO_VSM_S_IOERR              1
#define VIRTIO_VSM_S_UNSUPP             2

#define VIRTIO_VSM_QUEUE_NAME_SIZE      32
#define VIRTIO_VSM_REQ_QUEUE(queueId)   (queueId)
#define VIRTIO_VSM_COMP_QUEUE           (pDrvCtrl->channelMax)
#define VIRTIO_VSM_IRQ_QUEUE            (pDrvCtrl->channelMax + 1)
#define VIRTIO_VSM_IRQ_INC(q, x)        (x) = (((x) + 1) % VIRTIO_VSM_QUEUE_NUM(q))

/*
 * This flag is WR private ring flag, it was set by BE (Hypervisor) to
 * illustrate that FE need to send kick when it put new buffer to queue.
 */
#define VRING_AVAIL_F_REQ_INTERRUPT    (1 << 15)

/* forward declarations */

static struct virtioVsmQueue* virtioVsmGetQueue(struct virtioVsm *, uint32_t);
static int virtioVsmQueueInit(struct virtioVsmQueue *, struct virtioHost *);
static int virtioVsmNotify(struct virtioVsmQueue *, struct virtioHost *, uint32_t status);
static void virtioVsmQueueDone(struct virtqueue *);
static void* virtioVsmReqHandle(void *arg);
static void* virtioVsmCompHandle(void *arg);
static void* virtioVsmIrqHandle(void *arg);
static int virtioVsmShmRegionGet(struct virtioVsm *, struct virtioVsmShmRegion *);
static void virtioVsmShmRegionRelease(struct virtioVsm *, struct virtioVsmShmRegion *);

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

/* virtio vsm config */
struct virtioVsmConfig
{
	uint32_t channelMax;
	uint32_t channelId[1];
};

/* virtio vsm virtual queue */
struct virtioVsmQueue
{
	struct virtioVsm *pDrvCtrl;
	struct virtioHost *vHost;
	uint32_t channelId;
	atomic_int int_pending;
	pthread_mutex_t int_lock;
	struct virtqueue *pReqQueue;
	pthread_t req_thread;
	sem_t req_sem;
	struct virtioVsmReq *req;
};

struct virtioVsm
{
	uint32_t queueNum;
	uint32_t reqQueueNum;
	uint32_t channelMax; /* max channel */

	pthread_t comp_thread;
	pthread_t irq_thread;
	sem_t irq_sem;
	sem_t comp_sem;

	int virtioVsmUnit;
	struct virtio_device *vdev;
	uint64_t features;

	/* virt queue array */
	struct virtqueue **pQueue;

	/* virt queue info */
	struct virtqueueInfo* pVirtqueueInfo;

	pthread_mutex_t irq_lock;
	uint32_t irqProd;

	/* irq queue array */
	struct virtioVsmIrq *pIrq;

	/* virtio host channel */
	struct virtioVsmQueue pVsmQueue[0];
};

static void* virtioVsmCompHandle(void *arg)
{
	struct virtioVsm *pDrvCtrl = arg;
	struct virtioVsmQueue *pVsmQueue;
	struct virtqueueBuf bufList[0];
	struct virtioVsmReq *pReq;
	struct virtqueue *pCompQueue;
	struct virtqueue *pReqQueue;
	uint32_t len;
	uint32_t token;
	uint32_t q;
	bool found;
	uint16_t flags;

	const volatile struct vring *vr;
	int rc;

	while(1) {
		rc = sem_wait(&pDrvCtrl->comp_sem);
		if (rc < 0) {
			log_err("failed to sem_wait\n");
			continue;
		}

		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_IOREQ, "start\n");

		pCompQueue = pDrvCtrl->pQueue[VIRTIO_VSM_COMP_QUEUE];
again:
		while (1) {
			pReq = virtqueueGetBuffer(pCompQueue, &len, &token);
			if (!pReq) {

				VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_IOREQ,
						"enable interrupt\n");

				atomic_store(&pDrvCtrl->pVsmQueue[VIRTIO_VSM_COMP_QUEUE].int_pending, false);

				pthread_mutex_lock(&pDrvCtrl->pVsmQueue[VIRTIO_VSM_COMP_QUEUE].int_lock);
				if (!virtqueueIntrEnable(pCompQueue)) {
					virtqueueIntrDisable(pCompQueue);
					pthread_mutex_unlock(&pDrvCtrl->pVsmQueue[VIRTIO_VSM_COMP_QUEUE].int_lock);
					goto again;
				}
				pthread_mutex_unlock(&pDrvCtrl->pVsmQueue[VIRTIO_VSM_COMP_QUEUE].int_lock);

				break;
			}

			VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
					"recycle one complete request\n");

			for (q = 0, found = false; q < pDrvCtrl->reqQueueNum; q++) {
				pVsmQueue = pDrvCtrl->pVsmQueue + q;

				if (!pVsmQueue->vHost)
					continue;
				else {
					if (pReq->channelId == pVsmQueue->vHost->channelId) {
						found = true;
						goto checkend;
					}
				}
			}

checkend:
			if (!found) {
				log_err("failed to find the queue\n");
				continue;
			}

			pReqQueue = pVsmQueue->pReqQueue;

			bufList[0].buf = pReq;
			bufList[0].len = sizeof(struct virtioVsmReq);

			/* in theory, adding buffer should always succeed */
			rc = virtqueueAddBuffer(pReqQueue, bufList, 0, 1,
						(void *)pReq);
			if (rc) {
				log_err("failed to return buf to request "
					"queue %s\n", strerror(errno));
			}

			/* kick remote device if needed */
			vr = virtqueue_get_vring(pReqQueue);
			if (vr) {
				flags = virtio16_to_cpu(pReqQueue->vdev, vr->used->flags);
				VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
						   "vr->used->flags:%x, flags:%x\n",
						   vr->used->flags, flags);
				//This flag is WR private ring flag, it was set by BE(Hypervisor) to
				//illustrate that FE(VSM) need to send kick when it put new buffer to queue.
				if (flags & VRING_AVAIL_F_REQ_INTERRUPT)
					virtqueueKick(pReqQueue);
			} else {
				log_err("failed to get vring\n");
			}
		}

		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_IOREQ, "done\n");
	}
}

static void* virtioVsmIrqHandle(void *arg)
{
	struct virtioVsm *pDrvCtrl = arg;
	struct virtqueue *pIrqQueue;
	struct virtioVsmIrq *pIrq;
	uint32_t len;
	uint32_t token;
	int rc;

	while(1) {
		rc = sem_wait(&pDrvCtrl->irq_sem);
		if (rc < 0) {
			log_err("failed to sem_wait\n");
			continue;
		}

		pIrqQueue = pDrvCtrl->pQueue[VIRTIO_VSM_IRQ_QUEUE];

		pthread_mutex_lock(&pDrvCtrl->irq_lock);
again:
		/* drain the irq used ring */
		while (1) {
			VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
					   "start\n");
			pIrq = virtqueueGetBuffer(pIrqQueue, &len, &token);
			if (!pIrq) {

				VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_IOREQ,
						"enable interrupt\n");

				atomic_store(&pDrvCtrl->pVsmQueue[VIRTIO_VSM_IRQ_QUEUE].int_pending, false);

				pthread_mutex_lock(&pDrvCtrl->pVsmQueue[VIRTIO_VSM_IRQ_QUEUE].int_lock);
				if (!virtqueueIntrEnable(pIrqQueue)) {
					virtqueueIntrDisable(pIrqQueue);
					pthread_mutex_unlock(&pDrvCtrl->pVsmQueue[VIRTIO_VSM_IRQ_QUEUE].int_lock);
					goto again;
				}
				pthread_mutex_unlock(&pDrvCtrl->pVsmQueue[VIRTIO_VSM_IRQ_QUEUE].int_lock);

				break;
			}

			VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
					"recycle one irq request\n");
		}

		pthread_mutex_unlock(&pDrvCtrl->irq_lock);
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "done\n");
	}
}

static void virtioVsmQueueDone(struct virtqueue *pQueue)
{
	struct virtioVsm *pDrvCtrl;
	struct virtioVsmQueue *pVsmQueue;
	uint32_t queueId;
	struct work_struct *work;
	atomic_int *pending;
	pthread_mutex_t *lock;
	int old = false;
	sem_t* sem;
	int rc;

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
			"start\n");

	if (!pQueue) {
		log_err("null pQueue\n");
		return;
	}

	pDrvCtrl = pQueue->vdev->priv;
	if (!pDrvCtrl) {
		log_err("null pDrvCtrl\n");
		return;
	}

	if (pQueue == pDrvCtrl->pQueue[VIRTIO_VSM_COMP_QUEUE]) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				"comp_job\n");
		sem = &pDrvCtrl->comp_sem;
		lock = &pDrvCtrl->pVsmQueue[VIRTIO_VSM_COMP_QUEUE].int_lock;
		pending = &pDrvCtrl->pVsmQueue[VIRTIO_VSM_COMP_QUEUE].int_pending;
	} else if (pQueue == pDrvCtrl->pQueue[VIRTIO_VSM_IRQ_QUEUE]) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				"irq_job\n");
		sem = &pDrvCtrl->irq_sem;
		lock = &pDrvCtrl->pVsmQueue[VIRTIO_VSM_IRQ_QUEUE].int_lock;
		pending = &pDrvCtrl->pVsmQueue[VIRTIO_VSM_IRQ_QUEUE].int_pending;
	} else {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				"req_job\n");
		for (queueId = 0; queueId < pDrvCtrl->reqQueueNum; queueId++) {
			pVsmQueue = pDrvCtrl->pVsmQueue + queueId;
			VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
					"pVsmQueue:%d:0x%lx\n",
					queueId, (unsigned long)pVsmQueue);
			if (pVsmQueue->pReqQueue == pQueue) {
				VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
						"found pQueue:0x%lx\n",
						(unsigned long)pQueue);
				break;
			}
		}

		if (queueId == pDrvCtrl->reqQueueNum) {
			log_err("pVsmQueue not found\n");
			return;
		}

		sem = &pVsmQueue->req_sem;
		lock = &pVsmQueue->int_lock;
		pending = &pVsmQueue->int_pending;
	}

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "pending:%d old:%d\n",
			atomic_load(pending), old);

	/* returning true means original value equals to the expected */
	if (atomic_compare_exchange_strong(pending, &old, true) == true) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_IOREQ,
				"disable interrupt\n");
		pthread_mutex_lock(lock);
		virtqueueIntrDisable(pQueue);
		pthread_mutex_unlock(lock);

		rc = sem_post(sem);
		if (rc)
			log_err("failed to sem_post: %s\n", strerror(errno));
	}

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "done\n");
}

static void* virtioVsmReqHandle(void *arg)
{
	struct virtioVsm *pDrvCtrl;
	struct virtioVsmQueue *pVsmQueue = arg;
	struct virtqueueBuf bufList[1];
	struct virtioHost *vHost;
	struct virtqueue *pReqQueue;
	struct virtqueue *pCompQueue;
	struct virtioVsmReq *pReq;
	uint32_t value;
	uint32_t len;
	uint32_t token;

	const volatile struct vring *vr;
	int rc;
	uint16_t flags = 0;

	while(1) {
		rc = sem_wait(&pVsmQueue->req_sem);
		if (rc < 0) {
			log_err("failed to sem_wait\n");
			continue;
		}

		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				"pVsmQueue->pReqQueue:0x%lx\n",
				(unsigned long)pVsmQueue->pReqQueue);
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				"pVsmQueue->vHost:0x%lx\n",
				(unsigned long)pVsmQueue->vHost);

		if (!pVsmQueue->vHost) {
			log_err("null pVsmQueue->vHost\n");
			return NULL;
		}

		if (!pVsmQueue->pReqQueue) {
			log_err("null pVsmQueue->pReqQueue\n");
			return NULL;
		}

		vHost = pVsmQueue->vHost;
		pReqQueue = pVsmQueue->pReqQueue;
		pDrvCtrl = pVsmQueue->pDrvCtrl;
again:
		while (1) {
			VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_IOREQ,
					   "start\n");
			pReq = virtqueueGetBuffer(pReqQueue, &len, &token);
			if (!pReq) {
				VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_IOREQ,
						"enable interrupt\n");

				/* checking virtqueue is in normal status */
				if (virtqueue_is_broken(pReqQueue)){
					break;
				}

				atomic_store(&pVsmQueue->int_pending, false);

				pthread_mutex_lock(&pVsmQueue->int_lock);
				if (!virtqueueIntrEnable(pReqQueue)) {
					virtqueueIntrDisable(pReqQueue);
					pthread_mutex_unlock(&pVsmQueue->int_lock);
					goto again;
				}
				pthread_mutex_unlock(&pVsmQueue->int_lock);

				break;
			}

			/* Endianess has been handled by virtiolib */
			if (pReq->type == VIRTIO_VSM_T_IN) {
				VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
						   "read request\n");

				if (virtioHostVsmReqRead(vHost, pReq->address,
							 pReq->size, &value) == 0) {
					pReq->value = value;
					pReq->status = VIRTIO_VSM_S_OK;
				} else
					pReq->status = VIRTIO_VSM_S_IOERR;
			} else if (pReq->type == VIRTIO_VSM_T_OUT) {
				VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
						"write request\n");

				if (virtioHostVsmReqWrite(
					    vHost, pReq->address, pReq->size,
					    pReq->value) == 0) {
					pReq->status = VIRTIO_VSM_S_OK;
				} else {
					pReq->status = VIRTIO_VSM_S_IOERR;
				}
			} else if (pReq->type == VIRTIO_VSM_T_NOTIFY) {
				VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
						"notify request\n");

				if (virtioHostVsmReqKick(vHost, pReq->value) == 0)
					pReq->status = VIRTIO_VSM_S_OK;
				else
					pReq->status = VIRTIO_VSM_S_IOERR;
			} else if (pReq->type == VIRTIO_VSM_T_VERSION) {
				VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
						"version request\n");

				pReq->value = 2;
				pReq->status = VIRTIO_VSM_S_OK;
			} else if (pReq->type == VIRTIO_VSM_T_RESET) {
				VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
						"reset request\n");

				if (virtioHostVsmReqReset(vHost) == 0)
					pReq->status = VIRTIO_VSM_S_OK;
				else
					pReq->status = VIRTIO_VSM_S_IOERR;
			} else {
				log_err("not supported request\n");
				pReq->status = VIRTIO_VSM_S_UNSUPP;
			}

			bufList[0].buf = pReq;
			bufList[0].len = sizeof(struct virtioVsmReq);

			if (pReq->type != VIRTIO_VSM_T_NOTIFY) {
				VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
						"move sync request to complete queue\n");

				/* insert the req to complete queue */
				pCompQueue = pDrvCtrl->pQueue[VIRTIO_VSM_COMP_QUEUE];

				/*
				 * The VSM complete queue is shared by all channels,
				 * once it is found full, handle the complete queue in advance.
				 */
				while ((rc = virtqueueAddBuffer(pCompQueue,
								bufList,
								0, 1,
								(void*)pReq))) {
					if (rc == -ENOSPC) {
						VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
								"complete queue is full, drain it\n");
						sem_post(&pDrvCtrl->comp_sem);
					} else {
						log_err("failed to move sync request to complete queue: %s\n",
								   strerror(errno));
					}
				}

				virtqueueKick(pCompQueue);
			} else {
				VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
						   "return notify buf to "
						   "request queue\n");

				/* in theory, adding buffer should always succeed */
				rc = virtqueueAddBuffer(pReqQueue,
							bufList, 1, 0,
							(void *)pReq);
				if (rc) {
					log_err("failed to return buf "
						"to request queue %s\n",
						strerror(errno));
				}

				/*
				 * kick remote device if needed, this is a
				 * WR specific flag
				 */
				vr = virtqueue_get_vring(pReqQueue);
				if (vr) {
					flags = virtio16_to_cpu(pReqQueue->vdev, vr->used->flags);
					VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
							"vr->used->flags:%x, flags:%x\n", vr->used->flags, flags);
					if (flags & VRING_AVAIL_F_REQ_INTERRUPT) {
						VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
								"kick\n");
						virtqueueKick(pReqQueue);
					}
				} else {
					log_err("failed to get vring\n");
				}
			}
		}

	}
}

static int virtioVsmQueueInit(struct virtioVsmQueue *pVsmQueue, struct virtioHost *vHost)
{
	struct virtioVsm *pDrvCtrl;
	uint32_t queueId;

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
			"start\n");

	if (!pVsmQueue) {
		log_err("null pVsmQueue\n");
		return -EINVAL;
	}

	if (!pVsmQueue->pDrvCtrl) {
		log_err("null pVsmQueue->pDrvCtrl\n");
		return -EINVAL;
	}

	if (!vHost) {
		log_err("null vHost\n");
		return -EINVAL;
	}

	pDrvCtrl = pVsmQueue->pDrvCtrl;

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
			"pDrvCtrl->pVsmQueue:0x%lx pVsmQueue:0x%lx vHost:0x%lx\n",
			(unsigned long)pDrvCtrl->pVsmQueue,
			(unsigned long)pVsmQueue,
			(unsigned long)vHost);

	queueId = (uint32_t)(pVsmQueue - pDrvCtrl->pVsmQueue);
	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
			"queueId:%u\n", queueId);

	pVsmQueue->vHost = vHost;

	atomic_init(&pVsmQueue->int_pending, false);

	virtioVsmVirtqueueEnable((pDrvCtrl->pQueue[queueId])->vdev,
				 queueId, true);

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "done\n");

	return 0;
}

static struct virtioVsmQueue *virtioVsmGetQueue(struct virtioVsm *pVsm, uint32_t channelId)
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
		log_err("invalid channel ID (%d)\n", channelId);
		return NULL;
	}

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
		"got queue (%d)\n", i);

	return (&pVsm->pVsmQueue[VIRTIO_VSM_REQ_QUEUE(i)]);
}

static int virtioVsmNotify(struct virtioVsmQueue *pVsmQueue,
			   struct virtioHost *vHost, uint32_t status)
{
	struct virtioVsm *pDrvCtrl;
	struct virtqueueBuf bufList[1];
	struct virtqueue *pIrqQueue;
	struct virtioVsmIrq *irq;
	uint32_t num;
	int rc;

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "start\n");

	if (!pVsmQueue || !pVsmQueue->pDrvCtrl || !vHost)
		return -EINVAL;

	pDrvCtrl = pVsmQueue->pDrvCtrl;

	pthread_mutex_lock(&pDrvCtrl->irq_lock);

	pIrqQueue = pDrvCtrl->pQueue[VIRTIO_VSM_IRQ_QUEUE];

	if (pIrqQueue->num_free == 0) {
		log_err("no irq resource available\n");
		errno = ENOBUFS;
		return -ENOBUFS;
	}

	irq = &pDrvCtrl->pIrq[pDrvCtrl->irqProd];

	/* take along the status */
	irq->channelId = vHost->channelId;
	irq->value = status;

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
			"channelId:%u value:0x%x\n",
			irq->channelId, irq->value);

	bufList[0].buf = (void *)irq;
	bufList[0].len = sizeof(struct virtioVsmIrq);

	num = virtqueue_get_vring_size(pIrqQueue);
	pDrvCtrl->irqProd = (pDrvCtrl->irqProd + 1) % num;

	rc = virtqueueAddBuffer(pIrqQueue,
				bufList,
				1, 0,
				(void *)irq);
	if (rc) {
		log_err("virtqueueAddBuffer failed %d\n", rc);
		pthread_mutex_unlock(&pDrvCtrl->irq_lock);
		return rc;
	}

	virtqueueKick(pIrqQueue);

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
static bool
virtioGetShmRegionInternal(struct virtioVsm *pVsm,
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
		log_err("invalid input parameters\n");
		errno = EINVAL;
		return false;
	}
	if (pVsm->vdev == NULL) {
		log_err("VSM virtio device not initialized\n");
		errno = EINVAL;
		return false;
	}
	if (pVsm->vdev->virtio_ctrl_device == NULL) {
		log_err("VSM virtio control device name is NULL\n");
		errno = EINVAL;
		return false;
	}
	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
			   "Obtaining %d memory region\n", region.indx);
	ctrl_fd = open(pVsm->vdev->virtio_ctrl_device, O_RDWR | O_SYNC);
	if (ctrl_fd < 0) {
		log_err("opening control device failed: %s\n",
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
		log_err("invalid input parameters\n");
		errno = EINVAL;
		return -1;
	}
	if (pVsm->vdev == NULL) {
		log_err("VSM virtio device not initialized\n");
		errno = EINVAL;
		return false;
	}
	if (pVsm->vdev->uio_device == NULL) {
		log_err("VSM virtio UIO device name is NULL\n");
		errno = EINVAL;
		return false;
	}

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
			"start\n");

	if (!virtioGetShmRegionInternal(pVsm, &(pVsmRegion->region),
					VIRTIO_VSM_CFG_REGION)) {
		log_err("virtio_get_shm_region failed\n");
		errno = ENOMEM;
		return -1;
	}
	uio_fd = open(pVsm->vdev->uio_device, O_RDWR | O_SYNC);
	if (uio_fd < 0) {
		log_err("UIO device error: %s\n", strerror(errno));
		return -1;
	}
	pVsmRegion->vaddr = mmap(NULL, pVsmRegion->region.len,
				 PROT_READ | PROT_WRITE,
				 MAP_SHARED, uio_fd,
				 pVsmRegion->region.offset);
	if (pVsmRegion->vaddr == MAP_FAILED) {
		log_err("memory map failed\n");
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

static int init_vq(struct virtioVsm *pDrvCtrl)
{
	uint32_t queueId;
	int err;

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "start\n");

	/* create callback and name array */

	pDrvCtrl->pVirtqueueInfo = zmalloc(pDrvCtrl->queueNum *
					    sizeof(struct virtqueueInfo));
	if (pDrvCtrl->pVirtqueueInfo == NULL) {
		log_err("virtio queue info mem alloc failed\n");
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
		log_err("device virtqueue and vring "
			"pointers setup failed\n");
		return -1;
	}

	/* allocate VirtIO queues */
	for (queueId = 0; queueId < pDrvCtrl->queueNum; queueId++) {
		if (setup_vq(pDrvCtrl->vdev, queueId,
			     &pDrvCtrl->pVirtqueueInfo[queueId]) != 0) {
			log_err("virtqueue %d setup FAILED\n",
				queueId);
			break;
		}
	}
	if (queueId != pDrvCtrl->queueNum) {
		log_err("failed\n");
		return -1;
	}

	pDrvCtrl->pQueue = pDrvCtrl->vdev->queues;
	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "done\n");
	return 0;
}

extern void virtioHostNetDrvInit(void);
extern void virtioHostNetDrvRelease(void);
extern void virtioHostBlkDrvInit(uint32_t mountTimeout);
extern void virtioHostBlkDrvRelease(void);
extern void virtioHostConsoleDrvInit(void);
extern void virtioHostConsoleDrvRelease(void);
extern void virtioHostGpuDrvInit(void);
extern void virtioHostGpuDrvRelease(void);

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
		log_err("invalid input parameter\n");
                errno = EINVAL;
                return -1;
        }
        cfg = (struct virtioVsmConfig*)(vdev->dev.base + VIRTIO_MMIO_CONFIG);
        *channelMax = cfg->channelMax;
        return 0;
}

int vsm_init(struct virtio_device *vdev)
{
	uint32_t channelMax;
	uint32_t queueNum;
	struct virtioVsm *pDrvCtrl;
	struct virtioVsmQueue * pVsmQueue;
	uint32_t offset;
	struct virtqueueBuf bufList[1];
	uint32_t i, num, queueId;
	void *reqAddr;
	int rc;

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "virtvsm_probe start\n");

	if (virtioHostVsmDev.vsmId) {
		log_err("virtioHostVsmDev.vsmId is not null\n");
		return -EINVAL;
	}

	if (!vdev) {
		log_err("vdev is null\n");
		return -EINVAL;
	}

	/*
	 * Handle the situation when Linux boots and the kernel VirtIO
	 * driver has already set the VIRTIO_CONFIG_S_ACKNOWLEDGE flag.
	 * We do not want to bring the device back to reset status but
	 * continue the initialization instead.
	 */
	if (virtioGetStatus(vdev) != VIRTIO_CONFIG_S_ACKNOWLEDGE) {
		virtioDevReset(vdev);
	}

	/* Set up virtual device */
	virtioDevInit(vdev);

	virtio_add_status(vdev, VIRTIO_CONFIG_S_ACKNOWLEDGE);

	/* Get max channels */
        if (virtioGetChannelMax(vdev, &channelMax) != 0) {
                return -1;
        }
	queueNum = channelMax + 2;

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "channelMax=%d queueNum=%d\n",
			channelMax, queueNum);

	pDrvCtrl = calloc(sizeof(*pDrvCtrl) +
			queueNum * sizeof(struct virtioVsmQueue), 1);
	if (!pDrvCtrl) {
		log_err("calloc virtioVsm failed\n");
		goto failed;
	}

	pDrvCtrl->channelMax = channelMax;
	pDrvCtrl->queueNum = queueNum;
	pDrvCtrl->reqQueueNum = channelMax;

	rc = sem_init(&pDrvCtrl->comp_sem, 0, 0);
	if (rc) {
		log_err("Failed to create VSM complete "
			"queue sem (%s)\n",
			strerror(errno));
		goto failed;
	}

	rc = pthread_create(&pDrvCtrl->comp_thread, NULL,
			    virtioVsmCompHandle, pDrvCtrl);
	if (rc) {
		log_err("Failed to create VSM complete "
			"queue thread (%s)\n",
			strerror(errno));
		goto failed;
	}

	rc = sem_init(&pDrvCtrl->irq_sem, 0, 0);
	if (rc) {
		log_err("Failed to create VSM irq "
			"queue sem (%s)\n",
			strerror(errno));
		goto failed;
	}

	rc = pthread_create(&pDrvCtrl->irq_thread, NULL,
			    virtioVsmIrqHandle, pDrvCtrl);
	if (rc) {
		log_err("Failed to create VSM irq queue "
			"thread (%s)\n",
			strerror(errno));
		goto failed;
	}

	/* set virtio device private data */
	vdev->priv = pDrvCtrl;

	/* save vDev to driver control */
	pDrvCtrl->vdev = vdev;

	init_vq(pDrvCtrl);

	for (queueId = 0; queueId < pDrvCtrl->queueNum; queueId++) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				"queue%d Magic   %x\n", queueId,
				virtio_read((pDrvCtrl->pQueue[queueId])->vdev, 0x0));
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				"queue%d Version %x\n", queueId,
				virtio_read((pDrvCtrl->pQueue[queueId])->vdev, 0x4));
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				"queue%d Device  %x\n", queueId,
				virtio_read((pDrvCtrl->pQueue[queueId])->vdev, 0x8));
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				"queue%d Vendor  %x\n", queueId,
				virtio_read((pDrvCtrl->pQueue[queueId])->vdev, 0xc));
	}

	/* setup the queue data for complete queue */
	virtioVsmVirtqueueEnable(
		(pDrvCtrl->pQueue[VIRTIO_VSM_COMP_QUEUE])->vdev,
		VIRTIO_VSM_COMP_QUEUE, true);

	/* setup the queue data for irq queue */
	virtioVsmVirtqueueEnable(
		(pDrvCtrl->pQueue[VIRTIO_VSM_IRQ_QUEUE])->vdev,
		VIRTIO_VSM_IRQ_QUEUE, true);

	/* setup the io req queue */
	offset = offsetof(struct virtioVsmConfig, channelId);

	for (queueId = 0; queueId < pDrvCtrl->reqQueueNum; queueId++) {
		/* setup queue */
		pVsmQueue = pDrvCtrl->pVsmQueue + queueId;
		pVsmQueue->channelId = virtio_cread32(vdev, offset + queueId * 4);
		pVsmQueue->pReqQueue = pDrvCtrl->pQueue[queueId];
		pVsmQueue->pDrvCtrl  = pDrvCtrl;

		num = virtqueue_get_vring_size(pVsmQueue->pReqQueue);

		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				"queueId = %d\n", queueId);
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				"pVsmQueue->channelId = %d\n",
				pVsmQueue->channelId);
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				"pVsmQueue->pReqQueue = %p\n",
				pVsmQueue->pReqQueue);
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				"pVsmQueue queue size = %d\n", num);

		pVsmQueue->req = (struct virtioVsmReq *)calloc(num,
				sizeof(struct virtioVsmReq));
		if (!pVsmQueue->req) {
			log_err("calloc buffer for request "
				"queue[%d] failed\n",
				queueId);
			goto failed;
		}

		/* Add buf to desc ring */
		for (i = 0; i < num; i++) {
			int rc;

			reqAddr = (void *)pVsmQueue->req +
				i * sizeof(struct virtioVsmReq);
			bufList[0].buf = reqAddr;
			bufList[0].len = sizeof(struct virtioVsmReq);

			rc = virtqueueAddBuffer(pVsmQueue->pReqQueue,
						bufList, 0, 1,
						(void *)reqAddr);
			if (rc) {
				log_err("virtqueueAddBuffer failed %d\n",
					rc);
				goto failed;
			}

			virtqueueKick(pVsmQueue->pReqQueue);
		}

		pthread_mutex_init(&pVsmQueue->int_lock, NULL);

		rc = sem_init(&pVsmQueue->req_sem, 0, 0);
		if (rc) {
			log_err("Failed to create VSM request queue "
				"%d sem(%d)\n", queueId, rc);
			goto failed;
		}
		/*
		 * We can't use priv, it'll be overwritten by linux virtiolib.
		 * When specific pVsmQueue is needed, we need to iterate
		 * pDrvCtrl->pVsmQueue and compare pVsmQueue->pReqQueue potiners
		 * with current pReqQueue.
		 *pVsmQueue->pReqQueue->priv = pVsmQueue;
		 */
		rc = pthread_create(&pVsmQueue->req_thread, NULL,
				    virtioVsmReqHandle, pVsmQueue);
		if (rc) {
			log_err("Failed to create VSM request queue "
				"%d thread(%d)\n", queueId, rc);
			goto failed;
		}

	}

	pthread_mutex_init(&pDrvCtrl->pVsmQueue[VIRTIO_VSM_COMP_QUEUE].int_lock, NULL);
	pthread_mutex_init(&pDrvCtrl->pVsmQueue[VIRTIO_VSM_IRQ_QUEUE].int_lock, NULL);

	pthread_mutex_init(&pDrvCtrl->irq_lock, NULL);

	num = virtqueue_get_vring_size(pDrvCtrl->pQueue[pDrvCtrl->queueNum - 1]);
	pDrvCtrl->pIrq = calloc(num, sizeof(struct virtioVsmIrq));
	if (!pDrvCtrl->pIrq) {
		log_err("allocate IRQ buffer failed\n");
		goto failed;
	}

	pDrvCtrl->irqProd = 0;

	/* register VSM to virtio host library */
	virtioHostVsmDev.vsmId = pDrvCtrl;
	if (virtioHostVsmRegister(&virtioHostVsmDev)) {
		log_err("register to host library failed\n");
		goto failed;
	}
	virtioHostInit();

	virtio_add_status(vdev, VIRTIO_CONFIG_S_DRIVER);

	/* Init host net driver */
	virtioHostNetDrvInit();

	/* Init host block driver */
	virtioHostBlkDrvInit(10);

	/* Init host console driver */
	virtioHostConsoleDrvInit();

#ifdef INCLUDE_HOST_GPU
	/* Init host gpu driver */
	virtioHostGpuDrvInit();
#endif

	/* Init host lib */
	virtioHostDevicesInit();

	virtio_add_status(vdev, VIRTIO_CONFIG_S_FEATURES_OK);

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "done\n");

	return 0;

failed:
	if (pDrvCtrl) {
		for (queueId = 0; queueId < pDrvCtrl->reqQueueNum; queueId++) {
			pVsmQueue = pDrvCtrl->pVsmQueue + queueId;
			if (pVsmQueue->req)
				free(pVsmQueue->req);

			if (pVsmQueue->req_thread &&
			    pthread_cancel(pVsmQueue->req_thread) == 0) {
				pthread_join(pVsmQueue->req_thread, NULL);
			}
		}

		if (pDrvCtrl->pIrq)
			free(pDrvCtrl->pIrq);

		if (pDrvCtrl->pVirtqueueInfo)
			free(pDrvCtrl->pVirtqueueInfo);

		if (pDrvCtrl->comp_thread &&
		    pthread_cancel(pDrvCtrl->comp_thread) == 0) {
			pthread_join(pDrvCtrl->comp_thread, NULL);
		}

		if (pDrvCtrl->irq_thread &&
		    pthread_cancel(pDrvCtrl->irq_thread) == 0) {
			pthread_join(pDrvCtrl->irq_thread, NULL);
		}

		if (pDrvCtrl->pQueue)
			free(pDrvCtrl->pQueue);

		free(pDrvCtrl);
	}

	log_err("failed\n");

	return -EAGAIN;
}

void vsm_deinit(struct virtio_device *vdev)
{
	struct virtioVsm *pDrvCtrl;
	uint32_t queueId;
	int ret;

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "start\n");

	/* Release host console driver */
	virtioHostConsoleDrvRelease();

	/* Release host block driver */
	virtioHostBlkDrvRelease();

	/* Release host net driver */
	virtioHostNetDrvRelease();

#ifdef INCLUDE_HOST_GPU
	/* Release host gpu driver */
	virtioHostGpuDrvRelease();
#endif

	pDrvCtrl = vdev->priv;
	if (!pDrvCtrl) {
		log_err("null pDrvCtrl\n");
		return;
	}

	/* Destroy virtqueue */

	/* TODO: implement the device reset */
	//vdev->config->reset(vdev);
	virtioDevReset(vdev);

	/*
	 * TODO: Replaced until the MMIO specific code moves to a separate entity
	 */
	//vdev->config->del_vqs(vdev);
	virtioDevFree(vdev);

	for (queueId = 0; queueId < pDrvCtrl->reqQueueNum; queueId++) {
		if (pDrvCtrl->pVsmQueue[queueId].req)
			free(pDrvCtrl->pVsmQueue[queueId].req);
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				   "queue %d thread cancel ->",
				   queueId);
		ret = pthread_cancel(pDrvCtrl->pVsmQueue[queueId].req_thread);
		if (ret == 0) {
			pthread_join(pDrvCtrl->pVsmQueue[queueId].req_thread,
				     NULL);
			VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
					   "done\n");
		} else {
			VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
					   "error: %s\n",
					   strerror(errno));
		}
	}

	if (pDrvCtrl->pVirtqueueInfo)
		free(pDrvCtrl->pVirtqueueInfo);

	if (pDrvCtrl->pIrq)
		free(pDrvCtrl->pIrq);

	if (pDrvCtrl->comp_thread) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				   "comp thread cancel ->");
		ret = pthread_cancel(pDrvCtrl->comp_thread);
		if (ret == 0) {
			pthread_join(pDrvCtrl->comp_thread, NULL);
			VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
					   "done\n");
		} else {
			log_err("error: %s\n", strerror(errno));
		}
	}

	if (pDrvCtrl->irq_thread) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				   "irq thread cancel ->");
		ret = pthread_cancel(pDrvCtrl->irq_thread);
		if (ret == 0) {
			pthread_join(pDrvCtrl->irq_thread, NULL);
			VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
					   "done\n");
		} else {
			VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
					   "error: %s\n",
					   strerror(errno));
		}
	}

	free(pDrvCtrl);

	ret = virtioHostCfgFree();
	if (ret) {
		log_err("failed to free configuration memory\n");
	}

	vdev->priv = NULL;

	VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO, "done\n");

	return;
}

int virtioHostEventHandler(struct virtio_device* vdev)
{
	uint32_t queueId;
	int err;
	struct virtioVsm *pDrvCtrl = vdev->priv;
	volatile uint32_t status = 0;
	virtio_mb();
	status = virtio_read(vdev, VIRTIO_MMIO_INTERRUPT_STATUS);
	virtio_write(vdev, VIRTIO_MMIO_INTERRUPT_ACK, status);

	if ((status & VIRTIO_MMIO_INT_CONFIG) != 0U) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				   "config event\n");
		virtioConfigChange(vdev);
	}
	if ((status & VIRTIO_MMIO_INT_VRING) != 0U) {
		VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
				   "vring interrupt\n");
		for (queueId = 0; queueId < pDrvCtrl->queueNum; queueId++) {
			VIRTIO_VSM_DBG_MSG(VIRTIO_VSM_DBG_INFO,
					   "queue %d\n", queueId);
			virtqueueNotification(pDrvCtrl->pQueue[queueId]);
		}
	}
	return 0;
}

/*
 * Open and return the UIO device file descriptor
 *
 * Returns file descriptor in success and -1 on error
 */
int virtioVsmGetUIO(VIRTIO_VSM_ID pDrvCtrl)
{
	struct virtual_device* vdev;
	int uio_fd;

	if (pDrvCtrl == NULL || pDrvCtrl->vdev == NULL) {
		log_err("invalid parameter\n");
		return -1;
	}
	uio_fd = open(pDrvCtrl->vdev->uio_device, O_RDWR | O_SYNC);
	if (uio_fd < 0) {
		log_err("UIO device error: %s\n", strerror(errno));
		return -1;
	}
	return uio_fd;
}

/*
 * Open and return the Control device file descriptor
 *
 * Returns file descriptor in success and -1 on error
 */
int virtioVsmGetCtrl(VIRTIO_VSM_ID pDrvCtrl)
{
	int ctrl_fd;

	if (pDrvCtrl == NULL || pDrvCtrl->vdev == NULL) {
		log_err("invalid parameter\n");
		return -1;
	}
	ctrl_fd = open(pDrvCtrl->vdev->virtio_ctrl_device,
		       O_RDWR | O_SYNC);
	if (ctrl_fd < 0) {
		log_err("cntrol device error: %s\n",
			strerror(errno));
		return -1;
	}
	return ctrl_fd;
}

bool virtioVsmLegacyIsLittleEndian(VIRTIO_VSM_ID pDrvCtrl)
{
	if (pDrvCtrl == NULL || pDrvCtrl->vdev == NULL) {
		log_err("invalid parameter\n");
		return false;
	}
	return virtio_legacy_is_little_endian(pDrvCtrl->vdev);
}
