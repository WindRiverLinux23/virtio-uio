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

#ifndef __INCvirtioLibh
#define __INCvirtioLibh

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <linux/types.h>
#include <sys/queue.h>
#include <linux/virtio_types.h>
#include <linux/virtio_ring.h>
#include <linux/virtio_mmio.h>
#include <linux/virtio_config.h>
#include "uio-virtio.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IRQ_AFFINITY_MAX_SETS 4
#define VIRTIO_DEV_ANY_ID 0xffffffff
#define VIRTIO_QUEUE_NAME_LEN 256

#define VIRTIO_VSM_CFG_REGION 1

#define dmb(opt) asm volatile("dmb " #opt : : : "memory")
#define virtio_wmb()	dmb(ish)
#define __iomem volatile
#define virtio_rmb() dmb(ishld)
#define virtio_wmb() dmb(ishst)
#define virtio_mb() __sync_synchronize()

#define max(a,b)				\
({						\
	__typeof__ (a) _a = (a);		\
	__typeof__ (b) _b = (b);		\
	_a > _b ? _a : _b;			\
})

#define min(a,b)				\
({						\
	__typeof__ (a) _a = (a);		\
	__typeof__ (b) _b = (b);		\
	_a < _b ? _a : _b;			\
})

typedef unsigned int __bitwise gfp_t;
typedef void* VIRT_ADDR;
typedef uintptr_t PHYS_ADDR;

struct virtqueueBuf
{
	void *buf;
	uint32_t len;
};

struct device {
	uint32_t version;
	void* base; /* device base address */
};

struct virtio_device_id {
	uint32_t device;
	uint32_t vendor;
};

/**
 * struct virtio_device - representation of a device using virtio
 * @queueList: internal list of virtqueues
 * @index: unique position on the virtio bus
 * @failed: saved value for VIRTIO_CONFIG_S_FAILED bit (for restore)
 * @config_enabled: configuration change reporting enabled
 * @config_change_pending: configuration change reported while disabled
 * @config_lock: protects configuration change reporting
 * @vqs_list_lock: protects @vqs.
 * @dev: underlying device.
 * @id: the device type identification (used to match it with a driver).
 * @features: the features supported by both driver and device.
 * @queues: virtqueue array
 * @ringAddr: address of vrings associated with queues
 * @nVqs: number of virtual queues in the device.
 * @virtio_ctrl_device: name of the control device node
 * @uio_device: name of the UIO device node
 * @priv: private pointer for the driver's use.
 */
struct virtio_device {
	TAILQ_HEAD(vqList, virtqueue) queueList;
	int index;
	bool failed;
	bool config_enabled;
	bool config_change_pending;
	pthread_mutex_t config_lock;
	pthread_mutex_t vqs_list_lock;
	struct device dev;
	struct virtio_device_id id;
	uint64_t features;
	struct virtqueue** queues;
	VIRT_ADDR* ringAddr;
	uint32_t nVqs;
	const char* virtio_ctrl_device;
	const char* uio_device;
#if 0 //TODO: later when we move MMIO specific functions to a separate entity
	const struct virtio_config_ops *config;
#endif

	void *priv;
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
 * @isBroken: if the virtqueue is broken
 * @availIdx: the next desc to add buf
 * @usedIdx: the next used to get buf
 * @lastAvailIdx: last avail when do kick
 * @availFlagShadow: flag to indicate if interrupt is enabled or not
 * @indirect: if the buffers are indirect
 * @vqDescx: internal data structure
 *
 * A note on @num_free: with indirect buffers, each buffer needs one
 * element in the queue, otherwise a buffer will need one element per
 * sg element.
 */
struct virtqueue {
	TAILQ_ENTRY(virtqueue) node;
	volatile struct vring vRing;
	struct virtioOps func;
	const char *name;
	struct virtio_device *vdev;
	unsigned int index;
	unsigned int num_free;
	unsigned int num_max;
	bool isBroken;
	uint16_t availIdx;
	uint16_t usedIdx;
	uint16_t lastAvailIdx;
	uint16_t availFlagShadow;
	bool indirect;
	size_t idrNum;
	struct vqDescExtra {
		void* cookie;
		struct vring_desc* idrTbl;
		PHYS_ADDR idrTblPhy;
		uint16_t ndescs;
        } vqDescx[0];
};

struct irq_affinity {
        unsigned int    pre_vectors;
        unsigned int    post_vectors;
        unsigned int    nr_sets;
        unsigned int    set_size[IRQ_AFFINITY_MAX_SETS];
        void            (*calc_sets)(struct irq_affinity *, unsigned int nvecs);
        void            *priv;
};

struct virtio_config_ops {
        void (*get)(struct virtio_device *vdev, unsigned offset,
                    void *buf, unsigned len);
        void (*set)(struct virtio_device *vdev, unsigned offset,
                    const void *buf, unsigned len);
        uint32_t (*generation)(struct virtio_device *vdev);
        uint8_t (*get_status)(struct virtio_device *vdev);
        void (*set_status)(struct virtio_device *vdev, uint8_t status);
        void (*reset)(struct virtio_device *vdev);
        void (*del_vqs)(struct virtio_device *);
        void (*synchronize_cbs)(struct virtio_device *);
        uint64_t (*get_features)(struct virtio_device *vdev);
        int (*finalize_features)(struct virtio_device *vdev);
        const char *(*bus_name)(struct virtio_device *vdev);
//        int (*set_vq_affinity)(struct virtqueue *vq,
//                               const struct cpumask *cpu_mask);
        const struct cpumask *(*get_vq_affinity)(struct virtio_device *vdev,
                        int index);
//        bool (*get_shm_region)(struct virtio_device *vdev,
//                               struct virtio_shm_region *region, uint8_t id);
        int (*disable_vq_and_reset)(struct virtqueue *vq);
        int (*enable_vq_after_reset)(struct virtqueue *vq);
};

static inline bool virtio_legacy_is_little_endian(
	const struct virtio_device* vdev)
{
  #ifdef __LITTLE_ENDIAN
	return true;
  #else
	return (virtioHasFeatures(vdev, VIRTIO_F_VERSION_1) == 0UL);
  #endif
}

static inline uint16_t host_readw(uint16_t __iomem *addr)
{
	volatile uint16_t val;

	val = *addr;

	return val;
}

static inline uint32_t host_readl(uint32_t __iomem *addr)
{
	volatile uint32_t val;

	val = *addr;

	return val;
}

static inline uint64_t host_readq(uint64_t __iomem *addr)
{
	volatile uint64_t val;

	val = *addr;

	return val;
}

static inline void host_writew(uint16_t v, uint16_t __iomem *addr)
{
	*addr = v;
}

static inline void host_writel(uint32_t v, uint32_t __iomem *addr)
{
	*addr = v;
}

static inline void host_writeq(uint64_t v, uint64_t __iomem *addr)
{
	*addr = v;
}

extern void *zmalloc(size_t size);
extern uint32_t virtio_cread32(struct virtio_device *vdev, unsigned int offset);
extern int setup_vq(struct virtio_device *vdev, unsigned int index,
		    struct virtqueueInfo* vqInfo);
extern uint32_t virtio_read(struct virtio_device *vdev, uint32_t reg);
extern void virtio_write(struct virtio_device *vdev, uint32_t reg, uint32_t val);
extern void virtio_add_status(struct virtio_device *dev, uint8_t status);
extern void* virtqueueGetBuffer(struct virtqueue* vq, unsigned int *len,
				uint32_t* token);
extern unsigned int virtqueue_get_vring_size(struct virtqueue *_vq);
extern bool virtqueue_is_broken(struct virtqueue *_vq);
extern const volatile struct vring* virtqueue_get_vring(struct virtqueue *vq);
extern uint16_t virtio16_to_cpu(struct virtio_device *vdev, __virtio16 val);
extern void virtioVsmVirtqueueEnable(struct virtio_device* vdev,
				     int queueId, bool enable);
int virtqueueAddBuffer(struct virtqueue* pQueue,
		       const struct virtqueueBuf* bufList,
		       uint32_t readable,
		       uint32_t writable,
		       void* cookie);
extern int virtqueueKick(struct virtqueue* pQueue);
extern void virtqueueNotification(struct virtqueue* pQueue);
extern void virtioReadShmRegion(struct virtio_device* vdev,
				struct virtio_region* region, int idx);
extern bool virtqueueIntrEnable(struct virtqueue* pQueue);
extern void virtqueueIntrDisable(struct virtqueue* pQueue);

extern void virtioDevInit(struct virtio_device* vdev);
extern void virtioDevFree(struct virtio_device* vdev);
extern size_t virtioRegionGet(int ctrl_fd, PHYS_ADDR addr, size_t size,
			      uint32_t* offset);
extern void virtioConfigChange(const struct virtio_device* vdev);
extern uint64_t virtioHasFeatures(const struct virtio_device* vdev,
				  uint64_t feature);
void virtioDevReset(struct virtio_device* vdev);
#ifdef __cplusplus
}
#endif

#endif /* __INCvirtioLibh */
