/* virtioHostLib.h - virtio host library header */

/*
 * Copyright (c) 2022-2023 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */


#ifndef __INCvirtioHostLibh
#define __INCvirtioHostLibh

#include <linux/types.h>
#include <linux/virtio_types.h>
#include <linux/virtio_ring.h>
#include <linux/virtio_config.h>
#include <limits.h>
#include <sys/queue.h>
#include <endian.h>
#include <stdbool.h>
#include <stdint.h>
#include "uio-virtio.h"
#include "virtioLib.h"

#ifdef __cplusplus
extern "C" {
#endif

	/* virtio device type ID */

#define VIRTIO_TYPE_NET                     1   /* virtio net */
#define VIRTIO_TYPE_BLOCK                   2   /* virtio block */
#define VIRTIO_TYPE_CONSOLE                 3   /* virtio console */
#define VIRTIO_TYPE_RNG                     4   /* virtio rng */
#define VIRTIO_TYPE_BALLOON                 5   /* virtio balloon */
#define VIRTIO_TYPE_IOMEM                   6   /* virtio ioMemory */
#define VIRTIO_TYPE_RPMSG                   7   /* virtio remote processor */
	/* messaging               */
#define VIRTIO_TYPE_SCSI                    8   /* virtio scsi */
#define VIRTIO_TYPE_9P                      9   /* 9p virtio console */
#define VIRTIO_TYPE_MAC80211_WLAN           10  /* virtio WLAN MAC */
#define VIRTIO_TYPE_RPROC_SERIAL            11  /* virtio remoteproc serial */
	/* link */
#define VIRTIO_TYPE_CAIF                    12  /* Virtio caif */
#define VIRTIO_TYPE_MEMORY_BALLOON          13  /* virtio memory balloon */
#define VIRTIO_TYPE_GPU                     16  /* virtio GPU */
#define VIRTIO_TYPE_CLOCK                   17  /* virtio clock/timer */
#define VIRTIO_TYPE_INPUT                   18  /* virtio input */
#define VIRTIO_TYPE_VSOCK                   19  /* virtio vsock transport */
#define VIRTIO_TYPE_CRYPTO                  20  /* virtio crypto */
#define VIRTIO_TYPE_SIGNAL_DIST             21  /* virtio signal distribution */
	/* device                     */
#define VIRTIO_TYPE_PSTORE                  22  /* virtio pstore device */
#define VIRTIO_TYPE_IOMMU                   23  /* virtio IOMMU */
#define VIRTIO_TYPE_MEM                     24  /* virtio mem */
#define VIRTIO_TYPE_SOUND                   25  /* virtio sound */
#define VIRTIO_TYPE_FS                      26  /* virtio filesystem */
#define VIRTIO_TYPE_PMEM                    27  /* virtio pmem */
#define VIRTIO_TYPE_RPMB                    28  /* virtio rpmb */
#define VIRTIO_TYPE_MAC80211_HWSIM          29  /* virtio mac80211-hwsim */
#define VIRTIO_TYPE_VIDEO_ENCODER           30  /* virtio video encoder */
#define VIRTIO_TYPE_VIDEO_DECODER           31  /* virtio video decoder */
#define VIRTIO_TYPE_SCMI                    32  /* virtio SCMI */
#define VIRTIO_TYPE_NITRO_SEC_MOD           33  /* virtio nitro secure module*/
#define VIRTIO_TYPE_I2C_ADAPTER             34  /* virtio i2c adapter */
#define VIRTIO_TYPE_WATCHDOG                35  /* virtio watchdog */
#define VIRTIO_TYPE_CAN                     36  /* virtio can */
#define VIRTIO_TYPE_DMABUF                  37  /* virtio dmabuf */
#define VIRTIO_TYPE_PARAM_SERV              38  /* virtio parameter server */
#define VIRTIO_TYPE_AUDIO_POLICY            39  /* virtio audio policy */
#define VIRTIO_TYPE_BT                      40  /* virtio bluetooth */
#define VIRTIO_TYPE_GPIO                    41  /* virtio gpio */
#define VIRTIO_TYPE_RDMA                    42  /* virtio RDMA device */

#define VIRTIO_DEV_ANY_ID 0xffffffff

#define VIRTIO_MMIO_MAGIC_VALUE_LE 0x74726976 /* virt */

/* driver status code */

#define VIRTIO_STATUS_RESET       0x00u
#define VIRTIO_STATUS_ACK         0x01u
#define VIRTIO_STATUS_DRIVER      0x02u
#define VIRTIO_STATUS_FEATURES_OK 0x08u
#define VIRTIO_STATUS_DRIVER_OK   0x04u
#define VIRTIO_STATUS_NEEDS_RESET 0x40u
#define VIRTIO_STATUS_FAILED      0x80u


struct virtioVsm;
struct virtioHost;
struct virioChannel;
struct shmRegion;

typedef struct virtioVsm * VIRTIO_VSM_ID;
typedef struct virtioVsmQueue * VIRTIO_VSM_QUEUE_ID;

typedef void (* vHostDevCallbackFn)(struct virtioHost *, void *);

struct virtioShmRegion
{
	PHYS_ADDR paddr;
	uint64_t len;
	uint32_t id;
	uint32_t offset; /* region offset. Needed by UIO */
};

struct virtioVsmShmRegion
{
	struct virtioShmRegion region;
	VIRT_ADDR              vaddr;
};

struct virtioVsmOps 
{
	VIRTIO_VSM_QUEUE_ID (*getQueue)(VIRTIO_VSM_ID, uint32_t);
	int (*init)(VIRTIO_VSM_QUEUE_ID , struct virtioHost *);
	int (*notify)(VIRTIO_VSM_QUEUE_ID, struct virtioHost *, uint32_t);
	int (*shmRegionGet)(VIRTIO_VSM_ID, struct virtioVsmShmRegion *);
	void (*shmRegionRelease)(VIRTIO_VSM_ID, struct virtioVsmShmRegion *);
};

struct virtioHostVsm 
{
	VIRTIO_VSM_ID vsmId;
	struct virtioVsmOps vsmOps;
	struct virtioMap **pMaps;
	uint32_t mapNum;
};

struct virtioHostQueue
{
	volatile struct vring vRing;
	uint16_t availIdx;       /* the next desc to get buf  */
	uint16_t usedIdx;        /* the next used to put buf */
	uint16_t lastUsedIdx;    /* last used idx when do notification */
	uint16_t usedFlagShadow; /* flag to indicat interrupt is enabled or not */

	/* point to Virtio host device */
	struct virtioHost *vHost;
};

struct virtioHostBuf
{
	void *buf;
	uint32_t len;
	uint16_t flags;
	uint16_t pad;
};

struct virtioMap
{
	char name[NAME_MAX + 1];
	uint32_t count;
	uint32_t refCnt;
	struct virtio_map_entry {
		VIRT_ADDR hvaddr;
		PHYS_ADDR hpaddr;
		PHYS_ADDR gpaddr;
		PHYS_ADDR cpaddr;
		uint32_t  offset; 
		size_t size;
	} entry[0];
};

struct virtioChannel 
{
	uint32_t channelId;
	struct virtioMap *pMap;
};

struct virtioHostDev 
{
	uint32_t typeId;
	char args[PATH_MAX + 1];
	uint32_t channelNum;
	struct virtioChannel channels[1];
};

struct virtioHostOps
{
	/* reset */
	int (*reset)(struct virtioHost *);
	/* reg read */
	int (*reqRead)(struct virtioHost *, uint64_t, uint64_t, uint32_t *);
	/* reg write */
	int (*reqWrite)(struct virtioHost *, uint64_t, uint64_t, uint32_t);
	/* notify */
	void (*kick)(struct virtioHostQueue *);
	/* set status optional */
	int (*setStatus)(struct virtioHost *, uint32_t);
	/* create host instance */
	int (*create)(void *);
	/* show */
	void (*show)(struct virtioHost *, uint32_t);
};

struct virtioHost 
{
	VIRTIO_VSM_QUEUE_ID pVsmQueue;
	struct virtioVsmOps *pVsmOps;
	struct virtioHostOps *pHostOps;
	struct virtioHostQueue *pQueue;
	struct virtioMap *pMaps;
	void *ctx;
	uint32_t channelId;
	uint32_t queueMax;
	uint32_t shmMax;
	uint32_t version;       /* 0x4 */
	uint32_t deviceId;      /* 0x8 */
	uint32_t vendorId;      /* 0xc */
	uint32_t devFeature[2]; /* 0x10 */
	uint32_t devFeatureSel; /* 0x14 */
	uint32_t drvFeature[2]; /* 0x20 */
	uint32_t drvFeatureSel; /* 0x24 */
	uint32_t queueSel;      /* 0x30 */
	uint32_t queueMaxNum;   /* 0x34 */
	uint32_t intStatus;     /* 0x60 */
	uint32_t status;        /* 0x70 */
	uint32_t shmSel;        /* 0xac */
	struct virtioHostQueueReg
	{
		uint32_t queueNum;  /* 0x38 */
		uint32_t queueReady;/* 0x44 */
		uint32_t desc[2];   /* 0x80 */
		uint32_t avail[2];  /* 0x90 */
		uint32_t used[2];   /* 0xa0 */
	} *pHostQueueReg;
	struct virtioHostShmReg
	{
		uint32_t len[2];    /* 0xb0 */
		uint32_t addr[2];   /* 0xb8 */
	} *pHostShmReg;
	TAILQ_ENTRY(virtioHost) node;
};

struct virtioHostDrvInfo 
{
	uint32_t typeId;
	int (*create)(struct virtioHostDev *);
	TAILQ_ENTRY(virtioHostDrvInfo) node;
};

/* APIs for VSM */
extern void virtioHostDevicesInit(void);
extern void virtioHostInit(void);
extern int virtioHostVsmRegister(struct virtioHostVsm *);
extern int virtioHostVsmReqRead(struct virtioHost *, uint64_t,
				uint64_t, uint32_t *);
extern int virtioHostVsmReqWrite(struct virtioHost *,
				 uint64_t, uint64_t, uint32_t);
extern int virtioHostVsmReqReset(struct virtioHost *);
extern int virtioHostVsmReqKick(struct virtioHost *, uint32_t);

/* APIs for virtio host device */
extern int virtioHostCreate(struct virtioHost *, uint32_t, uint32_t,
			    uint64_t *, uint32_t, uint32_t, uint32_t, 
			    struct virtioShmRegion *, struct virtioHostOps *);
extern void virtioHostRelease(struct virtioHost *vHost);
extern uint64_t vritioHostHasFeature (struct virtioHost *, uint64_t);
extern uint16_t host_virtio16_to_cpu(struct virtioHost *vHost, __virtio16 val);
extern uint32_t host_virtio32_to_cpu(struct virtioHost *vHost, __virtio32 val);
extern uint64_t host_virtio64_to_cpu(struct virtioHost *vHost, __virtio64 val);
extern __virtio16 host_cpu_to_virtio16(struct virtioHost *vHost, uint16_t val);
extern __virtio32 host_cpu_to_virtio32(struct virtioHost *vHost, uint32_t val);
extern __virtio64 host_cpu_to_virtio64(struct virtioHost *vHost, uint64_t val);
extern int virtioHostNeedReset(struct virtioHost *);
extern int virtioHostTranslate(struct virtioHost*, PHYS_ADDR, VIRT_ADDR *);
extern int virtioHostConfigNotify(struct virtioHost *);
extern int virtioHostQueueNotify(struct virtioHostQueue *);
extern int virtioHostQueueGetBuf(struct virtioHostQueue *, uint16_t *,
		struct virtioHostBuf *, uint16_t);
extern int virtioHostQueueRetBuf(struct virtioHostQueue *);
extern int virtioHostQueueRelBuf(struct virtioHostQueue *, uint16_t, uint32_t);
extern int virtioHostQueueIntrEnable(struct virtioHostQueue *);
extern int virtioHostQueueIntrDisable(struct virtioHostQueue *);
extern int virtioHostDrvRegister(struct virtioHostDrvInfo *);
extern void virtioHostDevTravel(vHostDevCallbackFn, void *);
extern int virtioHostHpaConvertToCpa(PHYS_ADDR, PHYS_ADDR *);
extern int virtioHostCfgFree(void);
extern bool virtioHostQueueHasBuf(struct virtioHostQueue *pQueue);
extern int virtioHostStopThread(pthread_t thread);
extern int vsm_init(struct virtio_device *vdev);
extern void vsm_deinit(struct virtio_device *vdev);
extern int virtioVsmGetUIO(VIRTIO_VSM_ID pDrvCtrl);
extern int virtioVsmGetCtrl(VIRTIO_VSM_ID pDrvCtrl);
extern bool virtioVsmLegacyIsLittleEndian(VIRTIO_VSM_ID pDrvCtrl);

static inline uint16_t __virtio16_to_cpu(bool little_endian, __virtio16 val)
{
  	if (little_endian)
  		return le16toh(val);
  	else
		return be16toh(val);
}

static inline __virtio16 __cpu_to_virtio16(bool little_endian, uint16_t val)
{
  	if (little_endian)
  		return htole16(val);
  	else
		return htobe16(val);
}

static inline uint32_t __virtio32_to_cpu(bool little_endian, __virtio32 val)
{
  	if (little_endian)
  		return le32toh(val);
  	else
  		return be32toh(val);
}

static inline __virtio32 __cpu_to_virtio32(bool little_endian, uint32_t val)
{
  	if (little_endian)
  		return htole32(val);
  	else
  		return htobe32(val);
}

static inline uint64_t __virtio64_to_cpu(bool little_endian, __virtio64 val)
{
  	if (little_endian)
  		return le64toh(val);
  	else
  		return be64toh(val);
}

static inline __virtio64 __cpu_to_virtio64(bool little_endian, uint64_t val)
{
  	if (little_endian)
  		return htole64(val);
  	else
  		return htobe64(val);
}

#ifdef __cplusplus
}
#endif

#endif /* __INCvirtioHostLibh */
