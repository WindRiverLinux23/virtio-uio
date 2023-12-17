/* virtioHostBlock.c - virtio block host device */

/*
 * Copyright (c) 2022-2023 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

/*
   DESCRIPTION

   This is the application that supply a virtio blk host driver, it provides
   the back-end storage media support for the reading and writing functions
   of virtio-block device on the host VM.
 */

#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/queue.h>
#include <linux/virtio_blk.h>
#include "virtio_host_lib.h"

#undef VIRTIO_BLK_PERF

#ifdef VIRTIO_BLK_PERF
/* FIXME: add functions for the time measurements */
#include <linux/timex.h>
#endif

#define VIRTIO_BLK_DEV_DBG_ON
#ifdef VIRTIO_BLK_DEV_DBG_ON

#define VIRTIO_BLK_DEV_DBG_OFF             0x00000000
#define VIRTIO_BLK_DEV_DBG_ISR             0x00000001
#define VIRTIO_BLK_DEV_DBG_ARGS            0x00000020
#define VIRTIO_BLK_DEV_DBG_ERR             0x00000100
#define VIRTIO_BLK_DEV_DBG_INFO            0x00000200
#define VIRTIO_BLK_DEV_DBG_ALL             0xffffffff

static uint32_t virtioBlkDevDbgMask = VIRTIO_BLK_DEV_DBG_ERR;

#define VIRTIO_BLK_DEV_DBG(mask, fmt, ...)				\
	do {								\
		if ((virtioBlkDevDbgMask & (mask)) ||			\
		    ((mask) == VIRTIO_BLK_DEV_DBG_ALL)) {		\
			printf("%d: %s() " fmt, __LINE__, __func__,	\
			       ##__VA_ARGS__);				\
		}							\
	}								\
while ((false));
#else
#define VIRTIO_BLK_DEV_DBG(...)
#endif  /* VIRTIO_BLK_DEV_DBG_ON */


#define VIRTIO_BLK_DRV_NAME         "virtio-block-host"

#define VIRTIO_BLK_QUEUE_MAX        1     /* block device only has one queue */
#define VIRTIO_BLK_QUEUE_MAX_NUM    2048  /* max number of descriptors in a queue*/
#define VIRTIO_BLK_DISK_ID_BYTES    20

#define BLOCK_IO_REQ_MAX            256//256
#define VIRTIO_BLK_SIZE             512

#define VIRTIO_BLK_HOST_DEV_MAX     30

/* feature */
#define HEX_CODE_CHECK(s, mode)                                                \
	do {                                                                   \
		if ((s[0] == '0') && ((s[1] == 'x') || (s[1] == 'X')))         \
		{                                                              \
			mode = 16;                                             \
		}                                                              \
		else                                                           \
		{                                                              \
			mode = 10;                                             \
		}                                                              \
	} while (0)

enum virtioBlkOpType {
	BLK_OP_READ,
	BLK_OP_WRITE,
	BLK_OP_FLUSH,
	BLK_OP_DISCARD
};

struct virtioBlkConfig {
	uint64_t         capacity;                   /* 0x00 */
	uint32_t         size_max;                   /* 0x08 */
	uint32_t         seg_max;                    /* 0x0c */
	struct {
		uint16_t cylinders;                  /* 0x10 */
		uint8_t  heads;                      /* 0x12 */
		uint8_t  sectors;                    /* 0x13 */
	} geometry;
	uint32_t         blk_size;                   /* 0x14 */
	struct {
		uint8_t  physical_block_exp;         /* 0x15 */
		uint8_t  alignment_offset;           /* 0x16 */
		uint16_t min_io_size;                /* 0x18 */
		uint32_t opt_io_size;                /* 0x1c */
	} topology;
	uint8_t          writeback;                  /* 0x20 */
	uint8_t          unused;                     /* 0x21 */
	uint16_t         num_queues;                 /* 0x22 */
	uint32_t         max_discard_sectors;        /* 0x24 */
	uint32_t         max_discard_seg;            /* 0x28 */
	uint32_t         discard_sector_alignment;   /* 0x2c */
	uint32_t         max_write_zeroes_sectors;
	uint8_t          write_zeroes_may_unmap;
	uint8_t          unused1[3];
	uint32_t         max_secure_erase_sectors;
	uint32_t         max_secure_erase_seg;
	uint32_t         secure_erase_sector_alignment;
} __attribute__((packed));

struct virtioBlkReqHdr {                 /* fixed-size block header */
	uint32_t type;
	uint32_t reserved;
	uint64_t sector;
#ifdef VIRTIO_BLK_PERF
	uint64_t time1;
	uint64_t time2;
	uint64_t time3;
	uint64_t time4;
	uint64_t time5;
#endif
	uint8_t status;
} __attribute__((packed));

struct virtioBlkIoReq {                  /* virtio block I/O request */
	TAILQ_ENTRY(virtioBlkIoReq) node;
	struct virtioBlkHostCtx *blkHostCtx;
	struct virtioHostBuf bufList[BLOCK_IO_REQ_MAX];
	int bufcnt;
	uint16_t idx;
	uint64_t offset;
	size_t len;
	uint8_t *pStatus;
	enum virtioBlkOpType opType;
	struct virtioBlkReqHdr *pReqHdr;
};

struct virtioBlkHostDev {
	struct virtioBlkHostCtx {
		struct virtioHost vhost;
		struct virtioBlkIoReq ioReqlist[VIRTIO_BLK_QUEUE_MAX_NUM];
		struct virtioBlkConfig cfg;
		uint64_t feature;
		pthread_t work_thread;
		bool work_thread_created;
		sem_t work_sem;
		pthread_mutex_t listLock;
		TAILQ_HEAD(requestList, virtioBlkHostDev) pendReqList;
	} blkHostCtx;

	struct virtioBlkBeDevArgs {
		char bePath[PATH_MAX + 1];     /* backend path     */
		bool isFile;                   /* backend is file  */
		bool ro;                       /* read-only        */
		bool writeThru;                /*  1: write-though */
		                               /*  0: copy-back    */
		uint32_t  sectorSize;               /* sector size      */
		uint32_t  phySectorSize;            /* PHYS sector size */
		bool subFile;                  /* sub-file mode    */
		uint64_t  subFileLba;               /* sub-file start   */
		uint64_t  subFileSize;              /* sub-file size    */
		struct virtioChannel channel[1];
	} beDevArgs;

	struct block_device *bdev;
	int fd;
	bool rdOnly;
	uint64_t capacity;
	uint32_t blkSize;
	char ident[VIRTIO_BLK_DISK_ID_BYTES + 1];
};

static struct virtioBlkHostDrv {
	struct virtioBlkHostDev * vBlkHostDevList[VIRTIO_BLK_HOST_DEV_MAX];
	uint32_t vBlkHostDevNum;
	pthread_mutex_t drvLock;
	uint32_t mountTimeout;
} vBlkHostDrv;

static int virtioHostBlkReset(struct virtioHost *);
static void virtioHostBlkNotify(struct virtioHostQueue *);
static void virtioHostBlkFlush(struct virtioBlkIoReq *);
static void virtioHostBlkGetId(struct virtioBlkIoReq *);
static int virtioHostBlkCfgRead(struct virtioHost *, uint64_t, uint64_t size, uint32_t *);
static int virtioHostBlkCfgWrite(struct virtioHost *, uint64_t, uint64_t, uint32_t);
static void* virtioHostBlkReqHandle(void* arg);
static void virtioHostBlkDone(struct  virtioBlkIoReq *, struct virtioHostQueue *, int);
static int virtioHostBlkCreate(struct virtioHostDev *);
static void virtioHostBlkShow(struct virtioHost *, uint32_t);

struct virtioHostOps virtioBlkHostOps = {
	.reset    = virtioHostBlkReset,
	.kick     = virtioHostBlkNotify,
	.reqRead  = virtioHostBlkCfgRead,
	.reqWrite = virtioHostBlkCfgWrite,
	.show     = virtioHostBlkShow,
};

static struct virtioHostDrvInfo virtioBlkHostDrvInfo =
{
	.typeId = VIRTIO_TYPE_BLOCK,
	.create = virtioHostBlkCreate,
};

/* Define the following line to use the disk in memory */
#undef VIRTIO_BLK_MEM
#ifdef VIRTIO_BLK_MEM
#define VIRTIO_BLK_MEM_BLK_NUM 2*1024*64
char *disk_mem = NULL;
#endif

/*******************************************************************************
 *
 * virtioHostBlkDrvInit - initialize virtio-blk host device driver
 *
 * This routine initializes the virtio-blk host device driver.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

void virtioHostBlkDrvInit(uint32_t mountTimeout)
{
	virtioHostDrvRegister((struct virtioHostDrvInfo *)&virtioBlkHostDrvInfo);

	pthread_mutex_init(&vBlkHostDrv.drvLock, NULL);

	vBlkHostDrv.mountTimeout = mountTimeout;
}


void virtioHostBlkDrvRelease(void)
{
	uint32_t devNum;
	struct virtioBlkHostDev *pBlkHostDev;
	struct virtioBlkHostCtx *pBlkHostCtx;

	for (devNum = 0; devNum < vBlkHostDrv.vBlkHostDevNum; devNum++) {
		pBlkHostDev = vBlkHostDrv.vBlkHostDevList[devNum];
		pBlkHostCtx = (struct virtioBlkHostCtx *)pBlkHostDev;

		if (pBlkHostDev)
			if (pBlkHostDev->bdev)
				blkdev_put(pBlkHostDev->bdev, FMODE_READ | FMODE_WRITE);

		if (pBlkHostCtx && pBlkHostCtx->work_thread_created &&
		    virtioHostStopThread(pBlkHostCtx->work_thread) != 0 ) {
			VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
					   "work thread cancel failed\n");
			return;
		}

		virtioHostRelease(&pBlkHostCtx->vhost);

		free(pBlkHostDev);
	}
}

/*****************************************************************************
 *
 * virtioHostBlkFlushOp - virtio host block flush operation
 *
 * This routine executes host block flush operation
 *
 * RETURNS: 0 for success and minus error number otherwise
 *
 * ERRNO: N/A
 */

inline int virtioHostBlkFlushOp(struct virtioBlkHostDev *pBlkHostDev)
{
/* FIXME: clarify the operation later ifdefed out for now */
#if 0
#ifndef VIRTIO_BLK_MEM
	int ret;
	struct bio *bio;
#endif
	if (pBlkHostDev->beDevArgs.isFile) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"virtioHostBlkFlushOp file-backed not supported\n");
		return -EFAULT;
	}
#ifndef VIRTIO_BLK_MEM
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	bio = bio_alloc(GFP_NOIO | __GFP_HIGH, 0);
#else
	bio = bio_alloc(pBlkHostDev->bdev, 0, REQ_OP_FLUSH | REQ_PREFLUSH, GFP_NOIO | __GFP_HIGH);
#endif
	if (!bio) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"virtioHostBlkFlushOp failed to allocate bio\n");
		return -EFAULT;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	bio_set_dev(bio, pBlkHostDev->bdev);
	bio->bi_opf = REQ_OP_FLUSH | REQ_PREFLUSH;
#endif

	ret = submit_bio_wait(bio);
	if (ret) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"virtioHostBlkFlushOp failed to submit bio(%d)\n",
				ret);
		return -EFAULT;
	}

	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
			"virtioHostBlkFlushOp bio:0x%llx opf:0x%x\n",
			(uint64_t)bio, bio->bi_opf);
	bio_put(bio);
#endif
#endif /* 0 */
	return 0;
}

/*******************************************************************************
 *
 * virtioHostBlkSubmitBio - virto block host submit block IO request to general
 * block layer
 *
 * This routine is used to write data or read date to or from backend storage
 * media.
 *
 * RETURN: N/A
 *
 * ERROR: N/A
 */
static void virtioHostBlkSubmitBio(struct virtioBlkIoReq *pBlkReq)
{
#if 0
	struct virtioBlkHostDev *pBlkHostDev;
	struct virtioHost *vhost;
	uint32_t blkSize;
	uint64_t offset;
	int ret = 0;
	int i;

#ifndef VIRTIO_BLK_MEM
	struct bio *bio;
	struct page *page;
	unsigned long ram_buf;
	int len;
#endif

	pBlkHostDev = (struct virtioBlkHostDev *)pBlkReq->blkHostCtx;
	if (pBlkHostDev->beDevArgs.isFile) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"virtioHostBlkSubmitBio file-backed not supported\n");
		return;
	}

	vhost = (struct virtioHost *)pBlkReq->blkHostCtx;
	blkSize = pBlkHostDev->blkSize;
	offset = pBlkReq->offset;

#ifdef VIRTIO_BLK_PERF
	pBlkReq->pReqHdr->time3 = ktime_get_real_fast_ns();
#endif

	for (i = 0, pBlkReq->len = 0; i < pBlkReq->bufcnt; i++) {
#ifdef VIRTIO_BLK_MEM
		if (!disk_mem)
			VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
					"virtioHostBlkSubmitBio null disk_mem\n");

		if (pBlkReq->opType == BLK_OP_READ) {
			VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
					"virtioHostBlkSubmitBio read 0x%x, 0x%lx -> 0x%lx (%u)\n",
					pBlkReq->bufList[i].len,
					(unsigned long)(disk_mem + offset * blkSize),
					(unsigned long)pBlkReq->bufList[i].buf,
					blkSize);

			memcpy(pBlkReq->bufList[i].buf,
					disk_mem + (offset * blkSize),
					pBlkReq->bufList[i].len);
		} else {
			VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
					"virtioHostBlkSubmitBio write 0x%x, 0x%lx -> 0x%lx (%u)\n",
					pBlkReq->bufList[i].len,
					(unsigned long)pBlkReq->bufList[i].buf,
					(unsigned long)(disk_mem + offset * blkSize),
					blkSize);

			memcpy(disk_mem + (offset * blkSize),
					pBlkReq->bufList[i].buf,
					pBlkReq->bufList[i].len);
		}

		offset += (pBlkReq->bufList[i].len / blkSize);
#else
		//native block driver
		page = alloc_pages(GFP_KERNEL | __GFP_ZERO, get_order(pBlkReq->bufList[i].len));
		if (!page) {
			VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
					"virtioHostBlkSubmitBio failed to alloc page\n");
			return;
		}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
		bio = bio_alloc(GFP_NOIO | __GFP_HIGH, 1);
#else
		bio = bio_alloc(pBlkHostDev->bdev, 1,
				(pBlkReq->opType == BLK_OP_READ) ? REQ_OP_READ : REQ_OP_WRITE,
				GFP_NOIO | __GFP_HIGH);
#endif
		if (!bio) {
			VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
					"virtioHostBlkSubmitBio failed to alloc bio\n");
			return;
		}

		bio->bi_iter.bi_sector = (sector_t)offset;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
		bio_set_dev(bio, pBlkHostDev->bdev);
		bio->bi_opf = (pBlkReq->opType == BLK_OP_READ) ? REQ_OP_READ : REQ_OP_WRITE;
#endif

		ram_buf = (unsigned long)page_address(page);

		// TODO
		// This copy might be saved by a local ring buffer.
		if (pBlkReq->opType == BLK_OP_WRITE)
			memcpy((void *)ram_buf, pBlkReq->bufList[i].buf,
					pBlkReq->bufList[i].len);

		len = bio_add_page(bio, page, pBlkReq->bufList[i].len, 0);
		if (len < pBlkReq->bufList[i].len) {
			VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
					"virtioHostBlkSubmitBio failed to add page 0x%x:0x%x\n",
					pBlkReq->bufList[i].len, len);
			bio_put(bio);
			__free_pages(page, get_order(pBlkReq->bufList[i].len));
			virtioHostBlkDone(pBlkReq, vhost->pQueue, ret);
			return;
		}

		// TODO
		// Should be able to submit multiple buffers together as much as
		// possible so that native driver could do the potential
		// optimization.
		ret = submit_bio_wait(bio);
		if (ret) {
			VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
					"virtioHostBlkSubmitBio failed to submit bio(%d)\n",
					ret);
			bio_put(bio);
			virtioHostBlkDone(pBlkReq, vhost->pQueue, ret);
			return;
		}

		if (pBlkReq->opType == BLK_OP_READ)
			memcpy(pBlkReq->bufList[i].buf, (void *)ram_buf,
					pBlkReq->bufList[i].len);

		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
				"virtioHostBlkSubmitBio "
				"page:0x%llx bio:0x%llx sector:0x%llx opf:0x%x\n",
				(uint64_t)page, (uint64_t)bio, offset, bio->bi_opf);
		bio_put(bio);

		__free_pages(page, get_order(pBlkReq->bufList[i].len));

		offset += (pBlkReq->bufList[i].len / blkSize);
#endif
		pBlkReq->len += pBlkReq->bufList[i].len;
	}

#ifdef VIRTIO_BLK_PERF
	pBlkReq->pReqHdr->time4 = ktime_get_real_fast_ns();
#endif

#endif /* 0 */
	struct virtioHost* vhost = (struct virtioHost *)pBlkReq->blkHostCtx;
	struct virtioBlkHostDev* pBlkHostDev =
		(struct virtioBlkHostDev *)pBlkReq->blkHostCtx;
	int ret = 0;

	if ((vritioHostHasFeature(vhost, VIRTIO_BLK_F_FLUSH) == 0) &&
			(pBlkReq->opType == BLK_OP_WRITE)) {
		ret = virtioHostBlkFlushOp(pBlkHostDev);
	}

	virtioHostBlkDone(pBlkReq, vhost->pQueue, ret);

	return;
}

/*******************************************************************************
 *
 * virtioHostBlkFlush - flush the data from filesystem catch to storage media
 *
 * This routine is used to flush the data in filesystem catch into storage media.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void virtioHostBlkFlush(struct virtioBlkIoReq *pBlkReq)
{
	struct virtioHost *vhost;
	struct virtioBlkHostDev *vBlkHostDev;
	int ret = 0;

	vBlkHostDev = (struct virtioBlkHostDev *)pBlkReq->blkHostCtx;
	vhost = (struct virtioHost *)pBlkReq->blkHostCtx;

	ret = virtioHostBlkFlushOp(vBlkHostDev);
	if (ret)
		VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ERR,
				"%s failed to synchronize storage media\n",
				__FUNCTION__);

	virtioHostBlkDone(pBlkReq, vhost->pQueue, ret);

	return;
}

/*******************************************************************************
 *
 * virtioHostBlkGetId - Get the identify of the block device
 *
 * This routine is used to read back to the guest buffers a 20 byte ID string.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void virtioHostBlkGetId(struct virtioBlkIoReq *pBlkReq)
{
	struct virtioBlkHostDev *vBlkHostDev;
	struct virtioHost *vhost;
	uint32_t size;

	vBlkHostDev = (struct virtioBlkHostDev *)pBlkReq->blkHostCtx;
	vhost = (struct virtioHost *)pBlkReq->blkHostCtx;

	size = sizeof(vBlkHostDev->ident);
	pBlkReq->len = min(size, pBlkReq->bufList[0].len);

	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
			"virtioHostBlkGetId vBlkHostDev->ident: %d, %s\n",
			size, vBlkHostDev->ident);

	memcpy(pBlkReq->bufList[0].buf, vBlkHostDev->ident, pBlkReq->len);

	virtioHostBlkDone(pBlkReq, vhost->pQueue, 0);
}

/*******************************************************************************
 *
 * virtioHostBlkCreateWithBlk - create virtio host block with block device
 *
 * This routine creates a virtio host block with storage block device,
 * the block device is allowed a block device or a block device partition.
 * To ensure the device or partition couldn't be accessed from host side,
 * the filesystem mounted on device is kicked off.
 *
 * RETURNS: 0, or negative values if the virtio host block device creating
 * failed.
 *
 * ERRNO: N/A
 */
static int virtioHostBlkCreateWithBlk(struct virtioBlkHostDev *pBlkHostDev)
{
	struct virtioBlkBeDevArgs *pBlkBeDevArgs = &pBlkHostDev->beDevArgs;
#if 0
#ifdef VIRTIO_BLK_MEM
	pBlkHostDev->blkSize = VIRTIO_BLK_SIZE; //block size
	pBlkHostDev->capacity = VIRTIO_BLK_MEM_BLK_NUM; //total number of blocks

	disk_mem = vzalloc(VIRTIO_BLK_MEM_BLK_NUM * pBlkHostDev->blkSize);
	if (!disk_mem) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"virtioHostBlkCreateWithBlk failed to alloc disk_mem\n");
		return -EFAULT;
	}
#else
	pBlkHostDev->bdev = blkdev_get_by_path(pBlkBeDevArgs->bePath,
			FMODE_READ | FMODE_WRITE, NULL);
	if (IS_ERR(pBlkHostDev->bdev)) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"virtioHostBlkCreateWithBlk failed to get blkdev %s(%ld)\n",
				pBlkBeDevArgs->bePath, PTR_ERR(pBlkHostDev->bdev));
		return -EFAULT;
	} else {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
				"virtioHostBlkCreateWithBlk got blkdev %s\n",
				pBlkBeDevArgs->bePath);
	}

	pBlkHostDev->blkSize = VIRTIO_BLK_SIZE;
	pBlkHostDev->capacity = bdev_nr_sectors(pBlkHostDev->bdev);

	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
			"virtioHostBlkCreateWithBlk bdev:0x%llx blkSize:%u capacity:0x%llx\n",
			(uint64_t)pBlkHostDev->bdev, pBlkHostDev->blkSize, pBlkHostDev->capacity);
#endif

#endif /* 0 */
	if (pBlkBeDevArgs->ro)
		pBlkHostDev->rdOnly = true;
	return 0;
}

/*******************************************************************************
 *
 * virtioHostBlkBeDevCreate - create virtio block backend device
 *
 * This routine creates virtio block backend real device
 *
 * RETURNS: 0, or -1 if any error is raised in process of the backend block
 * device creating.
 *
 * ERRNO: N/A
 */

static int virtioHostBlkBeDevCreate(struct virtioBlkHostDev *pBlkHostDev)
{
	struct virtioBlkHostCtx *pBlkHostCtx;
	int ret;

	pBlkHostCtx = &pBlkHostDev->blkHostCtx;

	if (pBlkHostDev->beDevArgs.isFile) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"virtioHostBlkBeDevCreate file-backed not supported\n");
	} else {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
				"virtioHostBlkBeDevCreate harddisk\n");
		ret = virtioHostBlkCreateWithBlk(pBlkHostDev);
	}

	if (ret) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"virtioHostBlkBeDevCreate failed(%d)\n", ret);
		return ret;
	}

	// The rest registers are all 0
	pBlkHostCtx->cfg.capacity = host_virtio64_to_cpu(&pBlkHostCtx->vhost,
			pBlkHostDev->capacity);
	pBlkHostCtx->cfg.seg_max  = host_virtio32_to_cpu(&pBlkHostCtx->vhost,
			BLOCK_IO_REQ_MAX);
	pBlkHostCtx->cfg.blk_size = host_virtio32_to_cpu(&pBlkHostCtx->vhost,
			bdev_logical_block_size(pBlkHostDev->bdev));
	pBlkHostCtx->cfg.num_queues = (uint16_t)host_virtio16_to_cpu(&pBlkHostCtx->vhost,
			VIRTIO_BLK_QUEUE_MAX_NUM);

	/* set device features */
	pBlkHostCtx->feature = (1UL << VIRTIO_F_VERSION_1) |
		(1UL << VIRTIO_BLK_F_SEG_MAX) |
		(1UL << VIRTIO_BLK_F_BLK_SIZE) |
		(1UL << VIRTIO_RING_F_INDIRECT_DESC);

	if (pBlkHostDev->rdOnly)
		pBlkHostCtx->feature |= (1UL << VIRTIO_BLK_F_RO);

	if (!pBlkHostDev->beDevArgs.writeThru) {
		pBlkHostCtx->feature |= (1UL << VIRTIO_BLK_F_CONFIG_WCE)
			|(1UL << VIRTIO_BLK_F_FLUSH);
		pBlkHostCtx->cfg.writeback = 1;
	}

	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
			"pBlkHostCtx->feature:0x%lx\n",
			pBlkHostCtx->feature);

	return 0;
}

/*******************************************************************************
 *
 * virtioBlkHostIdentGet - generate virtio block device ident
 *
 * This routine generates virtio block device ident
 *
 * RETURNS: 0, or -1 if failed to create EVP_MD_CTX .
 *
 * ERRNO: N/A
 */

static int virtioBlkHostIdentGet(struct virtioBlkHostDev *pBlkHostDev)
{
	uint8_t md5_hash[16];
	struct crypto_shash *alg = NULL;

	alg = crypto_alloc_shash("md5", 0, 0);
	if (IS_ERR(alg)) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
				   "could not allocate shash TFM %ld\n",
				   PTR_ERR(alg));
		return PTR_ERR(alg);
	}
#if 0
	struct shash_desc *sdesc = NULL;


	sdesc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(alg),
			GFP_KERNEL);
	if (!sdesc) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
				"virtioBlkHostIdentGet failed to allocate memory\n");
		return -ENOMEM;
	}

	sdesc->tfm = alg;

	crypto_shash_init(sdesc);
	crypto_shash_update(sdesc, pBlkHostDev->beDevArgs.bePath,
			strlen(pBlkHostDev->beDevArgs.bePath));
	crypto_shash_final(sdesc, md5_hash);
	crypto_free_shash(sdesc->tfm);
	sdesc->tfm = NULL;
	kfree_sensitive(sdesc);
#endif
	(void)snprintf(pBlkHostDev->ident, VIRTIO_BLK_DISK_ID_BYTES + 1,
			"WRHV--%02X%02X-%02X%02X-%02X%02X",
			md5_hash[0], md5_hash[1], md5_hash[2],
			md5_hash[3], md5_hash[4], md5_hash[5]);
 
	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
			   "ident:%s\n",
			   pBlkHostDev->ident);

	return 0;
}

/*******************************************************************************
 *
 * virtioHostBlkDevCreate - create virtio block device instance
 *
 * This routine creates and initializes create virtio block device instance.
 *
 * RETURNS: 0, or -1 if any error is raised in process of the block device
 * context creating.
 *
 * ERRNO: N/A
 */

static int virtioHostBlkDevCreate(struct virtioBlkHostDev *pBlkHostDev)
{
	struct virtioBlkHostCtx *pBlkHostCtx;
	struct virtioBlkBeDevArgs *pBlkBeDevArgs;
	struct virtioHost *vhost;
	uint32_t devNum;
	int ret;

	vhost         = (struct virtioHost *)pBlkHostDev;
	pBlkHostCtx   = (struct virtioBlkHostCtx *)pBlkHostDev;
	pBlkBeDevArgs = &pBlkHostDev->beDevArgs;

	/* initialize virtio block host device context */
	TAILQ_INIT(&pBlkHostCtx->pendReqList);

	pthread_mutex_init(&pBlkHostCtx->listLock, NULL);

	/* create virtio block host device ident */
	if (virtioBlkHostIdentGet(pBlkHostDev))
		goto err;

	ret = virtioHostBlkBeDevCreate(pBlkHostDev);
	if (ret)
		goto err;

	vhost->channelId = pBlkBeDevArgs->channel->channelId;
	vhost->pMaps = pBlkBeDevArgs->channel->pMap;

	ret = virtioHostCreate(vhost,
			VIRTIO_DEV_ANY_ID,
			VIRTIO_ID_BLOCK,
			&pBlkHostCtx->feature,
			VIRTIO_BLK_QUEUE_MAX,
			VIRTIO_BLK_QUEUE_MAX_NUM,
			0, NULL,
			&virtioBlkHostOps);
	if (ret) {
		VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ERR,
				"%s: virtio block host context creating failed %d\n",
				__FUNCTION__, ret);
		goto err;
	}

	pthread_mutex_lock(&vBlkHostDrv.drvLock);

	vBlkHostDrv.vBlkHostDevList[vBlkHostDrv.vBlkHostDevNum] = pBlkHostDev;

	devNum = vBlkHostDrv.vBlkHostDevNum++;

	pthread_mutex_unlock(&vBlkHostDrv.drvLock);

#if 0
	INIT_WORK(&pBlkHostCtx->work, virtioHostBlkReqHandle);

	pBlkHostCtx->workqueue = alloc_workqueue("kvblkd%d",
			0, 512, devNum);
	if (!pBlkHostCtx->workqueue) {
		VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ERR,
				"%s: failed to create virtio block host kworker\n",
				__FUNCTION__);
		goto err;
	}
#endif
	pBlkHostCtx->work_thread_created = false;
	ret = pthread_create(&pBlkHostCtx->work_thread, NULL, virtioHostBlkReqHandle, pBlkHostCtx);
	if (ret) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"%s: failed to create virtio block host worker thread\n",
				__FUNCTION__);
		goto err;
	}

	pBlkHostCtx->work_thread_created = true;
	rc = sem_init(&pBlkHostCtx->work_sem, 0, 0);                        
	if (rc) {                                                        
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,                   
				   "Failed to create VSM request "
				   "queue %d sem(%d)\n",
				   queueId, rc);
		goto err;
	}

	return 0;

err:
	virtioHostBlkDrvRelease();
	return -1;
}

/*******************************************************************************
 *
 * virtioHostBlkParseArgs - parse argument list of virtio block device
 *
 * This routine parses argument list of virtio block device.
 *
 * RETURNS: 0, or negative value of errno number if any error is raised
 * in process of the parsing.
 *
 * ERRNO: N/A
 */

static int virtioHostBlkParseArgs(struct virtioBlkBeDevArgs *pBlkBeDevArgs, char *pArgs, uint32_t len)
{
	char *          p0;
	char *          p1;
	char *          p2;
	char *          p3;
	char *          p4;
	int             ret;
	int             base;
	uint32_t *      pVal32;
	uint64_t *      pVal64;

	ret = 0;
	pBlkBeDevArgs->writeThru  = 1;
	pBlkBeDevArgs->sectorSize = VIRTIO_BLK_SIZE;

	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
			"virtioHostBlkParseArgs %s\n", pArgs);

	p0 = pArgs;
	p3 = p0 + len;

	for (p1 = p0; p1 <= p3; p1++)
	{
		if ((*p1 == ',') || (*p1 == '\0'))
		{
			/* reach to ',' or reach to ending */
			len = (uint32_t)(p1 - p0);

			if (len == 0)
			{
				/* reached the list end, parsed done */
				break;
			}

			p2 = strstr(p0, "be=");
			if (p2 == p0)
			{
				if (p0 != pArgs)
				{
					VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ERR, "%s: be = xxx "\
							"must be the first argument!\n",
							__FUNCTION__);
					ret = -EINVAL;
					goto done;
				}

				p0 += (sizeof("be=") - 1);
				*p1 = '\0';

				strncpy(pBlkBeDevArgs->bePath, p0, PATH_MAX);
				pBlkBeDevArgs->bePath[PATH_MAX] = '\0';
				p4 = pBlkBeDevArgs->bePath + strlen(pBlkBeDevArgs->bePath);
				if (p4 > p0)
				{
					//if (pathIsSep (*(p4 - 1))) zhe
					if (*(p4 - 1) == '/')
					{
						*(p4 - 1) = '\0';
					}
				}
				else
				{
					VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ERR,
							"%s: be=null!\n", __FUNCTION__);
					ret = -EINVAL;
					goto done;
				}

				if (strchr(pBlkBeDevArgs->bePath + 1, '/'))
				{
					pBlkBeDevArgs->isFile = true;
				}
				else
				{
					pBlkBeDevArgs->isFile = false;
				}
			}
			else if ((!strncmp (p0, "writethru", len)) &&
					(len== (sizeof ("writethru") - 1)))
			{
				pBlkBeDevArgs->writeThru = 1;
			}
			else if ((!strncmp (p0, "writeback", len)) &&
					(len == (sizeof ("writeback") - 1)))
			{
				pBlkBeDevArgs->writeThru = 0;
			}
			else if (!strncmp (p0, "ro", len))
			{
				pBlkBeDevArgs->ro = true;
			}
			else if (!strncmp(p0, "sectorsize", (sizeof ("sectorsize") - 1)))
			{
				/*
				 * sectorsize=<sector size>
				 * or
				 * sectorsize=<sector size>/<physical sector size>
				 */

				p0 += (sizeof ("sectorsize") - 1);

				if (*p0++ != '=')
				{
					VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ERR,
							"%s: incorrect format! \n", __FUNCTION__);
					ret = -EINVAL;
					goto done;
				}

				for (p2 = p0; p2 <= p1; p2++)
				{
					if ((*p2 == '/') || (p2 == p1))
					{
						*p2 = '\0';

						HEX_CODE_CHECK(p0, base);

						if (pBlkBeDevArgs->sectorSize == 0)
						{
							pVal32 = &pBlkBeDevArgs->sectorSize;;
						}
						else
						{
							pVal32 = &pBlkBeDevArgs->phySectorSize;
						}

						*pVal32 = (uint32_t)strtoul (p0, NULL, base);

						p0 = p2 + 1;
					}
				}
			}
			else if (!strncmp(p0, "range", (sizeof ("range") - 1)))
			{

				/* range=<start lba in file>/<sub file size> */

				p0 += (sizeof ("range") - 1);

				if (*p0++ != '=')
				{
					VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ERR,
							"%s: incorrect format! \n", __FUNCTION__);
					ret = -EINVAL;
					goto done;
				}

				for (p2 = p0; p2 <= p1; p2++)
				{
					if ((*p2 == '/') || (p2 == p1))
					{
						HEX_CODE_CHECK(p0, base);

						if (*p2 == '/')
						{
							pVal64 = &pBlkBeDevArgs->subFileLba;
						}
						else
						{
							pVal64 = &pBlkBeDevArgs->subFileSize;
						}

						*p2 = '\0';
						*pVal64 = strtoull (p0, NULL, base);

						p0 = p2 + 1;
					}
				}

				pBlkBeDevArgs->subFile = true;
			}
			else
			{
				VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ERR,
						"%s: unknown argument %s! \n",
						__FUNCTION__, p0);
				ret = -EINVAL;
				goto done;
			}
			p0 = p1 + 1;
		}
	}

	if (pBlkBeDevArgs->sectorSize != VIRTIO_BLK_SIZE)
	{
		VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ERR,
				"%s: sector size must equal to %d\n", __FUNCTION__, VIRTIO_BLK_SIZE);
		ret = -EINVAL;
		goto done;
	}

	if ((pBlkBeDevArgs->subFile) && (pBlkBeDevArgs->subFileSize == 0))
	{
		VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ERR,
				"%s: subFile size is not allowed equal to zero\n",
				__FUNCTION__);
		ret = -EINVAL;
		goto done;
	}

#ifdef VIRTIO_BLK_DEV_DBG_ON
	VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ARGS,
			"%s: back device arguments \n", __FUNCTION__);
	VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ARGS,
			"\t back device [%s] \n", pBlkBeDevArgs->bePath);

	if (pBlkBeDevArgs->ro)
	{
		VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ARGS,
				"\t back device is [read-only]\n");
	}

	if (pBlkBeDevArgs->isFile)
	{
		VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ARGS,
				"\t back device is [back file]\n");

		if (pBlkBeDevArgs->subFile)
		{
			VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ARGS,
					"\t     back device is [sub-file]\n" \
					"\t     sub-file start [0x%llx]\n" \
					"\t     sub-file size [0x%llx]\n", \
					pBlkBeDevArgs->subFileLba * pBlkBeDevArgs->sectorSize,
					pBlkBeDevArgs->subFileSize * pBlkBeDevArgs->sectorSize);
		}
	}
	else
	{
		VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ARGS,
				"\t back device is [disk partition]\n");
	}

	if (pBlkBeDevArgs->writeThru)
	{
		VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ARGS,
				"\t back device support [write-through]\n");
	}
	else
	{
		VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ARGS,
				"\t back device support [write-back]\n");
	}

	VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ARGS,
			"\t back device sector size [%d]\n",
			pBlkBeDevArgs->sectorSize);
#endif /* VIRTIO_BLK_DEV_DBG_ON */

done:
	return ret;
}

/*******************************************************************************
 *
 * virtioHostBlkCreate - create a virtio block device
 *
 * This routine creates a virtio block device backend driver to simuilate
 * a real storage device.
 *
 * RETURNS: 0, or negative value of errno number if any error is raised
 * in process of the block device creating.
 *
 * ERRNO: N/A
 */

static int virtioHostBlkCreate(struct virtioHostDev *pHostDev)
{
	struct virtioBlkHostDev *pBlkHostDev;
	struct virtioBlkBeDevArgs *pBeDevArgs;
	uint32_t len;
	char *pBuf;
	int ret;

	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO, "virtioHostBlkCreate start\n");

	if (!pHostDev) {
		VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ERR,
				"%s: pChannel is NULL!\n", __FUNCTION__);
		return -EINVAL;
	}

	/* the virtio channel number is always one */
	if (pHostDev->channelNum > 1) {
		VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ERR, "%s channel number is %d " \
				"only one channel is supported\n",
				__FUNCTION__, pHostDev->channelNum);
		return -EINVAL;
	}

	VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_INFO, "%s:\n"
			"  typeId = %d args %s channelNum = %d\n" \
			"    - channel ID = %d \n"  \
			"      hpaddr = 0x%lx \n" \
			"      gpaddr = 0x%lx \n" \
			"      cpaddr = 0x%lx \n" \
			"      size   = 0x%lx \n",
			__FUNCTION__,
			pHostDev->typeId, pHostDev->args, pHostDev->channelNum,
			pHostDev->channels[0].channelId,
			pHostDev->channels[0].pMap->entry->hpaddr,
			pHostDev->channels[0].pMap->entry->gpaddr,
			pHostDev->channels[0].pMap->entry->cpaddr,
			pHostDev->channels[0].pMap->entry->size);

	if (vBlkHostDrv.vBlkHostDevNum == VIRTIO_BLK_HOST_DEV_MAX) {
		VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ERR,
				"%s no more than %d block devices can be created\n",
				__FUNCTION__, VIRTIO_BLK_HOST_DEV_MAX);
		return -ENOENT;
	}

	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
			"virtioHostBlkCreate sizeof(struct virtioBlkHostDev) %ld bytes\n",
			sizeof(struct virtioBlkHostDev));

	//sizeof(struct virtioBlkHostDev) == 0x8311A0
	pBlkHostDev = calloc(1, sizeof(struct virtioBlkHostDev));
	if (!pBlkHostDev) {
		VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ERR,
				"%s: allocate memory failed for virtio block " \
				"host device failed! \n", __FUNCTION__);
		return -ENOMEM;
	}

	pBlkHostDev->fd = -1;

	/* allocate a buffer and copy the argument list to it */
	pBeDevArgs = &pBlkHostDev->beDevArgs;

	pBuf = pHostDev->args;
	pHostDev->args[PATH_MAX - 1] = '\0';
	len = strlen(pHostDev->args);

	ret = virtioHostBlkParseArgs(pBeDevArgs, pBuf, len);
	if (ret)
		goto exit;

	memcpy((void *)pBeDevArgs->channel, (void *)pHostDev->channels, sizeof(struct virtioChannel));

	ret = virtioHostBlkDevCreate(pBlkHostDev);
exit:
	if (ret) {
		free(pBlkHostDev);
		return ret;
	}

	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO, "virtioHostBlkCreate done\n");

	return 0;
}

/*******************************************************************************
 *
 * virtioHostBlkAbort - abort a request handling
 *
 * This routine is used to abort a request handling when a request is seen
 * with incorrect format, which will be abandoned.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void virtioHostBlkAbort(struct virtioHostQueue *pQueue, uint16_t idx)
{
	if (idx < pQueue->vRing.num) {
		(void)virtioHostQueueRelBuf(pQueue, idx, 1);
		(void)virtioHostQueueNotify(pQueue);
	}

	return;
}

/*******************************************************************************
 *
 * virtioHostBlkReqHandle - virtio block device handle task
 *
 * This routine is used to handle virtio block device read or write operations.
 *
 * RETURNS: 0, or -1 if the recieved operation request with a invalid format or
 * error meeting a failure in process of filesystem operation.
 *
 * ERRNO: N/A
 */

static void* virtioHostBlkReqHandle(void* arg)
{
	int n;
	uint16_t idx;
	struct virtioHost *vhost;
	struct virtioBlkHostCtx *pBlkHostCtx = (struct virtioBlkHostCtx*)arg;
	volatile struct virtioBlkReqHdr *pReqHdr;
	struct virtioBlkHostCtx *vBlkHostCtx = pBlkHostCtx;
	struct virtioBlkHostDev *vBlkHostDev;
	struct virtioBlkIoReq *pBlkReq;
	struct virtioHostBuf bufList[BLOCK_IO_REQ_MAX + 2];
	int rc;

	__virtio32 *ptype;
	__virtio64 *psector;
#if 0
	vBlkHostCtx = container_of(work, struct virtioBlkHostCtx, work);
	if (!vBlkHostCtx)
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
				"%s null vBlkHostCtx\n", __FUNCTION__);
#endif
	vhost = (struct virtioHost *)vBlkHostCtx;
	vBlkHostDev = (struct virtioBlkHostDev *)vBlkHostCtx;

        while(1) {                                                                   
                rc = sem_wait(&vBlkHostCtx->work_sem);
                if (rc < 0) {
                        VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
					   "failed to work_sem\n");
                        continue;
                }

		while (1) {
			n = virtioHostQueueGetBuf(vhost->pQueue, &idx, bufList,
					BLOCK_IO_REQ_MAX + 2);
			if (n == 0) {
				VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
						   "no new queue buffer\n");
				break;
			}

			if (n < 0) {
				VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
						   "failed to get buffer %d\n",
						   n);

				break;
			}

			if ((n < 2) || (n > BLOCK_IO_REQ_MAX + 2)) {
				VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
						   "invalid length of desc chain: %d, 2 to %d is valid\n",
						   n, BLOCK_IO_REQ_MAX + 2);

				virtioHostBlkAbort(vhost->pQueue, vhost->pQueue->availIdx);
				continue;
			}

			pReqHdr = (struct virtioBlkReqHdr *)bufList[0].buf;

#ifdef VIRTIO_BLK_PERF
			pReqHdr->time2 = ktime_get_real_fast_ns();
#endif

			ptype   = (__virtio32 *)((unsigned char*)pReqHdr + offsetof(struct virtioBlkReqHdr, type));
			psector = (__virtio64 *)((unsigned char*)pReqHdr + offsetof(struct virtioBlkReqHdr, sector));

			pReqHdr->type = host_virtio32_to_cpu(vhost, host_readl(ptype));
			pReqHdr->sector = host_virtio64_to_cpu(
				vhost,
				host_readq((uint64_t*)psector));

			if (bufList[0].flags & VRING_DESC_F_WRITE) {
				VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
						   "invalid header flag: "
						   "VRING_DESC_F_WRITE\n");

				virtioHostBlkAbort(vhost->pQueue, vhost->pQueue->availIdx);
				continue;
			}

			pBlkReq = &vBlkHostCtx->ioReqlist[idx % VIRTIO_BLK_QUEUE_MAX_NUM];
			pBlkReq->pReqHdr = (struct virtioBlkReqHdr *)pReqHdr;

			(void)memcpy((void*)pBlkReq->bufList, (void *)&bufList[1],
					sizeof(struct virtioHostBuf) * (uint32_t)(n - 2));

			pBlkReq->idx = idx;
			pBlkReq->blkHostCtx = vBlkHostCtx;
			pBlkReq->pStatus = bufList[n - 1].buf;
			pBlkReq->bufcnt = n - 2;

			pBlkReq->offset = pReqHdr->sector;

			VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
					"%s request type:%x sector:%lx\n",
					__FUNCTION__, pReqHdr->type, pReqHdr->sector);

			if (pReqHdr->type == VIRTIO_BLK_T_OUT) {
				if (vBlkHostDev->rdOnly) {
					VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
							"%s cannot write on read-only device\n",
							__FUNCTION__);
					virtioHostBlkDone(pBlkReq, vhost->pQueue, EROFS);
					continue;
				}

				pBlkReq->opType = BLK_OP_WRITE;
				virtioHostBlkSubmitBio(pBlkReq);
				continue;
			} else if (pReqHdr->type == VIRTIO_BLK_T_IN) {
				pBlkReq->opType = BLK_OP_READ;
				virtioHostBlkSubmitBio(pBlkReq);
				continue;
			} else if (pReqHdr->type == VIRTIO_BLK_T_FLUSH) {
				//pBlkReq->opType = BLK_OP_FLUSH;
				virtioHostBlkFlush(pBlkReq);
				continue;
			} else if (pReqHdr->type == VIRTIO_BLK_T_GET_ID) {
				virtioHostBlkGetId(pBlkReq);
				continue;
			} else if ((pReqHdr->type == VIRTIO_BLK_T_DISCARD) ||
					(pReqHdr->type == VIRTIO_BLK_T_WRITE_ZEROES)) {
				VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
						"%s not supported request type %x\n",
						__FUNCTION__, pReqHdr->type);

				virtioHostBlkDone(pBlkReq, vhost->pQueue, ENOTSUPP);
				continue;
			} else {
				VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ERR,
						"%s unknown request type %x\n",
						__FUNCTION__, pReqHdr->type);

				virtioHostBlkDone(pBlkReq, vhost->pQueue, ENOTSUPP);
				continue;
			}
		}
	}
	return arg;
}

/*******************************************************************************
 *
 * virtioHostBlkNotify - notify there is a new arrived io-request
 *
 * This routine is used to notify the handler that an new recieved io-request
 * in virtio queue.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void virtioHostBlkNotify(struct virtioHostQueue *pQueue)
{
	struct virtioBlkHostCtx *vBlkHostCtx;
	int rc;

	if (!pQueue) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"%s null pQueue\n", __FUNCTION__);
		return;
	}

	if (pQueue->vHost) {
		if ((pQueue->vHost->status & VIRTIO_CONFIG_S_DRIVER_OK) != 0) {
			vBlkHostCtx = (struct virtioBlkHostCtx *)pQueue->vHost;
                	rc = sem_post(&vBlkHostCtx->work_sem);
			if (rc)
				VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
						"%s failed to sem_post: %s\n", __FUNCTION__, strerror(errno));
		}
	}

	return;
}

/*******************************************************************************
 *
 * virtioHostBlkDone - mark the virtio blk request handled done.
 *
 * This routine is used to set the request handeled status accroding the
 * backend filesystem operation result before the descriptors released to
 * the used ring.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void virtioHostBlkDone(struct virtioBlkIoReq *pBlkReq,
		struct virtioHostQueue *pQueue, int err)
{
	if (err == ENOTSUPP) {
		VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ERR,
				"%s general block layer unsupported\n", __FUNCTION__);
		*pBlkReq->pStatus = VIRTIO_BLK_S_UNSUPP;
	} else if (err) {
		VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ERR,
				"%s general block layers error %d\n", __FUNCTION__, err);
		*pBlkReq->pStatus = VIRTIO_BLK_S_IOERR;
	} else {
		*pBlkReq->pStatus = VIRTIO_BLK_S_OK;
	}

#ifdef VIRTIO_BLK_PERF
	pBlkReq->pReqHdr->time5 = ktime_get_real_fast_ns();
#endif

	/* write 1 status byte */
	(void)virtioHostQueueRelBuf(pQueue, pBlkReq->idx, 1);
	(void)virtioHostQueueNotify(pQueue);

	return;
}

/*******************************************************************************
 *
 * virtioHostBlkReset - reset virtio block device
 *
 * This routine is used to reset the virtio block device. All the configuration
 * settings setted by customer driver will be cleared and all the backend
 * driver software flags are reset to initial status.
 *
 * RETURNS: 0, or -1 if failure raised in process of restarting the device.
 *
 * ERRNO: N/A
 */

static int virtioHostBlkReset(struct virtioHost *vHost)
{
	struct virtioBlkHostCtx *vBlkHostCtx;
	int err = 0;

	vBlkHostCtx = (struct virtioBlkHostCtx *)vHost;
	if (!vBlkHostCtx) {
		VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ERR,
				"%s: null vBlkHostCtx\n", __FUNCTION__);
		return -1;
	}

	return err;
}

/*******************************************************************************
 *
 * virtioHostBlkCfgRead - read virtio block specific configuration register
 *
 * This routine is used to read virtio block specific configuration register,
 * the value read out is stored in the request buffer.
 *
 * RETURN: 0, or -1 if the to be read register is non-existed.
 *
 * ERRNO: N/A
 */

static int virtioHostBlkCfgRead(struct virtioHost *vHost, uint64_t address,
		uint64_t size, uint32_t *pValue)
{
	struct virtioBlkHostCtx *vBlkHostCtx;
	uint8_t *cfgAddr;

	if (!vHost) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR, "%s null vHost\n",
				__FUNCTION__);
		return -EINVAL;
	}

	vBlkHostCtx = (struct virtioBlkHostCtx *)vHost;

	cfgAddr = (uint8_t *)&vBlkHostCtx->cfg + address;

	(void)memcpy((void *)pValue, (void *)cfgAddr, (size_t)size);

	return 0;
}

/*******************************************************************************
 *
 * virtioHostBlkCfgWrite - set virtio block specific configuration register
 *
 * This routine is used to set virtio block specific configuration register,
 * the setting value is stored in the request buffer.
 *
 * RETURN: 0, or -1 if the to be read register is non-existed.
 *
 * ERRNO: N/A
 */

static int virtioHostBlkCfgWrite(struct virtioHost *vHost, uint64_t address,
		uint64_t size, uint32_t value)
{
	struct virtioBlkHostCtx *pBlkHostCtx;
	struct virtioBlkHostDev *pBlkHostDev;
	uint8_t *cfgAddr;

	if (!vHost) {
		VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ERR,
				"%s: NULL pointer \n", __FUNCTION__);
		return -EINVAL;
	}

	pBlkHostDev = (struct virtioBlkHostDev *)vHost;
	pBlkHostCtx = (struct virtioBlkHostCtx *)pBlkHostDev;

	if ((address == offsetof(struct virtioBlkConfig, writeback)) &&	(size == 1)) {
		cfgAddr = (uint8_t *)&pBlkHostCtx->cfg + address;
		(void)memcpy((void *)cfgAddr, (void *)&value, (size_t)size);
		return 0;
	}

	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
			"failed to write to read-only register %ld\n",
			host_virtio64_to_cpu(vHost, address));

	return -EINVAL;
}

/*******************************************************************************
 *
 * virtioHostBlkShow - virtio block host device show
 *
 * This routine shows the virtio block host device setting and configurations.
 *
 * RETURN: 0 aleays.
 *
 * ERRNO: N/A
 */

static void virtioHostBlkShow(struct virtioHost * vHost, uint32_t indent)
{
	struct virtioBlkHostDev *vBlkHostDev;

	vBlkHostDev = (struct virtioBlkHostDev *)vHost;

	printf("%*sdriver [%s]\n", (indent + 1) * 3, "", VIRTIO_BLK_DRV_NAME);
	printf("%*scapacity [%lld]\n", (indent + 1) * 3, "", vBlkHostDev->capacity);
	printf("%*sblock size [%d]\n", (indent + 1) * 3, "", vBlkHostDev->blkSize);

	if (vritioHostHasFeature(vHost, VIRTIO_BLK_F_FLUSH) == VIRTIO_BLK_F_FLUSH)
		printf("%*swrite cache enabled\n", (indent + 1) * 3, "");
	else
		printf("%*swrite copy-back enabled\n", (indent + 1) * 3, "");

	printf("%*sbackend device :\n", (indent + 1) * 3, "");
	printf("%*spath [%s]\n", (indent + 2) * 3, "", vBlkHostDev->beDevArgs.bePath);
	if (vBlkHostDev->beDevArgs.ro)
		printf("%*sread-only permission \n", (indent + 2) * 3, "");
}

