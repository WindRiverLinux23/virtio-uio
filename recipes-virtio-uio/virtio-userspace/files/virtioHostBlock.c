/* virtioHostBlock.c - virtio block host device */

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

   This is the application that supply a virtio blk host driver, it provides
   the back-end storage media support for the reading and writing functions
   of virtio-block device on the host VM.
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
#include <syslog.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <openssl/md5.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/evp.h>
#endif
#include <linux/fs.h>
#include <linux/virtio_blk.h>
#include "virtioHostLib.h"

/* #define VIRTIO_BLK_PERF */
#ifdef VIRTIO_BLK_PERF
/* #include <time.h> */
#endif

#define VIRTIO_BLK_DEV_DBG_ON
#ifdef VIRTIO_BLK_DEV_DBG_ON

#define VIRTIO_BLK_DEV_DBG_OFF             0x00000000
#define VIRTIO_BLK_DEV_DBG_ISR             0x00000001
#define VIRTIO_BLK_DEV_DBG_ARGS            0x00000020
#define VIRTIO_BLK_DEV_DBG_ERR             0x00000100
#define VIRTIO_BLK_DEV_DBG_INFO            0x00000200
#define VIRTIO_BLK_DEV_DBG_ALL             0xffffffff

static uint32_t virtioBlkDevDbgMask = VIRTIO_BLK_DEV_DBG_ALL;

#undef VIRTIO_BLK_DEV_DBG
#undef VIRTIO_BLK_DEV_DBG_PRINTF

#ifdef VIRTIO_BLK_DEV_DBG_PRINTF
#define VIRTIO_BLK_DEV_DBG(mask, fmt, ...)				\
	do {								\
		if ((virtioBlkDevDbgMask & (mask)) ||			\
		    ((mask) == VIRTIO_BLK_DEV_DBG_ALL)) {		\
			printf("%d: %s() " fmt, __LINE__, __func__,	\
			       ##__VA_ARGS__);				\
		}							\
	}								\
while ((false))
#else
#define VIRTIO_BLK_DEV_DBG(mask, fmt, ...)				\
	do {								\
		if ((virtioBlkDevDbgMask & (mask)) ||			\
		    ((mask) == VIRTIO_BLK_DEV_DBG_ALL)) {		\
			syslog(LOG_ERR, "%d: %s() " fmt, __LINE__, __func__, \
				##__VA_ARGS__);				\
		}							\
	}								\
while ((false))
#endif

#else
#define VIRTIO_BLK_DEV_DBG(...)
#endif  /* VIRTIO_BLK_DEV_DBG_ON */


#define VIRTIO_BLK_DRV_NAME         "virtio-block-host"

#define VIRTIO_BLK_QUEUE_MAX     1     /* block device only has one queue */
#define VIRTIO_BLK_QUEUE_MAX_NUM 2048  /* max number of descriptors in a queue*/
#define VIRTIO_BLK_DISK_ID_BYTES 20

#define BLOCK_IO_REQ_MAX         256
#define VIRTIO_BLK_SIZE          512

#define VIRTIO_BLK_HOST_DEV_MAX  30

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
	struct timespec time1;
	struct timespec time2;
	struct timespec time3;
	struct timespec time4;
	struct timespec time5;
#endif
	uint8_t status;
} __attribute__((packed));

struct virtioBlkIoReq {                  /* virtio block I/O request */
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
		sem_t work_sem;
	} blkHostCtx;

	struct virtioBlkBeDevArgs {
		char bePath[PATH_MAX + 1];     /* backend path     */
		bool isFile;                   /* backend is file  */
		bool ro;                       /* read-only        */
		bool writeThru;                /* 1: write-though, 0: copy-back */
		bool canDiscard;               /* discard          */
		uint32_t sectorSize;           /* sector size      */
		uint32_t phySectorSize;        /* PHYS sector size */
		bool subFile;                  /* sub-file mode    */
		uint64_t subFileLba;           /* sub-file start   */
		uint64_t subFileSize;          /* sub-file size    */
		uint32_t maxDiscardSectors;
		uint32_t maxDiscardSeg;
		uint32_t discardSectorAlignment;
		struct virtioChannel channel[1];
	} beDevArgs;
	int fd;
	bool rdOnly;
	uint64_t capacity;
	uint32_t blkSize;
	uint32_t logBlkSize;
	uint32_t phyBlkSize;
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
static void* virtioHostBlkReqHandle(void *pBlkHostCtx);
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

/* Uncomment the following line to use in-memory disk */
/* #define VIRTIO_BLK_MEM_DISK */
#ifdef VIRTIO_BLK_MEM_DISK
#define VIRTIO_BLK_MEM_DISK_BLK_NUM 2*1024*64 /* 64MB */
char *memDisk = NULL;
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
	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
			   "enter\n");
	virtioHostDrvRegister((struct virtioHostDrvInfo *)&virtioBlkHostDrvInfo);

	pthread_mutex_init(&vBlkHostDrv.drvLock, NULL);

	vBlkHostDrv.mountTimeout = mountTimeout;
	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
			   "done\n");
}

void virtioHostBlkDrvRelease(void)
{
	uint32_t devNum;
	struct virtioBlkHostDev *pBlkHostDev;
	struct virtioBlkHostCtx *pBlkHostCtx;

	for (devNum = 0; devNum < vBlkHostDrv.vBlkHostDevNum; devNum++) {
		pBlkHostDev = vBlkHostDrv.vBlkHostDevList[devNum];
		pBlkHostCtx = (struct virtioBlkHostCtx *)pBlkHostDev;

#if 0 //TODO
		if (pBlkHostDev)
			if (pBlkHostDev->bdev)
				blkdev_put(pBlkHostDev->bdev, FMODE_READ | FMODE_WRITE);
#endif

		if (pBlkHostCtx && pBlkHostCtx->work_thread &&
		    pthread_cancel(pBlkHostCtx->work_thread) == 0) {
			pthread_join(pBlkHostCtx->work_thread, NULL);
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

int virtioHostBlkFlushOp(struct virtioBlkHostDev *pBlkHostDev)
{
	int ret = 0;

	if (fsync(pBlkHostDev->fd)) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"failed to fsync: %s\n", strerror(errno));
		ret = errno;
	}

	return ret;
}

/*******************************************************************************
 *
 * virtioHostBlkSubmitBio - virto block host submit block IO request to general
 * block layer
 *
 * This routine is used to write data to or read data from backend storage
 * media.
 *
 * RETURN: N/A
 *
 * ERROR: N/A
 */
static void virtioHostBlkSubmitBio(struct virtioBlkIoReq *pBlkReq)
{
	struct virtioBlkHostDev *pBlkHostDev;
	struct virtioHost *vhost;
	int ret = 0;
	int len, i;
	off_t offset;

	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
			   "start\n");
	pBlkHostDev = (struct virtioBlkHostDev *)pBlkReq->blkHostCtx;
	if (pBlkHostDev->beDevArgs.isFile) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"file-backed not supported\n");
		return;
	}

	vhost = (struct virtioHost *)pBlkReq->blkHostCtx;

#ifdef VIRTIO_BLK_PERF
	clock_gettime(CLOCK_MONOTONIC, &pReqHdr->time3);
#endif

	offset = pBlkReq->offset * VIRTIO_BLK_SIZE;

#ifdef VIRTIO_BLK_MEM_DISK
	for (i = 0; i < pBlkReq->bufcnt; i++) {
		if (pBlkReq->opType == BLK_OP_READ) {
			(void)memcpy(pBlkReq->bufList[i].buf,
					memDisk + (offset % (VIRTIO_BLK_MEM_DISK_BLK_NUM * pBlkHostDev->blkSize)),
					pBlkReq->bufList[i].len);
		} else if (pBlkReq->opType == BLK_OP_WRITE) {
			(void)memcpy(memDisk + (offset % (VIRTIO_BLK_MEM_DISK_BLK_NUM * pBlkHostDev->blkSize)),
					pBlkReq->bufList[i].buf, pBlkReq->bufList[i].len);
		}
		offset += pBlkReq->bufList[i].len;
	}
#else
	switch (pBlkReq->opType) {
		case BLK_OP_READ:
			for (i = 0; i < pBlkReq->bufcnt; i++) {
				len = pread(pBlkHostDev->fd,
						pBlkReq->bufList[i].buf,
						pBlkReq->bufList[i].len,
						offset);
				if (len < 0) {
					VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
							"failed to pread: %s\n", strerror(errno));
					ret = errno;
				}
				offset += pBlkReq->bufList[i].len;
			}
			break;
		case BLK_OP_WRITE:
			for (i = 0; i < pBlkReq->bufcnt; i++) {
				len = pwrite(pBlkHostDev->fd,
						pBlkReq->bufList[i].buf,
						pBlkReq->bufList[i].len,
						offset);
				if (len < 0) {
					VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
							"failed to pwrite: %s\n", strerror(errno));
					ret = errno;
				}
				offset += pBlkReq->bufList[i].len;
			}
			break;
		case BLK_OP_FLUSH:
			if (fsync(pBlkHostDev->fd)) {
				VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
						"failed to fsync: %s\n", strerror(errno));
				ret = errno;
			}
		case BLK_OP_DISCARD:
		default:
			ret = -ENOTSUP;
			break;
	}
#endif

#ifdef VIRTIO_BLK_PERF
	clock_gettime(CLOCK_MONOTONIC, &pReqHdr->time4);
#endif

#ifndef VIRTIO_BLK_MEM_DISK
	if ((vritioHostHasFeature(vhost, VIRTIO_BLK_F_FLUSH) == 0) &&
			(pBlkReq->opType == BLK_OP_WRITE)) {
		ret = virtioHostBlkFlushOp(pBlkHostDev);
	}
#endif

	virtioHostBlkDone(pBlkReq, vhost->pQueue, ret);

	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
			   "done\n");
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
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"failed to synchronize storage media\n");

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
	pBlkReq->len = MIN(size, pBlkReq->bufList[0].len);

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
	struct stat sbuf;
	long sz;
	long long b;
	off_t size, psectsz;
	off_t probe_arg[] = {0, 0};
	int ret = 0;

#ifdef VIRTIO_BLK_MEM_DISK
	pBlkHostDev->blkSize = VIRTIO_BLK_SIZE; //block size
	pBlkHostDev->logBlkSize = VIRTIO_BLK_SIZE; //block size
	pBlkHostDev->phyBlkSize = VIRTIO_BLK_SIZE; //block size
	pBlkHostDev->capacity = VIRTIO_BLK_MEM_DISK_BLK_NUM; //total number of blocks

	memDisk = calloc(VIRTIO_BLK_MEM_DISK_BLK_NUM, pBlkHostDev->blkSize);
	if (!memDisk) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"failed to alloc memDisk\n");
		return -ENOMEM;
	}
#else
	pBlkHostDev->fd = open(pBlkBeDevArgs->bePath, O_RDWR);
	if (pBlkHostDev->fd < 0) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"failed to open %s(%d)\n",
				pBlkBeDevArgs->bePath, pBlkHostDev->fd);
		return -EFAULT;
	}

	ret = fstat(pBlkHostDev->fd, &sbuf);
	if (ret < 0) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"failed to stat %s(%d)\n",
				pBlkBeDevArgs->bePath, ret);
	}

	if (S_ISBLK(sbuf.st_mode)) {
		/* get size */
		ret = ioctl(pBlkHostDev->fd, BLKGETSIZE, &sz);
		if (ret) {
			VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
					"failed to BLKGETSIZE(%d)\n", ret);
			VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
					"sbuf.st_size: 0x%lx\n", sbuf.st_size);
			size = sbuf.st_size;	/* set default value */
		} else {
			VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
					"BLKGETSIZE: 0x%lx\n", sz);
			size = sz * DEV_BSIZE;	/* DEV_BSIZE is 512 on Linux */
		}
		if (!ret || ret == EFBIG) {
			ret = ioctl(pBlkHostDev->fd, BLKGETSIZE64, &b);
			VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
					"BLKGETSIZE64: 0x%lx(%d)\n", b, ret);
			if (ret || b == 0 || b == sz)
				size = b * DEV_BSIZE;
			else
				size = b;
		}
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
				"block partition size is 0x%lx\n", size);

		/* get sector size, 512 on Linux */
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
				"block partition sector size is 0x%x\n", DEV_BSIZE);

		/* get physical sector size */
		ret = ioctl(pBlkHostDev->fd, BLKPBSZGET, &psectsz);
		if (ret) {
			VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
					"failed to BLKPBSZGET(%d)\n", ret);
			psectsz = DEV_BSIZE;  /* set default physical size */
		}
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
				"block partition physical sector size is 0x%lx\n",
				psectsz);

		if (pBlkBeDevArgs->canDiscard) {
			ret = ioctl(pBlkHostDev->fd, BLKDISCARD, probe_arg);
			if (ret) {
				VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
						"not support DISCARD\n");
				pBlkBeDevArgs->canDiscard = false;
			}
		}

		ret = ioctl(pBlkHostDev->fd, BLKSSZGET, &pBlkHostDev->logBlkSize);
		if (ret) {
			VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
					"failed to BLKSSZGET(%d)\n", ret);
			/* fall back to physical sector size */
			pBlkHostDev->logBlkSize = psectsz;
		}

		pBlkHostDev->phyBlkSize = psectsz;
	} else {
		/* TODO file-backed device needs more care here */
	}

	pBlkHostDev->blkSize = VIRTIO_BLK_SIZE;
	pBlkHostDev->capacity = size / VIRTIO_BLK_SIZE;

	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
			"fd:%d\nblkSize:0x%x\nlogBlkSize:0x%x\nphyBlkSize:0x%x\ncapacity:0x%lx\n",
			pBlkHostDev->fd,
			pBlkHostDev->blkSize,
			pBlkHostDev->logBlkSize,
			pBlkHostDev->phyBlkSize,
			pBlkHostDev->capacity);

	if (pBlkBeDevArgs->ro)
		pBlkHostDev->rdOnly = true;
#endif

err:
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
				"file-backed not supported\n");
	} else {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
				"creating disk-backed\n");
		ret = virtioHostBlkCreateWithBlk(pBlkHostDev);
	}

	if (ret) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"failed to create back-end device(%d)\n", ret);
		return ret;
	}

	/* The rest registers are all 0 */
	pBlkHostCtx->cfg.capacity = host_virtio64_to_cpu(&pBlkHostCtx->vhost,
			pBlkHostDev->capacity);
	pBlkHostCtx->cfg.seg_max  = host_virtio32_to_cpu(&pBlkHostCtx->vhost,
			BLOCK_IO_REQ_MAX);
	pBlkHostCtx->cfg.blk_size = host_virtio32_to_cpu(&pBlkHostCtx->vhost,
			pBlkHostDev->logBlkSize);
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
			"pBlkHostCtx->feature:0x%lx\n", pBlkHostCtx->feature);

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
	uint8_t digest[16];
	int ret;

	/*
	 * Create an identifier for the backing file. Use parts of the
	 * md5 sum of the filename
	 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
	EVP_DigestUpdate(mdctx, pBlkHostDev->beDevArgs.bePath, strlen(pBlkHostDev->beDevArgs.bePath));
	EVP_DigestFinal_ex(mdctx, digest, NULL);
	EVP_MD_CTX_free(mdctx);
#else
	MD5_CTX mdctx;
	MD5_Init(&mdctx);
	MD5_Update(&mdctx, pBlkHostDev->beDevArgs.bePath, strlen(pBlkHostDev->beDevArgs.bePath));
	MD5_Final(digest, &mdctx);
#endif
	ret = snprintf(pBlkHostDev->ident, VIRTIO_BLK_DISK_ID_BYTES + 1,
			"VIRT--%02X%02X-%02X%02X-%02X%02X",
			digest[0], digest[1], digest[2],
			digest[3], digest[4], digest[5]);
	if (ret > VIRTIO_BLK_DISK_ID_BYTES + 1 || ret < 0)
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"device name is invalid\n");
 
	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
			"ident:%s\n", pBlkHostDev->ident);
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
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"virtio block host context creating failed %d\n",
				ret);
		goto err;
	}

	pthread_mutex_lock(&vBlkHostDrv.drvLock);

	vBlkHostDrv.vBlkHostDevList[vBlkHostDrv.vBlkHostDevNum] = pBlkHostDev;

	devNum = vBlkHostDrv.vBlkHostDevNum++;

	pthread_mutex_unlock(&vBlkHostDrv.drvLock);

	ret = pthread_create(&pBlkHostCtx->work_thread, NULL, virtioHostBlkReqHandle, pBlkHostCtx);
	if (ret) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"failed to create virtio block host worker thread\n");
		goto err;
	}

	ret = sem_init(&pBlkHostCtx->work_sem, 0, 0);                        
	if (ret) {                                                        
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,                   
				"Failed to create block work thread 0x%ld sem(%d)\n", pBlkHostCtx->work_thread, ret);
		goto err;
	}

	return 0;

err:
	virtioHostBlkDrvRelease();
	return -1;
}

/*******************************************************************************
 *
 * dmStrtol - convert string to long int
 *
 * This routine is a wrapper of strtol.
 *
 * RETURNS: 0 on success or -1 according to errno
 *
 * ERRNO: N/A
 */

int dmStrtol(const char *s, char **end, unsigned int base, long *val)
{
	if (!s)
		return -1;

	*val = strtol(s, end, base);
	if ((end && *end == s) || errno == ERANGE)
		return -1;
	return 0;
}

/*******************************************************************************
 *
 * dmStrtoi - convert string to int
 *
 * This routine is a wrapper of strtoi.
 *
 * RETURNS: 0 on success or -1 according to errno
 *
 * ERRNO: N/A
 */
int dmStrtoi(const char *s, char **end, unsigned int base, int *val)
{
	long l_val;
	int ret;

	l_val = 0;
	ret = dmStrtol(s, end, base, &l_val);
	if (ret == 0)
		*val = (int)l_val;
	return ret;
}

/*******************************************************************************
 *
 * dmStrtoul - convert string to unsigned long
 *
 * This routine is a wrapper of strtoul.
 *
 * RETURNS: 0 on success or -1 according to errno
 *
 * ERRNO: N/A
 */

int dmStrtoul(const char *s, char **end, unsigned int base, unsigned long *val)
{
	if (!s)
		return -1;

	*val = strtoul(s, end, base);
	if ((end && *end == s) || errno == ERANGE)
		return -1;
	return 0;
}

/*******************************************************************************
 *
 * dmStrtoui - convert string to unsigned int
 *
 * This routine is a wrapper of strtoui.
 *
 * RETURNS: 0 on success or -1 according to errno
 *
 * ERRNO: N/A
 */

int dmStrtoui(const char *s, char **end, unsigned int base, unsigned int *val)
{
	unsigned long l_val;
	int ret;

	l_val = 0;
	ret = dmStrtoul(s, end, base, &l_val);
	if (ret == 0)
		*val = (unsigned int)l_val;
	return ret;
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

static int virtioHostBlkParseArgs(struct virtioBlkBeDevArgs *pBlkBeDevArgs, char *pArgs)
{
	char *nopt, *xopts, *cp;
	int ret = 0;

	pBlkBeDevArgs->isFile = false;
	pBlkBeDevArgs->writeThru = false;
	pBlkBeDevArgs->sectorSize = VIRTIO_BLK_SIZE;

	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
			"virtioHostBlkParseArgs %s\n", pArgs);

	nopt = xopts = strdup(pArgs);
	if (!nopt) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"failed to strdup pArgs\n");
		return -EINVAL;
	}

	while (xopts != NULL) {
		cp = strsep(&xopts, ",");
		if (cp == nopt) { /* file or device pathname */
			if (!strncmp(cp, "be=", 3))
				strncpy(pBlkBeDevArgs->bePath, nopt + 3, PATH_MAX);
			else
				VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
						"device option must start with be=\n");
			continue;
		} else if (!strcmp(cp, "writeback"))
			pBlkBeDevArgs->writeThru = false;
		else if (!strcmp(cp, "writethru"))
			pBlkBeDevArgs->writeThru = true;
		else if (!strcmp(cp, "ro"))
			pBlkBeDevArgs->ro = true;
		else if (!strncmp(cp, "discard", strlen("discard"))) {
			strsep(&cp, "=");
			if (cp != NULL) {
				if (!(!dmStrtoi(cp, &cp, 10, &pBlkBeDevArgs->maxDiscardSectors) &&
					*cp == ':' &&
					!dmStrtoi(cp + 1, &cp, 10, &pBlkBeDevArgs->maxDiscardSeg) &&
					*cp == ':' &&
					!dmStrtoi(cp + 1, &cp, 10, &pBlkBeDevArgs->discardSectorAlignment)))
					goto err;
			}
			pBlkBeDevArgs->canDiscard = true;
		} else if (!strncmp(cp, "sectorsize", strlen("sectorsize"))) {
			/*
			 *  sectorsize=<sector size>
			 * or
			 *  sectorsize=<sector size>/<physical sector size>
			 */
			if (strsep(&cp, "=") && !dmStrtoi(cp, &cp, 10, &pBlkBeDevArgs->sectorSize)) {
				pBlkBeDevArgs->phySectorSize = pBlkBeDevArgs->sectorSize;
				if (*cp == '/' &&
					dmStrtoi(cp + 1, &cp, 10, &pBlkBeDevArgs->phySectorSize) < 0)
					goto err;
			} else {
				goto err;
			}
		} else if (!strncmp(cp, "range", strlen("range"))) {
			/* range=<start lba>/<subfile size> */
			if (strsep(&cp, "=") &&
				!dmStrtol(cp, &cp, 10, &pBlkBeDevArgs->subFileLba) &&
				*cp == '/' &&
				!dmStrtol(cp + 1, &cp, 10, &pBlkBeDevArgs->subFileSize))
				pBlkBeDevArgs->subFile = true;
			else
				goto err;
		} else {
			VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
					"invalid device option(%s)\n", cp);
			goto err;
		}
	}

	if ((pBlkBeDevArgs->subFile) && (pBlkBeDevArgs->subFileSize == 0)) {
		VIRTIO_BLK_DEV_DBG (VIRTIO_BLK_DEV_DBG_ERR,
				"subFile size is not allowed equal to zero\n");
		ret = -EINVAL;
		goto err;
	}

#ifdef VIRTIO_BLK_DEV_DBG_ON
	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ARGS, "back device arguments\n");
	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ARGS,
			"\t back device [%s]\n", pBlkBeDevArgs->bePath);

	if (pBlkBeDevArgs->ro) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ARGS,
				"\t back device is [read-only]\n");
	}

	if (pBlkBeDevArgs->isFile) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ARGS,
				"\t back device is [back file]\n");

		if (pBlkBeDevArgs->subFile) {
			VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ARGS,
					"\t     back device is [sub-file]\n" \
					"\t     sub-file start [0x%lx]\n" \
					"\t     sub-file size [0x%lx]\n", \
					pBlkBeDevArgs->subFileLba * pBlkBeDevArgs->sectorSize,
					pBlkBeDevArgs->subFileSize * pBlkBeDevArgs->sectorSize);
		}
	} else {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ARGS,
				"\t back device is [disk partition]\n");
	}

	if (pBlkBeDevArgs->writeThru) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ARGS,
				"\t back device support [write-through]\n");
	} else {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ARGS,
				"\t back device support [write-back]\n");
	}

	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ARGS,
			"\t back device logical sector size [%d]\n",
			pBlkBeDevArgs->sectorSize);

	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ARGS,
			"\t back device physical sector size [%d]\n",
			pBlkBeDevArgs->phySectorSize);
#endif /* VIRTIO_BLK_DEV_DBG_ON */

err:
	if (nopt)
		free(nopt);

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
	char *pBuf;
	int ret;

	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO, "virtioHostBlkCreate start\n");

	if (!pHostDev) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"pChannel is NULL!\n");
		return -EINVAL;
	}

	/* the virtio channel number is always one */
	if (pHostDev->channelNum > 1) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR, "channel number is %d " \
				"only one channel is supported\n", pHostDev->channelNum);
		return -EINVAL;
	}

	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO, "\n"
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

	if (vBlkHostDrv.vBlkHostDevNum == VIRTIO_BLK_HOST_DEV_MAX) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"no more than %d block devices can be created\n",
				VIRTIO_BLK_HOST_DEV_MAX);
		return -ENOENT;
	}

	VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_INFO,
			"virtioHostBlkCreate sizeof(struct virtioBlkHostDev) %ld bytes\n",
			sizeof(struct virtioBlkHostDev));

	pBlkHostDev = calloc(1, sizeof(struct virtioBlkHostDev));
	if (!pBlkHostDev) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"allocate memory failed for virtio block " \
				"host device failed!\n");
		return -ENOMEM;
	}

	pBlkHostDev->fd = -1;

	/* allocate a buffer and copy the argument list to it */
	pBeDevArgs = &pBlkHostDev->beDevArgs;

	pBuf = pHostDev->args;
	pHostDev->args[PATH_MAX - 1] = '\0';

	ret = virtioHostBlkParseArgs(pBeDevArgs, pBuf);
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

static void* virtioHostBlkReqHandle(void *pBlkHostCtx)
{
	int n;
	uint16_t idx;
	struct virtioHost *vhost;
	struct virtioBlkReqHdr *pReqHdr;
	struct virtioBlkHostCtx *vBlkHostCtx = pBlkHostCtx;
	struct virtioBlkHostDev *vBlkHostDev;
	struct virtioBlkIoReq *pBlkReq;
	struct virtioHostBuf bufList[BLOCK_IO_REQ_MAX + 2];
	int rc;

	vhost = (struct virtioHost *)vBlkHostCtx;
	vBlkHostDev = (struct virtioBlkHostDev *)vBlkHostCtx;

        while(1) {                                                                   
                rc = sem_wait(&vBlkHostCtx->work_sem);
                if (rc < 0) {
			VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
					"failed to sem_wait work_sem: %s\n", strerror(errno));
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
						"failed to get buffer(%d)\n", n);
				break;
			}

			if ((n < 2) || (n > BLOCK_IO_REQ_MAX + 2)) {
				VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
						"invalid length of desc chain: %d, while 2 to %d is valid\n",
						n, BLOCK_IO_REQ_MAX + 2);

				virtioHostBlkAbort(vhost->pQueue, vhost->pQueue->availIdx);
				continue;
			}

			pReqHdr = (struct virtioBlkReqHdr *)bufList[0].buf;

#ifdef VIRTIO_BLK_PERF
			clock_gettime(CLOCK_MONOTONIC, &pReqHdr->time2);
#endif

			pReqHdr->type = host_virtio32_to_cpu(vhost, host_readl(&pReqHdr->type));
			pReqHdr->sector = host_virtio64_to_cpu(vhost, host_readq(&pReqHdr->sector));

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
					"request type:%x sector:%lx\n",
					pReqHdr->type, pReqHdr->sector);

			if (pReqHdr->type == VIRTIO_BLK_T_OUT) {
				if (vBlkHostDev->rdOnly) {
					VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
							"cannot write on read-only device\n");
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
				//TODO pBlkReq->opType = BLK_OP_FLUSH;
				virtioHostBlkFlush(pBlkReq);
				continue;
			} else if (pReqHdr->type == VIRTIO_BLK_T_GET_ID) {
				virtioHostBlkGetId(pBlkReq);
				continue;
			} else if ((pReqHdr->type == VIRTIO_BLK_T_DISCARD) ||
					(pReqHdr->type == VIRTIO_BLK_T_WRITE_ZEROES)) {
				VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
						"not supported request type %x\n",
						pReqHdr->type);

				virtioHostBlkDone(pBlkReq, vhost->pQueue, ENOTSUP);
				continue;
			} else {
				VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
						"unknown request type %x\n",
						pReqHdr->type);

				virtioHostBlkDone(pBlkReq, vhost->pQueue, ENOTSUP);
				continue;
			}
		}
	}
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
	int ret;

	if (!pQueue) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR, "null pQueue\n");
		return;
	}

	if (pQueue->vHost) {
		if ((pQueue->vHost->status & VIRTIO_CONFIG_S_DRIVER_OK) != 0) {
			vBlkHostCtx = (struct virtioBlkHostCtx *)pQueue->vHost;
                	ret = sem_post(&vBlkHostCtx->work_sem);
			if (ret)
				VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
						"failed to sem_post work_sem: %s\n", strerror(errno));
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
	if (err == ENOTSUP) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"general block layer unsupported\n");
		*pBlkReq->pStatus = VIRTIO_BLK_S_UNSUPP;
	} else if (err) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"general block layers error %d\n", err);
		*pBlkReq->pStatus = VIRTIO_BLK_S_IOERR;
	} else {
		*pBlkReq->pStatus = VIRTIO_BLK_S_OK;
	}

#ifdef VIRTIO_BLK_PERF
	clock_gettime(CLOCK_MONOTONIC, &pReqHdr->time5);
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

	vBlkHostCtx = (struct virtioBlkHostCtx *)vHost;
	if (!vBlkHostCtx) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR,
				"null vBlkHostCtx\n");
		return -1;
	}

	return 0;
}

/*******************************************************************************
 *
 * virtioHostBlkCfgRead - read virtio block specific configuration register
 *
 * This routine is used to read virtio block specific configuration register,
 * the value read out is stored in the request buffer.
 *
 * RETURN: 0, or errno if the to be read register is non-existed.
 *
 * ERRNO: N/A
 */

static int virtioHostBlkCfgRead(struct virtioHost *vHost, uint64_t address,
		uint64_t size, uint32_t *pValue)
{
	struct virtioBlkHostCtx *vBlkHostCtx;
	uint8_t *cfgAddr;

	if (!vHost) {
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR, "null vHost\n");
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
 * RETURN: 0, or errno if the to be read register is non-existed.
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
		VIRTIO_BLK_DEV_DBG(VIRTIO_BLK_DEV_DBG_ERR, "null vHost\n");
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
	printf("%*scapacity [%lu]\n", (indent + 1) * 3, "", vBlkHostDev->capacity);
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

