/* virtioHostVSock.h - virtio host library header */

/*
 * Copyright (c) 2024 Wind River Systems, Inc.
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

#ifndef __VIRTIOHOSTVSOCK_H__
#define __VIRTIOHOSTVSOCK_H__

#include <pthread.h>
#include <string.h>
#include <semaphore.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/virtio_vsock.h>
#include "virtioHostLib.h"

#define CONNECT_STREAM_CHANNEL              "/tmp/host."
#define FORWARD_PATH                        "/tmp"
#define CONNECT_CMD_HEADER                  "CONNECT "
#define MAX_FORWARD_PATH_LENGTH             128U
#define VIRTIO_VSOCK_HOST_MAXSEGS           128U
#define VIRTIO_VSOCK_HOST_DEV_MAX           30U
#define WRITE_BUF_LENGTH                    (128 * 1024U) /* sock buffer cache */
#define VIRTIO_VSOCK_QUEUE_MAX              3U      /* vsock device queue number */
#define VIRTIO_VSOCK_QUEUE_MAX_NUM          1024U
#define VIRTIO_HOST_VSOCK_CID               2U

/* virtio host vsock device supports features */

#define VIRTIO_HOST_VSOCK_FEATURES      ((1UL << VIRTIO_F_VERSION_1) | \
                                        (1UL << VIRTIO_RING_F_INDIRECT_DESC) | \
                                        (1UL << VIRTIO_RING_F_EVENT_IDX))

//#define VIRTIO_HOST_VSOCK_FEATURES (1UL << VIRTIO_F_VERSION_1)
/* when target packet is G2G, set max packet length */
#define VIRTIO_VSOCK_HOST_PKT_LENGTH    (68 * 1024U)

#define VIRTIO_VSOCK_RX_QUEUE(vhost)    (&vhost->pQueue[VIRTIO_VSOCK_RXQ])
#define VIRTIO_VSOCK_TX_QUEUE(vhost)    (&vhost->pQueue[VIRTIO_VSOCK_TXQ])
#define VIRTIO_VSOCK_EVENT_QUEUE(vhost) (&vhost->pQueue[VIRTIO_VSOCK_EVENTQ])
#define VIRTIO_VSOCK_PQUEUE_RETRY   -255
#define VIRTIO_VSOCK_PQUEUE_ERROR   -1

static const char * const opnames[] = {
    [VIRTIO_VSOCK_OP_REQUEST] = "REQUEST",
    [VIRTIO_VSOCK_OP_RESPONSE] = "RESPONSE",
    [VIRTIO_VSOCK_OP_RST] = "RST",
    [VIRTIO_VSOCK_OP_SHUTDOWN] = "SHUTDOWN",
    [VIRTIO_VSOCK_OP_RW] = "RW",
    [VIRTIO_VSOCK_OP_CREDIT_UPDATE] = "CREDIT_UPDATE",
    [VIRTIO_VSOCK_OP_CREDIT_REQUEST] = "CREDIT_REQUEST"
};
#define DECODE_VIRTIO_OP(v) { printf("opcode is %s \n", opnames[v]);};

#define VIRTIO_VSOCK_DEV_DBG_ON
#ifdef VIRTIO_VSOCK_DEV_DBG_ON
#define VIRTIO_VSOCK_DEV_DBG_OFF             0x00000000U
#define VIRTIO_VSOCK_DEV_DBG_ISR             0x00000001U
#define VIRTIO_VSOCK_DEV_DBG_IOCTL           0x00000002U
#define VIRTIO_VSOCK_DEV_DBG_LOAD            0x00000004U
#define VIRTIO_VSOCK_DEV_DBG_UNLOAD          0x00000008U
#define VIRTIO_VSOCK_DEV_DBG_START           0x00000010U
#define VIRTIO_VSOCK_DEV_DBG_STOP            0x00000020U
#define VIRTIO_VSOCK_DEV_DBG_TX              0x00000040U
#define VIRTIO_VSOCK_DEV_DBG_RX              0x00000080U
#define VIRTIO_VSOCK_DEV_DBG_ERR             0x00000100U
#define VIRTIO_VSOCK_DEV_DBG_INFO            0x00000200U
#define VIRTIO_VSOCK_DEV_DBG_ALL             0xffffffffU

static uint32_t virtioVsockDevDbgMask = VIRTIO_VSOCK_DEV_DBG_ALL;
//#undef VIRTIO_VSOCK_DEV_DBG_MSG
#define VIRTIO_VSOCK_DEV_DBG_MSG(mask, fmt, ...)				\
    do {								\
        if ((virtioVsockDevDbgMask & (mask)) ||			\
            ((mask) == VIRTIO_VSOCK_DEV_DBG_ALL)) {		\
            printf("%d: %s() \n" fmt, __LINE__, __func__,	\
                   ##__VA_ARGS__);				\
        }							\
    }								\
while ((false))
#else
#define VIRTIO_VSOCK_DEV_DBG_MSG(...)
#endif  /* VIRTIO_VSOCK_DEV_DBG_ON */

#ifndef MAX_FD
#define MAX_FD(a, b) (((a) > (b)) ? (a) : (b))
#endif

/* vtsock addr type */
struct vtsock_addr {
    uint64_t cid;
    uint32_t port;
};

struct unix_connect_socket{
    int stream_fd;
};

struct vtsock_unix_socket {
    LIST_ENTRY(vtsock_unix_socket) list;
    LIST_ENTRY(vtsock_unix_socket) txq;
    LIST_ENTRY(vtsock_unix_socket) toclose;

    enum sock_state{
        SOCK_FREE = 0, /* Initial state */
        SOCK_CONNECTING,
        SOCK_CONNECT_WAITING,
        SOCK_CONNECTED,
        SOCK_CLOSING_TX,
        SOCK_CLOSING_RX,
        SOCK_UNKNOWN,
    } state;

    int fd;
    uint32_t sock_type;
    uint16_t port_generation;
    uint32_t buf_alloc;
    uint32_t fwd_cnt;
    uint32_t peer_buf_alloc;
    uint32_t rx_cnt;
    uint32_t peer_fwd_cnt;
    struct vtsock_addr local_addr;
    struct vtsock_addr peer_addr;
    bool credit_update_required;
};

LIST_HEAD(sock_list_head, vtsock_unix_socket);

/* Queue definitions */

enum vsock_queue
{
    VIRTIO_VSOCK_RXQ      = 0,
    VIRTIO_VSOCK_TXQ      = 1,
    VIRTIO_VSOCK_EVENTQ   = 2,
    VIRTIO_VSOCK_MAXQ     = 3
};

/*
 * virtio host vsock device structure
 */

struct virtioHostVsock
{
    struct virtioHost           vhost;
    struct virtio_vsock_config  config;
    struct virtioChannel *      channel;
    uint64_t                    features;   /* negotiated features */
    struct unix_connect_socket  ufds;
    pthread_t                   tTaskRx;
    pthread_t                   tTaskUnixSockRx;
    pthread_t                   tTaskUnixServer;
    sem_t                       rxTaskSem;
    sem_t                       unixSockTaskSem;
    pthread_mutex_t             rxMutex;
    pthread_mutex_t             txMutex;
    pthread_mutex_t             cacheMutex;
    void *                      txQBuf;
    int                         wakeupfd;
    int                         kickfd;
    char *                      pArgs;
    struct sock_list_head       inuseList, freeList;
    struct vtsock_unix_socket   sockCache[VIRTIO_VSOCK_QUEUE_MAX_NUM];
};

struct virtioHostVsockDevs
{
    struct virtioHostVsock *    virtioHostVsocks[VIRTIO_VSOCK_HOST_DEV_MAX];
    uint32_t                    vHostVsockDevNum;
    pthread_mutex_t             drvLock;
};

int virtioHostVsockUnixSockInit(struct virtioHostVsock *vSock);
int openForwardSocket(uint64_t cid, unsigned int port);
void buildRespWithSock(struct virtio_vsock_hdr *hdr, struct vtsock_unix_socket *sock, uint16_t opcode, \
                       uint32_t flags);
void buildRespWithoutSock(struct virtio_vsock_hdr *hdr, struct vtsock_addr *local_addr, \
                                 struct vtsock_addr *peer_addr, uint16_t opcode, uint16_t type);
int virtioHostVsockTx (struct virtio_vsock_hdr * pHdr, void * pBuf, uint32_t bufLen);
int virtioHostVsockXmit(struct virtioHostVsock *vSock, struct vtsock_unix_socket *sock);
int setupSockOpt(struct vtsock_unix_socket *s);
#endif


