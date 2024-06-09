/* virtioHostVsock.c - virtio socket host device driver process*/

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

/*
   DESCRIPTION

   This is the application that supply a virtio socket host driver, it provides
   the back-end driver support for the sending and receiving functions of
   virtio-sock device on the host VM.
 */

#include "virtioHostVSock.h"

/* global vsock device(s) data structure */
struct virtioHostVsockDevs vHostVsockDevs;


/* hook functions for virtio handler */
static int virtioHostVsockReset (struct virtioHost *);
static void virtioHostVsockIntHandle (struct virtioHostQueue *);
static int virtioHostVsockCfgRead (struct virtioHost *, uint64_t, uint64_t size, uint32_t *);
static int virtioHostVsockSetStatus (struct virtioHost * vHost, uint32_t status);
static void virtioHostVsockShow (struct virtioHost *, uint32_t);
static int virtioHostVsockCreate (struct virtioHostDev *);

struct virtioHostOps virtioHostVsockOps =
{
    .reset      = virtioHostVsockReset,
    .kick       = virtioHostVsockIntHandle,
    .reqRead    = virtioHostVsockCfgRead,
    .setStatus  = virtioHostVsockSetStatus,
    .show       = virtioHostVsockShow,
};

/* device information */
static struct virtioHostDrvInfo virtioHostVsockDrvInfo =
{
    .typeId = VIRTIO_TYPE_VSOCK,
    .flags = VIRTIO_HOST_FLAG_THREAD,
    .create = virtioHostVsockCreate,
};

/*******************************************************************************
 *
 *  buildBasicRespHeader - Build vsock virtio header
 *
 *
 *  RETURN N/A
 *
 *  ERRNO: N/A
 */

static void buildBasicRespHeader(struct virtio_vsock_hdr *hdr, \
                                 struct vtsock_addr *local_addr, \
                                 struct vtsock_addr *peer_addr, \
                                 uint16_t opcode,\
                                 uint16_t type, \
                                 uint32_t flags, \
                                 uint32_t buf_alloc,\
                                 uint32_t fwd_cnt) {
    if (!hdr || !local_addr || !peer_addr)
        return;

    memset(hdr, 0x0, sizeof(struct virtio_vsock_hdr));
    hdr->buf_alloc = buf_alloc;
    hdr->fwd_cnt = fwd_cnt;
    hdr->len = 0;//no more data to send
    hdr->src_cid = VIRTIO_HOST_VSOCK_CID;
    hdr->src_port = local_addr->port;
    hdr->dst_cid = peer_addr->cid;
    hdr->dst_port = peer_addr->port;
    hdr->type = type;
    hdr->flags = flags;
    hdr->op = opcode;

    //dump_frame("sendRESP:", (unsigned char *)hdr, sizeof(struct virtio_vsock_hdr));
}

/*******************************************************************************
 *
 *  buildRespWithSock - Build vsock virtio header if sock already created
 *
 *
 *  RETURN N/A
 *
 *  ERRNO: N/A
 */

void buildRespWithSock(struct virtio_vsock_hdr *hdr, struct vtsock_unix_socket *sock, uint16_t opcode, uint32_t flags)
{
    if (!sock)
        return;
    buildBasicRespHeader(hdr, &sock->local_addr, \
                         &sock->peer_addr, opcode, sock->sock_type, \
                         flags, sock->buf_alloc, sock->fwd_cnt);
}

/*******************************************************************************
 *
 *  buildRespWithoutSock - Build vsock virtio header if sock not creat yet.
 *
 *
 *  RETURN N/A
 *
 *  ERRNO: N/A
 */
void buildRespWithoutSock(struct virtio_vsock_hdr *hdr, struct vtsock_addr *local_addr, \
                                 struct vtsock_addr *peer_addr, uint16_t opcode, uint16_t type)
{
    buildBasicRespHeader(hdr, local_addr, peer_addr, opcode, type, 0, 0, 0);
}

/*******************************************************************************
 *
 *  kickSelect - Break select loop.
 *
 *
 *  RETURN N/A
 *
 *  ERRNO: N/A
 */
static void kickSelect(struct virtioHostVsock * vSock)
{
    char c = '0';

    if (vSock) {
        if (write(vSock->kickfd, &c, 1) == 1)
            sem_post(&vSock->unixSockTaskSem);
        else
            VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR, "Failed to kick the select()\n");
    }
}

/*******************************************************************************
 *
 *  vsockRxOpResp - Process response from guest side
 *
 *
 *  RETURN 0, or -1 if error happens.
 *
 *  ERRNO: N/A
 */

static int vsockRxOpResp(struct virtioHostVsock * vsockDev, struct vtsock_unix_socket *sock)
{
    char respmsg[32] = "\0";

    if (!sock) {
        VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR,"taskVirtioVSockRx: Guest want to resp to a non-exsits socket\n");
        return -1;
    } else {
        memset(respmsg, '\0', sizeof(respmsg));
        pthread_mutex_lock(&vsockDev->cacheMutex);
        if (sock->state == SOCK_CONNECT_WAITING) {
            sock->state = SOCK_CONNECTED;
            snprintf(respmsg, sizeof(respmsg), "OK %d\n",sock->peer_addr.port);
            if (write(sock->fd, (void *)respmsg,  strlen(respmsg)) < 0)
                perror("write():");

            kickSelect(vsockDev); //kick select() to break
        }
        pthread_mutex_unlock(&vsockDev->cacheMutex);
    }

    return 0;
}

/*******************************************************************************
 *
 *  vsockRxOpReq - Process request from guest side
 *
 *
 *  RETURN 0, or -1 if error happens.
 *
 *  ERRNO: N/A
 */

static int vsockRxOpReq(struct virtioHostVsock * vsockDev, struct vtsock_unix_socket *sock, struct virtio_vsock_hdr *hdr)
{
    int fd, ret, backup;
    struct vtsock_unix_socket *s = NULL;
    struct vtsock_addr local, peer;
    struct virtio_vsock_hdr resp;

    if (!hdr)
        return -1;

    local.cid = hdr->dst_cid;
    local.port = hdr->dst_port;
    peer.cid = hdr->src_cid;
    peer.port = hdr->src_port;

    if (sock) {
        VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR,"peer connecting to a exsits socket, reset it \n");
        buildRespWithSock(&resp, sock, VIRTIO_VSOCK_OP_RST, 0);
        if (virtioHostVsockTx(&resp, NULL, 0) == 0) {
            pthread_mutex_lock(&vsockDev->cacheMutex);
            sock->state = SOCK_UNKNOWN;
            pthread_mutex_unlock(&vsockDev->cacheMutex);
            kickSelect(vsockDev); //kick select() to break
        }
        return -1;
    }

    fd = openForwardSocket(vsockDev->config.guest_cid, local.port);
    if (fd < 0) {
        VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR,"vsockRxOpReq: host dont have a socket in listen status port=%d\n", local.port);
        buildRespWithoutSock(&resp, &local, &peer, VIRTIO_VSOCK_OP_RST, 0);
        return virtioHostVsockTx(&resp, NULL, 0);
    }

    pthread_mutex_lock(&vsockDev->cacheMutex);
    s = LIST_FIRST(&vsockDev->freeList);
    if (!s) {
        VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR,"vsockRxOpReq: host dont have socket in free list \n");
        close(fd);
        pthread_mutex_unlock(&vsockDev->cacheMutex);
        return -1;
    }

    LIST_REMOVE(s, list);

    /* backup to keep port_generation still increase */
    backup = s->port_generation;
    memset(s, 0x0, sizeof(struct vtsock_unix_socket));
    s->port_generation = backup;

    /* setup the peer info */
    s->peer_buf_alloc = hdr->buf_alloc;
    s->peer_fwd_cnt = hdr->fwd_cnt;
    s->peer_addr.cid = peer.cid;
    s->peer_addr.port = peer.port;
    s->sock_type = hdr->type;

    /* setup the local info */
    s->local_addr.cid = local.cid;
    s->local_addr.port = local.port;
    s->buf_alloc = hdr->buf_alloc;
    s->fd = fd;
    s->state = SOCK_CONNECTED;

    setupSockOpt(s);
    LIST_INSERT_HEAD(&vsockDev->inuseList, s, list);
    buildRespWithSock(&resp, s, VIRTIO_VSOCK_OP_RESPONSE, 0);
    ret = virtioHostVsockTx(&resp, NULL, 0);
    pthread_mutex_unlock(&vsockDev->cacheMutex);

    kickSelect(vsockDev);

    return ret;
}

/*******************************************************************************
 *
 *  unixSocketRxHandler - Handle vsock guest to host direction's protocol
 *
 *
 *  RETURN 0, or -1 if error happens.
 *
 *  ERRNO: N/A
 */
static int unixSocketRxHandler(struct virtioHostVsock * vsockDev, \
                                  struct virtio_vsock_hdr *hdr, \
                                  struct iovec *iov, int iovnum, \
                                  struct vtsock_unix_socket *sock)
{
    struct virtio_vsock_hdr resp;
    int nwrite = 0;

    if (!hdr || !vsockDev || !iov)
        return -1;

    //DECODE_VIRTIO_OP(hdr->op);
    switch(hdr->op){
    case VIRTIO_VSOCK_OP_REQUEST:
        vsockRxOpReq(vsockDev, sock, hdr);
        break;
    case VIRTIO_VSOCK_OP_RESPONSE:
        vsockRxOpResp(vsockDev, sock);
        break;
    case VIRTIO_VSOCK_OP_RW:
        if (!sock || sock->state != SOCK_CONNECTED) {
            goto do_nosock_reset;
        } else {
            iov[0].iov_base = iov[0].iov_base + sizeof(struct virtio_vsock_hdr);
            iov[0].iov_len = iov[0].iov_len - sizeof(struct virtio_vsock_hdr);
            nwrite = writev(sock->fd, iov, iovnum);
            if (nwrite <= 0) {
                if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
                    perror("writev: ");
                    sock->state = SOCK_CLOSING_TX;
                    kickSelect(vsockDev);
                }
                return -1;
            }

            sock->fwd_cnt += nwrite;

            // tell the guest our fwd_cnt via credit frame.
            buildRespWithSock(&resp, sock, VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0);

            //if send credit info failed, tx thread will try again.
            if (virtioHostVsockTx(&resp, NULL, 0) != 0) {
                sock->credit_update_required = true;
                kickSelect(vsockDev); //kick select() to break
                return -1;
            } else {
                sock->credit_update_required = false;
            }
        }
        break;
    case VIRTIO_VSOCK_OP_RST:
        /* no response */
        if (sock) {
            sock->state = SOCK_CLOSING_RX;
            kickSelect(vsockDev); //kick select() to break
        }

        break;
    case VIRTIO_VSOCK_OP_SHUTDOWN:
        if (!sock)
            goto do_nosock_reset;

        sock->state = SOCK_CLOSING_RX;
        kickSelect(vsockDev); //kick select() to break
        break;
    case VIRTIO_VSOCK_OP_CREDIT_UPDATE:
        if (!sock || sock->state != SOCK_CONNECTED)
            goto do_nosock_reset;
        // We have already updated the credit when rx the data
        // so nothing to do.
        break;
    case VIRTIO_VSOCK_OP_CREDIT_REQUEST:
        if (!sock || sock->state != SOCK_CONNECTED)
            goto do_nosock_reset;

        buildRespWithSock(&resp, sock, VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0);
        //if send credit info failed, tx thread will try again.
        if (virtioHostVsockTx(&resp, NULL, 0) != 0)
            sock->credit_update_required = true;
        break;
    default:
        break;
    }

    return 0;

do_nosock_reset:
    /* it is a non-connection sock */
    buildRespWithoutSock(&resp, &(struct vtsock_addr){.cid = hdr->dst_cid, .port = hdr->dst_port}, \
                         &(struct vtsock_addr){.cid = hdr->src_cid, .port = hdr->src_port}, \
                         VIRTIO_VSOCK_OP_RST, 0);

    return 0;
}

/******************************************************************************
*
* virtioHostVsockDevFind - find virtio vsock device from global structure
*
* This routine finds virtio vsock device from global structure.
*
* RETURNS: virtio vsock device structure pointer, or NULL if no matched virtio
* vsock device is found.
*
* ERRNO: N/A
*/

static struct virtioHostVsock * virtioHostVsockDevFind(uint64_t cid)
{
    uint32_t i;

    for (i = 0; i < vHostVsockDevs.vHostVsockDevNum; i++) {
        if (vHostVsockDevs.virtioHostVsocks[i] != NULL) {
            if (cid == vHostVsockDevs.virtioHostVsocks[i]->config.guest_cid) {
                return vHostVsockDevs.virtioHostVsocks[i];
            }
        }
    }

    VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                              "%s : not find virtio vsock device!\n",
                              __func__);
    return NULL;
}

/******************************************************************************
*
* virtioHostVsockTx - fill data to receiving virtual queue
*
* This routine fills data to virtio vsock receiving virtual queue buffer.
*
* RETURNS: 0, or -1 if any error is raised in process of handling data in
* receivig virtual queue.
*
* ERRNO: N/A
*/

int virtioHostVsockTx(struct virtio_vsock_hdr *pHdr,void *pBuf,uint32_t bufLen)
{
    struct virtioHostVsock *    pHostVsockDev = NULL;
    struct virtioHost *         vHost;
    struct virtioHostBuf        hostBuf[VIRTIO_VSOCK_QUEUE_MAX_NUM];
    int                         n;
    uint16_t                    idx;
    struct virtioHostQueue *    pRxQueue;
    bool                        needNotify = false;
    int                         i;
    uint32_t                    hdrOffset;
    uint32_t                    bufOffset;
    uint32_t                    releaseLen = 0U;
    uint32_t                    payloadLen = 0U;
    uint32_t                    totalLen = 0U;
    uint32_t                    sndOffset = 0U;
    uint32_t                    hdrLen;
    bool                        needGetbuf;

    if (pHdr == NULL) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                  "%s : invalid vsock header!\n", __func__);
        return -1;
    }

    pHostVsockDev = virtioHostVsockDevFind (pHdr->dst_cid);
    if (pHostVsockDev == NULL) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                  "%s : input invalid! dst_cid=%lld\n", __func__, pHdr->dst_cid);
        return -1;
    }

    vHost = (struct virtioHost *) pHostVsockDev;
    pRxQueue = VIRTIO_VSOCK_RX_QUEUE(vHost);

    pthread_mutex_lock(&pHostVsockDev->txMutex);
    if (bufLen > VIRTIO_VSOCK_HOST_PKT_LENGTH) {
        (void) virtioHostQueueIntrEnable (pRxQueue);
        (void) pthread_mutex_unlock (&pHostVsockDev->txMutex);
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                  "%s : Packet too large! bufLen = %d\n",
                                  __func__, bufLen);
        return -1;
    }

    do {
        n = virtioHostQueueGetBuf (pRxQueue, &idx, hostBuf, VIRTIO_VSOCK_QUEUE_MAX_NUM);
        if (n < 0) {
            if ((n != (-EINVAL)) && (n != (-EACCES))) {
                (void) virtioHostQueueRetBuf (pRxQueue);
            }
            (void) virtioHostQueueIntrEnable (pRxQueue);
            (void) pthread_mutex_unlock (&pHostVsockDev->txMutex);

            VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                      "%s: something wrong with pRxQueue \n",
                                      __func__);
            return -1;
        } else if (n == 0) {
            (void) virtioHostQueueIntrEnable (pRxQueue);
            (void) virtioHostQueueNotify (pRxQueue);
            (void) pthread_mutex_unlock (&pHostVsockDev->txMutex);

            return -1;
        }

        totalLen    = 0U;
        releaseLen  = 0U;
        hdrOffset   = 0U;
        bufOffset   = 0U;
        hdrLen      = (uint32_t)sizeof(struct virtio_vsock_hdr);

        /* Calculate total length */
        for (i = 0; i < n; i++) {
            totalLen += hostBuf[i].len;
        }

        if (totalLen < hdrLen) {
            (void) virtioHostQueueRelBuf (pRxQueue, idx, (uint32_t)totalLen);
            (void) virtioHostQueueIntrEnable (pRxQueue);
            (void) virtioHostQueueNotify (pRxQueue);
            (void) pthread_mutex_unlock (&pHostVsockDev->txMutex);

            VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                      "%s:hostBuf len is too small.\n",
                                      __func__);
            return -1;
        }

        if (pBuf != NULL) {
            payloadLen = totalLen - hdrLen;

            if (bufLen > payloadLen) {
                pHdr->len  = payloadLen;
                bufLen     -= payloadLen;
                needGetbuf = true;
            } else {
                payloadLen = bufLen;
                pHdr->len  = payloadLen;
                bufLen     = 0U;
                needGetbuf = false;
            }
        } else {
            pHdr->len  = 0U;
            needGetbuf = false;
        }

        /* fill data to hostBuf */

        for (i = 0; i < n; i++) {
            if (hostBuf[i].len == 0U) {
                continue;
            }
            if (hdrLen > 0U) {

                /*
                 * Store pHdr to buffer, if one buffer can not store the whole
                 * pHdr, then store the remaining content to next buffer.
                 */

                if (hostBuf[i].len <= hdrLen) {
                    (void) memcpy (hostBuf[i].buf, (char *)pHdr + hdrOffset, (size_t)hostBuf[i].len);
                    hdrOffset  += hostBuf[i].len;
                    hdrLen     -= hostBuf[i].len;
                    releaseLen += hostBuf[i].len;
                    continue;
                } else {
                    /*
                     * If the buffer length is larger than vsock header length,
                     * store it to the buffer. And continue storing the data
                     * pointed by pBuf behind the vsock header, if pBuf is not
                     * NULL.
                     */

                    (void) memcpy (hostBuf[i].buf, (char *)pHdr + hdrOffset,(size_t)hdrLen);

                    bufOffset  = hdrLen;
                    hdrLen     = 0U;

                    if (pBuf != NULL) {
                        /*
                         * Check if the remaining buffer can store the payload,
                         * if yes, just continue storing the payload to buffer,
                         * otherwise, continue calling virtioHostQueueGetBuf()
                         * to get more buffers, so that store all data pointed
                         * by pBuf to the buffers.
                         */

                        if ((payloadLen + bufOffset) <= hostBuf[i].len) {
                            (void) memcpy (hostBuf[i].buf + bufOffset, pBuf + sndOffset, (size_t)payloadLen);
                            releaseLen += hostBuf[i].len;
                            sndOffset  += payloadLen;
                            payloadLen = 0U;
                        } else {
                            (void) memcpy (hostBuf[i].buf + bufOffset, pBuf + sndOffset, (size_t)hostBuf[i].len - bufOffset);
                            payloadLen -= hostBuf[i].len - bufOffset;
                            releaseLen += hostBuf[i].len;
                            sndOffset  += hostBuf[i].len - bufOffset;
                        }
                    } else {
                        releaseLen += hostBuf[i].len;
                    }
                }
            } else {
                if (pBuf != NULL) {
                    /*
                     * We have stored all vsock header to buffer, so this
                     * branch mainly stores the data pointed by pBuf to buffer.
                     */

                    if (payloadLen <= hostBuf[i].len) {
                        (void) memcpy (hostBuf[i].buf,
                                         pBuf + sndOffset,
                                         (size_t)payloadLen);
                        sndOffset  += payloadLen;
                        releaseLen += hostBuf[i].len;
                        payloadLen = 0U;
                    } else {
                        (void) memcpy (hostBuf[i].buf,
                                         pBuf + sndOffset,
                                         (size_t)hostBuf[i].len);
                        payloadLen -= hostBuf[i].len;
                        releaseLen += hostBuf[i].len;
                        sndOffset  += hostBuf[i].len;
                    }
                }
            }
        }

        if (releaseLen == 0) {
            (void) virtioHostQueueRetBuf (pRxQueue);
        } else {
            (void) virtioHostQueueRelBuf (pRxQueue, idx, (uint32_t)releaseLen);
            needNotify = true;
        }

        /* Enable interrupt */

        (void) virtioHostQueueIntrEnable (pRxQueue);

        /* Notify frontend driver */

        if (needNotify) {
            (void) virtioHostQueueNotify (pRxQueue);
        }

    }while (needGetbuf);

    (void) pthread_mutex_unlock (&pHostVsockDev->txMutex);

    return 0;
}

/******************************************************************************
*
* virtioHostVsockRxHandle - process received frames in TxQueue
*
* This routine processes data from the virtual sending queue.
*
* RETURNS: N/A
*
* ERRNO: N/A
*/
static void virtioHostVsockRxHandle(struct virtioHostVsock * dev)
{
    struct virtioHostBuf        bufList[VIRTIO_VSOCK_QUEUE_MAX_NUM];
    struct iovec                iov[VIRTIO_VSOCK_QUEUE_MAX_NUM];
    //struct virtio_vsock_hdr     *hdr;
    struct virtio_vsock_hdr     *pHdr = NULL;
    int i, n;
    uint16_t idx;
    struct virtioHostVsock      *pHostVsockDev;
    bool needNotify = false;
    struct virtioHost           *vHost;
    struct virtioHostQueue      *pQueue;
    void *txBuf = NULL;
    //uint64_t localCid;
    int ret = 0;
    char *pktBuf = NULL;
    uint32_t hdrLen = 0U;
    uint32_t totalLen = 0U;
    uint32_t pktOffset = 0;
    struct vtsock_unix_socket *sock;

    pHostVsockDev = dev;
    if (pHostVsockDev == NULL) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                  "%s : input invalid!\n", __func__);
        return;
    }

    pktBuf = (char *)pHostVsockDev->txQBuf;
    hdrLen = (uint32_t)sizeof(struct virtio_vsock_hdr);
    vHost  = (struct virtioHost *) pHostVsockDev;
    pQueue = VIRTIO_VSOCK_TX_QUEUE(vHost);

    pthread_mutex_lock(&pHostVsockDev->rxMutex);

    /* get local cid */
    //localCid = VIRTIO_HOST_VSOCK_CID;
    while(1) {

        n = virtioHostQueueGetBuf (pQueue, &idx, bufList, VIRTIO_VSOCK_QUEUE_MAX_NUM);
        if (n < 0) {
            if ((n != (-EINVAL)) && (n != (-EACCES))) {
                VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "QueueGetBuf: Rxbuf: return < 0, ret buf \n ");
                (void) virtioHostQueueRetBuf (pQueue);
            }

            (void) virtioHostQueueIntrEnable (pQueue);
            (void) pthread_mutex_unlock(&pHostVsockDev->rxMutex);
            VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                      "%s: something wrong with pQueue \n",
                                      __func__);
            return;
        } else if (n == 0) {
            (void) virtioHostQueueIntrEnable (pQueue);
            (void) virtioHostQueueNotify (pQueue);
            //(void) pthread_mutex_unlock(&pHostVsockDev->rxMutex);
            //VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_INFO,
            //                          "%s: no new queue buffer \n", __func__);
            break;
        }

        pHdr = (struct virtio_vsock_hdr *) bufList[0].buf;
        pktOffset   = 0U;
        totalLen    = 0U;

        for (i = 0; i < n; i++) {
            totalLen += bufList[i].len;
            iov[i].iov_base = bufList[i].buf;
            iov[i].iov_len = bufList[i].len;
        }

        if ((totalLen < hdrLen) || (totalLen >= VIRTIO_VSOCK_HOST_PKT_LENGTH)) {
            (void) virtioHostQueueRetBuf (pQueue);
            (void) virtioHostQueueIntrEnable (pQueue);
            (void) virtioHostQueueNotify (pQueue);
            (void) pthread_mutex_unlock (&pHostVsockDev->rxMutex);
            VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                      "%s: Buffer length is invalid!"
                                      "totalLen = %u\n",
                                      __func__, totalLen);
            return;
         }



        //pHdr = (struct virtio_vsock_hdr *)pktBuf;
        //dump_frame("RX:", (unsigned char *)pHdr, sizeof(struct virtio_vsock_hdr));
        ret = 0;
        if (pHdr != NULL) {
            if (le64toh (pHdr->dst_cid) == VIRTIO_HOST_VSOCK_CID) {
                pktOffset = totalLen;
                /* handle TX Queue data */
                pthread_mutex_lock(&pHostVsockDev->cacheMutex);
                LIST_FOREACH(sock, &pHostVsockDev->inuseList, list) {
                    if ( ((sock->state == SOCK_CONNECTED) || (sock->state == SOCK_CONNECT_WAITING)) && \
                         (sock->peer_addr.cid == pHdr->src_cid) && \
                         (sock->peer_addr.port == pHdr->src_port) && \
                         (sock->local_addr.port == pHdr->dst_port) && \
                         (sock->sock_type == pHdr->type)) {
                        /* match, update the buf and fwd data from header */
                        ret = 1;
                        sock->peer_buf_alloc = pHdr->buf_alloc;
                        sock->peer_fwd_cnt = pHdr->fwd_cnt;
                        break;
                    }
                }
                pthread_mutex_unlock(&pHostVsockDev->cacheMutex);

                /* the header's sock not in our current list */
                if (!ret) {
                    sock = NULL;
                }

                if (unixSocketRxHandler(pHostVsockDev,  pHdr, iov, n, sock) < 0) {
                    needNotify = true;
                    break;
                }
            } else {
                // copying data from buffer list
                for (i = 0; i < n; i++) {
                    (void) memcpy (pktBuf + pktOffset,
                                     bufList[i].buf,
                                     bufList[i].len);

                    pktOffset += bufList[i].len;
                }

                /* forward packets to destination cid */
                if (pHdr->len > 0U) {
                    txBuf = (void *)pktBuf + hdrLen;
                } else {
                    txBuf = NULL;
                }

                ret = virtioHostVsockTx (pHdr, txBuf,
                                         pHdr->len);
                if (ret != 0) {
                    VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                              "%s: virtioHostVsockTx failed \n",
                                              __func__);
                }
            }
        } else {
            (void) virtioHostQueueRetBuf (pQueue);
            (void) virtioHostQueueIntrEnable (pQueue);
            (void) virtioHostQueueNotify (pQueue);
            (void) pthread_mutex_unlock (&pHostVsockDev->rxMutex);
            VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                      "%s: Vsock header is NULL!\n",
                                      __func__);
            return;
        }

        if (pktOffset == 0) {
            (void) virtioHostQueueRetBuf (pQueue);
        } else {
            (void) virtioHostQueueRelBuf (pQueue, idx, (uint32_t)pktOffset);
            needNotify = true;
        }
    }

    (void) virtioHostQueueIntrEnable (pQueue);
    if (virtioHostQueueHasBuf (pQueue)) {
        sem_post(&pHostVsockDev->rxTaskSem);
    }

    if (needNotify) {
        (void) virtioHostQueueNotify (pQueue);
    }

    (void) pthread_mutex_unlock (&pHostVsockDev->rxMutex);

}

/******************************************************************************
*
* virtioHostVsockRxHandleProc - Task to process received virtio queue
*
* This routine processes received virtio queue.
*
* RETURNS: N/A
*
* ERRNO: N/A
*/
static void *virtioHostVsockRxHandleProc(void *arg)
{
    struct virtioHostVsock * pVsockDev = (struct virtioHostVsock *)arg;

    if (!arg) {
        VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR, "%s arg is NULL\n", __func__);
        return NULL;
    }

    while(1) {
        if (sem_wait(&pVsockDev->rxTaskSem) != 0) {
            VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR, "%s sem_wait failed\n", __func__);
            continue;
        }
        virtioHostVsockRxHandle(pVsockDev);
    }

    return NULL;
}

/*******************************************************************************
*
* virtioHostVsockDrvInit - initialize virtio vsock host device driver
*
* This routine initializes the virtio vsock host device driver.
*
* RETURNS: N/A
*
* ERRNO: N/A
*/

void virtioVTSockBEDrvInit(void)
{
    virtioHostDrvRegister ((struct virtioHostDrvInfo *)
                           &virtioHostVsockDrvInfo);

    pthread_mutex_init (&vHostVsockDevs.drvLock, NULL);
    vHostVsockDevs.vHostVsockDevNum = 0;
}

/*******************************************************************************
*
* virtioVTSockBEDrvTerminate - terminate virtio vsock host device driver
*
* This routine destroy virtio vsock host driver
*
* RETURNS: N/A
*
* ERRNO: N/A
*/

void virtioVTSockBEDrvTerminate(void)
{
    int i;
    struct virtioHostVsock *pHostVsock;

    if (vHostVsockDevs.vHostVsockDevNum == 0)
        return;

    pthread_mutex_lock(&vHostVsockDevs.drvLock);
    for(i=0; i<(int)vHostVsockDevs.vHostVsockDevNum; i++) {
        if (vHostVsockDevs.virtioHostVsocks[i]) {
            close(pHostVsock->wakeupfd);
            close(pHostVsock->kickfd);
            pHostVsock = vHostVsockDevs.virtioHostVsocks[i];
            pthread_cancel(pHostVsock->tTaskRx);
            pthread_cancel(pHostVsock->tTaskUnixSockRx);
            pthread_cancel(pHostVsock->tTaskUnixServer);
            //clean all active socks
            virtioHostVsockReset((struct virtioHost *)pHostVsock);
            sem_destroy(&pHostVsock->rxTaskSem);
            sem_destroy(&pHostVsock->unixSockTaskSem);
            //free cache
            if (pHostVsock->txQBuf)
                free(pHostVsock->txQBuf);

            pthread_mutex_destroy(&pHostVsock->txMutex);
            pthread_mutex_destroy(&pHostVsock->rxMutex);
            pthread_mutex_destroy(&pHostVsock->cacheMutex);
            free(pHostVsock);
            vHostVsockDevs.virtioHostVsocks[i] = NULL;
            pHostVsock = NULL;
        }
    }
    pthread_mutex_unlock(&vHostVsockDevs.drvLock);
    pthread_mutex_destroy(&vHostVsockDevs.drvLock);

    //Final step, cleanning all driver data
    memset(&vHostVsockDevs, 0x0, sizeof(vHostVsockDevs));

    return;
}

/*******************************************************************************
*
* virtioHostVsockFeatureSet - set virtio vsock backend device features
*
* This routine sets virtio vsock backend device features.
*
* RETURNS: 0
*
* ERRNO: N/A
*/

static int virtioHostVsockFeatureSet(struct virtioHostVsock *   pHostVsockDev)
{

    /* set device features */
    pHostVsockDev->features = VIRTIO_HOST_VSOCK_FEATURES;

    return 0;
}

/*******************************************************************************
*
* virtioHostVsockDevCreate - create virtio vsock device instance
*
* This routine creates and initializes virtio vsock device instance.
*
* RETURNS: 0, or -1 if any error is raised in process of the vsock device
* context creating.
*
* ERRNO: N/A
*/

static int virtioHostVsockDevCreate(struct virtioHostVsock *    pHostVsockDev)
{
    struct virtioHost *         vhost;
    int                         ret;

    if (!pHostVsockDev) {
        ret = -1;
        goto error;
    }

    vhost = (struct virtioHost *) pHostVsockDev;

    /* initialize virtio host vsock device features */
    ret = virtioHostVsockFeatureSet (pHostVsockDev);
    if (ret == -1){
        goto error;
    }

    if (sem_init(&pHostVsockDev->rxTaskSem, 0, 0) != 0) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                "%s: create semaphore rxTaskSem failed, "
                                "errno [%d]!\n", __func__, errno);
        ret = -1;
        goto error;
    }

    /*
     * Create a task to run the queue to handle deferred IRQ work
     */

    vhost = (struct virtioHost *) pHostVsockDev;
    vhost->channelId = pHostVsockDev->channel->channelId;
    vhost->pMaps     = pHostVsockDev->channel->pMap;

    ret = virtioHostCreate (vhost, VIRTIO_DEV_ANY_ID, VIRTIO_TYPE_VSOCK,
                            &pHostVsockDev->features, VIRTIO_VSOCK_QUEUE_MAX,
                            VIRTIO_VSOCK_QUEUE_MAX_NUM, 0, NULL,
                            &virtioHostVsockOps);
    if (ret != 0) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                            "%s: virtio vsock host context creating failed\n",
                            __func__);
        goto error;
    }

    pthread_mutex_lock (&vHostVsockDevs.drvLock);
    vHostVsockDevs.virtioHostVsocks[vHostVsockDevs.vHostVsockDevNum++] = pHostVsockDev;
    pthread_mutex_unlock (&vHostVsockDevs.drvLock);

    if (virtioHostVsockUnixSockInit(pHostVsockDev) != 0 ) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,\
                                  "%s: failed to init unix sock service\n", __func__ );
        goto error;
    }
    pthread_create(&pHostVsockDev->tTaskRx, NULL, virtioHostVsockRxHandleProc, (void *)pHostVsockDev);

    return 0;

error:
    (void) sem_destroy(&pHostVsockDev->rxTaskSem);

    return ret;
}

/*******************************************************************************
*
* virtioHostVsockArgsParse - parse argument list of virtio vsock device
*
* This routine parses argument list of virtio vsock device.
*
* RETURNS: 0, or negative value of errno number if any error is raised
* in process of the parsing.
*
* ERRNO: N/A
*/

static int virtioHostVsockArgsParse(struct virtioHostVsock *    pHostVsockDev)
{
    char    *   tmpstr = NULL;
    char    *   endPtr;
    char    *   start = NULL;
    uint32_t    i;

    if (pHostVsockDev == NULL || pHostVsockDev->pArgs == NULL) {
        return -EINVAL;
    }

    /* Parse guest cid */

    tmpstr = strstr (pHostVsockDev->pArgs, "cid=");
    if (tmpstr == NULL) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                  "%s: Not find cid argument in XML",
                                  __func__);
        goto error;
    }

    start = tmpstr + strnlen ("cid=", 4);
    pHostVsockDev->config.guest_cid = (uint64_t) strtoul (start, &endPtr, 16);
    if (endPtr == start) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                  "%s: cid is not configured ! \n",
                                  __func__);
        goto error;
    }

    if ((pHostVsockDev->config.guest_cid < VIRTIO_HOST_VSOCK_CID) ||
        (pHostVsockDev->config.guest_cid >= UINT32_MAX)) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                  "%s: Reserved cid ! \n",
                                  __func__);
        goto error;
    }

    for(i = 0; i < vHostVsockDevs.vHostVsockDevNum; i++) {
        if (vHostVsockDevs.virtioHostVsocks[i]->config.guest_cid == pHostVsockDev->config.guest_cid) {
            VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                      "%s: cid already in use! \n",
                                      __func__);
            goto error;
        }
    }
    return 0;

error:
    return -1;
}

/*******************************************************************************
*
* virtioHostVsockDevInit - Initialize virtioHostVsock driver
*
* This routine initializes virtioHostVsock driver.
*
* RETURNS: 0, or negative value of errno number if any error is raised
* in process of the parsing.
*
* ERRNO: N/A
*/

static int virtioHostVsockDevInit(struct virtioHostVsock *pHostVsockDev)
{
    if (pHostVsockDev == NULL) {
        return -EINVAL;
    }
    pHostVsockDev->txQBuf = (void *) calloc (1, VIRTIO_VSOCK_HOST_PKT_LENGTH);
    if (pHostVsockDev->txQBuf == NULL) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                  "%s: calloc failed!\n",
                                  __func__);
        return -1;
    }

    return 0;
}

/*******************************************************************************
*
* virtioHostVsockCreate - create a virtio vsock device
*
* This routine creates a virtio vsock device.
*
* RETURNS: 0, or negative value of errno number if any error is raised
* in process of the vsock device creating.
*
* ERRNO: N/A
*/

static int virtioHostVsockCreate (struct virtioHostDev *  pHostDev)
{
    struct virtioHostVsock *  pHostVsockDev;
    int                       ret;

    if (pHostDev == NULL) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                  "%s: pHostDev is NULL! \n", __func__);
        return -EINVAL;
    }
    /* the virtio channel number is always one */
    if (pHostDev->channelNum != 1U) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                  "%s channel number is %d "
                                  "only support channel number equals to one!\n",
                                  __func__, pHostDev->channelNum);
        return -EINVAL;
    }

    VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_INFO, "%s:\n"
                        "  typeId = %d args %s channelNum = %d \n"
                        "    - channel ID = %d \n"
                        "      hvaddr = 0x%lx \n"
                        "      gpaddr = 0x%lx \n"
                        "      cpaddr = 0x%lx \n"
                        "      size   = 0x%lx \n",
                        __func__,
                        pHostDev->typeId, pHostDev->args, pHostDev->channelNum,
                        pHostDev->channels[0].channelId,
                        pHostDev->channels[0].pMap->entry->hpaddr,
                        pHostDev->channels[0].pMap->entry->gpaddr,
                        pHostDev->channels[0].pMap->entry->cpaddr,
                        pHostDev->channels[0].pMap->entry->size);

    if (vHostVsockDevs.vHostVsockDevNum == VIRTIO_VSOCK_HOST_DEV_MAX) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                  "%s: reach the maximum handle limitation!\n",
                                  __func__);
        return -ENOENT;
    }

    pHostVsockDev = calloc (1, sizeof (struct virtioHostVsock));
    if (pHostVsockDev == NULL) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                            "%s: allocate memory failed for virtio vsock "
                            "host device failed! \n", __func__);
        return -ENOSPC;
    }

    /* Create mutex for host vsock device */
    pthread_mutex_init(&pHostVsockDev->rxMutex, NULL);
    pthread_mutex_init(&pHostVsockDev->txMutex, NULL);

    pHostVsockDev->channel = pHostDev->channels;
    pHostVsockDev->pArgs = pHostDev->args;


    /* parse arguments set in XML file */
    ret = virtioHostVsockArgsParse (pHostVsockDev);
    if (ret != 0) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                  "Failed to parse arugments\n");
        goto exit;
    }
    /* create virtioHost vsock device */
    ret = virtioHostVsockDevCreate (pHostVsockDev);
    if (ret != 0) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                  "Failed to create vsock device\n");
        goto exit;
    }

    /* Initialize virtioHostVsock device */
    ret = virtioHostVsockDevInit (pHostVsockDev);

exit:
    if (ret != 0) {
        if (pHostVsockDev != NULL) {
            free (pHostVsockDev);
        }

        return -1;
    }
    return 0;
}

/*******************************************************************************
*
* virtioHostVsockIntHandle - process received frames and transmited frames
*
* This function is scheduled by the ISR to run in the context of tTask
* whenever a RX/TX interrupt is received.
*
* RETURNS: N/A
*
* ERRNO: N/A
*/

static void virtioHostVsockIntHandle(struct virtioHostQueue *  pQueue)
    {
    struct virtioHost *       vHost;
    struct virtioHostVsock *  pHostVsockDev;

    if (pQueue == NULL) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                  "%s, %d: invalid argument \n",
                                  __func__, __LINE__);
        return;
    }

    if (pQueue->vHost == NULL) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                  "%s, %d: invalid argument \n",
                                  __func__, __LINE__);
        return;
    }

    vHost = pQueue->vHost;
    pHostVsockDev = (struct virtioHostVsock *) vHost;

    if ((vHost->status & VIRTIO_CONFIG_S_DRIVER_OK) == 0) {
        return;
    }

    if (pQueue == VIRTIO_VSOCK_TX_QUEUE (vHost)) {
        (void) virtioHostQueueIntrDisable (pQueue);
        sem_post(&pHostVsockDev->rxTaskSem);
    } else if (pQueue == VIRTIO_VSOCK_RX_QUEUE (vHost)) {
        ;
    } else if (pQueue == VIRTIO_VSOCK_EVENT_QUEUE (vHost)) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                  "Event Q trigger \n");
        (void) virtioHostQueueIntrDisable (pQueue);
        (void) virtioHostQueueIntrEnable (pQueue);
    } else {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                  "%s: invalid queue\n",
                                  __func__);
    }

    return;
}

/*******************************************************************************
*
* virtioHostVsockSetStatus - initialize virtioHostVsock status
*
* This routine is used to initialize virtioHostVsock status when receiving reset
* signal from guest.
*
* RETURNS: 0, or -1 if failure raised in process of changing status.
*
* ERRNO: N/A
*/

static int virtioHostVsockSetStatus(struct virtioHost * vHost, uint32_t status)
{
    struct virtioHostQueue  *   pQueue;
    struct virtioHostVsock  *   pHostVsockDev;

    pHostVsockDev = (struct virtioHostVsock *) vHost;
    if (pHostVsockDev == NULL) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                  "%s: status = %d invalid pHostVsockDev \n", __func__, status);
        return -EINVAL;
    }

    if ((vHost->status & VIRTIO_CONFIG_S_DRIVER_OK) == 0) {
        return 0;
    }

    pQueue = VIRTIO_VSOCK_TX_QUEUE (vHost);
    (void) virtioHostQueueIntrEnable (pQueue);

    pQueue = VIRTIO_VSOCK_RX_QUEUE (vHost);
    (void) virtioHostQueueIntrEnable (pQueue);

    pQueue = VIRTIO_VSOCK_EVENT_QUEUE (vHost);
    (void) virtioHostQueueIntrEnable (pQueue);

    return 0;
}

/*******************************************************************************
*
* virtioHostVsockReset - reset virtio vsock device
*
* This routine is used to reset the virtio vsock device. All the configuration
* settings setted by customer driver will be cleared and all the backend
* driver software flags are reset to initial status.
*
* RETURNS: 0, or -1 if failure raised in process of restarting the device.
*
* ERRNO: N/A
*/

static int virtioHostVsockReset(struct virtioHost * vHost)
{
    struct virtioHostVsock *  pHostVsockDev;
    int                       ret = 0;
    struct vtsock_unix_socket *sock = NULL;

    pHostVsockDev = (struct virtioHostVsock *) vHost;
    if (pHostVsockDev == NULL) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                  "%s: invalid pHostVsockDev \n", __func__);
        return -1;
    }

    pthread_mutex_lock(&pHostVsockDev->cacheMutex);
    if (!LIST_EMPTY(&pHostVsockDev->inuseList)) {
        LIST_FOREACH(sock, &pHostVsockDev->inuseList, list) {
            if (sock) {
                close(sock->fd);
                LIST_REMOVE(sock, list);
                memset(sock, 0x0, sizeof(struct vtsock_unix_socket));
                sock->fd = -1;
                LIST_INSERT_HEAD(&pHostVsockDev->freeList, sock, list);
            }
        }
    }
    pthread_mutex_unlock(&pHostVsockDev->cacheMutex);

    return ret;
}

/*******************************************************************************
*
* virtioHostVsockCfgRead - read virtio vsock specific configuration register
*
* This routine is used to read virtio vsock specific configuration register,
* the value read out is stored in the request buffer.
*
* RETURN: 0, or -EINVAL if virtio host device is non-existed.
*
* ERRNO: N/A
*/

static int virtioHostVsockCfgRead(struct virtioHost *vHost,uint64_t address,uint64_t size, uint32_t * pValue)
{
    struct virtioHostVsock *  pHostVsockDev;
    uint8_t *   cfgAddr;

    if (vHost == NULL){
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,
                                  "%s: NULL pointer \n", __func__);
        return -EINVAL;
    }

    pHostVsockDev = (struct virtioHostVsock *)vHost;
    cfgAddr = (uint8_t *)&pHostVsockDev->config + address;
    (void) memcpy ((void *)pValue, (void *)cfgAddr, size);

    return 0;
}

/*******************************************************************************
*
* virtioHostVsockShow - virtio vsock host device show
*
* This routine shows the virtio vsock host device setting and configurations.
*
* RETURNS: N/A
*
* ERRNO: N/A
*/

static void virtioHostVsockShow(struct virtioHost * vHost, uint32_t indent)
{
    int i;

    if ((vHost->status & VIRTIO_CONFIG_S_DRIVER_OK) == 0)
        return;

    printf ("-------- Virtio Vsock Device Information --------\n");
    pthread_mutex_lock(&vHostVsockDevs.drvLock);
    printf("Indent=%d \n", indent);
    printf("Local Unix Stream Sock Path: %s\n", CONNECT_STREAM_CHANNEL);
    for(i=0; i<(int)vHostVsockDevs.vHostVsockDevNum; i++) {
        if (!vHostVsockDevs.virtioHostVsocks[i])
            continue;

        printf("----Device %d:\n", i);
        printf("CID=%llu\n", vHostVsockDevs.virtioHostVsocks[i]->config.guest_cid);
        printf("RXQ num=%d,  ", vHostVsockDevs.virtioHostVsocks[i]->vhost.pQueue[VIRTIO_VSOCK_RXQ].vRing.num);
        printf("TXQ num=%d,  ", vHostVsockDevs.virtioHostVsocks[i]->vhost.pQueue[VIRTIO_VSOCK_TXQ].vRing.num);
        printf("Event num=%d \n", vHostVsockDevs.virtioHostVsocks[i]->vhost.pQueue[VIRTIO_VSOCK_EVENTQ].vRing.num);
        printf("---------------\n");
    }
    pthread_mutex_unlock(&vHostVsockDevs.drvLock);

}
