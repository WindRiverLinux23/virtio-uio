/* virtioHostVsock_unix.c - vsock host over unix socket emulator*/

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

/*******************************************************************************
 *
 *  setup_sock_opt - setup the sock status
 *
 *  This routine is setup the sock status, mapping sock buffer and marking the
 *  socket in non-blocking mode
 *
 *  RETURN 0,  or -1 if error happens.
 *
 *  ERRNO: N/A
 */

int setupSockOpt(struct vtsock_unix_socket *s)
{
    int buf_alloc;
    socklen_t opt_len;

    if (!s)
        return -1;

    buf_alloc = (int)s->buf_alloc;
    if (setsockopt(s->fd, SOL_SOCKET, SO_SNDBUF, &buf_alloc, sizeof(buf_alloc)) < 0) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "Failed to set sockopt SO_SNDBUF");
        return -1;
    }

    if (setsockopt(s->fd, SOL_SOCKET, SO_RCVBUF, &buf_alloc, sizeof(buf_alloc)) < 0) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "Failed to set sockopt SO_RCVBUF");
        return -1;
    }

    opt_len = sizeof(buf_alloc);
    if (getsockopt(s->fd, SOL_SOCKET, SO_SNDBUF, &buf_alloc, &opt_len) < 0) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "Failed to get sockopt SO_SNDBUF");
        return -1;
    }

    /* seems our system doesn't support setup R/W buffer size, using system default */
    if (buf_alloc < (int)s->buf_alloc)
        s->buf_alloc = buf_alloc;

    return 0;
}

/*******************************************************************************
 *
 *  openForwardSocket - open a forward socket if guest need to connect to host
 *
 *  This routine is check and open a forward when host is server guest is client
 *  if local unix exsits, connection will be enabled and the socket in non-blocking
 *  mode
 *
 *  RETURN 0,  or -1 if error happens.
 *
 *  ERRNO: N/A
 */

int openForwardSocket(uint64_t cid, unsigned int port)
{
    char s_path[MAX_FORWARD_PATH_LENGTH];
    int fd = -1;
    struct sockaddr_un un;

    bzero(&un, sizeof(struct sockaddr_un));
    memset(s_path, 0x0, sizeof(s_path));

    if (snprintf(s_path, sizeof(un.sun_path), "%s/vsock.%ld_%d", FORWARD_PATH, cid, port) < 0) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "Failed to format unix socket path");
        return -1;
    }

    if (access((const char *)s_path, F_OK) != 0) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "No such port was enabled on host, port=%d <%08x>\n", port,port);
        return -1;
    }

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "Failed to create socket for forwarding");
        return -1;
    }

    un.sun_family = AF_UNIX;
    strncpy(un.sun_path, s_path, strlen(s_path));

    if (connect(fd, (struct sockaddr *)&un, sizeof(struct sockaddr_un)) < 0) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "Failed to connect target socket");
        close(fd);
        return -1;
    }

    return fd;
}

static void *taskUnixSocketServer(void *arg)
{
    struct virtioHostVsock *vSock = (struct virtioHostVsock *)arg;
    int sockfd = -1, connectfd = -1;
    struct sockaddr_un un;
    const char *path = CONNECT_STREAM_CHANNEL;
    uint32_t cid;
    char buf[128]; //CONNECT:%d\n\0
    char *p = buf;
    socklen_t clen;
    uint32_t port;
    int bytes = 0;
    struct sockaddr_un client_addr;
    struct vtsock_unix_socket *sock = NULL;

    if (!arg) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "taskUnixSocketServer: arg is NULL \n");
        return NULL;
    }

    VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR, "unix socket server for cid %lld start\n",vSock->config.guest_cid);
rebind:
    memset((void *)&un, 0x0, sizeof(struct sockaddr_un));
    un.sun_family = AF_UNIX;
    cid = (uint32_t)vSock->config.guest_cid;

    if (snprintf(un.sun_path, sizeof(un.sun_path), "%s%d", path, cid) < 0) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "Failed to format strings for sockaddr_un.sun_path");
        return NULL;
    }

    if (unlink(un.sun_path) < 0) {
        if (errno != ENOENT) {
            VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "Failed to unlink socket");
            return NULL;
        }
    }

    if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "cannot create unix socket");
        return NULL;
    }

    if (bind(sockfd, (struct sockaddr *)&un, sizeof(struct sockaddr_un)) < 0) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "Failed to bind socket");
        close(sockfd);
        return NULL;
    }

    if (listen(sockfd, SOMAXCONN) < 0) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "Failed to listen socket");
        close(sockfd);
        return NULL;
    }

    vSock->ufds.stream_fd = sockfd;

    while(1) {
        p = buf;
        clen = sizeof(client_addr);
        connectfd = accept(sockfd, (struct sockaddr *)&client_addr, &clen);
        if (connectfd < 0) {
            VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "Failed to accept socket");
            perror("accept:");
            close(sockfd);
            goto rebind;
        }

        if (connectfd >= FD_SETSIZE) {
            VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "connect_channel_handler: accepted fd larger than FD_SETSIZE");
            close(connectfd);
            continue;
        }

        do{
            bytes = read(connectfd, buf, sizeof(buf));

        } while(bytes == -1 && errno == EAGAIN);

        if (strncmp(p, CONNECT_CMD_HEADER, strlen(CONNECT_CMD_HEADER)) != 0) {
            VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "connect_channel_handler: connect cmd=%s not match target=%s\n", p, CONNECT_CMD_HEADER);
            close(connectfd);
            continue;
        }

        p = p + strlen(CONNECT_CMD_HEADER);
        if (sscanf(p, "%d\n", &port) != 1) {
            VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "connect_channel_handler: failed to parse connect command\n");
            close(connectfd);
            continue;
        }

        pthread_mutex_lock(&vSock->cacheMutex);
        if (LIST_EMPTY(&vSock->freeList)) {
            VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,  "no enough node in freelist, devID=%d\n", cid);
            goto listErr;
        }

        sock = LIST_FIRST(&vSock->freeList);
        if (!sock) {
            VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR,  "got NULL sock, devID=%d\n", cid);
            goto listErr;
        }

        LIST_REMOVE(sock, list);
        /*backup port_generation */
        bytes = (int)sock->port_generation;
        memset(sock, 0x0, sizeof(struct vtsock_unix_socket));
        sock->local_addr.cid = VIRTIO_HOST_VSOCK_CID;
        /*restore port_generation */
        sock->port_generation = bytes;
        /* for local port, since we are unix domain socket, just faking a port number for guest */
        sock->local_addr.port = (uint32_t)((sock - &vSock->sockCache[0]) << 16) + \
                sock->port_generation++ + (unsigned short int)random();
        sock->peer_addr.cid = cid;
        sock->peer_addr.port = port;
        sock->fd = connectfd;
        sock->sock_type = VIRTIO_VSOCK_TYPE_STREAM;
        sock->state = SOCK_CONNECTING;
        sock->buf_alloc = WRITE_BUF_LENGTH;
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "new connection fd = %d, \
        local cid=%d, port=%d, dst cid=%d, port=%d \n", connectfd, VIRTIO_HOST_VSOCK_CID, \
                sock->local_addr.port, cid, port );

        setupSockOpt(sock);
        LIST_INSERT_HEAD(&vSock->inuseList, sock, list);
        pthread_mutex_unlock(&vSock->cacheMutex);

        sem_post(&vSock->unixSockTaskSem);
        //Kick to break select to process new connection
        if (write(vSock->kickfd, buf, 1) != 1)
            perror("write:");

        continue;
listErr:
        close(connectfd);
        pthread_mutex_unlock(&vSock->cacheMutex);
    }

    VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR, "unix socket server for cid %lld exit\n",vSock->config.guest_cid);
    return NULL;
}

int virtioHostVsockXmit(struct virtioHostVsock *vSock, struct vtsock_unix_socket *sock)
{
    struct virtioHost* vHost = (struct virtioHost *)vSock;
    struct virtioHostBuf bufList[VIRTIO_VSOCK_QUEUE_MAX_NUM];
    struct iovec iov[VIRTIO_VSOCK_QUEUE_MAX_NUM];
    struct virtioHostQueue *pQueue;
    struct virtio_vsock_hdr *hdr;
    uint16_t idx;
    uint32_t totalBuf = 0;
    uint32_t totalRead = 0;
    int i, n, nread;

    if (!vSock) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "virtioHostVsockXmit :vSock is NULL\n");
        return -1;
    }

    if (!sock) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "virtioHostVsockXmit :sock is NULL\n");
        return -1;
    }

continue_read:

    pQueue = VIRTIO_VSOCK_RX_QUEUE(vHost);
    pthread_mutex_lock(&vSock->txMutex);
    n = virtioHostQueueGetBuf(pQueue, &idx, bufList, VIRTIO_VSOCK_QUEUE_MAX_NUM);
    if (n == 0) {
        pthread_mutex_unlock(&vSock->txMutex);
        //VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR,
        //        "no new RX queue buffer\n");
        virtioHostQueueIntrEnable(pQueue);
        virtioHostQueueNotify (pQueue);
        return (totalRead == 0) ? VIRTIO_VSOCK_PQUEUE_RETRY : totalRead;
    } else if (n < 0) {
        if ((n != (-EINVAL)) && (n != (-EACCES))) {
            virtioHostQueueRetBuf (pQueue);
        }
        virtioHostQueueIntrEnable(pQueue);
        pthread_mutex_unlock(&vSock->txMutex);
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "something wrong with Rx queue\n");
        virtioHostQueueNotify (pQueue);

        return (totalRead == 0) ? -1 : totalRead;
    }
    pthread_mutex_unlock(&vSock->txMutex);

    for (i = 0; i < n; i++) {
        iov[i].iov_base = bufList[i].buf;
        iov[i].iov_len = bufList[i].len;
        totalBuf += bufList[i].len;
    }

    /* reserved header space */
    iov[0].iov_base = (void *)(iov[0].iov_base + sizeof(struct virtio_vsock_hdr));
    iov[0].iov_len = iov[0].iov_len - sizeof(struct virtio_vsock_hdr);

    nread = readv(sock->fd, iov, n);
    if (nread == 0) {
        VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR, "virtioHostVsockXmit: fd<%d> closed \n", sock->fd);
        // peer socket closed.
        virtioHostQueueIntrEnable(pQueue);
        virtioHostQueueRelBuf(pQueue, idx, 1);
        virtioHostQueueNotify(pQueue);
        return 0;
    } else if (nread < 0) {
        perror("readv:");
        virtioHostQueueIntrEnable(pQueue);
        virtioHostQueueRelBuf(pQueue, idx, 1);
        virtioHostQueueNotify(pQueue);
        return -1;
    }

    hdr = (struct virtio_vsock_hdr *)bufList[0].buf;
    buildRespWithSock(hdr, sock, VIRTIO_VSOCK_OP_RW, 0);
    hdr->len = nread;
    totalRead += nread;

    virtioHostQueueRelBuf(pQueue, idx, (nread + sizeof(struct virtio_vsock_hdr)));
    if (totalBuf == (nread + sizeof(struct virtio_vsock_hdr))) {
        totalBuf = 0;
        goto continue_read;
    }

    virtioHostQueueIntrEnable(pQueue);
    virtioHostQueueNotify(pQueue);

    return totalRead;
}

static void *taskUnixSockRecv(void *arg)
{
    struct virtioHostVsock *vSock = (struct virtioHostVsock *)arg;
    struct virtio_vsock_hdr hdr;
    int n, maxfd, nread;
    struct vtsock_unix_socket *sock;
    struct timeval tmo;
    fd_set rfd;
    bool has_close = false;
    bool need_post_sem = false;
    unsigned char dummy[128];
    LIST_HEAD(txQ, vtsock_unix_socket) queue;
    LIST_HEAD(toclose, vtsock_unix_socket) toclose;

    if (!arg) {
        VIRTIO_VSOCK_DEV_DBG_MSG (VIRTIO_VSOCK_DEV_DBG_ERR, "taskUnixSockXmit: arg is NULL \n");
        return NULL;
    }

    VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR, "unix socket recv thread for cid %lld start\n",vSock->config.guest_cid);

    while(1) {
        tmo.tv_sec = 1; tmo.tv_usec = 0;
        maxfd = vSock->wakeupfd;
        has_close = false;
        need_post_sem = false;
        FD_ZERO(&rfd);
        LIST_INIT(&queue);
        LIST_INIT(&toclose);
        FD_SET(vSock->wakeupfd, &rfd);

        sem_wait(&vSock->unixSockTaskSem);
        if (LIST_EMPTY(&vSock->inuseList)) {
            VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR,"Inuse List is empty\n");
            continue;
        }

        pthread_mutex_lock(&vSock->cacheMutex);
        LIST_FOREACH(sock, &vSock->inuseList, list) {
            if (!sock) {
                VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR,"Null sock in inuseList\n");
                continue;
            }

            if (sock->state == SOCK_CONNECTED) {
                /*
                 * sock status is connected, add to recv queue, if need to send
                 * our credit, send it before enter the select
                 */
                LIST_INSERT_HEAD(&queue, sock, txq);
                FD_SET(sock->fd, &rfd);
                maxfd = MAX_FD(maxfd, sock->fd);

                if (sock->credit_update_required) {
                    buildRespWithSock(&hdr, sock, VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0);
                    if (virtioHostVsockTx(&hdr, NULL, 0) == 0)
                        sock->credit_update_required = false;
                }

            } else if ((sock->state == SOCK_CLOSING_RX) || (sock->state == SOCK_CLOSING_TX) \
                       ||(sock->state) == SOCK_UNKNOWN) {
                /* Sock in close/freeze status, move them to toclose */
                has_close = true;
                close(sock->fd);
                sock->fd = -1;
                LIST_INSERT_HEAD(&toclose, sock, toclose);

            } else if (sock->state == SOCK_CONNECTING) {
                /* a request from host to connect to guest, send the request */
                buildRespWithSock(&hdr, sock, VIRTIO_VSOCK_OP_REQUEST, 0);
                if (virtioHostVsockTx(&hdr, NULL, 0) == 0)
                    sock->state = SOCK_CONNECT_WAITING;
                else
                    VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR, "failed to send req to guest\n");

            } else {
                //other state will process after select() call or vq rx thread
                continue;
            }
        }
        pthread_mutex_unlock(&vSock->cacheMutex);

        n = select(maxfd + 1, &rfd, NULL, NULL, (has_close ? &tmo : NULL));
        if (n <= 0) {
            //ignore everything, reload fd/socks
            //perror("select:");
            continue;
        }

        /* checking if wakeup fd has information */
        if (FD_ISSET(vSock->wakeupfd, &rfd)) {
            if (read(vSock->wakeupfd, &dummy, sizeof(dummy)) < 0)
                perror("read dummy wakup failed\n");
        }

        LIST_FOREACH(sock, &queue, txq) {
            if (!sock) {
                continue;
            }

            if ((sock->state == SOCK_CLOSING_RX) || (sock->state == SOCK_CLOSING_TX) ||\
                    (sock->state == SOCK_UNKNOWN)) {
                LIST_REMOVE(sock, txq);
                LIST_INSERT_HEAD(&toclose, sock, toclose);
                has_close = true;
            }

            if (sock->state != SOCK_CONNECTED) {
                continue;
            }

            if (FD_ISSET(sock->fd, &rfd)) {
                if ((nread = virtioHostVsockXmit(vSock, sock)) < 0) {
                    //VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR, "Failed to send data to guest\n");
                    if (nread == VIRTIO_VSOCK_PQUEUE_RETRY) { //Cannot get queue buffer, retry next cycle
                        need_post_sem = true;
                        continue;
                    }
                    if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
                        perror("virtioHostVsockXmit() error neither EAGAIN nor EWDBLOCK:");
                        sock->state = SOCK_CLOSING_TX;
                        LIST_INSERT_HEAD(&toclose, sock, toclose);
                        has_close = true;
                    }
                } else if (nread == 0) {
                    VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR, "sock<%d> closed by host\n", sock->fd);
                    sock->state = SOCK_CLOSING_TX;
                    LIST_INSERT_HEAD(&toclose, sock, toclose);
                    has_close = true;
                } else {
                    //VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR, "sock<%d> read %d bytes\n", sock->fd, nread);
                    sock->rx_cnt += nread;
                    need_post_sem = true;
                }
            }
        }

        if (has_close) {
            LIST_FOREACH(sock, &toclose, toclose) {
                if (!sock)
                    continue;

                if (sock->state == SOCK_CLOSING_TX) {
                    buildRespWithSock(&hdr, sock, VIRTIO_VSOCK_OP_SHUTDOWN, VIRTIO_VSOCK_SHUTDOWN_SEND);
                    if (virtioHostVsockTx(&hdr, NULL, 0) != 0) {
                        continue;
                    }
                }

                if (sock->fd > 0)
                    close(sock->fd);

                pthread_mutex_lock(&vSock->cacheMutex);
                LIST_REMOVE(sock, list);
                LIST_INSERT_HEAD(&vSock->freeList, sock, list);
                sock->state = SOCK_FREE;
                pthread_mutex_unlock(&vSock->cacheMutex);
            }
        }

        /* we have active socket, restart next loop cycle */
        if ((need_post_sem) || (!LIST_EMPTY(&vSock->inuseList))) {
            sem_post(&vSock->unixSockTaskSem);
        }
    }

    VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR, "unix socket recv thread for cid %lld exit\n",vSock->config.guest_cid);
    return NULL;
}

int virtioHostVsockUnixSockInit(struct virtioHostVsock *vSock)
{
    uint32_t i;
    int pipefds[2];

    if (!vSock) {
        VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR, "virtioHostVsockUnixSockInit: vSock is NULL\n");
        return -1;
    }

    /*
     * When we are using select() for polling socks, if someting changed from
     * guest, we have to break select to update the sock status.
     * currently, creating a pair of pipefd, one for select() fds, another for kick
     * to break select()
     */
    if (pipe(pipefds)) {
        perror("Failed to create pipe fds");
        return -1;
    }

    vSock->wakeupfd = pipefds[0];
    vSock->kickfd = pipefds[1];

    if (sem_init(&vSock->unixSockTaskSem, 0, 0) != 0) {
        perror("virtioHostVsockUnixSockInit: init unixSockTaskSem failed");
        return -1;
    }

    pthread_mutex_init(&vSock->cacheMutex, NULL);
    LIST_INIT(&vSock->inuseList);
    LIST_INIT(&vSock->freeList);

    for(i=0; i<VIRTIO_VSOCK_QUEUE_MAX_NUM; i++) {
        memset(&vSock->sockCache[i], 0x0, sizeof(struct vtsock_unix_socket));
        vSock->sockCache[i].state = SOCK_FREE;
        LIST_INSERT_HEAD(&vSock->freeList, &vSock->sockCache[i], list);
    }
    VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR, "sock list for cid %lld init .. OK\n", \
                             vSock->config.guest_cid);

    pthread_create(&vSock->tTaskUnixServer, NULL, taskUnixSocketServer, (void *)vSock);
    pthread_create(&vSock->tTaskUnixSockRx, NULL, taskUnixSockRecv, (void *)vSock);

    VIRTIO_VSOCK_DEV_DBG_MSG(VIRTIO_VSOCK_DEV_DBG_ERR, "unix socket tasks for cid %lld init .. OK\n", \
                             vSock->config.guest_cid);

    return 0;
}
