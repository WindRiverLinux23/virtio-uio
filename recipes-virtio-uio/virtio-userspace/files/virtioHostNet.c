/* virtioHostNet.c - virtio net host device */

/*
 * Copyright (c) 2022-2023 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

/*
   DESCRIPTION

   This is the application that supply a virtio net host driver, it provides
   the back-end driver support for the sending and receiving functions of
   virtio-net device on the host VM.
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
#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_ring.h>
#include <linux/virtio_config.h>
#include <linux/virtio_net.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include "virtioHostLib.h"
#include <syslog.h>

/*
 * Netlink headers
 */
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>


#undef VIRTIO_NET_DEV_DBG_ON
#ifdef VIRTIO_NET_DEV_DBG_ON

#define VIRTIO_NET_DEV_DBG_OFF             0x00000000
#define VIRTIO_NET_DEV_DBG_ISR             0x00000001
#define VIRTIO_NET_DEV_DBG_ARGS            0x00000020
#define VIRTIO_NET_DEV_DBG_ERR             0x00000100
#define VIRTIO_NET_DEV_DBG_INFO            0x00000200
#define VIRTIO_NET_DEV_DBG_ALL             0xffffffff

static uint32_t virtioNetDevDbgMask = VIRTIO_NET_DEV_DBG_ALL;

#undef VIRTIO_NET_DEV_DBG
#define VIRTIO_NET_DEV_DBG(mask, fmt, ...)				\
	do {								\
		if ((virtioNetDevDbgMask & (mask)) ||			\
		    ((mask) == VIRTIO_NET_DEV_DBG_ALL)) {		\
			printf("%d: %s() " fmt, __LINE__, __func__,	\
			       ##__VA_ARGS__);				\
		}							\
	}								\
while ((false))
#define log_err(fmt, ...)					\
	VIRTIO_NET_DEV_DBG(VIRTIO_NET_DEV_DBG_ERR, fmt,		\
			   ##__VA_ARGS__)
#else
#define VIRTIO_NET_DEV_DBG(...)
#define log_err(fmt, ...)					\
	syslog(LOG_ERR, "%d: %s() " fmt, __LINE__, __func__,	\
	       ##__VA_ARGS__)
#endif  /* REG_MAP_DBG_ON */


#define VIRTIO_NET_DRV_NAME         "virtio-net-host"

#define VIRTIO_NET_QUEUE_MAX     3     /* tx rx and cmd */
#define VIRTIO_NET_QUEUE_MAX_NUM 4096  /* max number of descriptors in a queue*/

#define VIRTIO_NET_IO_REQ_MAX    256

#define VIRTIO_NET_HOST_DEV_MAX  30
#define VIRTIO_NET_DISP_OBJ_MAX (VIRTIO_NET_QUEUE_MAX_NUM / VIRTIO_NET_IO_REQ_MAX * VIRTIO_NET_HOST_DEV_MAX)

#define VIRTIO_NET_RXQ           0
#define VIRTIO_NET_TXQ           1
#define VIRTIO_NET_CMDQ          2

#define VIRTIO_NET_RX_QUEUE(vhost)    (&vhost->pQueue[VIRTIO_NET_RXQ])
#define VIRTIO_NET_TX_QUEUE(vhost)    (&vhost->pQueue[VIRTIO_NET_TXQ])

#define ETHER_IS_MULTICAST(addr) (*(addr) & 0x01)

#define VIRTIO_HDR_LEN sizeof(struct virtio_net_hdr)

#define VIRTIO_NET_IP "192.168.1.1"
#define VIRTIO_NET_MASK 24

struct virtioNetConfig
{
	uint8_t mac[ETH_ALEN];
	uint16_t status;
	uint16_t max_virtqueue_pairs;
	uint16_t mtu;
	uint32_t speed;
	uint8_t duplex;
	uint8_t rss_max_key_size;
	uint16_t rss_max_indirection_table_length;
	uint32_t supported_hash_types;
};

struct virtioNetHostDev {
	struct virtioNetHostCtx {
		struct virtioHost vhost;
		struct virtioNetConfig cfg;
		uint64_t feature;
		pthread_t tx_thread;
		sem_t tx_sem;
		sem_t rx_sem;
		pthread_t rx_thread;
	} netHostCtx;

	struct virtioNetBeDevArgs {
		char tapType[IFNAMSIZ];
		char mac[6];
		struct virtioChannel channel[1];
	} beDevArgs;

	int tapfd;
	int epollfd;
	struct epoll_event ee;
};

struct virtioDispObj {
	TAILQ_ENTRY(virtioDispObj) link;
	struct virtioHostQueue *pQueue;
};

static struct virtioNetHostDrv {
	struct virtioNetHostDev * vNetHostDevList[VIRTIO_NET_HOST_DEV_MAX];
	uint32_t vNetHostDevNum;
	pthread_mutex_t drvMtx;
	TAILQ_HEAD(, virtioDispObj) dispFreeQ;
	TAILQ_HEAD(, virtioDispObj) dispBusyQ;
	pthread_t dispThread;
	pthread_mutex_t dispMtx;
	pthread_cond_t dispCond;
	struct virtioDispObj dispObj[VIRTIO_NET_DISP_OBJ_MAX];
} vNetHostDrv;

static int virtioHostNetReset(struct virtioHost *);
static void virtioHostNetNotify(struct virtioHostQueue *);
static int virtioHostNetCfgRead(struct virtioHost *, uint64_t, uint64_t size, uint32_t *);
static int virtioHostNetCfgWrite(struct virtioHost *, uint64_t, uint64_t, uint32_t);
static void* virtioHostNetReqDispatch(void *);
static void* virtioHostNetTxHandle(void *pNetHostCtx);
static void* virtioHostNetRxHandle(void *pNetHostCtx);
static int virtioHostNetCreate(struct virtioHostDev *);
static void virtioHostNetShow(struct virtioHost *, uint32_t);
static int virtioHostNetSetStatus(struct virtioHost * vHost, uint32_t status);

struct virtioHostOps virtioNetHostOps = {
	.reset    = virtioHostNetReset,
	.kick     = virtioHostNetNotify,
	.reqRead  = virtioHostNetCfgRead,
	.reqWrite = virtioHostNetCfgWrite,
	.show     = virtioHostNetShow,
	.setStatus = virtioHostNetSetStatus,
};

static struct virtioHostDrvInfo virtioNetHostDrvInfo =
{
	.typeId = VIRTIO_TYPE_NET,
	.create = virtioHostNetCreate,
};

/*******************************************************************************
 *
 * virtioHostNetDrvInit - initialize virtio-net host device driver
 *
 * This routine initializes the virtio-net host device driver.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

void virtioHostNetDrvInit(void)
{
	int ret, i;

	virtioHostDrvRegister((struct virtioHostDrvInfo *)&virtioNetHostDrvInfo);

	pthread_mutex_init(&vNetHostDrv.drvMtx, NULL);

	TAILQ_INIT(&vNetHostDrv.dispFreeQ);
	TAILQ_INIT(&vNetHostDrv.dispBusyQ);
	for (i = 0; i < VIRTIO_NET_DISP_OBJ_MAX; i++) {
		TAILQ_INSERT_HEAD(&vNetHostDrv.dispFreeQ,
				  &vNetHostDrv.dispObj[i], link);
	}
	pthread_mutex_init(&vNetHostDrv.dispMtx, NULL);
	pthread_cond_init(&vNetHostDrv.dispCond, NULL);

	ret = pthread_create(&vNetHostDrv.dispThread, NULL,
			     virtioHostNetReqDispatch, NULL);
	if (ret) {
		log_err("failed to create virtio net host dispatch thread\n");
	}
}

void virtioHostNetDrvRelease(void)
{
	uint32_t devNum;
	struct virtioNetHostDev *pNetHostDev;
	struct virtioNetHostCtx *pNetHostCtx;

	for (devNum = 0; devNum < vNetHostDrv.vNetHostDevNum; devNum++) {
		pNetHostDev = vNetHostDrv.vNetHostDevList[devNum];
		pNetHostCtx = (struct virtioNetHostCtx *)pNetHostDev;

		if (pNetHostDev) {
			if (pNetHostDev->epollfd > 0)
				close(pNetHostDev->epollfd);
			if (pNetHostDev->tapfd > 0)
				close(pNetHostDev->tapfd);
		}

		if (pNetHostCtx) {
			if (pNetHostCtx->tx_thread &&
			    pthread_cancel(pNetHostCtx->tx_thread) == 0)
				pthread_join(pNetHostCtx->tx_thread, NULL);
			if (pNetHostCtx->rx_thread &&
			    pthread_cancel(pNetHostCtx->rx_thread) == 0)
				pthread_join(pNetHostCtx->rx_thread, NULL);
			sem_destroy(&pNetHostCtx->tx_sem);
			sem_destroy(&pNetHostCtx->rx_sem);
		}

		virtioHostRelease(&pNetHostCtx->vhost);

		free(pNetHostDev);
	}
}

static int virtioNetParseMac(char *mac_str, uint8_t *mac_addr)
{
	struct ether_addr ether_addr;
	struct ether_addr *ea;
	char *tmpstr;
	char zero_addr[ETHER_ADDR_LEN] = { 0, 0, 0, 0, 0, 0 };

	tmpstr = strsep(&mac_str, "=");
	ea = &ether_addr;
	if ((mac_str != NULL) && (!strcmp(tmpstr, "mac"))) {
		ea = ether_aton(mac_str);

		if (ea == NULL || ETHER_IS_MULTICAST(ea->ether_addr_octet) ||
		    memcmp(ea->ether_addr_octet, zero_addr, ETHER_ADDR_LEN)
				== 0) {
			log_err("Invalid MAC %s\n", mac_str);
			return -1;
		}
		memcpy(mac_addr, ea->ether_addr_octet, ETHER_ADDR_LEN);
	}

	return 0;
}

static bool virtioNetIsMacvtap(char *devname, int *ifindex)
{
	char tempbuf[IFNAMSIZ];
	int rc;
	unsigned int ifidx;

	ifidx = if_nametoindex(devname);
	if (ifidx == 0)
		return false;

	*ifindex = ifidx;
	return true;
}

static int virtioNetTapOpen(char *devname)
{
	char tbuf[IFNAMSIZ];
	int tunfd, rc, macvtap_index;
	struct ifreq ifr;

	/*Check if tun/tap or macvtap interface is used */
	if (virtioNetIsMacvtap(devname, &macvtap_index)) {
		log_err("Interface %s is used\n", devname);
                return -1;
	}

	rc = snprintf(tbuf, IFNAMSIZ, "%s", "/dev/net/tun");
	if (rc < 0 || rc >= IFNAMSIZ) {
		log_err("Failed to set interface name %s\n", tbuf);
		return -1;
	}

	tunfd = open(tbuf, O_RDWR);
	if (tunfd < 0) {
		log_err("Failed to open interface %s\n", tbuf);
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_BROADCAST;

	if (*devname) {
		strncpy(ifr.ifr_name, devname, IFNAMSIZ);
		ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	}

	rc = ioctl(tunfd, TUNSETIFF, (void *)&ifr);
	if (rc < 0) {
		log_err("tap device %s creation failed: %s\n",
			devname, strerror(errno));
		close(tunfd);
		return -1;
	}

	strncpy(devname, ifr.ifr_name, IFNAMSIZ);
	return tunfd;
}

/*******************************************************************************
 *
 * virtioHostNetCreateWithTap - create virtio host net with net device
 *
 * This routine creates a virtio host net with tap device.
 *
 * RETURNS: 0, or negative values if the virtio host net device creating
 * failed.
 *
 * ERRNO: N/A
 */
static int virtioHostNetCreateWithTap(struct virtioNetHostDev *pNetHostDev)
{
	struct virtioNetBeDevArgs *pNetBeDevArgs = &pNetHostDev->beDevArgs;
	char buf[IFNAMSIZ];
	int opt = 1;
	int ret;

	ret = snprintf(buf, IFNAMSIZ, "%s", pNetBeDevArgs->tapType);
	if (ret < 0 || ret >= IFNAMSIZ) {
		log_err("failed to form net interface name(%d)\n", ret);
		return -1;
	}

	pNetHostDev->tapfd = virtioNetTapOpen(buf);
	if (pNetHostDev->tapfd == -1) {
		log_err("failed to open net interface %s\n", buf);
		return -1;
	}

	if (ioctl(pNetHostDev->tapfd, FIONBIO, &opt) < 0) {
		log_err("failed to open net interface to "
			"nonblocking mode\n");
		return -1;
	}

	return 0;
}

/*
 * Establish netlink connection
 *
 * Return: file descriptor on success or -1 on error
 */
static int virtioNetlinkConnect(void)
{
        int netlink_fd, rc;
        struct sockaddr_nl sockaddr;

        netlink_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (netlink_fd == -1) {
		log_err("Netlink socket open error: %s\n",
			strerror(errno));
                return -1;
        }

        memset(&sockaddr, 0, sizeof sockaddr);
        sockaddr.nl_family = AF_NETLINK;
        rc = bind(netlink_fd, (struct sockaddr*) &sockaddr, sizeof sockaddr);
        if (rc == -1) {
                int bind_errno = errno;

		close(netlink_fd);
                errno = bind_errno;
		log_err("Netlink socket bind error: %s\n",
			strerror(errno));
                return -1;
        }
        return netlink_fd;
}


static int virtioNetlinkSetAddrIpv4(int netlink_fd, const char *iface_name,
				    const char *address, uint8_t netmask_bits)
{
	struct {
		struct nlmsghdr  header;
		struct ifaddrmsg content;
		char             attributes_buf[64];
	} request;

	struct rtattr *request_attr;
	size_t attributes_buf_avail = sizeof request.attributes_buf;

	memset(&request, 0, sizeof(request));
	request.header.nlmsg_len = NLMSG_LENGTH(sizeof(request.content));
	request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_EXCL | NLM_F_CREATE;
	request.header.nlmsg_type = RTM_NEWADDR;
	request.content.ifa_index = if_nametoindex(iface_name);
	request.content.ifa_family = AF_INET;
	request.content.ifa_prefixlen = netmask_bits;

	/* request.attributes[IFA_LOCAL] = address */
	request_attr = IFA_RTA(&request.content);
	request_attr->rta_type = IFA_LOCAL;
	request_attr->rta_len = RTA_LENGTH(sizeof(struct in_addr));
	request.header.nlmsg_len += request_attr->rta_len;
	inet_pton(AF_INET, address, RTA_DATA(request_attr));

	/* request.attributes[IFA_ADDRESS] = address */
	request_attr = RTA_NEXT(request_attr, attributes_buf_avail);
	request_attr->rta_type = IFA_ADDRESS;
	request_attr->rta_len = RTA_LENGTH(sizeof(struct in_addr));
	request.header.nlmsg_len += request_attr->rta_len;
	inet_pton(AF_INET, address, RTA_DATA(request_attr));

	if (send(netlink_fd, &request, request.header.nlmsg_len, 0) == -1) {
		log_err("interface %s configuration error: %s\n",
			iface_name, strerror(errno));
		return -1;
	}
	return 0;
}

static int virtioNetlinkUp(int netlink_fd, const char *iface_name)
{
	struct {
		struct nlmsghdr  header;
		struct ifinfomsg content;
	} request;

	memset(&request, 0, sizeof request);
	request.header.nlmsg_len = NLMSG_LENGTH(sizeof request.content);
	request.header.nlmsg_flags = NLM_F_REQUEST;
	request.header.nlmsg_type = RTM_NEWLINK;
	request.content.ifi_index = if_nametoindex(iface_name);
	request.content.ifi_flags = IFF_UP;
	request.content.ifi_change = 1;

	if (send(netlink_fd, &request, request.header.nlmsg_len, 0) == -1) {
		log_err("interface %s up error: %s\n",
			iface_name, strerror(errno));
		return -1;
	}
	return 0;
}

/*******************************************************************************
 *
 * virtioHostNetBeDevCreate - create virtio net backend device
 *
 * This routine creates virtio net backend real device
 *
 * RETURNS: 0, or -1 if any error is raised in process of the backend net 
 * device creating.
 *
 * ERRNO: N/A
 */

static int virtioHostNetBeDevCreate(struct virtioNetHostDev *pNetHostDev)
{
	struct virtioNetHostCtx *pNetHostCtx = &pNetHostDev->netHostCtx;
	struct virtioNetBeDevArgs *pNetBeDevArgs = &pNetHostDev->beDevArgs;
	int ret;
	int netlink_fd;

	ret = virtioHostNetCreateWithTap(pNetHostDev);
	if (ret) {
		log_err("failed to create back-end device(%d)\n", ret);
		return ret;
	}

	memcpy(pNetHostCtx->cfg.mac, pNetHostDev->beDevArgs.mac, ETH_ALEN);

	/*
	 * Configure TAP interface
	 */
	netlink_fd = virtioNetlinkConnect();
        if (netlink_fd < 0) {
                return -1;
        }
	ret = virtioNetlinkSetAddrIpv4(netlink_fd, pNetBeDevArgs->tapType,
				       VIRTIO_NET_IP, VIRTIO_NET_MASK);
	if (ret != 0) {
		close(netlink_fd);
		return -1;
	}
	ret = virtioNetlinkUp(netlink_fd, pNetBeDevArgs->tapType);
	if (ret != 0) {
		close(netlink_fd);
		return -1;
	}
	close(netlink_fd);

	/* set device features */
	pNetHostCtx->feature = (1UL << VIRTIO_F_VERSION_1) |
		(1UL << VIRTIO_NET_F_MAC) |
		(1UL << VIRTIO_RING_F_INDIRECT_DESC) |
		(1UL << VIRTIO_NET_F_STATUS) |
		(1UL << VIRTIO_RING_F_EVENT_IDX);

	VIRTIO_NET_DEV_DBG(VIRTIO_NET_DEV_DBG_INFO,
			"pNetHostCtx->feature:0x%lx\n", pNetHostCtx->feature);

	return 0;
}

/*******************************************************************************
 *
 * virtioHostNetDevCreate - create virtio net device instance
 *
 * This routine creates and initializes create virtio net device instance.
 *
 * RETURNS: 0, or -1 if any error is raised in process of the net device
 * context creating.
 *
 * ERRNO: N/A
 */

static int virtioHostNetDevCreate(struct virtioNetHostDev *pNetHostDev)
{
	struct virtioNetHostCtx *pNetHostCtx;
	struct virtioNetBeDevArgs *pNetBeDevArgs;
	struct virtioHost *vhost;
	uint32_t devNum;
	int ret;

	vhost         = (struct virtioHost *)pNetHostDev;
	pNetHostCtx   = (struct virtioNetHostCtx *)pNetHostDev;
	pNetBeDevArgs = &pNetHostDev->beDevArgs;

	ret = virtioHostNetBeDevCreate(pNetHostDev);
	if (ret)
		goto err;

	vhost->channelId = pNetBeDevArgs->channel->channelId;
	vhost->pMaps = pNetBeDevArgs->channel->pMap;

	ret = virtioHostCreate(vhost,
			VIRTIO_DEV_ANY_ID,
			VIRTIO_ID_NET,
			&pNetHostCtx->feature,
			VIRTIO_NET_QUEUE_MAX,
			VIRTIO_NET_QUEUE_MAX_NUM,
			0, NULL,
			&virtioNetHostOps);
	if (ret) {
		log_err("virtio net host context creating failed %d\n",
			ret);
		goto err;
	}

	pthread_mutex_lock(&vNetHostDrv.drvMtx);
	vNetHostDrv.vNetHostDevList[vNetHostDrv.vNetHostDevNum] = pNetHostDev;
	devNum = vNetHostDrv.vNetHostDevNum++;
	pthread_mutex_unlock(&vNetHostDrv.drvMtx);

	pNetHostDev->epollfd = epoll_create1(0);
	if (pNetHostDev->epollfd < 0) {
		log_err("failed to create epoll fd(%d): %s\n",
			pNetHostDev->epollfd, strerror(errno));
		goto err;
	}
	pNetHostDev->ee.data.fd = pNetHostDev->tapfd;
	pNetHostDev->ee.events = EPOLLIN;
	ret = epoll_ctl(pNetHostDev->epollfd, EPOLL_CTL_ADD,
			pNetHostDev->tapfd, &pNetHostDev->ee);
	if (ret) {
		log_err("failed to set up epoll fd(%d): %s\n",
			ret, strerror(errno));
		goto err;
	}

	ret = sem_init(&pNetHostCtx->tx_sem, 0, 0);
	if (ret) {
		log_err("Failed to create tx sem(%d): %s\n",
			ret, strerror(errno));
		goto err;
	}
	ret = sem_init(&pNetHostCtx->rx_sem, 0, 0);
	if (ret) {
		log_err("Failed to create rx sem(%d): %s\n",
			ret, strerror(errno));
		goto err;
	}

	ret = pthread_create(&pNetHostCtx->tx_thread, NULL,
			     virtioHostNetTxHandle, pNetHostCtx);
	if (ret) {
		log_err("failed to create tx worker thread(%d): %s\n",
			ret, strerror(errno));
		goto err;
	}

	ret = pthread_create(&pNetHostCtx->rx_thread, NULL,
			     virtioHostNetRxHandle, pNetHostCtx);
	if (ret) {
		log_err("failed to create rx worker thread(%d): %s\n",
			ret, strerror(errno));
		goto err;
	}

	return 0;

err:
	virtioHostNetDrvRelease();
	return -1;
}

/*******************************************************************************
 *
 * virtioHostNetParseArgs - parse argument list of virtio net device
 *
 * This routine parses argument list of virtio net device.
 *
 * RETURNS: 0, or negative value of errno number if any error is raised
 * in process of the parsing.
 *
 * ERRNO: N/A
 */

static int virtioHostNetParseArgs(struct virtioNetBeDevArgs *pNetBeDevArgs,
				  char *pArgs)
{
	char *nopt, *xopts, *cp;
	int ret = 0;

	VIRTIO_NET_DEV_DBG(VIRTIO_NET_DEV_DBG_INFO,
			"virtioHostNetParseArgs %s\n", pArgs);

	nopt = xopts = strdup(pArgs);
	if (!nopt) {
		log_err("failed to strdup pArgs\n");
		return -EINVAL;
	}

	while (xopts != NULL) {
		cp = strsep(&xopts, ",");
		if (cp == nopt) { /* file or device pathname */
			if (!strncmp(cp, "tap=", 4)) {
				strncpy(pNetBeDevArgs->tapType, nopt + 4,
					strlen(nopt + 4));
			} else {
				log_err("device option must start "
					"with tap=\n");
			}
			continue;
		} else if (!strncmp(cp, "mac=", 4)) {
			virtioNetParseMac(cp, pNetBeDevArgs->mac);
		} else {
			VIRTIO_NET_DEV_DBG(VIRTIO_NET_DEV_DBG_INFO,
					"invalid device option(%s)\n", cp);
			ret = -EINVAL;
			goto err;
		}
	}

#ifdef VIRTIO_NET_DEV_DBG_ON
	VIRTIO_NET_DEV_DBG(VIRTIO_NET_DEV_DBG_ARGS, "back device arguments\n");
	VIRTIO_NET_DEV_DBG(VIRTIO_NET_DEV_DBG_ARGS,
			"\t back device [%s]\n", pNetBeDevArgs->tapType);
	VIRTIO_NET_DEV_DBG(VIRTIO_NET_DEV_DBG_ARGS,
                        "\t MAC address %02x:%02x:%02x:%02x:%02x:%02x\n",
                           pNetBeDevArgs->mac[0],
                           pNetBeDevArgs->mac[1],
                           pNetBeDevArgs->mac[2],
                           pNetBeDevArgs->mac[3],
                           pNetBeDevArgs->mac[4],
                           pNetBeDevArgs->mac[5]
		);
#endif /* VIRTIO_NET_DEV_DBG_ON */

err:
	if (nopt)
		free(nopt);

	return ret;
}

/*******************************************************************************
 *
 * virtioHostNetCreate - create a virtio net device
 *
 * This routine creates a virtio net device backend driver to simuilate
 * a real net device.
 *
 * RETURNS: 0, or negative value of errno number if any error is raised
 * in process of the net device creating.
 *
 * ERRNO: N/A
 */

static int virtioHostNetCreate(struct virtioHostDev *pHostDev)
{
	struct virtioNetHostDev *pNetHostDev;
	struct virtioNetBeDevArgs *pBeDevArgs;
	struct virtioNetHostCtx *pNetHostCtx;
	char *pBuf;
	int ret;

	VIRTIO_NET_DEV_DBG(VIRTIO_NET_DEV_DBG_INFO, "start\n");

	if (!pHostDev) {
		log_err("pChannel is NULL!\n");
		return -EINVAL;
	}

	/* the virtio channel number is always one */
	if (pHostDev->channelNum > 1) {
		log_err("channel number is %d "
			"only one channel is supported\n",
			pHostDev->channelNum);
		return -EINVAL;
	}

	VIRTIO_NET_DEV_DBG(VIRTIO_NET_DEV_DBG_INFO, "\n"
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

	if (vNetHostDrv.vNetHostDevNum == VIRTIO_NET_HOST_DEV_MAX) {
		log_err("no more than %d net devices can be created\n",
			VIRTIO_NET_HOST_DEV_MAX);
		return -ENOENT;
	}

	VIRTIO_NET_DEV_DBG(VIRTIO_NET_DEV_DBG_INFO,
			"sizeof(struct virtioNetHostDev) %ld bytes\n",
			sizeof(struct virtioNetHostDev));

	pNetHostDev = calloc(1, sizeof(struct virtioNetHostDev));
	if (!pNetHostDev) {
		log_err("failed to allocate memory for "
			"virtio net host device failed\n");
		return -ENOMEM;
	}

	pNetHostDev->tapfd = -1;

	/* allocate a buffer and copy the argument list to it */
	pBeDevArgs = &pNetHostDev->beDevArgs;

	pBuf = pHostDev->args;
	pHostDev->args[PATH_MAX - 1] = '\0';

	ret = virtioHostNetParseArgs(pBeDevArgs, pBuf);
	if (ret)
		goto exit;

	memcpy((void *)pBeDevArgs->channel, (void *)pHostDev->channels,
	       sizeof(struct virtioChannel));

	ret = virtioHostNetDevCreate(pNetHostDev);
exit:
	if (ret) {
		free(pNetHostDev);
		return ret;
	}

	pNetHostCtx = &pNetHostDev->netHostCtx;
	pNetHostCtx->cfg.status |= VIRTIO_NET_S_LINK_UP;

	VIRTIO_NET_DEV_DBG(VIRTIO_NET_DEV_DBG_INFO, "done\n");

	return 0;
}

/*******************************************************************************
 *
 * virtioHostNetAbort - abort a request handling
 *
 * This routine is used to abort a request handling when a request is seen
 * with incorrect format, which will be abandoned.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void virtioHostNetAbort(struct virtioHostQueue *pQueue, uint16_t idx)
{
	if (idx < pQueue->vRing.num) {
		(void)virtioHostQueueRelBuf(pQueue, idx, 1);
		(void)virtioHostQueueNotify(pQueue);
	}

	return;
}

/*******************************************************************************
 *
 * virtioHostNetReqDispatch - virtio net device dispatch task
 *
 * This routine is used to dispatch virtio net device IO requests to specific
 * handling thread(s).
 *
 * RETURNS: 0, or -1 if the recieved operation request with a invalid format or
 * error meeting a failure in process of filesystem operation.
 *
 * ERRNO: N/A
 */

static void* virtioHostNetReqDispatch(void *my_unused)
{
	struct virtioNetHostCtx *pNetHostCtx;
	struct virtioDispObj *pDispObj;
	int ret;

	pthread_mutex_lock(&vNetHostDrv.dispMtx);

	while (1) {
		while (1) {
			if (TAILQ_EMPTY(&vNetHostDrv.dispBusyQ))
				break;

			pDispObj = TAILQ_FIRST(&vNetHostDrv.dispBusyQ);
			if (pDispObj) {
				TAILQ_REMOVE(&vNetHostDrv.dispBusyQ, pDispObj, link);
			} else {
				log_err("failed to get dispatch object "
					"from busy queue\n");
			}

			pthread_mutex_unlock(&vNetHostDrv.dispMtx);

			if (pDispObj && pDispObj->pQueue &&
			    pDispObj->pQueue->vHost) {
				pNetHostCtx =
					(struct virtioNetHostCtx *)
					pDispObj->pQueue->vHost;
				if (pDispObj->pQueue ==
				    &pDispObj->pQueue->vHost->pQueue[VIRTIO_NET_TXQ]) {
					ret = sem_post(&pNetHostCtx->tx_sem);
					if (ret) {
						log_err("failed to sem_post "
							"tx_sem: %s\n",
							strerror(errno));
					}
				}
				if (pDispObj->pQueue ==
				    &pDispObj->pQueue->vHost->pQueue[VIRTIO_NET_RXQ]) {
					ret = sem_post(&pNetHostCtx->rx_sem);
					if (ret) {
						log_err("failed to sem_post "
							"tx_sem: %s\n",
							strerror(errno));
					}
				}
			} else {
				log_err("failed to get virtqueue from busy object\n");
			}

			pthread_mutex_lock(&vNetHostDrv.dispMtx);

			TAILQ_INSERT_TAIL(&vNetHostDrv.dispFreeQ, pDispObj, link);
		}

		pthread_cond_wait(&vNetHostDrv.dispCond, &vNetHostDrv.dispMtx);
	}

	pthread_mutex_unlock(&vNetHostDrv.dispMtx);

	return NULL;
}

/**
 * Remove VirtIO header from the ethernet packet before sending it to
 * the tap device
 *
 * @buffs: buffers received from virtqueue
 * @niov: pointer to the number fo the buffers
 * @hlen: the VirtIO header length
 */
static struct virtioHostBuf* txIovTrim(struct virtioHostBuf *buffs,
				       int *nbuffs, int hlen)
{
	struct virtioHostBuf* rbuffs = NULL;
	int i;
	int _nbuf = *nbuffs;
	uint32_t offset = 0;

	for (i = 0; i < _nbuf; i++) {
		if (buffs[i].len == 0) {
			/* Why should this happen? */
			continue;
		}
		if (buffs[i].len <= hlen) {
			/*
			 * VirtIO header spans across several buffers
			 */
			VIRTIO_NET_DEV_DBG(
				VIRTIO_NET_DEV_DBG_INFO,
				"buf_len=%u, tlen=%d\n",
				buffs[i].len, hlen);
			hlen -= buffs[i].len;
		} else {
			/*
			 * Subtract VirtIO header from the buffer
			 */
			rbuffs = &buffs[i];
			buffs[i].len -= hlen;
			buffs[i].buf += hlen;
			*nbuffs -= i;
			break;
		}
	}
	return rbuffs;
}

/*******************************************************************************
 *
 * virtioHostNetTxHandle - virtio net device handle task
 *
 * This routine is used to handle virtio net device read or write operations.
 *
 * RETURNS: 0, or -1 if the recieved operation request with a invalid format or
 * error meeting a failure in process of filesystem operation.
 *
 * ERRNO: N/A
 */

static void* virtioHostNetTxHandle(void *pNetHostCtx)
{
	int n, i, len, ret;
	uint16_t idx;
	struct virtioHost *vhost;
	struct virtioNetHostCtx *vNetHostCtx = pNetHostCtx;
	struct virtioNetHostDev *vNetHostDev;
	struct virtioHostBuf bufList[VIRTIO_NET_IO_REQ_MAX];
	struct iovec iov[VIRTIO_NET_IO_REQ_MAX];
	static char pad[ETH_ZLEN] = { 0 };
	struct virtioHostBuf* rbuffs;
	struct virtioHostQueue* txQueue;

	vhost = (struct virtioHost *)vNetHostCtx;
	vNetHostDev = (struct virtioNetHostDev *)vNetHostCtx;
	txQueue = &vhost->pQueue[VIRTIO_NET_TXQ];

        while(1) {
                ret = sem_wait(&vNetHostCtx->tx_sem);
                if (ret < 0) {
			log_err("failed to sem_wait tx_sem: %s\n",
				strerror(errno));
                        continue;
                }

		while (1) {
			/* Get one chain of buffers from the virtqueue */
			n = virtioHostQueueGetBuf(txQueue, &idx, bufList,
						  VIRTIO_NET_IO_REQ_MAX);
			if (n == 0) {
				VIRTIO_NET_DEV_DBG(VIRTIO_NET_DEV_DBG_INFO,
						"no new queue buffer\n");

				/* Re-enable kick from FE driver */
				virtioHostQueueIntrEnable(txQueue);
				(void)virtioHostQueueNotify(txQueue);
				break;
			}

			if (n < 0) {
				log_err("failed to get buffer(%d)\n", n);
				break;
			}

			/* Skip the VirtIO header descriptor */
		        rbuffs = txIovTrim(bufList, &n,
					   VIRTIO_HDR_LEN + 2);
			if (rbuffs == NULL) {
				log_err("received buffers are smaller than "
					"VirtIO header\n");
				break;
			}
			len = 0;
			for (i = 0; i < n; i++) {
                                iov[i].iov_base = rbuffs[i].buf;
                                iov[i].iov_len = rbuffs[i].len;
                                len += rbuffs[i].len;
                        }
                        if (len < ETH_ZLEN) {
                                iov[n].iov_base = pad;
                                iov[n].iov_len = ETH_ZLEN - len;
				VIRTIO_NET_DEV_DBG(VIRTIO_NET_DEV_DBG_INFO,
						   "padding %d bytes\n",
						   ETH_ZLEN - len);
                        }

			VIRTIO_NET_DEV_DBG(VIRTIO_NET_DEV_DBG_INFO,
					   "writev %d bytes\n", len);

			ret = writev(vNetHostDev->tapfd, iov,
				     len < ETH_ZLEN ? n : n + 1);
			if (ret < 0) {
				log_err("failed to writev(%s)\n",
					strerror(ret));
				(void) virtioHostQueueRetBuf(txQueue);
				break;
			}

			(void)virtioHostQueueRelBuf(txQueue, idx,
						    ret + VIRTIO_HDR_LEN);
		}
	}
}

/**
 * Fill in VirtIO header
 *
 * @hdr: VirtIO header to fill in
 */
static void virtioHdr(struct virtio_net_hdr* hdr)
{
	//FIXME: do we need to add TCP or UDP header length
	hdr->hdr_len = ETH_HLEN + sizeof(struct iphdr);
	hdr->csum_start = ETH_HLEN + sizeof(struct iphdr);
	hdr->gso_type = VIRTIO_NET_HDR_GSO_NONE;
	hdr->flags = 0U;
}

/*******************************************************************************
 *
 * virtioHostNetRxHandle - virtio net device handle task
 *
 * This routine is used to handle virtio net device read or write operations.
 *
 * RETURNS: 0, or -1 if the recieved operation request with a invalid format or
 * error meeting a failure in process of filesystem operation.
 *
 * ERRNO: N/A
 */

static void* virtioHostNetRxHandle(void *pNetHostCtx)
{
	int n, i, ret;
	uint16_t idx;
	struct virtioHost *vhost;
	struct virtioNetHostCtx *vNetHostCtx = pNetHostCtx;
	struct virtioNetHostDev *vNetHostDev;
	struct epoll_event eventlist[64];
	struct virtioHostBuf bufList[VIRTIO_NET_IO_REQ_MAX];
	struct iovec iov[VIRTIO_NET_IO_REQ_MAX];
	static char pad[ETH_ZLEN] = { 0 };
	struct virtio_net_hdr* hdr = NULL;
	struct virtioHostQueue* rxQueue;
	const uint32_t hdrLen = VIRTIO_HDR_LEN + 2;

	vhost = (struct virtioHost *)vNetHostCtx;
	vNetHostDev = (struct virtioNetHostDev *)vNetHostCtx;
	rxQueue = &vhost->pQueue[VIRTIO_NET_RXQ];

        while(1) {
                ret = sem_wait(&vNetHostCtx->rx_sem);
                if (ret < 0) {
			log_err("failed to sem_wait rx_sem: %s\n",
				strerror(errno));
                        continue;
                }
		while(1) {
			ret = epoll_wait(vNetHostDev->epollfd, eventlist,
					 64, -1);
			if (ret == -1 && errno != EINTR) {
				log_err("failed to epoll wait(%d)\n",
					ret);
				continue;
			}

			VIRTIO_NET_DEV_DBG(VIRTIO_NET_DEV_DBG_INFO,
					   "start\n");

			/* Get one chain of buffers from the virtqueue */

			n = virtioHostQueueGetBuf(rxQueue,
						  &idx, bufList,
						  VIRTIO_NET_IO_REQ_MAX);
			if (n == 0) {
				VIRTIO_NET_DEV_DBG(VIRTIO_NET_DEV_DBG_INFO,
						   "no new queue buffer\n");

				/* Re-enable kick from FE driver */
				virtioHostQueueIntrEnable(rxQueue);
				(void)virtioHostQueueNotify(rxQueue);
				break;
			} else if (n < 0) {
				log_err("failed to get buffer(%d)\n", n);
				break;
			} else {

				/*
				 * Fill the first buffet with the VirtIO
				 * structure
				 */
				hdr = (struct virtio_net_hdr *)bufList[0].buf;
				bzero(hdr, hdrLen);
				virtioHdr(hdr);

				iov[0].iov_base = bufList[0].buf +
					hdrLen;
				iov[0].iov_len = bufList[0].len - hdrLen;
				for (i = 1; i < n; i++) {
					iov[i].iov_base = bufList[i].buf;
					iov[i].iov_len = bufList[i].len;
				}
				ret = readv(vNetHostDev->tapfd, iov, n);
				if (ret < 0) {
					log_err("failed to readv(%s)\n",
						strerror(ret));
					(void) virtioHostQueueRetBuf(rxQueue);
				} else {
					VIRTIO_NET_DEV_DBG(
						VIRTIO_NET_DEV_DBG_INFO,
						"readv: %d bytes\n",
						ret);
					(void)virtioHostQueueRelBuf(
						rxQueue, idx,
						ret + hdrLen);
					virtioHostQueueIntrEnable(rxQueue);
					(void)virtioHostQueueNotify(rxQueue);
				}
				VIRTIO_NET_DEV_DBG(VIRTIO_NET_DEV_DBG_INFO,
						   "done\n");
			}
		}
	}
}

/*******************************************************************************
 *
 * virtioHostNetNotify - notify of a new arrived io-request
 *
 * This routine is used to notify the handler that an new recieved io-request
 * in virtio queue.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */

static void virtioHostNetNotify(struct virtioHostQueue *pQueue)
{
	int ret;
	struct virtioHost *vHost;
	struct virtioDispObj *pDispObj;

	if (!pQueue) {
		log_err("null pQueue\n");
		return;
	}

	vHost = (struct virtioHost *)pQueue->vHost;

	if (pQueue->vHost && (pQueue->vHost->status &
			      VIRTIO_CONFIG_S_DRIVER_OK) != 0) {
		pthread_mutex_lock(&vNetHostDrv.dispMtx);
		if (!TAILQ_EMPTY(&vNetHostDrv.dispFreeQ)) {
			pDispObj = TAILQ_FIRST(&vNetHostDrv.dispFreeQ);
			if (!pDispObj) {
				log_err("failed to get dispatch object from "
					"free queue\n");
				pthread_mutex_unlock(&vNetHostDrv.dispMtx);
				return;
			}

			/* Disable kick from FE driver during handling requests */
			virtioHostQueueIntrDisable(pQueue);

			TAILQ_REMOVE(&vNetHostDrv.dispFreeQ, pDispObj, link);
			pDispObj->pQueue = pQueue;
			TAILQ_INSERT_TAIL(&vNetHostDrv.dispBusyQ, pDispObj, link);

			pthread_cond_signal(&vNetHostDrv.dispCond);
		} else {
			log_err("No object in dispatch free queue\n");
		}
		pthread_mutex_unlock(&vNetHostDrv.dispMtx);
	}

	return;
}

/*******************************************************************************
 *
 * virtioHostNetReset - reset virtio net device
 *
 * This routine is used to reset the virtio net device. All the configuration
 * settings setted by customer driver will be cleared and all the backend
 * driver software flags are reset to initial status.
 *
 * RETURNS: 0, or -1 if failure raised in process of restarting the device.
 *
 * ERRNO: N/A
 */

static int virtioHostNetReset(struct virtioHost *vHost)
{
	struct virtioNetHostCtx *vNetHostCtx;

	vNetHostCtx = (struct virtioNetHostCtx *)vHost;
	if (!vNetHostCtx) {
		log_err("null vNetHostCtx\n");
		return -1;
	}
	vNetHostCtx->cfg.status = 0;

	VIRTIO_NET_DEV_DBG(VIRTIO_NET_DEV_DBG_INFO,
			   "device reset\n");
	return 0;
}

/*******************************************************************************
 *
 * virtioHostNetCfgRead - read virtio net specific configuration register
 *
 * This routine is used to read virtio net specific configuration register,
 * the value read out is stored in the request buffer.
 *
 * RETURN: 0, or errno if the to be read register is non-existed.
 *
 * ERRNO: N/A
 */

static int virtioHostNetCfgRead(struct virtioHost *vHost, uint64_t address,
		uint64_t size, uint32_t *pValue)
{
	struct virtioNetHostCtx *vNetHostCtx;
	uint8_t *cfgAddr;

	if (!vHost) {
		log_err("null vHost\n");
		return -EINVAL;
	}

	vNetHostCtx = (struct virtioNetHostCtx *)vHost;

	cfgAddr = (uint8_t *)&vNetHostCtx->cfg + address;

	(void)memcpy((void *)pValue, (void *)cfgAddr, (size_t)size);

	return 0;
}

/*******************************************************************************
 *
 * virtioHostNetCfgWrite - set virtio net specific configuration register
 *
 * This routine is used to set virtio net specific configuration register,
 * the setting value is stored in the request buffer.
 *
 * RETURN: 0, or errno if the to be read register is non-existed.
 *
 * ERRNO: N/A
 */

static int virtioHostNetCfgWrite(struct virtioHost *vHost, uint64_t address,
		uint64_t size, uint32_t value)
{
	struct virtioNetHostCtx *pNetHostCtx;
	struct virtioNetHostDev *pNetHostDev;
	uint8_t *cfgAddr;

	if (!vHost) {
		log_err("null vHost\n");
		return -EINVAL;
	}

	log_err("failed to write to read-only register %ld\n",
		host_virtio64_to_cpu(vHost, address));

	/* No writiable options so far */
	return -EINVAL;
}

/*******************************************************************************
 *
 * virtioHostNetShow - virtio net host device show
 *
 * This routine shows the virtio net host device setting and configurations.
 *
 * RETURN: 0 aleays.
 *
 * ERRNO: N/A
 */

static void virtioHostNetShow(struct virtioHost * vHost, uint32_t indent)
{
	struct virtioNetHostDev *vNetHostDev;

	vNetHostDev = (struct virtioNetHostDev *)vHost;

	printf("%*sdriver [%s]\n", (indent + 1) * 3, "", VIRTIO_NET_DRV_NAME);
	printf("%*stap [%s]\n", (indent + 2) * 3, "", vNetHostDev->beDevArgs.tapType);
	printf("%*smac [%s]\n", (indent + 2) * 3, "", vNetHostDev->beDevArgs.mac);
}

/*******************************************************************************
 *
 * virtioHostNetSetStatus - initialize virtioHostNet status
 *
 * This routine is used to initialize virtioHostNet status when receiving reset
 * signal from guest.
 *
 * RETURNS: 0, or -1 if failure raised in process of changing status.
 *
 * ERRNO: N/A
 */

static int virtioHostNetSetStatus(struct virtioHost* vHost, uint32_t status)
{
	struct virtioHostQueue* pQueue;
	if (!vHost) {
		log_err("null vHost\n");
		return -EINVAL;
	}
	VIRTIO_NET_DEV_DBG(VIRTIO_NET_DEV_DBG_INFO,
			   "set status 0x%x\n", status);
	if ((status & VIRTIO_CONFIG_S_DRIVER_OK) != 0) {
		/*
		 * Enable interrupts to update the vring available
		 * event index
		 */
		pQueue = VIRTIO_NET_TX_QUEUE(vHost);
		(void)virtioHostQueueIntrEnable(pQueue);

		pQueue = VIRTIO_NET_RX_QUEUE(vHost);
		(void)virtioHostQueueIntrEnable(pQueue);

		/*
		 * Notify driver to make it update the vring used
		 * event index
		 */
		vHost->intStatus |= VIRTIO_MMIO_INT_VRING;
		(void)vHost->pVsmOps->notify(vHost->pVsmQueue,
					     vHost, vHost->intStatus);
	}
	return 0;
}
