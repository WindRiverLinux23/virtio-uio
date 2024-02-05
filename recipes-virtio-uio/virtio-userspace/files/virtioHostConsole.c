/* virtio_host_console.c - virtio console host device */

/*
 * Copyright (c) 2022-2023 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

/*
   DESCRIPTION

   This is the application that supply a virtio console host driver, it provides
   the back-end storage media support for the reading and writing functions
   of virtio-console device on the host VM.
*/

#define _GNU_SOURCE
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/param.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <termios.h>
#include <limits.h>
#include <linux/virtio_console.h>
#include "mevent.h"
#include "virtioHostLib.h"

#define container_of(ptr, type, member) ({ \
		const typeof( ((type *)0)->member ) *__mptr = (ptr); \
		(type *)( (char *)__mptr - offsetof(type,member) );})

#undef VIRTIO_CONSOLE_DEV_DUMP_PACKETS
#define VIRTIO_CONSOLE_DEV_DBG_ON
#ifdef VIRTIO_CONSOLE_DEV_DBG_ON

#define VIRTIO_CONSOLE_DEV_DBG_OFF             0x00000000
#define VIRTIO_CONSOLE_DEV_DBG_ISR             0x00000001
#define VIRTIO_CONSOLE_DEV_DBG_ARGS            0x00000020
#define VIRTIO_CONSOLE_DEV_DBG_ERR             0x00000100
#define VIRTIO_CONSOLE_DEV_DBG_INFO            0x00000200
#define VIRTIO_CONSOLE_DEV_DBG_ALL             0xffffffff

static uint32_t virtioConsoleDevDbgMask =  VIRTIO_CONSOLE_DEV_DBG_ERR;

#undef VIRTIO_CONSOLE_DEV_DBG
#define VIRTIO_CONSOLE_DEV_DBG(mask, fmt, ...)				\
	do {								\
		if ((virtioConsoleDevDbgMask & (mask)) ||			\
		    ((mask) == VIRTIO_CONSOLE_DEV_DBG_ALL)) {		\
			printf("%d: %s() " fmt, __LINE__, __func__,	\
			       ##__VA_ARGS__);				\
		}							\
	}								\
while ((false))
#else
#define VIRTIO_CONSOLE_DEV_DBG(...)
#endif

#define VIRTIO_CONSOLE_DRV_NAME         "virtio-console-host"
#define VIRTIO_CONSOLE_QUEUE_MAX_NUM    128
#define VIRTIO_CONSOLE_IO_REQ_MAX       64
#define VIRTIO_CONSOLE_BUF_SIZE_MAX     1024
#define VIRTIO_CONSOLE_HOST_DEV_MAX     30
#define VIRTIO_CONSOLE_DISP_OBJ_MAX (VIRTIO_CONSOLE_QUEUE_MAX_NUM / VIRTIO_CONSOLE_IO_REQ_MAX * VIRTIO_CONSOLE_HOST_DEV_MAX)

#define VIRTIO_CONSOLE_MAXPORTS 16
#define VIRTIO_CONSOLE_MAXQ     (VIRTIO_CONSOLE_MAXPORTS * 2 + 2)

enum virtioConsoleBeType {
	VIRTIO_CONSOLE_BE_STDIO = 0,
	VIRTIO_CONSOLE_BE_TTY,
	VIRTIO_CONSOLE_BE_PTY,
	VIRTIO_CONSOLE_BE_FILE,
	VIRTIO_CONSOLE_BE_SOCKET,
	VIRTIO_CONSOLE_BE_MAX,
	VIRTIO_CONSOLE_BE_INVALID = VIRTIO_CONSOLE_BE_MAX
};

#define VIRTIO_CONSOLE_BE_SOCKET_SERVER 1
#define VIRTIO_CONSOLE_BE_SOCKET_CLIENT 2

static const char *virtioConsoleBeTable[VIRTIO_CONSOLE_BE_MAX] = {
	[VIRTIO_CONSOLE_BE_STDIO]	= "stdio",
	[VIRTIO_CONSOLE_BE_TTY]		= "tty",
	[VIRTIO_CONSOLE_BE_PTY]		= "pty",
	[VIRTIO_CONSOLE_BE_FILE]	= "file",
	[VIRTIO_CONSOLE_BE_SOCKET]	= "socket"
};

struct virtioConsolePort {
	struct virtioConsoleHostDev *pConsoleHostDev;
	int			id;
	const char		*name;
	bool			enabled;
	bool			is_console;
	bool			rx_ready;
	bool			open;
	int			rxq;
	int			txq;
	void			*arg;
	pthread_t		tx_thread;
	sem_t			tx_sem;
};

struct virtioConsoleBackend {
	struct virtioConsolePort	*port;
	struct mevent			*evp;
	struct mevent			*conn_evp;
	int				fd;
	int				server_fd;
	bool				open;
	enum virtioConsoleBeType	be_type;
	int				pts_fd;	/* only valid for PTY */
	const char 			*path;
	int				socket_type;
};

struct virtioConsoleBePortArgs {
	char name[NAME_MAX + 1];          /* backend name       */
	char path[PATH_MAX + 1];          /* backend path       */
	bool is_console;                  /* backend is console */
	enum virtioConsoleBeType be_type; /* BE type            */
	int socket_type;                  /* socket type        */
};

struct virtioConsoleHostDev {
	struct virtioConsoleHostCtx {
		struct virtioHost vhost;
		struct virtio_console_config cfg;
		uint64_t feature;
		uint32_t nports;
		uint32_t queues;
		struct virtioConsolePort controlPort;
		struct virtioConsolePort ports[VIRTIO_CONSOLE_MAXPORTS];
	} consoleHostCtx;

	struct virtioConsoleBeDevArgs {
		bool multiport;            /* multi port         */
		uint32_t nports;           /* number of ports    */
		uint32_t queues;           /* number of queues   */
		struct virtioChannel channel[1];
		struct virtioConsoleBePortArgs ports[VIRTIO_CONSOLE_MAXPORTS];
	} beDevArgs;

	int refCount;
	bool ready;
};

struct virtioDispObj {
	TAILQ_ENTRY(virtioDispObj) link;
	struct virtioHostQueue *pQueue;
};

static struct virtioConsoleHostDrv {
	struct virtioConsoleHostDev *vConsoleHostDevList[VIRTIO_CONSOLE_HOST_DEV_MAX];
	uint32_t vConsoleHostDevNum;
	pthread_mutex_t drvMtx;
	TAILQ_HEAD(, virtioDispObj) dispFreeQ;
	TAILQ_HEAD(, virtioDispObj) dispBusyQ;
	pthread_t dispThread;
	pthread_mutex_t dispMtx;
	pthread_cond_t dispCond;
	struct virtioDispObj dispObj[VIRTIO_CONSOLE_DISP_OBJ_MAX];
} vConsoleHostDrv;

static int virtioHostConsoleReset(struct virtioHost *);
static void virtioHostConsoleNotify(struct virtioHostQueue *);
static int virtioHostConsoleCfgRead(struct virtioHost *, uint64_t, uint64_t size, uint32_t *);
static int virtioHostConsoleCfgWrite(struct virtioHost *, uint64_t, uint64_t, uint32_t);
static void virtioHostConsoleDone(uint16_t idx, struct virtioHostQueue *, uint32_t);
static int virtioHostConsoleCreate(struct virtioHostDev *);
static void virtioHostConsoleShow(struct virtioHost *, uint32_t);
static void virtioHostConsoleAbort(struct virtioHostQueue *pQueue, uint16_t idx);
static void virtioConsoleOpenPort(struct virtioConsolePort *port, bool open);
static void virtioConsoleBackendRead(int fd __attribute__((unused)),
			    enum ev_type t __attribute__((unused)),
			    void *arg);
static void virtioConsoleRestoreStdio(void);
static void* virtioHostConsoleReqDispatch(void *);
static void virtioHostConsoleReqHandleRx(struct virtioConsolePort *pConsolePort);
static void* virtioHostConsoleReqHandleTx(void *arg);
static void* virtioHostConsoleReqHandleControlTx(void *arg);

struct virtioHostOps virtioConsoleHostOps = {
	.reset    = virtioHostConsoleReset,
	.kick     = virtioHostConsoleNotify,
	.reqRead  = virtioHostConsoleCfgRead,
	.reqWrite = virtioHostConsoleCfgWrite,
	.show     = virtioHostConsoleShow,
};

static struct virtioHostDrvInfo HostDrvInfo =
{
	.typeId = VIRTIO_TYPE_CONSOLE,
	.create = virtioHostConsoleCreate,
};

bool stdio_in_use = false;
static struct termios virtio_console_saved_tio;
static int virtio_console_saved_flags;

pthread_t virtioHostMeventDispatchThread;
void* virtioHostMeventDispatch(void *)
{
	mevent_init();
	mevent_dispatch();
}

/*******************************************************************************
 *
 * virtioHostConsoleDrvInit - initialize console host device driver
 *
 * This routine initializes the console host device driver.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */
void virtioHostConsoleDrvInit(void)
{
	int ret, i;

	virtioHostDrvRegister((struct virtioHostDrvInfo *)&HostDrvInfo);

	pthread_mutex_init(&vConsoleHostDrv.drvMtx, NULL);

	TAILQ_INIT(&vConsoleHostDrv.dispFreeQ);
	TAILQ_INIT(&vConsoleHostDrv.dispBusyQ);
	for (i = 0; i < VIRTIO_CONSOLE_DISP_OBJ_MAX; i++) {
		TAILQ_INSERT_HEAD(&vConsoleHostDrv.dispFreeQ, &vConsoleHostDrv.dispObj[i], link);
	}
	pthread_mutex_init(&vConsoleHostDrv.dispMtx, NULL);
	pthread_cond_init(&vConsoleHostDrv.dispCond, NULL);

	ret = pthread_create(&vConsoleHostDrv.dispThread, NULL, virtioHostConsoleReqDispatch, NULL);
	if (ret) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"failed to create virtio console host dispatch thread\n");
	}

	ret = pthread_create(&virtioHostMeventDispatchThread, NULL,
			virtioHostMeventDispatch, NULL);
	if (ret) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"failed to create mevent dispatch thread(%d)\n", ret);
	}
}

static int virtioConsoleOpenBackend(const char *path, enum virtioConsoleBeType be_type)
{
	int fd = -1;

	switch (be_type) {
		case VIRTIO_CONSOLE_BE_PTY:
			fd = posix_openpt(O_RDWR | O_NOCTTY);
			if (fd == -1) {
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
						"posix_openpt failed, errno = %d\n", errno);
			} else if (grantpt(fd) == -1 || unlockpt(fd) == -1) {
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
						"grant/unlock failed, errno = %d\n", errno);
				close(fd);
				fd = -1;
			}
			break;
		case VIRTIO_CONSOLE_BE_STDIO:
			if (stdio_in_use) {
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
						"stdio is used by other device\n");
				break;
			}
			fd = STDIN_FILENO;
			stdio_in_use = true;
			break;
		case VIRTIO_CONSOLE_BE_TTY:
			fd = open(path, O_RDWR | O_NONBLOCK);
			if (fd < 0)
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
						"open failed: %s\n", path);
			else if (!isatty(fd)) {
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
						"not a tty: %s\n", path);
				close(fd);
				fd = -1;
			}
			break;
		case VIRTIO_CONSOLE_BE_FILE:
			fd = open(path, O_WRONLY|O_CREAT|O_APPEND|O_NONBLOCK, 0666);
			if (fd < 0)
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
						"open failed: %s\n", path);
			break;
		case VIRTIO_CONSOLE_BE_SOCKET:
			fd = socket(AF_UNIX, SOCK_STREAM, 0);
			if (fd < 0)
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
						"socket open failed \n");
			break;
		default:
			VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
					"not supported backend %d!\n", be_type);
	}

	return fd;
}

static int virtioConsoleMakeSocketNonblocking(int fd)
{
	int flags, s;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
			"fcntl get failed =%d\n", errno);
		return -1;
	}

	flags |= O_NONBLOCK;
	s = fcntl(fd, F_SETFL, flags);
	if (s == -1) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"fcntl set failed =%d\n", errno);
		return -1;
	}

	return 0;
}

static int virtioConsoleConfigBackend(struct virtioConsoleBackend *be)
{
	int fd, flags;
	char *pts_name = NULL;
	int client_fd = -1;
	struct termios tio, saved_tio;
	struct sockaddr_un addr;

	if (!be || be->fd == -1)
		return -1;

	fd = be->fd;
	switch (be->be_type) {
		case VIRTIO_CONSOLE_BE_PTY:
			pts_name = ptsname(fd);
			if (pts_name == NULL) {
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
						"ptsname return NULL, errno = %d\n",
						errno);
				return -1;
			}

			client_fd = open(pts_name, O_RDWR);
			if (client_fd == -1) {
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
						"client_fd open failed, errno = %d\n",
						errno);
				return -1;
			}

			tcgetattr(client_fd, &tio);
			cfmakeraw(&tio);
			tcsetattr(client_fd, TCSAFLUSH, &tio);
			be->pts_fd = client_fd;

			VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
				"***********************************************\n");
			VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
				"virt-console backend redirected to %s\n", pts_name);
			VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
				"***********************************************\n");

			flags = fcntl(fd, F_GETFL);
			fcntl(fd, F_SETFL, flags | O_NONBLOCK);
			break;
		case VIRTIO_CONSOLE_BE_TTY:
		case VIRTIO_CONSOLE_BE_STDIO:
			tcgetattr(fd, &tio);
			saved_tio = tio;
			cfmakeraw(&tio);
			tio.c_cflag |= CLOCAL;
			tio.c_oflag |= OPOST;
			tcsetattr(fd, TCSANOW, &tio);

			if (be->be_type == VIRTIO_CONSOLE_BE_STDIO) {
				flags = fcntl(fd, F_GETFL);
				fcntl(fd, F_SETFL, flags | O_NONBLOCK);

				virtio_console_saved_flags = flags;
				virtio_console_saved_tio = saved_tio;
				atexit(virtioConsoleRestoreStdio);
			}
			break;
		case VIRTIO_CONSOLE_BE_SOCKET:
			if (be->path == NULL) {
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
						"path is NULL\n");
				return -1;
			}

			memset(&addr, 0, sizeof(addr));
			addr.sun_family = AF_UNIX;
			strncpy(addr.sun_path, be->path, sizeof(addr.sun_path));
			addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

			if (be->socket_type == VIRTIO_CONSOLE_BE_SOCKET_SERVER) {
				unlink(be->path);
				if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
					VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
							"Bind Error = %d\n", errno);
					return -1;
				}
				if (listen(fd, 64) == -1) {
					VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
							"Listen Error= %d\n", errno);
					return -1;
				}
				if (virtioConsoleMakeSocketNonblocking(fd) == -1) {
					VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
							"Backend config: fcntl Error\n");
					return -1;
				}
			} else if (be->socket_type == VIRTIO_CONSOLE_BE_SOCKET_CLIENT) {
				if (access(be->path, 0)) {
					VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
							"%s not exist\n", be->path);
					return -1;
				}
				if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
					VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
							"connect error[%d] \n", errno);
				} else {
					if (virtioConsoleMakeSocketNonblocking(fd) == -1) {
						VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
								"Backend config: fcntl Error\n");
					}
				}
			} else {
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
						"Socket type not exist\n");
				return -1;
			}

		default:
			break; /* nothing to do */
	}

	return 0;
}

static struct virtioConsolePort* virtioConsoleAddPort(
			struct virtioConsoleHostCtx *pConsoleHostCtx,			
			const char *name, void *arg, bool is_console, uint32_t portId)
{
	struct virtioConsolePort *port = &pConsoleHostCtx->ports[portId];

	port->id = portId;
	port->pConsoleHostDev = (struct virtioConsoleHostDev *)pConsoleHostCtx;
	port->name = name;
	port->arg = arg;
	port->is_console = is_console;

	/* receiveq start from 0 and transmitq start from 1 according to virtio v1.2 */
	if (port->id == 0) {
		port->rxq = 0;
		port->txq = 1;
	} else {
		/* 
                 * port->id here starts from 1, rxq from 4, txq from 5.
		 * So as to skip control queue whose rxq is 2 and txq is 3.
                 */
		port->rxq = (port->id + 1) * 2;
		port->txq = port->rxq + 1;
	}

	port->enabled = true;
	return port;
}

static void virtioConsoleAcceptNewConnection(int fd __attribute__((unused)),
					enum ev_type t __attribute__((unused)), void *arg)
{
	int accepted_fd;
	uint32_t len;
	struct sockaddr_un addr;
	struct virtioConsoleBackend *be = arg;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, be->path, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

	len = sizeof(addr);
	/* be->server_fd is kept for client User VM reconnect again */
	accepted_fd = accept(be->server_fd, (struct sockaddr *)&addr, &len);
	if (accepted_fd == -1) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"accept error= %d, addr.sun_path=%s\n",
				errno, addr.sun_path);
		return;
	} else {
		be->fd = accepted_fd;
	}

	be->conn_evp = mevent_add(be->fd, EVF_READ, virtioConsoleBackendRead, be,
				NULL, NULL);
	if (be->conn_evp == NULL) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"accepted fd mevent_add failed\n");
		return;
	}

	if (virtioConsoleMakeSocketNonblocking(be->fd) == -1) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"accepted fd non-blocking failed\n");
		return;
	}
}

static void virtioConsoleResetBackend(struct virtioConsoleBackend *be)
{
	if (!be)
		return;

	if (be->evp)
		mevent_disable(be->evp);
	if (be->fd != STDIN_FILENO)
		close(be->fd);
	be->fd = -1;
	be->open = false;
}

static void virtioConsoleSocketClear(struct virtioConsoleBackend *be)
{
	if (be->conn_evp) {
		mevent_delete(be->conn_evp);
		be->conn_evp = NULL;
	}
	if (be->fd != -1) {
		close(be->fd);
		be->fd = -1;
	}
}

static void virtioConsoleBackendRead(int fd __attribute__((unused)),
			    enum ev_type t __attribute__((unused)),
			    void *arg)
{
	int ret;
	struct virtioConsolePort *port;
	struct virtioConsoleBackend *be = arg;
	static char dummybuf[2048];

	VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO, "start\n");

	port = be->port;

	if (!be->open || !port->rx_ready) {
		ret = read(be->fd, dummybuf, sizeof(dummybuf));
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
				"backend rx is not ready, drop it.\n");
		return;
	}

	virtioHostConsoleReqHandleRx(port);

	return;
}

static void virtioConsoleRestoreStdio(void)
{
	tcsetattr(STDIN_FILENO, TCSANOW, &virtio_console_saved_tio);
	fcntl(STDIN_FILENO, F_SETFL, virtio_console_saved_flags);
	stdio_in_use = false;
}

static void virtioConsoleCloseBackend(struct virtioConsoleBackend *be)
{
	if (!be)
		return;

	switch (be->be_type) {
	case VIRTIO_CONSOLE_BE_PTY:
		if (be->pts_fd > 0) {
			close(be->pts_fd);
			be->pts_fd = -1;
		}
		break;
	case VIRTIO_CONSOLE_BE_STDIO:
		virtioConsoleRestoreStdio();
		break;
	case VIRTIO_CONSOLE_BE_SOCKET:
		if (be->socket_type == VIRTIO_CONSOLE_BE_SOCKET_SERVER) {
			virtioConsoleSocketClear(be);
			if (be->server_fd > 0) {
				close(be->server_fd);
				be->server_fd = -1;
			}
		}
		break;
	default:
		break;
	}

	if (be->be_type != VIRTIO_CONSOLE_BE_STDIO && be->fd > 0) {
		close(be->fd);
		be->fd = -1;
	}

	memset(be->port, 0, sizeof(*be->port));
	free(be);
}

static void virtioConsoleDestroy(struct virtioConsoleHostDev *pConsoleHostDev)
{
	/* TODO reset virtio device */
	;
}

static void virtioConsoleTeardownBackend(void *param)
{
	struct virtioConsoleHostDev *pConsoleHostDev = NULL;
	struct virtioConsoleBackend *be;

	VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO, "start\n");

	be = (struct virtioConsoleBackend *)param;
	if (!be)
		return;

	if (be->port)
		pConsoleHostDev = be->port->pConsoleHostDev;

	virtioConsoleCloseBackend(be);

	if (pConsoleHostDev) {
		pConsoleHostDev->refCount--;
		/* free virtio_console if this is the last backend */
		if (pConsoleHostDev->refCount == 0)
			virtioConsoleDestroy(pConsoleHostDev);
	}
}


/*******************************************************************************
 *
 * virtioHostConsoleBeDevCreate - create virtio console backend device
 *
 * This routine creates virtio console backend device
 *
 * RETURNS: 0, or -1 if any error is raised in process of the backend console
 * device creating.
 *
 * ERRNO: N/A
 */
static int virtioHostConsoleBeDevCreate(struct virtioConsoleHostDev *pConsoleHostDev, uint32_t portId)
{
	struct virtioConsoleHostCtx *pConsoleHostCtx;
	struct virtioConsoleBePortArgs *pConsoleBePortArgs;
	struct virtioConsoleBackend *be;
	int fd = -1, ret;

	pConsoleHostCtx = &pConsoleHostDev->consoleHostCtx;
	pConsoleBePortArgs = &pConsoleHostDev->beDevArgs.ports[portId];

	fd = virtioConsoleOpenBackend(pConsoleBePortArgs->path,
			pConsoleBePortArgs->be_type);
	if (fd < 0) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"failed to open backend device\n");
		goto err;
	}

	be = calloc(1, sizeof(struct virtioConsoleBackend));
	if (be == NULL) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"failed to allocate memory for backend device\n");
		goto err;
	}

	be->fd          = fd;
	be->server_fd   = fd;
	be->be_type     = pConsoleBePortArgs->be_type;
	be->socket_type = pConsoleBePortArgs->socket_type;
	be->path        = pConsoleBePortArgs->path;

	if (virtioConsoleConfigBackend(be) < 0) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"virtio_console_config_backend failed\n");
		goto err;
	}

	be->port = virtioConsoleAddPort(pConsoleHostCtx, pConsoleBePortArgs->name,
			be, pConsoleBePortArgs->is_console, portId);
	if (be->port == NULL) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"virtio_console_add_port failed\n");
		goto err;
	}

	if (be->be_type != VIRTIO_CONSOLE_BE_FILE) {
		if (be->be_type == VIRTIO_CONSOLE_BE_SOCKET
				&& be->socket_type == VIRTIO_CONSOLE_BE_SOCKET_SERVER) {
			be->evp = mevent_add(fd, EVF_READ,
					virtioConsoleAcceptNewConnection, be,
					virtioConsoleTeardownBackend, be);
			if (be->evp == NULL) {
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
						"mevent_add failed\n");
				goto err;
			}
			pConsoleHostDev->refCount++;
		} else if (isatty(fd) || (be->be_type == VIRTIO_CONSOLE_BE_SOCKET
			&& be->socket_type == VIRTIO_CONSOLE_BE_SOCKET_CLIENT)) {
			be->evp = mevent_add(fd, EVF_READ,
					virtioConsoleBackendRead, be,
					virtioConsoleTeardownBackend, be);
			if (be->evp == NULL) {
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
						"mevent_add failed\n");
				goto err;
			}
			pConsoleHostDev->refCount++;
		}
	}

	virtioConsoleOpenPort(be->port, true);
	be->open = true;

	return 0;
err:
	if (be) {
		if (be->port) {
			be->port->enabled = false;
			be->port->arg = NULL;
		}

		if (be->be_type == VIRTIO_CONSOLE_BE_PTY && be->pts_fd > 0)
			close(be->pts_fd);

		free(be);
	}

	if (fd != -1 && fd != STDIN_FILENO)
		close(fd);

	return -1;
}

void virtioHostConsoleDrvRelease(void)
{
	struct virtioConsoleHostDev *pConsoleHostDev;
	struct virtioConsoleHostCtx *pConsoleHostCtx;
	struct virtioConsolePort *pConsolePort;
	uint32_t queue;
	uint32_t devNum;
	int ret;

	for (devNum = 0; devNum < vConsoleHostDrv.vConsoleHostDevNum; devNum++) {
		pConsoleHostDev = vConsoleHostDrv.vConsoleHostDevList[devNum];

		if (!pConsoleHostDev)
			continue;


		pConsoleHostCtx = (struct virtioConsoleHostCtx *)pConsoleHostDev;
		for (queue = 0; queue < pConsoleHostCtx->queues; queue++) {
			pConsolePort = &pConsoleHostCtx->ports[queue];
			virtioConsoleTeardownBackend(
			    (struct virtioConsoleBackend *)pConsolePort->arg);
			if (pConsolePort->tx_thread &&
			    pthread_cancel(pConsolePort->tx_thread) == 0) {
				pthread_join(pConsolePort->tx_thread, NULL);
			}
		}

		if (pConsoleHostCtx->controlPort.tx_thread &&
		    pthread_cancel(pConsoleHostCtx->controlPort.tx_thread) == 0) {
			pthread_join(pConsoleHostCtx->controlPort.tx_thread, NULL);
		}

		if (pthread_cancel(virtioHostMeventDispatchThread) == 0) {
			pthread_join(virtioHostMeventDispatchThread, NULL);
		}

		virtioHostRelease(&pConsoleHostCtx->vhost);

		free(pConsoleHostDev);
	}
}

/*******************************************************************************
 *
 * virtioHostConsoleDevCreate - create virtio console device instance
 *
 * This routine parses argument list of virtio console device.
 * [@]tty|file:portname[=port],[,[@]stdio|tty|file|socket:portname[:socket_type]]
 * and creates and initializes create virtio console device instance.
 *
 * RETURNS: 0, or negative value of errno number if any error is raised
 * in process of the parsing.
 *
 * ERRNO: N/A
 */

static int virtioHostConsoleDevCreate(struct virtioHostDev *pHostDev,
		struct virtioConsoleHostDev *pConsoleHostDev)
{
	struct virtioConsoleBeDevArgs *pConsoleBeDevArgs = &pConsoleHostDev->beDevArgs;
	struct virtioConsoleHostCtx *pConsoleHostCtx = (struct virtioConsoleHostCtx *)pConsoleHostDev;
	struct virtioHost *vhost = (struct virtioHost *)pConsoleHostDev;
	struct virtioConsolePort *pConsolePort;
	struct virtioConsoleBePortArgs *pConsoleBePortArgs;
	char *opts = NULL;
	char *opt = NULL;
	char *p = NULL;
	char *backend = NULL;
	int ret, i;

	pHostDev->args[PATH_MAX] = '\0';

	VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO, "%s\n", pHostDev->args);

	opts = pHostDev->args;
	pConsoleBeDevArgs->nports = 0; 
	pConsoleBeDevArgs->multiport = false;

	/* port parsing */
	while ((opt = strsep(&opts, ",")) != NULL) {
		if (pConsoleBeDevArgs->nports == VIRTIO_CONSOLE_MAXPORTS) {
			VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
					"too many device, support up to %d\n", VIRTIO_CONSOLE_MAXPORTS);
			goto err;
		}

		pConsoleBePortArgs = &pConsoleBeDevArgs->ports[pConsoleBeDevArgs->nports];

		backend = strsep(&opt, ":");
		if (!backend) {
			VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
					"no backend\n");
			goto err;
		}

		if (backend[0] == '@') {
			pConsoleBePortArgs->is_console = 1;
			backend++;
		} else
			pConsoleBePortArgs->is_console = 0;

		for (i = 0; i < VIRTIO_CONSOLE_BE_MAX; i++)
			if (strcasecmp(backend, virtioConsoleBeTable[i]) == 0)
				break;

		if (i == VIRTIO_CONSOLE_BE_MAX) {
			VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
					"unknown type\n");
			goto err;
		}

		pConsoleBePortArgs->be_type = i;

		if (opt) {
			if (pConsoleBePortArgs->be_type == VIRTIO_CONSOLE_BE_SOCKET) {
				p = strsep(&opt, "=");
				if (p) {
					strncpy(pConsoleBePortArgs->name, p, strlen(p));
				} else {
					VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
							"no socket name\n");
					goto err;
				}

				p = strsep(&opt, ":");
				if (p) {
					strncpy(pConsoleBePortArgs->path, p, strlen(p));
				} else {
					VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
							"no socket path\n");
					goto err;
				}

				if (opt) {
					if (!strcmp("server", opt)) {
						pConsoleBePortArgs->socket_type
								= VIRTIO_CONSOLE_BE_SOCKET_SERVER;
					} else if (!strcmp("client", opt)) {
						pConsoleBePortArgs->socket_type
								= VIRTIO_CONSOLE_BE_SOCKET_CLIENT;
					} else {
						VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
								"unknown socket type\n");
						return -EINVAL;
					}
				} else {
					VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
							"no socket type\n");
					goto err;
				}
			} else if (pConsoleBePortArgs->be_type == VIRTIO_CONSOLE_BE_STDIO ||
					pConsoleBePortArgs->be_type == VIRTIO_CONSOLE_BE_PTY) {
				/* stdio and pty don't need port path */
				pConsoleBePortArgs->path[0] = '\0';
			} else {
				p = strsep(&opt, "=");
				if (opt) {
					strncpy(pConsoleBePortArgs->path, opt, strlen(opt));
				} else {
					VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
							"no port path\n");
					goto err;
				}
			}
		} else {
			VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
					"no port name\n");
			goto err;
		}

		pConsoleBeDevArgs->nports++;
	}

	/* device parsing */
	if (pConsoleBeDevArgs->nports == 0) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR, "no port\n");
		goto err;
	} else if (pConsoleBeDevArgs->nports == 1) {
		pConsoleBeDevArgs->queues = 4;
		pConsoleBeDevArgs->multiport = false;
	} else {
		pConsoleBeDevArgs->queues = (pConsoleBeDevArgs->nports * 2) + 2;
		pConsoleBeDevArgs->multiport = true;
	}

	/* set device features */
	pConsoleHostCtx->feature = (1UL << VIRTIO_F_VERSION_1) |
		(1UL << VIRTIO_CONSOLE_F_SIZE) |
		(1UL << VIRTIO_CONSOLE_F_EMERG_WRITE) |
		(1UL << VIRTIO_RING_F_EVENT_IDX) |
		(1UL << VIRTIO_RING_F_INDIRECT_DESC);

	if (pConsoleHostDev->beDevArgs.multiport)
		pConsoleHostCtx->feature |= (1UL << VIRTIO_CONSOLE_F_MULTIPORT);

	VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
			"pConsoleHostCtx->feature:0x%lx\n",
			pConsoleHostCtx->feature);

	/* host device initialization */
	pConsoleHostCtx->queues = pConsoleBeDevArgs->queues;

	memcpy((void *)pConsoleBeDevArgs->channel, (void *)pHostDev->channels, sizeof(struct virtioChannel));

	vhost->channelId = pConsoleBeDevArgs->channel->channelId;
	vhost->pMaps = pConsoleBeDevArgs->channel->pMap;

	ret = virtioHostCreate(vhost,
			VIRTIO_DEV_ANY_ID,
			VIRTIO_ID_CONSOLE,
			&pConsoleHostCtx->feature,
			pConsoleHostCtx->queues,
			VIRTIO_CONSOLE_QUEUE_MAX_NUM,
			0, NULL,
			&virtioConsoleHostOps);
	if (ret) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"failed to create virtio host device(%d)\n", ret);
		goto err;
	}

	/* port initialization */
	for (i = 0; i < pConsoleBeDevArgs->nports; i++) {
		ret = virtioHostConsoleBeDevCreate(pConsoleHostDev, i);
		if (ret)
			goto err;

		pConsolePort = &pConsoleHostCtx->ports[i];

		ret = pthread_create(&pConsolePort->tx_thread, NULL,
				virtioHostConsoleReqHandleTx, pConsolePort);
		if (ret) {
			VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
					"failed to create tx thread(%d)\n", ret);
			goto err;
		}

		sem_init(&pConsolePort->tx_sem, 0, 0);
	}

	if (pConsoleBeDevArgs->multiport) {
		pConsoleHostCtx->controlPort.pConsoleHostDev = pConsoleHostDev;
		pConsoleHostCtx->controlPort.rxq = 2;
		pConsoleHostCtx->controlPort.txq = 3;
		pConsoleHostCtx->controlPort.enabled = true;

		ret = pthread_create(&pConsoleHostCtx->controlPort.tx_thread, NULL,
				virtioHostConsoleReqHandleControlTx, &pConsoleHostCtx->controlPort);
		if (ret) {
			VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
					"failed to create control tx thread(%d)\n", ret);
			goto err;
		}

		sem_init(&pConsoleHostCtx->controlPort.tx_sem, 0, 0);
	}

	/* device initialization */
	pConsoleHostCtx->nports = pConsoleBeDevArgs->nports;

	pConsoleHostCtx->cfg.cols = 80;
	pConsoleHostCtx->cfg.rows = 25;
	pConsoleHostCtx->cfg.max_nr_ports = VIRTIO_CONSOLE_MAXPORTS;
	pConsoleHostCtx->cfg.emerg_wr = 0;

	pthread_mutex_lock(&vConsoleHostDrv.drvMtx);
	vConsoleHostDrv.vConsoleHostDevList[vConsoleHostDrv.vConsoleHostDevNum]
			= pConsoleHostDev;
	vConsoleHostDrv.vConsoleHostDevNum++;
	pthread_mutex_unlock(&vConsoleHostDrv.drvMtx);

	/* Only notify FE of window size change of port0 according to standard v1.2 */
	virtioHostConfigNotify(vhost);

	VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
			"multiport:%d\n", pConsoleBeDevArgs->multiport);
	VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
			"queues:%d\n", pConsoleBeDevArgs->queues);
	VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
			"nports:%d\n", pConsoleBeDevArgs->nports);

	for (i = 0; i < pConsoleHostDev->beDevArgs.nports; i++) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
				"port:%d\n", i);
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
				"name:%s\n", pConsoleBeDevArgs->ports[i].name);
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
				"path:%s\n", pConsoleBeDevArgs->ports[i].path);
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
				"is_console:%d\n", pConsoleBeDevArgs->ports[i].is_console);
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
				"be_type:%d\n", pConsoleBeDevArgs->ports[i].be_type);
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
				"socket_type:%d\n", pConsoleBeDevArgs->ports[i].socket_type);
	}

	return 0;
err:
	virtioHostConsoleDrvRelease();
	return -1;
}

/*******************************************************************************
 *
 * virtioHostConsoleCreate - create a virtio console device
 *
 * This routine creates a virtio console device backend driver to simuilate
 * a real storage device.
 *
 * RETURNS: 0, or negative value of errno number if any error is raised
 * in process of the console device creating.
 *
 * ERRNO: N/A
 */

static int virtioHostConsoleCreate(struct virtioHostDev *pHostDev)
{
	struct virtioConsoleHostDev *pConsoleHostDev;
	struct virtioConsoleBeDevArgs *pBeDevArgs;
	int ret;

	VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO, "start\n");

	if (!pHostDev) {
		VIRTIO_CONSOLE_DEV_DBG (VIRTIO_CONSOLE_DEV_DBG_ERR,
				"pHostDev is NULL\n");
		return -EINVAL;
	}

	/* the virtio channel number is always one */
	if (pHostDev->channelNum > 1) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"channel number is %d, only one channel is supported\n",
				pHostDev->channelNum);
		return -EINVAL;
	}

	VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO, "\n"
			"  typeId = %d args %s channelNum = %d \n" \
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

	if (vConsoleHostDrv.vConsoleHostDevNum == VIRTIO_CONSOLE_HOST_DEV_MAX) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"No more than %d console devices can be created\n", VIRTIO_CONSOLE_HOST_DEV_MAX);
		return -ENOENT;
	}

	VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
			"sizeof(struct virtioConsoleHostDev) is %ld bytes\n",
			sizeof(struct virtioConsoleHostDev));

	pConsoleHostDev = calloc(1, sizeof(struct virtioConsoleHostDev));
	if (!pConsoleHostDev) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"failed to allocate memory\n");
		return -ENOMEM;
	}

	ret = virtioHostConsoleDevCreate(pHostDev, pConsoleHostDev);
	if (ret)
		goto exit;

exit:
	if (ret) {
		free(pConsoleHostDev);
		return ret;
	}

	VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO, "done\n");

	return 0;
}

/*******************************************************************************
 *
 * virtioHostConsoleAbort - abort a request handling
 *
 * This routine is used to abort a request handling when a request is seen
 * with incorrect format, which will be abandoned.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */
static void virtioHostConsoleAbort(struct virtioHostQueue *pQueue, uint16_t idx)
{
	if (idx < pQueue->vRing.num) {
		(void)virtioHostQueueRelBuf(pQueue, idx, 1);
		(void)virtioHostQueueNotify(pQueue);
	}

	return;
}

/*******************************************************************************
 *
 * virtioHostConsoleReqDispatch - virtio net device dispatch task
 *
 * This routine is used to dispatch virtio net device IO or control requests
 * to specific handling thread(s).
 *
 * RETURNS: 0, or -1 if the recieved operation request with a invalid format or
 * error meeting a failure in process of filesystem operation.
 *
 * ERRNO: N/A
 */

static void* virtioHostConsoleReqDispatch(void *)
{
	struct virtioConsoleHostCtx *pConsoleHostCtx;
	struct virtioDispObj *pDispObj;
	uint32_t queueId, portId;
	int ret;

	pthread_mutex_lock(&vConsoleHostDrv.dispMtx);

	while (1) {
		while (1) {
			if (TAILQ_EMPTY(&vConsoleHostDrv.dispBusyQ))
				break;

			pDispObj = TAILQ_FIRST(&vConsoleHostDrv.dispBusyQ);
			if (pDispObj) {
				TAILQ_REMOVE(&vConsoleHostDrv.dispBusyQ, pDispObj, link);
			} else {
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
						"failed to get dispatch object from busy queue\n");
			}

			pthread_mutex_unlock(&vConsoleHostDrv.dispMtx);

			if (pDispObj && pDispObj->pQueue && pDispObj->pQueue->vHost) {
				pConsoleHostCtx = (struct virtioConsoleHostCtx *)pDispObj->pQueue->vHost;
				queueId = pDispObj->pQueue - pDispObj->pQueue->vHost->pQueue;
				portId = queueId / 2 == 0 ? 0 : (queueId / 2) - 1;

				if (queueId / 2 != 1) { /* IO queue ID: 0,1,4,5... */
					if (queueId % 2 == 0) {
						if (!pConsoleHostCtx->ports[portId].rx_ready)
							pConsoleHostCtx->ports[portId].rx_ready = 1;
					} else {
						ret = sem_post(&pConsoleHostCtx->ports[portId].tx_sem);
						if (ret)
							VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
									"failed to sem_post tx_sem: %s\n",
									strerror(errno));
					}
				} else { /* control queue ID: 2,3 */
					ret = sem_post(&pConsoleHostCtx->controlPort.tx_sem);
					if (ret)
						VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
								"failed to sem_post tx_sem: %s\n",
								strerror(errno));
				}
			} else {
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
						"failed to get virtqueue from busy object\n");
			}

			pthread_mutex_lock(&vConsoleHostDrv.dispMtx);

			TAILQ_INSERT_TAIL(&vConsoleHostDrv.dispFreeQ, pDispObj, link);
		}

		pthread_cond_wait(&vConsoleHostDrv.dispCond, &vConsoleHostDrv.dispMtx);
	}

	pthread_mutex_unlock(&vConsoleHostDrv.dispMtx);

	return NULL;
}

/*******************************************************************************
 *
 * virtioHostConsoleReqHandleRx - virtio console device request rx handle task
 *
 * This routine is used to create a handler task for virtio console device
 * read or write operations.
 *
 * RETURNS: NULL
 *
 * ERRNO: N/A
 */
static void virtioHostConsoleReqHandleRx(struct virtioConsolePort *pConsolePort)
{
	int n, i, len, total, ret;
	uint16_t idx;
	struct virtioHost *vhost;
	struct virtioConsoleHostDev *pConsoleHostDev;
	struct virtioConsoleHostCtx *pConsoleHostCtx;
	struct virtioHostQueue *pQueue;
	struct virtioConsolePort *pPorts;
	struct virtioConsoleBackend *be = pConsolePort->arg;
	struct virtioHostBuf bufList[VIRTIO_CONSOLE_IO_REQ_MAX];
	struct iovec iov[VIRTIO_CONSOLE_IO_REQ_MAX];

	pPorts = pConsolePort->rxq == 0 ? pConsolePort :
			pConsolePort - ((pConsolePort->rxq / 2) - 1);
	pConsoleHostCtx = container_of((struct virtioConsolePort (*)[VIRTIO_CONSOLE_MAXPORTS])pPorts,
			struct virtioConsoleHostCtx, ports);

	vhost = (struct virtioHost *)pConsoleHostCtx;
	pQueue = vhost->pQueue + pConsolePort->rxq;

	n = virtioHostQueueGetBuf(pQueue, &idx, bufList, VIRTIO_CONSOLE_IO_REQ_MAX);
	VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
			"n:%d\n", n);
	if (n == 0) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
				"no new queue buffer\n");
		return;
	}

	if (n < 0) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"failed to get buffer(%d)\n", n);
		virtioHostConsoleAbort(pQueue, pQueue->availIdx);
		return;
	}

	if (n > VIRTIO_CONSOLE_IO_REQ_MAX) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"invalid length of desc chain: %d, 1 to %d is valid\n",
				n, VIRTIO_CONSOLE_IO_REQ_MAX);

		virtioHostConsoleAbort(pQueue, pQueue->availIdx);
		return;
	}

	for (i = 0; i < n; i++) {
		iov[i].iov_base = bufList[i].buf;
		iov[i].iov_len = bufList[i].len;
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
				"len: %d\n", bufList[i].len);
	}

	len = readv(be->fd, &iov[0], n);
	if (len <= 0) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"failed to read len:%d, %s\n", len, strerror(errno));

		virtioHostConsoleAbort(pQueue, pQueue->availIdx);

		/* no data available */
		if (len == -1 && errno == EAGAIN)
			return;

		/* when client User VM reboot or shutdown,
		 * be->fd will be closed, then the return
		 * value of readv function will be 0 */
		if (len == 0 || errno == ECONNRESET)
			goto clear;

		/* any other errors */
		goto close;
	}
#ifdef VIRTIO_CONSOLE_DEV_DUMP_PACKETS
	for (i = 0; i < 8; i++)
		printf("%02x ", *((char *)bufList[0].buf + i));
	printf("len: %d\n", len);
#endif
	virtioHostConsoleDone(idx, pQueue, len);
	return;
close:
	virtioConsoleResetBackend(be);
	VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
			"be read failed and close! len = %d, errno = %d\n",
			len, errno);
clear:
	if (be->be_type == VIRTIO_CONSOLE_BE_SOCKET &&
			be->socket_type == VIRTIO_CONSOLE_BE_SOCKET_SERVER) {
		virtioConsoleSocketClear(be);
	} else if (be->be_type == VIRTIO_CONSOLE_BE_SOCKET &&
			be->socket_type == VIRTIO_CONSOLE_BE_SOCKET_CLIENT) {
		virtioConsoleResetBackend(be);
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"be read failed and close! len = %d, errno = %d\n",
				len, errno);
	}
}

/*******************************************************************************
 *
 * virtioHostConsoleReqHandleTx - virtio console device request tx handle task
 *
 * This routine is used to create a handler task for virtio console device
 * read or write operations.
 *
 * RETURNS: NULL
 *
 * ERRNO: N/A
 */
static void* virtioHostConsoleReqHandleTx(void *arg)
{
	int n, i, ret;
	uint16_t idx;
	struct virtioConsolePort *pConsolePort = arg;
	struct virtioHost *vhost;
	struct virtioConsoleHostDev *pConsoleHostDev;
	struct virtioConsoleHostCtx *pConsoleHostCtx;
	struct virtioHostQueue *pQueue;
	struct virtioConsolePort *pPorts;
	struct virtioConsoleBackend *be = pConsolePort->arg;
	struct virtioHostBuf bufList[VIRTIO_CONSOLE_IO_REQ_MAX];
	struct iovec iov[VIRTIO_CONSOLE_IO_REQ_MAX];

	pPorts = pConsolePort->txq == 1 ? pConsolePort :
			pConsolePort - ((pConsolePort->txq / 2) - 1);
	pConsoleHostCtx = container_of((struct virtioConsolePort (*)[VIRTIO_CONSOLE_MAXPORTS])pPorts,
			struct virtioConsoleHostCtx, ports);

	vhost = (struct virtioHost *)pConsoleHostCtx;
	pQueue = vhost->pQueue + pConsolePort->txq;

	while (1) {
		ret = sem_wait(&pConsolePort->tx_sem);
		if (ret < 0) {
			VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
					"failed to sem_wait tx_sem: %s\n", strerror(errno));
		}

		while (1) {
			n = virtioHostQueueGetBuf(pQueue, &idx, bufList, VIRTIO_CONSOLE_IO_REQ_MAX);
			VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
					"n:%d\n", n);
			if (n == 0) {
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
						"no new queue buffer\n");
				break;
			}

			if (n < 0) {
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
						"failed to get buffer(%d)\n", n);
				virtioHostConsoleAbort(pQueue, pQueue->availIdx);
				break;
			}

			if (n > VIRTIO_CONSOLE_IO_REQ_MAX) {
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
						"invalid length of desc chain: %d, 1 to %d is valid\n",
						n, VIRTIO_CONSOLE_IO_REQ_MAX);

				virtioHostConsoleAbort(pQueue, pQueue->availIdx);
				continue;
			}

			for (i = 0; i < n; i++) {
				iov[i].iov_base = bufList[i].buf;
				iov[i].iov_len = bufList[i].len;
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
						"len: %d\n", bufList[i].len);
			}

			ret = writev(be->fd, iov, n);
			if (ret <= 0) {
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
						"failed to write ret:%d, %s\n", ret, strerror(errno));
				/* Case 1:backend cannot receive more data. For example when pts is
				 * not connected to any client, its tty buffer will become full.
				 * In this case we just drop data from guest hvc console.
				 *
				 * Case 2: Backend connection not yet setup. For example, when
				 * virtio-console is used as console port with socket backend, guest
				 * kernel tries to hook it up with hvc console and sets it up. It
				 * doesn't check if a client is connected and can result in ENOTCONN
				 * with virtio-console backend being reset. This will prevent
				 * client connection at a later point. To avoid this, ignore
				 * ENOTCONN error.
				 */
				if (ret == -1 && (errno == EAGAIN || errno == ENOTCONN)) {
					break;
				}

				if (ret == -1 && errno == EBADF) {
					if (be->be_type == VIRTIO_CONSOLE_BE_SOCKET &&
							be->socket_type == VIRTIO_CONSOLE_BE_SOCKET_SERVER) {
						virtioConsoleSocketClear(be);
						break;
					}
				}

				virtioConsoleResetBackend(be);
				break;
			}
#ifdef VIRTIO_CONSOLE_DEV_DUMP_PACKETS
			for (i = 0; i < 8; i++)
				printf("%02x ", *((char *)bufList[0].buf + i));
			printf("len: %d\n", ret);
#endif
			virtioHostConsoleDone(idx, pQueue, ret);
		}
	}

	return NULL;
}

static void virtioConsoleControlSend(struct virtioConsoleHostCtx *pConsoleHostCtx,
			    struct virtio_console_control *ctrl,
			    const void *payload, size_t len)
{
	struct virtioHost *vHost;
	struct virtioHostQueue *pQueue;
	struct virtioHostBuf buf;
	struct iovec iov;
	uint16_t idx;
	int n;

	vHost = (struct virtioHost *)pConsoleHostCtx;
	pQueue = vHost->pQueue + pConsoleHostCtx->controlPort.txq;

	n = virtioHostQueueGetBuf(pQueue, &idx, &buf, 1);
	if (n < 1) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"failed to get buffer(%d)\n", n);
		virtioHostConsoleAbort(pQueue, pQueue->availIdx);
		return;
	}

	memcpy(buf.buf, ctrl, sizeof(struct virtio_console_control));
	if (payload != NULL && len > 0)
		memcpy(buf.buf + sizeof(struct virtio_console_control),
		     payload, len);

	virtioHostConsoleDone(idx, pQueue, sizeof(struct virtio_console_control) + len);
}


static void virtioConsoleAnnouncePort(struct virtioConsolePort *port)
{
	struct virtio_console_control event;

	event.id = port->id;
	event.event = VIRTIO_CONSOLE_PORT_ADD; /* named VIRTIO_CONSOLE_DEVICE_ADD in virtio v1.2 */
	event.value = 1;
	virtioConsoleControlSend((struct virtioConsoleHostCtx *)port->pConsoleHostDev, &event, NULL, 0);

	event.event = VIRTIO_CONSOLE_PORT_NAME;
	virtioConsoleControlSend((struct virtioConsoleHostCtx *)port->pConsoleHostDev, &event, port->name,
	    strnlen(port->name, NAME_MAX));
}

static void virtioConsoleOpenPort(struct virtioConsolePort *port, bool open)
{
	struct virtio_console_control event;

	if (!port->pConsoleHostDev->ready) {
		port->open = true;
		return;
	}

	event.id = port->id;
	event.event = VIRTIO_CONSOLE_PORT_OPEN;
	event.value = (int)open;
	virtioConsoleControlSend((struct virtioConsoleHostCtx *)port->pConsoleHostDev, &event, NULL, 0);
}

/*******************************************************************************
 *
 * virtioHostConsoleReqHandleControlTx - virtio console device control tx handle task
 *
 * This routine is used to create a handler task for virtio console device
 * read or write operations.
 *
 * RETURNS: NULL
 *
 * ERRNO: N/A
 */
static void* virtioHostConsoleReqHandleControlTx(void *arg)
{
	int n, i, len, total, ret;
	uint16_t idx;
	struct virtioConsolePort *pConsolePort = arg;
	struct virtioHost *vhost;
	struct virtioConsoleHostDev *pConsoleHostDev;
	struct virtioConsoleHostCtx *pConsoleHostCtx;
	struct virtioHostQueue *pQueue;
	struct virtioConsolePort *tmp;
	struct virtioHostBuf bufList[VIRTIO_CONSOLE_IO_REQ_MAX];
	struct virtio_console_control resp, *ctrl;

	if (!pConsolePort || pConsolePort->txq != 3) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"invalid argument\n");
		return NULL;
	}

	pConsoleHostCtx = container_of(pConsolePort, struct virtioConsoleHostCtx, controlPort);
	pConsoleHostDev = (struct virtioConsoleHostDev *)pConsoleHostCtx;
	vhost = (struct virtioHost *)pConsoleHostCtx;
	pQueue = vhost->pQueue + pConsolePort->txq;

	while (1) {
		ret = sem_wait(&pConsolePort->tx_sem);
		if (ret < 0) {
			VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
					"failed to sem_wait tx_sem: %s\n", strerror(errno));
		}

		total = 0;

		while (1) {
			n = virtioHostQueueGetBuf(pQueue, &idx, bufList, VIRTIO_CONSOLE_IO_REQ_MAX);
			VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
					"n:%d\n", n);
			if (n == 0) {
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_INFO,
						"no new queue buffer\n");
				break;
			}

			if (n < 0) {
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
						"failed to get buffer(%d)\n", n);
				virtioHostConsoleAbort(pQueue, pQueue->availIdx);
				break;
			}

			if (n > VIRTIO_CONSOLE_IO_REQ_MAX) {
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
						"invalid length of desc chain: %d, 1 to %d is valid\n",
						n, VIRTIO_CONSOLE_IO_REQ_MAX);

				virtioHostConsoleAbort(pQueue, pQueue->availIdx);
				continue;
			}

			for (i = 0; i < n; i++) {
				ctrl = (struct virtio_console_control *)bufList[i].buf;
				if (!ctrl) {
					VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
							"null ctrl request\n");
					continue;
				}

				total += bufList[i].len;

				switch (ctrl->event) {
					case VIRTIO_CONSOLE_DEVICE_READY:
						pConsoleHostDev->ready = true;
						/* set port ready events for registered ports */
						for (i = 0; i < VIRTIO_CONSOLE_MAXPORTS; i++) {
							tmp = &pConsoleHostCtx->ports[i];
							if (tmp->enabled)
								virtioConsoleAnnouncePort(tmp);

							if (tmp->open)
								virtioConsoleOpenPort(tmp, true);
						}
						break;

					case VIRTIO_CONSOLE_PORT_READY:
						if (ctrl->id >= pConsoleHostCtx->nports) {
							VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
								"VTCONSOLE_PORT_READY for unknown port %d\n",
								ctrl->id);
							break;
						}

						tmp = &pConsoleHostCtx->ports[ctrl->id];
						if (tmp->is_console) {
							resp.event = VIRTIO_CONSOLE_CONSOLE_PORT;
							resp.id = ctrl->id;
							resp.value = 1;
							virtioConsoleControlSend(pConsoleHostCtx, &resp, NULL, 0);
						}
						break;
				}
			}
		}

		virtioHostConsoleDone(idx, pQueue, total);
	}

	return NULL;
}

/*******************************************************************************
 *
 * virtioHostConsoleNotify - notify here comes a new IO/control request
 *
 * This routine is used to notify the handler that an new recieved io-request
 * in virtio queue.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */
static void virtioHostConsoleNotify(struct virtioHostQueue *pQueue)
{
	int ret;
	struct virtioDispObj *pDispObj;

	if (!pQueue) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR, "null pQueue\n");
		return;
	}

	if (pQueue->vHost && (pQueue->vHost->status & VIRTIO_CONFIG_S_DRIVER_OK) != 0) {
		pthread_mutex_lock(&vConsoleHostDrv.dispMtx);
		if (!TAILQ_EMPTY(&vConsoleHostDrv.dispFreeQ)) {

			pDispObj = TAILQ_FIRST(&vConsoleHostDrv.dispFreeQ);
			if (!pDispObj) {
				VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
						"failed to get dispatch object from free queue\n");
				pthread_mutex_unlock(&vConsoleHostDrv.dispMtx);
				return;
			}
			TAILQ_REMOVE(&vConsoleHostDrv.dispFreeQ, pDispObj, link);
			pDispObj->pQueue = pQueue;
			TAILQ_INSERT_TAIL(&vConsoleHostDrv.dispBusyQ, pDispObj, link);

			pthread_cond_signal(&vConsoleHostDrv.dispCond);
		} else {
			VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
					"No object in dispatch free queue\n");
		}
		pthread_mutex_unlock(&vConsoleHostDrv.dispMtx);
	}

	return;
}

/*******************************************************************************
 *
 * virtioHostConsoleDone - mark the virtio console request handled done.
 *
 * This routine is used to set the request handeled status according to the
 * backend device operation result before the descriptors released to
 * the used ring.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */
static void virtioHostConsoleDone(uint16_t idx, struct virtioHostQueue *pQueue, uint32_t len)
{
	(void)virtioHostQueueRelBuf(pQueue, idx, len);
	(void)virtioHostQueueNotify(pQueue);

	return;
}

/*******************************************************************************
 *
 * virtioHostConsoleReset - reset virtio console device
 *
 * This routine is used to reset the virtio console device. All the configuration
 * settings setted by customer driver will be cleared and all the backend
 * driver software flags are reset to initial status.
 *
 * RETURNS: 0, or -1 if failure raised in process of restarting the device.
 *
 * ERRNO: N/A
 */
static int virtioHostConsoleReset(struct virtioHost *vHost)
{
	struct virtioConsoleHostCtx *vConsoleHostCtx;
	int err = 0;

	vConsoleHostCtx = (struct virtioConsoleHostCtx *)vHost;
	if (!vConsoleHostCtx) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"null vConsoleHostCtx\n");
		return -1;
	}

	return err;
}

/*******************************************************************************
 *
 * virtioHostConsoleCfgRead - read virtio console specific configuration register
 *
 * This routine is used to read virtio console specific configuration register,
 * the value read out is stored in the request buffer.
 *
 * RETURN: 0, or -1 if the to be read register is non-existed.
 *
 * ERRNO: N/A
 */
static int virtioHostConsoleCfgRead(struct virtioHost *vHost, uint64_t address,
		uint64_t size, uint32_t *pValue)
{
	struct virtioConsoleHostCtx *vConsoleHostCtx;
	uint8_t *cfgAddr;

	if (!vHost) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"NULL pointer\n");
		return -EINVAL;
	}

	vConsoleHostCtx = (struct virtioConsoleHostCtx *)vHost;

	cfgAddr = (uint8_t *)&vConsoleHostCtx->cfg + address;

	(void)memcpy(pValue, cfgAddr, (size_t)size);

	return 0;
}

/*******************************************************************************
 *
 * virtioHostConsoleCfgWrite - set virtio console specific configuration register
 *
 * This routine is used to set virtio console specific configuration register,
 * the setting value is stored in the request buffer.
 *
 * RETURN: 0, or -1 if the to be read register is non-existed.
 *
 * ERRNO: N/A
 */

static int virtioHostConsoleCfgWrite(struct virtioHost *vHost, uint64_t address,
		uint64_t size, uint32_t value)
{
	if (!vHost) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR, "null vHost\n");
		return -EINVAL;
	}

	if ((address == offsetof(struct virtio_console_config, emerg_wr)) && (size == 4)) {
		VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
				"EMERGENT WRITE: %u\n", value);
		return 0;
	}

	VIRTIO_CONSOLE_DEV_DBG(VIRTIO_CONSOLE_DEV_DBG_ERR,
			"failed to write to read-only register %lu\n", address);

	return -EINVAL;
}

/*******************************************************************************
 *
 * virtioHostConsoleShow - virtio console host device show
 *
 * This routine shows the virtio console host device setting and configurations.
 *
 * RETURN: 0 aleays.
 *
 * ERRNO: N/A
 */
static void virtioHostConsoleShow(struct virtioHost * vHost, uint32_t indent)
{
	struct virtioConsoleHostDev *pConsoleHostDev;
	int i;

	pConsoleHostDev = (struct virtioConsoleHostDev *)vHost;

	printf("%*sdriver [%s]\n", (indent + 1) * 3, "",
			 VIRTIO_CONSOLE_DRV_NAME);
	printf("%*sbackend device :\n", (indent + 1) * 3, "");

	printf("%*smultiport   [%d]\n", (indent + 2) * 3, "",
			pConsoleHostDev->beDevArgs.multiport);
	printf("%*squeues      [%d]\n", (indent + 2) * 3, "",
			pConsoleHostDev->beDevArgs.queues);
	printf("%*snports      [%d]\n", (indent + 2) * 3, "",
			pConsoleHostDev->beDevArgs.nports);

	for (i = 0; i < pConsoleHostDev->beDevArgs.nports; i++) {
		printf("%*sport        [%d]\n", (indent + 3) * 3, "", i);
		printf("%*spath        [%s]\n", (indent + 3) * 3, "",
				pConsoleHostDev->beDevArgs.ports[i].path);
		printf("%*sname        [%s]\n", (indent + 3) * 3, "",
				pConsoleHostDev->beDevArgs.ports[i].name);
		printf("%*sconsole     [%d]\n", (indent + 3) * 3, "",
				pConsoleHostDev->beDevArgs.ports[i].is_console);
		printf("%*sBE type     [%d]\n", (indent + 3) * 3, "",
				pConsoleHostDev->beDevArgs.ports[i].be_type);
		printf("%*ssocket type [%d]\n", (indent + 3) * 3, "",
				pConsoleHostDev->beDevArgs.ports[i].socket_type);
	}
}

