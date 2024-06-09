/* virtioHostGpio.c - virtio GPIO host device */

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

   This is the application that supply a virtio GPIO host driver, it provides
   the back-end GPIO pin control functions of virtio-gpio device on host VM.
*/

#include <sys/uio.h>
#include <sys/types.h>
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
#include <limits.h>
#include <ctype.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_gpio.h>
#include <linux/gpio.h>
#include <gpiod.h>

#include "mevent.h"
#include "virtioHostLib.h"

#define VIRTIO_GPIO_DEV_DUMP
#define VIRTIO_GPIO_DEV_DBG_ON
#ifdef VIRTIO_GPIO_DEV_DBG_ON

#define VIRTIO_GPIO_DEV_DBG_OFF             0x00000000
#define VIRTIO_GPIO_DEV_DBG_ISR             0x00000001
#define VIRTIO_GPIO_DEV_DBG_ARGS            0x00000020
#define VIRTIO_GPIO_DEV_DBG_ERR             0x00000100
#define VIRTIO_GPIO_DEV_DBG_INFO            0x00000200
#define VIRTIO_GPIO_DEV_DBG_ALL             0xffffffff

static uint32_t virtioGpioDevDbgMask = VIRTIO_GPIO_DEV_DBG_ERR;

#undef VIRTIO_GPIO_DEV_DBG
#define VIRTIO_GPIO_DEV_DBG(mask, fmt, ...)				\
	do {								\
		if ((virtioGpioDevDbgMask & (mask)) ||			\
		    ((mask) == VIRTIO_GPIO_DEV_DBG_ALL)) {		\
			printf("%d: %s() " fmt, __LINE__, __func__,	\
			       ##__VA_ARGS__);				\
                        fflush(stdout);                                 \
		}							\
	}								\
	while ((false))
#else
#define VIRTIO_GPIO_DEV_DBG(...)
#endif

#define VIRTIO_GPIO_DRV_NAME         "virtio-gpio-host"
#define VIRTIO_GPIO_QUEUE_MAX_NUM    128
#define VIRTIO_GPIO_IO_REQ_MAX       64
#define VIRTIO_GPIO_BUF_SIZE_MAX     1024
#define VIRTIO_GPIO_HOST_DEV_MAX     30
#define VIRTIO_GPIO_DISP_OBJ_MAX (VIRTIO_GPIO_QUEUE_MAX_NUM / VIRTIO_GPIO_IO_REQ_MAX * VIRTIO_GPIO_HOST_DEV_MAX)
#define VIRTIO_GPIO_BUFFER_NUM_PER_LINE 16 /* libgpiod can allocate at most 64*16 buffers */

#define VIRTIO_GPIO_MAX_VLINES       64  /* maximum number of virtual gpio */
#define VIRTIO_GPIO_MAX_CHIPS        8   /* maximum native gpio chips */
#define VIRTIO_GPIO_MAXQ             2   /* maximum virtqueue numbers */
#define VIRTIO_GPIO_REQ_QUEUE        0   /* request virtqueue number */
#define VIRTIO_GPIO_EVT_QUEUE        1   /* event virtqueue number */

struct gpio_irq_stat {
	uint64_t unmasked;
	uint64_t latched;
	uint64_t valid;
	uint64_t invalid;
	uint64_t total;
};

struct gpio_line {
	struct gpiod_line_request *request;	/* libgpiod structure */
	char	name[GPIO_MAX_NAME_SIZE];	/* native gpio name */
	char	vname[GPIO_MAX_NAME_SIZE];	/* virtual gpio name */
	int	offset;				/* offset in real chip */
	int	voffset;			/* offset in virtual chip */
	int	dir;				/* gpio direction */
	bool	busy;				/* gpio line request by kernel */
	int	value;				/* gpio value */
	uint64_t		config;		/* gpio configuration */
	struct native_gpio_chip	*chip;		/* parent gpio chip */
	struct gpio_irq_desc	*desc;		/* connect to irq descriptor */
	struct gpio_irq_stat	irq_stat; 	/* interrupts count */
};

struct native_gpio_chip {
	struct gpiod_chip *lchip;		/* libgpiod structure */
	char	 name[GPIO_MAX_NAME_SIZE];	/* gpio chip name */
	char	 label[GPIO_MAX_NAME_SIZE];	/* gpio chip label name */
	char	 dev_name[GPIO_MAX_NAME_SIZE];	/* device node name */
	uint32_t ngpio;				/* gpio line numbers */
	struct   gpio_line *lines;		/* gpio lines in the chip */
};

struct gpio_irq_desc {
	struct gpio_line	*line;	/* connect to gpio line */
	struct mevent		*mevt;	/* mevent for event report */
	int			pin;	/* pin number */
	bool			mask;	/* mask or unmask */
	uint8_t			level;	/* level value */
	uint64_t		mode;	/* interrupt trigger mode */
	void			*data;	/* virtio gpio instance */
	uint16_t		idx;    /* index of the 1st buffer of the buffer pair */
	struct virtio_gpio_irq_response *irs;
	bool			pending;/* pending, only for edge trigger */
	pthread_mutex_t		mtx;
	struct gpiod_edge_event_buffer *event_buffer;
	uint32_t                nbuffer;
	struct virtioGpioHostCtx *pGpioHostCtx;
};

struct gpio_irq_chip {
	struct gpio_irq_desc	descs[VIRTIO_GPIO_MAX_VLINES];
};

struct virtioGpioHostDev {
	struct virtioGpioHostCtx {
		struct virtioHost vhost;
		uint64_t feature;
		pthread_mutex_t	mtx;
		uint32_t nqueue;           	/* number of queues   */
		struct native_gpio_chip	chips[VIRTIO_GPIO_MAX_CHIPS];
		uint32_t		nchip;
		struct gpio_line	*vlines[VIRTIO_GPIO_MAX_VLINES];
		uint32_t		nvline;
		struct virtio_gpio_config cfg;  /* from UAPI */
		struct gpio_irq_chip	irq_chip;
		struct gpio_irq_stat	irq_stat; /* interrupts count */
		pthread_t               rq_thread;
		sem_t                   rq_sem;
		pthread_t               ev_thread;
		sem_t                   ev_sem;
	} gpioHostCtx;
};

struct virtioDispObj {
	TAILQ_ENTRY(virtioDispObj) link;
	struct virtioHostQueue *pQueue;
};

static struct virtioGpioHostDrv {
	struct virtioGpioHostDev *vGpioHostDevList[VIRTIO_GPIO_HOST_DEV_MAX];
	uint32_t vGpioHostDevNum;
	pthread_mutex_t drvMtx;
	TAILQ_HEAD(, virtioDispObj) dispFreeQ;
	TAILQ_HEAD(, virtioDispObj) dispBusyQ;
	pthread_t dispThread;
	pthread_mutex_t dispMtx;
	pthread_cond_t dispCond;
	struct virtioDispObj dispObj[VIRTIO_GPIO_DISP_OBJ_MAX];
} vGpioHostDrv;

static int virtioHostGpioReset(struct virtioHost *);
static void virtioHostGpioNotify(struct virtioHostQueue *);
static int virtioHostGpioCfgRead(struct virtioHost *, uint64_t, uint64_t size, uint32_t *);
static int virtioHostGpioCfgWrite(struct virtioHost *, uint64_t, uint64_t, uint32_t);
static void virtioHostGpioDone(uint16_t idx, struct virtioHostQueue *, uint32_t);
static int virtioHostGpioCreate(struct virtioHostDev *);
static void virtioHostGpioShow(struct virtioHost *, uint32_t);
static void virtioHostGpioAbort(struct virtioHostQueue *pQueue, uint16_t idx);
static void* virtioHostGpioReqDispatch(void *);
static void* virtioHostGpioHandleRequest(void *arg);
static void* virtioHostGpioHandleEvent(void *arg);
static void* virtioHostGpioReqHandleTx(void *arg);
static void* virtioHostGpioReqHandleControlTx(void *arg);
static int virtioHostGpioSetStatus(struct virtioHost* vHost, uint32_t status);

struct virtioHostOps virtioGpioHostOps = {
	.reset    = virtioHostGpioReset,
	.kick     = virtioHostGpioNotify,
	.reqRead  = virtioHostGpioCfgRead,
	.reqWrite = virtioHostGpioCfgWrite,
	.show     = virtioHostGpioShow,
	.setStatus= virtioHostGpioSetStatus,
};

static struct virtioHostDrvInfo HostDrvInfo =
{
	.typeId = VIRTIO_TYPE_GPIO,
	.flags = VIRTIO_HOST_FLAG_THREAD,
	.create = virtioHostGpioCreate,
};

pthread_t virtioHostGpioMeventDispatchThread;
void* virtioHostGpioMeventDispatch(void *my_unused)
{
	mevent_init();
	mevent_dispatch();
}

/*******************************************************************************
 *
 * virtioHostGpioDrvInit - initialize GPIO host device driver
 *
 * This routine initializes the GPIO host device driver.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */
void virtioHostGpioDrvInit(void)
{
	int ret, i;

	virtioHostDrvRegister((struct virtioHostDrvInfo *)&HostDrvInfo);

	pthread_mutex_init(&vGpioHostDrv.drvMtx, NULL);

	TAILQ_INIT(&vGpioHostDrv.dispFreeQ);
	TAILQ_INIT(&vGpioHostDrv.dispBusyQ);
	for (i = 0; i < VIRTIO_GPIO_DISP_OBJ_MAX; i++) {
		TAILQ_INSERT_HEAD(&vGpioHostDrv.dispFreeQ, &vGpioHostDrv.dispObj[i], link);
	}
	pthread_mutex_init(&vGpioHostDrv.dispMtx, NULL);
	pthread_cond_init(&vGpioHostDrv.dispCond, NULL);

	ret = pthread_create(&vGpioHostDrv.dispThread, NULL, virtioHostGpioReqDispatch, NULL);
	if (ret) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"failed to create virtio GPIO host dispatch thread\n");
	}

	ret = pthread_create(&virtioHostGpioMeventDispatchThread, NULL,
			virtioHostGpioMeventDispatch, NULL);
	if (ret) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"failed to create mevent dispatch thread(%d)\n", ret);
	}
}

static void virtioHostGpioUpdateLineInfo(struct gpio_line *line)
{
	struct gpiod_line_info *linfo;
	enum gpiod_line_direction dir;
	const char *name;

	linfo = gpiod_chip_get_line_info(line->chip->lchip, line->offset);
	if (!linfo) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"failed to get line info\n");
		return;
	}

	line->busy = gpiod_line_info_is_used(linfo);

	/*
	 * if it is already used by virtio gpio model,
	 * it is not set to busy state
	 */
	if (line->request)
		line->busy = false;

	dir = gpiod_line_info_get_direction(linfo);
	switch (dir) {
		case GPIOD_LINE_DIRECTION_AS_IS:
			line->dir = VIRTIO_GPIO_DIRECTION_NONE;
			break;
		case GPIOD_LINE_DIRECTION_OUTPUT:
			line->dir = VIRTIO_GPIO_DIRECTION_OUT;
			break;
		case GPIOD_LINE_DIRECTION_INPUT:
			line->dir = VIRTIO_GPIO_DIRECTION_IN;
			break;
		default:
			VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"unknown direction type, fall back to none\n");
			line->dir = VIRTIO_GPIO_DIRECTION_NONE;
			break;
	}

	name = gpiod_line_info_get_name(linfo);
	if (name)
		strncpy(line->name, name, sizeof(line->name) - 1);

	gpiod_line_info_free(linfo);
}

static void virtioHostGpioCloseLine(struct gpio_line *line)
{
	if (line->request)
		gpiod_line_request_release(line->request);
}

static void virtioHostGpioCloseChip(struct native_gpio_chip *chip)
{
	int i;

	if (chip) {
		memset(chip->name, 0, sizeof(chip->name));
		memset(chip->label, 0, sizeof(chip->label));
		memset(chip->dev_name, 0, sizeof(chip->dev_name));
		for (i = 0; i < chip->ngpio; i++) {
			virtioHostGpioCloseLine(&chip->lines[i]);
		}

		if (chip->lines) {
			free(chip->lines);
			chip->lines = NULL;
		}

		chip->ngpio = 0;
	}
}

static int virtioHostGpioOpenLine(struct gpio_line *line)
{
	struct gpiod_request_config *req_cfg = NULL;
	struct gpiod_line_settings *settings;
	struct gpiod_line_config *line_cfg;
	int ret;

	settings = gpiod_line_settings_new();
	if (!settings)
		return -1;

	gpiod_line_settings_set_direction(settings, GPIOD_LINE_DIRECTION_AS_IS);

	line_cfg = gpiod_line_config_new();
	if (!line_cfg)
		goto free_settings;

	ret = gpiod_line_config_add_line_settings(line_cfg, &line->offset, 1,
			settings);
	if (ret)
		goto free_line_config;

	req_cfg = gpiod_request_config_new();
	if (!req_cfg)
		goto free_line_config;

	gpiod_request_config_set_consumer(req_cfg, "VirtIO IO");

	line->request = gpiod_chip_request_lines(line->chip->lchip, req_cfg, line_cfg);
	if (!line->request)
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"failed to request line %d, %d, %s\n", line->offset, ret, strerror(errno));

	gpiod_request_config_free(req_cfg);

free_line_config:
	gpiod_line_config_free(line_cfg);

free_settings:
	gpiod_line_settings_free(settings);

	return ret;
}

static int virtioHostGpioSetValue(struct virtioGpioHostCtx *pGpioHostCtx, uint16_t offset,
		uint32_t value)
{
	struct gpio_line *line;
	enum gpiod_line_value lvalue;
	struct gpiod_line_settings *settings;
	struct gpiod_line_config *line_cfg;
	int ret;

	line = pGpioHostCtx->vlines[offset];
	if (!line) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"null line %d\n", offset);
		return -1;
	}

	if (!line->request) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"null request %d\n", offset);
		return -1;
	}

	if (line->busy) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"busy line %d\n", offset);
		return -1;
	}

	if (value == 1) {
		lvalue = GPIOD_LINE_VALUE_ACTIVE;
	} else if (value == 0) {
		lvalue = GPIOD_LINE_VALUE_INACTIVE;
	} else {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"unknown value gpio %d value: %d\n", offset, value);
		return -1;
	}

	if (line->dir == VIRTIO_GPIO_DIRECTION_OUT) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
				"set offset %d value to %d\n", offset, value);

		ret = gpiod_line_request_set_value(line->request, line->offset, lvalue);
		if (ret) {
			VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
					"failed to set value %d, %s\n", offset, strerror(errno));
			return -1;
		}
	} else {
		/* Set direction to out with output value as we want */
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
				"set offset %d direction to out with value %d\n", offset, value);

		settings = gpiod_line_settings_new();
		if (!settings) {
			VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
					"failed to allocate settings %d\n", offset);
			return -1;
		}

		gpiod_line_settings_set_direction(settings, GPIOD_LINE_DIRECTION_OUTPUT);
		gpiod_line_settings_set_output_value(settings, lvalue);

		line_cfg = gpiod_line_config_new();
		if (!line_cfg) {
			VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
					"failed to allocate line config %d\n", offset);
			goto free_settings;
		}

		ret = gpiod_line_config_add_line_settings(line_cfg, &line->offset, 1,
				settings);
		if (ret) {
			VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
					"failed to add line settings %d, %d\n", offset, ret);
			goto free_line_config;
		}

		ret = gpiod_line_request_reconfigure_lines(line->request, line_cfg);
		if (ret) {
			VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
					"failed to reconfigure line %d, %d: %s\n", offset, ret, strerror(errno));
			goto free_line_config;
		}

		/* Update line info */
		virtioHostGpioUpdateLineInfo(line);

free_line_config:
		if (line_cfg)
			gpiod_line_config_free(line_cfg);

free_settings:
		if (settings)
			gpiod_line_settings_free(settings);
	}

	/* Update line value */
	line->value = value;

	return ret;
}

static int virtioHostGpioGetValue(struct virtioGpioHostCtx *pGpioHostCtx,
		uint16_t offset)
{
	struct gpio_line *line;
	enum gpiod_line_value lvalue;
	int value;
	int rc;

	line = pGpioHostCtx->vlines[offset];
	if (!line) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"null line %d\n", offset);
		return -1;
	}

	if (!line->request) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"null request %d\n", offset);
		return -1;
	}

	if (line->busy) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"busy line %d\n", offset);
		return -1;
	}

	lvalue = gpiod_line_request_get_value(line->request, offset);

	if (lvalue == GPIOD_LINE_VALUE_ACTIVE) {
		value = 1;
	} else if (lvalue == GPIOD_LINE_VALUE_INACTIVE) {
		value = 0;
	} else {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"unknown value gpio %d lvalue %d, %s\n", offset, lvalue, strerror(errno));
		return -1;
	}

	return value;
}

static int virtioHostGpioSetDirection(struct virtioGpioHostCtx *pGpioHostCtx,
		uint16_t offset, uint32_t value)
{
	struct gpio_line *line;
	struct gpiod_line_settings *settings;
	struct gpiod_line_config *line_cfg;
	enum gpiod_line_direction ldir;
	enum gpiod_line_value lvalue;
	int ret = -1;

	line = pGpioHostCtx->vlines[offset];

	if (!line) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"null line %d\n", offset);
		return -1;
	}

	if (!line->request) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"null request %d\n", offset);
		return -1;
	}

	if (line->busy) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"busy line %d\n", offset);
		return -1;
	}

	switch (value) {
		case VIRTIO_GPIO_DIRECTION_NONE:
			ldir = GPIOD_LINE_DIRECTION_AS_IS;
			break;
		case VIRTIO_GPIO_DIRECTION_OUT:
			ldir = GPIOD_LINE_DIRECTION_OUTPUT;
			break;
		case VIRTIO_GPIO_DIRECTION_IN:
			ldir = GPIOD_LINE_DIRECTION_INPUT;
			break;
		default:
			VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"unknown gpio %d direction: %d\n", offset, value);
			return -1;
	}

	settings = gpiod_line_settings_new();
	if (!settings) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"failed to allocate settings %d\n", offset);
		return -1;
	}

	gpiod_line_settings_set_direction(settings, ldir);

	/* output pin needs a value*/
	if (ldir == GPIOD_LINE_DIRECTION_OUTPUT) {
		if (line->value == 1) {
			lvalue = GPIOD_LINE_VALUE_ACTIVE;
		} else if (line->value == 0) {
			lvalue = GPIOD_LINE_VALUE_INACTIVE;
		} else {
			VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
					"unknown gpio %d value: %d\n",
					offset, line->value);
			return -1;
		}

		gpiod_line_settings_set_output_value(settings, lvalue);
	}

	line_cfg = gpiod_line_config_new();
	if (!line_cfg) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"failed to allocate line config %d\n", offset);
		goto free_settings;
	}

	ret = gpiod_line_config_add_line_settings(line_cfg, &line->offset, 1,
						  settings);
	if (ret) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"failed to add line settings %d, %d\n", offset, ret);
		goto free_line_config;
	}

	ret = gpiod_line_request_reconfigure_lines(line->request, line_cfg);
	if (ret) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"failed to reconfigure line %d, %d: %s\n", offset, ret, strerror(errno));
		goto free_line_config;
	}

	/* Update line info */
	virtioHostGpioUpdateLineInfo(line);

free_line_config:
	gpiod_line_config_free(line_cfg);

free_settings:
	gpiod_line_settings_free(settings);

	return ret;
}

static int virtioHostGpioGetDirection(struct virtioGpioHostCtx *pGpioHostCtx,
		uint16_t offset)
{
	struct gpio_line *line;

	line = pGpioHostCtx->vlines[offset];
	if (!line) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"null line %d\n", offset);
		return -1;
	}

	if (!line->request) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"null request %d\n", offset);
		return -1;
	}

	if (line->busy) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"busy line %d\n", offset);
		return -1;
	}

	virtioHostGpioUpdateLineInfo(line);

	return line->dir;
}

static int virtioHostGpioOpenChip(struct native_gpio_chip *chip, const char *name)
{
	struct gpiod_chip *lchip;
	struct gpiod_chip_info *lchip_info;
	struct gpio_line *line;
	char path[64] = {0};
	int rc, i;

	snprintf(path, sizeof(path), "/dev/%s", name);
	lchip = gpiod_chip_open(path);
	if (!lchip) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"failed to open chip\n");
		goto fail;
	}

	lchip_info = gpiod_chip_get_info(lchip);
	if (!lchip_info) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"failed to get chip info\n");
		goto fail;
	}

	chip->ngpio = gpiod_chip_info_get_num_lines(lchip_info);
	chip->lines = calloc(1, chip->ngpio * sizeof(*chip->lines));
	if (!chip->lines) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"Alloc chip lines error, %s:%d, error %s\n",
				path, chip->ngpio, strerror(errno));
		goto fail;
	}

	chip->lchip = lchip;
	strncpy(chip->name, gpiod_chip_info_get_name(lchip_info), min(sizeof(chip->name), 32) - 1);
	strncpy(chip->label, gpiod_chip_info_get_label(lchip_info), min(sizeof(chip->label), 32) - 1);
	strncpy(chip->dev_name, name, sizeof(chip->dev_name) - 1);

	/* initialize all lines of the chip */
	for (i = 0; i < chip->ngpio; i++) {
		line = &chip->lines[i];
		line->offset = i;
		line->chip = chip;

		/*
		 * The line's voffset will be initialized
		 * when virtual gpio line connects to the real line.
		 */
		line->voffset = -1;

		/* Set line state and name via ioctl*/
		virtioHostGpioUpdateLineInfo(line);
	}

	return 0;

fail:
	gpiod_chip_info_free(lchip_info);
	chip->ngpio = 0;
	return -1;
}

static int virtioHostGpioGetOffset(struct native_gpio_chip *chip, char *name)
{
	int rc;
	int i;

	/* try to find a gpio index by offset or name */
	if (isalpha(name[0])) {
		for (i = 0; i < chip->ngpio; i++) {
			if (!strcmp(chip->lines[i].name, name))
				return i;
		}
	} else if (isdigit(name[0])) {
		i = (int)strtol(name, NULL, 10);
		if (i < chip->ngpio)
			return i;
	}
	return -1;
}

static struct gpio_line* virtioHostGpioFindLine(struct native_gpio_chip *chip, const char *name)
{
	int offset, ret;
	char *b, *o, *c;
	struct gpio_line *line = NULL;

	b = o = strdup(name);
	c = strsep(&o, "=");

	/* find the line's offset in the chip by name or number */
	offset = virtioHostGpioGetOffset(chip, c);
	if (offset < 0) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"line %s has not been found in chip %s\n",
				c, chip->dev_name);
		goto out;
	}

	line = &chip->lines[offset];
	if (line->busy) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"line %s is busy now\n");
		line = NULL;
		goto out;
	}

	line->offset = offset;

	ret = virtioHostGpioOpenLine(line);
	if (ret) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"failed to open line %d, %d\n", offset, ret);
		line = NULL;
		goto out;
	}

	/* If the user sets the name of the GPIO, copy it to vname */
	if (o)
		strncpy(line->vname, o, sizeof(line->vname) - 1);

out:
	free(b);
	return line;
}

static int virtioHostGpioInit(struct virtioGpioHostCtx *pGpioHostCtx, char *opts)
{
	struct gpio_line *line;
	char *cstr, *lstr, *tmp, *b, *o;
	int rc;
	int cn = 0;
	int ln = 0;

	/*
	 * <gpio resources> format
	 * <@chip_name0{offset|name[=vname]:offset|name[=vname]:...}
	 * [@chip_name1{offset|name[=vname]:offset|name[=vname]:...}]
	 * [@chip_name2{offset|name[=vname]:offset|name[=vname]:...}]
	 * ...>
	 */

	b = o = strdup(opts);
	while ((tmp = strsep(&o, "@")) != NULL) {

		/* discard subsequent chips */
		if (cn >= VIRTIO_GPIO_MAX_CHIPS ||
				ln >= VIRTIO_GPIO_MAX_VLINES) {
			VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
					"gpio chips or lines reach max, cn %d, ln %d\n",
					cn, ln);
			break;
		}

		/* ignore the null string */
		if (tmp[0] == '\0')
			continue;

		/*
		 * parse gpio chip name
		 * if there is no gpiochip information, like "@{...}"
		 * ignore all of the lines.
		 */
		cstr = strsep(&tmp, "{");
		if (!tmp || !cstr || cstr[0] == '\0')
			continue;

		/* get chip information with its name */
		rc = virtioHostGpioOpenChip(&pGpioHostCtx->chips[cn], cstr);
		if (rc < 0)
			continue;

		/* parse all gpio lines in one chip */
		cstr = strsep(&tmp, "}");
		while ((lstr = strsep(&cstr, ":")) != NULL) {

			/* safety check, to avoid "@gpiochip0{::0:1...}" */
			if (lstr[0] == '\0')
				continue;

			/* discard subsequent lines */
			if (ln >= VIRTIO_GPIO_MAX_VLINES) {
				VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
						"virtual gpio lines reach max:%d\n",
						ln);
				break;
			}

			/*
			 * If the line provided by gpio command line is found
			 * assign one virtual gpio offset for it.
			 * We now have got the request handle for the line.
			 */
			line = virtioHostGpioFindLine(&pGpioHostCtx->chips[cn], lstr);
			if (line) {
				pGpioHostCtx->vlines[ln] = line;
				line->voffset = ln;
				ln++;
			}
		}
		cn++;
	}

	pGpioHostCtx->nchip = cn;
	pGpioHostCtx->nvline = ln;
	free(b);

	return ln == 0 ? -1 : 0;
}

static void virtioHostGpioIrqGenerateInt(struct virtioGpioHostCtx *pGpioHostCtx, int pin)
{
	struct gpio_irq_chip *chip;
	struct gpio_irq_desc *desc;
	struct virtio_gpio_irq_response *irs;
	struct virtioHostQueue *pQueue;
	struct virtioHost *vhost = (struct virtioHost *)pGpioHostCtx;

	pQueue = vhost->pQueue + VIRTIO_GPIO_EVT_QUEUE;

	chip = &pGpioHostCtx->irq_chip;
	desc = &chip->descs[pin];

	pGpioHostCtx->irq_stat.total++;

	pthread_mutex_lock(&desc->mtx);

	desc->line->irq_stat.total++;

	if (desc->mode == VIRTIO_GPIO_IRQ_TYPE_NONE) {
		/* interrupts coming when pin disabled are delivered as invalid */
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"irq comes when disabled\n");
		pGpioHostCtx->irq_stat.invalid++;
		desc->line->irq_stat.invalid++;

		if (desc->irs)
			desc->irs->status = VIRTIO_GPIO_IRQ_STATUS_INVALID;
	} else if (desc->mask) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
				"irq comes when enabled but masked\n");

		pGpioHostCtx->irq_stat.latched++;
		desc->line->irq_stat.latched++;

		/* edge trigger: latch and return
		 * level trigger: ignore and return
		 */
		if (desc->mode & VIRTIO_GPIO_IRQ_TYPE_EDGE_BOTH)
			desc->pending = true;

		pthread_mutex_unlock(&desc->mtx);
		return;
	} else {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
				"irq comes when enabled and unmasked\n");

		pGpioHostCtx->irq_stat.valid++;
		desc->line->irq_stat.valid++;

		if (desc->irs)
			desc->irs->status = VIRTIO_GPIO_IRQ_STATUS_VALID;

		/* mask it until FE driver unmasks it again */
		desc->mask = true;
	}

	/* return the buffer pair */
	(void)virtioHostQueueRelBuf(pQueue, desc->idx, sizeof(*desc->irs));
	(void)virtioHostQueueNotify(pQueue);

	desc->irs = NULL;
	desc->idx = UINT16_MAX;

	pthread_mutex_unlock(&desc->mtx);
}

static void virtioHostGpioIrqSetPin(int fd __attribute__((unused)),
		enum ev_type t __attribute__((unused)),
		void *arg)
{
	struct gpio_irq_desc *desc = (struct gpio_irq_desc *)arg;
	struct gpiod_edge_event *event;
	int i, ret;

	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO, "start\n");

	ret = gpiod_line_request_read_edge_events(desc->line->request,
			desc->event_buffer, desc->nbuffer);
	if (ret == -1) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"failed to read edge events: %s\n",
				strerror(errno));
		return;
	}

	for (i = 0; i < ret; i++) {
		event = gpiod_edge_event_buffer_get_event(desc->event_buffer, i);
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
				"offset: %d, #%ld, type: %d\n",
				gpiod_edge_event_get_line_offset(event),
				gpiod_edge_event_get_line_seqno(event),
				gpiod_edge_event_get_event_type(event));

		switch (gpiod_edge_event_get_event_type(event)) {
			case GPIOD_EDGE_EVENT_RISING_EDGE:
				/* jitter protection */
				if ((desc->mode & VIRTIO_GPIO_IRQ_TYPE_EDGE_RISING)
						|| (desc->mode & VIRTIO_GPIO_IRQ_TYPE_LEVEL_HIGH))
					virtioHostGpioIrqGenerateInt(desc->pGpioHostCtx, desc->pin);
				break;
			case GPIOD_EDGE_EVENT_FALLING_EDGE:
				/* jitter protection */
				if ((desc->mode & VIRTIO_GPIO_IRQ_TYPE_EDGE_FALLING)
						|| (desc->mode & VIRTIO_GPIO_IRQ_TYPE_LEVEL_LOW))
					virtioHostGpioIrqGenerateInt(desc->pGpioHostCtx, desc->pin);
				break;
			default:
				VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
						"undefined libgpiod event id %d\n",
						gpiod_edge_event_get_line_offset(event));
		}
	}

	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO, "done\n");
}

static int virtioHostGpioIrqDisable(struct virtioGpioHostCtx *pGpioHostCtx,
		uint16_t offset)
{
	struct gpio_irq_desc *desc;
	struct virtioHost *vhost;
	struct virtioHostQueue *pQueue;
	int ret;

	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO, "start\n");

	if (offset >= VIRTIO_GPIO_MAX_VLINES) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"invalid pin offset %d\n", offset);
		return -1;
	}

	desc = &pGpioHostCtx->irq_chip.descs[offset];

	pthread_mutex_lock(&desc->mtx);

	/* close the line */
	virtioHostGpioCloseLine(desc->line);

	/* switch the pin to GPIO mode */
	ret = virtioHostGpioOpenLine(desc->line);
	if (ret)
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"failed to switch pin to GPIO mode, %d\n", ret);

	/* return pending buffer pair as invalid */
	if (desc->irs) {
		vhost = (struct virtioHost *)pGpioHostCtx;
		pQueue = &vhost->pQueue[VIRTIO_GPIO_EVT_QUEUE];
		desc->irs->status = VIRTIO_GPIO_IRQ_STATUS_INVALID;

		(void)virtioHostQueueRelBuf(pQueue, desc->idx, sizeof(*desc->irs));
		(void)virtioHostQueueNotify(pQueue);

		desc->irs = NULL;
		desc->idx = UINT16_MAX;
	}

	/* release the mevent, mevent teardown handles IRQ desc reset */
	if (desc->mevt) {
		mevent_delete(desc->mevt);
		desc->mevt = NULL;
	}

	pthread_mutex_unlock(&desc->mtx);

	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO, "done\n");

	return 0;
}

static void virtioHostGpioIrqTeardown(void *param)
{
	struct gpio_irq_desc *desc;

	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO, "start\n");

	desc = (struct gpio_irq_desc *)param;
	desc->mask = true;
	desc->pending = false;
	desc->mode = VIRTIO_GPIO_IRQ_TYPE_NONE;
	desc->irs = NULL;
	desc->idx = UINT16_MAX;

	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO, "done\n");
}

static int virtioHostGpioIrqEnable(struct virtioGpioHostCtx *pGpioHostCtx,
		uint16_t offset, uint16_t type)
{
	unsigned int offsets = (unsigned int)offset;
	struct gpiod_line_settings *settings;
	struct gpiod_line_config *line_cfg;
	struct gpiod_request_config *req_cfg;
	enum gpiod_line_edge ltype;
	struct gpio_line *line;
	struct gpio_irq_desc *desc;
	int ret;

	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO, "start\n");

	line = pGpioHostCtx->vlines[offset];

	/* Close the line */
	virtioHostGpioCloseLine(line);

	/* Request the line as an interrupt source */
	settings = gpiod_line_settings_new();
	if (!settings) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"failed to allocate settings\n");
		return -EINVAL;
	}

	/* libgpiod only supports edge trigger */
	switch (type) {
		case VIRTIO_GPIO_IRQ_TYPE_NONE:
			ltype = GPIOD_LINE_EDGE_NONE;
			break;
		case VIRTIO_GPIO_IRQ_TYPE_EDGE_RISING:
		case VIRTIO_GPIO_IRQ_TYPE_LEVEL_HIGH:
			ltype = GPIOD_LINE_EDGE_RISING;
			break;
		case VIRTIO_GPIO_IRQ_TYPE_EDGE_FALLING:
		case VIRTIO_GPIO_IRQ_TYPE_LEVEL_LOW:
			ltype = GPIOD_LINE_EDGE_FALLING;
			break;
		case VIRTIO_GPIO_IRQ_TYPE_EDGE_BOTH:
			ltype = GPIOD_LINE_EDGE_BOTH;
			break;
		default:
			VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
					"unknown irq type %d, fall back to GPIOD_LINE_EDGE_NONE\n",
					type);
			ltype = GPIOD_LINE_EDGE_NONE;
			break;
	}

	gpiod_line_settings_set_direction(settings, GPIOD_LINE_DIRECTION_INPUT);
	gpiod_line_settings_set_edge_detection(settings, ltype);

	line_cfg = gpiod_line_config_new();
	if (!line_cfg)
		goto free_settings;

	ret = gpiod_line_config_add_line_settings(line_cfg, &offsets, 1,
						  settings);
	if (ret)
		goto free_line_config;

	req_cfg = gpiod_request_config_new();
	if (!req_cfg)
		goto free_line_config;

	gpiod_request_config_set_consumer(req_cfg, "VirtIO IRQ");

	line->request = gpiod_chip_request_lines(line->chip->lchip, req_cfg, line_cfg);

	gpiod_request_config_free(req_cfg);

	/* Set desc */
	desc = line->desc;
	pthread_mutex_lock(&desc->mtx);

	desc->pGpioHostCtx = pGpioHostCtx;
	desc->mode = type;
	desc->mevt = mevent_add(gpiod_line_request_get_fd(line->request), EVF_READ,
			virtioHostGpioIrqSetPin, desc,
			virtioHostGpioIrqTeardown, desc);
	if (!desc->mevt) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"failed to enable IRQ pin %d, mevent add error\n",
				offset);
		pthread_mutex_unlock(&desc->mtx);
		goto mevent_fail;
	}

	pthread_mutex_unlock(&desc->mtx);

free_line_config:
	gpiod_line_config_free(line_cfg);

free_settings:
	gpiod_line_settings_free(settings);

	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO, "done\n");

	return ret;

mevent_fail:
	ret = virtioHostGpioIrqDisable(pGpioHostCtx, offset);
	return ret;
}

static int virtioHostGpioIrqInit(struct virtioGpioHostCtx *pGpioHostCtx)
{
	struct gpio_irq_chip *chip;
	struct gpio_irq_desc *desc;
	struct gpio_line *line;
	int i, ret;

	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO, "start\n");

	chip = &pGpioHostCtx->irq_chip;
	for (i = 0; i < pGpioHostCtx->nvline; i++) {
		desc = &chip->descs[i];
		line = pGpioHostCtx->vlines[i];

		ret = pthread_mutex_init(&desc->mtx, NULL);
		if (ret) {
			VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
					"failed to init desc mutex %d\n", ret);
			return -1;
		}

		desc->event_buffer = gpiod_edge_event_buffer_new(VIRTIO_GPIO_BUFFER_NUM_PER_LINE);
		if (!desc->event_buffer) {
			VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
					"failed to allocate event buffer for vline %d\n", i);
			return -1;
		}
		desc->nbuffer = VIRTIO_GPIO_BUFFER_NUM_PER_LINE;

		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
				"desc %d: %p, event_buffer=%p\n",
				i, desc, desc->event_buffer);

		desc->pin = i;
		desc->mevt = NULL;
		desc->data = pGpioHostCtx;
		desc->line = line;
		desc->mask = true;
		desc->pending = false;
		desc->mode = VIRTIO_GPIO_IRQ_TYPE_NONE; /* will be set when enabled */
		desc->irs = NULL;
		desc->idx = UINT16_MAX;
		line->desc = desc;
	}

	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO, "done\n");

	return 0;
}

static void virtioHostGpioIrqDeinit(struct virtioGpioHostCtx *pGpioHostCtx)
{
	struct gpio_irq_chip *chip;
	struct gpio_irq_desc *desc;
	int i;

	chip = &pGpioHostCtx->irq_chip;
	for (i = 0; i < pGpioHostCtx->nvline; i++) {
		desc = &chip->descs[i];
		pthread_mutex_destroy(&desc->mtx);
		if (desc->mevt) {
			mevent_delete(desc->mevt);
			desc->mevt = NULL;
		}
		gpiod_edge_event_buffer_free(desc->event_buffer);
	}
}

static void virtioHostGpioPrintStats(struct gpio_irq_chip *chip)                                    
{                                                                                
	struct gpio_irq_desc *desc;
	int i;

	for (i = 0; i < VIRTIO_GPIO_MAX_VLINES; i++) {
		desc = &chip->descs[i];
		if (!desc->line)
			continue;
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
				"GPIO %d int: unmasked: %lu, valid: %lu, invalid: %lu, latched: %lu, total: %lu\n",
				desc->line->offset,
				desc->line->irq_stat.unmasked,
				desc->line->irq_stat.valid,
				desc->line->irq_stat.invalid,
				desc->line->irq_stat.latched,
				desc->line->irq_stat.total);
	}                                                                        
}

void virtioHostGpioDrvRelease(void)
{
	struct virtioGpioHostDev *pGpioHostDev;
	struct virtioGpioHostCtx *pGpioHostCtx;
	uint32_t queue;
	uint32_t devNum;
	int ret;

	for (devNum = 0; devNum < vGpioHostDrv.vGpioHostDevNum; devNum++) {
		pGpioHostDev = vGpioHostDrv.vGpioHostDevList[devNum];

		if (!pGpioHostDev)
			continue;

		pGpioHostCtx = (struct virtioGpioHostCtx *)pGpioHostDev;
		if (pGpioHostCtx->rq_thread &&
		    pthread_cancel(pGpioHostCtx->rq_thread) == 0) {
			pthread_join(pGpioHostCtx->rq_thread, NULL);
		}

		if (pGpioHostCtx->ev_thread &&
		    pthread_cancel(pGpioHostCtx->ev_thread) == 0) {
			pthread_join(pGpioHostCtx->ev_thread, NULL);
		}

		if (pthread_cancel(virtioHostGpioMeventDispatchThread) == 0) {
			pthread_join(virtioHostGpioMeventDispatchThread, NULL);
		}

		virtioHostRelease(&pGpioHostCtx->vhost);

		free(pGpioHostDev);
	}
}

/*******************************************************************************
 *
 * virtioHostGpioDevCreate - create virtio GPIO device instance
 *
 * This routine parses argument list of virtio GPIO device.
 * and creates and initializes create virtio GPIO device instance.
 *
 * RETURNS: 0, or negative value of errno number if any error is raised
 * in process of the parsing.
 *
 * ERRNO: N/A
 */

static int virtioHostGpioDevCreate(struct virtioHostDev *pHostDev,
		struct virtioGpioHostDev *pGpioHostDev)
{
	struct virtioGpioHostCtx *pGpioHostCtx = (struct virtioGpioHostCtx *)pGpioHostDev;
	struct virtioHost *vhost = (struct virtioHost *)pGpioHostDev;
	int ret, i;

	pHostDev->args[PATH_MAX] = '\0';

	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO, "%s\n", pHostDev->args);

	/* backend device initialization */
	ret = virtioHostGpioInit(pGpioHostCtx, pHostDev->args);
	if (ret) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"failed to init GPIO %d\n", ret);
		goto gpio_fail;
	}

	ret = virtioHostGpioIrqInit(pGpioHostCtx);
	if (ret) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"failed to init IRQ %d\n", ret);
		goto irq_fail;
	}

	/* set device features */
	pGpioHostCtx->feature = (1UL << VIRTIO_F_VERSION_1) |
		(1UL << VIRTIO_GPIO_F_IRQ) |
		(1UL << VIRTIO_RING_F_EVENT_IDX) |
		(1UL << VIRTIO_RING_F_INDIRECT_DESC);

	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
			"feature: 0x%lx\n", pGpioHostCtx->feature);

	/* host device initialization */
	pGpioHostCtx->nqueue = (pGpioHostCtx->feature & (1UL << VIRTIO_GPIO_F_IRQ)) ? 2 : 1;

	vhost->channelId = pHostDev->channels->channelId;
	vhost->pMaps = pHostDev->channels->pMap;

	ret = virtioHostCreate(vhost,
			VIRTIO_DEV_ANY_ID,
			VIRTIO_ID_GPIO,
			&pGpioHostCtx->feature,
			pGpioHostCtx->nqueue,
			VIRTIO_GPIO_QUEUE_MAX_NUM,
			0, NULL,
			&virtioGpioHostOps);
	if (ret) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"failed to create virtio host device(%d)\n", ret);
		goto host_fail;
	}

	/* IO handling threads initialization */
	ret = pthread_create(&pGpioHostCtx->rq_thread, NULL,
			virtioHostGpioHandleRequest, pGpioHostCtx);
	if (ret) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"failed to create request queue handling thread(%d)\n", ret);
		goto rq_fail;
	}

	sem_init(&pGpioHostCtx->rq_sem, 0, 0);

	ret = pthread_create(&pGpioHostCtx->ev_thread, NULL,
			virtioHostGpioHandleEvent, pGpioHostCtx);
	if (ret) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"failed to create event queue handling thread(%d)\n", ret);
		goto ev_fail;
	}

	sem_init(&pGpioHostCtx->ev_sem, 0, 0);

	/* GPIO configuration initialization */
	pGpioHostCtx->cfg.ngpio = pGpioHostCtx->nvline;
	pGpioHostCtx->cfg.gpio_names_size = pGpioHostCtx->nvline * GPIO_MAX_NAME_SIZE;

	/* GPIO driver initialization */
	pthread_mutex_lock(&vGpioHostDrv.drvMtx);
	vGpioHostDrv.vGpioHostDevList[vGpioHostDrv.vGpioHostDevNum]
			= pGpioHostDev;
	vGpioHostDrv.vGpioHostDevNum++;
	pthread_mutex_unlock(&vGpioHostDrv.drvMtx);

	/* Show configuration */
	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
			"nqueue:%d\n", pGpioHostCtx->nqueue);
	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
			"nchip:%d\n", pGpioHostCtx->nchip);
	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
			"nvline:%d\n", pGpioHostCtx->nvline);

	for (i = 0; i < pGpioHostCtx->nchip; i++) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
				"chip %d native name: %s\n", i, pGpioHostCtx->chips[i].name);
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
				"chip %d virtio name: %s\n", i, pGpioHostCtx->chips[i].dev_name);
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
				"chip %d label: %s\n", i, pGpioHostCtx->chips[i].label);
	}

	for (i = 0; i < pGpioHostCtx->nvline; i++) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
				"vline %d native name: %s\n", i, pGpioHostCtx->vlines[i]->name);
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
				"vline %d virtio name: %s\n", i, pGpioHostCtx->vlines[i]->vname);
	}

	return 0;

ev_fail:
rq_fail:
host_fail:
	virtioHostGpioIrqDeinit(pGpioHostCtx);

irq_fail:
	for (i = 0; i < pGpioHostCtx->nchip; i++)
		virtioHostGpioCloseChip(&pGpioHostCtx->chips[i]);

gpio_fail:
	virtioHostGpioDrvRelease();

	return -1;
}

/*******************************************************************************
 *
 * virtioHostGpioCreate - create a virtio GPIO device
 *
 * This routine creates a virtio GPIO device backend driver to simuilate
 * a real storage device.
 *
 * RETURNS: 0, or negative value of errno number if any error is raised
 * in process of the GPIO device creating.
 *
 * ERRNO: N/A
 */

static int virtioHostGpioCreate(struct virtioHostDev *pHostDev)
{
	struct virtioGpioHostDev *pGpioHostDev;
	int ret;

	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO, "start\n");

	if (!pHostDev) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"pHostDev is NULL\n");
		return -EINVAL;
	}

	/* the virtio channel number is always one */
	if (pHostDev->channelNum > 1) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"channel number is %d, only one channel is supported\n",
				pHostDev->channelNum);
		return -EINVAL;
	}

	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO, "\n"
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

	if (vGpioHostDrv.vGpioHostDevNum == VIRTIO_GPIO_HOST_DEV_MAX) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"No more than %d GPIO devices can be created\n", VIRTIO_GPIO_HOST_DEV_MAX);
		return -ENOENT;
	}

	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
			"sizeof(struct virtioGpioHostDev) is %ld bytes\n",
			sizeof(struct virtioGpioHostDev));

	pGpioHostDev = calloc(1, sizeof(struct virtioGpioHostDev));
	if (!pGpioHostDev) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"failed to allocate memory\n");
		return -ENOMEM;
	}

	ret = virtioHostGpioDevCreate(pHostDev, pGpioHostDev);
	if (ret)
		goto exit;

exit:
	if (ret) {
		free(pGpioHostDev);
		return ret;
	}

	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO, "done\n");

	return 0;
}

/*******************************************************************************
 *
 * virtioHostGpioAbort - abort a request handling
 *
 * This routine is used to abort a request handling when a request is seen
 * with incorrect format, which will be abandoned.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */
static void virtioHostGpioAbort(struct virtioHostQueue *pQueue, uint16_t idx)
{
	if (idx < pQueue->vRing.num) {
		(void)virtioHostQueueRelBuf(pQueue, idx, 1);
		(void)virtioHostQueueNotify(pQueue);
	}

	return;
}

/*******************************************************************************
 *
 * virtioHostGpioReqDispatch - virtio net device dispatch task
 *
 * This routine is used to dispatch virtio net device IO or control requests
 * to specific handling thread(s).
 *
 * RETURNS: 0, or -1 if the recieved operation request with a invalid format or
 * error meeting a failure in process of filesystem operation.
 *
 * ERRNO: N/A
 */

static void* virtioHostGpioReqDispatch(void *my_unused)
{
	struct virtioGpioHostCtx *pGpioHostCtx;
	struct virtioDispObj *pDispObj;
	uint32_t queueId;
	int ret;

	pthread_mutex_lock(&vGpioHostDrv.dispMtx);

	while (1) {
		while (1) {
			if (TAILQ_EMPTY(&vGpioHostDrv.dispBusyQ))
				break;

			pDispObj = TAILQ_FIRST(&vGpioHostDrv.dispBusyQ);
			if (pDispObj) {
				TAILQ_REMOVE(&vGpioHostDrv.dispBusyQ, pDispObj, link);
			} else {
				VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
						"failed to get dispatch object from busy queue\n");
			}

			pthread_mutex_unlock(&vGpioHostDrv.dispMtx);

			if (pDispObj && pDispObj->pQueue && pDispObj->pQueue->vHost) {
				pGpioHostCtx = (struct virtioGpioHostCtx *)pDispObj->pQueue->vHost;
				queueId = pDispObj->pQueue - pDispObj->pQueue->vHost->pQueue;
				if (queueId == VIRTIO_GPIO_REQ_QUEUE) {
					ret = sem_post(&pGpioHostCtx->rq_sem);
					if (ret)
						VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
								"failed to sem_post rq_sem: %s\n",
								strerror(errno));
				} else if (queueId == VIRTIO_GPIO_EVT_QUEUE) {
					ret = sem_post(&pGpioHostCtx->ev_sem);
					if (ret)
						VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
								"failed to sem_post ev_sem: %s\n",
								strerror(errno));
				} else {
					VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
							"unknown queue ID: %d\n", queueId);
				}
			} else {
				VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
						"failed to get virtqueue from busy object\n");
			}

			pthread_mutex_lock(&vGpioHostDrv.dispMtx);

			TAILQ_INSERT_TAIL(&vGpioHostDrv.dispFreeQ, pDispObj, link);
		}

		pthread_cond_wait(&vGpioHostDrv.dispCond, &vGpioHostDrv.dispMtx);
	}

	pthread_mutex_unlock(&vGpioHostDrv.dispMtx);

	return NULL;
}

/*******************************************************************************
 *
 * virtioHostGpioHandleRequest - virtio GPIO device request handle task
 *
 * This routine is used to create a handler task for virtio GPIO device to
 * handle request queue IO from front end.
 *
 * RETURNS: NULL
 *
 * ERRNO: N/A
 */
static void* virtioHostGpioHandleRequest(void *arg)
{
	int n, i, ret, len;
	uint16_t idx;
	struct virtioHost *vhost;
	struct virtioGpioHostCtx *pGpioHostCtx = arg;
	struct virtioHostQueue *pQueue;
	struct virtioHostBuf buffer[2];
	struct virtio_gpio_request *rq;
	struct virtio_gpio_response *rs;
	struct virtio_gpio_response_get_names *rsn;
	struct gpio_line *line;
	bool doNotify = false;

	vhost = (struct virtioHost *)pGpioHostCtx;
	pQueue = &vhost->pQueue[VIRTIO_GPIO_REQ_QUEUE];

	while (1) {
		ret = sem_wait(&pGpioHostCtx->rq_sem);
		if (ret < 0) {
			VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
					"failed to sem_wait rq_sem: %s\n", strerror(errno));
		}

		while (1) {
			n = virtioHostQueueGetBuf(pQueue, &idx, &buffer[0], 2);
			VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
					"n:%d\n", n);
			if (n == 0) {
				VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
						"no new request queue buffer\n");
				break;
			}

			if (n < 0) {
				VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
						"failed to get buffer(%d)\n", n);
				virtioHostGpioAbort(pQueue, pQueue->availIdx);
				break;
			}

			if (n == 1) {
				VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
						"failed to get request buffer pair\n");
				virtioHostGpioAbort(pQueue, pQueue->availIdx);
				break;
			}

			if (n > 2) {
				VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
						"invalid length of desc chain: %d, only 2 is valid\n", idx);
				virtioHostGpioAbort(pQueue, pQueue->availIdx);
				continue;
			}

			rq = (struct virtio_gpio_request *)buffer[0].buf;
			if (rq->type == VIRTIO_GPIO_MSG_GET_NAMES)
				rsn = (struct virtio_gpio_response_get_names *)buffer[1].buf;
			else
				rs = (struct virtio_gpio_response *)buffer[1].buf;

			if (rq->type == VIRTIO_GPIO_MSG_GET_NAMES) {
				if (buffer[1].len < sizeof(*rsn) + pGpioHostCtx->cfg.gpio_names_size) {
					VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
							"not enough space to save pin names: %d < %d\n",
							buffer[1].len, sizeof(*rsn) + pGpioHostCtx->cfg.gpio_names_size);
					virtioHostGpioAbort(pQueue, pQueue->availIdx);
					continue;
				}
			} else if (buffer[0].len != sizeof(*rq)) {
				VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
						"invalid request size: %d, %lu\n",
						buffer[0].len, sizeof(*rq));
				virtioHostGpioAbort(pQueue, pQueue->availIdx);
				continue;
			} else if (buffer[1].len != sizeof(*rs)) {
				VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
						"invalid response size: %d, %lu\n",
						buffer[1].len, sizeof(*rs));
				virtioHostGpioAbort(pQueue, pQueue->availIdx);
				continue;
			}

#ifdef VIRTIO_GPIO_DEV_DUMP
			VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
					"request start: %d, %d, %d\n", rq->gpio, rq->type, rq->value);
#endif
			switch(rq->type) {
				case VIRTIO_GPIO_MSG_GET_NAMES:
					len = 0;
					ret = 0;

					for (i = 0; i < pGpioHostCtx->nvline; i++) {
						line = pGpioHostCtx->vlines[i];

						/* user provided name or native name */
						if (strnlen(line->vname, sizeof(line->vname))) {
							strncpy((char *)(rsn->value + len), line->vname,
									strnlen(line->vname, sizeof(line->vname)));
							len += strnlen(line->vname, sizeof(line->vname));
						} else if (strnlen(line->name, sizeof(line->name))) {
							strncpy((char *)(rsn->value + len), line->name,
									strnlen(line->name, sizeof(line->name)));
							len += strnlen(line->name, sizeof(line->name));
						}

						rsn->value[len++] = '\0';

						VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
								"name %d: %s\n", i, rsn->value);

						if (len > sizeof(*rsn) + pGpioHostCtx->cfg.gpio_names_size) {
							VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
								"truncate %d, %d\n",
								len, sizeof(*rsn) + pGpioHostCtx->cfg.gpio_names_size);
							break;
						}
					}

					break;
				case VIRTIO_GPIO_MSG_GET_DIRECTION:
					ret = virtioHostGpioGetDirection(pGpioHostCtx, rq->gpio);
					if (ret >= 0) {
						rs->value = ret;
						ret = 0;
					}
					break;
				case VIRTIO_GPIO_MSG_SET_DIRECTION:
					ret = virtioHostGpioSetDirection(pGpioHostCtx, rq->gpio, rq->value);
					break;
				case VIRTIO_GPIO_MSG_GET_VALUE:
					ret = virtioHostGpioGetValue(pGpioHostCtx, rq->gpio);
					if (ret >= 0) {
						rs->value = ret;
						ret = 0;
					}
					break;
				case VIRTIO_GPIO_MSG_SET_VALUE:
					ret = virtioHostGpioSetValue(pGpioHostCtx, rq->gpio, rq->value);
					break;
				case VIRTIO_GPIO_MSG_IRQ_TYPE:
					if (rq->value == VIRTIO_GPIO_IRQ_TYPE_NONE)
						ret = virtioHostGpioIrqDisable(pGpioHostCtx, rq->gpio);
					else
						ret = virtioHostGpioIrqEnable(pGpioHostCtx, rq->gpio, rq->value);
					break;
				default:
					VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
						"invalid request type: %d\n",
						rq->type);
					break;
			}

#ifdef VIRTIO_GPIO_DEV_DUMP
			VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
					"request done: %d\n", ret);
#endif
			doNotify = true;

			if (rq->type == VIRTIO_GPIO_MSG_GET_NAMES) {
				rsn->status = ret ? VIRTIO_GPIO_STATUS_ERR : VIRTIO_GPIO_STATUS_OK;
				(void)virtioHostQueueRelBuf(pQueue, idx,
					sizeof(*rsn) + pGpioHostCtx->cfg.gpio_names_size);
			} else {
				rs->status = ret ? VIRTIO_GPIO_STATUS_ERR : VIRTIO_GPIO_STATUS_OK;
				(void)virtioHostQueueRelBuf(pQueue, idx, sizeof(*rs));
			}
		}

		virtioHostQueueIntrEnable(pQueue);
		if (doNotify)
			(void)virtioHostQueueNotify(pQueue);
	}

	return NULL;
}

/*******************************************************************************
 *
 * virtioHostGpioHandleEvent - virtio GPIO device event sending task
 *
 * This routine is used to create a handler task for virtio GPIO device to
 * handle unmask command from front-end driver and deliver interrupt event
 * to front-end driver.
 *
 * RETURNS: NULL
 *
 * ERRNO: N/A
 */
static void* virtioHostGpioHandleEvent(void *arg)
{
	int n, i, ret, len;
	uint16_t idx;
	struct virtioHost *vhost;
	struct virtioGpioHostCtx *pGpioHostCtx = arg;
	struct virtioHostQueue *pQueue;
	struct virtioHostBuf buffer[2];
	struct virtio_gpio_irq_request *irq;
	struct virtio_gpio_irq_response *irs;
	struct gpio_line *line;
	struct gpio_irq_chip *chip;
	struct gpio_irq_desc *desc;

	vhost = (struct virtioHost *)pGpioHostCtx;
	pQueue = &vhost->pQueue[VIRTIO_GPIO_EVT_QUEUE];

	while (1) {
		ret = sem_wait(&pGpioHostCtx->ev_sem);
		if (ret < 0) {
			VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
					"failed to sem_wait ev_sem: %s\n", strerror(errno));
		}

		while (1) {
			n = virtioHostQueueGetBuf(pQueue, &idx, &buffer[0], 2);
			VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
					"n:%d\n", n);
			if (n == 0) {
				VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
						"no new event queue buffer\n");
				break;
			}

			if (n < 0) {
				VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
						"failed to get buffer(%d)\n", n);
				virtioHostGpioAbort(pQueue, pQueue->availIdx);
				break;
			}

			if (n == 1) {
				VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
						"failed to get request buffer pair\n");
				virtioHostGpioAbort(pQueue, pQueue->availIdx);
				break;
			}

			if (n > 2) {
				VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
						"invalid length of desc chain: %d, only 2 is valid\n", idx);
				virtioHostGpioAbort(pQueue, pQueue->availIdx);
				continue;
			}

			irq = (struct virtio_gpio_irq_request *)buffer[0].buf;
			irs = (struct virtio_gpio_irq_response *)buffer[1].buf;

			if (buffer[0].len != sizeof(*irq)) {
				VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
						"invalid irq request size: %d, %lu\n",
						buffer[0].len, sizeof(*irq));
				virtioHostGpioAbort(pQueue, pQueue->availIdx);
				continue;
			} else if (buffer[1].len != sizeof(*irs)) {
				VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
						"invalid irq response size: %d, %lu\n",
						buffer[1].len, sizeof(*irs));
				virtioHostGpioAbort(pQueue, pQueue->availIdx);
				continue;
			}

#ifdef VIRTIO_GPIO_DEV_DUMP
			VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
					"event start: %d\n", irq->gpio);
#endif
			chip = &pGpioHostCtx->irq_chip;
			desc = &chip->descs[irq->gpio];

			pGpioHostCtx->irq_stat.unmasked++;

			pthread_mutex_lock(&desc->mtx);

			desc->line->irq_stat.unmasked++;

			if (desc->mode == VIRTIO_GPIO_IRQ_TYPE_NONE) {
				/* not yet enabled as an interrupt source, return the buffer pair */
				VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
						"gpio %d not yet enabled as irq, return the buffer pair\n",
						irq->gpio);
				virtioHostGpioAbort(pQueue, pQueue->availIdx);

			} else if (!desc->mask) {
				/* reduntant or out of sequence unmask, return the buffer pair */
				VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
						"gpio %d unmasked before, return the buffer pair\n",
						irq->gpio);
				virtioHostGpioAbort(pQueue, pQueue->availIdx);

			} else if (desc->pending) {
				/* handle previous pending interrupt and
				 * remain masked until FE driver unmasks it again
				 */
				VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
						"gpio %d pending, deliver it\n",
						irq->gpio);
				desc->pending = false;
				desc->irs->status = VIRTIO_GPIO_IRQ_STATUS_VALID;
				(void)virtioHostQueueRelBuf(pQueue, idx, sizeof(*desc->irs));
				(void)virtioHostQueueNotify(pQueue);

				desc->irs = NULL;
				desc->idx = UINT16_MAX;

			} else {
				/* unmask and expect upcoming interrupts */
				VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO,
						"gpio %d unmasked now\n",
						irq->gpio);
				desc->mask = false;
				desc->irs = irs;
				desc->idx = idx;
			}

			pthread_mutex_unlock(&desc->mtx);
		}

		virtioHostQueueIntrEnable(pQueue);
	}

	return NULL;
}

/*******************************************************************************
 *
 * virtioHostGpioNotify - notify here comes a new IO/control request
 *
 * This routine is used to notify the handler that an new recieved io-request
 * in virtio queue.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */
static void virtioHostGpioNotify(struct virtioHostQueue *pQueue)
{
	int ret;
	struct virtioDispObj *pDispObj;

	if (!pQueue) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR, "null pQueue\n");
		return;
	}

	if (pQueue->vHost && (pQueue->vHost->status & VIRTIO_CONFIG_S_DRIVER_OK) != 0) {
		pthread_mutex_lock(&vGpioHostDrv.dispMtx);
		if (!TAILQ_EMPTY(&vGpioHostDrv.dispFreeQ)) {

			pDispObj = TAILQ_FIRST(&vGpioHostDrv.dispFreeQ);
			if (!pDispObj) {
				VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
						"failed to get dispatch object from free queue\n");
				pthread_mutex_unlock(&vGpioHostDrv.dispMtx);
				return;
			}
			virtioHostQueueIntrDisable(pQueue);
			TAILQ_REMOVE(&vGpioHostDrv.dispFreeQ, pDispObj, link);
			pDispObj->pQueue = pQueue;
			TAILQ_INSERT_TAIL(&vGpioHostDrv.dispBusyQ, pDispObj, link);

			pthread_cond_signal(&vGpioHostDrv.dispCond);
		} else {
			VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
					"No object in dispatch free queue\n");
		}
		pthread_mutex_unlock(&vGpioHostDrv.dispMtx);
	}

	return;
}

/*******************************************************************************
 *
 * virtioHostGpioDone - mark the virtio GPIO request handled done.
 *
 * This routine is used to set the request handeled status according to the
 * backend device operation result before the descriptors released to
 * the used ring.
 *
 * RETURNS: N/A
 *
 * ERRNO: N/A
 */
static void virtioHostGpioDone(uint16_t idx, struct virtioHostQueue *pQueue, uint32_t len)
{
	(void)virtioHostQueueRelBuf(pQueue, idx, len);
	(void)virtioHostQueueNotify(pQueue);

	return;
}

/*******************************************************************************
 *
 * virtioHostGpioReset - reset virtio GPIO device
 *
 * This routine is used to reset the virtio GPIO device. All the configuration
 * settings setted by customer driver will be cleared and all the backend
 * driver software flags are reset to initial status.
 *
 * RETURNS: 0, or -1 if failure raised in process of restarting the device.
 *
 * ERRNO: N/A
 */
static int virtioHostGpioReset(struct virtioHost *vHost)
{
	struct virtioGpioHostCtx *vGpioHostCtx;
	int err = 0;

	vGpioHostCtx = (struct virtioGpioHostCtx *)vHost;
	if (!vGpioHostCtx) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
				"null vGpioHostCtx\n");
		return -1;
	}

	return err;
}

/*******************************************************************************
 *
 * virtioHostGpioCfgRead - read virtio GPIO specific configuration register
 *
 * This routine is used to read virtio GPIO specific configuration register,
 * the value read out is stored in the request buffer.
 *
 * RETURN: 0, or -1 if the to be read register is non-existed.
 *
 * ERRNO: N/A
 */
static int virtioHostGpioCfgRead(struct virtioHost *vHost, uint64_t address,
		uint64_t size, uint32_t *pValue)
{
	struct virtioGpioHostCtx *pGpioHostCtx;
	uint8_t *cfgAddr;

	if (!vHost) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR, "null vHost\n");
		return -EINVAL;
	}

	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO, "address: %lu, size: %lu\n", address, size);

	pGpioHostCtx = (struct virtioGpioHostCtx *)vHost;
	cfgAddr = (uint8_t *)&pGpioHostCtx->cfg + address;

	(void)memcpy(pValue, cfgAddr, (size_t)size);

	return 0;
}

/*******************************************************************************
 *
 * virtioHostGpioCfgWrite - set virtio GPIO specific configuration register
 *
 * This routine is used to set virtio GPIO specific configuration register,
 * the setting value is stored in the request buffer.
 *
 * RETURN: 0, or -1 if the to be read register is non-existed.
 *
 * ERRNO: N/A
 */

static int virtioHostGpioCfgWrite(struct virtioHost *vHost, uint64_t address,
		uint64_t size, uint32_t value)
{
	if (!vHost) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR, "null vHost\n");
		return -EINVAL;
	}

	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR,
			"failed to write to read-only register %lu\n", address);

	return -EIO;
}

/*******************************************************************************
 *
 * virtioHostGpioShow - virtio GPIO host device show
 *
 * This routine shows the virtio GPIO host device setting and configurations.
 *
 * RETURN: 0 aleays.
 *
 * ERRNO: N/A
 */
static void virtioHostGpioShow(struct virtioHost *vHost, uint32_t indent)
{
	struct virtioGpioHostCtx *pGpioHostCtx;
	int i;

	pGpioHostCtx = (struct virtioGpioHostCtx *)vHost;

	printf("%*sdriver [%s]\n", (indent + 1) * 3, "", VIRTIO_GPIO_DRV_NAME);
	printf("%*sbackend device :\n", (indent + 1) * 3, "");
	printf("%*snqueue      [%d]\n", (indent + 2) * 3, "", pGpioHostCtx->nqueue);
	printf("%*snchip       [%d]\n", (indent + 2) * 3, "", pGpioHostCtx->nchip);
	printf("%*snvline      [%d]\n", (indent + 2) * 3, "", pGpioHostCtx->nvline);

	for (i = 0; i < pGpioHostCtx->nchip; i++) {
		printf("%*sname        [%s]\n", (indent + 2) * 3, "",
				pGpioHostCtx->chips[i].name);
		printf("%*sdev_name    [%s]\n", (indent + 2) * 3, "",
				pGpioHostCtx->chips[i].dev_name);
	}

	for (i = 0; i < pGpioHostCtx->nvline; i++) {
		printf("%*sname        [%s]\n", (indent + 2) * 3, "",
				pGpioHostCtx->vlines[i]->name);
		printf("%*sdev_name    [%s]\n", (indent + 2) * 3, "",
				pGpioHostCtx->vlines[i]->vname);
	}
}

/*******************************************************************************
 *
 * virtioHostGpioSetStatus - initialize virtioHostGpio status
 *
 * This routine is used to initialize virtioHostGpio status when
 * receiving reset signal from guest.
 *
 * RETURNS: 0, or -1 if failure raised in process of changing status.
 *
 * ERRNO: N/A
 */

static int virtioHostGpioSetStatus(struct virtioHost* vHost, uint32_t status)
{
	struct virtioGpioHostDev *pGpioHostDev;
	struct virtioGpioHostCtx *pGpioHostCtx =
		(struct virtioGpioHostCtx *)vHost;

	if (!vHost) {
		VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_ERR, "null vHost\n");
		return -EINVAL;
	}

	VIRTIO_GPIO_DEV_DBG(VIRTIO_GPIO_DEV_DBG_INFO, "set status 0x%x\n",
			status);

	if ((status & VIRTIO_CONFIG_S_DRIVER_OK) == 0)
		return 0;

	(void)virtioHostQueueIntrEnable(vHost->pQueue + VIRTIO_GPIO_REQ_QUEUE);
	(void)virtioHostQueueIntrEnable(vHost->pQueue + VIRTIO_GPIO_EVT_QUEUE);

	/*
	 * Notify driver to make it update the vring used
	 * event index
	 */
	vHost->intStatus = VIRTIO_MMIO_INT_VRING;
	(void)vHost->pVsmOps->notify(vHost->pVsmQueue,
				     vHost, vHost->intStatus);
	return 0;
}
