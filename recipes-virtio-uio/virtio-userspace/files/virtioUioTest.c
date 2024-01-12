/* virtio host VSM functions */

/*
 * Copyright (c) 2024 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

/*
DESCRIPTION

A program that tests VirtIO userspace subsystem

*/

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include "virtio_host_parser.h"
#include "uio-virtio.h"
#include "virtioHostLib.h"

/* local variables */

const char* virtio_ctrl_device = "/dev/virtio_ctrl";
const char* uio_device = "/dev/uio0";

/* This flag controls termination of the main loop. */
volatile sig_atomic_t is_running;

extern int virtioHostEventHandler(struct virtio_device* vdev);

static void signal_handler(int signo)
{
	is_running = 0;
	signal(signo, signal_handler);
}

static int virtioIntProcess(struct virtio_device* vdev, int uio_fd)
{
	struct pollfd uio;
	uint32_t enable = 1;
	uint32_t nints = 0; /* number of interrupts */
	struct timeval tv = { 5, 0 };
	int err;

	is_running = 1;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Tell the remote device, we're ready */
        virtio_add_status(vdev, VIRTIO_CONFIG_S_DRIVER_OK);

	while (is_running) {
		/* Eenable the interrupt */
		if (write(uio_fd, &enable, sizeof(enable)) < 0) {
			printf("Interrupt enable error: %s\n",
			       strerror(errno));
			break;
		}

		uio.fd = uio_fd;
                uio.events = POLLIN;

                err = poll(&uio, 1, tv.tv_sec * 1000);
                if (err == 0) {
                        continue;
                } else if (err < 0) {
                        printf("Error\n");
                        break;
                } else {
                        if (uio.revents & POLLIN) {
                                err = read(uio_fd, &nints, sizeof(nints));
                                if (err < 0) {
                                        printf("Read error %s\n",
                                               strerror(errno));
					continue;
                                }
				err = virtioHostEventHandler(vdev);
				if (err != 0) {
					break;
				}
			}
                }
        }

	enable = 0;
        if (write(uio_fd, &enable, sizeof(enable)) < 0) {
                printf("Interrupt disable error: %s\n", strerror(errno));
	}
	return err;
}

int main (void)
{
	struct virtio_device virtioDevice = {
		.virtio_ctrl_device = virtio_ctrl_device,
		.uio_device = uio_device
	};
	struct virtio_region region = {
		.indx = 0x0,
		.addr = 0x0,
		.size = 0x0
	};

	int err;
	int uio_fd;
	int ctrl_fd;
        void* addr;

	printf("VirtIO test starts\n");

	/*
         * Open VirtIO control device and add get region size
         */

        printf("Open %s and add VirtIO memory region\n",
	       virtioDevice.virtio_ctrl_device);
        ctrl_fd = open(virtioDevice.virtio_ctrl_device, O_RDWR | O_SYNC);
        if (ctrl_fd < 0) {
                printf("Control device open error: %s\n", strerror(errno));
                return -1;
        }
        err = ioctl(ctrl_fd, VHOST_VIRTIO_GET_REGION, &region);
        if (err == 0) {
                printf("Region exists: addr: 0x%lx, size 0x%lx, offset 0x%X\n",
                       region.addr, region.size, region.offs);
        } else {
		printf("getting VirtIO memory region failed: %s\n",
		       strerror(errno));
		return -1;
	}
        close(ctrl_fd);

	/*
         * Open the device file and map memory
         */

        uio_fd = open(virtioDevice.uio_device, O_RDWR | O_SYNC);
        if (uio_fd < 0) {
                printf("Device open error %s\n", strerror(errno));
                return -1;
        }

        addr = mmap(NULL, region.size, PROT_READ | PROT_WRITE, MAP_SHARED, uio_fd, 0);
        if (addr == MAP_FAILED) {
                printf("Memory map error %s\n", strerror(errno));
                return -1;
        }
	close(uio_fd);

	/*
	 * Initialize host VSM
	 */

	virtioDevice.dev.base = addr;
	if (vsm_init(&virtioDevice) != 0) {
		printf("VSM initialization FAILED\n");
		return -1;
	}

	printf("VirtIO initialization complete. 5 seconds for an int\n");
        uio_fd = open(virtioDevice.uio_device, O_RDWR | O_SYNC);
	virtioIntProcess(&virtioDevice, uio_fd);
	close(uio_fd);
	vsm_deinit(&virtioDevice);
	printf("VirtIO test complete\n");
	return 0;
}
