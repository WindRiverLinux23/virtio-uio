/*
 * UIO test program
 */
#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#include "uio-virtio.h"

#define VIRTIO_MAGIC  0
#define VIRTIO_VER    1
#define VIRTIO_ID     2
#define VIRTIO_VENDOR 3

#define printreg32(reg) printf("%s: 0x%08x\n", #reg, le32toh(regs[(reg)]));

const char* virtio_ctrl_device = "/dev/virtio_ctrl";
const char* uio_device = "/dev/uio0";
const char* sysfssize = "/sys/class/uio/uio0/maps/map0/size";

#define VIRTIO_REGION 1
#define VIRTIO_QUEUE_ADDR 0xffcf0000
#define VIRTIO_QUEUE_SIZE 0x10000

struct virtio_region region = {
    .indx = VIRTIO_REGION,
    .addr = VIRTIO_QUEUE_ADDR,
    .size = VIRTIO_QUEUE_SIZE
    };

int main (void)
{
        int fd;

        void* addr;
        volatile uint32_t* regs;

        int i;
        void* queue_addr;
        volatile uint8_t* queue_buf;
        size_t queue_size = 80;
        
        int memsize = 0;
        struct pollfd uio;
        int err;
        struct timeval tv = { 5, 0 };
        uint32_t enable = 1;
        uint32_t nints = 0; /* number of interrupts */

        /*
         * Open VirtIO control device and add a memory region
         */

        printf("Open %s and add VirtIO memory region\n", virtio_ctrl_device);
        fd = open(virtio_ctrl_device, O_RDWR | O_SYNC);
        if (fd < 0) {
                printf("Control device open error: %s\n", strerror(errno));
                return -1;
        }
        err = ioctl(fd, VHOST_VIRTIO_GET_REGION, &region);
        if (err == 0) {
                printf("Region exists: addr: 0x%x, size 0x%x, offset 0x%X\n",
                       region.addr, region.size, region.offs);
        } else if (err != 0 && errno == ENOMEM) {
                err = ioctl(fd, VHOST_VIRTIO_ADD_REGION, &region);
                if (err != 0) {
                        printf("Adding VirtIO memory region failed: %s\n",
                               strerror(errno));
                        return -1;
                }
        } else {
                printf("Getting VirtIO memory region failed: %s\n",
                       strerror(errno));
                return -1;
        }
        close(fd);
        

        /*
         * Open sysfs and read memory size
         */

        printf("Open %s and read GPIO memory size\n", sysfssize);

        FILE* sysfd = fopen(sysfssize, "r");
        if (sysfd == NULL) {
                printf("Sysfs open error %s\n", strerror(errno));
                return -1;
        }
        err = fscanf(sysfd, "%x", &memsize);
        if (err <= 0) {
                printf("Sysfs read error %s\n", strerror(errno));
                return -1;
        }

        fclose(sysfd);

        printf("Device memory size: 0x%x\n", memsize);
        
        /*
         * Open the device file and map memory
         */

        fd = open(uio_device, O_RDWR | O_SYNC);
        if (fd < 0) {
                printf("Device open error %s\n", strerror(errno));
                return -1;
        }

        addr = mmap(NULL, memsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (addr == NULL) {
                printf("Memory map error %s\n", strerror(errno));
                return -1;
        }

        queue_addr = mmap(NULL, VIRTIO_QUEUE_SIZE, PROT_READ,
            MAP_SHARED, fd, region.offs);
        if (queue_addr == NULL) {
                printf("Memory map error %s\n", strerror(errno));
                return -1;
        } else {
                printf("Mapped VirtIO queue at %p\n", queue_addr);
        }

        /*
         * Reading queue buf
         */

        queue_buf = (uint8_t*)queue_addr;
        for (i = 0; i < queue_size; i++) {
                printf("0x%02x ", queue_buf[i]);
        }
        printf("\n\n");
        
        /*
         * Controlling GPIO
         */

        regs = (uint32_t*)addr;

        printreg32(VIRTIO_MAGIC);
        printreg32(VIRTIO_VER);
        printreg32(VIRTIO_ID);
        printreg32(VIRTIO_VENDOR);

	printf("Waiting for %ld seconds for interrupt\n", tv.tv_sec);
        while (1) {
                uio.fd = fd;
                uio.events = POLLIN;

                if (write(fd, &enable, sizeof(enable)) < 0) {
			printf("Interrupt enable error: %s\n",
			       strerror(errno));
			break;
		}

                err = poll(&uio, 1, tv.tv_sec * 1000);
                if (err == 0) {
                        printf("Timeout\n");
                        break;
                } else if (err < 0) {
                        printf("Error\n");
                        break;
                } else {
                        printf("Event: 0x%X ", uio.revents);
                        if (uio.revents & POLLIN) {
                                err = read(fd, &nints, sizeof(nints));
                                if (err < 0) {
                                        printf("Read error %s\n",
                                               strerror(errno));
                                } else {
                                        printf("N interrupts: %d\n", nints);
                                }
                        }
                }
        }

        /* disable interrupt before closing */
        enable = 0;
        if (write(fd, &enable, sizeof(enable)) < 0) {
                printf("Interrupt disable error: %s\n", strerror(errno));
	}

        if (munmap(addr, memsize) != 0) {
                printf("Memory unmap error %s\n", strerror(errno));
        }
        
        close(fd);
        return 0;
}
