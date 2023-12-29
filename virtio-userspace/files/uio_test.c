/*
 * UIO test program
 */
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
#include <linux/virtio_mmio.h>
#include <linux/virtio_ring.h>

#include "virtio_host_parser.h"
#include "uio-virtio.h"
#include "virtio_host_lib.h"

/* local macros */

#define printreg32(reg)							\
    printf("%s: 0x%08x\n", #reg, le32toh(regs[(reg / sizeof(uint32_t))]));

#define offset2idx(offset) (offset / sizeof(uint32_t))

#define readl(offset) le32toh(regs[(offset / sizeof(uint32_t))])
#define writel(offset, val) regs[(offset / sizeof(uint32_t))] = htole32(val)

/* local variables */

const char* virtio_ctrl_device = "/dev/virtio_ctrl";
const char* uio_device = "/dev/uio0";
const char* sysfssize = "/sys/class/uio/uio0/maps/map0/size";

#define VIRTIO_CFG_REGION 1
#define VIRTIO_QUE_REGION 2

struct virtio_region region = {
    .indx = VIRTIO_CFG_REGION,
    .addr = 0x0,
    .size = 0x0
    };

/* functions */

/*
 * Obtain VirtIO shared memory region
 * regs - VirtIO registers address
 * region - region descriptor structure
 * idx - region index
 *
 * Return: 0 on success
 */

int virtioGetShmRegion(volatile uint32_t* regs,
		       struct virtio_region* region, int idx)
{
	/* Select memory region */
        writel(VIRTIO_MMIO_SHM_SEL, idx);

	/* Get address and length */
	region->addr = (uint64_t)readl(VIRTIO_MMIO_SHM_BASE_LOW) |
		((uint64_t)readl(VIRTIO_MMIO_SHM_BASE_HIGH)) << 32;
	region->size = (uint64_t)readl(VIRTIO_MMIO_SHM_LEN_LOW) |
		((uint64_t)readl(VIRTIO_MMIO_SHM_LEN_HIGH)) << 32;

	return 0;
}

/*
 * Create guest VirtIO memory mapped region
 */
int virtioCreateGuestMap(const char* virtio_ctrl_dev,
			 struct guestConfig* guests)
{
        int ctrl_fd; /* control device file descriptor */
	struct virtio_region region; /* memory region to create */
	int guestIdx;
	int mapIdx;
	int err;

	ctrl_fd = open(virtio_ctrl_device, O_RDWR | O_SYNC);
        if (ctrl_fd < 0) {
                printf("Control device open error: %s\n", strerror(errno));
                return -1;
        }

	for (guestIdx = 0; guestIdx < guests->guests_count; guestIdx++) {
		for (mapIdx = 0;
		     mapIdx < guests->guests[guestIdx].maps_count;
		     mapIdx++) {
			/* FIXME: make sure that the address is page aligned */
			region.addr =
				guests->guests[guestIdx].maps[mapIdx].hpa;
			/* region size must be page aligned */
			region.size =
				((guests->guests[guestIdx].maps[mapIdx].size
				  + getpagesize() - 1) /
				 getpagesize()) * getpagesize();
			region.indx = VIRTIO_QUE_REGION + mapIdx;
			if (region.addr == 0) {
				continue;
			}
			err = ioctl(ctrl_fd, VHOST_VIRTIO_GET_REGION, &region);
			if (err == 0) {
				printf("Region exists: addr: 0x%lx, "
				       "size 0x%lx, offset 0x%X\n",
				       region.addr, region.size, region.offs);
			} else if (err != 0 && errno == ENOMEM) {
				err = ioctl(ctrl_fd, VHOST_VIRTIO_ADD_REGION,
					    &region);
				if (err != 0) {
					printf("Adding VirtIO memory "
					       "region failed: %s\n",
					       strerror(errno));
					break;
				}
			} else {
				printf("Getting VirtIO memory "
				       "region failed: %s\n",
				       strerror(errno));
				break;
			}
		}
	}
	close(ctrl_fd);
	return err;
}

/*
 * Map guest VirtIO regions
 */
int virtioMapGuestMemory(const char* virtio_ctrl_dev, int uio_fd,
			 int idx, struct virtioVsmShmRegion* pVsmRegion)
{
        int ctrl_fd; /* control device file descriptor */
	struct virtio_region region; /* memory region to find and map */
	int err;

	ctrl_fd = open(virtio_ctrl_device, O_RDWR | O_SYNC);
        if (ctrl_fd < 0) {
                printf("Control device open error: %s\n", strerror(errno));
                return -1;
        }

	region.indx = VIRTIO_QUE_REGION + idx;

	err = ioctl(ctrl_fd, VHOST_VIRTIO_GET_REGION, &region);
	if (err != 0) {
		printf("VirtIO region with index %d does not exist\n",
		       idx);
		errno = EINVAL;
		goto out;
	}

	printf("VirtIO Region exists: addr: 0x%lx, "
	       "size 0x%lx, offset 0x%X\n",
	       region.addr, region.size, region.offs);
	pVsmRegion->region.paddr = region.addr;
	pVsmRegion->region.offset = region.offs;
	pVsmRegion->region.len = region.size;
	pVsmRegion->region.id = idx;

	pVsmRegion->region.len =
		((region.size + getpagesize() - 1) / getpagesize()) *
		getpagesize();

	printf("Mapping region %d: len: 0x%lx, offset: 0x%x\n",
	       pVsmRegion->region.id, pVsmRegion->region.len,
	       pVsmRegion->region.offset);
	pVsmRegion->vaddr = mmap(NULL, pVsmRegion->region.len,
	    PROT_READ | PROT_WRITE,
            MAP_SHARED, uio_fd, pVsmRegion->region.offset);

	if (pVsmRegion->vaddr == MAP_FAILED) {
                printf("Memory map error %s\n", strerror(errno));
		err = -1;
                goto out;
        } else {
		printf("VirtIO region mapped at %p\n", pVsmRegion->vaddr);
	}
out:
	close(ctrl_fd);
	return err;
}

/*
 * Unmap guest VirtIO regions
 */
int virtioUnmapGuestMemory(struct virtioVsmShmRegion* pVsmRegion)
{
	int err;

	printf("Unmapping region %d: 0x%p len: 0x%lx, offset: 0x%x\n",
	       pVsmRegion->region.id, pVsmRegion->vaddr,
	       pVsmRegion->region.len, pVsmRegion->region.offset);
	err = munmap(pVsmRegion->vaddr, pVsmRegion->region.len);
        if (err != 0) {
                printf("Memory unmap error %s\n", strerror(errno));
        } else {
		printf("VirtIO region unmapped at %p\n", pVsmRegion->vaddr);
	}
	return err;
}


int main (void)
{
        int uio_fd;
        int ctrl_fd;

        void* addr;
        volatile uint32_t* regs;

        int i;
        void* virtio_cfg_addr;
        char* virtio_cfg_buf;
        size_t virtio_cfg_size;
        size_t virtio_cfg_len;
        
        int memsize = 0;
        struct pollfd uio;
        int err;
        struct timeval tv = { 5, 0 };
        uint32_t enable = 1;
        uint32_t nints = 0; /* number of interrupts */

	struct guestConfig guests; /* guests configuration */

	struct virtioVsmShmRegion* vsmRegions;

	struct virtio_device virtioDevice = {
		.virtio_ctrl_device = virtio_ctrl_device,
		.uio_device = uio_device
	};

	/*
         * Open sysfs and read memory size
         */

        printf("Open %s and read VirtIO memory size\n", sysfssize);

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

        uio_fd = open(virtioDevice.uio_device, O_RDWR | O_SYNC);
        if (uio_fd < 0) {
                printf("Device open error %s\n", strerror(errno));
                return -1;
        }

        addr = mmap(NULL, memsize, PROT_READ | PROT_WRITE, MAP_SHARED, uio_fd, 0);
        if (addr == MAP_FAILED) {
                printf("Memory map error %s\n", strerror(errno));
                return -1;
        }

        /*
         * Controlling VirtIO
         */

	sleep(1);
        regs = (uint32_t*)addr;

        printreg32(VIRTIO_MMIO_MAGIC_VALUE);
        printreg32(VIRTIO_MMIO_VERSION);
        printreg32(VIRTIO_MMIO_DEVICE_ID);
        printreg32(VIRTIO_MMIO_VENDOR_ID);
	sleep(1);

	if (virtioGetShmRegion(regs, &region, 0) != 0) {
                printf("Getting VirtIO memory region failed: %s\n",
                       strerror(errno));
                return -1;
	}

	/*
         * Open VirtIO control device and add a memory region
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
        } else if (err != 0 && errno == ENOMEM) {
                err = ioctl(ctrl_fd, VHOST_VIRTIO_ADD_REGION, &region);
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
        close(ctrl_fd);

	virtio_cfg_addr = mmap(NULL, region.size, PROT_READ,
            MAP_SHARED, uio_fd, region.offs);
        if (virtio_cfg_addr == MAP_FAILED) {
                printf("VirtIO config memory map error %s\n", strerror(errno));
                return -1;
        } else {
                printf("Mapped VirtIO configuration at %p\n", virtio_cfg_addr);
        }

        /*
         * VirtIO configuration buf
         */
	virtio_cfg_size = region.size;
        virtio_cfg_buf = (uint8_t*)virtio_cfg_addr;
	virtio_cfg_len = strnlen(virtio_cfg_buf, virtio_cfg_size);

	for (i = 0; i < virtio_cfg_len; i++) {
                printf("%c", virtio_cfg_buf[i]);
        }
        printf("\n\n");

	char* yaml_cfg = malloc(virtio_cfg_len + 1);

	if (yaml_cfg == NULL) {
		printf("YAML buffer allocation error %s\n",
		       strerror(errno));
		return -1;
	}

	for (i = 0; i < virtio_cfg_len; i++) {
		yaml_cfg[i] = virtio_cfg_buf[i];
        }
	yaml_cfg[virtio_cfg_len] = 0;

	printf("YAML config size: %ld\n", virtio_cfg_len);

	if (virtioHostYamlLoader(yaml_cfg, virtio_cfg_len, &guests) != 0) {
		printf("YAML configuration parsing error %s\n",
		       strerror(errno));
	} else {
		printGuestConfig(&guests);
	}

	/*
	 * Once we parsed VirtIO configuration, we don't need it
	 * anymore
	 */
	free(yaml_cfg);
	if (munmap(virtio_cfg_addr, virtio_cfg_size) != 0) {
                printf("Memory unmap error %s\n", strerror(errno));
        }

	sleep(1); /* pause to have a clean output */

	if (virtioCreateGuestMap(virtioDevice.virtio_ctrl_device,
				 &guests) != 0) {
		printf("Guest memory region creation error %s\n",
		       strerror(errno));
	}

	vsmRegions = malloc(guests.guests[0].maps_count *
			    sizeof(struct virtioVsmShmRegion));
	if (vsmRegions == NULL) {
		printf("VSM regions allocation error\n");
		return -1;
	}
	for (i = 0; i < guests.guests[0].maps_count; i++) {
		if (virtioMapGuestMemory(virtioDevice.virtio_ctrl_device,
					 uio_fd, i, &vsmRegions[i]) != 0) {
			printf("VSM memory mapping error\n");
			return -1;
		}
	}

	/*
	 * Initialize host VSM
	 */

	virtioDevice.dev.base = addr;
	printf("Virtio device address is %p\n", &virtioDevice);

	if (virtvsm_init(&virtioDevice) != 0) {
		printf("VSM initialization FAILED\n");
	}

	printf("Waiting for %ld seconds for interrupt\n", tv.tv_sec);
        while (1) {
                uio.fd = uio_fd;
                uio.events = POLLIN;

                if (write(uio_fd, &enable, sizeof(enable)) < 0) {
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
                                err = read(uio_fd, &nints, sizeof(nints));
                                if (err < 0) {
                                        printf("Read error %s\n",
                                               strerror(errno));
                                } else {
                                        printf("N interrupts: %d\n", nints);
                                }
                        }
                }
        }

	virtvsm_deinit(&virtioDevice);

	freeGuestConfig(&guests);

	/* disable interrupt before closing */
        enable = 0;
        if (write(uio_fd, &enable, sizeof(enable)) < 0) {
                printf("Interrupt disable error: %s\n", strerror(errno));
	}

	for (i = 0; i < guests.guests[0].maps_count; i++) {
		if (virtioUnmapGuestMemory(&vsmRegions[i]) != 0) {
			printf("VSM memory unmapping error\n");
		}
	}
	free(vsmRegions);

	if (munmap(addr, memsize) != 0) {
                printf("Memory unmap error %s\n", strerror(errno));
        }

        close(uio_fd);
        return 0;
}
