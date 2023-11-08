/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2023 Wind River Systems
 */

/*
 * The VirtIO uio driver sample
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/sizes.h>
#include <linux/uio_driver.h>

#include "uio-virtio.h"

#define VIRTIO_IRQ 0x0

static struct resource virtio_uio_resources[] = {
        DEFINE_RES_MEM(0x0, 0x200),
        DEFINE_RES_IRQ(VIRTIO_IRQ)
};

struct uio_info virtio_p_data = {
        .name = "virtio_uio",
  	.version = "0",
};

struct uio_map {
  	struct kobject kobj;
  	struct uio_mem *mem;
};

static struct platform_device virtio_p_device = {
        .name = "uio_pdrv_genirq",
        .id = 0,
        .resource = virtio_uio_resources,
        .num_resources = ARRAY_SIZE(virtio_uio_resources),
        .dev = {
                .platform_data = &virtio_p_data,
        },
};

/* number of control devices */
#define VIRTIO_NCTRL 1

/* character device that controls VirtIO UIO device */
static dev_t virtio_ctrl;
static struct cdev virtio_ctrl_cdev;

/* sysfs class structure */
static struct class* virtio_ctrl_class = NULL;

static int virtio_ctrl_dev_major = 0;

static int irq = VIRTIO_IRQ;
module_param(irq, int, S_IRUGO);

/*
 * VirtIO control device functions
 */

static int virtioctrl_add_region(struct virtio_region* region, int memtype)
{
        int i;
        const struct kobj_type* ktype = NULL;
        int mem_avail_idx; /* index of the next memory region available */
        struct uio_map *map; /* new memory mapping */
        int err = 0;
        struct uio_device* idev = virtio_p_data.uio_dev;
        unsigned long offset = 0;

        /* Walk through the memory regions rray and find the first free slot */
        for (i = 0;
             (i < MAX_UIO_MAPS) && (virtio_p_data.mem[i].size != 0);
             i++) {
                if ((ktype == NULL) &&
                    (virtio_p_data.mem[i].map != NULL)) {
                        ktype = virtio_p_data.mem[i].map->kobj.ktype;
                }
                offset += virtio_p_data.mem[i].offs + virtio_p_data.mem[i].size;
                pr_info("Region: %d: 0x%X, %d bytes\n",
                        i, virtio_p_data.mem[i].addr, virtio_p_data.mem[i].size);
        }
        mem_avail_idx = i;
        if (mem_avail_idx >= MAX_UIO_MAPS) {
                pr_err ("No memory regions available\n");
                return -1;
        }

        /* Fill in the new memory region info */
        pr_info("Creating a new memory mapping at %d\n", mem_avail_idx);

        map = kzalloc(sizeof(*map), GFP_KERNEL);
        if (map == NULL ) {
                pr_err("Memory allocation error!\n");
                return -1;
        }

        mutex_lock(&virtio_p_data.uio_dev->info_lock);
        virtio_p_data.mem[mem_avail_idx].addr = region->addr;
        virtio_p_data.mem[mem_avail_idx].size = region->size;
        virtio_p_data.mem[mem_avail_idx].memtype = memtype;
        virtio_p_data.mem[mem_avail_idx].name = "virtio";
        virtio_p_data.mem[mem_avail_idx].offs = offset;
        region->offs = offset;
        region->indx = mem_avail_idx;
        kobject_init(&map->kobj, ktype);
        virtio_p_data.mem[mem_avail_idx].map = map;
        map->mem = &virtio_p_data.mem[mem_avail_idx];
        err = kobject_add(&map->kobj, idev->map_dir, "map%d", mem_avail_idx);
        if (err != 0) {
                goto error;
        }
        err = kobject_uevent(&map->kobj, KOBJ_ADD);
error:
        mutex_unlock(&virtio_p_data.uio_dev->info_lock);
        
        if (err != 0) {
                pr_err("Memory map initialization error\n");
                kfree (map);
        }
        return 0;
}

static int virtioctrl_open (struct inode *, struct file *)
{
        return 0;
}

static int virtioctrl_release (struct inode *, struct file *)
{
        return 0;
}

ssize_t virtioctrl_read (struct file* filep, char *, size_t, loff_t *)
{
        return 0;
}

ssize_t virtioctrl_write (struct file *, const char *, size_t, loff_t *)
{
        return 0;
}

long int virtioctrl_ioctl (struct file* dev,
                      unsigned int ioctl, unsigned long arg)
{
        struct virtio_region* regp = (struct virtio_region*)arg;
        struct virtio_region region;
        int error;

        switch (ioctl) {
        case VHOST_VIRTIO_ADD_REGION:
                if (copy_from_user(&region, regp, sizeof(region))) {
                        return -EFAULT;
                }
                error = virtioctrl_add_region(&region, UIO_MEM_PHYS);
                if (error != 0) {
                        return error;
                }
                if (copy_to_user(regp, &region, sizeof(region))) {
                        return -EFAULT;
                }
                break;
        case VHOST_VIRTIO_GET_REGION:
                uint32_t regsize;
                uint32_t reg_index;

                if (copy_from_user(&region, regp, sizeof(region))) {
                        return -EFAULT;
                }
                reg_index = region.indx;
                if (reg_index >= MAX_UIO_MAPS) {
                        return -EINVAL;
                }

                mutex_lock(&virtio_p_data.uio_dev->info_lock);
                regsize = virtio_p_data.mem[reg_index].size;
                if (regsize > 0) {
                        region.offs = virtio_p_data.mem[reg_index].offs;
                        region.addr = virtio_p_data.mem[reg_index].addr;
                        region.size = virtio_p_data.mem[reg_index].size;
                }
                mutex_unlock(&virtio_p_data.uio_dev->info_lock);
                if (regsize == 0) {
                        return -ENOMEM;
                }
                if (copy_to_user(regp, &region, sizeof(region))) {
                        return -EFAULT;
                }
                break;
        default:
                return -ENOIOCTLCMD;
        }
        return 0;
}

static struct file_operations virtioctrl_fops = {
        .open = virtioctrl_open,
        .read = virtioctrl_read,
        .write = virtioctrl_write,
        .unlocked_ioctl = virtioctrl_ioctl,
        .release = virtioctrl_release
};

/*
 * UIO functions
 */

static void virtio_uio_release(struct device* dev)
{
        (void)dev;
	pr_info("Releasing VirtIO uio device\n");
}

static void virtio_free_resource(struct platform_device* pdev)
{
        platform_device_unregister(pdev);
        of_node_put(pdev->dev.of_node);
}

static int __init virtio_uio_init(void)
{
        int err; /* error code */
        int i;
        struct resource* res;
        struct device_node* dev_node;

        dev_node = of_find_compatible_node(NULL, NULL, "virtio-host,mmio");

        dev_set_name(&virtio_p_device.dev, "virtio_uio_device");
	virtio_p_device.dev.release = virtio_uio_release;
        virtio_p_device.dev.of_node = NULL;

        if (dev_node == NULL) {
		pr_err("No compatible device node found\n");
		return -1;
        }
        err = of_address_to_resource(dev_node, 0,
                                     &virtio_uio_resources[0]);
        if (res != 0) {
                pr_err("Error getting address from node\n");
                return -1;
        }
        err = of_irq_to_resource(dev_node, 0,
                                 &virtio_uio_resources[1]);
        if (res != 0) {
                pr_err("Error getting irq from node\n");
                return -1;
        }
        if (irq == 0) {
                irq = of_irq_get(dev_node, 0);
        }

	virtio_p_data.irq = irq;
        virtio_p_data.irq_flags = IRQF_TRIGGER_RISING;

        /* save IRQ data to resources */
        irqresource_disabled(&virtio_uio_resources[1], irq);
        virtio_uio_resources[1].flags = IORESOURCE_IRQ;

        /*
         * Register device
         */
        err = platform_device_register(&virtio_p_device);
	if (err != 0) {
		pr_err("Failing to register platform device: %d\n",
                       err);
		return -1;
	}

        res = platform_get_resource(&virtio_p_device, IORESOURCE_MEM, 0);
	pr_info("Registered UIO handler for IRQ=%d\n", irq);
        for (i = 0; i < virtio_p_device.num_resources; i++) {
                pr_info("Resource found:\n");
                pr_info("start: 0x%X, end: 0x%X, flags: 0x%lX\n",
                       virtio_p_device.resource[i].start,
                        virtio_p_device.resource[i].end,
                        virtio_p_device.resource[i].flags);
        }

        /* create sysfs class */
        virtio_ctrl_class = class_create(THIS_MODULE, VIRTIO_CTRL_NAME);

        /* create a controlling character device */
        err = alloc_chrdev_region(&virtio_ctrl, 0, VIRTIO_NCTRL,
                                  VIRTIO_CTRL_NAME);
        if (err < 0) {
                pr_err("Unable to allocate character driver region\n");
                goto error;
        }

        virtio_ctrl_dev_major = MAJOR(virtio_ctrl);

        pr_info("Registered VirtIO control device %s (%d)\n",
                VIRTIO_CTRL_NAME, virtio_ctrl_dev_major);

        cdev_init(&virtio_ctrl_cdev, &virtioctrl_fops);
        virtio_ctrl_cdev.owner = THIS_MODULE;

        cdev_add(&virtio_ctrl_cdev, MKDEV(virtio_ctrl_dev_major, 0), 1);
        device_create(virtio_ctrl_class,
                      NULL, MKDEV(virtio_ctrl_dev_major, 0),
                      NULL, VIRTIO_CTRL_NAME);
        return 0;
error:
        virtio_free_resource(&virtio_p_device);
        return -1;
}

static void __exit virtio_uio_exit(void)
{
        device_destroy(virtio_ctrl_class, MKDEV(virtio_ctrl_dev_major, 0));
        class_destroy(virtio_ctrl_class);
        unregister_chrdev_region(virtio_ctrl, VIRTIO_NCTRL);
        virtio_free_resource(&virtio_p_device);
	printk(KERN_INFO "Un-Registered UIO handler for IRQ=%d\n", irq);
}

module_init(virtio_uio_init);
module_exit(virtio_uio_exit);

MODULE_AUTHOR("Dmitriy Korovkin");
MODULE_DESCRIPTION("UIO driver for VirtIO");
MODULE_LICENSE("GPL v2");
