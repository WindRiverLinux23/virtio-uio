#
# Copyright (C) 2023 Wind River Systems, Inc.
#

# UIO driver for VirtIO memory area and interrupts

SRCS = uio-virtio.c
virtio-uio-objs := $(SRCS:.c=.o)
obj-m := virtio-uio.o

SRC := $(shell pwd)

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC)

modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) modules_install

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f Module.markers Module.symvers modules.order
	rm -rf .tmp_versions Modules.symvers

