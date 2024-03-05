# This file is used to add packages to the ramfs image.

# Add the virtio-uio kernel module to the ramfs image
IMAGE_INSTALL += "virtio-uio"
IMAGE_INSTALL += "kernel-module-virtio-uio"

# Add userspace program to the ramfs image
IMAGE_INSTALL += "virtio-userspace"