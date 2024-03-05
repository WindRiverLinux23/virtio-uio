FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

# Add UIO drivers
SRC_URI:append = " file://fragments/uio.cfg \
                   file://fragments/virtio.cfg \
                   file://0001-uio_make_MAX_UIO_MAPS_MAX_UIO_PORT_REGIONS_configurable.patch"
