#
# Copyright (C) 2024 Wind River Systems, Inc.
#

FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

# Add UIO drivers
SRC_URI:append = " \
    file://fragments/uio.cfg \
    file://fragments/virtio.cfg \
    file://0001-uio_make_MAX_UIO_MAPS_MAX_UIO_PORT_REGIONS_configurable.patch"

KDEFCONFIG_EXTRAS:append = " uio.cfg virtio.cfg"

do_custom_patch() {
    set +e

    cd "${S}"
    if ! git apply --reverse --check "${WORKDIR}/0001-uio_make_MAX_UIO_MAPS_MAX_UIO_PORT_REGIONS_configurable.patch"; then
        git apply "${WORKDIR}/0001-uio_make_MAX_UIO_MAPS_MAX_UIO_PORT_REGIONS_configurable.patch"
    fi
}

addtask do_custom_patch before do_deploy_source_date_epoch after do_unpack do_symlink_kernsrc
