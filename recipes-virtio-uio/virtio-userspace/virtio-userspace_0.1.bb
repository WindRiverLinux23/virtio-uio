#
# Copyright (C) 2024 Wind River Systems, Inc.
#

DESCRIPTION      = "UGOS VirtIO userspace driver for HV 3.0"
LICENSE          = "windriver"
SECTION          = "network"
LIC_FILES_CHKSUM = "file://COPYING;md5=ea54fd9db8421313ddc26370e6aa7e11"

# The inherit of module.bbclass will automatically name module packages with
# "kernel-module-" prefix as required by the oe-core build environment.

inherit systemd
SYSTEMD_SERVICE:${PN} = "virtio-userspace.service"

PKG_name = "${PN}"

PR = "r0"
PV = "0.1"
S  = "${WORKDIR}"

DEPENDS = "virtio-uio libyaml openssl"

SRC_URI = "file://Makefile \
           file://COPYING \
           file://virtioUioTest.c \
           file://virtioHostLib.h \
           file://virtioHostLib.c \
           file://virtio_host_parser.h \
           file://virtio_host_yaml_parser.c \
           file://virtioVsm.c \
           file://virtioLib.c \
           file://virtioLib.h \
           file://virtioHostBlock.c \
           file://virtioHostNet.c \
           file://virtioHostConsole.c \
           file://mevent.c \
           file://mevent.h \
           file://virtio-userspace.service \
          "
do_install() {
  install -d ${D}${bindir}
  install -m 0755 uio_test ${D}${bindir} 

  install -d ${D}${systemd_system_unitdir}
  install -m 0644 ${WORKDIR}/virtio-userspace.service ${D}${systemd_system_unitdir}
  sed -i -e 's,@BINDIR@,${bindir},g' \
         -e 's,@BASE_BINDIR@,${base_bindir},g' \
         -e 's,@BASE_SBINDIR@,${base_sbindir},g' \
         ${D}${systemd_system_unitdir}/virtio-userspace.service

}

RRECOMMENDS_${PN} += "${PN}"
