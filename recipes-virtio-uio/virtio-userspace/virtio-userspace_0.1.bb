#
# Copyright (c) 2024, Wind River Systems, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

DESCRIPTION      = "UGOS VirtIO userspace driver for HV 3.0"
LICENSE          = "MIT"
SECTION          = "network"
LIC_FILES_CHKSUM = "file://COPYING;md5=6bf501cbeeba69b506091e4d20d46f09"

# The inherit of module.bbclass will automatically name module packages with
# "kernel-module-" prefix as required by the oe-core build environment.

inherit systemd
SYSTEMD_SERVICE:${PN} = "virtio-userspace.service"

PKG_name = "${PN}"

PR = "r0"
PV = "0.1"
S  = "${WORKDIR}"

DEPENDS = "linux-libc-headers virtio-uio libyaml openssl"

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
COMPATIBLE_MACHINE = "(aptiv-cvc-fl|aptiv-cvc-131|euto-v9-discovery)"
