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

DESCRIPTION      = "UGOS VirtIO UIO driver for HV 3.0"
LICENSE          = "MIT"
SECTION          = "network"
LIC_FILES_CHKSUM = "file://COPYING;md5=6bf501cbeeba69b506091e4d20d46f09"

# The inherit of module.bbclass will automatically name module packages with
# "kernel-module-" prefix as required by the oe-core build environment.
inherit module

PKG_name = "kernel-module-${PN}"

PR = "r0"
PV = "0.1"
S  = "${WORKDIR}"

SRC_URI = "file://Makefile \
           file://COPYING \
           file://uio-virtio.c \
           file://uio-virtio.h \
          "
do_install:append() {
  install -d ${D}${includedir}
  install -m 0644 uio-virtio.h ${D}${includedir} 
}

RRECOMMENDS_${PN} += "kernel-module-${PN}"
COMPATIBLE_MACHINE = "(aptiv-cvc-fl|aptiv-cvc-131|euto-v9-discovery)"
