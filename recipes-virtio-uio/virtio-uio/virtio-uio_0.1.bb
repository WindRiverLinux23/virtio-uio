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
