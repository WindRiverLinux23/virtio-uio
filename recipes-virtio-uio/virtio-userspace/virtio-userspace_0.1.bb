DESCRIPTION      = "UGOS VirtIO userspace driver for HV 3.0"
LICENSE          = "MIT"
SECTION          = "network"
LIC_FILES_CHKSUM = " \
    file://Makefile;beginline=1;endline=21;md5=13a73f1b45d9a0ba4c1702f0dc025282 \
    file://mevent.c;beginline=1;endline=22;md5=9d3a60a5d0d872a78d77298655c5987c \
    file://mevent.h;beginline=1;endline=22;md5=9d3a60a5d0d872a78d77298655c5987c \
    file://virtioHostBlock.c;beginline=3;endline=23;md5=f6543e0490f594fcadd256b584fe21b0 \
    file://virtioHostConsole.c;beginline=3;endline=23;md5=f6543e0490f594fcadd256b584fe21b0 \
    file://virtioHostLib.c;beginline=3;endline=23;md5=f6543e0490f594fcadd256b584fe21b0 \
    file://virtioHostLib.h;beginline=3;endline=23;md5=f6543e0490f594fcadd256b584fe21b0 \
    file://virtioHostNet.c;beginline=3;endline=23;md5=f6543e0490f594fcadd256b584fe21b0 \
    file://virtio_host_parser.h;beginline=3;endline=23;md5=f6543e0490f594fcadd256b584fe21b0 \
    file://virtio_host_yaml_parser.c;beginline=3;endline=23;md5=f6543e0490f594fcadd256b584fe21b0 \
    file://virtioLib.c;beginline=3;endline=23;md5=f6543e0490f594fcadd256b584fe21b0 \
    file://virtioLib.h;beginline=3;endline=23;md5=f6543e0490f594fcadd256b584fe21b0 \
    file://virtioUioTest.c;beginline=3;endline=23;md5=f6543e0490f594fcadd256b584fe21b0 \
    file://virtioVsm.c;beginline=3;endline=23;md5=f6543e0490f594fcadd256b584fe21b0 \
    "

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
