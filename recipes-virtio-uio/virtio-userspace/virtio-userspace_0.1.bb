DESCRIPTION      = "UGOS VirtIO userspace driver for HV 3.0"
LICENSE          = "BSD-3-Clause & MIT"
SECTION          = "network"
LIC_FILES_CHKSUM = " \
    file://gpu/atomic.h;beginline=1;endline=5;md5=bca6549c36843804782ba1ad3817837c \
    file://gpu/timer.c;beginline=1;endline=6;md5=1bcd0a1dfcd540911c25090e5a75c07d \
    file://gpu/timer.h;beginline=1;endline=6;md5=1bcd0a1dfcd540911c25090e5a75c07d \
    file://gpu/vdisplay.h;beginline=1;endline=9;md5=03ee5a5262e0725ec86e3b6dacf57868 \
    file://gpu/vdisplay_sdl.c;beginline=1;endline=9;md5=276661ad1fad98cb28ed08432c2e8d87 \
    file://gpu/vdisplay_sdl_gl.c;beginline=1;endline=21;md5=ed71ff9eb2c383db4f6b2bb02a86ef4f \
    file://gpu/virtio_gpu.c;beginline=1;endline=10;md5=48a91b9ba4c606a5c32bd613d0c1930e \
    file://gpu/virtio_gpu.h;beginline=1;endline=36;md5=9911bb005c4a3f8ca5b42bb30f037cf1 \
    file://gpu/virtio_gpu_virgl.c;beginline=1;endline=21;md5=ed71ff9eb2c383db4f6b2bb02a86ef4f \
    file://gpu/virtio_host_gpu.c;beginline=1;endline=21;md5=ed71ff9eb2c383db4f6b2bb02a86ef4f \
    file://gpu/virtio_host_gpu_cfg.h;beginline=1;endline=21;md5=ed71ff9eb2c383db4f6b2bb02a86ef4f \
    file://gpu/virtio_host_gpu.h;beginline=1;endline=21;md5=ed71ff9eb2c383db4f6b2bb02a86ef4f \
    file://gpu/window.h;beginline=1;endline=21;md5=079ae21dbf98ada52ec23744851b0a5c \
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
    file://virtioHostVSock.c;beginline=3;endline=23;md5=f6543e0490f594fcadd256b584fe21b0 \
    file://virtioHostVSock_unix.c;beginline=3;endline=23;md5=f6543e0490f594fcadd256b584fe21b0 \
    file://virtioHostVSock.h;beginline=3;endline=23;md5=f6543e0490f594fcadd256b584fe21b0 \
    "

# The inherit of module.bbclass will automatically name module packages with
# "kernel-module-" prefix as required by the oe-core build environment.

inherit systemd
SYSTEMD_SERVICE:${PN} = "virtio-userspace.service"

DEPENDS += "libyaml linux-libc-headers openssl virtio-uio libgpiod"
DEPENDS:append:euto-v9-discovery = " \
    libsdl2 sgpu-userspace pixman virglrenderer wayland"
RDEPENDS:${PN} += "libgpiod"

PR = "r0"
PV = "0.1"

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
           file://virtioHostGpio.c \
           file://mevent.c \
           file://mevent.h \
           file://virtio-userspace.service \
           file://gpu/virtio_host_gpu.c \
           file://gpu/vdisplay_sdl.c \
           file://gpu/atomic.h \
           file://gpu/timer.h \
           file://gpu/vdisplay.h \
           file://gpu/virtio_host_gpu.h \
           file://gpu/window.h \
           file://gpu/virtio_gpu_virgl.c \
           file://gpu/timer.c \
           file://gpu/virtio_gpu.c \
           file://gpu/virtio_host_gpu_cfg.h \
           file://gpu/vdisplay_sdl_gl.c \
           file://gpu/virtio_gpu.h \
           file://virtioHostVSock.c \
           file://virtioHostVSock.h \
           file://virtioHostVSock_unix.c \
          "

S = "${WORKDIR}"

EXTRA_OEMAKE:append:euto-v9-discovery = " CONFIG_INCLUDE_HOST_GPU=y"
TARGET_CFLAGS:append:euto-v9-discovery = " ${@bb.utils.contains("DISTRO_FEATURES", "x11", "", "-DEGL_NO_X11 ", d)}"
TARGET_CXXFLAGS:append:euto-v9-discovery = " ${@bb.utils.contains("DISTRO_FEATURES", "x11", "", "-DEGL_NO_X11 ", d)}"

# The header files of pixman library package is located at non-standard
# location as defined by STAGING_INCDIR. So, we manually specify the location
# to look for these header files.
TARGET_CFLAGS:append:euto-v9-discovery = " -I${STAGING_INCDIR}/pixman-1"

do_install() {
  install -d ${D}${bindir}
  install -m 0755 uio_test ${D}${bindir}

  install -d ${D}${systemd_system_unitdir}
  install -m 0644 ${WORKDIR}/virtio-userspace.service \
      ${D}${systemd_system_unitdir}
  sed -i -e 's,@BINDIR@,${bindir},g' \
         -e 's,@BASE_BINDIR@,${base_bindir},g' \
         -e 's,@BASE_SBINDIR@,${base_sbindir},g' \
         ${D}${systemd_system_unitdir}/virtio-userspace.service

}

COMPATIBLE_MACHINE = "(aptiv-cvc-fl|aptiv-cvc-131|euto-v9-discovery|xilinx-zynqmp|nxp-s32g|nxp-imx8)"
