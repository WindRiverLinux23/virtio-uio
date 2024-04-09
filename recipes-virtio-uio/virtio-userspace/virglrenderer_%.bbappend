DEPENDS:remove:euto-v9-discovery = "mesa"
DEPENDS:append:euto-v9-discovery = " virtual/egl"

TARGET_CFLAGS:append:euto-v9-discovery = " ${@bb.utils.contains("DISTRO_FEATURES", "x11", "", "-DEGL_NO_X11 ", d)}"
TARGET_CXXFLAGS:append:euto-v9-discovery = " ${@bb.utils.contains("DISTRO_FEATURES", "x11", "", "-DEGL_NO_X11 ", d)}"
