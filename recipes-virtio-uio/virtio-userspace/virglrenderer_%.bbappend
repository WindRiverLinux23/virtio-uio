DEPENDS_remove_euto-v9-discovery = "mesa"
DEPENDS_append_euto-v9-discovery = " virtual/egl"

TARGET_CFLAGS_append_euto-v9-discovery = " ${@bb.utils.contains("DISTRO_FEATURES", "x11", "", "-DEGL_NO_X11 ", d)}"
TARGET_CXXFLAGS_append_euto-v9-discovery = " ${@bb.utils.contains("DISTRO_FEATURES", "x11", "", "-DEGL_NO_X11 ", d)}"
