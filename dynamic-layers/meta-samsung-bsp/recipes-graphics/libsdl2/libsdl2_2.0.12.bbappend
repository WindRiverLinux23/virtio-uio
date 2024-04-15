# If the sgpu-userspace is used for GPU driver, then we need to remove opengl
# as sgpu-userspace does not provide OpenGL support (virtual/libgl).
PACKAGECONFIG:remove:euto-v9-discovery = "\
    ${@bb.utils.contains("GPU_MODE", "sgpu-userspace", "opengl", "", d)}"

EXTRA_OECONF:append:euto-v9-discovery = " --enable-video-wayland"
