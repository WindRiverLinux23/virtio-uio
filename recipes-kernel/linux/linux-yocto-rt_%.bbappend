#
# Copyright (C) 2024 Wind River Systems, Inc.
#

FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

# Add UIO drivers
SRC_URI:append = " file://fragments/uio.scc"
