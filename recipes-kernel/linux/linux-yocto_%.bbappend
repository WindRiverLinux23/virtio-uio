#
# Copyright (C) 2024 Wind River Systems, Inc.
#

FILESEXTRAPATHS:prepend := "${THISDIR}/${PN}:"

# Add UIO drivers
SRC_URI:append = " file://uio.scc"
