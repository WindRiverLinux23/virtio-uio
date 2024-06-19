#
# Copyright (c) 2024 Wind River Systems, Inc.
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

# UIO driver test Makefile

SRCS = \
    virtioUioTest.c \
    virtio_host_yaml_parser.c \
    virtioHostLib.c \
    virtioVsm.c \
    virtioLib.c \
    virtioHostBlock.c \
    virtioHostNet.c \
    mevent.c \
    virtioHostConsole.c \
    virtioHostGpio.c \
    virtioHostVSock.c \
    virtioHostVSock_unix.c \
    virtioHostShowLib.c \
    virtioShowLib.c

LDFLAGS += -lyaml -lssl -lcrypto -lpthread -lgpiod

ifeq ($(CONFIG_INCLUDE_HOST_GPU),y)
SRCS += \
    gpu/timer.c \
    gpu/vdisplay_sdl.c \
    gpu/vdisplay_sdl_gl.c \
    gpu/virtio_gpu.c \
    gpu/virtio_gpu_virgl.c \
    gpu/virtio_host_gpu.c
CFLAGS += -DINCLUDE_HOST_GPU
LDFLAGS += \
    -lpixman-1 -lwayland-client -lGLESv2 -lEGL -lSDL2 -lvirglrenderer -lm
endif

BINARY = uio_test

OBJS = $(SRCS:.c=.o)

.PHONY: all clean distclean

.c.o:
	@echo CFLAGS = $(CFLAGS)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINARY): $(OBJS)
	@echo LDFLAGS = $(LDFLAGS)
	$(CC) $^ $(LDFLAGS) -o $@

all: $(BINARY)
	@echo SRCS = $(SRCS)

clean:
	@rm -f $(BINARY) $(OBJS)

distclean: clean
	@rm *~
