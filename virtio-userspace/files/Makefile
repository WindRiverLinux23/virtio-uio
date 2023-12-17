# UIO driver test Makefile

SRCS = uio_test.c \
       virtio_host_yaml_parser.c \
       virtio_host_lib.c \
       virtioVsmHost.c \
       virtio_host_block.c

BINARY = uio_test

OBJS = $(SRCS:.c=.o)
LIBS = -lyaml

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINARY): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(LIBDIR) $^ $(LIBS)

all: $(BINARY)

clean:
	@rm -f $(BINARY) $(OBJS)

distclean: clean
	@rm *~
