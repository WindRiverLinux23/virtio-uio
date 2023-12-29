# UIO driver test Makefile

SRCS = virtioUioTest.c \
       virtio_host_yaml_parser.c \
       virtio_host_lib.c \
       virtioVsmHost.c \
       virtioHostBlock.c

BINARY = uio_test

OBJS = $(SRCS:.c=.o)
LIBS = -lyaml -lssl -lcrypto

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINARY): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(LIBDIR) $^ $(LIBS)

all: $(BINARY)

clean:
	@rm -f $(BINARY) $(OBJS)

distclean: clean
	@rm *~
