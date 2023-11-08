# UIO driver test Makefile

SRCS = uio_test.c
BINARY = uio_test

OBJS = $(SRCS:.c=.o)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINARY): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(LIBDIR) $^ $(LIBS)

all: $(BINARY)

clean:
	@rm -f $(BINARY) $(OBJS)

distclean: clean
	@rm *~
