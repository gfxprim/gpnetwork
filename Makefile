CFLAGS=-W -Wall -Wextra -O2 $(shell gfxprim-config --cflags) $(shell pkg-config --cflags libnl-genl-3.0) -ggdb
LDLIBS=-lgfxprim $(shell gfxprim-config --libs-widgets) $(shell pkg-config --libs libnl-genl-3.0 libnl-route-3.0)
BIN=gpnetwork
DEP=$(BIN:=.dep)

all: $(DEP) $(BIN)

%.dep: %.c
	$(CC) $(CFLAGS) -M $< -o $@

install:
	install -D $(BIN) -t $(DESTDIR)/usr/bin/

-include $(DEP)

clean:
	rm -f $(BIN) *.dep *.o
