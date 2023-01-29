CFLAGS?=-W -Wall -Wextra -O2 -ggdb
CFLAGS+=$(shell gfxprim-config --cflags) $(shell pkg-config --cflags libnl-genl-3.0)
LDLIBS=-lgfxprim $(shell gfxprim-config --libs-widgets) $(shell pkg-config --libs libnl-genl-3.0 libnl-route-3.0)
BIN=gpnetwork
DEP=$(BIN:=.dep)
JSON=tab.json

all: $(DEP) $(BIN)

%.dep: %.c
	$(CC) $(CFLAGS) -M $< -o $@

install:
	install -D $(BIN) -t $(DESTDIR)/usr/bin/
	install -m 644 -D $(JSON) $(DESTDIR)/etc/gp_apps/$(BIN)/$(JSON)

-include $(DEP)

clean:
	rm -f $(BIN) *.dep *.o
