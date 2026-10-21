CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c99
PREFIX  ?= /usr/local

PROG    = mturoute
SRC     = mturoute.c

.PHONY: all universal debug install uninstall clean

all: $(PROG)

$(PROG): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC)

# Fat binary that runs on both Apple Silicon and Intel Macs
universal: $(SRC)
	$(CC) $(CFLAGS) -arch arm64 -arch x86_64 -o $(PROG) $(SRC)

debug: CFLAGS = -O0 -g -Wall -Wextra -std=c99
debug: clean $(PROG)

install: $(PROG)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(PROG) $(DESTDIR)$(PREFIX)/bin/$(PROG)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(PROG)

clean:
	rm -rf $(PROG) $(PROG).dSYM
