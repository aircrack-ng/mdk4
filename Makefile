PREFIX		= /usr/local
SBINDIR		= $(PREFIX)/sbin
MANDIR		= $(PREFIX)/share/man

SRC		= src


all: clean
	$(MAKE) -C $(SRC)

install: all
	PREFIX=$(PREFIX) $(MAKE) -C $(SRC) install
	install -D -m 0644 man/mdk3.8 $(MANDIR)/man8/mdk3.8
	gzip -f $(MANDIR)/man8/mdk3.8

.PHONY : clean
clean:
	$(MAKE) -C $(SRC) clean

test:
	$(MAKE) -C $(SRC) test

distclean: clean
