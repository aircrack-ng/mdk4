DESTDIR		= 
PREFIX		= /usr/local
SBINDIR		= $(PREFIX)/sbin
MANDIR		= $(PREFIX)/share/man

SRC		= src


all: clean
	$(MAKE) -C $(SRC)

install: all
	PREFIX=$(DESTDIR)$(PREFIX)
	$(MAKE) -C $(SRC) install
	install -D -m 0644 man/mdk4.2 $(DESTDIR)$(MANDIR)/man8/mdk4.2
	gzip -f $(DESTDIR)$(MANDIR)/man8/mdk4.2

.PHONY : clean
clean:
	$(MAKE) -C $(SRC) clean

test:
	$(MAKE) -C $(SRC) test

distclean: clean
