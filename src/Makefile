CC=/usr/bin/gcc
RM=/bin/rm -f
MKDIR=/bin/mkdir -p
CCFLAGS=-Wall -O2
INSTALL=/usr/bin/install -c
DESTDIR=/usr

sbindir=$(DESTDIR)/sbin

all: nfct-snatlog

nfct-snatlog: nfct-snatlog-stamp
nfct-snatlog-stamp: nfct-snatlog.o list.o
	$(CC) $(CCFLAGS) $^ -o $(@:-stamp=) `pkg-config --cflags --libs libnetfilter_conntrack`
	touch $@

.c.o:
	$(CC) $(CCFLAGS) $< -c -o $@

install: install-exec


install-exec: install-exec-stamp
install-exec-stamp: nfct-snatlog
	test -z "$(sbindir)" || $(MKDIR) $(sbindir)
	$(INSTALL) $< $(sbindir)
	touch $@

uninstall: uninstall-exec
uninstall-exec:
	$(RM) $(sbindir)/nfct-snatlog

distclean: clean
clean:
	$(RM) *.o nfct-snatlog *-stamp

.PHONY: all nfct-snatlog clean distclean install uninstall install-exec \
	uninstall-exec
