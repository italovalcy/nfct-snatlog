RM=/bin/rm -f
MKDIR=/bin/mkdir -p
INSTALL=/usr/bin/install -c -m 644
DESTDIR=/usr
man8dir=$(DESTDIR)/man/man8


install: install-man8

uninstall: uninstall-man8

install-man8: install-man8-stamp
install-man8-stamp: nfct-snatlog.8
	test -z "$(man8dir)" || $(MKDIR) $(man8dir)
	$(INSTALL) $< $(man8dir)
	touch $@

uninstall-man8:
	$(RM) $(man8dir)/nfct-snatlog.8

distclean: clean
clean:
	$(RM) *-stamp

.PHONY: all install distclean clean uninstall install-man8 uninstall-man8
