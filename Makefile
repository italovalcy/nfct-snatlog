MAKE=/usr/bin/make
SUBDIRS=src man

RECURSIVE_TARGETS = all-recursive install-recursive uninstall-recursive \
						  clean-recursive

all: all-recursive

install: install-recursive

uninstall: uninstall-recursive

distclean: clean
clean: clean-recursive

$(RECURSIVE_TARGETS):
	@target=`echo $@ | sed s/-recursive//`; \
	for subdir in $(SUBDIRS); do \
		echo "Making $$target in $$subdir"; \
		(cd $$subdir && $(MAKE) $(AM_MAKEFLAGS) $$target) \
		|| exit 1; \
	done;

.PHONY: all install uninstall clean distclean $(RECURSIVE_TARGETS)
