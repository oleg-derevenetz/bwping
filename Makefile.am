AUTOMAKE_OPTIONS   = subdir-objects

sbin_PROGRAMS      = bwping

bwping_SOURCES     = src/bwping.c src/cygwin.h src/features.h

man_MANS           = man/bwping.8
EXTRA_DIST         = man/bwping.8

dist_check_SCRIPTS = tests/bwping tests/bwping6
TESTS              = tests/bwping tests/bwping6

## Create symlinks for bwping6 for convenience.
bwping_links       = bwping6

install-exec-hook:
	cd $(DESTDIR)$(sbindir) && \
	target=`echo bwping | sed '$(transform)'`$(EXEEXT) && \
	for name in $(bwping_links); do \
		link=`echo $$name | sed '$(transform)'`$(LN_EXEEXT) && \
		rm -f $$link && \
		$(LN_S) $$target $$link; \
	done

install-data-hook:
	cd $(DESTDIR)$(mandir)/man8 && \
	target=`echo bwping | sed '$(transform)'` && \
	for name in $(bwping_links); do \
		link=`echo $$name | sed '$(transform)'` && \
		rm -f $$link.8 && \
		$(LN_S) $$target.8 $$link.8; \
	done

uninstall-hook:
	cd $(DESTDIR)$(sbindir) && \
	for name in $(bwping_links); do \
		link=`echo $$name | sed '$(transform)'`$(LN_EXEEXT) && \
		rm -f $$link; \
	done
	cd $(DESTDIR)$(mandir)/man8 && \
	for name in $(bwping_links); do \
		link=`echo $$name | sed '$(transform)'` && \
		rm -f $$link.8; \
	done
