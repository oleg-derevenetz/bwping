AUTOMAKE_OPTIONS   = subdir-objects

sbin_PROGRAMS      = bwping bwping6

bwping_SOURCES     = include/cygwin.h include/features.h src/bwping.c
bwping_CFLAGS      = ${AM_CFLAGS} -DBUILD_BWPING

bwping6_SOURCES    = include/cygwin.h include/features.h src/bwping.c
bwping6_CFLAGS     = ${AM_CFLAGS} -DBUILD_BWPING6

man_MANS           = man/bwping.8
EXTRA_DIST         = man/bwping.8

dist_check_SCRIPTS = tests/bwping tests/bwping6
TESTS              = tests/bwping tests/bwping6

## Create symlinks for bwping6 for convenience.
bwpinglinks        = bwping6

install-data-hook:
	cd $(DESTDIR)$(mandir)/man8 && \
	target=`echo bwping | sed '$(transform)'` && \
	for name in $(bwpinglinks); do \
		link=`echo $$name | sed '$(transform)'` && \
		rm -f $$link.8 && \
		$(LN_S) $$target.8 $$link.8; \
	done

uninstall-hook:
	cd $(DESTDIR)$(mandir)/man8 && \
	for name in $(bwpinglinks); do \
		link=`echo $$name | sed '$(transform)'` && \
		rm -f $$link.1; \
	done
