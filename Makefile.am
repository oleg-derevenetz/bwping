AUTOMAKE_OPTIONS   = subdir-objects

sbin_PROGRAMS      = bwping bwping6

bwping_SOURCES     = include/cygwin.h include/features.h src/bwping.c
bwping_CFLAGS      = ${AM_CFLAGS} -DBUILD_BWPING

bwping6_SOURCES    = include/cygwin.h include/features.h src/bwping.c
bwping6_CFLAGS     = ${AM_CFLAGS} -DBUILD_BWPING6

man_MANS           = man/bwping.8 man/bwping6.8
EXTRA_DIST         = man/bwping.8 man/bwping6.8

dist_check_SCRIPTS = tests/bwping tests/bwping6
TESTS              = tests/bwping tests/bwping6
