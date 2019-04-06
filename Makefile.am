AUTOMAKE_OPTIONS   = subdir-objects
dist_check_SCRIPTS = tests/bwping tests/bwping6
EXTRA_DIST         = man/bwping.8 man/bwping6.8
if BUILD_IPV6
sbin_PROGRAMS      = bwping bwping6
bwping_SOURCES     = include/cygwin.h include/features.h src/bwping.c
bwping6_SOURCES    = include/cygwin.h include/features.h src/bwping6.c
man_MANS           = man/bwping.8 man/bwping6.8
TESTS              = tests/bwping tests/bwping6
else
sbin_PROGRAMS      = bwping
bwping_SOURCES     = include/cygwin.h include/features.h src/bwping.c
man_MANS           = man/bwping.8
TESTS              = tests/bwping
endif
