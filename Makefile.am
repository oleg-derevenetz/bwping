AUTOMAKE_OPTIONS = subdir-objects

sbin_PROGRAMS = bwping bwping6

bwping_SOURCES = include/cygwin.h include/features.h src/bwping.c
bwping_CFLAGS  = -DBUILD_BWPING -Wall -Wextra -Wpedantic

bwping6_SOURCES = include/cygwin.h include/features.h src/bwping.c
bwping6_CFLAGS  = -DBUILD_BWPING6 -Wall -Wextra -Wpedantic

man_MANS   = man/bwping.8 man/bwping6.8
EXTRA_DIST = man/bwping.8 man/bwping6.8

dist_check_SCRIPTS = tests/bwping tests/bwping6
TESTS              = tests/bwping tests/bwping6
