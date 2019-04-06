AUTOMAKE_OPTIONS = subdir-objects
if BUILDIPV6
sbin_PROGRAMS    = bwping bwping6
bwping_SOURCES   = include/cygwin.h include/features.h src/bwping.c
bwping6_SOURCES  = include/cygwin.h include/features.h src/bwping6.c
man_MANS         = man/bwping.8 man/bwping6.8
else
sbin_PROGRAMS    = bwping
bwping_SOURCES   = include/cygwin.h include/features.h src/bwping.c
man_MANS         = man/bwping.8
endif
EXTRA_DIST       = $(man_MANS)
