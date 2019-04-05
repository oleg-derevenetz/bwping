if BUILDIPV6
sbin_PROGRAMS   = bwping bwping6
bwping_SOURCES  = bwping.c cygwin.h
bwping6_SOURCES = bwping6.c cygwin.h
man_MANS        = bwping.8 bwping6.8
else
sbin_PROGRAMS   = bwping
bwping_SOURCES  = bwping.c cygwin.h
man_MANS        = bwping.8
endif
EXTRA_DIST      = $(man_MANS)
