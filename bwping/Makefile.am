if BUILDIPV6
sbin_PROGRAMS	= bwping bwping6
bwping_SOURCES	= bwping.c
bwping6_SOURCES	= bwping6.c
man_MANS	= bwping.8 bwping6.8
else
sbin_PROGRAMS	= bwping
bwping_SOURCES	= bwping.c
man_MANS	= bwping.8
endif
AM_CFLAGS	= -Wall
EXTRA_DIST	= $(man_MANS)
