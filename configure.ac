AC_INIT([bwping], [1.11])
AC_CONFIG_SRCDIR([ChangeLog])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([config.h])
AC_ARG_ENABLE([ipv6], [AS_HELP_STRING([--disable-ipv6], [Disable IPv6])])
AC_PROG_CC
AC_PROG_CC_C99
if test "$ac_cv_prog_cc_c99" = "no"; then
    echo "C99-capable compiler is required for build"; exit -1
fi
AC_PROG_INSTALL
AC_CHECK_HEADER([netinet/icmp6.h],
                [AC_DEFINE([HAVE_NETINET_ICMP6_H], [1], [Define to 1 if you have the <netinet/icmp6.h> header file.])],
                [],
                [
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip6.h>
                ])
AC_CHECK_MEMBER([struct sockaddr_in.sin_len],
                [AC_DEFINE([HAVE_SOCKADDR_IN_SIN_LEN], [1], [Define to 1 if you have the sin_len member in struct sockaddr_in.])],
                [],
                [
#include <sys/types.h>

#include <netinet/in.h>
                ])
AC_CHECK_FUNC([socket])
if test "$ac_cv_func_socket" = "no"; then
    AC_SEARCH_LIBS([socket], [socket], [], [echo "socket() is required for build"; exit -1])
fi
AC_CHECK_FUNC([inet_aton])
if test "$ac_cv_func_inet_aton" = "no"; then
    AC_SEARCH_LIBS([inet_aton], [resolv nsl socket], [], [echo "inet_aton() is required for build"; exit -1])
fi
AC_CHECK_FUNC([inet_ntop])
if test "$ac_cv_func_inet_ntop" = "no"; then
    AC_SEARCH_LIBS([inet_ntop], [resolv nsl socket], [], [echo "inet_ntop() is required for build"; exit -1])
fi
AC_CHECK_FUNC([hstrerror])
if test "$ac_cv_func_hstrerror" = "no"; then
    AC_SEARCH_LIBS([hstrerror], [resolv nsl socket], [], [echo "hstrerror() is required for build"; exit -1])
fi
AC_CHECK_FUNC([gethostbyname])
if test "$ac_cv_func_gethostbyname" = "no"; then
    AC_SEARCH_LIBS([gethostbyname], [resolv nsl socket], [], [echo "gethostbyname() is required for build"; exit -1])
fi
AC_CHECK_FUNC([getaddrinfo])
if test "$ac_cv_func_getaddrinfo" = "no"; then
    AC_SEARCH_LIBS([getaddrinfo], [resolv nsl socket], [], [echo "getaddrinfo() is required for build"; exit -1])
fi
my_save_cflags="$CFLAGS"
AC_MSG_CHECKING([whether the C compiler accepts -Wall...])
CFLAGS="$CFLAGS -Wall"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
                  [my_cv_wall=yes],
                  [my_cv_wall=no])
AC_MSG_RESULT([$my_cv_wall])
CFLAGS="$my_save_cflags"
AC_MSG_CHECKING([whether the C compiler accepts -Wextra...])
CFLAGS="$CFLAGS -Wextra"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
                  [my_cv_wextra=yes],
                  [my_cv_wextra=no])
AC_MSG_RESULT([$my_cv_wextra])
CFLAGS="$my_save_cflags"
AC_MSG_CHECKING([whether the C compiler accepts -Wpedantic...])
CFLAGS="$CFLAGS -Wpedantic"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
                  [my_cv_wpedantic=yes],
                  [my_cv_wpedantic=no])
AC_MSG_RESULT([$my_cv_wpedantic])
CFLAGS="$my_save_cflags"
if test "$my_cv_wall" = "yes"; then
    AM_CFLAGS="$AM_CFLAGS -Wall"
fi
if test "$my_cv_wextra" = "yes"; then
    AM_CFLAGS="$AM_CFLAGS -Wextra"
fi
if test "$my_cv_wpedantic" = "yes"; then
    AM_CFLAGS="$AM_CFLAGS -Wpedantic"
fi
AC_SUBST([AM_CFLAGS])
AC_MSG_CHECKING([for IPv6 support])
AC_CACHE_VAL([my_cv_ipv6],
             [AC_RUN_IFELSE([AC_LANG_PROGRAM([
/* Make sure the definitions for AF_INET6, struct sockaddr_in6 and
 * struct icmp6_hdr are defined, and that we can actually create an
 * IPv6 socket.
 */

#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip6.h>
#ifdef HAVE_NETINET_ICMP6_H
#include <netinet/icmp6.h>
#endif

#ifdef __CYGWIN__
#include <netinet/ip.h>
#include "cygwin.h"
#endif
    ], [
        int fd;
        struct sockaddr_in6 foo;
        struct icmp6_hdr bar;
        fd = socket(AF_INET6, SOCK_STREAM, 0);
        exit(fd >= 0 ? 0 : 1);
    ])],
    [my_cv_ipv6=yes],
    [my_cv_ipv6=no],
    [my_cv_ipv6=no])])
AC_MSG_RESULT([$my_cv_ipv6])
if test "$my_cv_ipv6" = "yes"; then
    AC_DEFINE([IPV6], [1], [Define to 1 if your system supports IPV6.])
fi
AM_CONDITIONAL([BUILDIPV6], [test "$enable_ipv6" != "no" -a "$my_cv_ipv6" = "yes"])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
