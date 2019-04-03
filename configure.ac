AC_INIT([bwping], [1.11])
AC_CONFIG_SRCDIR([ChangeLog])
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER([config.h])
AC_ARG_ENABLE([ipv6], AS_HELP_STRING([--disable-ipv6], [Disable IPv6]))
AC_PROG_CC_C99
if test "x$ac_cv_prog_cc_c99" = xno; then
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
if test "x$ac_cv_func_socket" = xno; then
    AC_CHECK_LIB(socket, socket, [], [echo "socket() is required for build"; exit -1])
fi
AC_CHECK_FUNC([inet_aton])
if test "x$ac_cv_func_inet_aton" = xno; then
    AC_CHECK_LIB(resolv, inet_aton, [], [echo "inet_aton() is required for build"; exit -1])
fi
AC_CHECK_FUNC([inet_ntop])
if test "x$ac_cv_func_inet_ntop" = xno; then
    AC_CHECK_LIB(resolv, inet_ntop, [], [echo "inet_ntop() is required for build"; exit -1])
fi
AC_CHECK_FUNC([gethostbyname])
if test "x$ac_cv_func_gethostbyname" = xno; then
    AC_SEARCH_LIBS(gethostbyname, [nsl socket], [], [echo "gethostbyname() is required for build"; exit -1])
fi
AC_CHECK_FUNC([getaddrinfo])
if test "x$ac_cv_func_getaddrinfo" = xno; then
    AC_SEARCH_LIBS(getaddrinfo, [nsl socket], [], [echo "getaddrinfo() is required for build"; exit -1])
fi
AC_MSG_CHECKING([for IPv6 support])
AC_CACHE_VAL([ac_cv_ipv6],
             AC_TRY_RUN([
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

/* Make sure the definitions for AF_INET6, struct sockaddr_in6 and
 * struct icmp6_hdr are defined, and that we can actually create an
 * IPv6 socket.
 */

int main()
{
    int fd;
    struct sockaddr_in6 foo;
    struct icmp6_hdr bar;
    fd = socket(AF_INET6, SOCK_STREAM, 0);
    exit(fd >= 0 ? 0 : 1);
}
             ],
             [ac_cv_ipv6=yes],
             [ac_cv_ipv6=no],
             [ac_cv_ipv6=no]))
AC_MSG_RESULT([$ac_cv_ipv6])
if test "x$ac_cv_ipv6" = xyes ; then
    AC_DEFINE([IPV6], [1], [Define to 1 if your system supports IPV6.])
fi
AM_CONDITIONAL([BUILDIPV6], [test "x$enable_ipv6" != "xno" -a $ac_cv_ipv6 = yes])
AC_OUTPUT([Makefile])
