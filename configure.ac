AC_INIT([bwping], [2.4])

AC_CONFIG_SRCDIR([ChangeLog])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE

AC_USE_SYSTEM_EXTENSIONS

AC_PROG_CC
AS_IF([test "${ac_cv_prog_cc_c11}" = "no"], [
    AC_MSG_ERROR([C11 compiler is required for build])
])

AC_PROG_LN_S
AC_PROG_INSTALL

AC_SEARCH_LIBS([clock_gettime], [rt], [],
    [AC_MSG_ERROR([`clock_gettime' function is required for build])])
AC_SEARCH_LIBS([socket], [socket], [],
    [AC_MSG_ERROR([`socket' function is required for build])])
AC_SEARCH_LIBS([getaddrinfo], [resolv nsl xnet], [],
    [AC_MSG_ERROR([`getaddrinfo' function is required for build])])
AC_SEARCH_LIBS([getnameinfo], [resolv nsl xnet], [],
    [AC_MSG_ERROR([`getnameinfo' function is required for build])])
AC_SEARCH_LIBS([sendmmsg], [socket],
    [AC_DEFINE([HAVE_SENDMMSG], [1],
        [Define to 1 if you have the `sendmmsg' function.])])
AC_SEARCH_LIBS([recvmmsg], [socket],
    [AC_DEFINE([HAVE_RECVMMSG], [1],
        [Define to 1 if you have the `recvmmsg' function.])])

AC_CHECK_HEADERS([netinet/icmp6.h], [], [], [
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip6.h>
    ])
AC_CHECK_HEADERS([linux/filter.h])

bwping_save_cflags=${CFLAGS}
AC_MSG_CHECKING([whether the C compiler accepts -Wall...])
CFLAGS="${CFLAGS} -Wall"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
                  [bwping_cv_c_wall=yes],
                  [bwping_cv_c_wall=no])
CFLAGS=${bwping_save_cflags}
AC_MSG_RESULT([${bwping_cv_c_wall}])
AS_IF([test "${bwping_cv_c_wall}" = "yes"], [
    AM_CFLAGS="${AM_CFLAGS} -Wall"
])
AC_MSG_CHECKING([whether the C compiler accepts -Wextra...])
CFLAGS="${CFLAGS} -Wextra"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
                  [bwping_cv_c_wextra=yes],
                  [bwping_cv_c_wextra=no])
CFLAGS=${bwping_save_cflags}
AC_MSG_RESULT([${bwping_cv_c_wextra}])
AS_IF([test "${bwping_cv_c_wextra}" = "yes"], [
    AM_CFLAGS="${AM_CFLAGS} -Wextra"
])
AC_MSG_CHECKING([whether the C compiler accepts -Wpedantic...])
CFLAGS="${CFLAGS} -Wpedantic"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
                  [bwping_cv_c_wpedantic=yes],
                  [bwping_cv_c_wpedantic=no])
CFLAGS=${bwping_save_cflags}
AC_MSG_RESULT([${bwping_cv_c_wpedantic}])
AS_IF([test "${bwping_cv_c_wpedantic}" = "yes"], [
    AM_CFLAGS="${AM_CFLAGS} -Wpedantic"
])
AC_MSG_CHECKING([whether the C compiler accepts -Wno-missing-field-initializers...])
CFLAGS="${CFLAGS} -Wno-missing-field-initializers"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
                  [bwping_cv_c_wnomissingfieldinitializers=yes],
                  [bwping_cv_c_wnomissingfieldinitializers=no])
CFLAGS=${bwping_save_cflags}
AC_MSG_RESULT([${bwping_cv_c_wnomissingfieldinitializers}])
AS_IF([test "${bwping_cv_c_wnomissingfieldinitializers}" = "yes"], [
    AM_CFLAGS="${AM_CFLAGS} -Wno-missing-field-initializers"
])
AC_SUBST([AM_CFLAGS])

AC_MSG_CHECKING([for IPv6 support])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
#include <sys/types.h>
#include <sys/socket.h>

#include <stdlib.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#ifdef HAVE_NETINET_ICMP6_H
#include <netinet/icmp6.h>
#endif

#ifdef __CYGWIN__
m4_include([src/cygwin.h])
#endif
    ], [
        struct sockaddr_in6 foo;
        struct icmp6_hdr bar;

        socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

        exit(0);
    ])],
    [bwping_cv_sys_ipv6=yes],
    [bwping_cv_sys_ipv6=no])
AC_MSG_RESULT([${bwping_cv_sys_ipv6}])
AS_IF([test "${bwping_cv_sys_ipv6}" = "no"], [
    AC_MSG_ERROR([IPv6 support is required for build])
])

AC_ARG_ENABLE([mmsg],
    AS_HELP_STRING([--disable-mmsg], [Disable the use of the `sendmmsg' and `recvmmsg' functions]))
AS_IF([test "${enable_mmsg}" != "no"], [
    AC_DEFINE([ENABLE_MMSG], [1],
        [Define to 1 if you want to use the `sendmmsg' and `recvmmsg' functions.])
], [
    AC_MSG_NOTICE([The use of the `sendmmsg' and `recvmmsg' functions has been disabled])
])
AC_ARG_ENABLE([bpf],
    AS_HELP_STRING([--disable-bpf], [Disable the use of BPF for filtering incoming packets]))
AS_IF([test "${enable_bpf}" != "no"], [
    AC_DEFINE([ENABLE_BPF], [1],
        [Define to 1 if you want to use BPF to filter incoming packets.])
], [
    AC_MSG_NOTICE([The use of BPF for filtering incoming packets has been disabled])
])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
