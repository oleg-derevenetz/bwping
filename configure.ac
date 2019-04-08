AC_INIT([bwping], [1.11])

AC_CONFIG_SRCDIR([ChangeLog])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AM_INIT_AUTOMAKE

AC_ARG_ENABLE([warn], [AS_HELP_STRING([--disable-warn], [Disable additional warnings (-Wall -Wextra -Wpedantic)])])
AC_ARG_ENABLE([ipv6], [AS_HELP_STRING([--disable-ipv6], [Disable IPv6])])

AC_PROG_CC
AC_PROG_CC_C99
if test "$ac_cv_prog_cc_c99" = "no"; then
    AC_MSG_ERROR([C99-capable compiler is required for build])
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

AC_CHECK_FUNC([socket])
if test "$ac_cv_func_socket" = "no"; then
    AC_SEARCH_LIBS([socket], [socket], [], [AC_MSG_ERROR([socket() is required for build])])
fi
AC_CHECK_FUNC([inet_aton])
if test "$ac_cv_func_inet_aton" = "no"; then
    AC_SEARCH_LIBS([inet_aton], [resolv nsl socket], [], [AC_MSG_ERROR([inet_aton() is required for build])])
fi
AC_CHECK_FUNC([inet_ntop])
if test "$ac_cv_func_inet_ntop" = "no"; then
    AC_SEARCH_LIBS([inet_ntop], [resolv nsl socket], [], [AC_MSG_ERROR([inet_ntop() is required for build])])
fi
AC_CHECK_FUNC([hstrerror])
if test "$ac_cv_func_hstrerror" = "no"; then
    AC_SEARCH_LIBS([hstrerror], [resolv nsl socket], [], [AC_MSG_ERROR([hstrerror() is required for build])])
fi
AC_CHECK_FUNC([gethostbyname])
if test "$ac_cv_func_gethostbyname" = "no"; then
    AC_SEARCH_LIBS([gethostbyname], [resolv nsl socket], [], [AC_MSG_ERROR([gethostbyname() is required for build])])
fi
AC_CHECK_FUNC([getaddrinfo])
if test "$ac_cv_func_getaddrinfo" = "no"; then
    AC_SEARCH_LIBS([getaddrinfo], [resolv nsl socket], [], [AC_MSG_ERROR([getaddrinfo() is required for build])])
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

if test "$enable_warn" != "no" -a "$my_cv_wall" = "yes"; then
    AM_CFLAGS="$AM_CFLAGS -Wall"
fi
if test "$enable_warn" != "no" -a "$my_cv_wextra" = "yes"; then
    AM_CFLAGS="$AM_CFLAGS -Wextra"
fi
if test "$enable_warn" != "no" -a "$my_cv_wpedantic" = "yes"; then
    AM_CFLAGS="$AM_CFLAGS -Wpedantic"
fi
AC_SUBST([AM_CFLAGS])

AC_MSG_CHECKING([for IPv6 support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
/* Make sure the definitions for AF_INET6, struct sockaddr_in6 and
 * struct icmp6_hdr are defined, and that we can actually create an
 * IPv6 socket.
 */

#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#ifdef HAVE_NETINET_ICMP6_H
#include <netinet/icmp6.h>
#endif

#ifdef __CYGWIN__

/* BEGIN OF INCLUDE/CYGWIN.H */

#ifndef CYGWIN_H
#define CYGWIN_H

#ifndef ICMP_MINLEN
#define ICMP_MINLEN 8
#endif
#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif
#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY 0
#endif

struct icmp_ra_addr
{
    u_int32_t ira_addr;
    u_int32_t ira_preference;
};

struct icmp
{
  u_int8_t  icmp_type;  /* type of message, see below */
  u_int8_t  icmp_code;  /* type sub code */
  u_int16_t icmp_cksum; /* ones complement checksum of struct */
  union
  {
    u_char ih_pptr;             /* ICMP_PARAMPROB */
    struct in_addr ih_gwaddr;   /* gateway address */
    struct ih_idseq             /* echo datagram */
    {
      u_int16_t icd_id;
      u_int16_t icd_seq;
    } ih_idseq;
    u_int32_t ih_void;

    /* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
    struct ih_pmtu
    {
      u_int16_t ipm_void;
      u_int16_t ipm_nextmtu;
    } ih_pmtu;

    struct ih_rtradv
    {
      u_int8_t irt_num_addrs;
      u_int8_t irt_wpa;
      u_int16_t irt_lifetime;
    } ih_rtradv;
  } icmp_hun;
#define icmp_pptr       icmp_hun.ih_pptr
#define icmp_gwaddr     icmp_hun.ih_gwaddr
#define icmp_id         icmp_hun.ih_idseq.icd_id
#define icmp_seq        icmp_hun.ih_idseq.icd_seq
#define icmp_void       icmp_hun.ih_void
#define icmp_pmvoid     icmp_hun.ih_pmtu.ipm_void
#define icmp_nextmtu    icmp_hun.ih_pmtu.ipm_nextmtu
#define icmp_num_addrs  icmp_hun.ih_rtradv.irt_num_addrs
#define icmp_wpa        icmp_hun.ih_rtradv.irt_wpa
#define icmp_lifetime   icmp_hun.ih_rtradv.irt_lifetime
  union
  {
    struct
    {
      u_int32_t its_otime;
      u_int32_t its_rtime;
      u_int32_t its_ttime;
    } id_ts;
    struct
    {
      struct ip idi_ip;
      /* options and then 64 bits of data */
    } id_ip;
    struct icmp_ra_addr id_radv;
    u_int32_t   id_mask;
    u_int8_t    id_data[1];
  } icmp_dun;
#define icmp_otime      icmp_dun.id_ts.its_otime
#define icmp_rtime      icmp_dun.id_ts.its_rtime
#define icmp_ttime      icmp_dun.id_ts.its_ttime
#define icmp_ip         icmp_dun.id_ip.idi_ip
#define icmp_radv       icmp_dun.id_radv
#define icmp_mask       icmp_dun.id_mask
#define icmp_data       icmp_dun.id_data
};

struct icmp6_hdr {
  u_int8_t  icmp6_type;     /* type field */
  u_int8_t  icmp6_code;     /* code field */
  u_int16_t icmp6_cksum;    /* checksum field */
  union {
    u_int32_t icmp6_un_data32[1]; /* type-specific field */
    u_int16_t icmp6_un_data16[2]; /* type-specific field */
    u_int8_t  icmp6_un_data8[4];  /* type-specific field */
  } icmp6_dataun;
} __packed;

#define icmp6_data32    icmp6_dataun.icmp6_un_data32
#define icmp6_data16    icmp6_dataun.icmp6_un_data16
#define icmp6_data8     icmp6_dataun.icmp6_un_data8
#define icmp6_pptr      icmp6_data32[0] /* parameter prob */
#define icmp6_mtu       icmp6_data32[0] /* packet too big */
#define icmp6_id        icmp6_data16[0] /* echo request/reply */
#define icmp6_seq       icmp6_data16[1] /* echo request/reply */
#define icmp6_maxdelay  icmp6_data16[0] /* mcast group membership */

#define ICMP6_ECHO_REQUEST 128 /* echo service */
#define ICMP6_ECHO_REPLY   129 /* echo reply */

#endif /* CYGWIN_H */

/* END OF INCLUDE/CYGWIN.H */

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
    [my_cv_ipv6=no])
AC_MSG_RESULT([$my_cv_ipv6])

AM_CONDITIONAL([BUILD_IPV6], [test "$enable_ipv6" != "no" -a "$my_cv_ipv6" = "yes"])

AC_OUTPUT
