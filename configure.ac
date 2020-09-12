AC_INIT([bwping], [2.0])

AC_CONFIG_SRCDIR([ChangeLog])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AM_INIT_AUTOMAKE

AC_ARG_ENABLE([mmsg],
    AS_HELP_STRING([--disable-mmsg], [Disable the use of sendmmsg()/recvmmsg()]))
AS_IF([test "${enable_mmsg}" != "no"], [
    AC_DEFINE([ENABLE_MMSG], [1],
        [Define to 1 if you want to use the `sendmmsg' and `recvmmsg' functions.])
])
AC_ARG_ENABLE([bpf],
    AS_HELP_STRING([--disable-bpf], [Disable the use of BPF for filtering incoming packets]))
AS_IF([test "${enable_bpf}" != "no"], [
    AC_DEFINE([ENABLE_BPF], [1],
        [Define to 1 if you want to use BPF to filter incoming packets.])
])

AC_PROG_CC
AC_PROG_CC_C99
AS_IF([test "${ac_cv_prog_cc_c99}" = "no"], [
    AC_MSG_ERROR([C99 compiler is required for build])
])

AC_PROG_LN_S
AC_PROG_INSTALL

AC_SEARCH_LIBS([socket], [socket], [],
    [AC_MSG_ERROR([socket() is required for build])])
AC_SEARCH_LIBS([getaddrinfo], [resolv nsl xnet], [],
    [AC_MSG_ERROR([getaddrinfo() is required for build])])
AC_SEARCH_LIBS([getnameinfo], [resolv nsl xnet], [],
    [AC_MSG_ERROR([getnameinfo() is required for build])])
AC_SEARCH_LIBS([clock_gettime], [rt],
    [AC_DEFINE([HAVE_CLOCK_GETTIME], [1],
        [Define to 1 if you have the `clock_gettime' function.])])
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
} __attribute__((packed));

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
        } __attribute__((packed)) ih_idseq;
        u_int32_t ih_void;

        /* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
        struct ih_pmtu
        {
            u_int16_t ipm_void;
            u_int16_t ipm_nextmtu;
        } __attribute__((packed)) ih_pmtu;

        struct ih_rtradv
        {
            u_int8_t irt_num_addrs;
            u_int8_t irt_wpa;
            u_int16_t irt_lifetime;
        } __attribute__((packed)) ih_rtradv;
    } __attribute__((packed)) icmp_hun;
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
        } __attribute__((packed)) id_ts;
        struct
        {
            struct ip idi_ip;
            /* options and then 64 bits of data */
        } __attribute__((packed)) id_ip;
        struct icmp_ra_addr id_radv;
        u_int32_t   id_mask;
        u_int8_t    id_data[1];
    } __attribute__((packed)) icmp_dun;
#define icmp_otime      icmp_dun.id_ts.its_otime
#define icmp_rtime      icmp_dun.id_ts.its_rtime
#define icmp_ttime      icmp_dun.id_ts.its_ttime
#define icmp_ip         icmp_dun.id_ip.idi_ip
#define icmp_radv       icmp_dun.id_radv
#define icmp_mask       icmp_dun.id_mask
#define icmp_data       icmp_dun.id_data
} __attribute__((packed));

struct icmp6_hdr {
    u_int8_t  icmp6_type;     /* type field */
    u_int8_t  icmp6_code;     /* code field */
    u_int16_t icmp6_cksum;    /* checksum field */
    union {
        u_int32_t icmp6_un_data32[1]; /* type-specific field */
        u_int16_t icmp6_un_data16[2]; /* type-specific field */
        u_int8_t  icmp6_un_data8[4];  /* type-specific field */
    } __attribute__((packed)) icmp6_dataun;
} __attribute__((packed));

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

#endif /* __CYGWIN__ */
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

AC_OUTPUT
