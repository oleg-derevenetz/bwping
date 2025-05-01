/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2007-2025, Oleg Derevenetz <oleg.derevenetz@gmail.com>.
 *
 * Use of this source code is governed by a BSD-style license that can be found in the COPYING file.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#ifdef HAVE_NETINET_ICMP6_H
#include <netinet/icmp6.h>
#endif

#ifdef HAVE_LINUX_FILTER_H
#include <linux/filter.h>
#endif

#ifdef __CYGWIN__
#include "cygwin.h"
#endif

#include <netdb.h>

#ifdef BWPING_CALIBRATION_CYCLES
#if BWPING_CALIBRATION_CYCLES < 1
#error "BWPING_CALIBRATION_CYCLES must be greater than zero"
#endif
#else
#define BWPING_CALIBRATION_CYCLES 32
#endif

#if defined( ENABLE_MMSG ) && ( defined( HAVE_SENDMMSG ) || defined( HAVE_RECVMMSG ) )
#ifdef BWPING_MAX_MMSG_VLEN
#if BWPING_MAX_MMSG_VLEN < 1
#error "BWPING_MAX_MMSG_VLEN must be greater than zero"
#endif
#else
#define BWPING_MAX_MMSG_VLEN 64
#endif
#else
#undef BWPING_MAX_MMSG_VLEN
#endif

/* The max length of an IPv4 address is 15 chars, the max length of an IPv6 address is 45 chars plus a scope ID (no fixed length) */
#ifdef BWPING_MAX_ADDR_LEN
#if BWPING_MAX_ADDR_LEN < 1
#error "BWPING_MAX_ADDR_LEN must be greater than zero"
#endif
#else
#define BWPING_MAX_ADDR_LEN 128
#endif

struct pkt_counters
{
    uint64_t count;
    uint64_t volume;
};

struct rtt_counters
{
    uint64_t count;
    uint64_t sum;
    uint64_t min;
    uint64_t max;
};

static const size_t   MAX_IPV4_HDR_SIZE = 60;
static const uint64_t PKT_BURST_SCALE   = 1000;

static const char * prog_name;

static void get_time( struct timespec * const ts )
{
#if defined( CLOCK_HIGHRES )
    const clockid_t id = CLOCK_HIGHRES; /* Solaris */
#elif defined( CLOCK_MONOTONIC_RAW )
    const clockid_t id = CLOCK_MONOTONIC_RAW; /* Linux */
#elif defined( CLOCK_MONOTONIC )
    const clockid_t id = CLOCK_MONOTONIC;
#else
    const clockid_t id = CLOCK_REALTIME;
#endif

    if ( clock_gettime( id, ts ) < 0 ) {
        fprintf( stderr, "%s: clock_gettime() failed: %s\n", prog_name, strerror( errno ) );

        ts->tv_sec  = 0;
        ts->tv_nsec = 0;
    }
}

static int64_t int64_sub( const int64_t i1, const int64_t i2 )
{
    if ( i2 < 0 ) {
        if ( i1 > INT64_MAX + i2 ) {
            return INT64_MAX;
        }
    }
    else {
        if ( i1 < INT64_MIN + i2 ) {
            return INT64_MIN;
        }
    }

    return i1 - i2;
}

static int64_t ts_sub( const struct timespec * const ts1, const struct timespec * const ts2 )
{
    int64_t sec_diff = int64_sub( ts1->tv_sec, ts2->tv_sec );

    if ( sec_diff > INT32_MAX ) {
        sec_diff = INT32_MAX;
    }
    if ( sec_diff < INT32_MIN ) {
        sec_diff = INT32_MIN;
    }

    int64_t nsec_diff = int64_sub( ts1->tv_nsec, ts2->tv_nsec );

    if ( nsec_diff > INT32_MAX ) {
        nsec_diff = INT32_MAX;
    }
    if ( nsec_diff < INT32_MIN ) {
        nsec_diff = INT32_MIN;
    }

    return sec_diff * 1000000 + nsec_diff / 1000;
}

static uint16_t cksum( const char * const data, const size_t size )
{
    uint32_t sum = 0;

    for ( size_t i = 0; i < size; i = i + 2 ) {
        uint16_t u16 = 0;

        if ( i < size - 1 ) {
            memcpy( &u16, &data[i], 2 );
        }
        else {
            memcpy( &u16, &data[i], 1 );
        }

        sum += u16;
    }

    sum = ( sum >> 16 ) + ( sum & 0xFFFF );
    sum += ( sum >> 16 );

    return ~sum;
}

static uint64_t calibrate_timer( void )
{
    uint64_t time_diffs[BWPING_CALIBRATION_CYCLES];

    size_t successful_cycles = 0;

    for ( unsigned int i = 0; i < BWPING_CALIBRATION_CYCLES; i++ ) {
        struct timespec before;

        get_time( &before );

        struct timeval timeout = { .tv_sec = 0, .tv_usec = 10 };

        if ( select( 0, NULL, NULL, NULL, &timeout ) < 0 ) {
            fprintf( stderr, "%s: select() failed: %s\n", prog_name, strerror( errno ) );
        }
        else {
            struct timespec after;

            get_time( &after );

            const int64_t time_diff = ts_sub( &after, &before );

            if ( time_diff >= 0 ) {
                time_diffs[successful_cycles++] = time_diff;
            }
            else {
                fprintf( stderr, "%s: clock skew detected\n", prog_name );
            }
        }
    }

    if ( successful_cycles > 1 ) {
        uint64_t sum = 0;

        /* Use the basic 3rd-order median filter to remove random spikes */
        for ( size_t i = 0; i < successful_cycles; i++ ) {
            uint64_t a = i == 0 ? time_diffs[i] : time_diffs[i - 1];
            uint64_t b = time_diffs[i];
            uint64_t c = i == successful_cycles - 1 ? time_diffs[i] : time_diffs[i + 1];

            /* Take the median value from the set of values a, b and c */
            sum += ( a < b ) ? ( ( b < c ) ? b : ( ( c < a ) ? a : c ) ) : ( ( a < c ) ? a : ( ( c < b ) ? b : c ) );
        }

        return sum / successful_cycles;
    }

    if ( successful_cycles == 1 ) {
        return time_diffs[0];
    }

    return 0;
}

static void clear_socket_buffer( const int sock )
{
    ssize_t res = 0;

    do {
        static char packet[IP_MAXPACKET];

        res = recv( sock, packet, sizeof( packet ), 0 );

        if ( res < 0 && errno != EAGAIN && errno != EWOULDBLOCK ) {
            fprintf( stderr, "%s: recv() failed: %s\n", prog_name, strerror( errno ) );
        }
    } while ( res > 0 );
}

static void prepare_ping4( char * const packet, const size_t pkt_size, const uint16_t ident, const bool insert_timestamp, struct pkt_counters * const transmitted )
{
    struct icmp icmp4 = { .icmp_type = ICMP_ECHO, .icmp_code = 0, .icmp_cksum = 0, .icmp_id = htons( ident ), .icmp_seq = htons( transmitted->count ) };

    memcpy( packet, &icmp4, sizeof( icmp4 ) );

    if ( insert_timestamp ) {
        struct timespec pkt_time;

        get_time( &pkt_time );

        memcpy( &packet[sizeof( icmp4 )], &pkt_time, sizeof( pkt_time ) );

        /* Optimization: it is assumed that the rest of the packet is already zeroed */
        icmp4.icmp_cksum = cksum( packet, sizeof( icmp4 ) + sizeof( pkt_time ) );
    }
    else {
        memset( &packet[sizeof( icmp4 )], 0, sizeof( struct timespec ) );

        /* Optimization: it is assumed that the rest of the packet is already zeroed */
        icmp4.icmp_cksum = cksum( packet, sizeof( icmp4 ) );
    }

    memcpy( &packet[offsetof( struct icmp, icmp_cksum )], &icmp4.icmp_cksum, sizeof( icmp4.icmp_cksum ) );

    transmitted->count += 1;
    transmitted->volume += pkt_size;
}

static void prepare_ping6( char * const packet, const size_t pkt_size, const uint16_t ident, const bool insert_timestamp, struct pkt_counters * const transmitted )
{
    const struct icmp6_hdr icmp6
        = { .icmp6_type = ICMP6_ECHO_REQUEST, .icmp6_code = 0, .icmp6_cksum = 0, .icmp6_id = htons( ident ), .icmp6_seq = htons( transmitted->count ) };

    memcpy( packet, &icmp6, sizeof( icmp6 ) );

    if ( insert_timestamp ) {
        struct timespec pkt_time;

        get_time( &pkt_time );

        memcpy( &packet[sizeof( icmp6 )], &pkt_time, sizeof( pkt_time ) );
    }
    else {
        memset( &packet[sizeof( icmp6 )], 0, sizeof( struct timespec ) );
    }

    transmitted->count += 1;
    transmitted->volume += pkt_size;
}

#if defined( ENABLE_MMSG ) && defined( HAVE_SENDMMSG )

static void sendmmsg_ping( const bool                  ipv4_mode,
                           const int                   sock,
                           const size_t                pkt_size,
                           const uint16_t              ident,
                           const uint64_t              pkt_count,
                           struct pkt_counters * const transmitted )
{
    for ( uint64_t i = 0; i < pkt_count; i = i + BWPING_MAX_MMSG_VLEN ) {
        static char packets[BWPING_MAX_MMSG_VLEN][IP_MAXPACKET] = { { 0 } };

        struct iovec   iov[BWPING_MAX_MMSG_VLEN];
        struct mmsghdr msg[BWPING_MAX_MMSG_VLEN];

        const unsigned int vlen = pkt_count - i > BWPING_MAX_MMSG_VLEN ? BWPING_MAX_MMSG_VLEN : pkt_count - i;

        for ( unsigned int j = 0; j < vlen; j++ ) {
            if ( ipv4_mode ) {
                prepare_ping4( packets[j], pkt_size, ident, i == 0 && j == 0, transmitted );
            }
            else {
                prepare_ping6( packets[j], pkt_size, ident, i == 0 && j == 0, transmitted );
            }

            memset( &iov[j], 0, sizeof( iov[j] ) );

            iov[j].iov_base = packets[j];
            iov[j].iov_len  = pkt_size;

            memset( &msg[j], 0, sizeof( msg[j] ) );

            msg[j].msg_hdr.msg_iov    = &iov[j];
            msg[j].msg_hdr.msg_iovlen = 1;
        }

        const int res = sendmmsg( sock, msg, vlen, 0 );

        if ( res < 0 ) {
            fprintf( stderr, "%s: sendmmsg() failed: %s\n", prog_name, strerror( errno ) );
        }
        else if ( (unsigned int)res != vlen ) {
            fprintf( stderr, "%s: sendmmsg() packets to send: %u, sent: %d\n", prog_name, vlen, res );
        }
    }
}

#else /* ENABLE_MMSG && HAVE_SENDMMSG */

static void send_ping( const bool                  ipv4_mode,
                       const int                   sock,
                       const size_t                pkt_size,
                       const uint16_t              ident,
                       const bool                  insert_timestamp,
                       struct pkt_counters * const transmitted )
{
    static char packet[IP_MAXPACKET] = { 0 };

    if ( ipv4_mode ) {
        prepare_ping4( packet, pkt_size, ident, insert_timestamp, transmitted );
    }
    else {
        prepare_ping6( packet, pkt_size, ident, insert_timestamp, transmitted );
    }

    const ssize_t res = send( sock, packet, pkt_size, 0 );

    if ( res < 0 ) {
        fprintf( stderr, "%s: send() failed: %s\n", prog_name, strerror( errno ) );
    }
    else if ( (size_t)res != pkt_size ) {
        fprintf( stderr, "%s: send() packet size: %zu, sent: %zd\n", prog_name, pkt_size, res );
    }
}

#endif /* ENABLE_MMSG && HAVE_SENDMMSG */

static void process_ping4( const char * const packet, const size_t pkt_size, const uint16_t ident, struct pkt_counters * const received, struct rtt_counters * const rtt )
{
    struct ip ip4;

    if ( pkt_size < sizeof( ip4 ) ) {
        return;
    }

    memcpy( &ip4, packet, sizeof( ip4 ) );

    if ( ip4.ip_p != IPPROTO_ICMP || ( ntohs( ip4.ip_off ) & 0x1FFF ) != 0 ) {
        return;
    }

    const size_t hdr_len = ip4.ip_hl << 2;

    struct icmp icmp4;

    if ( pkt_size < hdr_len + sizeof( icmp4 ) ) {
        return;
    }

    memcpy( &icmp4, &packet[hdr_len], sizeof( icmp4 ) );

    if ( icmp4.icmp_type != ICMP_ECHOREPLY || ntohs( icmp4.icmp_id ) != ident ) {
        return;
    }

    received->count += 1;
    received->volume += pkt_size - hdr_len;

    struct timespec pkt_time;

    if ( pkt_size < hdr_len + sizeof( icmp4 ) + sizeof( pkt_time ) ) {
        return;
    }

    memcpy( &pkt_time, &packet[hdr_len + sizeof( icmp4 )], sizeof( pkt_time ) );

    if ( pkt_time.tv_sec == 0 && pkt_time.tv_nsec == 0 ) {
        return;
    }

    struct timespec now;

    get_time( &now );

    const int64_t pkt_rtt = ts_sub( &now, &pkt_time ) / 1000;

    if ( pkt_rtt < 0 ) {
        fprintf( stderr, "%s: packet has an invalid timestamp\n", prog_name );

        return;
    }

    rtt->count += 1;
    rtt->sum += pkt_rtt;

    if ( rtt->min > (uint64_t)pkt_rtt ) {
        rtt->min = pkt_rtt;
    }
    if ( rtt->max < (uint64_t)pkt_rtt ) {
        rtt->max = pkt_rtt;
    }
}

static void process_ping6( const char * const packet, const size_t pkt_size, const uint16_t ident, struct pkt_counters * const received, struct rtt_counters * const rtt )
{
    struct icmp6_hdr icmp6;

    if ( pkt_size < sizeof( icmp6 ) ) {
        return;
    }

    memcpy( &icmp6, packet, sizeof( icmp6 ) );

    if ( icmp6.icmp6_type != ICMP6_ECHO_REPLY || ntohs( icmp6.icmp6_id ) != ident ) {
        return;
    }

    received->count += 1;
    received->volume += pkt_size;

    struct timespec pkt_time;

    if ( pkt_size < sizeof( icmp6 ) + sizeof( pkt_time ) ) {
        return;
    }

    memcpy( &pkt_time, &packet[sizeof( icmp6 )], sizeof( pkt_time ) );

    if ( pkt_time.tv_sec == 0 && pkt_time.tv_nsec == 0 ) {
        return;
    }

    struct timespec now;

    get_time( &now );

    const int64_t pkt_rtt = ts_sub( &now, &pkt_time ) / 1000;

    if ( pkt_rtt < 0 ) {
        fprintf( stderr, "%s: packet has an invalid timestamp\n", prog_name );

        return;
    }

    rtt->count += 1;
    rtt->sum += pkt_rtt;

    if ( rtt->min > (uint64_t)pkt_rtt ) {
        rtt->min = pkt_rtt;
    }
    if ( rtt->max < (uint64_t)pkt_rtt ) {
        rtt->max = pkt_rtt;
    }
}

#if defined( ENABLE_MMSG ) && defined( HAVE_RECVMMSG )

static bool recvmmsg_ping( const bool ipv4_mode, const int sock, const uint16_t ident, struct pkt_counters * const received, struct rtt_counters * const rtt )
{
    static char packets[BWPING_MAX_MMSG_VLEN][IP_MAXPACKET];

    struct iovec   iov[BWPING_MAX_MMSG_VLEN] = { { .iov_len = 0 } };
    struct mmsghdr msg[BWPING_MAX_MMSG_VLEN] = { { .msg_len = 0 } };

    for ( unsigned int i = 0; i < BWPING_MAX_MMSG_VLEN; i++ ) {
        iov[i].iov_base = packets[i];
        iov[i].iov_len  = sizeof( packets[i] );

        msg[i].msg_hdr.msg_iov    = &iov[i];
        msg[i].msg_hdr.msg_iovlen = 1;
    }

    const int res = recvmmsg( sock, msg, BWPING_MAX_MMSG_VLEN, 0, NULL );

    if ( res < 0 && errno != EAGAIN && errno != EWOULDBLOCK ) {
        fprintf( stderr, "%s: recvmmsg() failed: %s\n", prog_name, strerror( errno ) );

        return false;
    }

    if ( res > 0 ) {
        for ( int i = 0; i < res; i++ ) {
            if ( ipv4_mode ) {
                process_ping4( packets[i], msg[i].msg_len, ident, received, rtt );
            }
            else {
                process_ping6( packets[i], msg[i].msg_len, ident, received, rtt );
            }
        }

        return true;
    }

    return false;
}

#else /* ENABLE_MMSG && HAVE_RECVMMSG */

static bool recv_ping( const bool ipv4_mode, const int sock, const uint16_t ident, struct pkt_counters * const received, struct rtt_counters * const rtt )
{
    static char packet[IP_MAXPACKET];

    const ssize_t res = recv( sock, packet, sizeof( packet ), 0 );

    if ( res < 0 && errno != EAGAIN && errno != EWOULDBLOCK ) {
        fprintf( stderr, "%s: recv() failed: %s\n", prog_name, strerror( errno ) );

        return false;
    }

    if ( res > 0 ) {
        if ( ipv4_mode ) {
            process_ping4( packet, res, ident, received, rtt );
        }
        else {
            process_ping6( packet, res, ident, received, rtt );
        }

        return true;
    }

    return false;
}

#endif /* ENABLE_MMSG && HAVE_RECVMMSG */

static bool resolve_name( const bool ipv4_mode, const char * const name, struct addrinfo ** const ai )
{
    struct addrinfo hints = { .ai_flags = AI_CANONNAME, .ai_socktype = SOCK_RAW };

    if ( ipv4_mode ) {
        hints.ai_family   = AF_INET;
        hints.ai_protocol = IPPROTO_ICMP;
    }
    else {
        hints.ai_family   = AF_INET6;
        hints.ai_protocol = IPPROTO_ICMPV6;
    }

    const int res = getaddrinfo( name, NULL, &hints, ai );

    if ( res != 0 ) {
        fprintf( stderr, "%s: cannot resolve %s: %s\n", prog_name, name, gai_strerror( res ) );

        return false;
    }

    return true;
}

int main( int argc, char * argv[] )
{
    prog_name = basename( argv[0] );

    bool ipv4_mode = ( strcmp( prog_name, "bwping" ) == 0 );
    int  exit_val  = EX_OK;

    unsigned int tos_or_traf_class = 0;
    unsigned int buf_size          = 0;
    size_t       pkt_size          = 0;
    uint16_t     ident             = 0;
    int32_t      reporting_period  = 0;
    uint32_t     kbps              = 0;
    uint64_t     volume            = 0;
    const char * bind_addr         = NULL;
    const char * target            = NULL;

    int ch;

    while ( ( ch = getopt( argc, argv, "46B:I:T:b:r:s:u:v:" ) ) != -1 ) {
        char * ep;

        switch ( ch ) {
        case '4':
            ipv4_mode = true;

            break;
        case '6':
            ipv4_mode = false;

            break;
        case 'B':
            bind_addr = optarg;

            break;
        case 'I':
            ident = strtoul( optarg, &ep, 0 );

            if ( *ep || ep == optarg ) {
                exit_val = EX_USAGE;
            }

            break;
        case 'T':
            tos_or_traf_class = strtoul( optarg, &ep, 0 );

            if ( *ep || ep == optarg ) {
                exit_val = EX_USAGE;
            }

            break;
        case 'b':
            kbps = strtoul( optarg, &ep, 0 );

            if ( *ep || ep == optarg ) {
                exit_val = EX_USAGE;
            }

            break;
        case 'r':
            reporting_period = strtol( optarg, &ep, 0 );

            if ( *ep || ep == optarg ) {
                exit_val = EX_USAGE;
            }

            break;
        case 's':
            pkt_size = strtoul( optarg, &ep, 0 );

            if ( *ep || ep == optarg ) {
                exit_val = EX_USAGE;
            }

            break;
        case 'u':
            buf_size = strtoul( optarg, &ep, 0 );

            if ( *ep || ep == optarg ) {
                exit_val = EX_USAGE;
            }

            break;
        case 'v':
            volume = strtoull( optarg, &ep, 0 );

            if ( *ep || ep == optarg ) {
                exit_val = EX_USAGE;
            }

            break;
        default:
            exit_val = EX_USAGE;
        }
    }

    if ( argc - optind == 1 ) {
        target = argv[optind];
    }

    if ( pkt_size == 0 || kbps == 0 || volume == 0 || target == NULL ) {
        exit_val = EX_USAGE;
    }

    if ( exit_val != EX_OK ) {
#if defined( PACKAGE_STRING )
        fprintf( stderr, "%s is part of the %s package\n", prog_name, PACKAGE_STRING );
#endif
        fprintf( stderr,
                 "Usage: %s [-4 | -6] [-B bind_addr] [-I ident] [-T tos(v4) | traf_class(v6)] [-r reporting_period]"
                 " [-u buf_size] -b kbps -s pkt_size -v volume target\n",
                 prog_name );

        exit( exit_val );
    }

    if ( ipv4_mode ) {
        if ( pkt_size < sizeof( struct icmp ) + sizeof( struct timespec ) || pkt_size > IP_MAXPACKET - MAX_IPV4_HDR_SIZE ) {
            fprintf( stderr,
                     "%s: invalid packet size, should be between %zu and %zu\n",
                     prog_name,
                     sizeof( struct icmp ) + sizeof( struct timespec ),
                     (size_t)IP_MAXPACKET - MAX_IPV4_HDR_SIZE );

            exit( EX_USAGE );
        }
    }
    else {
        if ( pkt_size < sizeof( struct icmp6_hdr ) + sizeof( struct timespec ) || pkt_size > IP_MAXPACKET ) {
            fprintf( stderr,
                     "%s: invalid packet size, should be between %zu and %zu\n",
                     prog_name,
                     sizeof( struct icmp6_hdr ) + sizeof( struct timespec ),
                     (size_t)IP_MAXPACKET );

            exit( EX_USAGE );
        }
    }

    if ( reporting_period < 0 ) {
        fprintf( stderr, "%s: invalid reporting period, should be non-negative\n", prog_name );

        exit( EX_USAGE );
    }

    int sock;

    if ( ipv4_mode ) {
        sock = socket( AF_INET, SOCK_RAW, IPPROTO_ICMP );

        if ( sock < 0 ) {
            fprintf( stderr, "%s: socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) failed: %s\n", prog_name, strerror( errno ) );

            exit( EX_OSERR );
        }
    }
    else {
        sock = socket( AF_INET6, SOCK_RAW, IPPROTO_ICMPV6 );

        if ( sock < 0 ) {
            fprintf( stderr, "%s: socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6) failed: %s\n", prog_name, strerror( errno ) );

            exit( EX_OSERR );
        }
    }

    if ( setuid( getuid() ) < 0 ) {
        fprintf( stderr, "%s: setuid(getuid()) failed: %s\n", prog_name, strerror( errno ) );

        exit_val = EX_OSERR;
    }

    if ( exit_val == EX_OK ) {
        if ( fcntl( sock, F_SETFL, O_NONBLOCK ) < 0 ) {
            fprintf( stderr, "%s: fcntl(F_SETFL, O_NONBLOCK) failed: %s\n", prog_name, strerror( errno ) );

            exit_val = EX_OSERR;
        }
    }

    if ( exit_val == EX_OK ) {
        if ( bind_addr != NULL ) {
            struct addrinfo * bind_ai;

            if ( resolve_name( ipv4_mode, bind_addr, &bind_ai ) ) {
                if ( bind( sock, bind_ai->ai_addr, bind_ai->ai_addrlen ) < 0 ) {
                    fprintf( stderr, "%s: bind() failed: %s\n", prog_name, strerror( errno ) );

                    exit_val = EX_OSERR;
                }

                freeaddrinfo( bind_ai );
            }
            else {
                exit_val = EX_NOHOST;
            }
        }
    }

    if ( exit_val == EX_OK ) {
        struct addrinfo * target_ai;

        if ( resolve_name( ipv4_mode, target, &target_ai ) ) {
            if ( connect( sock, target_ai->ai_addr, target_ai->ai_addrlen ) < 0 ) {
                fprintf( stderr, "%s: connect() failed: %s\n", prog_name, strerror( errno ) );

                exit_val = EX_OSERR;
            }
            else {
                char addr_buf[BWPING_MAX_ADDR_LEN];

                const int res = getnameinfo( target_ai->ai_addr, target_ai->ai_addrlen, addr_buf, sizeof( addr_buf ), NULL, 0, NI_NUMERICHOST );

                if ( res != 0 ) {
                    fprintf( stderr, "%s: getnameinfo() failed: %s\n", prog_name, gai_strerror( res ) );

                    if ( sizeof( addr_buf ) > 1 ) {
                        addr_buf[0] = '?';
                        addr_buf[1] = 0;
                    }
                    else {
                        addr_buf[0] = 0;
                    }
                }

                printf( "Target: %s (%s), transfer speed: %" PRIu32 " kbps, packet size: %zu bytes, traffic volume: %" PRIu64 " bytes\n",
                        target,
                        addr_buf,
                        kbps,
                        pkt_size,
                        volume );
            }

            freeaddrinfo( target_ai );
        }
        else {
            exit_val = EX_NOHOST;
        }
    }

    if ( exit_val == EX_OK ) {
        if ( buf_size > 0 ) {
            if ( setsockopt( sock, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof( buf_size ) ) < 0 ) {
                fprintf( stderr, "%s: setsockopt(SO_RCVBUF, %u) failed: %s\n", prog_name, buf_size, strerror( errno ) );
            }
            if ( setsockopt( sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof( buf_size ) ) < 0 ) {
                fprintf( stderr, "%s: setsockopt(SO_SNDBUF, %u) failed: %s\n", prog_name, buf_size, strerror( errno ) );
            }
        }

        if ( ipv4_mode ) {
            if ( setsockopt( sock, IPPROTO_IP, IP_TOS, &tos_or_traf_class, sizeof( tos_or_traf_class ) ) < 0 ) {
                fprintf( stderr, "%s: setsockopt(IP_TOS, %u) failed: %s\n", prog_name, tos_or_traf_class, strerror( errno ) );
            }
        }
        else {
            if ( setsockopt( sock, IPPROTO_IPV6, IPV6_TCLASS, &tos_or_traf_class, sizeof( tos_or_traf_class ) ) < 0 ) {
                fprintf( stderr, "%s: setsockopt(IPV6_TCLASS, %u) failed: %s\n", prog_name, tos_or_traf_class, strerror( errno ) );
            }
        }

#if defined( HAVE_NETINET_ICMP6_H ) && defined( ICMP6_FILTER ) && defined( ICMP6_FILTER_SETBLOCKALL ) && defined( ICMP6_FILTER_SETPASS )
        if ( !ipv4_mode ) {
            struct icmp6_filter filter6;

            ICMP6_FILTER_SETBLOCKALL( &filter6 );
            ICMP6_FILTER_SETPASS( ICMP6_ECHO_REPLY, &filter6 );

            if ( setsockopt( sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filter6, sizeof( filter6 ) ) < 0 ) {
                fprintf( stderr, "%s: setsockopt(ICMP6_FILTER) failed: %s\n", prog_name, strerror( errno ) );
            }
        }
#endif /* HAVE_NETINET_ICMP6_H && ICMP6_FILTER && ICMP6_FILTER_SETBLOCKALL && ICMP6_FILTER_SETPASS */

        if ( ident == 0 ) {
            ident = getpid() & 0xFFFF;
        }

#if defined( ENABLE_BPF ) && defined( HAVE_LINUX_FILTER_H ) && defined( SO_ATTACH_FILTER )
        if ( ipv4_mode ) {
            struct sock_filter filter[] = {
                /* (00) */ { 0x30, 0, 0, 0x00000009 },     /* ldb  [9]                         - IP Protocol */
                /* (01) */ { 0x15, 0, 8, IPPROTO_ICMP },   /* jeq  $IPPROTO_ICMP   jt 2  jf 10 - IP Protocol is ICMP */
                /* (02) */ { 0x28, 0, 0, 0x00000006 },     /* ldh  [6]                         - IP Fragment Offset */
                /* (03) */ { 0x45, 6, 0, 0x00001FFF },     /* jset #0x1FFF         jt 10 jf 4  - IP Fragment Offset is zero */
                /* (04) */ { 0xB1, 0, 0, 0x00000000 },     /* ldxb 4*([0]&0xF)                 - Load IHL*4 to X */
                /* (05) */ { 0x50, 0, 0, 0x00000000 },     /* ldb  [x]                         - ICMP Type */
                /* (06) */ { 0x15, 0, 3, ICMP_ECHOREPLY }, /* jeq  $ICMP_ECHOREPLY jt 7  jf 10 - ICMP Type is Echo Reply */
                /* (07) */ { 0x48, 0, 0, 0x00000004 },     /* ldh  [x + 4]                     - ICMP Id */
                /* (08) */ { 0x15, 0, 1, ident },          /* jeq  $ident          jt 9  jf 10 - ICMP Id is ident */
                /* (09) */ { 0x06, 0, 0, 0x00040000 },     /* ret  #0x40000                    - Accept packet */
                /* (10) */ { 0x06, 0, 0, 0x00000000 }      /* ret  #0x0                        - Discard packet */
            };

            const struct sock_fprog bpf = { .len = sizeof( filter ) / sizeof( filter[0] ), .filter = filter };

            if ( setsockopt( sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof( bpf ) ) < 0 ) {
                fprintf( stderr, "%s: setsockopt(SO_ATTACH_FILTER) failed: %s\n", prog_name, strerror( errno ) );
            }
        }
        else {
            struct sock_filter filter[] = {
                /* (00) */ { 0x30, 0, 0, 0x00000000 },       /* ldb [0]                         - ICMPv6 Type */
                /* (01) */ { 0x15, 0, 3, ICMP6_ECHO_REPLY }, /* jeq $ICMP6_ECHO_REPLY jt 2 jf 5 - ICMPv6 Type is Echo Reply */
                /* (02) */ { 0x28, 0, 0, 0x00000004 },       /* ldh [4]                         - ICMPv6 Id */
                /* (03) */ { 0x15, 0, 1, ident },            /* jeq $ident            jt 4 jf 5 - ICMPv6 Id is ident */
                /* (04) */ { 0x06, 0, 0, 0x00040000 },       /* ret #0x40000                    - Accept packet */
                /* (05) */ { 0x06, 0, 0, 0x00000000 }        /* ret #0x0                        - Discard packet */
            };

            const struct sock_fprog bpf = { .len = sizeof( filter ) / sizeof( filter[0] ), .filter = filter };

            if ( setsockopt( sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof( bpf ) ) < 0 ) {
                fprintf( stderr, "%s: setsockopt(SO_ATTACH_FILTER) failed: %s\n", prog_name, strerror( errno ) );
            }
        }
#endif /* ENABLE_BPF && HAVE_LINUX_FILTER_H && SO_ATTACH_FILTER */

        clear_socket_buffer( sock );

        const uint64_t min_interval = calibrate_timer() * 2; /* Leave space for interval_error adjustments */
        uint64_t       interval     = pkt_size * 8000 / kbps;

        uint64_t pkt_burst;

        if ( interval >= min_interval ) {
            pkt_burst = PKT_BURST_SCALE * 1;
        }
        else if ( interval == 0 ) {
            pkt_burst = PKT_BURST_SCALE * min_interval * kbps / 8000 / pkt_size;
            interval  = min_interval;
        }
        else {
            pkt_burst = PKT_BURST_SCALE * min_interval / interval;
            interval  = min_interval;
        }

        const uint64_t total_count = volume % pkt_size == 0 ? volume / pkt_size : volume / pkt_size + 1;

        bool                finish           = false;
        uint64_t            pkt_burst_error  = 0;
        uint64_t            current_interval = interval;
        uint64_t            interval_error   = 0;
        struct pkt_counters transmitted      = { .count = 0, .volume = 0 };
        struct pkt_counters received         = { .count = 0, .volume = 0 };
        struct rtt_counters rtt              = { .count = 0, .sum = 0, .min = UINT64_MAX, .max = 0 };

        struct timespec start;
        struct timespec end;
        struct timespec report;

        get_time( &start );
        get_time( &end );
        get_time( &report );

        while ( !finish ) {
            struct timespec interval_start;

            get_time( &interval_start );

            const uint64_t pkt_count = total_count - transmitted.count > pkt_burst / PKT_BURST_SCALE + pkt_burst_error / PKT_BURST_SCALE
                                           ? pkt_burst / PKT_BURST_SCALE + pkt_burst_error / PKT_BURST_SCALE
                                           : total_count - transmitted.count;

#if defined( ENABLE_MMSG ) && defined( HAVE_SENDMMSG )
            sendmmsg_ping( ipv4_mode, sock, pkt_size, ident, pkt_count, &transmitted );
#else
            for ( uint64_t i = 0; i < pkt_count; i++ ) {
                send_ping( ipv4_mode, sock, pkt_size, ident, i == 0, &transmitted );
            }
#endif

            pkt_burst_error = pkt_burst_error % PKT_BURST_SCALE;
            pkt_burst_error += pkt_burst % PKT_BURST_SCALE;

            uint64_t select_timeout = current_interval;

            while ( true ) {
                fd_set fds;

                FD_ZERO( &fds );
                FD_SET( sock, &fds );

                struct timeval timeout = { .tv_sec = select_timeout / 1000000, .tv_usec = select_timeout % 1000000 };

                const int n = select( sock + 1, &fds, NULL, NULL, &timeout );

                if ( n < 0 ) {
                    fprintf( stderr, "%s: select() failed: %s\n", prog_name, strerror( errno ) );
                }
                else if ( n > 0 ) {
#if defined( ENABLE_MMSG ) && defined( HAVE_RECVMMSG )
                    while ( recvmmsg_ping( ipv4_mode, sock, ident, &received, &rtt ) ) {
#else
                    while ( recv_ping( ipv4_mode, sock, ident, &received, &rtt ) ) {
#endif
                        if ( received.count >= transmitted.count ) {
                            break;
                        }
                    }
                }

                struct timespec now;

                get_time( &now );

                const int64_t time_diff = ts_sub( &now, &interval_start );

                if ( time_diff < 0 || (uint64_t)time_diff >= current_interval ) {
                    if ( transmitted.volume >= volume ) {
                        finish = true;
                    }
                    else {
                        if ( time_diff >= 0 ) {
                            interval_error += time_diff - current_interval;
                        }
                        else {
                            fprintf( stderr, "%s: clock skew detected\n", prog_name );
                        }

                        if ( interval_error >= interval / 2 ) {
                            current_interval = interval / 2;
                            interval_error -= interval / 2;
                        }
                        else {
                            current_interval = interval;
                        }
                    }

                    break;
                }

                select_timeout = current_interval - time_diff;
            }

            get_time( &end );

            const int64_t report_sec_diff = ts_sub( &end, &report ) / 1000000;
            const int64_t start_sec_diff  = ts_sub( &end, &start ) / 1000000;

            if ( reporting_period > 0 && report_sec_diff >= reporting_period ) {
                printf( "Periodic: pkts sent/rcvd: %" PRIu64 "/%" PRIu64 ", volume sent/rcvd: %" PRIu64 "/%" PRIu64 " bytes,"
                        " time: %" PRId64 " sec, speed: %" PRIu64 " kbps, rtt min/max/average: %" PRIu64 "/%" PRIu64 "/%" PRIu64 " ms\n",
                        transmitted.count,
                        received.count,
                        transmitted.volume,
                        received.volume,
                        start_sec_diff,
                        start_sec_diff > 0 ? received.volume / start_sec_diff * 8 / 1000 : received.volume * 8 / 1000,
                        rtt.min == UINT64_MAX ? 0 : rtt.min,
                        rtt.max,
                        rtt.count > 0 ? rtt.sum / rtt.count : 0 );

                get_time( &report );
            }
        }

        const int64_t sec_diff = ts_sub( &end, &start ) / 1000000;

        printf( "Total: pkts sent/rcvd: %" PRIu64 "/%" PRIu64 ", volume sent/rcvd: %" PRIu64 "/%" PRIu64 " bytes,"
                " time: %" PRId64 " sec, speed: %" PRIu64 " kbps, rtt min/max/average: %" PRIu64 "/%" PRIu64 "/%" PRIu64 " ms\n",
                transmitted.count,
                received.count,
                transmitted.volume,
                received.volume,
                sec_diff,
                sec_diff > 0 ? received.volume / sec_diff * 8 / 1000 : received.volume * 8 / 1000,
                rtt.min == UINT64_MAX ? 0 : rtt.min,
                rtt.max,
                rtt.count > 0 ? rtt.sum / rtt.count : 0 );
    }

    close( sock );

    exit( exit_val );
}
