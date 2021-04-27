#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/socket.h>

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sysexits.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <libgen.h>

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

#if defined(ENABLE_MMSG)
#if defined(HAVE_SENDMMSG) || defined(HAVE_RECVMMSG)
#define MAX_MMSG_VLEN 64
#endif /* HAVE_SENDMMSG || HAVE_RECVMMSG */
#endif /* ENABLE_MMSG */

static const size_t   MAX_IPV4_HDR_SIZE  = 60;
static const uint32_t CALIBRATION_CYCLES = 100;
static const uint64_t AVERAGE_RTT_SCALE  = 1000000,
                      PKT_BURST_SCALE    = 1000;

static char *prog_name;

static void get_time(struct timespec *ts)
{
#if defined(CLOCK_HIGHRES)
    const clockid_t id = CLOCK_HIGHRES; /* Solaris */
#elif defined(CLOCK_MONOTONIC_RAW)
    const clockid_t id = CLOCK_MONOTONIC_RAW; /* Linux */
#elif defined(CLOCK_MONOTONIC)
    const clockid_t id = CLOCK_MONOTONIC;
#else
    const clockid_t id = CLOCK_REALTIME;
#endif

    if (clock_gettime(id, ts) < 0) {
        fprintf(stderr, "%s: clock_gettime() failed: %s\n", prog_name, strerror(errno));

        ts->tv_sec  = 0;
        ts->tv_nsec = 0;
    }
}

static int64_t int64_sub(int64_t i1, int64_t i2)
{
    if (i2 < 0) {
        if (i1 > INT64_MAX + i2) {
            return INT64_MAX;
        }
    } else {
        if (i1 < INT64_MIN + i2) {
            return INT64_MIN;
        }
    }

    return i1 - i2;
}

static int64_t ts_sub(const struct timespec *ts1, const struct timespec *ts2)
{
    int64_t sec_diff = int64_sub(ts1->tv_sec, ts2->tv_sec);

    if (sec_diff > INT32_MAX) {
        sec_diff = INT32_MAX;
    }
    if (sec_diff < INT32_MIN) {
        sec_diff = INT32_MIN;
    }

    int64_t nsec_diff = int64_sub(ts1->tv_nsec, ts2->tv_nsec);

    if (nsec_diff > INT32_MAX) {
        nsec_diff = INT32_MAX;
    }
    if (nsec_diff < INT32_MIN) {
        nsec_diff = INT32_MIN;
    }

    return sec_diff * 1000000 + nsec_diff / 1000;
}

static uint16_t cksum(const char *data, size_t size)
{
    uint32_t sum = 0;

    for (size_t i = 0; i < size; i = i + 2) {
        uint16_t u16 = 0;

        if (i < size - 1) {
            memcpy(&u16, &data[i], 2);
        } else {
            memcpy(&u16, &data[i], 1);
        }

        sum += u16;
    }

    sum  = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}

static int64_t calibrate_timer(void)
{
    uint32_t successful_cycles = 0;
    int64_t  sum               = 0;

    for (uint32_t i = 0; i < CALIBRATION_CYCLES; i++) {
        struct timespec before;

        get_time(&before);

        struct timeval timeout = {.tv_sec = 0, .tv_usec = 10};

        if (select(0, NULL, NULL, NULL, &timeout) < 0) {
            fprintf(stderr, "%s: select() failed: %s\n", prog_name, strerror(errno));
        } else {
            struct timespec after;

            get_time(&after);

            successful_cycles += 1;
            sum               += ts_sub(&after, &before);
        }
    }

    return successful_cycles > 0 ? sum / successful_cycles : 0;
}

static void prepare_ping4(char *packet, size_t pkt_size, uint16_t ident, bool insert_timestamp,
                          uint64_t *transmitted_count, uint64_t *transmitted_volume)
{
    struct icmp icmp4 = {
        .icmp_type  = ICMP_ECHO,
        .icmp_code  = 0,
        .icmp_cksum = 0,
        .icmp_id    = htons(ident),
        .icmp_seq   = htons(*transmitted_count)
    };

    memcpy(packet, &icmp4, sizeof(icmp4));

    if (insert_timestamp) {
        struct timespec pkt_time;

        get_time(&pkt_time);

        memcpy(&packet[sizeof(icmp4)], &pkt_time, sizeof(pkt_time));

        /* Optimization: it is assumed that packet was zeroed before calling this function */
        icmp4.icmp_cksum = cksum(packet, sizeof(icmp4) + sizeof(pkt_time));
    } else {
        /* Optimization: it is assumed that packet was zeroed before calling this function */
        icmp4.icmp_cksum = cksum(packet, sizeof(icmp4));
    }

    memcpy(&packet[offsetof(struct icmp, icmp_cksum)], &icmp4.icmp_cksum, sizeof(icmp4.icmp_cksum));

    *transmitted_count  += 1;
    *transmitted_volume += pkt_size;
}

static void prepare_ping6(char *packet, size_t pkt_size, uint16_t ident, bool insert_timestamp,
                          uint64_t *transmitted_count, uint64_t *transmitted_volume)
{
    struct icmp6_hdr icmp6 = {
        .icmp6_type  = ICMP6_ECHO_REQUEST,
        .icmp6_code  = 0,
        .icmp6_cksum = 0,
        .icmp6_id    = htons(ident),
        .icmp6_seq   = htons(*transmitted_count)
    };

    memcpy(packet, &icmp6, sizeof(icmp6));

    if (insert_timestamp) {
        struct timespec pkt_time;

        get_time(&pkt_time);

        memcpy(&packet[sizeof(icmp6)], &pkt_time, sizeof(pkt_time));
    }

    *transmitted_count  += 1;
    *transmitted_volume += pkt_size;
}

#if defined(ENABLE_MMSG) && defined(HAVE_SENDMMSG)

static void sendmmsg_ping(bool ipv4_mode, int sock, const struct addrinfo *to_ai, size_t pkt_size, uint16_t ident,
                          uint64_t pkt_count, uint64_t *transmitted_count, uint64_t *transmitted_volume)
{
    for (uint64_t i = 0; i < pkt_count; i = i + MAX_MMSG_VLEN) {
        static char packets[MAX_MMSG_VLEN][IP_MAXPACKET];

        struct iovec   iov[MAX_MMSG_VLEN];
        struct mmsghdr msg[MAX_MMSG_VLEN];

        unsigned int vlen = pkt_count - i > MAX_MMSG_VLEN ? MAX_MMSG_VLEN : pkt_count - i;

        for (unsigned int j = 0; j < vlen; j++) {
            memset(packets[j], 0, pkt_size);

            if (ipv4_mode) {
                prepare_ping4(packets[j], pkt_size, ident, i == 0 && j == 0, transmitted_count, transmitted_volume);
            } else {
                prepare_ping6(packets[j], pkt_size, ident, i == 0 && j == 0, transmitted_count, transmitted_volume);
            }

            memset(&iov[j], 0, sizeof(iov[j]));

            iov[j].iov_base = packets[j];
            iov[j].iov_len  = pkt_size;

            memset(&msg[j], 0, sizeof(msg[j]));

            msg[j].msg_hdr.msg_name    = to_ai->ai_addr;
            msg[j].msg_hdr.msg_namelen = to_ai->ai_addrlen;
            msg[j].msg_hdr.msg_iov     = &iov[j];
            msg[j].msg_hdr.msg_iovlen  = 1;
        }

        int res = sendmmsg(sock, msg, vlen, 0);

        if (res < 0) {
            fprintf(stderr, "%s: sendmmsg() failed: %s\n", prog_name, strerror(errno));
        } else if ((unsigned int)res != vlen) {
            fprintf(stderr, "%s: sendmmsg() packets to send: %u, sent: %d\n", prog_name, vlen, res);
        }
    }
}

#else /* ENABLE_MMSG && HAVE_SENDMMSG */

static void send_ping(bool ipv4_mode, int sock, const struct addrinfo *to_ai, size_t pkt_size, uint16_t ident,
                      bool insert_timestamp, uint64_t *transmitted_count, uint64_t *transmitted_volume)
{
    static char packet[IP_MAXPACKET];

    memset(packet, 0, pkt_size);

    if (ipv4_mode) {
        prepare_ping4(packet, pkt_size, ident, insert_timestamp, transmitted_count, transmitted_volume);
    } else {
        prepare_ping6(packet, pkt_size, ident, insert_timestamp, transmitted_count, transmitted_volume);
    }

    ssize_t res = sendto(sock, packet, pkt_size, 0, to_ai->ai_addr, to_ai->ai_addrlen);

    if (res < 0) {
        fprintf(stderr, "%s: sendto() failed: %s\n", prog_name, strerror(errno));
    } else if ((size_t)res != pkt_size) {
        fprintf(stderr, "%s: sendto() packet size: %zu, sent: %zd\n", prog_name, pkt_size, res);
    }
}

#endif /* ENABLE_MMSG && HAVE_SENDMMSG */

static void process_ping4(const char *packet, ssize_t pkt_size, uint16_t ident, uint64_t *received_count,
                          uint64_t *received_volume, uint64_t *min_rtt, uint64_t *max_rtt, uint64_t *average_rtt)
{
    struct ip ip4;

    if (pkt_size >= (ssize_t)sizeof(ip4)) {
        memcpy(&ip4, packet, sizeof(ip4));

        if (ip4.ip_p == IPPROTO_ICMP && (ntohs(ip4.ip_off) & 0x1FFF) == 0) {
            size_t hdr_len = ip4.ip_hl << 2;

            struct icmp icmp4;

            if (pkt_size >= (ssize_t)(hdr_len + sizeof(icmp4))) {
                memcpy(&icmp4, &packet[hdr_len], sizeof(icmp4));

                if (icmp4.icmp_type == ICMP_ECHOREPLY && ntohs(icmp4.icmp_id) == ident) {
                    *received_count  += 1;
                    *received_volume += pkt_size - hdr_len;

                    struct timespec pkt_time;

                    if (pkt_size >= (ssize_t)(hdr_len + sizeof(icmp4) + sizeof(pkt_time))) {
                        memcpy(&pkt_time, &packet[hdr_len + sizeof(icmp4)], sizeof(pkt_time));

                        if (pkt_time.tv_sec != 0 || pkt_time.tv_nsec != 0) {
                            struct timespec now;

                            get_time(&now);

                            int64_t rtt = ts_sub(&now, &pkt_time) / 1000;

                            if (rtt >= 0) {
                                if (*min_rtt > (uint64_t)rtt) {
                                    *min_rtt = rtt;
                                }
                                if (*max_rtt < (uint64_t)rtt) {
                                    *max_rtt = rtt;
                                }
                                if (*received_count > 0) {
                                    *average_rtt = (*average_rtt * (*received_count - 1) + rtt * AVERAGE_RTT_SCALE) / *received_count;
                                }
                            } else {
                                fprintf(stderr, "%s: packet has an invalid timestamp\n", prog_name);
                            }
                        }
                    }
                }
            }
        }
    }
}

static void process_ping6(const char *packet, ssize_t pkt_size, uint16_t ident, uint64_t *received_count,
                          uint64_t *received_volume, uint64_t *min_rtt, uint64_t *max_rtt, uint64_t *average_rtt)
{
    struct icmp6_hdr icmp6;

    if (pkt_size >= (ssize_t)sizeof(icmp6)) {
        memcpy(&icmp6, packet, sizeof(icmp6));

        if (icmp6.icmp6_type == ICMP6_ECHO_REPLY && ntohs(icmp6.icmp6_id) == ident) {
            *received_count  += 1;
            *received_volume += pkt_size;

            struct timespec pkt_time;

            if (pkt_size >= (ssize_t)(sizeof(icmp6) + sizeof(pkt_time))) {
                memcpy(&pkt_time, &packet[sizeof(icmp6)], sizeof(pkt_time));

                if (pkt_time.tv_sec != 0 || pkt_time.tv_nsec != 0) {
                    struct timespec now;

                    get_time(&now);

                    int64_t rtt = ts_sub(&now, &pkt_time) / 1000;

                    if (rtt >= 0) {
                        if (*min_rtt > (uint64_t)rtt) {
                            *min_rtt = rtt;
                        }
                        if (*max_rtt < (uint64_t)rtt) {
                            *max_rtt = rtt;
                        }
                        if (*received_count > 0) {
                            *average_rtt = (*average_rtt * (*received_count - 1) + rtt * AVERAGE_RTT_SCALE) / *received_count;
                        }
                    } else {
                        fprintf(stderr, "%s: packet has an invalid timestamp\n", prog_name);
                    }
                }
            }
        }
    }
}

#if defined(ENABLE_MMSG) && defined(HAVE_RECVMMSG)

static bool recvmmsg_ping(bool ipv4_mode, int sock, uint16_t ident, uint64_t *received_count, uint64_t *received_volume,
                          uint64_t *min_rtt, uint64_t *max_rtt, uint64_t *average_rtt)
{
    static char packets[MAX_MMSG_VLEN][IP_MAXPACKET];

    struct iovec   iov[MAX_MMSG_VLEN] = {{.iov_len = 0}};
    struct mmsghdr msg[MAX_MMSG_VLEN] = {{.msg_len = 0}};

    for (unsigned int i = 0; i < MAX_MMSG_VLEN; i++) {
        iov[i].iov_base = packets[i];
        iov[i].iov_len  = sizeof(packets[i]);

        msg[i].msg_hdr.msg_iov    = &iov[i];
        msg[i].msg_hdr.msg_iovlen = 1;
    }

    int res = recvmmsg(sock, msg, MAX_MMSG_VLEN, MSG_DONTWAIT, NULL);

    if (res < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        fprintf(stderr, "%s: recvmmsg() failed: %s\n", prog_name, strerror(errno));

        return false;
    } else if (res > 0) {
        if (ipv4_mode) {
            for (int i = 0; i < res; i++) {
                process_ping4(packets[i], msg[i].msg_len, ident, received_count, received_volume, min_rtt, max_rtt, average_rtt);
            }
        } else {
            for (int i = 0; i < res; i++) {
                process_ping6(packets[i], msg[i].msg_len, ident, received_count, received_volume, min_rtt, max_rtt, average_rtt);
            }
        }

        return true;
    } else {
        return false;
    }
}

#else /* ENABLE_MMSG && HAVE_RECVMMSG */

static bool recv_ping(bool ipv4_mode, int sock, uint16_t ident, uint64_t *received_count, uint64_t *received_volume,
                      uint64_t *min_rtt, uint64_t *max_rtt, uint64_t *average_rtt)
{
    static char packet[IP_MAXPACKET];

    struct iovec  iov = {.iov_base = packet, .iov_len    = sizeof(packet)};
    struct msghdr msg = {.msg_iov  = &iov,   .msg_iovlen = 1};

    ssize_t res = recvmsg(sock, &msg, MSG_DONTWAIT);

    if (res < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        fprintf(stderr, "%s: recvmsg() failed: %s\n", prog_name, strerror(errno));

        return false;
    } else if (res > 0) {
        if (ipv4_mode) {
            process_ping4(packet, res, ident, received_count, received_volume, min_rtt, max_rtt, average_rtt);
        } else {
            process_ping6(packet, res, ident, received_count, received_volume, min_rtt, max_rtt, average_rtt);
        }

        return true;
    } else {
        return false;
    }
}

#endif /* ENABLE_MMSG && HAVE_RECVMMSG */

static bool resolve_name(bool ipv4_mode, const char *name, struct addrinfo **addr_info)
{
    struct addrinfo hints = {.ai_flags = AI_CANONNAME, .ai_socktype = SOCK_RAW};

    if (ipv4_mode) {
        hints.ai_family   = AF_INET;
        hints.ai_protocol = IPPROTO_ICMP;
    } else {
        hints.ai_family   = AF_INET6;
        hints.ai_protocol = IPPROTO_ICMPV6;
    }

    int res = getaddrinfo(name, NULL, &hints, addr_info);

    if (res != 0) {
        fprintf(stderr, "%s: cannot resolve %s: %s\n", prog_name, name, gai_strerror(res));

        return false;
    } else {
        return true;
    }
}

int main(int argc, char *argv[])
{
    prog_name = basename(argv[0]);

    bool ipv4_mode = (strcmp(prog_name, "bwping") == 0);
    int  exit_val  = EX_OK;

    unsigned int buf_size          = 0,
                 tos_or_traf_class = 0;
    size_t       pkt_size          = 0;
    int32_t      reporting_period  = 0;
    uint32_t     kbps              = 0;
    uint64_t     volume            = 0;
    char        *bind_addr         = NULL,
                *target            = NULL;

    int ch;

    while ((ch = getopt(argc, argv, "46B:T:b:r:s:u:v:")) != -1) {
        char *ep;

        switch (ch) {
            case '4':
                ipv4_mode = true;

                break;
            case '6':
                ipv4_mode = false;

                break;
            case 'B':
                bind_addr = optarg;

                break;
            case 'T':
                tos_or_traf_class = strtoul(optarg, &ep, 0);

                if (*ep || ep == optarg) {
                    exit_val = EX_USAGE;
                }

                break;
            case 'b':
                kbps = strtoul(optarg, &ep, 0);

                if (*ep || ep == optarg) {
                    exit_val = EX_USAGE;
                }

                break;
            case 'r':
                reporting_period = strtol(optarg, &ep, 0);

                if (*ep || ep == optarg) {
                    exit_val = EX_USAGE;
                }

                break;
            case 's':
                pkt_size = strtoul(optarg, &ep, 0);

                if (*ep || ep == optarg) {
                    exit_val = EX_USAGE;
                }

                break;
            case 'u':
                buf_size = strtoul(optarg, &ep, 0);

                if (*ep || ep == optarg) {
                    exit_val = EX_USAGE;
                }

                break;
            case 'v':
                volume = strtoull(optarg, &ep, 0);

                if (*ep || ep == optarg) {
                    exit_val = EX_USAGE;
                }

                break;
            default:
                exit_val = EX_USAGE;
        }
    }

    if (argc - optind == 1) {
        target = argv[optind];
    }

    if (pkt_size == 0 || kbps == 0 || volume == 0 || target == NULL) {
        exit_val = EX_USAGE;
    }

    if (exit_val != EX_OK) {
#if defined(PACKAGE_STRING)
        fprintf(stderr, "%s is part of the %s package\n", prog_name, PACKAGE_STRING);
#endif
        fprintf(stderr, "Usage: %s [-4 | -6] [-u buf_size] [-r reporting_period] [-T tos(v4) | traf_class(v6)] [-B bind_addr]"
                        " -b kbps -s pkt_size -v volume target\n", prog_name);

        exit(exit_val);
    }

    if (ipv4_mode) {
        if (pkt_size < sizeof(struct icmp) + sizeof(struct timespec) || pkt_size > IP_MAXPACKET - MAX_IPV4_HDR_SIZE) {
            fprintf(stderr, "%s: invalid packet size, should be between %zu and %zu\n", prog_name,
                                                                                        sizeof(struct icmp) + sizeof(struct timespec),
                                                                                        (size_t)IP_MAXPACKET - MAX_IPV4_HDR_SIZE);

            exit(EX_USAGE);
        }
    } else {
        if (pkt_size < sizeof(struct icmp6_hdr) + sizeof(struct timespec) || pkt_size > IP_MAXPACKET) {
            fprintf(stderr, "%s: invalid packet size, should be between %zu and %zu\n", prog_name,
                                                                                        sizeof(struct icmp6_hdr) + sizeof(struct timespec),
                                                                                        (size_t)IP_MAXPACKET);

            exit(EX_USAGE);
        }
    }

    if (reporting_period < 0) {
        fprintf(stderr, "%s: invalid reporting period, should be non-negative\n", prog_name);

        exit(EX_USAGE);
    }

    int sock;

    if (ipv4_mode) {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

        if (sock < 0) {
            fprintf(stderr, "%s: socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) failed: %s\n", prog_name, strerror(errno));

            exit(EX_OSERR);
        }
    } else {
        sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

        if (sock < 0) {
            fprintf(stderr, "%s: socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6) failed: %s\n", prog_name, strerror(errno));

            exit(EX_OSERR);
        }
    }

    if (setuid(getuid()) < 0) {
        fprintf(stderr, "%s: setuid(getuid()) failed: %s\n", prog_name, strerror(errno));

        exit_val = EX_OSERR;
    } else {
        if (bind_addr != NULL) {
            struct addrinfo *bind_ai;

            if (resolve_name(ipv4_mode, bind_addr, &bind_ai)) {
                if (bind(sock, bind_ai->ai_addr, bind_ai->ai_addrlen) < 0) {
                    fprintf(stderr, "%s: bind() failed: %s\n", prog_name, strerror(errno));

                    exit_val = EX_OSERR;
                }

                freeaddrinfo(bind_ai);
            } else {
                exit_val = EX_NOHOST;
            }
        }

        if (exit_val == EX_OK) {
            struct addrinfo *to_ai;

            if (resolve_name(ipv4_mode, target, &to_ai)) {
                char addr_buf[ipv4_mode ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN];

                if (getnameinfo(to_ai->ai_addr, to_ai->ai_addrlen, addr_buf, sizeof(addr_buf), NULL, 0, NI_NUMERICHOST) != 0) {
                    addr_buf[0] = '?';
                    addr_buf[1] = 0;
                }

                printf("Target: %s (%s), transfer speed: %" PRIu32 " kbps, packet size: %zu bytes, traffic volume: %" PRIu64 " bytes\n",
                       target, addr_buf, kbps, pkt_size, volume);

                if (buf_size > 0) {
                    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) < 0) {
                        fprintf(stderr, "%s: setsockopt(SO_RCVBUF, %u) failed: %s\n", prog_name, buf_size, strerror(errno));
                    }
                    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) < 0) {
                        fprintf(stderr, "%s: setsockopt(SO_SNDBUF, %u) failed: %s\n", prog_name, buf_size, strerror(errno));
                    }
                }

                if (ipv4_mode) {
                    if (setsockopt(sock, IPPROTO_IP, IP_TOS, &tos_or_traf_class, sizeof(tos_or_traf_class)) < 0) {
                        fprintf(stderr, "%s: setsockopt(IP_TOS, %u) failed: %s\n", prog_name, tos_or_traf_class, strerror(errno));
                    }
                } else {
                    if (setsockopt(sock, IPPROTO_IPV6, IPV6_TCLASS, &tos_or_traf_class, sizeof(tos_or_traf_class)) < 0) {
                        fprintf(stderr, "%s: setsockopt(IPV6_TCLASS, %u) failed: %s\n", prog_name, tos_or_traf_class, strerror(errno));
                    }
                }

                uint16_t ident = getpid() & 0xFFFF;

#if defined(ENABLE_BPF) && defined(HAVE_LINUX_FILTER_H) && defined(SO_ATTACH_FILTER)
                struct sock_filter filter4[] = {
                    /* (00) */ {0x30, 0, 0, 0x00000009},     /* ldb  [9]                         - IP Protocol */
                    /* (01) */ {0x15, 0, 8, IPPROTO_ICMP},   /* jeq  $IPPROTO_ICMP   jt 2  jf 10 - IP Protocol is ICMP */
                    /* (02) */ {0x28, 0, 0, 0x00000006},     /* ldh  [6]                         - IP Fragment Offset */
                    /* (03) */ {0x45, 6, 0, 0x00001FFF},     /* jset #0x1FFF         jt 10 jf 4  - IP Fragment Offset is zero */
                    /* (04) */ {0xB1, 0, 0, 0x00000000},     /* ldxb 4*([0]&0xF)                 - Load IHL*4 to X */
                    /* (05) */ {0x50, 0, 0, 0x00000000},     /* ldb  [x]                         - ICMP Type */
                    /* (06) */ {0x15, 0, 3, ICMP_ECHOREPLY}, /* jeq  $ICMP_ECHOREPLY jt 7  jf 10 - ICMP Type is Echo Reply */
                    /* (07) */ {0x48, 0, 0, 0x00000004},     /* ldh  [x + 4]                     - ICMP Id */
                    /* (08) */ {0x15, 0, 1, ident},          /* jeq  $ident          jt 9  jf 10 - ICMP Id is equal to ident */
                    /* (09) */ {0x06, 0, 0, 0x00040000},     /* ret  #0x40000                    - Accept packet */
                    /* (10) */ {0x06, 0, 0, 0x00000000}      /* ret  #0x0                        - Discard packet */
                };
                struct sock_filter filter6[] = {
                    /* (00) */ {0x30, 0, 0, 0x00000000},       /* ldb [0]                         - ICMPv6 Type */
                    /* (01) */ {0x15, 0, 3, ICMP6_ECHO_REPLY}, /* jeq $ICMP6_ECHO_REPLY jt 2 jf 5 - ICMPv6 Type is Echo Reply */
                    /* (02) */ {0x28, 0, 0, 0x00000004},       /* ldh [4]                         - ICMPv6 Id */
                    /* (03) */ {0x15, 0, 1, ident},            /* jeq $ident            jt 4 jf 5 - ICMPv6 Id is equal to ident */
                    /* (04) */ {0x06, 0, 0, 0x00040000},       /* ret #0x40000                    - Accept packet */
                    /* (05) */ {0x06, 0, 0, 0x00000000}        /* ret #0x0                        - Discard packet */
                };

                struct sock_fprog bpf;

                if (ipv4_mode) {
                    bpf.len    = sizeof(filter4) / sizeof(filter4[0]);
                    bpf.filter = filter4;
                } else {
                    bpf.len    = sizeof(filter6) / sizeof(filter6[0]);
                    bpf.filter = filter6;
                }

                if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
                    fprintf(stderr, "%s: setsockopt(SO_ATTACH_FILTER) failed: %s\n", prog_name, strerror(errno));
                }
#endif /* ENABLE_BPF && HAVE_LINUX_FILTER_H && SO_ATTACH_FILTER */

                int64_t interval     = (int64_t)pkt_size * 8000 / kbps,
                        min_interval = calibrate_timer() * 2; /* Leave space for interval_error adjustments */

                uint64_t pkt_burst;

                if (interval >= min_interval) {
                    pkt_burst = PKT_BURST_SCALE * 1;
                } else if (interval == 0) {
                    pkt_burst = PKT_BURST_SCALE * min_interval * kbps / 8000 / pkt_size;
                    interval  = min_interval;
                } else {
                    pkt_burst = PKT_BURST_SCALE * min_interval / interval;
                    interval  = min_interval;
                }

                bool     finish             = false;
                int64_t  current_interval   = interval,
                         interval_error     = 0;
                uint64_t min_rtt            = UINT64_MAX,
                         max_rtt            = 0,
                         average_rtt        = 0,
                         transmitted_count  = 0,
                         received_count     = 0,
                         transmitted_volume = 0,
                         received_volume    = 0,
                         total_count        = volume % pkt_size == 0 ? volume / pkt_size :
                                                                       volume / pkt_size + 1,
                         pkt_burst_error    = 0;

                struct timespec start, end, report;

                get_time(&start);
                get_time(&end);
                get_time(&report);

                while (!finish) {
                    struct timespec interval_start;

                    get_time(&interval_start);

                    uint64_t pkt_count = total_count - transmitted_count > pkt_burst / PKT_BURST_SCALE + pkt_burst_error / PKT_BURST_SCALE ?
                                                                           pkt_burst / PKT_BURST_SCALE + pkt_burst_error / PKT_BURST_SCALE :
                                                                           total_count - transmitted_count;

#if defined(ENABLE_MMSG) && defined(HAVE_SENDMMSG)
                    sendmmsg_ping(ipv4_mode, sock, to_ai, pkt_size, ident, pkt_count, &transmitted_count, &transmitted_volume);
#else
                    for (uint64_t i = 0; i < pkt_count; i++) {
                        send_ping(ipv4_mode, sock, to_ai, pkt_size, ident, i == 0, &transmitted_count, &transmitted_volume);
                    }
#endif

                    pkt_burst_error  = pkt_burst_error % PKT_BURST_SCALE;
                    pkt_burst_error += pkt_burst       % PKT_BURST_SCALE;

                    int64_t select_timeout = current_interval;

                    while (1) {
                        fd_set fds;

                        FD_ZERO(&fds);
                        FD_SET(sock, &fds);

                        struct timeval timeout = {.tv_sec = select_timeout / 1000000, .tv_usec = select_timeout % 1000000};

                        int n = select(sock + 1, &fds, NULL, NULL, &timeout);

                        if (n < 0) {
                            fprintf(stderr, "%s: select() failed: %s\n", prog_name, strerror(errno));
                        } else if (n > 0) {
#if defined(ENABLE_MMSG) && defined(HAVE_RECVMMSG)
                            while (recvmmsg_ping(ipv4_mode, sock, ident, &received_count, &received_volume, &min_rtt, &max_rtt, &average_rtt)) {
#else
                            while (recv_ping(ipv4_mode, sock, ident, &received_count, &received_volume, &min_rtt, &max_rtt, &average_rtt)) {
#endif
                                if (received_count >= transmitted_count) {
                                    break;
                                }
                            }
                        }

                        struct timespec now;

                        get_time(&now);

                        if (ts_sub(&now, &interval_start) >= current_interval) {
                            if (transmitted_volume >= volume) {
                                finish = true;
                            } else {
                                interval_error += ts_sub(&now, &interval_start) - current_interval;

                                if (interval_error >= interval / 2) {
                                    current_interval  = interval / 2;
                                    interval_error   -= interval / 2;
                                } else {
                                    current_interval = interval;
                                }
                            }

                            break;
                        } else {
                            select_timeout = current_interval - ts_sub(&now, &interval_start);
                        }
                    }

                    get_time(&end);

                    if (reporting_period > 0 && end.tv_sec - report.tv_sec >= reporting_period) {
                        printf("Periodic: pkts sent/rcvd: %" PRIu64 "/%" PRIu64 ", volume sent/rcvd: %" PRIu64 "/%" PRIu64 " bytes, time: %ld sec,"
                               " speed: %" PRIu64 " kbps, rtt min/max/average: %" PRIu64 "/%" PRIu64 "/%" PRIu64 " ms\n",
                               transmitted_count, received_count, transmitted_volume, received_volume, (long int)(end.tv_sec - start.tv_sec),
                               end.tv_sec - start.tv_sec > 0 ? received_volume / (end.tv_sec - start.tv_sec) * 8 / 1000 : received_volume * 8 / 1000,
                               min_rtt == UINT64_MAX ? 0 : min_rtt, max_rtt, average_rtt / AVERAGE_RTT_SCALE);

                        get_time(&report);
                    }
                }

                printf("Total: pkts sent/rcvd: %" PRIu64 "/%" PRIu64 ", volume sent/rcvd: %" PRIu64 "/%" PRIu64 " bytes, time: %ld sec,"
                       " speed: %" PRIu64 " kbps, rtt min/max/average: %" PRIu64 "/%" PRIu64 "/%" PRIu64 " ms\n",
                       transmitted_count, received_count, transmitted_volume, received_volume, (long int)(end.tv_sec - start.tv_sec),
                       end.tv_sec - start.tv_sec > 0 ? received_volume / (end.tv_sec - start.tv_sec) * 8 / 1000 : received_volume * 8 / 1000,
                       min_rtt == UINT64_MAX ? 0 : min_rtt, max_rtt, average_rtt / AVERAGE_RTT_SCALE);

                freeaddrinfo(to_ai);
            } else {
                exit_val = EX_NOHOST;
            }
        }
    }

    close(sock);

    exit(exit_val);
}
