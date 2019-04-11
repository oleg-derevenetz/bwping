#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../include/features.h"

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sysexits.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#ifdef HAVE_NETINET_ICMP6_H
#include <netinet/icmp6.h>
#endif

#ifdef __CYGWIN__
#include "../include/cygwin.h"
#endif

#include <netdb.h>

#ifdef BUILD_BWPING
const bool         IPV4_MODE          = true;
#else
const bool         IPV4_MODE          = false;
#endif
const uint32_t     CALIBRATE_RETRIES  = 1000,
                   PKTBURST_PRECISION = 1000;
#ifdef BUILD_BWPING
const char * const PROG_NAME          = "bwping";
#else
const char * const PROG_NAME          = "bwping6";
#endif

int64_t min_rtt, max_rtt, average_rtt;

static int64_t tvsub(struct timeval *t1, struct timeval *t2)
{
    if (t1->tv_usec > t2->tv_usec) {
        return (int64_t)(t1->tv_sec - t2->tv_sec)     * 1000000 + (t1->tv_usec           - t2->tv_usec);
    } else {
        return (int64_t)(t1->tv_sec - t2->tv_sec - 1) * 1000000 + (t1->tv_usec + 1000000 - t2->tv_usec);
    }
}

static uint16_t cksum(uint16_t *addr, size_t len)
{
    ssize_t   nleft;
    uint16_t  last;
    uint32_t  sum;
    uint16_t *w;

    nleft = len;
    sum   = 0;
    w     = addr;

    while (nleft > 1) {
        sum   += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        last = 0;

        memcpy(&last, w, nleft);

        sum += last;
    }

    sum  = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}

static int64_t calibrate_timer()
{
    int            n;
    uint32_t       i;
    int64_t        sum;
    struct timeval begin, end, seltimeout;

    sum = 0;

    for (i = 0; i < CALIBRATE_RETRIES; i++) {
        n = -1;

        seltimeout.tv_sec  = 0;
        seltimeout.tv_usec = 10;

        while (n < 0) {
            gettimeofday(&begin, NULL);

            n = select(0, NULL, NULL, NULL, &seltimeout);
        }

        gettimeofday(&end, NULL);

        sum += tvsub(&end, &begin);
    }

    return sum / CALIBRATE_RETRIES;
}

static void send_ping4(int sock, struct sockaddr_in *to4, size_t pktsize, uint16_t ident, bool first_in_burst, uint32_t *transmitted_number)
{
    size_t         size;
    ssize_t        res;
    unsigned char  packet[IP_MAXPACKET] __attribute__((aligned(4)));
    struct icmp   *icmp4;
    struct timeval now, pkttime;

    icmp4 = (struct icmp *)packet;

    memset(icmp4, 0, sizeof(*icmp4));

    icmp4->icmp_type  = ICMP_ECHO;
    icmp4->icmp_code  = 0;
    icmp4->icmp_cksum = 0;
    icmp4->icmp_id    = ident;
    icmp4->icmp_seq   = htons(*transmitted_number);

    if (first_in_burst) {
        gettimeofday(&now, NULL);

        pkttime.tv_sec  = now.tv_sec;
        pkttime.tv_usec = now.tv_usec;
    } else {
        memset(&pkttime, 0, sizeof(pkttime));
    }

    memcpy(&packet[sizeof(struct icmp)], &pkttime, sizeof(pkttime));

    size = pktsize - sizeof(struct ip);

    icmp4->icmp_cksum = cksum((uint16_t *)icmp4, size);

    res = sendto(sock, packet, size, 0, (struct sockaddr *)to4, sizeof(*to4));

    if (res < 0) {
        fprintf(stderr, "%s: sendto() failed: %s\n", PROG_NAME, strerror(errno));
    } else if (res != (ssize_t)size) {
        fprintf(stderr, "%s: partial write: packet size: %zu, sent: %zd\n", PROG_NAME, size, res);
    }

    (*transmitted_number)++;
}

static void send_ping6(int sock, struct sockaddr_in6 *to6, size_t pktsize, uint16_t ident, bool first_in_burst, uint32_t *transmitted_number)
{
    size_t            size;
    ssize_t           res;
    unsigned char     packet[IP_MAXPACKET] __attribute__((aligned(4)));
    struct icmp6_hdr *icmp6;
    struct timeval    now, pkttime;

    icmp6 = (struct icmp6_hdr *)packet;

    memset(icmp6, 0, sizeof(*icmp6));

    icmp6->icmp6_type  = ICMP6_ECHO_REQUEST;
    icmp6->icmp6_code  = 0;
    icmp6->icmp6_cksum = 0;
    icmp6->icmp6_id    = ident;
    icmp6->icmp6_seq   = htons(*transmitted_number);

    if (first_in_burst) {
        gettimeofday(&now, NULL);

        pkttime.tv_sec  = now.tv_sec;
        pkttime.tv_usec = now.tv_usec;
    } else {
        memset(&pkttime, 0, sizeof(pkttime));
    }

    memcpy(&packet[sizeof(struct icmp6_hdr)], &pkttime, sizeof(pkttime));

    size = pktsize - sizeof(struct ip6_hdr);

    res = sendto(sock, packet, size, 0, (struct sockaddr *)to6, sizeof(*to6));

    if (res < 0) {
        fprintf(stderr, "%s: sendto() failed: %s\n", PROG_NAME, strerror(errno));
    } else if (res != (ssize_t)size) {
        fprintf(stderr, "%s: partial write: packet size: %zu, sent: %zd\n", PROG_NAME, size, res);
    }

    (*transmitted_number)++;
}

static bool recv_ping4(int sock, uint16_t ident, uint32_t *received_number, uint64_t *received_volume)
{
    size_t             hlen;
    ssize_t            res;
    int64_t            rtt;
    unsigned char      packet[IP_MAXPACKET] __attribute__((aligned(4)));
    struct sockaddr_in from4;
    struct iovec       iov;
    struct msghdr      msg;
    struct ip         *ip4;
    struct icmp       *icmp4;
    struct timeval     now, pkttime;

    memset(&iov, 0, sizeof(iov));

    iov.iov_base = packet;
    iov.iov_len  = sizeof(packet);

    memset(&msg, 0, sizeof(msg));

    msg.msg_name    = (caddr_t)&from4;
    msg.msg_namelen = sizeof(from4);
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;

    res = recvmsg(sock, &msg, MSG_DONTWAIT);

    if (res > 0) {
        ip4 = (struct ip *)packet;

        hlen = ip4->ip_hl << 2;

        if (res >= (ssize_t)(hlen + sizeof(struct icmp))) {
            icmp4 = (struct icmp *)(packet + hlen);

            if (icmp4->icmp_type == ICMP_ECHOREPLY &&
                icmp4->icmp_id   == ident) {
                (*received_number)++;
                (*received_volume) += res;

                if (res >= (ssize_t)(hlen + sizeof(struct icmp) + sizeof(pkttime))) {
                    memcpy(&pkttime, &packet[hlen + sizeof(struct icmp)], sizeof(pkttime));

                    if (pkttime.tv_sec != 0 || pkttime.tv_usec != 0) {
                        gettimeofday(&now, NULL);

                        rtt = tvsub(&now, &pkttime) / 1000;

                        if (min_rtt > rtt) {
                            min_rtt = rtt;
                        }
                        if (max_rtt < rtt) {
                            max_rtt = rtt;
                        }

                        average_rtt = *received_number ? ((average_rtt * (*received_number - 1)) + rtt) / *received_number : average_rtt;
                    }
                }
            }
        }

        return true;
    } else {
        return false;
    }
}

static bool recv_ping6(int sock, uint16_t ident, uint32_t *received_number, uint64_t *received_volume)
{
    ssize_t             res;
    int64_t             rtt;
    unsigned char       packet[IP_MAXPACKET] __attribute__((aligned(4)));
    struct sockaddr_in6 from6;
    struct iovec        iov;
    struct msghdr       msg;
    struct icmp6_hdr   *icmp6;
    struct timeval      now, pkttime;

    memset(&iov, 0, sizeof(iov));

    iov.iov_base = packet;
    iov.iov_len  = sizeof(packet);

    memset(&msg, 0, sizeof(msg));

    msg.msg_name    = (caddr_t)&from6;
    msg.msg_namelen = sizeof(from6);
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;

    res = recvmsg(sock, &msg, MSG_DONTWAIT);

    if (res > 0) {
        icmp6 = (struct icmp6_hdr *)packet;

        if (icmp6->icmp6_type == ICMP6_ECHO_REPLY &&
            icmp6->icmp6_id   == ident) {
            (*received_number)++;
            (*received_volume) += res + sizeof(struct ip6_hdr);

            if (res >= (ssize_t)(sizeof(struct icmp6_hdr) + sizeof(pkttime))) {
                memcpy(&pkttime, &packet[sizeof(struct icmp6_hdr)], sizeof(pkttime));

                if (pkttime.tv_sec != 0 || pkttime.tv_usec != 0) {
                    gettimeofday(&now, NULL);

                    rtt = tvsub(&now, &pkttime) / 1000;

                    if (min_rtt > rtt) {
                        min_rtt = rtt;
                    }
                    if (max_rtt < rtt) {
                        max_rtt = rtt;
                    }

                    average_rtt = *received_number ? ((average_rtt * (*received_number - 1)) + rtt) / *received_number : average_rtt;
                }
            }
        }

        return true;
    } else {
        return false;
    }
}

static bool resolve_name4(char *name, struct sockaddr_in *addr4)
{
    int              res;
    struct addrinfo  hints;
    struct addrinfo *res_info;

    memset(&hints, 0, sizeof(hints));

    hints.ai_flags    = AI_CANONNAME;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;

    res = getaddrinfo(name, NULL, &hints, &res_info);

    if (res != 0) {
        fprintf(stderr, "%s: cannot resolve %s: %s\n", PROG_NAME, name, gai_strerror(res));

        return false;
    } else if (res_info->ai_addr == NULL || res_info->ai_addrlen != sizeof(*addr4)) {
        freeaddrinfo(res_info);

        fprintf(stderr, "%s: getaddrinfo() returned an illegal address\n", PROG_NAME);

        return false;
    } else {
        memcpy(addr4, res_info->ai_addr, sizeof(*addr4));

        freeaddrinfo(res_info);

        return true;
    }
}

static bool resolve_name6(char *name, struct sockaddr_in6 *addr6)
{
    int              res;
    struct addrinfo  hints;
    struct addrinfo *res_info;

    memset(&hints, 0, sizeof(hints));

    hints.ai_flags    = AI_CANONNAME;
    hints.ai_family   = AF_INET6;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMPV6;

    res = getaddrinfo(name, NULL, &hints, &res_info);

    if (res != 0) {
        fprintf(stderr, "%s: cannot resolve %s: %s\n", PROG_NAME, name, gai_strerror(res));

        return false;
    } else if (res_info->ai_addr == NULL || res_info->ai_addrlen != sizeof(*addr6)) {
        freeaddrinfo(res_info);

        fprintf(stderr, "%s: getaddrinfo() returned an illegal address\n", PROG_NAME);

        return false;
    } else {
        memcpy(addr6, res_info->ai_addr, sizeof(*addr6));

        freeaddrinfo(res_info);

        return true;
    }
}

int main(int argc, char **argv)
{
    bool                finish;
    int                 sock, exitval, ch, n;
    unsigned int        bufsize, tos_or_tclass;
    size_t              pktsize;
    uint16_t            ident;
    int32_t             rperiod;
    uint32_t            kbps, transmitted_number, received_number, pktburst, pktburst_error, i;
    int64_t             min_interval, interval, current_interval, interval_error;
    uint64_t            volume, received_volume;
    char               *ep,
                       *bind_addr,
                       *target;
    char                p_addr4[INET_ADDRSTRLEN],
                        p_addr6[INET6_ADDRSTRLEN];
    fd_set              fds;
    struct sockaddr_in  bind_to4, to4;
    struct sockaddr_in6 bind_to6, to6;
    struct timeval      begin, end, report, start, now, seltimeout;

    if (IPV4_MODE) {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

        if (sock < 0) {
            fprintf(stderr, "%s: socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) failed: %s\n", PROG_NAME, strerror(errno));

            exit(EX_OSERR);
        }
    } else {
        sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

        if (sock < 0) {
            fprintf(stderr, "%s: socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6) failed: %s\n", PROG_NAME, strerror(errno));

            exit(EX_OSERR);
        }
    }

    if (setuid(getuid()) < 0) {
        fprintf(stderr, "%s: setuid(getuid()) failed: %s\n", PROG_NAME, strerror(errno));

        exitval = EX_OSERR;
    } else {
        exitval = EX_OK;

        bufsize       = 0;
        tos_or_tclass = 0;
        pktsize       = 0;
        rperiod       = 0;
        kbps          = 0;
        volume        = 0;
        bind_addr     = NULL;

        while ((ch = getopt(argc, argv, "B:T:b:r:s:u:v:")) != -1) {
            switch (ch) {
                case 'B':
                    bind_addr = optarg;

                    break;
                case 'T':
                    tos_or_tclass = strtoul(optarg, &ep, 0);

                    if (*ep || ep == optarg) {
                        exitval = EX_USAGE;
                    }

                    break;
                case 'b':
                    kbps = strtoul(optarg, &ep, 0);

                    if (*ep || ep == optarg) {
                        exitval = EX_USAGE;
                    }

                    break;
                case 'r':
                    rperiod = strtol(optarg, &ep, 0);

                    if (*ep || ep == optarg || rperiod < 0) {
                        exitval = EX_USAGE;
                    }

                    break;
                case 's':
                    pktsize = strtoul(optarg, &ep, 0);

                    if (*ep || ep == optarg) {
                        exitval = EX_USAGE;
                    }

                    break;
                case 'u':
                    bufsize = strtoul(optarg, &ep, 0);

                    if (*ep || ep == optarg) {
                        exitval = EX_USAGE;
                    }

                    break;
                case 'v':
                    volume = strtoull(optarg, &ep, 0);

                    if (*ep || ep == optarg) {
                        exitval = EX_USAGE;
                    }

                    break;
                default:
                    exitval = EX_USAGE;
            }
        }

        if (pktsize == 0 || kbps == 0 || volume == 0) {
            exitval = EX_USAGE;
        } else if (argc - optind != 1) {
            exitval = EX_USAGE;
        }

        if (exitval == EX_OK) {
            if (IPV4_MODE) {
                if (pktsize < sizeof(struct ip) + sizeof(struct icmp) + sizeof(struct timeval) || pktsize > IP_MAXPACKET) {
                    fprintf(stderr, "%s: invalid packet size, should be between %zu and %zu\n", PROG_NAME,
                                                                                                sizeof(struct ip) + sizeof(struct icmp) + sizeof(struct timeval),
                                                                                                (size_t)IP_MAXPACKET);
                    exitval = EX_USAGE;
                }
            } else {
                if (pktsize < sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + sizeof(struct timeval) || pktsize > IP_MAXPACKET) {
                    fprintf(stderr, "%s: invalid packet size, should be between %zu and %zu\n", PROG_NAME,
                                                                                                sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + sizeof(struct timeval),
                                                                                                (size_t)IP_MAXPACKET);
                    exitval = EX_USAGE;
                }
            }

            if (exitval == EX_OK) {
                if (bind_addr != NULL) {
                    if (IPV4_MODE) {
                        if (resolve_name4(bind_addr, &bind_to4)) {
                            if (bind(sock, (struct sockaddr *)&bind_to4, sizeof(bind_to4)) < 0) {
                                fprintf(stderr, "%s: bind() failed: %s\n", PROG_NAME, strerror(errno));
                                exitval = EX_OSERR;
                            }
                        } else {
                            exitval = EX_SOFTWARE;
                        }
                    } else {
                        if (resolve_name6(bind_addr, &bind_to6)) {
                            if (bind(sock, (struct sockaddr *)&bind_to6, sizeof(bind_to6)) < 0) {
                                fprintf(stderr, "%s: bind() failed: %s\n", PROG_NAME, strerror(errno));
                                exitval = EX_OSERR;
                            }
                        } else {
                            exitval = EX_SOFTWARE;
                        }
                    }
                }

                if (exitval == EX_OK) {
                    target = argv[optind];

                    if (IPV4_MODE ? resolve_name4(target, &to4) :
                                    resolve_name6(target, &to6)) {
                        ident = getpid() & 0xFFFF;

                        if (IPV4_MODE) {
                            memset(&p_addr4, 0, sizeof(p_addr4));

                            if (inet_ntop(AF_INET, &(to4.sin_addr), p_addr4, sizeof(p_addr4)) == NULL) {
                                strncpy(p_addr4, "?", sizeof(p_addr4) - 1); p_addr4[sizeof(p_addr4) - 1] = 0;
                            }

                            printf("Target: %s (%s), transfer speed: %" PRIu32 " kbps, packet size: %zu bytes, traffic volume: %" PRIu64 " bytes\n",
                                   target, p_addr4, kbps, pktsize, volume);
                        } else {
                            memset(&p_addr6, 0, sizeof(p_addr6));

                            if (inet_ntop(AF_INET6, &(to6.sin6_addr), p_addr6, sizeof(p_addr6)) == NULL) {
                                strncpy(p_addr6, "?", sizeof(p_addr6) - 1); p_addr6[sizeof(p_addr6) - 1] = 0;
                            }

                            printf("Target: %s (%s), transfer speed: %" PRIu32 " kbps, packet size: %zu bytes, traffic volume: %" PRIu64 " bytes\n",
                                   target, p_addr6, kbps, pktsize, volume);
                        }

                        min_rtt     = INT64_MAX;
                        max_rtt     = 0;
                        average_rtt = 0;

                        finish             = false;
                        transmitted_number = 0;
                        received_number    = 0;
                        received_volume    = 0;

                        interval = (int64_t)pktsize * 8000 / kbps;

                        min_interval = calibrate_timer() * 2;

                        if (interval >= min_interval) {
                            pktburst = PKTBURST_PRECISION * 1;
                        } else if (interval == 0) {
                            pktburst = PKTBURST_PRECISION * min_interval * kbps / 8000 / pktsize;
                            interval = min_interval;
                        } else {
                            pktburst = PKTBURST_PRECISION * min_interval / interval;
                            interval = min_interval;
                        }

                        if (bufsize == 0) {
                            bufsize = pktsize * (pktburst / PKTBURST_PRECISION + 1) * 2;
                        }

                        if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)) < 0) {
                            fprintf(stderr, "%s: setsockopt(SO_RCVBUF, %u) failed: %s\n", PROG_NAME, bufsize, strerror(errno));
                        }
                        if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0) {
                            fprintf(stderr, "%s: setsockopt(SO_SNDBUF, %u) failed: %s\n", PROG_NAME, bufsize, strerror(errno));
                        }

                        if (IPV4_MODE) {
                            if (setsockopt(sock, IPPROTO_IP, IP_TOS, &tos_or_tclass, sizeof(tos_or_tclass)) < 0) {
                                fprintf(stderr, "%s: setsockopt(IP_TOS, %u) failed: %s\n", PROG_NAME, tos_or_tclass, strerror(errno));
                            }
                        } else {
                            if (setsockopt(sock, IPPROTO_IPV6, IPV6_TCLASS, &tos_or_tclass, sizeof(tos_or_tclass)) < 0) {
                                fprintf(stderr, "%s: setsockopt(IPV6_TCLASS, %u) failed: %s\n", PROG_NAME, tos_or_tclass, strerror(errno));
                            }
                        }

                        gettimeofday(&begin,  NULL);
                        gettimeofday(&end,    NULL);
                        gettimeofday(&report, NULL);

                        current_interval = interval;
                        pktburst_error   = 0;
                        interval_error   = 0;

                        while (!finish) {
                            gettimeofday(&start, NULL);

                            for (i = 0; i < pktburst / PKTBURST_PRECISION + pktburst_error / PKTBURST_PRECISION; i++) {
                                if ((uint64_t)pktsize * transmitted_number < volume) {
                                    if (IPV4_MODE) {
                                        send_ping4(sock, &to4, pktsize, ident, !i, &transmitted_number);
                                    } else {
                                        send_ping6(sock, &to6, pktsize, ident, !i, &transmitted_number);
                                    }
                                }
                            }

                            if (pktburst_error >= PKTBURST_PRECISION) {
                                pktburst_error = pktburst_error % PKTBURST_PRECISION;
                            }

                            pktburst_error = pktburst_error + pktburst % PKTBURST_PRECISION;

                            while (1) {
                                FD_ZERO(&fds);
                                FD_SET(sock, &fds);

                                seltimeout.tv_sec  = current_interval / 1000000;
                                seltimeout.tv_usec = current_interval % 1000000;

                                n = select(sock + 1, &fds, NULL, NULL, &seltimeout);

                                if (n > 0) {
                                    while (IPV4_MODE ? recv_ping4(sock, ident, &received_number, &received_volume) :
                                                       recv_ping6(sock, ident, &received_number, &received_volume)) {
                                        if (received_number >= transmitted_number) {
                                            break;
                                        }
                                    }
                                }

                                gettimeofday(&now, NULL);

                                if (tvsub(&now, &start) >= current_interval) {
                                    if ((uint64_t)pktsize * transmitted_number >= volume) {
                                        finish = true;
                                    } else {
                                        interval_error += tvsub(&now, &start) - current_interval;

                                        if (interval_error >= interval / 2) {
                                            current_interval = interval / 2;
                                            interval_error   = interval_error - interval / 2;
                                        } else {
                                            current_interval = interval;
                                        }
                                    }

                                    break;
                                }
                            }

                            gettimeofday(&end, NULL);

                            if (rperiod != 0 && end.tv_sec - report.tv_sec >= rperiod) {
                                printf("Periodic: pkts sent/rcvd: %" PRIu32 "/%" PRIu32 ", volume rcvd: %" PRIu64 " bytes, time: %ld sec, speed: %" PRIu64 " kbps, rtt min/max/average: %" PRId64 "/%" PRId64 "/%" PRId64 " ms\n",
                                       transmitted_number, received_number, received_volume, (long int)(end.tv_sec - begin.tv_sec),
                                       end.tv_sec - begin.tv_sec ? ((received_volume / (end.tv_sec - begin.tv_sec)) * 8) / 1000 : (received_volume * 8) / 1000,
                                       min_rtt == INT64_MAX ? 0 : min_rtt, max_rtt, average_rtt);

                                gettimeofday(&report, NULL);
                            }
                        }

                        printf("Total: pkts sent/rcvd: %" PRIu32 "/%" PRIu32 ", volume rcvd: %" PRIu64 " bytes, time: %ld sec, speed: %" PRIu64 " kbps, rtt min/max/average: %" PRId64 "/%" PRId64 "/%" PRId64 " ms\n",
                               transmitted_number, received_number, received_volume, (long int)(end.tv_sec - begin.tv_sec),
                               end.tv_sec - begin.tv_sec ? ((received_volume / (end.tv_sec - begin.tv_sec)) * 8) / 1000 : (received_volume * 8) / 1000,
                               min_rtt == INT64_MAX ? 0 : min_rtt, max_rtt, average_rtt);
                    } else {
                        exitval = EX_SOFTWARE;
                    }
                }
            }
        } else {
            if (IPV4_MODE) {
                fprintf(stderr, "Usage: %s [-u bufsize] [-r reporting_period] [-T tos] [-B bind_addr] -b kbps -s pktsize -v volume target\n", PROG_NAME);
            } else {
                fprintf(stderr, "Usage: %s [-u bufsize] [-r reporting_period] [-T tclass] [-B bind_addr] -b kbps -s pktsize -v volume target\n", PROG_NAME);
            }
        }
    }

    close(sock);

    exit(exitval);
}
