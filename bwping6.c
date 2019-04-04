#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define __STDC_FORMAT_MACROS

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
#include <strings.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <arpa/inet.h>

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

#include <netdb.h>

#define CALIBRATE_RETRIES  50
#define IP6_MAXPACKET      65536
#define IP6_PADDRBUF       512
#define DEF_MIN_RTT        0xFFFFFFFF
#define PKTBURST_PRECISION 1000

struct tv32 {
    uint32_t tv32_sec;
    uint32_t tv32_usec;
};

int64_t min_rtt, max_rtt, average_rtt;

static int64_t tvsub(struct timeval *t1, struct timeval *t2)
{
    if (t1->tv_usec > t2->tv_usec) {
        return (int64_t)(t1->tv_sec - t2->tv_sec)     * 1000000 + (t1->tv_usec           - t2->tv_usec);
    } else {
        return (int64_t)(t1->tv_sec - t2->tv_sec - 1) * 1000000 + (t1->tv_usec + 1000000 - t2->tv_usec);
    }
}

static int64_t calibrate_timer(void)
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

static void send_ping(int sock, struct sockaddr_in6 *to6, size_t pktsize, uint16_t ident, bool first_in_burst, uint32_t *transmitted_number)
{
    size_t            size;
    ssize_t           res;
    unsigned char     packet[IP6_MAXPACKET] __attribute__((aligned(4)));
    struct icmp6_hdr *icmp6;
    struct timeval    now;
    struct tv32       tv32;

    icmp6 = (struct icmp6_hdr *)packet;

    bzero(icmp6, sizeof(struct icmp6_hdr));

    icmp6->icmp6_type  = ICMP6_ECHO_REQUEST;
    icmp6->icmp6_code  = 0;
    icmp6->icmp6_cksum = 0;
    icmp6->icmp6_seq   = htons(*transmitted_number);
    icmp6->icmp6_id    = ident;

    gettimeofday(&now, NULL);

    if (first_in_burst) {
        tv32.tv32_sec  = htonl(now.tv_sec);
        tv32.tv32_usec = htonl(now.tv_usec);
    } else {
        bzero(&tv32, sizeof(tv32));
    }

    bcopy(&tv32, &packet[sizeof(struct icmp6_hdr)], sizeof(tv32));

    size = pktsize - sizeof(struct ip6_hdr);

    res = sendto(sock, packet, size, 0, (struct sockaddr *)to6, sizeof(*to6));

    if (res == -1 || res != (ssize_t)size) {
        if (res == -1) {
            perror("bwping6: sendto() failed");
        } else {
            fprintf(stderr, "bwping6: partial write: packet size: %zu, sent: %zd\n", size, res);
        }
    }

    (*transmitted_number)++;
}

static bool recv_ping(int sock, uint16_t ident, uint32_t *received_number, uint64_t *received_volume)
{
    ssize_t             res;
    int64_t             rtt;
    unsigned char       packet[IP6_MAXPACKET] __attribute__((aligned(4)));
    struct sockaddr_in6 from6;
    struct iovec        iov;
    struct msghdr       msg;
    struct icmp6_hdr   *icmp6;
    struct timeval      now, pkttime;
    struct tv32         tv32;

    bzero(&iov, sizeof(iov));

    iov.iov_base = packet;
    iov.iov_len  = IP6_MAXPACKET;

    bzero(&msg, sizeof(msg));

    msg.msg_name    = (caddr_t)&from6;
    msg.msg_namelen = sizeof(from6);
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;

    gettimeofday(&now, NULL);

    res = recvmsg(sock, &msg, MSG_DONTWAIT);

    if (res > 0) {
        icmp6 = (struct icmp6_hdr *)packet;

        if (icmp6->icmp6_type == ICMP6_ECHO_REPLY) {
            if (icmp6->icmp6_id == ident) {
                (*received_number)++;
                (*received_volume) += res + sizeof(struct ip6_hdr);

                if (res - sizeof(struct icmp6_hdr) >= sizeof(tv32)) {
                    bcopy(&packet[sizeof(struct icmp6_hdr)], &tv32, sizeof(tv32));

                    pkttime.tv_sec  = ntohl(tv32.tv32_sec);
                    pkttime.tv_usec = ntohl(tv32.tv32_usec);

                    if (pkttime.tv_sec != 0 || pkttime.tv_usec != 0) {
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

int main(int argc, char **argv)
{
    bool                finish;
    int                 sock, exitval, ch, res, n;
    unsigned int        bufsize;
    size_t              pktsize;
    uint16_t            ident;
    int32_t             rperiod;
    uint32_t            kbps, tclass, transmitted_number, received_number, pktburst, pktburst_error, i;
    int64_t             min_interval, interval, current_interval, interval_error;
    uint64_t            volume, received_volume;
    char               *ep,
                       *bind_addr,
                       *target,
                        p_addr[IP6_PADDRBUF];
    fd_set              fds;
    struct sockaddr_in6 bind_to6, to6;
    struct addrinfo     hints,
                       *res_info;
    struct timeval      begin, end, report, start, now, seltimeout;

    sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

    if (sock == -1) {
        perror("bwping6: socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6) failed");

        exit(EX_OSERR);
    } else {
        if (setuid(getuid()) == -1) {
            perror("bwping6: setuid(getuid()) failed");

            exit(EX_OSERR);
        } else {
            pktsize   = 0;
            bufsize   = 0;
            rperiod   = 0;
            kbps      = 0;
            tclass    = 0;
            volume    = 0;
            bind_addr = NULL;

            exitval = EX_OK;

            while ((ch = getopt(argc, argv, "B:T:b:r:s:u:v:")) != -1) {
                switch (ch) {
                    case 'B':
                        bind_addr = optarg;

                        break;
                    case 'T':
                        tclass = strtoul(optarg, &ep, 0);

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
                if (pktsize < sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + sizeof(struct tv32) || pktsize > IP6_MAXPACKET) {
                    fprintf(stderr, "bwping6: invalid packet size, should be between %zu and %zu\n", sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + sizeof(struct tv32), (size_t)IP6_MAXPACKET);
                    exitval = EX_USAGE;
                } else {
                    if (bind_addr != NULL) {
                        bzero(&hints, sizeof(hints));

                        hints.ai_flags    = AI_CANONNAME;
                        hints.ai_family   = AF_INET6;
                        hints.ai_socktype = SOCK_RAW;
                        hints.ai_protocol = IPPROTO_ICMPV6;

                        res = getaddrinfo(bind_addr, NULL, &hints, &res_info);

                        if (res != 0) {
                            fprintf(stderr, "bwping6: cannot resolve %s: %s\n", bind_addr, gai_strerror(res));
                            exitval = EX_SOFTWARE;
                        } else if (res_info->ai_addr == NULL || res_info->ai_addrlen != sizeof(bind_to6)) {
                            freeaddrinfo(res_info);

                            fprintf(stderr, "bwping6: getaddrinfo() returned an illegal address\n");
                            exitval = EX_SOFTWARE;
                        } else {
                            bcopy(res_info->ai_addr, &bind_to6, sizeof(bind_to6));

                            freeaddrinfo(res_info);
                        }

                        if (exitval == EX_OK) {
                            if (bind(sock, (struct sockaddr *)&bind_to6, sizeof(bind_to6)) < 0) {
                                perror("bwping6: bind() failed");
                                exitval = EX_OSERR;
                            }
                        }
                    }

                    if (exitval == EX_OK) {
                        target = argv[optind];

                        bzero(&hints, sizeof(hints));

                        hints.ai_flags    = AI_CANONNAME;
                        hints.ai_family   = AF_INET6;
                        hints.ai_socktype = SOCK_RAW;
                        hints.ai_protocol = IPPROTO_ICMPV6;

                        res = getaddrinfo(target, NULL, &hints, &res_info);

                        if (res != 0) {
                            fprintf(stderr, "bwping6: cannot resolve %s: %s\n", target, gai_strerror(res));
                            exitval = EX_SOFTWARE;
                        } else if (res_info->ai_addr == NULL || res_info->ai_addrlen != sizeof(to6)) {
                            freeaddrinfo(res_info);

                            fprintf(stderr, "bwping6: getaddrinfo() returned an illegal address\n");
                            exitval = EX_SOFTWARE;
                        } else {
                            bcopy(res_info->ai_addr, &to6, sizeof(to6));

                            freeaddrinfo(res_info);
                        }

                        if (exitval == EX_OK) {
                            ident = getpid() & 0xFFFF;

                            bzero(&p_addr, sizeof(p_addr));

                            if (inet_ntop(AF_INET6, &(to6.sin6_addr), p_addr, sizeof(p_addr)) == NULL) {
                                strncpy(p_addr, "?", sizeof(p_addr) - 1);
                            }

                            printf("Target: %s (%s), transfer speed: %" PRIu32 " kbps, packet size: %zu bytes, traffic volume: %" PRIu64 " bytes\n",
                                   target, p_addr, kbps, pktsize, volume);

                            min_rtt     = DEF_MIN_RTT;
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

                            if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)) == -1) {
                                fprintf(stderr, "bwping6: setsockopt(SO_RCVBUF, %u) failed: %s\n", bufsize, strerror(errno));
                            }
                            if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) == -1) {
                                fprintf(stderr, "bwping6: setsockopt(SO_SNDBUF, %u) failed: %s\n", bufsize, strerror(errno));
                            }

#ifdef IPV6_TCLASS
                            if (setsockopt(sock, IPPROTO_IPV6, IPV6_TCLASS, &tclass, sizeof(tclass)) == -1) {
                                fprintf(stderr, "bwping6: setsockopt(IPV6_TCLASS, %" PRIu32 ") failed: %s\n", tclass, strerror(errno));
                            }
#endif

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
                                        send_ping(sock, &to6, pktsize, ident, !i, &transmitted_number);
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

                                    gettimeofday(&now, NULL);

                                    if (n > 0) {
                                        while (recv_ping(sock, ident, &received_number, &received_volume)) {
                                            if (received_number >= transmitted_number) {
                                                break;
                                            }
                                        }
                                    }
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
                                           min_rtt == DEF_MIN_RTT ? 0 : min_rtt, max_rtt, average_rtt);

                                    gettimeofday(&report, NULL);
                                }
                            }

                            printf("Total: pkts sent/rcvd: %" PRIu32 "/%" PRIu32 ", volume rcvd: %" PRIu64 " bytes, time: %ld sec, speed: %" PRIu64 " kbps, rtt min/max/average: %" PRId64 "/%" PRId64 "/%" PRId64 " ms\n",
                                   transmitted_number, received_number, received_volume, (long int)(end.tv_sec - begin.tv_sec),
                                   end.tv_sec - begin.tv_sec ? ((received_volume / (end.tv_sec - begin.tv_sec)) * 8) / 1000 : (received_volume * 8) / 1000,
                                   min_rtt == DEF_MIN_RTT ? 0 : min_rtt, max_rtt, average_rtt);
                        }
                    }
                }
            } else {
                fprintf(stderr, "Usage: bwping6 [-u bufsize] [-r reporting_period] [-T tclass] [-B bind_addr] -b kbps -s pktsize -v volume target\n");
            }

            close(sock);

            exit(exitval);
        }
    }
}
