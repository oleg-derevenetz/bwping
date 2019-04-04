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
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#ifdef __CYGWIN__
#include "cygwin.h"
#endif

#include <netdb.h>

#define CALIBRATE_RETRIES  50
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

static uint16_t cksum(uint16_t *addr, size_t len)
{
    ssize_t   nleft;
    uint32_t  sum;
    uint16_t *w;
    union {
        uint16_t      us;
        unsigned char uc[2];
    } last;

    nleft = len;
    sum   = 0;
    w     = addr;

    while (nleft > 1) {
        sum   += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        last.uc[0] = *(unsigned char *)w;
        last.uc[1] = 0;
        sum       += last.us;
    }

    sum  = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
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

static void send_ping(int sock, struct sockaddr_in *to, size_t pktsize, uint16_t ident, bool first_in_burst, uint32_t *transmitted_number)
{
    size_t         size;
    ssize_t        res;
    unsigned char  packet[IP_MAXPACKET] __attribute__((aligned(4)));
    struct icmp   *icmp;
    struct timeval now;
    struct tv32    tv32;

    icmp = (struct icmp *)packet;

    bzero(icmp, sizeof(struct icmp));

    icmp->icmp_type  = ICMP_ECHO;
    icmp->icmp_code  = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_seq   = htons(*transmitted_number);
    icmp->icmp_id    = ident;

    gettimeofday(&now, NULL);

    if (first_in_burst) {
        tv32.tv32_sec  = htonl(now.tv_sec);
        tv32.tv32_usec = htonl(now.tv_usec);
    } else {
        bzero(&tv32, sizeof(tv32));
    }

    bcopy(&tv32, &packet[ICMP_MINLEN], sizeof(tv32));

    size = pktsize - sizeof(struct ip);

    icmp->icmp_cksum = cksum((uint16_t *)icmp, size);

    res = sendto(sock, packet, size, 0, (struct sockaddr *)to, sizeof(*to));

    if (res == -1 || res != (ssize_t)size) {
        if (res == -1) {
            perror("bwping: sendto() failed");
        } else {
            fprintf(stderr, "bwping: partial write: packet size: %zu, sent: %zd\n", size, res);
        }
    }

    (*transmitted_number)++;
}

static bool recv_ping(int sock, uint16_t ident, uint32_t *received_number, uint64_t *received_volume)
{
    size_t             hlen;
    ssize_t            res;
    int64_t            rtt;
    unsigned char      packet[IP_MAXPACKET] __attribute__((aligned(4)));
    struct sockaddr_in from;
    struct iovec       iov;
    struct msghdr      msg;
    struct ip         *ip;
    struct icmp       *icmp;
    struct timeval     now, pkttime;
    struct tv32        tv32;

    bzero(&iov, sizeof(iov));

    iov.iov_base = packet;
    iov.iov_len  = IP_MAXPACKET;

    bzero(&msg, sizeof(msg));

    msg.msg_name    = (caddr_t)&from;
    msg.msg_namelen = sizeof(from);
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;

    gettimeofday(&now, NULL);

    res = recvmsg(sock, &msg, MSG_DONTWAIT);

    if (res > 0) {
        ip = (struct ip *)packet;

        hlen = ip->ip_hl << 2;

        if (res >= (ssize_t)(hlen + ICMP_MINLEN)) {
            icmp = (struct icmp *)(packet + hlen);

            if (icmp->icmp_type == ICMP_ECHOREPLY) {
                if (icmp->icmp_id == ident) {
                    (*received_number)++;
                    (*received_volume) += res;

                    if (res - hlen - ICMP_MINLEN >= sizeof(tv32)) {
                        bcopy(icmp->icmp_data, &tv32, sizeof(tv32));

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
        }

        return true;
    } else {
        return false;
    }
}

int main(int argc, char **argv)
{
    bool               finish;
    int                sock, exitval, ch, n;
    size_t             pktsize, bufsize;
    uint16_t           ident;
    int32_t            rperiod;
    uint32_t           kbps, tos, transmitted_number, received_number, pktburst, pktburst_error, i;
    int64_t            min_interval, interval, current_interval, interval_error;
    uint64_t           volume, received_volume;
    char              *ep,
                      *bind_addr,
                      *target;
    fd_set             fds;
    struct sockaddr_in bind_to, to;
    struct hostent    *hp;
    struct timeval     begin, end, report, start, now, seltimeout;

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sock == -1) {
        perror("bwping: socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) failed");

        exit(EX_OSERR);
    } else {
        if (setuid(getuid()) == -1) {
            perror("bwping: setuid(getuid()) failed");

            exit(EX_OSERR);
        } else {
            pktsize   = 0;
            bufsize   = 0;
            rperiod   = 0;
            kbps      = 0;
            tos       = 0;
            volume    = 0;
            bind_addr = NULL;

            exitval = EX_OK;

            while ((ch = getopt(argc, argv, "B:T:b:r:s:u:v:")) != -1) {
                switch (ch) {
                    case 'B':
                        bind_addr = optarg;

                        break;
                    case 'T':
                        tos = strtoul(optarg, &ep, 0);

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
                if (pktsize < sizeof(struct ip) + ICMP_MINLEN + sizeof(struct tv32) || pktsize > IP_MAXPACKET) {
                    fprintf(stderr, "bwping: invalid packet size, should be between %zu and %zu\n", sizeof(struct ip) + ICMP_MINLEN + sizeof(struct tv32), (size_t)IP_MAXPACKET);
                    exitval = EX_USAGE;
                } else {
                    if (bind_addr != NULL) {
                        bzero(&bind_to, sizeof(bind_to));

                        bind_to.sin_family = AF_INET;
#ifdef HAVE_SOCKADDR_IN_SIN_LEN
                        bind_to.sin_len    = sizeof(bind_to);
#endif

                        if (inet_aton(bind_addr, &bind_to.sin_addr) == 0) {
                            hp = gethostbyname(bind_addr);

                            if (!hp) {
                                fprintf(stderr, "bwping: cannot resolve %s: %s\n", bind_addr, hstrerror(h_errno));
                                exitval = EX_SOFTWARE;
                            } else if ((size_t)hp->h_length != sizeof(bind_to.sin_addr)) {
                                fprintf(stderr, "bwping: gethostbyname() returned an illegal address\n");
                                exitval = EX_SOFTWARE;
                            } else {
                                bcopy(hp->h_addr_list[0], &bind_to.sin_addr, sizeof(bind_to.sin_addr));
                            }
                        }

                        if (exitval == EX_OK) {
                            if (bind(sock, (struct sockaddr *)&bind_to, sizeof(bind_to)) < 0) {
                                perror("bwping: bind() failed");
                                exitval = EX_OSERR;
                            }
                        }
                    }

                    if (exitval == EX_OK) {
                        target = argv[optind];

                        bzero(&to, sizeof(to));

                        to.sin_family = AF_INET;
#ifdef HAVE_SOCKADDR_IN_SIN_LEN
                        to.sin_len    = sizeof(to);
#endif

                        if (inet_aton(target, &to.sin_addr) == 0) {
                            hp = gethostbyname(target);

                            if (!hp) {
                                fprintf(stderr, "bwping: cannot resolve %s: %s\n", target, hstrerror(h_errno));
                                exitval = EX_SOFTWARE;
                            } else if ((size_t)hp->h_length != sizeof(to.sin_addr)) {
                                fprintf(stderr, "bwping: gethostbyname() returned an illegal address\n");
                                exitval = EX_SOFTWARE;
                            } else {
                                bcopy(hp->h_addr_list[0], &to.sin_addr, sizeof(to.sin_addr));
                            }
                        }

                        if (exitval == EX_OK) {
                            ident = getpid() & 0xFFFF;

                            printf("Target: %s (%s), transfer speed: %" PRIu32 " kbps, packet size: %zu bytes, traffic volume: %" PRIu64 " bytes\n",
                                   target, inet_ntoa(to.sin_addr), kbps, pktsize, volume);

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
                                fprintf(stderr, "bwping: setsockopt(SO_RCVBUF, %zu) failed: %s\n", bufsize, strerror(errno));
                            }
                            if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) == -1) {
                                fprintf(stderr, "bwping: setsockopt(SO_SNDBUF, %zu) failed: %s\n", bufsize, strerror(errno));
                            }

#ifdef IP_TOS
                            if (setsockopt(sock, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) == -1) {
                                fprintf(stderr, "bwping: setsockopt(IP_TOS, %" PRIu32 ") failed: %s\n", tos, strerror(errno));
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
                                        send_ping(sock, &to, pktsize, ident, !i, &transmitted_number);
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
                fprintf(stderr, "Usage: bwping [-u bufsize] [-r reporting_period] [-T tos] [-B bind_addr] -b kbps -s pktsize -v volume target\n");
            }

            close(sock);

            exit(exitval);
        }
    }
}
