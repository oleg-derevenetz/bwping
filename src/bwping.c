#include "../include/features.h"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/time.h>
#include <sys/types.h>
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

const size_t   MAX_IPV4_HDR_SIZE       = 60;
const uint32_t CALIBRATION_CYCLES      = 100,
               PKT_BURST_PRECISION     = 1000,
               BUF_SIZE_RESERVE_FACTOR = 10;

int64_t min_rtt, max_rtt, average_rtt;
char   *prog_name;

static void get_time(struct timespec *ts)
{
#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_REALTIME)
#if defined(CLOCK_HIGHRES)
    const clockid_t id = CLOCK_HIGHRES;
#elif defined(CLOCK_MONOTONIC_RAW)
    const clockid_t id = CLOCK_MONOTONIC_RAW;
#elif defined(CLOCK_MONOTONIC)
    const clockid_t id = CLOCK_MONOTONIC;
#else
    const clockid_t id = CLOCK_REALTIME;
#endif /* CLOCK_XXX */

    if (clock_gettime(id, ts) < 0) {
        fprintf(stderr, "%s: clock_gettime() failed: %s\n", prog_name, strerror(errno));

        ts->tv_sec  = 0;
        ts->tv_nsec = 0;
    }
#else
    struct timeval tv;

    if (gettimeofday(&tv, NULL) < 0) {
        fprintf(stderr, "%s: gettimeofday() failed: %s\n", prog_name, strerror(errno));

        ts->tv_sec  = 0;
        ts->tv_nsec = 0;
    } else {
        ts->tv_sec  = tv.tv_sec;
        ts->tv_nsec = tv.tv_usec * 1000;
    }
#endif /* HAVE_CLOCK_GETTIME */
}

static int64_t ts_sub(struct timespec *ts1, struct timespec *ts2)
{
    return ((int64_t)ts1->tv_sec - (int64_t)ts2->tv_sec) * 1000000 + (ts1->tv_nsec - ts2->tv_nsec) / 1000;
}

static uint16_t cksum(void *packet, size_t pkt_size)
{
    uint16_t buf[IP_MAXPACKET];

    memset(buf, 0,      sizeof(buf));
    memcpy(buf, packet, pkt_size);

    uint32_t sum = 0;

    for (size_t i = 0; i < pkt_size / 2 + pkt_size % 2; i++) {
        sum += buf[i];
    }

    sum  = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}

static int64_t calibrate_timer(void)
{
    int64_t sum = 0;

    for (uint32_t i = 0; i < CALIBRATION_CYCLES; i++) {
        struct timespec begin, end;

        int n = -1;

        while (n < 0) {
            get_time(&begin);

            struct timeval timeout;

            timeout.tv_sec  = 0;
            timeout.tv_usec = 10;

            n = select(0, NULL, NULL, NULL, &timeout);
        }

        get_time(&end);

        sum += ts_sub(&end, &begin);
    }

    return sum / CALIBRATION_CYCLES;
}

static void send_ping4(int sock, struct addrinfo *to_ai, size_t pkt_size, uint16_t ident, bool first_in_burst, uint32_t *transmitted_number, uint64_t *transmitted_volume)
{
    char packet[IP_MAXPACKET];

    struct icmp icmp4;

    memset(&icmp4, 0, sizeof(icmp4));

    icmp4.icmp_type  = ICMP_ECHO;
    icmp4.icmp_code  = 0;
    icmp4.icmp_cksum = 0;
    icmp4.icmp_id    = ident;
    icmp4.icmp_seq   = htons(*transmitted_number);

    memcpy(packet, &icmp4, sizeof(icmp4));

    struct timespec pkt_time;

    if (first_in_burst) {
        struct timespec now;

        get_time(&now);

        pkt_time.tv_sec  = now.tv_sec;
        pkt_time.tv_nsec = now.tv_nsec;
    } else {
        memset(&pkt_time, 0, sizeof(pkt_time));
    }

    memcpy(&packet[sizeof(icmp4)], &pkt_time, sizeof(pkt_time));

    icmp4.icmp_cksum = cksum(packet, pkt_size);

    memcpy(&packet[offsetof(struct icmp, icmp_cksum)], &icmp4.icmp_cksum, sizeof(icmp4.icmp_cksum));

    ssize_t res = sendto(sock, packet, pkt_size, 0, to_ai->ai_addr, to_ai->ai_addrlen);

    if (res < 0) {
        fprintf(stderr, "%s: sendto() failed: %s\n", prog_name, strerror(errno));
    } else if (res != (ssize_t)pkt_size) {
        fprintf(stderr, "%s: partial write: packet size: %zu, sent: %zd\n", prog_name, pkt_size, res);
    }

    (*transmitted_number)++;
    (*transmitted_volume) += pkt_size;
}

static void send_ping6(int sock, struct addrinfo *to_ai, size_t pkt_size, uint16_t ident, bool first_in_burst, uint32_t *transmitted_number, uint64_t *transmitted_volume)
{
    char packet[IP_MAXPACKET];

    struct icmp6_hdr icmp6;

    memset(&icmp6, 0, sizeof(icmp6));

    icmp6.icmp6_type  = ICMP6_ECHO_REQUEST;
    icmp6.icmp6_code  = 0;
    icmp6.icmp6_cksum = 0;
    icmp6.icmp6_id    = ident;
    icmp6.icmp6_seq   = htons(*transmitted_number);

    memcpy(packet, &icmp6, sizeof(icmp6));

    struct timespec pkt_time;

    if (first_in_burst) {
        struct timespec now;

        get_time(&now);

        pkt_time.tv_sec  = now.tv_sec;
        pkt_time.tv_nsec = now.tv_nsec;
    } else {
        memset(&pkt_time, 0, sizeof(pkt_time));
    }

    memcpy(&packet[sizeof(icmp6)], &pkt_time, sizeof(pkt_time));

    ssize_t res = sendto(sock, packet, pkt_size, 0, to_ai->ai_addr, to_ai->ai_addrlen);

    if (res < 0) {
        fprintf(stderr, "%s: sendto() failed: %s\n", prog_name, strerror(errno));
    } else if (res != (ssize_t)pkt_size) {
        fprintf(stderr, "%s: partial write: packet size: %zu, sent: %zd\n", prog_name, pkt_size, res);
    }

    (*transmitted_number)++;
    (*transmitted_volume) += pkt_size;
}

static bool recv_ping4(int sock, uint16_t ident, uint32_t *received_number, uint64_t *received_volume)
{
    char packet[IP_MAXPACKET];

    struct iovec iov;

    memset(&iov, 0, sizeof(iov));

    iov.iov_base = packet;
    iov.iov_len  = sizeof(packet);

    struct sockaddr_in from4;
    struct msghdr      msg;

    memset(&msg, 0, sizeof(msg));

    msg.msg_name    = (caddr_t)&from4;
    msg.msg_namelen = sizeof(from4);
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;

    ssize_t res = recvmsg(sock, &msg, MSG_DONTWAIT);

    struct ip ip4;

    if (res >= (ssize_t)sizeof(ip4)) {
        memcpy(&ip4, packet, sizeof(ip4));

        size_t hdr_len = ip4.ip_hl << 2;

        struct icmp icmp4;

        if (res >= (ssize_t)(hdr_len + sizeof(icmp4))) {
            memcpy(&icmp4, &packet[hdr_len], sizeof(icmp4));

            if (icmp4.icmp_type == ICMP_ECHOREPLY &&
                icmp4.icmp_id   == ident) {
                (*received_number)++;
                (*received_volume) += res - hdr_len;

                struct timespec pkt_time;

                if (res >= (ssize_t)(hdr_len + sizeof(icmp4) + sizeof(pkt_time))) {
                    memcpy(&pkt_time, &packet[hdr_len + sizeof(icmp4)], sizeof(pkt_time));

                    if (pkt_time.tv_sec != 0 || pkt_time.tv_nsec != 0) {
                        struct timespec now;

                        get_time(&now);

                        int64_t rtt = ts_sub(&now, &pkt_time) / 1000;

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
    char packet[IP_MAXPACKET];

    struct iovec iov;

    memset(&iov, 0, sizeof(iov));

    iov.iov_base = packet;
    iov.iov_len  = sizeof(packet);

    struct sockaddr_in6 from6;
    struct msghdr       msg;

    memset(&msg, 0, sizeof(msg));

    msg.msg_name    = (caddr_t)&from6;
    msg.msg_namelen = sizeof(from6);
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;

    ssize_t res = recvmsg(sock, &msg, MSG_DONTWAIT);

    struct icmp6_hdr icmp6;

    if (res >= (ssize_t)sizeof(icmp6)) {
        memcpy(&icmp6, packet, sizeof(icmp6));

        if (icmp6.icmp6_type == ICMP6_ECHO_REPLY &&
            icmp6.icmp6_id   == ident) {
            (*received_number)++;
            (*received_volume) += res;

            struct timespec pkt_time;

            if (res >= (ssize_t)(sizeof(icmp6) + sizeof(pkt_time))) {
                memcpy(&pkt_time, &packet[sizeof(icmp6)], sizeof(pkt_time));

                if (pkt_time.tv_sec != 0 || pkt_time.tv_nsec != 0) {
                    struct timespec now;

                    get_time(&now);

                    int64_t rtt = ts_sub(&now, &pkt_time) / 1000;

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

static bool resolve_name(bool ipv4_mode, char *name, struct addrinfo **addr_info)
{
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));

    hints.ai_flags    = AI_CANONNAME;
    hints.ai_socktype = SOCK_RAW;

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

int main(int argc, char **argv)
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

                if (*ep || ep == optarg || reporting_period < 0) {
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
        fprintf(stderr, "Usage: %s [-4 | -6] [-u buf_size] [-r reporting_period] [-T tos(v4) | traf_class(v6)] [-B bind_addr] -b kbps -s pkt_size -v volume target\n", prog_name);

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
                exit_val = EX_SOFTWARE;
            }
        }

        if (exit_val == EX_OK) {
            struct addrinfo *to_ai;

            if (resolve_name(ipv4_mode, target, &to_ai)) {
                uint16_t ident = getpid() & 0xFFFF;

                char addr_buf[ipv4_mode ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN];

                if (getnameinfo(to_ai->ai_addr, to_ai->ai_addrlen, addr_buf, sizeof(addr_buf), NULL, 0, NI_NUMERICHOST) != 0) {
                    addr_buf[0] = '?';
                    addr_buf[1] = 0;
                }

                printf("Target: %s (%s), transfer speed: %" PRIu32 " kbps, packet size: %zu bytes, traffic volume: %" PRIu64 " bytes\n",
                       target, addr_buf, kbps, pkt_size, volume);

                min_rtt     = INT64_MAX;
                max_rtt     = 0;
                average_rtt = 0;

                bool     finish             = false;
                uint32_t transmitted_number = 0,
                         received_number    = 0;
                uint64_t transmitted_volume = 0,
                         received_volume    = 0;

                int64_t interval     = (int64_t)pkt_size * 8000 / kbps,
                        min_interval = calibrate_timer();

                uint32_t pkt_burst;

                if (interval >= min_interval) {
                    pkt_burst = PKT_BURST_PRECISION * 1;
                } else if (interval == 0) {
                    pkt_burst = PKT_BURST_PRECISION * min_interval * kbps / 8000 / pkt_size;
                    interval  = min_interval;
                } else {
                    pkt_burst = PKT_BURST_PRECISION * min_interval / interval;
                    interval  = min_interval;
                }

                if (buf_size == 0) {
                    buf_size = pkt_size * (pkt_burst / PKT_BURST_PRECISION + 1) * BUF_SIZE_RESERVE_FACTOR;
                }

                if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) < 0) {
                    fprintf(stderr, "%s: setsockopt(SO_RCVBUF, %u) failed: %s\n", prog_name, buf_size, strerror(errno));
                }
                if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) < 0) {
                    fprintf(stderr, "%s: setsockopt(SO_SNDBUF, %u) failed: %s\n", prog_name, buf_size, strerror(errno));
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

                struct timespec begin, end, report;

                get_time(&begin);
                get_time(&end);
                get_time(&report);

                uint32_t pkt_burst_error  = 0;
                int64_t  current_interval = interval,
                         interval_error   = 0;

                while (!finish) {
                    struct timespec start;

                    get_time(&start);

                    for (uint32_t i = 0; i < pkt_burst / PKT_BURST_PRECISION + pkt_burst_error / PKT_BURST_PRECISION; i++) {
                        if ((uint64_t)pkt_size * transmitted_number < volume) {
                            if (ipv4_mode) {
                                send_ping4(sock, to_ai, pkt_size, ident, !i, &transmitted_number, &transmitted_volume);
                            } else {
                                send_ping6(sock, to_ai, pkt_size, ident, !i, &transmitted_number, &transmitted_volume);
                            }
                        }
                    }

                    pkt_burst_error  = pkt_burst_error % PKT_BURST_PRECISION;
                    pkt_burst_error += pkt_burst       % PKT_BURST_PRECISION;

                    int64_t select_timeout = current_interval;

                    while (1) {
                        fd_set fds;

                        FD_ZERO(&fds);
                        FD_SET(sock, &fds);

                        struct timeval timeout;

                        timeout.tv_sec  = select_timeout / 1000000;
                        timeout.tv_usec = select_timeout % 1000000;

                        int n = select(sock + 1, &fds, NULL, NULL, &timeout);

                        if (n > 0) {
                            while (ipv4_mode ? recv_ping4(sock, ident, &received_number, &received_volume) :
                                               recv_ping6(sock, ident, &received_number, &received_volume)) {
                                if (received_number >= transmitted_number) {
                                    break;
                                }
                            }
                        }

                        struct timespec now;

                        get_time(&now);

                        if (ts_sub(&now, &start) >= current_interval) {
                            if ((uint64_t)pkt_size * transmitted_number >= volume) {
                                finish = true;
                            } else {
                                interval_error += ts_sub(&now, &start) - current_interval;

                                if (interval_error >= interval / 2) {
                                    current_interval  = interval / 2;
                                    interval_error   -= interval / 2;
                                } else {
                                    current_interval = interval;
                                }
                            }

                            break;
                        } else {
                            select_timeout = current_interval - ts_sub(&now, &start);
                        }
                    }

                    get_time(&end);

                    if (reporting_period != 0 && end.tv_sec - report.tv_sec >= reporting_period) {
                        printf("Periodic: pkts sent/rcvd: %" PRIu32 "/%" PRIu32 ", volume sent/rcvd: %" PRIu64 "/%" PRIu64 " bytes, time: %ld sec, speed: %" PRIu64 " kbps, rtt min/max/average: %" PRId64 "/%" PRId64 "/%" PRId64 " ms\n",
                               transmitted_number, received_number, transmitted_volume, received_volume, (long int)(end.tv_sec - begin.tv_sec),
                               end.tv_sec - begin.tv_sec ? ((received_volume / (end.tv_sec - begin.tv_sec)) * 8) / 1000 : (received_volume * 8) / 1000,
                               min_rtt == INT64_MAX ? 0 : min_rtt, max_rtt, average_rtt);

                        get_time(&report);
                    }
                }

                printf("Total: pkts sent/rcvd: %" PRIu32 "/%" PRIu32 ", volume sent/rcvd: %" PRIu64 "/%" PRIu64 " bytes, time: %ld sec, speed: %" PRIu64 " kbps, rtt min/max/average: %" PRId64 "/%" PRId64 "/%" PRId64 " ms\n",
                       transmitted_number, received_number, transmitted_volume, received_volume, (long int)(end.tv_sec - begin.tv_sec),
                       end.tv_sec - begin.tv_sec ? ((received_volume / (end.tv_sec - begin.tv_sec)) * 8) / 1000 : (received_volume * 8) / 1000,
                       min_rtt == INT64_MAX ? 0 : min_rtt, max_rtt, average_rtt);

                freeaddrinfo(to_ai);
            } else {
                exit_val = EX_SOFTWARE;
            }
        }
    }

    close(sock);

    exit(exit_val);
}
