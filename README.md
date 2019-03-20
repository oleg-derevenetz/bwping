## NAME

bwping  and  bwping6  are tools to measure bandwidth and response times
between two hosts using Internet Control Message Protocol  (ICMP)  echo
request/echo  reply  mechanism.  bwping deals with IPv4 networks, while
bwping6 - with IPv6 networks.

## SYNOPSIS

```
bwping [ -u bufsize ] [ -r reporting_period ] [ -T tos ]
       [ -B bind_addr] -b kbps -s pktsize -v volume target
```

```
bwping6 [ -u bufsize ] [ -r reporting_period ] [ -T tclass ]
        [ -B bind_addr] -b kbps -s pktsize -v volume target
```

## OPTIONS

```
-u bufsize
```

Sets  the  send/receive  buffer  size  in  bytes.  Default  value  will  be
automatically   calculated  based  on  transfer speed, packet size and host
timer accuracy.

```
-r reporting_period
```

Sets   the   interval  time in seconds between periodic bandwidth, RTT, and
loss  reports.  If  zero,  there  will be no periodic reports (default).

```
-T tos (bwping only)
```

Sets the TOS value of outgoing ip packets. Default value is zero.

```
-T tclass (bwping6 only)
```

Sets the IPv6 Traffic Class value of outgoing ip packets.  Default value is
zero.

```
-B bind_addr
```

Sets   the  source  address  of outgoing ip packets. By default the address
of the outgoing interface will be used.

```
-b kbps
```

Sets the transfer speed in kilobits per second.

```
-s pktsize
```

Sets the packet size in bytes.

```
-v volume
```

Sets the volume to transfer in bytes.

## AUTHORS

Oleg Derevenetz <oleg.derevenetz@gmail.com>

## BUGS

[![Build Status](https://travis-ci.org/oleg-derevenetz/bwping.svg?branch=master)](https://travis-ci.org/oleg-derevenetz/bwping)

## RESTRICTIONS

This  utility  uses  raw  sockets  to  deal  with  ICMP  messages,  so root
privileges are required to run it.

Although  bwping  and  bwping6 does not require any special software on the
remote  host  (only the ability to respond on ICMP echo request  messages),
there  are  some  special requirements to network infrastructure, local and
remote host performance:

1.  There  should  be  no ICMP echo request/reply filtering on the network.
This includes QoS mechanisms (which often affects ICMP) at any point in the
testing path;

1.  Local  host  should  have  enough  CPU  resources  to  send  ICMP  echo
request   messages   with   given   rate,  and  remote  host should quickly
respond  on  these  messages  and should have no  ICMP  bandwidth  limiting
turned on.

If   some   of   these   requirements  are  not satisfied, then measurement
results  will  be  inadequate  or fail completely. In general, for  testing
bandwidth   where   QoS   is   implemented,  always  test with traffic that
matches the QoS class to be tested.
