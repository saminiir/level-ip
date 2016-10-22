# Development

Level-IP is at a very alpha stage, has many hardcoded values and is not really intuitive to develop on. 

This document aims to provide information on the current features, roadmap and overall development routine. 

# Current Features

* One hardcoded interface/netdev (IP 10.0.0.4)
* One hardcoded socket
* Ethernet II frame handling
* ARP request/reply, simple caching
* ICMP pings and replies 
* IPv4 packet handling, checksum
* One hardcoded route table with default netdevice
* TCPv4 Handshake

# Upcoming features

* TCP data transmission
* TCP RFC793 "Segment Arrives"

# Building

Standard `make` stuff.

`make debug` adds debugging symbols.

# Developing

Use `tcpdump` with the IP address you're using, e.g.:

```
$ tcpdump -i any host 10.0.0.4 -n
IP 10.0.0.4.12000 > 10.0.0.5.8000: Flags [S], seq 1525252, win 512, length 0
IP 10.0.0.5.8000 > 10.0.0.4.12000: Flags [S.], seq 1332068674, ack 1525253, win 29200, options [mss 1460], length 0
IP 10.0.0.4.12000 > 10.0.0.5.8000: Flags [.], ack 1, win 512, length 0
```

To trace program code, use gdb. 

In the future, a logging/tracing framework could be introduced, but I have not yet found a satisfactory solution.

# Coding Style

The foremost aim of Level-IP is to be an educational project on networking. Hence, source code readability should be focused on when developing Level-IP.

TODO: Actual style guidelines, so far I have been just winging it.
