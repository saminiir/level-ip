# Development

Level-IP is at a very alpha stage, has many hardcoded values and is not really intuitive to develop on. 

This document aims to provide information on the current features, roadmap and overall development routine. 

# General

Level-IP is a TCP/IP stack that is run as a single daemon process on your Linux host. Networking is achieved by configuring your Linux host to forward packets to/from Level-IP.

To interface applications against Level-IP, a wrapper library for standard libc calls is provided. This can then be used against existing binaries such as `curl` and `ip` to redirect communications to Level-IP.

# Building

Standard `make` stuff.

`make debug` adds debugging symbols.

The socket API wrapper is located under `tools` and is likewise `make`able.

# Setup

`lvl-ip` uses a Linux TAP device to communicate to the outside world. In short, the tap device is initialized in the host Linux' networking stack, and `lvl-ip` can then read the L2 frames:

```
$ sudo mknod /dev/net/tap c 10 200
```

In essence, `lvl-ip` operates as a host inside the tap device's subnet. Therefore, in order to communicate with other hosts, the tap device needs to be set in a forwarding mode.

An example from my (Arch) Linux machine, where `wlp2s0` is my outgoing interface, and `tap0` is the tap device for `lvl-ip`:

```
$ sysctl -w net.ipv4.ip_forward=1
$ iptables -I INPUT --source 10.0.0.0/24 -j ACCEPT
$ iptables -t nat -I POSTROUTING --out-interface wlp2s0 -j MASQUERADE
$ iptables -I FORWARD --in-interface wlp2s0 --out-interface tap0 -j ACCEPT
$ iptables -I FORWARD --in-interface tap0 --out-interface wlp2s0 -j ACCEPT
```

Now, packets coming from `lvl-ip` (e.g. 10.0.0.4) should be NATed by the host Linux interfaces and traverse the FORWARD chain correctly to host's outgoing gateway.

See http://www.netfilter.org/documentation/HOWTO/packet-filtering-HOWTO-9.html for more info.

# Usage

Level-IP is run as a daemon process:

```
$ sudo ./lvl-ip
```

Then, existing binaries and their socket API calls can be redirected to level-ip with:

```
$ cd tools
$ sudo ./level-ip curl google.com
```

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
