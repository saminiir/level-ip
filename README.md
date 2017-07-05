# Level-IP [![Build Status](https://travis-ci.org/saminiir/level-ip.svg?branch=master)](https://travis-ci.org/saminiir/level-ip)

Level-IP is a Linux userspace TCP/IP stack, implemented with TUN/TAP devices.

The main goals are to:
* Learn TCP/IP
* Learn Linux systems/network programming
* Learn Linux Socket API

The results of the learning experience will be accompanied by explanatory blog posts:

- Part 1, Ethernet & ARP: http://www.saminiir.com/lets-code-tcp-ip-stack-1-ethernet-arp
- Part 2, IPv4 & ICMPv4: http://www.saminiir.com/lets-code-tcp-ip-stack-2-ipv4-icmpv4
- Part 3, TCP Basics & Handshake: http://www.saminiir.com/lets-code-tcp-ip-stack-3-tcp-handshake/
- Part 4, TCP Data Flow & Socket API: http://www.saminiir.com/lets-code-tcp-ip-stack-4-tcp-data-flow-socket-api/
- Part 5, TCP Retransmission: http://www.saminiir.com/lets-code-tcp-ip-stack-5-tcp-retransmission/

See [Getting Started](Documentation/getting-started.md).

For development documentation, start with [Development](Documentation/development.md).

# Reference works

* Linux kernel TCP/IP stack, [source code](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/net/ipv4)
* picoTCP, [source code](https://github.com/tass-belgium/picotcp)
* Xiaochen Wang's TCP/IP stack, [source code](https://github.com/chobits/tapip)

# License

See [LICENSE.md](LICENSE.md) (MIT)
