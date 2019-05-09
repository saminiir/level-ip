# Getting Started

Level-IP is a TCP/IP stack that is run as a single daemon process on your Linux host. Networking is achieved by configuring your Linux host to forward packets to/from Level-IP.

To interface applications against Level-IP, a wrapper library for standard libc calls is provided. This wrapper can then be used with existing binaries such as `curl`, `surf` and `firefox` to redirect communications to Level-IP.

DISCLAIMER: Level-IP is not a production-ready networking stack, and does not intend to be one. The nature of lower-level networking imposes a great responsiblity to the software and any security vulnerabilities can be disastrous. Hence, do not run Level-IP for extended periods of time, purely because it has bugs (and as all software, will continue to have them).

# Building

Standard `make` stuff.

    make all

This builds `lvl-ip` and the libc wrapper (under `tools/`) and provided example applications (under `apps/`).

# Setup

Level-IP uses a Linux TAP device to communicate to the outside world. In short, the tap device is initialized in the host Linux' networking stack, and `lvl-ip` can then read the L2 frames:

    sudo mknod /dev/net/tap c 10 200
    sudo chmod 0666 /dev/net/tap
    sudo ip tuntap add mode tap tap0
    sudo ip link set dev tap0 up
    sudo ip addr add 10.0.0.5/24 dev tap0

In essence, `lvl-ip` operates as a host inside the tap device's subnet. Therefore, in order to communicate with other hosts, the tap device needs to be set in a forwarding mode:

An example from my (Arch) Linux machine, where `wlp2s0` is my outgoing interface, and `tap0` is the tap device for `lvl-ip`:

    sysctl -w net.ipv4.ip_forward=1
    iptables -I INPUT --source 10.0.0.0/24 -j ACCEPT
    iptables -t nat -I POSTROUTING --out-interface wlp2s0 -j MASQUERADE
    iptables -I FORWARD --in-interface wlp2s0 --out-interface tap0 -j ACCEPT
    iptables -I FORWARD --in-interface tap0 --out-interface wlp2s0 -j ACCEPT

Now, packets coming from `lvl-ip` (10.0.0.4/24 in this case) should be NATed by the host Linux interfaces and traverse the FORWARD chain correctly to the host's outgoing gateway.

See http://www.netfilter.org/documentation/HOWTO/packet-filtering-HOWTO-9.html for more info.

# Usage

When you've built lvl-ip and setup your host stack to forward packets, you can try communicating to the Internet:

    ./lvl-ip

The userspace TCP/IP stack should start. 

Now, first test communications with the provided applications:

    cd tools
    ./level-ip ../apps/curl/curl google.com 80

`./level-ip` is just a bash-script that allows `liblevelip.so` to take precedence over the libc socket API calls. 

The important point is that `./level-ip` aims to be usable against any existing dynamically-linked application. Let's try the _real_ `curl`:

    [saminiir@localhost tools]$ curl google.com
    <HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
    <TITLE>302 Moved</TITLE></HEAD><BODY>
    <H1>302 Moved</H1>
    The document has moved
    <A HREF="http://www.google.fi/?gfe_rd=cr&amp;ei=otEWWbbDGbGr8weExqg4">here</A>.
    </BODY></HTML>

And instead of using the Linux' TCP/IP stack, let's try it with `lvl-ip`:

    [saminiir@localhost tools]$ ./level-ip curl google.com
    <HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
    <TITLE>302 Moved</TITLE></HEAD><BODY>
    <H1>302 Moved</H1>
    The document has moved
    <A HREF="http://www.google.fi/?gfe_rd=cr&amp;ei=3NIWWZGjHqar8wf_kKf4Bg">here</A>.
    </BODY></HTML>

The result is exactly the same. Under the hood, however, `curl` calls the libc socket API but these calls are redirected to `lvl-ip` instead.

Try browsing the Web, with Level-IP doing the packet transfer:

    [saminiir@localhost tools]$ firefox --version
    Mozilla Firefox 47.0.1
    [saminiir@localhost tools]$ ./level-ip firefox google.com

That's it!

# Troubleshooting

Common errors:

## Tun module not loaded/available

`tun` is required to be loaded:

```
$ lsmod | grep tun
tun                    57344  2
```

Try loading it
```
$ modprobe tun
```

Otherwise, consult your distro's documentation on setting it up.
