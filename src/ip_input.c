#include "syshead.h"
#include "skbuff.h"
#include "arp.h"
#include "ip.h"
#include "icmpv4.h"
#include "tcp.h"
#include "utils.h"

int ip_rcv(struct sk_buff *skb)
{
    struct iphdr *iphdr = ip_hdr(skb);
    uint16_t csum = -1;

    if (iphdr->version != IPV4) {
        perror("Datagram version was not IPv4\n");
        return 0;
    }

    if (iphdr->ihl < 5) {
        perror("IPv4 header length must be at least 5\n");
        return 0;
    }

    if (iphdr->ttl == 0) {
        //TODO: Send ICMP error
        perror("Time to live of datagram reached 0\n");
        return 0;
    }

    csum = checksum(iphdr, iphdr->ihl * 4, 0);

    if (csum != 0) {
        // Invalid checksum, drop packet handling
        return 0;
    }

    // TODO: Check fragmentation, possibly reassemble
    iphdr->len = ntohs(iphdr->len);

    switch (iphdr->proto) {
    case ICMPV4:
        icmpv4_incoming(skb);
        break;
    case IP_TCP:
        tcp_in(skb);
        break;
    default:
        perror("Unknown IP header proto\n");
        return 0;
    }

    return -1;
}
