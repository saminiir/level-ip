#include "arp.h"
#include "ip.h"
#include "icmpv4.h"
#include "tcp.h"
#include "netdev.h"
#include "utils.h"

void ipv4_incoming(struct netdev *netdev, struct eth_hdr *hdr)
{
    struct iphdr *iphdr = (struct iphdr *) hdr->payload;
    uint16_t csum = -1;

    if (iphdr->version != IPV4) {
        perror("Datagram version was not IPv4\n");
        return;
    }

    if (iphdr->ihl < 5) {
        perror("IPv4 header length must be at least 5\n");
        return; 
    }

    if (iphdr->ttl == 0) {
        //TODO: Send ICMP error
        perror("Time to live of datagram reached 0\n");
        return;
    }

    csum = checksum(iphdr, iphdr->ihl * 4, 0);

    if (csum != 0) {
        // Invalid checksum, drop packet handling
        return;
    }

    // TODO: Check fragmentation, possibly reassemble
    iphdr->len = ntohs(iphdr->len);

    switch (iphdr->proto) {
    case ICMPV4:
        icmpv4_incoming(netdev, hdr);
        break;
    case IP_TCP:
        tcp_in(netdev, hdr);
        break;
    default:
        perror("Unknown IP header proto\n");
        return;
    }
}
