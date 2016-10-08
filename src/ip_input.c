#include "syshead.h"
#include "skbuff.h"
#include "arp.h"
#include "ip.h"
#include "icmpv4.h"
#include "tcp.h"
#include "utils.h"

static void ip_init_pkt(struct iphdr *ih)
{
    ih->saddr = ntohl(ih->saddr);
    ih->daddr = ntohl(ih->daddr);
    ih->len = ntohs(ih->len);
    ih->id = ntohs(ih->id);
}

int ip_rcv(struct sk_buff *skb)
{
    struct iphdr *ih = ip_hdr(skb);
    uint16_t csum = -1;

    if (ih->version != IPV4) {
        perror("Datagram version was not IPv4\n");
        return 0;
    }

    if (ih->ihl < 5) {
        perror("IPv4 header length must be at least 5\n");
        return 0;
    }

    if (ih->ttl == 0) {
        //TODO: Send ICMP error
        perror("Time to live of datagram reached 0\n");
        return 0;
    }

    csum = checksum(ih, ih->ihl * 4, 0);

    if (csum != 0) {
        // Invalid checksum, drop packet handling
        return 0;
    }

    // TODO: Check fragmentation, possibly reassemble

    ip_init_pkt(ih);

    switch (ih->proto) {
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
