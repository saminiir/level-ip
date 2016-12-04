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
        goto drop_pkt;
    }

    if (ih->ihl < 5) {
        perror("IPv4 header length must be at least 5\n");
        goto drop_pkt;
    }

    if (ih->ttl == 0) {
        //TODO: Send ICMP error
        perror("Time to live of datagram reached 0\n");
        goto drop_pkt;
    }

    csum = checksum(ih, ih->ihl * 4, 0);

    if (csum != 0) {
        // Invalid checksum, drop packet handling
        goto drop_pkt;
    }

    // TODO: Check fragmentation, possibly reassemble

    ip_init_pkt(ih);

    ip_dbg("INPUT", ih);

    switch (ih->proto) {
    case ICMPV4:
        icmpv4_incoming(skb);
        return 0;
    case IP_TCP:
        tcp_in(skb);
        return 0;
    default:
        perror("Unknown IP header proto\n");
        goto drop_pkt;
    }

drop_pkt:
    free_skb(skb);
    return 0;
}
