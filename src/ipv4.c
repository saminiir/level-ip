#include "arp.h"
#include "ipv4.h"
#include "icmpv4.h"
#include "netdev.h"

void ipv4_incoming(struct netdev *netdev, struct eth_hdr *hdr)
{
    struct iphdr *iphdr = (struct iphdr *) hdr->payload;

    if (iphdr->version != IPV4) {
        perror("Datagram version was not IPv4\n");
        return;
    }

    /* Convert fields from network byte order (Big Endian) to host network order */
    iphdr->len = ntohs(iphdr->len);
    iphdr->id = ntohs(iphdr->id);
    iphdr->flags = ntohs(iphdr->flags);
    iphdr->csum = ntohs(iphdr->csum);
    iphdr->saddr = ntohl(iphdr->saddr);
    iphdr->daddr = ntohl(iphdr->daddr);

    if (iphdr->ihl < 5) {
        perror("IPv4 header length must be at least 5\n");
        return; 
    }

    if (iphdr->ttl == 0) {
        //TODO: Send ICMP error
        perror("Time to live of datagram reached 0\n");
        return;
    }

    // TODO: Check fragmentation, possibly reassemble

    switch (iphdr->proto) {
    case ICMPV4:
        icmpv4_incoming(netdev, hdr);
        break;
    default:
        perror("Unknown IP header proto\n");
        return;
    }
}

void ipv4_outgoing(struct netdev *netdev, struct eth_hdr *hdr)
{
    struct iphdr *iphdr = (struct iphdr *)hdr->payload;
    unsigned char *smac;
    uint32_t tmpaddr;

    // Get HW address of the originator
    if ((smac = arp_get_hwaddr(&iphdr->saddr)) == NULL) {
        perror("Should make ARP request\n");
    } else {
        tmpaddr = iphdr->saddr;
        iphdr->daddr = tmpaddr;
        iphdr->saddr = netdev->addr;

        netdev_transmit(netdev, hdr, ETH_P_ARP, iphdr->len, hdr->smac);
    }
}
