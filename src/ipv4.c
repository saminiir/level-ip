#include "ipv4.h"
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

}
