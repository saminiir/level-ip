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
    printf("%d\n", iphdr->tot_len);
}
