#include "ipv4.h"
#include "netdev.h"

void ipv4_incoming(struct netdev *netdev, struct eth_hdr *hdr)
{
    struct iphdr *iphdr = (struct iphdr *) hdr->payload;

    iphdr->tot_len = ntohs(iphdr->tot_len);
    iphdr->id = ntohs(iphdr->id);
    iphdr->flags = ntohs(iphdr->flags);
    iphdr->check = ntohs(iphdr->check);
    iphdr->saddr = ntohl(iphdr->saddr);
    iphdr->daddr = ntohl(iphdr->daddr);
    printf("%d\n", iphdr->tot_len);
}
