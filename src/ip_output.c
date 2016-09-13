#include "syshead.h"
#include "skbuff.h"
#include "utils.h"
#include "ip.h"
#include "dst.h"
#include "route.h"

void ip_send_check(struct iphdr *ihdr)
{
    uint32_t csum = checksum(ihdr, ihdr->ihl * 4, 0);
    ihdr->csum = csum;
}

int ip_output(struct sock *sk, struct sk_buff *skb)
{
    struct rtable *rt;
    struct netdev *netdev;
    struct iphdr *ihdr = ip_hdr(skb);

    rt = route_lookup(ihdr->daddr);

    if (!rt) {
        // Raise error
    }

    skb_dst_set(skb, &rt->dst);
    netdev = rt->dst.dev;
    skb->netdev = netdev;

    skb_push(skb, IP_HDR_LEN);

    ihdr->version = IPV4;
    ihdr->ihl = 0x05;
    ihdr->tos = 0;
    ihdr->len = htons(skb->len);
    ihdr->id = htons(ihdr->id);
    ihdr->flags = 0;
    ihdr->frag_offset = 0;
    ihdr->ttl = 64;
    ihdr->proto = skb->protocol;
    ihdr->saddr = netdev->addr;
    /* ihdr->daddr = sock->daddr; */
    ihdr->csum = 0;
    
    ip_send_check(ihdr);

    return dst_neigh_output(skb);
}
