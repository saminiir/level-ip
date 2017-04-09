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
    struct rtentry *rt;
    struct iphdr *ihdr = ip_hdr(skb);

    rt = route_lookup(ihdr->daddr);

    if (!rt) {
        // Raise error
        // TODO: dest_unreachable
        return -1;
    }

    skb->dev = rt->dev;
    skb->rt = rt;

    skb_push(skb, IP_HDR_LEN);

    ihdr->version = IPV4;
    ihdr->ihl = 0x05;
    ihdr->tos = 0;
    ihdr->len = skb->len;
    ihdr->id = ihdr->id;
    ihdr->flags = 0;
    ihdr->frag_offset = 0;
    ihdr->ttl = 64;
    ihdr->proto = skb->protocol;
    ihdr->saddr = skb->dev->addr;
    ihdr->daddr = sk->daddr;
    ihdr->csum = 0;

    ip_dbg("out", ihdr);

    ihdr->len = htons(ihdr->len);
    ihdr->id = htons(ihdr->id);
    ihdr->daddr = htonl(ihdr->daddr);
    ihdr->saddr = htonl(ihdr->saddr);
    ihdr->csum = htons(ihdr->csum);

    ip_send_check(ihdr);

    return dst_neigh_output(skb);
}
