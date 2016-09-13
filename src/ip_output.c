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

int ip_queue_xmit(struct sock *sk, struct sk_buff *skb)
{
    /* struct rtable *rt; */
    /* struct iphdr *ihdr; */

    /* rt = route_lookup(sock->saddr, sock->daddr); */

    /* if (!rt) { */
    /*     // Raise error */
    /* } */

    /* skb_dst_set(skb, &rt->dst); */

    /* skb_push(skb, IP_HDR_LEN); */

    /* ihdr = ip_hdr(skb); */

    /* ihdr->version = IPV4; */
    /* ihdr->ihl = 0x05; */
    /* ihdr->tos = 0; */
    /* ihdr->len = htons(skb->len); */
    /* ihdr->id = htons(555); */
    /* ihdr->flags = 0; */
    /* ihdr->frag_offset = 0; */
    /* ihdr->ttl = 64; */
    /* ihdr->proto = IP_TCP; */
    /* ihdr->saddr = htonl(sock->saddr); */
    /* ihdr->daddr = sock->daddr; */
    /* ihdr->csum = 0; */
    
    /* ip_send_check(ihdr); */
    
    /* return ip_output(skb, rt->dst.dev); */

    return 0;
}

int ip_output(struct sk_buff *skb)
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

    /* struct iphdr */
    /* uint32_t tmpaddr; */
    /* uint16_t csum; */
    /* uint8_t len = iphdr->len; */

    /* /\* Just swap the source and destination IP addresses, */
    /*  * don't bother with ARP lookup just now */
    /*  *\/ */
    /* tmpaddr = iphdr->saddr; */
    /* iphdr->daddr = tmpaddr; */
    /* iphdr->saddr = netdev->addr; */

    /* /\* */
    /*  * Switch back the necessary fields to Network Byte Order */
    /*  *\/ */
    /* iphdr->len = htons(iphdr->len); */

    /* /\* Calculate and set datagram checksum *\/ */
    /* iphdr->csum = 0; */
    /* csum = checksum(iphdr, iphdr->ihl * 4, 0); */
    /* iphdr->csum = csum; */

    return dst_neigh_output(skb);
}
