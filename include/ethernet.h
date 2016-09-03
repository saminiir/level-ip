#ifndef ETHERNET_H_
#define ETHERNET_H_

#include <linux/if_ether.h>
#include "netdev.h"
#include "skbuff.h"
#include "syshead.h"

#define ETH_HDR_LEN sizeof(struct eth_hdr)

struct sk_buff;
struct netdev;

uint8_t *skb_head(struct sk_buff *skb);

struct eth_hdr 
{
    uint8_t  dmac[6];
    uint8_t  smac[6];
    uint16_t ethertype;
    uint8_t  payload[];
} __attribute__((packed));

inline struct eth_hdr *eth_hdr(struct sk_buff *skb)
{
    struct eth_hdr *hdr = (struct eth_hdr *)skb_head(skb);

    hdr->ethertype = ntohs(hdr->ethertype);
    return hdr;
}

#endif
