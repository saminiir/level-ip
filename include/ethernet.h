#ifndef ETHERNET_H_
#define ETHERNET_H_

#include <linux/if_ether.h>
#include "netdev.h"
#include "skbuff.h"
#include "syshead.h"
#include "utils.h"

#define ETH_HDR_LEN sizeof(struct eth_hdr)

#ifdef DEBUG_ETH
#define eth_dbg(msg, hdr)                                               \
    do {                                                                \
        print_debug("eth "msg" ("                                       \
                    "dmac: %.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx, " \
                    "smac: %.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx, " \
                    "ethertype: %.4hx)",                               \
                    hdr->dmac[0], hdr->dmac[1], hdr->dmac[2], hdr->dmac[3], \
                    hdr->dmac[4], hdr->dmac[5], hdr->smac[0], hdr->smac[1], \
                    hdr->smac[2], hdr->smac[3], hdr->smac[4], hdr->smac[5], hdr->ethertype); \
    } while (0)
#else
#define eth_dbg(msg, hdr)
#endif

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

static inline struct eth_hdr *eth_hdr(struct sk_buff *skb)
{
    struct eth_hdr *hdr = (struct eth_hdr *)skb_head(skb);

    hdr->ethertype = ntohs(hdr->ethertype);

    return hdr;
}

#endif
