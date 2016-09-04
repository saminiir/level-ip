#include "syshead.h"
#include "dst.h"
#include "arp.h"

int dst_neigh_output(struct sk_buff *skb)
{
    uint8_t dmac[6] = { 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f };
    return netdev_transmit(skb, dmac, ETH_P_IP);
}
