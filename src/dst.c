#include "syshead.h"
#include "dst.h"
#include "arp.h"

int dst_neigh_output(struct sk_buff *skb)
{
    return netdev_queue_xmit(skb);
}
