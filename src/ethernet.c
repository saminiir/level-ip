#include "ethernet.h"
#include "syshead.h"
#include "skbuff.h"

extern inline struct eth_hdr *eth_hdr(struct sk_buff *skb);
