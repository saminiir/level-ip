#ifndef ICMPV4_H
#define ICMPV4_H

#include "syshead.h"
#include "netdev.h"

void icmpv4_incoming(struct netdev *netdev, struct eth_hdr *hdr);

#endif
