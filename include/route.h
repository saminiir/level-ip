#ifndef _ROUTE_H
#define _ROUTE_H

#include "dst.h"
#include "list.h"

struct rtentry {
    struct list_head list;
    uint32_t dst;
    uint32_t gateway;
    uint32_t netmask;
    uint8_t flags;
    uint32_t metric;
    struct netdev *dev;
};

struct rtable {
    struct dst_entry dst;
};

void route_init();
struct rtable *route_lookup(uint32_t daddr);

#endif
