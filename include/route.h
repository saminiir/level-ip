#ifndef _ROUTE_H
#define _ROUTE_H

#include "list.h"

#define RT_LOOPBACK 0x01
#define RT_GATEWAY  0x02
#define RT_HOST     0x04
#define RT_REJECT   0x08
#define RT_UP       0x10

struct rtentry {
    struct list_head list;
    uint32_t dst;
    uint32_t gateway;
    uint32_t netmask;
    uint8_t flags;
    uint32_t metric;
    struct netdev *dev;
};

void route_init();
struct rtentry *route_lookup(uint32_t daddr);
void free_routes();

#endif
