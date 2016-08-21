#ifndef _ROUTE_H
#define _ROUTE_H

#include "dst.h"

struct rtable {
    struct dst_entry dst;
};

void route_init();
struct rtable *route_lookup(uint32_t daddr, uint32_t saddr);

#endif
