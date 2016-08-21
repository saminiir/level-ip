#include "syshead.h"
#include "route.h"
#include "dst.h"
#include "netdev.h"

struct rtable main_rt;

extern struct netdev netdev;

void route_init()
{
    struct dst_entry dst = {
        .dev = &netdev
    };
    
    main_rt.dst = dst;
}

struct rtable *route_lookup(uint32_t daddr, uint32_t saddr)
{
    return &main_rt;
}
