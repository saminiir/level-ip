#include "syshead.h"
#include "route.h"
#include "dst.h"
#include "netdev.h"
#include "list.h"
#include "ip.h"

static LIST_HEAD(routes);

extern struct netdev *netdev;
extern struct netdev *loop;

extern char *tapaddr;
extern char *taproute;

static uint8_t route_mask_len(uint32_t mask)
{
    uint8_t bits_set = 0;

    while (mask) {
        if (mask & 1) {
            bits_set++;
        }

        mask >>= 1;
    }

    return bits_set;
}

static struct rtentry *route_alloc(uint32_t dst, uint32_t gateway, uint32_t netmask,
                                   uint8_t flags, uint32_t metric, struct netdev *dev)
{
    struct rtentry *rt = malloc(sizeof(struct rtentry));
    list_init(&rt->list);

    rt->dst = dst;
    rt->gateway = gateway;
    rt->netmask = netmask;
    rt->flags = flags;
    rt->metric = metric;
    rt->dev = dev;
    return rt;
}

void route_add(uint32_t dst, uint32_t gateway, uint32_t netmask, uint8_t flags,
               uint32_t metric, struct netdev *dev)
{
    struct rtentry *rt = route_alloc(dst, gateway, netmask, flags, metric, dev);

    list_add_tail(&rt->list, &routes);
}

void route_init()
{
    route_add(loop->addr, 0, 0xff000000, RT_LOOPBACK, 0, loop);
    route_add(netdev->addr, 0, 0xffffff00, RT_HOST, 0, netdev);
    route_add(0, ip_parse(tapaddr), 0, RT_GATEWAY, 0, netdev);
}

struct rtentry *route_lookup(uint32_t daddr)
{
    struct list_head *item;
    struct rtentry *rt = NULL;
    struct rtentry *lpm_rt = NULL;
    uint8_t         longest_match = 0;

    list_for_each(item, &routes) {
        rt = list_entry(item, struct rtentry, list);
        if ((daddr & rt->netmask) == (rt->dst & rt->netmask)) {
            if (!lpm_rt || (route_mask_len(rt->netmask) > longest_match)) {
                lpm_rt = rt;
                longest_match = route_mask_len(rt->netmask);
            }
        }
        // If no matches, we default to to default gw (last item)
    }
    
    return lpm_rt;
}

void free_routes()
{
    struct list_head *item, *tmp;
    struct rtentry *rt;
    
    list_for_each_safe(item, tmp, &routes) {
        rt = list_entry(item, struct rtentry, list);
        list_del(item);

        free(rt);
    }
}
