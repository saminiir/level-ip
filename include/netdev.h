#ifndef NETDEV_H
#define NETDEV_H
#include "syshead.h"
#include "ethernet.h"

struct netdev {
    uint32_t addr;
    unsigned char hwaddr[6];
};

void netdev_init(struct netdev *dev, char *addr, char *hwaddr);
void netdev_transmit(struct netdev *dev, struct eth_hdr *hdr, 
                     uint16_t ethertype, int len, unsigned char *dst);
#endif
