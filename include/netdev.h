#ifndef NETDEV_H
#define NETDEV_H
#include "syshead.h"

struct netdev {
    uint32_t addr;
    unsigned char hwaddr[6];
};

void netdev_init(struct netdev *dev, char *addr, char *hwaddr);
#endif
