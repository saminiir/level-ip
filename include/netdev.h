#ifndef NETDEV_H
#define NETDEV_H
#include "syshead.h"

struct netdev {
    struct in_addr addr;
    unsigned char hwaddr[6];
};

void netdev_init(struct netdev *dev, char *addr, char *hwaddr);
#endif
