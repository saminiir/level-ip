#include "syshead.h"
#include "netdev.h"
#include "basic.h"

void netdev_init(struct netdev *dev, char *addr, char *hwaddr)
{
    CLEAR(*dev);

    if (inet_pton(AF_INET, addr, &dev->addr) != 1) {
        perror("ERR: Parsing inet address failed\n");
        exit(1);
    }

    sscanf(hwaddr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dev->hwaddr[0],
                                                    &dev->hwaddr[1],
                                                    &dev->hwaddr[2],
                                                    &dev->hwaddr[3],
                                                    &dev->hwaddr[4],
                                                    &dev->hwaddr[5]);
}
