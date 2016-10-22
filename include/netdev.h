#ifndef NETDEV_H
#define NETDEV_H
#include "syshead.h"
#include "ethernet.h"
#include "skbuff.h"
#include "utils.h"

#define BUFLEN 512
#define MAX_ADDR_LEN 32

#define netdev_dbg(fmt, args...)\
do {\
    print_debug("NETDEV: "fmt, ##args);         \
} while (0)

struct eth_hdr;

struct netdev {
    uint32_t addr;
    uint8_t addr_len;
    uint8_t hwaddr[6];
};

void netdev_init(char *addr, char *hwaddr);
int netdev_transmit(struct sk_buff *skb, uint8_t *dst, uint16_t ethertype);
void *netdev_rx_loop();
void free_netdev();
struct netdev *netdev_get(uint32_t sip);
#endif
