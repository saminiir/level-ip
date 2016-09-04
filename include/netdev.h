#ifndef NETDEV_H
#define NETDEV_H
#include "syshead.h"
#include "ethernet.h"
#include "skbuff.h"

#define BUFLEN 512
#define MAX_ADDR_LEN 32

struct eth_hdr;

struct netdev {
    uint32_t addr;
    uint8_t addr_len;
    uint8_t hwaddr[6];
};

void netdev_init(char *addr, char *hwaddr);
int netdev_transmit(struct sk_buff *skb, uint8_t *dst, uint16_t ethertype);
void *netdev_rx_loop();
int netdev_rx_action(struct sk_buff *skb, struct netdev *netdev);
void netdev_free();
#endif
