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
    uint8_t *dev_addr;
    unsigned char broadcast[MAX_ADDR_LEN];
    uint8_t hwaddr[6];
    char buf[BUFLEN];
    int buflen;
    char *tundev;
};

void netdev_init(char *addr, char *hwaddr);
int netdev_queue_xmit(struct sk_buff *skb);
void netdev_transmit(struct netdev *dev, struct eth_hdr *hdr, 
                     uint16_t ethertype, int len, uint8_t *dst);
void *netdev_rx_loop();
int netdev_rx_action(struct sk_buff *skb, struct netdev *netdev);
void netdev_free();
#endif
