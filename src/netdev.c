#include "syshead.h"
#include "utils.h"
#include "skbuff.h"
#include "netdev.h"
#include "ethernet.h"
#include "arp.h"
#include "ip.h"
#include "tuntap_if.h"
#include "basic.h"

struct netdev netdev;
extern int running;

void netdev_init(char *addr, char *hwaddr)
{
    struct netdev *dev = &netdev;
    CLEAR(*dev);

    if (inet_pton(AF_INET, addr, &dev->addr) != 1) {
        perror("ERR: Parsing inet address failed\n");
        exit(1);
    }

    dev->addr = ntohl(dev->addr);

    sscanf(hwaddr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dev->hwaddr[0],
                                                    &dev->hwaddr[1],
                                                    &dev->hwaddr[2],
                                                    &dev->hwaddr[3],
                                                    &dev->hwaddr[4],
                                                    &dev->hwaddr[5]);

    dev->addr_len = 6;
}

int netdev_transmit(struct sk_buff *skb, uint8_t *dst_hw, uint16_t ethertype)
{
    struct netdev *dev;
    struct eth_hdr *hdr;
    int ret = 0;

    dev = skb->netdev;

    skb_push(skb, ETH_HDR_LEN);

    hdr = (struct eth_hdr *)skb->data;

    memcpy(hdr->dmac, dst_hw, dev->addr_len);
    memcpy(hdr->smac, dev->hwaddr, dev->addr_len);

    eth_dbg("OUTPUT", hdr);
    hdr->ethertype = htons(ethertype);

    ret = tun_write((char *)skb->data, skb->len);

    free_skb(skb);

    return ret;
}

static int netdev_receive(struct sk_buff *skb)
{
    struct eth_hdr *hdr = eth_hdr(skb);

    eth_dbg("INPUT", hdr);

    switch (hdr->ethertype) {
        case ETH_P_ARP:
            arp_rcv(skb);
            break;
        case ETH_P_IP:
            ip_rcv(skb);
            break;
        case ETH_P_IPV6:
        default:
            printf("Unsupported ethertype %x\n", hdr->ethertype);
            free_skb(skb);
            break;
    }

    return 0;
}

void *netdev_rx_loop()
{
    while (running) {
        struct sk_buff *skb = alloc_skb(BUFLEN);
        
        if (tun_read((char *)skb->data, BUFLEN) < 0) { 
            print_error("ERR: Read from tun_fd: %s\n", strerror(errno));
            free_skb(skb);
            return NULL;
        }

        netdev_receive(skb);
    }

    return NULL;
}

struct netdev* netdev_get(uint32_t sip)
{
    if (netdev.addr == sip) {
        return &netdev;
    } else {
        return NULL;
    }
}

void free_netdev()
{
}
