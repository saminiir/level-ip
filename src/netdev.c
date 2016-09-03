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

    dev->buflen = 512;

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

    dev->tundev = calloc(10, 1);

    tun_init(dev->tundev);
}

int netdev_queue_xmit(struct sk_buff *skb)
{
    struct netdev *dev;
    struct eth_hdr *hdr;
    uint8_t dmac[6] = { 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f };

    dev = skb->dst->dev;

    skb_push(skb, ETH_HDR_LEN);

    hdr = (struct eth_hdr *)skb->data;

    memcpy(hdr->dmac, dmac, 6);
    memcpy(hdr->smac, dev->hwaddr, 6);
    hdr->ethertype = htons(ETH_P_IP);

    return tun_write((char *)skb->data, skb->len);
}

void netdev_transmit(struct netdev *dev, struct eth_hdr *hdr, 
                     uint16_t ethertype, int len, uint8_t *dst)
{
    uint8_t dst_mac[6];
    memcpy(dst_mac, dst, 6);
    hdr->ethertype = htons(ethertype);

    memcpy(hdr->smac, dev->hwaddr, 6);
    memcpy(hdr->dmac, dst_mac, 6);

    len += sizeof(struct eth_hdr);

    tun_write((char *)hdr, len);
}

void *netdev_rx_loop()
{
    while (running) {
        struct sk_buff *skb = alloc_skb(BUFLEN);
        
        if (tun_read((char *)skb->data, BUFLEN) < 0) { 
            print_error("ERR: Read from tun_fd: %s\n", strerror(errno));
            return NULL;
        }

        printf("Received packets, processing\n");

        netdev_rx_action(skb, &netdev);
    }

    return NULL;
}

int netdev_rx_action(struct sk_buff *skb, struct netdev *netdev)
{
    struct eth_hdr *hdr = eth_hdr(skb);

    switch (hdr->ethertype) {
        case ETH_P_ARP:
            arp_incoming(netdev, hdr);
            break;
        case ETH_P_IP:
            ip_rcv(skb, netdev);
            break;
        case ETH_P_IPV6:
            printf("IPv6 packet received, not supported\n");
            break;
        default:
            printf("Unrecognized ethertype %x\n", hdr->ethertype);
            break;
    }

    return 0;
}

void netdev_free()
{
    free(netdev.tundev);
}
