#include "syshead.h"
#include "basic.h"
#include "netdev.h"
#include "ethernet.h"
#include "arp.h"
#include "ip.h"

struct eth_hdr* init_eth_hdr(char* buf)
{
    struct eth_hdr *hdr = (struct eth_hdr *) buf;

    hdr->ethertype = htons(hdr->ethertype);

    return hdr;
}

void handle_frame(struct netdev *netdev, struct eth_hdr *hdr)
{
    switch (hdr->ethertype) {
        case ETH_P_ARP:
            arp_incoming(netdev, hdr);
            break;
        case ETH_P_IP:
            ipv4_incoming(netdev, hdr);
            break;
        case ETH_P_IPV6:
            printf("IPv6 packet received, not supported\n");
            break;
        default:
            printf("Unrecognized ethertype %x\n", hdr->ethertype);
            break;
    }
}
