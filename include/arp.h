#ifndef ARP_H
#define ARP_H
#include "syshead.h"
#include "ethernet.h"
#include "netdev.h"

#define ARP_ETHERNET    0x0001
#define ARP_IPV4        0x0800
#define ARP_REQUEST     0x0001

#define ARP_CACHE_LEN   32
#define ARP_FREE        0
#define ARP_WAITING     1
#define ARP_RESOLVED    2

struct arp_hdr
{
    uint16_t hw_type;
    uint16_t pro_type;
    unsigned char hw_size;
    unsigned char pro_size;
    uint16_t opcode;
    unsigned char data[];
} __attribute__((packed));

struct arp_ipv4
{
    unsigned char src_mac[6];
    unsigned char src_addr[4];
    unsigned char dst_mac[6];
    unsigned char dst_addr[4];
};
} __attribute__((packed));

struct arp_cache_entry
{
    uint16_t hw_type;
    unsigned char src_addr[4];
    unsigned char src_mac[4];
    unsigned int state;
};

void arp_init();
void arp_incoming(struct netdev *netdev, struct eth_hdr *hdr);

#endif
