#ifndef ARP_H
#define ARP_H
#include "syshead.h"
#include "ethernet.h"

#define ARP_ETHERNET    0x0001
#define ARP_IPV4        0x0800
#define ARP_REQUEST     0x0001

struct arp_hdr
{
    uint16_t hw_type;
    uint16_t pro_type;
    unsigned char hw_size;
    unsigned char pro_size;
    uint16_t opcode;
    unsigned char payload[];
};

struct arp_ipv4
{
    unsigned char src_mac[6];
    unsigned char src_addr[4];
    unsigned char dst_mac[6];
    unsigned char dst_addr[4];
};

void arp_incoming(int tun_fd, struct eth_hdr *hdr);

#endif
