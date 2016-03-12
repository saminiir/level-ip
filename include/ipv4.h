#ifndef IPV4_H
#define IPV4_H
#include "syshead.h"

#include "netdev.h"

struct iphdr {
    uint8_t version : 4;
    uint8_t ihl : 4;
    struct dsfield {
        uint8_t dscp : 6;
        uint8_t ecn : 2;
    } dsfield;
    uint16_t tot_len;
    uint16_t id;
    uint16_t flags : 3;
    uint16_t frag_offset : 13;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed));
    
void ipv4_incoming(struct netdev *netdev, struct eth_hdr *hdr);
    
#endif
