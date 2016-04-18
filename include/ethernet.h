#ifndef ETHERNET_H_
#define ETHERNET_H_
#include <linux/if_ether.h>

struct eth_hdr 
{
    uint8_t  dmac[6];
    uint8_t  smac[6];
    uint16_t ethertype;
    uint8_t  payload[];
} __attribute__((packed));

struct eth_hdr* init_eth_hdr(char* buf);

#endif
