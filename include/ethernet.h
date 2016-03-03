#ifndef ETHERNET_H_
#define ETHERNET_H_
#include <linux/if_ether.h>

struct eth_hdr 
{
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
    unsigned short ethertype;
    unsigned char* payload;
};

struct eth_hdr* init_eth_hdr(char* buf);
void print_eth_hdr(struct eth_hdr *ehdr);

#endif
