#include "syshead.h"
#include "basic.h"
#include "ethernet.h"

struct eth_hdr* init_eth_hdr(char* buf)
{
    struct eth_hdr *hdr = (struct eth_hdr *) buf;

    hdr->ethertype = htons(hdr->ethertype);

    return hdr;
}

void print_eth_hdr(struct eth_hdr *hdr)
{
    printf("\nPrinting Ethernet hdr:\n");

    printf("Source MAC: ");
    for (int i = 0; i < 6; i++) {
        printf("%x", hdr->src_mac[i]);
    }
    printf("\nDest MAC: ");
    for (int i = 0; i < 6; i++) {
        printf("%x", hdr->dst_mac[i]);
    }

    printf("\nEthertype: %x\n", hdr->ethertype);
}
