#ifndef ARP_H
#define ARP_H
#include "syshead.h"
#include "ethernet.h"

void arp_incoming(struct eth_hdr *hdr);

#endif
