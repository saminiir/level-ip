#ifndef ARP_H
#define ARP_H
#include "syshead.h"
#include "ethernet.h"
#include "netdev.h"
#include "skbuff.h"

#define ARP_ETHERNET    0x0001
#define ARP_IPV4        0x0800
#define ARP_REQUEST     0x0001
#define ARP_REPLY       0x0002

#define ARP_HDR_LEN sizeof(struct arp_hdr)
#define ARP_DATA_LEN sizeof(struct arp_ipv4)

#define ARP_CACHE_LEN   32
#define ARP_FREE        0
#define ARP_WAITING     1
#define ARP_RESOLVED    2

struct arp_hdr
{
    uint16_t hwtype;
    uint16_t protype;
    uint8_t hwsize;
    uint8_t prosize;
    uint16_t opcode;
    unsigned char data[];
} __attribute__((packed));

struct arp_ipv4
{
    unsigned char smac[6];
    uint32_t sip;
    unsigned char dmac[6];
    uint32_t dip;
} __attribute__((packed));

struct arp_cache_entry
{
    uint16_t hwtype;
    uint32_t sip;
    unsigned char smac[6];
    unsigned int state;
};

void arp_init();
void arp_rcv(struct sk_buff *skb);
void arp_reply(struct sk_buff *skb, struct netdev *netdev);
int arp_request(uint32_t sip, uint32_t dip, struct netdev *netdev);
unsigned char* arp_get_hwaddr(uint32_t sip);

static inline struct arp_hdr *arp_hdr(struct sk_buff *skb)
{
    return (struct arp_hdr *)(skb->head + ETH_HDR_LEN);
}

#endif
