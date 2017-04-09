#ifndef ARP_H
#define ARP_H
#include "syshead.h"
#include "ethernet.h"
#include "netdev.h"
#include "skbuff.h"
#include "list.h"
#include "utils.h"

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

#ifdef DEBUG_ARP
#define arp_dbg(str, hdr)                                               \
    do {                                                                \
        print_debug("arp "str" (hwtype: %hu, protype: %.4hx, "          \
                    "hwsize: %d, prosize: %d, opcode: %.4hx)",         \
                    hdr->hwtype, hdr->protype, hdr->hwsize,             \
                    hdr->prosize, hdr->opcode);                         \
    } while (0)

#define arpdata_dbg(str, data)                                          \
    do {                                                                \
        print_debug("arp data "str" (smac: %.2hhx:%.2hhx:%.2hhx:%.2hhx"  \
                    ":%.2hhx:%.2hhx, sip: %hhu.%hhu.%hhu.%hhu, dmac: %.2hhx:%.2hhx" \
                    ":%.2hhx:%.2hhx:%.2hhx:%.2hhx, dip: %hhu.%hhu.%hhu.%hhu)", \
                    data->smac[0], data->smac[1], data->smac[2], data->smac[3], \
                    data->smac[4], data->smac[5], data->sip >> 24, data->sip >> 16, \
                    data->sip >> 8, data->sip >> 0, data->dmac[0], data->dmac[1], \
                    data->dmac[2], data->dmac[3], data->dmac[4], data->dmac[5], \
                    data->dip >> 24, data->dip >> 16, data->dip >> 8, data->dip >> 0); \
    } while (0)

#define arpcache_dbg(str, entry) \
    do { \
    print_debug("arp cache "str" (hwtype: %hu, sip: %hhu.%hhu.%hhu.%hhu, " \
    "smac: %.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx, state: %d)", entry->hwtype, \
        entry->sip >> 24, entry->sip >> 16, entry->sip >> 8, entry->sip >> 0, \
        entry->smac[0], entry->smac[1], entry->smac[2], entry->smac[3], entry->smac[4], \
                entry->smac[5], entry->state); \
    } while (0)
#else
#define arp_dbg(str, hdr)
#define arpdata_dbg(str, data)
#define arpcache_dbg(str, entry)
#endif

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
    struct list_head list;
    uint16_t hwtype;
    uint32_t sip;
    unsigned char smac[6];
    unsigned int state;
};

void arp_init();
void free_arp();
void arp_rcv(struct sk_buff *skb);
void arp_reply(struct sk_buff *skb, struct netdev *netdev);
int arp_request(uint32_t sip, uint32_t dip, struct netdev *netdev);
unsigned char* arp_get_hwaddr(uint32_t sip);

static inline struct arp_hdr *arp_hdr(struct sk_buff *skb)
{
    return (struct arp_hdr *)(skb->head + ETH_HDR_LEN);
}

#endif
