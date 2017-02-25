#ifndef IPV4_H
#define IPV4_H
#include "syshead.h"
#include "ethernet.h"
#include "skbuff.h"
#include "sock.h"

#define IPV4 0x04
#define IP_TCP 0x06
#define ICMPV4 0x01

#define IP_HDR_LEN sizeof(struct iphdr)
#define ip_len(ip) (ip->len - (ip->ihl * 4))

#define ip_dbg(msg, hdr)                                                \
    do {                                                                \
        print_debug("\t\tIP "msg": ihl: %hhu, version: %hhu, tos: %hhu,\n"   \
                    "\t\t           len: %hu, id: %hu, flags: %hhu, frag_offset: %hu, ttl: %hhu,\n" \
                    "\t\t           proto: %hhu, csum: %hx,\n" \
                    "\t\t           saddr: %hhu.%hhu.%hhu.%hhu, daddr: %hhu.%hhu.%hhu.%hhu\n\n",  \
                    hdr->ihl,                                           \
                    hdr->version, hdr->tos, hdr->len, hdr->id, hdr->flags, \
                    hdr->frag_offset, hdr->ttl, hdr->proto, hdr->csum,   \
                    hdr->saddr >> 24, hdr->saddr >> 16, hdr->saddr >> 8, hdr->saddr >> 0, \
                    hdr->daddr >> 24, hdr->daddr >> 16, hdr->daddr >> 8, hdr->daddr >> 0); \
    } while (0)

struct iphdr {
    uint8_t ihl : 4; /* TODO: Support Big Endian hosts */
    uint8_t version : 4;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t flags : 3;
    uint16_t frag_offset : 13;
    uint8_t ttl;
    uint8_t proto;
    uint16_t csum;
    uint32_t saddr;
    uint32_t daddr;
    uint8_t data[];
} __attribute__((packed));

static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
    return (struct iphdr *)(skb->head + ETH_HDR_LEN);
}

static inline uint32_t ip_parse(char *addr)
{
    uint32_t dst = 0;
    
    if (inet_pton(AF_INET, addr, &dst) != 1) {
        perror("ERR: Parsing inet address failed");
        exit(1);
    }

    return ntohl(dst);
}

int ip_rcv(struct sk_buff *skb);
int ip_output(struct sock *sk, struct sk_buff *skb);

#endif
