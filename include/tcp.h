#ifndef TCP_H_
#define TCP_H_
#include "syshead.h"
#include "netdev.h"
#include "ipv4.h"

#define TCP_HDR_LEN 20

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

#define TCP_URG 0x20
#define TCP_ECN 0x40
#define TCP_WIN 0x80

struct tcphdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t rsvd : 4;
    uint8_t hl : 4;
    uint8_t flags;
    uint16_t win;
    uint16_t csum;
    uint16_t urp;
    uint8_t data[];
} __attribute__((packed));

struct tcpiphdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t proto;
    uint16_t tlen;
} __attribute__((packed));

void tcp_init();
void tcp_in(struct netdev *netdev, struct eth_hdr *hdr);
void tcp_out(struct netdev *netdev, struct eth_hdr *hdr);
int tcp_checksum(struct iphdr *iphdr, struct tcphdr *thdr);
#endif
