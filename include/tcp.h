#ifndef TCP_H
#include "syshead.h"
#include "netdev.h"

struct tcphdr {
  uint16_t sport;
  uint16_t dport;
  uint32_t seq;
  uint32_t ack;
  uint8_t hl : 4;
  uint8_t rsvd : 4;
  uint8_t flags;
  uint16_t win;
  uint16_t csum;
  uint16_t urg;
} __attribute__((packed));

void tcp_in(struct netdev *netdev, struct eth_hdr *hdr);
#endif
