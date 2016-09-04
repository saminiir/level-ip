#ifndef SKBUFF_H_
#define SKBUFF_H_

#include "netdev.h"
#include "dst.h"

struct sk_buff {
    struct dst_entry *dst;
    struct netdev *netdev;
    uint16_t protocol;
    uint32_t len;
    uint8_t *tail;
    uint8_t *end;
    uint8_t *head;
    uint8_t *data;
};

struct sk_buff *alloc_skb(unsigned int size);
uint8_t *skb_push(struct sk_buff *skb, unsigned int len);
uint8_t *skb_head(struct sk_buff *skb);
void *skb_reserve(struct sk_buff *skb, unsigned int len);
void skb_dst_set(struct sk_buff *skb, struct dst_entry *dst);

#endif
