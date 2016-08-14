#ifndef SKBUFF_H_
#define SKBUFF_H_

struct sk_buff {
    uint32_t len;
    uint8_t *tail;
    uint8_t *end;
    uint8_t *head;
    uint8_t *data;
    
} __attribute__((packed));

struct sk_buff *alloc_skb(unsigned int size);
uint8_t *skb_push(struct sk_buff *skb, unsigned int len);
void *skb_reserve(struct sk_buff *skb, unsigned int len);

#endif
