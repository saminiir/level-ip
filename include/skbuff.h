#ifndef SKBUFF_H_
#define SKBUFF_H_

struct sk_buff {
    uint32_t size;
    uint8_t data[];
} __attribute__((packed));

struct sk_buff *alloc_skb(unsigned int size);

#endif
