#include "syshead.h"
#include "skbuff.h"

struct sk_buff *alloc_skb(unsigned int size)
{
    struct sk_buff *skb = malloc(sizeof(struct sk_buff));

    memset(skb, 0, sizeof(struct sk_buff));
    skb->data = malloc(size);
    memset(skb->data, 0, size);
    
    skb->head = skb->data;
    skb->tail = skb->data;
    skb->end = skb->tail + size;

    return skb;
}

void free_skb(struct sk_buff *skb)
{
    free(skb->data);
    free(skb);
}

void *skb_reserve(struct sk_buff *skb, unsigned int len)
{
    skb->data += len;
    skb->tail += len;

    return skb->data;
}

uint8_t *skb_push(struct sk_buff *skb, unsigned int len)
{
    skb->data -= len;
    skb->len += len;

    return skb->data;
}

void skb_dst_set(struct sk_buff *skb, struct dst_entry *dst)
{
    skb->dst = dst;
}

uint8_t *skb_head(struct sk_buff *skb)
{
    return skb->head;
}
