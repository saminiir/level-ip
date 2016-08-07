#include "syshead.h"
#include "skbuff.h"

struct sk_buff *alloc_skb(unsigned int size)
{
    struct sk_buff *skb = malloc(size);

    return skb;
}
