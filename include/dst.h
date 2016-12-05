#ifndef DST_H_
#define DST_H_

#include "skbuff.h"

struct sk_buff;

int dst_neigh_output(struct sk_buff *skb);

#endif
