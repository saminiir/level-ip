#ifndef _INET_H
#define _INET_H

#include "syshead.h"
#include "socket.h"
#include "skbuff.h"

int inet_create(struct socket *sock, int protocol);
int inet_socket(struct socket *sock, int protocol);
int inet_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags);

struct sock *inet_lookup(struct sk_buff *skb, uint16_t sport, uint16_t dport);
#endif
