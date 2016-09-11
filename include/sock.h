#ifndef _SOCK_H
#define _SOCK_H

#include "socket.h"

struct sock;

struct net_ops {
    int (*connect) (struct sock *sk, struct sockaddr addr, int addr_len);
};

struct sock {
    struct socket *sock;
    struct net_ops *ops;
};

struct sock *sk_alloc(struct net_ops *ops);

#endif
