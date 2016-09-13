#ifndef _SOCK_H
#define _SOCK_H

#include "socket.h"

struct sock;

struct net_ops {
    struct sock* (*alloc_sock) (int protocol);
    int (*connect) (struct sock *sk, const struct sockaddr *addr, int addr_len, int flags);
};

struct sock {
    struct socket *sock;
    struct net_ops *ops;
    int protocol;
};

struct sock *sk_alloc(struct net_ops *ops, int protocol);
void sock_init_data(struct socket *sock, struct sock *sk);

#endif
