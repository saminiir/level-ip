#ifndef _SOCK_H
#define _SOCK_H

#include "socket.h"
#include "wait.h"
#include "skbuff.h"

struct sock;

struct net_ops {
    struct sock* (*alloc_sock) (int protocol);
    int (*init) (struct sock *sk);
    int (*connect) (struct sock *sk, const struct sockaddr *addr, int addr_len, int flags);
    int (*disconnect) (struct sock *sk, int flags);
    int (*write) (struct sock *sk, const void *buf, int len);
    int (*read) (struct sock *sk, void *buf, int len);
    int (*recv_notify) (struct sock *sk);
    int (*close) (struct sock *sk);
    int (*abort) (struct sock *sk);
};

struct sock {
    struct socket *sock;
    struct net_ops *ops;
    struct wait_lock recv_wait;
    struct sk_buff_head receive_queue;
    struct sk_buff_head write_queue;
    int protocol;
    int state;
    int err;
    short int poll_events;
    uint16_t sport;
    uint16_t dport;
    uint32_t saddr;
    uint32_t daddr;
};

static inline struct sk_buff *write_queue_head(struct sock *sk)
{
    return skb_peek(&sk->write_queue);
}

struct sock *sk_alloc(struct net_ops *ops, int protocol);
void sock_free(struct sock *sk);
void sock_init_data(struct socket *sock, struct sock *sk);
void sock_connected(struct sock *sk);

#endif
