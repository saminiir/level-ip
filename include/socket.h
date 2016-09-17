#ifndef SOCKET_H_
#define SOCKET_H_

#include "sock.h"
#include "wait.h"

struct socket;

enum socket_state {
    SS_FREE = 0,                    /* not allocated                */
    SS_UNCONNECTED,                 /* unconnected to any socket    */
    SS_CONNECTING,                  /* in process of connecting     */
    SS_CONNECTED,                   /* connected to socket          */
    SS_DISCONNECTING                /* in process of disconnecting  */
};

struct sock_type {
    struct sock_ops *sock_ops;
    struct net_ops *net_ops;
    int type;
    int protocol;
};

struct sock_ops {
    int (*connect) (struct socket *sock, const struct sockaddr *addr,
                    int addr_len, int flags);
};

struct net_family {
    int (*create) (struct socket *sock, int protocol);    
};

struct socket {
    int fd;
    enum socket_state state;
    short type;
    struct sock *sk;
    struct sock_ops *ops;
    struct wait_lock sleep;
};

int _socket(int domain, int type, int protocol);
int _connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

#endif
