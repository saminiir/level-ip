#include "syshead.h"
#include "inet.h"
#include "sock.h"
#include "tcp.h"

extern struct net_ops tcp_ops;

static int inet_stream_connect(struct socket *sock, const struct sockaddr *addr,
                               int addr_len, int flags);

static int INET_OPS = 1;

struct net_family inet = {
    .create = inet_create,
};



static struct sock_ops inet_stream_ops = {
    .connect = &inet_stream_connect,
};

static struct sock_type inet_ops[] = {
    {
        .sock_ops = &inet_stream_ops,
        .net_ops = &tcp_ops,
        .type = SOCK_STREAM,
        .protocol = IPPROTO_TCP,
    }
};

int inet_create(struct socket *sock, int protocol)
{
    struct sock *sk;
    struct sock_type *skt = NULL;

    for (int i = 0; i < INET_OPS; i++) {
        if (inet_ops[i].type == sock->type) {
            skt = &inet_ops[i];           
        }
    }

    if (!skt) {
        perror("Could not find socktype for socket\n");
        return 1;
    }

    sock->ops = skt->sock_ops;

    sk = sk_alloc(skt->net_ops, protocol);

    sock_init_data(sock, sk);
    sk->protocol = protocol;
    
    return 0;
}

int inet_socket(struct socket *sock, int protocol)
{
    return 0;
}

int inet_connect(struct socket *sock, struct sockaddr *addr,
                 int addr_len, int flags)
{
    return 0;
}

static int inet_stream_connect(struct socket *sock, const struct sockaddr *addr,
                        int addr_len, int flags)
{
    return 0;
}
