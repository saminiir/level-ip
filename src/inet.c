#include "syshead.h"
#include "inet.h"
#include "socket.h"
#include "sock.h"
#include "tcp.h"
#include "wait.h"

extern struct net_ops tcp_ops;

static int inet_stream_connect(struct socket *sock, const struct sockaddr *addr,
                               int addr_len, int flags);

static int INET_OPS = 1;

struct net_family inet = {
    .create = inet_create,
};

static struct sock_ops inet_stream_ops = {
    .connect = &inet_stream_connect,
    .write = &inet_write,
    .read = &inet_read,
    .close = &inet_close,
    .free = &inet_free,
    .abort = &inet_abort,
    .getpeername = &inet_getpeername,
    .getsockname = &inet_getsockname,
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
        if (inet_ops[i].type & sock->type) {
            skt = &inet_ops[i];
            break;
        }
    }

    if (!skt) {
        print_err("Could not find socktype for socket\n");
        return 1;
    }

    sock->ops = skt->sock_ops;

    sk = sk_alloc(skt->net_ops, protocol);
    sk->protocol = protocol;
    
    sock_init_data(sock, sk);
    
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
    struct sock *sk = sock->sk;
    int rc = 0;
    
    if (addr_len < sizeof(addr->sa_family)) {
        return -EINVAL;
    }

    if (addr->sa_family == AF_UNSPEC) {
        sk->ops->disconnect(sk, flags);
        return -EAFNOSUPPORT;
    }

    switch (sock->state) {
    default:
        sk->err = -EINVAL;
        goto out;
    case SS_CONNECTED:
        sk->err = -EISCONN;
        goto out;
    case SS_CONNECTING:
        sk->err = -EALREADY;
        goto out;
    case SS_UNCONNECTED:
        sk->err = -EISCONN;
        if (sk->state != TCP_CLOSE) {
            goto out;
        }

        sk->ops->connect(sk, addr, addr_len, flags);
        sock->state = SS_CONNECTING;
        sk->err = -EINPROGRESS;

        if (sock->flags & O_NONBLOCK) {
            goto out;
        }

        pthread_mutex_lock(&sock->sleep.lock);
        while (sock->state == SS_CONNECTING && sk->err == -EINPROGRESS) {
            socket_release(sock);
            wait_sleep(&sock->sleep);
            socket_wr_acquire(sock);
        }
        pthread_mutex_unlock(&sock->sleep.lock);
        socket_wr_acquire(sock);
        
        switch (sk->err) {
        case -ETIMEDOUT:
        case -ECONNREFUSED:
            goto sock_error;
        }

        if (sk->err != 0) {
            goto out;
        }

        sock->state = SS_CONNECTED;
        break;
    }
    
out:
    return sk->err;
sock_error:
    rc = sk->err;
    return rc;
}

int inet_write(struct socket *sock, const void *buf, int len)
{
    struct sock *sk = sock->sk;

    return sk->ops->write(sk, buf, len);
}

int inet_read(struct socket *sock, void *buf, int len)
{
    struct sock *sk = sock->sk;

    return sk->ops->read(sk, buf, len);
}

struct sock *inet_lookup(struct sk_buff *skb, uint16_t sport, uint16_t dport)
{
    struct socket *sock = socket_lookup(sport, dport);
    if (sock == NULL) return NULL;
    
    return sock->sk;
}

int inet_close(struct socket *sock)
{
    if (!sock) {
        return 0;
    }

    struct sock *sk = sock->sk;

    return sock->sk->ops->close(sk);
}

int inet_free(struct socket *sock)
{
    struct sock *sk = sock->sk;
    sock_free(sk);
    free(sock->sk);
    
    return 0;
}

int inet_abort(struct socket *sock)
{
    struct sock *sk = sock->sk;
    
    if (sk) {
        sk->ops->abort(sk);
    }

    return 0;
}

int inet_getpeername(struct socket *sock, struct sockaddr *restrict address,
                     socklen_t *address_len)
{
    struct sock *sk = sock->sk;

    if (sk == NULL) {
        return -1;
    }

    struct sockaddr_in *res = (struct sockaddr_in *) address;
    res->sin_family = AF_INET;
    res->sin_port = htons(sk->dport);
    res->sin_addr.s_addr = htonl(sk->daddr);
    *address_len = sizeof(struct sockaddr_in);

    inet_dbg(sock, "geetpeername sin_family %d sin_port %d sin_addr %d addrlen %d",
             res->sin_family, ntohs(res->sin_port), ntohl(res->sin_addr.s_addr), *address_len);
    
    return 0;
}
int inet_getsockname(struct socket *sock, struct sockaddr *restrict address,
                     socklen_t *address_len)
{
    struct sock *sk = sock->sk;

    if (sk == NULL) {
        return -1;
    }
    
    struct sockaddr_in *res = (struct sockaddr_in *) address;
    res->sin_family = AF_INET;
    res->sin_port = htons(sk->sport);
    res->sin_addr.s_addr = htonl(sk->saddr);
    *address_len = sizeof(struct sockaddr_in);

    inet_dbg(sock, "getsockname sin_family %d sin_port %d sin_addr %d addrlen %d",
             res->sin_family, ntohs(res->sin_port), ntohl(res->sin_addr.s_addr), *address_len);
    
    return 0;
}
