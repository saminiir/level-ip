#include "syshead.h"
#include "netlink.h"
#include "socket.h"
#include "sock.h"
#include "tcp.h"
#include "wait.h"

extern struct net_ops tcp_ops;

static int netlink_stream_connect(struct socket *sock, const struct sockaddr *addr,
        int addr_len, int flags);

static int netlink_OPS = 1;

struct net_family netlink = {
    .create = netlink_create,
};

static struct sock_ops netlink_stream_ops = {
    .connect = &netlink_stream_connect,
    .write = &netlink_write,
    .read = &netlink_read,
    .close = &netlink_close,
    .free = &netlink_free,
    .abort = &netlink_abort,
    .getpeername = &netlink_getpeername,
    .getsockname = &netlink_getsockname,
    .sendmsg = &netlink_sendmsg,
    .recvmsg = &netlink_recvmsg,
};

static struct sock_type netlink_ops[] = {
    {
        .sock_ops = &netlink_stream_ops,
        .net_ops = &tcp_ops,
        .type = SOCK_STREAM,
        .protocol = IPPROTO_TCP,
    }
};

int netlink_create(struct socket *sock, int protocol)
{
    struct sock *sk;
    struct sock_type *skt = NULL;

    for (int i = 0; i < netlink_OPS; i++) {
        if (netlink_ops[i].type & sock->type) {
            skt = &netlink_ops[i];
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

int netlink_socket(struct socket *sock, int protocol)
{
    return 0;
}

int netlink_connect(struct socket *sock, struct sockaddr *addr,
        int addr_len, int flags)
{
    return 0;
}

static int netlink_stream_connect(struct socket *sock, const struct sockaddr *addr,
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

int netlink_write(struct socket *sock, const void *buf, int len)
{
    struct sock *sk = sock->sk;

    return sk->ops->write(sk, buf, len);
}

int netlink_read(struct socket *sock, void *buf, int len)
{
    struct sock *sk = sock->sk;

    return sk->ops->read(sk, buf, len);
}

struct sock *netlink_lookup(struct sk_buff *skb, uint16_t sport, uint16_t dport)
{
    struct socket *sock = socket_lookup(sport, dport);
    if (sock == NULL) return NULL;

    return sock->sk;
}

int netlink_close(struct socket *sock)
{
    if (!sock) {
        return 0;
    }

    struct sock *sk = sock->sk;

    return sock->sk->ops->close(sk);
}

int netlink_free(struct socket *sock)
{
    struct sock *sk = sock->sk;
    sock_free(sk);
    free(sock->sk);

    return 0;
}

int netlink_abort(struct socket *sock)
{
    struct sock *sk = sock->sk;

    if (sk) {
        sk->ops->abort(sk);
    }

    return 0;
}

int netlink_getpeername(struct socket *sock, struct sockaddr *restrict address,
        socklen_t *address_len)
{
    struct sock *sk = sock->sk;

    if (sk == NULL) {
        return -1;
    }

    struct sockaddr_in *res = (struct sockaddr_in *) address;
    res->sin_family = AF_NETLINK;
    res->sin_port = htons(sk->dport);
    res->sin_addr.s_addr = htonl(sk->daddr);
    *address_len = sizeof(struct sockaddr_in);

    netlink_dbg(sock, "geetpeername sin_family %d sin_port %d sin_addr %d addrlen %d",
            res->sin_family, ntohs(res->sin_port), ntohl(res->sin_addr.s_addr), *address_len);

    return 0;
}

int netlink_getsockname(struct socket *sock, struct sockaddr *restrict address,
        socklen_t *address_len)
{
    struct sock *sk = sock->sk;

    if (sk == NULL) {
        return -1;
    }

    struct sockaddr_nl *res = (struct sockaddr_nl *) address;
    res->nl_family = AF_NETLINK;
    *address_len = sizeof(struct sockaddr_nl);

    return 0;
}

int netlink_sendmsg(struct socket *sock, const struct msghdr *message, int flags)
{
    struct sock *sk = sock->sk;

    if (sk == NULL) {
        return -1;
    }

    int rc = 0;

    printf("sizeof nlmsghdr %lu\n", sizeof(struct nlmsghdr));

    for (int i = 0; i<message->msg_iovlen; i++) {
        struct iovec *v = &message->msg_iov[i];
        struct nlmsghdr *nl = v->iov_base;
        struct sock_diag_req *sdr = v->iov_base + sizeof(struct nlmsghdr);

        printf("nl len %d, nl type %d, nl flags %d\n", nl->nlmsg_len, nl->nlmsg_type, nl->nlmsg_flags);
        printf("sdr family %d, proto %d\n", sdr->sdiag_family, sdr->sdiag_protocol);
        
        printf("type is sock_diag %d\n", nl->nlmsg_type == SOCK_DIAG_BY_FAMILY);
        printf("type is sock_diag %d\n", 1 == 1);
        rc += message->msg_iov[i].iov_len;
    }

    return rc;
}

int netlink_recvmsg(struct socket *sock, struct msghdr *message, int flags)
{
    struct sock *sk = sock->sk;

    if (sk == NULL) {
        return -1;
    }

    printf("peek %d, trunc %d\n", flags & MSG_PEEK, flags & MSG_TRUNC);

    printf("sizeof %lu\n", sizeof(struct nlmsgerr));

    printf("recv claled\n");

    if (flags & (MSG_PEEK | MSG_TRUNC)) {
        return 20;
    }

    struct iovec *v = message->msg_iov;

    struct nlmsghdr *nl = v->iov_base;

    nl->nlmsg_len = 20;
    nl->nlmsg_type = NLMSG_DONE;
    nl->nlmsg_flags = NLM_F_MULTI;
    nl->nlmsg_seq = 123456;
    nl->nlmsg_pid = 0;
    v->iov_len = 20;

    return 20;
}
