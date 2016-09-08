#include "syshead.h"
#include "utils.h"
#include "socket.h"
#include "inet.h"
#include "tcp.h"

static struct socket sockets[12];

extern struct proto_ops inet_ops;

static struct proto_ops *proto_ops[128] = {
    [AF_INET] = &inet_ops
};

static struct socket *alloc_socket()
{
    struct socket *sock = &sockets[0];

    sock->fd = 5;
    sock->state = SS_UNCONNECTED;
    
    return sock;
}

int _socket(int domain, int type, int protocol)
{
    struct socket *sock;

    if ((sock = alloc_socket()) == NULL) {
        print_error("Could not alloc socket\n");
        exit(1);
    }

    sock->type = type;
    
    printf("domain %x\n", domain);
    printf("type %x\n", type);
    printf("protocol %x\n", protocol);

    sock->ops = proto_ops[domain];

    sock->ops->socket(sock, protocol);

    return sock->fd;
}

int _connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct tcp_socket *sock;

    if ((sock = get_tcp_socket(sockfd)) == NULL) {
        print_error("Could not find socket for connection\n");
        exit(1);
    }

    return tcp_v4_connect(sock, addr, addrlen);
}
