#include "syshead.h"
#include "utils.h"
#include "socket.h"
#include "inet.h"
#include "wait.h"

static struct socket sockets[12];

extern struct net_family inet;

static struct net_family *families[128] = {
    [AF_INET] = &inet,
};

static struct socket *alloc_socket()
{
    struct socket *sock = &sockets[0];

    sock->fd = 5;
    sock->state = SS_UNCONNECTED;
    wait_init(&sock->sleep);
    
    return sock;
}

static struct socket *get_socket(int fd)
{
    return &sockets[0];
}

struct socket *socket_lookup(uint16_t sport, uint16_t dport)
{
    return &sockets[0];
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

    families[domain]->create(sock, protocol);

    return sock->fd;
}

int _connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct socket *sock;

    if ((sock = get_socket(sockfd)) == NULL) {
        print_error("Could not find socket for connection\n");
        exit(1);
    }

    return sock->ops->connect(sock, addr, addrlen, 0);
}

int _write(int sockfd, const void *buf, const unsigned int count)
{
    struct socket *sock;

    if ((sock = get_socket(sockfd)) == NULL) {
        print_error("Could not find socket for connection\n");
        exit(1);
    }

    return sock->ops->write(sock, buf, count);
}

int _read(int sockfd, void *buf, const unsigned int count)
{
    struct socket *sock;

    if ((sock = get_socket(sockfd)) == NULL) {
        print_error("Could not find socket for connection\n");
        exit(1);
    }

    return sock->ops->read(sock, buf, count);
}
