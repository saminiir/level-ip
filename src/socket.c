#include "syshead.h"
#include "utils.h"
#include "tcp.h"

int _socket(int domain, int type, int protocol)
{
    struct tcp_socket *sock;

    if ((sock = alloc_tcp_socket()) == NULL) {
        print_error("Could not alloc socket\n");
        exit(1);
    }
    
    printf("domain %x\n", domain);
    printf("type %x\n", type);
    printf("protocol %x\n", protocol);

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
