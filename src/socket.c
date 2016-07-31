#include "syshead.h"
#include "utils.h"
#include "tcp_socket.h"

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
    return connect_tcp_socket(sockfd, addr, addrlen);
}
