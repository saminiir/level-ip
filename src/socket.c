#include "syshead.h"
#include "tcp_socket.h"

int socket(int domain, int type, int protocol)
{
    struct tcp_socket *sock = alloc_tcp_socket();
    printf("domain %x\n", domain);
    printf("type %x\n", type);
    printf("protocol %x\n", protocol);

    return sock->fd;
}
