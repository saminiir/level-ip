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
    struct tcp_socket *sock;
    printf("%d\n", sockfd);
    uint16_t dport = addr->sa_data[1];

    if ((sock = get_tcp_socket(sockfd)) == NULL) {
        print_error("Could not find socket for connection\n");
        exit(1);
    };
    
    printf("Connecting socket %d to %hhu.%hhu.%hhu.%hhu\n", sockfd, addr->sa_data[2], addr->sa_data[3], addr->sa_data[4], addr->sa_data[5]);
    return 0;
}
