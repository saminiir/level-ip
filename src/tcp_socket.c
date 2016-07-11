#include "syshead.h"
#include "tcp_socket.h"

#define MAX_TCP_SOCKETS 128
static int cur_fd = 3;
static struct tcp_socket tcp_sockets[MAX_TCP_SOCKETS];

void init_tcp_sockets()
{
    memset(tcp_sockets, 0, sizeof(struct tcp_socket) * MAX_TCP_SOCKETS);
}

struct tcp_socket *alloc_tcp_socket()
{
    struct tcp_socket *sock;
    for (int i = 0; i<MAX_TCP_SOCKETS; i++) {
        sock = &tcp_sockets[i];
        if (sock->fd == 0) {
            sock->fd = cur_fd++;
            sock->state = CLOSED;
            return sock;
        }
    }

    /* No space left, error case */
    return NULL;
}

void free_tcp_socket(struct tcp_socket *sock)
{

}

struct tcp_socket *get_tcp_socket(int sockfd)
{
    struct tcp_socket *sk;
    for (int i = 0; i<MAX_TCP_SOCKETS; i++) {
        sk = &tcp_sockets[i];

        if (sk->fd == sockfd) return sk;
    }

    return NULL;
}
