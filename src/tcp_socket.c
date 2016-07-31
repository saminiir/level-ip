#include "syshead.h"
#include "tcp_socket.h"
#include "utils.h"

#define MAX_TCP_SOCKETS 128
#define FIRST_FD 3

static struct tcp_socket tcp_sockets[MAX_TCP_SOCKETS];

void init_tcp_sockets()
{
    memset(tcp_sockets, 0, sizeof(struct tcp_socket) * MAX_TCP_SOCKETS);
}

static uint16_t generate_port()
{
    return 12000;
}

struct tcp_socket *alloc_tcp_socket()
{
    struct tcp_socket *sock;
    for (int i = 0; i<MAX_TCP_SOCKETS; i++) {
        sock = &tcp_sockets[i];
        if (sock->fd == 0) {
            sock->fd = i + FIRST_FD;
            sock->state = CLOSED;
            return sock;
        }
    }

    /* No space left, error case */
    return NULL;
}

void free_tcp_socket(struct tcp_socket *sock)
{
    int fd = sock->fd;

    tcp_sockets[fd - FIRST_FD].fd = 0;
}

struct tcp_socket *get_tcp_socket(int sockfd)
{
    struct tcp_socket *sk;
    sk = &tcp_sockets[sockfd - FIRST_FD];

    if (sk->fd == 0) return NULL;

    return sk;
}

static int generate_iss()
{
    return 1525252;
}

static int send_syn(struct tcp_socket *sock)
{
    if (sock->state != CLOSED && sock->state != LISTEN) {
        print_error("Socket was not in correct state (closed or listen)");
        return 1;
    }

    sock->state = SYN_SENT;
    sock->tcb.iss = generate_iss();

    return 0;
}

int connect_tcp_socket(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct tcp_socket *sock;
    printf("%d\n", fd);
    uint16_t dport = addr->sa_data[1];

    if ((sock = get_tcp_socket(fd)) == NULL) {
        print_error("Could not find socket for connection\n");
        exit(1);
    }

    printf("Connecting socket %d to %hhu.%hhu.%hhu.%hhu\n", fd, addr->sa_data[2], addr->sa_data[3], addr->sa_data[4], addr->sa_data[5]);

    sock->dport = dport;
    sock->sport = generate_port();

    send_syn(sock);

    return 0;
}
