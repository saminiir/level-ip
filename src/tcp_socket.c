#include "syshead.h"
#include "tcp_socket.h"
#include "tcp.h"
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

static int tcp_send_syn(struct tcp_socket *sock)
{
    if (sock->state != CLOSED && sock->state != LISTEN) {
        print_error("Socket was not in correct state (closed or listen)");
        return 1;
    }

    struct tcphdr thdr;

    thdr.sport = sock->sport;
    thdr.dport = sock->dport;
    thdr.seq = sock->tcb.iss;
    thdr.ack = 0;
    thdr.rsvd = 0;
    thdr.hl = 6;
    thdr.flags = TCP_SYN;
    thdr.win = sock->tcb.rcv_wnd;
    thdr.urp = 0;

    sock->state = SYN_SENT;

    tcp_out(sock, &thdr);

    return 0;
}

static int tcp_connect(struct tcp_socket *sk)
{
    return tcp_send_syn(sk);
}

int tcp_v4_connect(struct tcp_socket *sock, const struct sockaddr *addr, socklen_t addrlen)
{
    uint16_t dport = addr->sa_data[1];

    printf("Connecting socket to %hhu.%hhu.%hhu.%hhu\n", addr->sa_data[2], addr->sa_data[3], addr->sa_data[4], addr->sa_data[5]);

    sock->dport = dport;
    sock->sport = generate_port();
    memcpy(&sock->dip, addr->sa_data + 2, 32);
    sock->tcb.iss = generate_iss();
    sock->tcb.snd_una = sock->tcb.iss;
    sock->tcb.snd_nxt = sock->tcb.iss + 1;
    sock->tcb.rcv_wnd = 4096;
    
    return tcp_connect(sock);
}
