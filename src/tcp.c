#include "tcp.h"
#include "ipv4.h"
#include "utils.h"

void tcp_init()
{
    init_tcp_sockets();
}

void tcp_in(struct netdev *netdev, struct eth_hdr *hdr)
{
    struct iphdr *iphdr = (struct iphdr *) hdr->payload;
    struct tcphdr *thdr = (struct tcphdr *) iphdr->data;

    if (tcp_checksum(iphdr, thdr) != 0) {
        printf("TCP segment checksum did not match, dropping\n");
        return;
    }
}

int tcp_checksum(struct iphdr *ihdr, struct tcphdr *thdr)
{
    struct tcpiphdr pseudo_hdr;
    int sum = 0;
    int tlen = ihdr->len - ihdr->ihl * 4;

    pseudo_hdr.saddr = ihdr->saddr;
    pseudo_hdr.daddr = ihdr->daddr;
    pseudo_hdr.zero = 0;
    pseudo_hdr.proto = ihdr->proto;
    pseudo_hdr.tlen = htons(tlen);

    sum = sum_every_16bits(&pseudo_hdr, sizeof(struct tcpiphdr));
        
    return checksum(thdr, tlen, sum);
}

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

int tcp_v4_connect(struct tcp_socket *sock, const struct sockaddr *addr, socklen_t addrlen)
{
    uint16_t dport = addr->sa_data[1];
    uint32_t daddr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;

    printf("Connecting socket to %hhu.%hhu.%hhu.%hhu\n", addr->sa_data[2], addr->sa_data[3], addr->sa_data[4], addr->sa_data[5]);

    sock->dport = dport;
    sock->sport = generate_port();
    sock->daddr = daddr;
    sock->tcb.iss = generate_iss();
    sock->tcb.snd_una = sock->tcb.iss;
    sock->tcb.snd_nxt = sock->tcb.iss + 1;
    sock->tcb.rcv_wnd = 4096;
    
    return tcp_connect(sock);
}
