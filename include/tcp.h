#ifndef TCP_H_
#define TCP_H_
#include "syshead.h"
#include "netdev.h"
#include "ipv4.h"

#define TCP_HDR_LEN sizeof(struct tcphdr)

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

#define TCP_URG 0x20
#define TCP_ECN 0x40
#define TCP_WIN 0x80

struct tcphdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t rsvd : 4;
    uint8_t hl : 4;
    uint8_t flags;
    uint16_t win;
    uint16_t csum;
    uint16_t urp;
    uint8_t data[];
} __attribute__((packed));

struct tcpiphdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t proto;
    uint16_t tlen;
} __attribute__((packed));

enum tcp_states {
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK
};

struct tcb {
    uint8_t tcp_flags;
    uint8_t *snd_buf;
    uint8_t *rcv_buf;
    uint32_t snd_una;
    uint32_t snd_nxt;
    uint32_t snd_wnd;
    uint32_t snd_up;
    uint32_t snd_wl1;
    uint32_t snd_wl2;
    uint32_t iss;
    uint32_t rcv_nxt;
    uint32_t rcv_wnd;
    uint32_t rcv_up;
    uint32_t irs;
};

struct tcp_socket {
    enum tcp_states state;
    int fd;
    uint16_t sport;
    uint16_t dport;
    uint32_t saddr;
    uint32_t daddr;
    uint16_t tcp_header_len;
    struct tcb tcb;
};

void tcp_init();
void tcp_in(struct netdev *netdev, struct eth_hdr *hdr);
int tcp_checksum(struct iphdr *iphdr, struct tcphdr *thdr);
void tcp_select_initial_window(uint32_t *rcv_wnd);

void init_tcp_sockets();
struct tcp_socket *alloc_tcp_socket();
void free_tcp_socket(struct tcp_socket *sock);
struct tcp_socket *get_tcp_socket(int sockfd);
int tcp_v4_connect(struct tcp_socket *sock, const struct sockaddr *addr, socklen_t addrlen);
int tcp_connect(struct tcp_socket *sock);
#endif
