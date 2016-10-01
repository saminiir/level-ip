#ifndef TCP_H_
#define TCP_H_
#include "syshead.h"
#include "ip.h"

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
    uint32_t ack_seq;
    uint8_t rsvd : 4;
    uint8_t hl : 4;
    uint8_t fin : 1,
            syn : 1,
            rst : 1,
            psh : 1,
            ack : 1,
            urg : 1,
            ece : 1,
            cwr : 1;
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
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECEIVED,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_LAST_ACK,
};

struct tcb {
    uint8_t tcp_flags;
    uint8_t *snd_buf;
    uint8_t *rcv_buf;
    uint32_t seq;
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

struct tcp_sock {
    struct sock sk;
    int fd;
    uint16_t tcp_header_len;
    struct tcb tcb;
};

static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
    return (struct tcphdr *)(skb->head + ETH_HDR_LEN + IP_HDR_LEN);

}
#define tcp_sk(sk) ((struct tcp_sock *)sk)

void tcp_init();
void tcp_in(struct sk_buff *skb);
int tcp_checksum(struct tcp_sock *sock, struct tcphdr *thdr);
void tcp_select_initial_window(uint32_t *rcv_wnd);

int generate_iss();
struct sock *tcp_alloc_sock();
int tcp_v4_init_sock(struct sock *sk);
int tcp_init_sock(struct sock *sk);
int tcp_v4_checksum(struct sk_buff *skb, uint32_t saddr, uint32_t daddr);
int tcp_v4_connect(struct sock *sk, const struct sockaddr *addr, int addrlen, int flags);
int tcp_connect(struct sock *sk);
int tcp_disconnect(struct sock *sk, int flags);
int tcp_input_state(struct sock *sk, struct sk_buff *skb);
int tcp_send_ack(struct sock *sk);
#endif
