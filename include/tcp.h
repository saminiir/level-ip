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

#define tcp_sk(sk) ((struct tcp_sock *)sk)
#define tcp_hlen(tcp) (tcp->hl << 2)

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
    TCP_LISTEN, /* represents waiting for a connection request from any remote
                   TCP and port. */
    TCP_SYN_SENT, /* represents waiting for a matching connection request
                     after having sent a connection request. */
    TCP_SYN_RECEIVED, /* represents waiting for a confirming connection
                         request acknowledgment after having both received and sent a
                         connection request. */
    TCP_ESTABLISHED, /* represents an open connection, data received can be
                        delivered to the user.  The normal state for the data transfer phase
                        of the connection. */
    TCP_FIN_WAIT_1, /* represents waiting for a connection termination request
                       from the remote TCP, or an acknowledgment of the connection
                       termination request previously sent. */
    TCP_FIN_WAIT_2, /* represents waiting for a connection termination request
                       from the remote TCP. */
    TCP_CLOSE, /* represents no connection state at all. */
    TCP_CLOSE_WAIT, /* represents waiting for a connection termination request
                       from the local user. */
    TCP_CLOSING, /* represents waiting for a connection termination request
                    acknowledgment from the remote TCP. */
    TCP_LAST_ACK, /* represents waiting for an acknowledgment of the
                     connection termination request previously sent to the remote TCP
                     (which includes an acknowledgment of its connection termination
                     request). */
    TCP_TIME_WAIT, /* represents waiting for enough time to pass to be sure
                      the remote TCP received the acknowledgment of its connection
                      termination request. */
};

/* Current Segment Variables */
struct tcp_segment {
    uint32_t seq; /* first sequence number of a segment */
    uint32_t ack; /* acknowledgment from the receiving TCP (next sequence
                     number expected by the receiving TCP) */
    uint32_t dlen;
    uint32_t len; /* the number of octets occupied by the data in the segment
                     (counting SYN and FIN) */
    uint32_t win;
    uint32_t up;
    uint32_t prc; /* precedence value, not used */
    uint32_t seq_last; /* last sequence number of a segment */
};

struct tcb {
    uint8_t *snd_buf;
    uint8_t *rcv_buf;
    uint32_t seq;
    uint32_t snd_una; /* oldest unacknowledged sequence number */
    uint32_t snd_nxt; /* next sequence number to be sent */
    uint32_t snd_wnd;
    uint32_t snd_up;
    uint32_t snd_wl1;
    uint32_t snd_wl2;
    uint32_t iss;
    uint32_t rcv_nxt; /* next sequence number expected on an incoming segments, and
                         is the left or lower edge of the receive window */
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
int tcp_write(struct sock *sk, const void *buf, int len);
int tcp_read(struct sock *sk, void *buf, int len);
int tcp_receive(struct tcp_sock *tsk, void *buf, int len);
int tcp_input_state(struct sock *sk, struct sk_buff *skb, struct tcp_segment *seg);
int tcp_send_ack(struct sock *sk);
int tcp_send(struct tcp_sock *tsk, const void *buf, int len);
int tcp_send_reset(struct tcp_sock *tsk, struct tcphdr *th);
#endif
