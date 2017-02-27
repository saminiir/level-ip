#ifndef TCP_H_
#define TCP_H_
#include "syshead.h"
#include "ip.h"
#include "timer.h"

#define TCP_HDR_LEN sizeof(struct tcphdr)

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

#define TCP_URG 0x20
#define TCP_ECN 0x40
#define TCP_WIN 0x80

#define TCP_SYN_BACKOFF 1000
#define TCP_CONN_RETRIES 3

#define tcp_sk(sk) ((struct tcp_sock *)sk)
#define tcp_hlen(tcp) (tcp->hl << 2)

#define tcphdr_dbg(msg, hdr) \
    do { \
        print_debug("\t\t\tTCP "msg": sport: %hu, dport: %hu, seq: %u, ack: %hu\n" \
                    "\t\t\t            rsvd: %hhu, hl: %hhu, CEUAPRSF: %hhu%hhu%hhu%hhu%hhu%hhu%hhu%hhu,\n" \
                    "\t\t\t            win: %hu, csum: %.4hx, urp: %hu\n\n", \
                    hdr->sport, hdr->dport, hdr->seq,                 \
                    hdr->ack_seq, hdr->rsvd, hdr->hl, hdr->cwr, hdr->ece, hdr->urg, \
                    hdr->ack, hdr->psh, hdr->rst, hdr->syn, hdr->fin, hdr->win, \
                    hdr->csum, hdr->urp);                               \
    } while (0)

#define tcpseg_dbg(msg, seg) \
    do {                                                                \
        print_debug("\t\t\t\tTCP Seg "msg": seq: %u, ack: %u, dlen: %u,\n" \
                    "\t\t\t\t                len: %u, win: %u,\n" \
                    "\t\t\t\t                up: %u, prc: %u, seq_last: %u\n\n", \
                    seg->seq, seg->ack, seg->dlen, seg->len,            \
                    seg->win, seg->up, seg->prc, seg->seq_last);        \
    } while (0)

#define tcptcb_dbg(msg, tcb) \
    do {                                                                \
        print_debug("\t\t\t\tTCP TCB "msg": seq: %u, snd_una: %u, snd_nxt: %u,\n" \
                    "\t\t\t\t                snd_wnd: %u, snd_up: %u,\n" \
                    "\t\t\t\t                snd_wl1: %u, snd_wl2: %u, iss: %u, rcv_nxt: %u,\n" \
                    "\t\t\t\t                rcv_wnd: %u, rcv_up: %u, irs: %u\n\n", \
                    tcb->seq, tcb->snd_una, tcb->snd_nxt, tcb->snd_wnd, tcb->snd_up, tcb->snd_wl1, \
                    tcb->snd_wl2, tcb->iss, tcb->rcv_nxt, tcb->rcv_wnd, tcb->rcv_up, tcb->irs); \
    } while (0)

#define tcpstate_dbg(msg)                       \
    do {                                        \
        print_debug("\t\t\t\tTCPSTATE: "msg"\n");       \
    } while (0)

#define tcpsock_dbg(msg, sock)                       \
    do {                                        \
        print_debug("\t\t\t\tTCPSOCK "msg": %d\n", sock->fd);       \
    } while (0)


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
    uint8_t flags;
    uint8_t backoff;
    struct timer *retransmit;
    struct timer *delack;
    struct timer *keepalive;
    struct sk_buff_head ofo_queue; /* Out-of-order queue */
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
void tcp_set_state(struct sock *sk, uint32_t state);
int tcp_v4_checksum(struct sk_buff *skb, uint32_t saddr, uint32_t daddr);
int tcp_v4_connect(struct sock *sk, const struct sockaddr *addr, int addrlen, int flags);
int tcp_connect(struct sock *sk);
int tcp_disconnect(struct sock *sk, int flags);
int tcp_write(struct sock *sk, const void *buf, int len);
int tcp_read(struct sock *sk, void *buf, int len);
int tcp_receive(struct tcp_sock *tsk, void *buf, int len);
int tcp_input_state(struct sock *sk, struct sk_buff *skb, struct tcp_segment *seg);
int tcp_send_synack(struct sock *sk);
int tcp_send_ack(struct sock *sk);
void tcp_send_delack(uint32_t ts, void *arg);
int tcp_send_finack(struct sock *sk);
int tcp_send(struct tcp_sock *tsk, const void *buf, int len);
int tcp_send_reset(struct tcp_sock *tsk);
int tcp_send_challenge_ack(struct sock *sk, struct sk_buff *skb);
int tcp_recv_notify(struct sock *sk);
int tcp_close(struct sock *sk);
int tcp_abort(struct sock *sk);
void tcp_done(struct sock *sk);
void tcp_clear_timers(struct sock *sk);

#endif
