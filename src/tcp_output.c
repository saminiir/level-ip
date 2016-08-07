#include "syshead.h"
#include "utils.h"
#include "tcp.h"
#include "skbuff.h"

static int tcp_transmit_skb(struct tcp_socket *sock, struct sk_buff *buff)
{
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

    return 0;
}

static int tcp_send_syn(struct tcp_socket *sock)
{
    if (sock->state != CLOSED && sock->state != LISTEN) {
        print_error("Socket was not in correct state (closed or listen)");
        return 1;
    }

    struct sk_buff *skb;

    skb = alloc_skb(TCP_HDR_LEN + IP_HDR_LEN + ETH_HDR_LEN);

    sock->state = SYN_SENT;

    return tcp_transmit_skb(sock, skb);
}

void tcp_select_initial_window(uint32_t *rcv_wnd)
{
    *rcv_wnd = 512;
}

int tcp_connect(struct tcp_socket *sk)
{
    tcp_select_initial_window(&sk->tcb.rcv_wnd);
    return tcp_send_syn(sk);
}
