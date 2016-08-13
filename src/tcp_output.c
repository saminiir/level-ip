#include "syshead.h"
#include "utils.h"
#include "tcp.h"
#include "ipv4.h"
#include "skbuff.h"

static int tcp_transmit_skb(struct tcp_socket *sk, struct sk_buff *skb)
{
    struct tcphdr *thdr = (struct tcphdr *)skb->data;
    struct tcb *tcb = &sk->tcb;

    thdr->sport = sk->sport;
    thdr->dport = sk->dport;
    thdr->seq = tcb->snd_nxt;
    thdr->ack = tcb->rcv_nxt;
    thdr->rsvd = 0;
    thdr->hl = 6;
    thdr->flags = tcb->tcp_flags;
    thdr->win = tcb->rcv_wnd;
    thdr->csum = 0;
    thdr->urp = 0;

    return ip_queue_xmit(skb);
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
