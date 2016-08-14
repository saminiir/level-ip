#include "syshead.h"
#include "utils.h"
#include "tcp.h"
#include "ipv4.h"
#include "skbuff.h"

static struct sk_buff *tcp_alloc_skb(int size)
{
    struct sk_buff *skb = alloc_skb(size + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    skb_reserve(skb, ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);

    return skb;
}

static int tcp_transmit_skb(struct tcp_socket *sk, struct sk_buff *skb)
{
    struct tcb *tcb = &sk->tcb;

    skb_push(skb, sk->tcp_header_len);

    struct tcphdr *thdr = (struct tcphdr *)skb->data;

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

    skb = tcp_alloc_skb(0);

    sock->state = SYN_SENT;
    
    return tcp_transmit_skb(sock, skb);
}

void tcp_select_initial_window(uint32_t *rcv_wnd)
{
    *rcv_wnd = 512;
}

int tcp_connect(struct tcp_socket *sk)
{
    sk->tcp_header_len = sizeof(struct tcphdr);
    sk->tcb.iss = generate_iss();
    sk->tcb.snd_wnd = 0;
    sk->tcb.snd_wl1 = 0;
    
    sk->tcb.snd_una = sk->tcb.iss;
    sk->tcb.snd_up = sk->tcb.iss;
    sk->tcb.snd_nxt = sk->tcb.iss;
    sk->tcb.rcv_nxt = 0;

    tcp_select_initial_window(&sk->tcb.rcv_wnd);
    return tcp_send_syn(sk);
}
