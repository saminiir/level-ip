#include "syshead.h"
#include "utils.h"
#include "tcp.h"
#include "ip.h"
#include "skbuff.h"

static struct sk_buff *tcp_alloc_skb(int size)
{
    struct sk_buff *skb = alloc_skb(size + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    skb_reserve(skb, size + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    skb->protocol = IP_TCP;

    return skb;
}

static int tcp_transmit_skb(struct sock *sk, struct sk_buff *skb)
{
    struct tcp_sock *tsk = tcp_sk(sk);
    struct tcb *tcb = &tsk->tcb;

    skb_push(skb, tsk->tcp_header_len);

    struct tcphdr *thdr = (struct tcphdr *)skb->data;

    thdr->sport = htons(sk->sport);
    thdr->dport = htons(sk->dport);
    thdr->seq = htonl(tcb->seq);
    thdr->ack_seq = htonl(tcb->rcv_nxt);
    thdr->hl = 5;
    thdr->rsvd = 0;
    thdr->win = htons(tcb->rcv_wnd);
    thdr->csum = 0;
    thdr->urp = 0;

    /* Calculate checksum */
    thdr->csum = tcp_v4_checksum(skb, htonl(sk->saddr), htonl(sk->daddr));

    return ip_output(sk, skb);
}

int tcp_send_ack(struct sock *sk)
{
    if (sk->state == TCP_CLOSE) return 0;
    
    struct sk_buff *skb;
    struct tcphdr *th;

    skb = tcp_alloc_skb(0);
    
    th = tcp_hdr(skb);
    th->ack = 1;

    return tcp_transmit_skb(sk, skb);
}

static int tcp_send_syn(struct sock *sk)
{
    if (sk->state != TCP_CLOSE && sk->state != TCP_LISTEN) {
        print_error("Socket was not in correct state (closed or listen)");
        return 1;
    }

    struct sk_buff *skb;
    struct tcphdr *th;

    skb = tcp_alloc_skb(0);
    th = tcp_hdr(skb);

    sk->state = TCP_SYN_SENT;
    th->syn = 1;
    
    return tcp_transmit_skb(sk, skb);
}

void tcp_select_initial_window(uint32_t *rcv_wnd)
{
    *rcv_wnd = 512;
}

int tcp_connect(struct sock *sk)
{
    struct tcp_sock *tsk = tcp_sk(sk);
    struct tcb *tcb = &tsk->tcb;
    
    tsk->tcp_header_len = sizeof(struct tcphdr);
    tcb->iss = generate_iss();
    tcb->snd_wnd = 0;
    tcb->snd_wl1 = 0;

    tcb->snd_una = tcb->iss;
    tcb->snd_up = tcb->iss;
    tcb->snd_nxt = tcb->iss + 1;
    tcb->rcv_nxt = 0;
    tcb->seq = tcb->iss;

    tcp_select_initial_window(&tsk->tcb.rcv_wnd);
    return tcp_send_syn(sk);
}

int tcp_send(struct tcp_sock *tsk, const void *buf, int len)
{
    struct sk_buff *skb;
    struct tcb *tcb = &tsk->tcb;
    struct tcphdr *th;
    int ret = -1;

    skb = tcp_alloc_skb(len);
    skb_push(skb, len);
    memcpy(skb->data, buf, len);

    th = tcp_hdr(skb);
    th->ack = 1;
    tcb->seq = tcb->snd_nxt;
    tcb->snd_nxt += len;

    ret = tcp_transmit_skb(&tsk->sk, skb);

    ret -= (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);

    if (ret != len) {
        return -1;
    }

    return ret;
}
