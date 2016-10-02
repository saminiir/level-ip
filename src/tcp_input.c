#include "syshead.h"
#include "tcp.h"
#include "skbuff.h"
#include "sock.h"

static int tcp_listen(struct tcp_sock *tsk, struct sk_buff *skb, struct tcphdr *th)
{
    return 0;
}

static int tcp_synsent(struct tcp_sock *tsk, struct sk_buff *skb, struct tcphdr *th)
{
    struct tcb *tcb = &tsk->tcb;
    if (th->ack) {
        if (th->ack_seq <= tcb->iss || th->ack_seq > tcb->snd_nxt) {
            if (th->rst) goto discard;

            goto reset_and_discard;
        }

        if (!(tcb->snd_una <= th->ack_seq && th->ack_seq <= tcb->snd_nxt))
            goto reset_and_discard;
    }

    if (th->rst) {
        goto reset_and_discard;
    }

    if (!th->syn) {
        goto discard;
    }

    tcb->rcv_nxt = th->seq + 1;
    tcb->irs = th->seq;
    if (th->ack) {
        /* Any packets in RTO queue that are acknowledged here should be removed */
        tcb->snd_una = th->ack_seq;
    }

    if (tcb->snd_una > tcb->iss) {
        tsk->sk.state = TCP_ESTABLISHED;
        tcb->seq = tcb->snd_nxt;
        tcp_send_ack(&tsk->sk);
        wait_wakeup(&tsk->sk.sock->sleep);
    }
    
    return 0;
discard:
    return 0;
reset_and_discard:
    return 0;
}

static int tcp_drop(struct tcp_sock *tsk, struct sk_buff *skb)
{
    return 0;
}

/*
 * Follows RFC793 "Segment Arrives" section closely
 */ 
int tcp_input_state(struct sock *sk, struct sk_buff *skb)
{
    struct tcphdr *th = tcp_hdr(skb);
    struct tcp_sock *tsk = tcp_sk(sk);

    switch (sk->state) {
    case TCP_CLOSE:
        goto discard;
    case TCP_LISTEN:
        return tcp_listen(tsk, skb, th);
    case TCP_SYN_SENT:
        return tcp_synsent(tsk, skb, th);
    }

    /* "Otherwise" section in RFC793 */
    return 0;
    
discard:
    return tcp_drop(tsk, skb);
}
