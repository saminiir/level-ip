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
