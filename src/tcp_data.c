#include "syshead.h"
#include "tcp.h"

int tcp_data_dequeue(struct tcp_sock *tsk, void *user_buf, int len)
{
    struct sock *sk = &tsk->sk;
    struct tcphdr *th;
    int rlen = 0;

    pthread_mutex_lock(&sk->receive_queue.lock);

    while (!skb_queue_empty(&sk->receive_queue)) {
        struct sk_buff *skb = skb_dequeue(&sk->receive_queue);
        th = tcp_hdr(skb);

        if (th->fin) tsk->flags |= TCP_FIN;
        if (th->psh) tsk->flags |= TCP_PSH;

        memcpy(user_buf, skb->payload, skb->dlen);
        rlen += skb->dlen;
        user_buf += skb->dlen;
        free_skb(skb);
    }
    
    pthread_mutex_unlock(&sk->receive_queue.lock);

    return rlen;
}

int tcp_data_queue(struct tcp_sock *tsk, struct sk_buff *skb,
                   struct tcphdr *th, struct tcp_segment *seg)
{
    struct sock *sk = &tsk->sk;
    struct tcb *tcb = &tsk->tcb;
    int rc = 0;
    
    /* if (seg->seq == tcb->rcv_nxt) { */
    /*     if (!tcb->rcv_wnd) { */
    /*         goto out; */
    /*     } */

    /* } */

    skb->dlen = seg->dlen;
    skb->payload = th->data;
        
    skb_queue_tail(&sk->receive_queue, skb);
    
    return rc;
}
