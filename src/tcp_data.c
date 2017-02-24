#include "syshead.h"
#include "tcp.h"

int tcp_data_dequeue(struct tcp_sock *tsk, void *user_buf, int userlen)
{
    struct sock *sk = &tsk->sk;
    struct tcphdr *th;
    int rlen = 0;

    pthread_mutex_lock(&sk->receive_queue.lock);

    while (!skb_queue_empty(&sk->receive_queue) && rlen < userlen) {
        struct sk_buff *skb = skb_peek(&sk->receive_queue);
        if (skb == NULL) break;
        
        th = tcp_hdr(skb);

        /* Guard datalen to not overflow userbuf */
        int dlen = (rlen + skb->dlen) > userlen ? (userlen - rlen) : skb->dlen;
        memcpy(user_buf, skb->payload, dlen);

        /* Accommodate next round of data dequeue */
        skb->dlen -= dlen;
        skb->payload += dlen;
        rlen += dlen;
        user_buf += dlen;

        /* skb is fully eaten, process flags and drop it */
        if (skb->dlen == 0) {
            if (th->psh) tsk->flags |= TCP_PSH;
            skb_dequeue(&sk->receive_queue);
            free_skb(skb);
        }
    }
    
    pthread_mutex_unlock(&sk->receive_queue.lock);

    return rlen;
}

int tcp_data_queue(struct tcp_sock *tsk, struct sk_buff *skb,
                   struct tcphdr *th, struct tcp_segment *seg)
{
    struct sock *sk = &tsk->sk;
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
