#include "syshead.h"
#include "tcp.h"

int tcp_data_dequeue(struct tcp_sock *tsk, void *user_buf, int len)
{
    struct sock *sk = &tsk->sk;

    pthread_mutex_lock(&sk->receive_queue.lock);
    if (skb_queue_empty(&sk->receive_queue)) {
        pthread_mutex_unlock(&sk->receive_queue.lock);
        return 0;
    }
    
    printf("Items in receive queue: %d\n", sk->receive_queue.qlen);
    struct sk_buff *skb = skb_dequeue(&sk->receive_queue);
    pthread_mutex_unlock(&sk->receive_queue.lock);
    
    printf("Copying %d bytes of data %s\n", skb->dlen, skb->payload);

    memcpy(user_buf, skb->payload, skb->dlen);

    return skb->len;
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

    pthread_mutex_lock(&sk->receive_queue.lock);
    skb_queue_tail(&sk->receive_queue, skb);
    pthread_mutex_unlock(&sk->receive_queue.lock);

    if (th->psh) {
        tsk->flags |= TCP_PSH;
        return tsk->sk.ops->recv_notify(&tsk->sk);
    }
    
    return rc;
}

int tcp_data_close(struct tcp_sock *tsk, struct sk_buff *skb, struct tcphdr *th,
                   struct tcp_segment *seg)
{
    int rc = 0;

    th->psh = 1;

    if (tcp_data_queue(tsk, skb, th, seg)) {
        print_error("Fail on tcp data queueing\n");
    }

    return 0;
}
