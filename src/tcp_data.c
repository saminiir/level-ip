#include "syshead.h"
#include "tcp.h"
#include "list.h"

/* Routine for inserting skbs ordered by seq into queue */
static void tcp_data_insert_ordered(struct sk_buff_head *queue, struct sk_buff *skb)
{
    struct sk_buff *next;
    struct list_head *item, *tmp;

    list_for_each_safe(item, tmp, &queue->head) {
        next = list_entry(item, struct sk_buff, list);

        if (skb->seq < next->seq) {
            list_add(&skb->list, &next->list);

            return;
        }
    }

    list_add_tail(&skb->list, &queue->head);
}

/* Routine for transforming out-of-order segments into order */
static void tcp_consume_ofo_queue(struct tcp_sock *tsk)
{
    if (skb_queue_empty(&tsk->ofo_queue)) return;

    struct sock *sk = &tsk->sk;
    struct tcb *tcb = &tsk->tcb;
    struct sk_buff *skb = skb_peek(&tsk->ofo_queue);

    while (tcb->rcv_nxt == skb->seq) {
       /* skb is in-order, consume it */
       tcb->rcv_nxt += skb->dlen;
       skb_queue_tail(&sk->receive_queue, skb);
       skb_dequeue(&tsk->ofo_queue);
       skb = skb_peek(&tsk->ofo_queue);
    }
}

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
    struct tcb *tcb = &tsk->tcb;
    int rc = 0;

    skb->dlen = seg->dlen;
    skb->payload = th->data;
    skb->seq = seg->seq;
    skb->end_seq = seg->seq + seg->dlen;
    
    if (seg->seq == tcb->rcv_nxt) {
        if (!tcb->rcv_wnd) {
            return -1;
        }

        tcb->rcv_nxt += seg->dlen;
        skb_queue_tail(&sk->receive_queue, skb);
        tcp_consume_ofo_queue(tsk);

        tcp_stop_delack_timer(tsk);
        tsk->delack = timer_add(200, &tcp_send_delack, &tsk->sk);
    } else {
        /* Segment is in-window but not the left-most sequence */
        tcp_data_insert_ordered(&tsk->ofo_queue, skb);
    }
    
    return rc;
}
