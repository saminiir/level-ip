#include "syshead.h"
#include "tcp.h"

static void *tcp_alloc_buf(int rcv_wnd)
{
    return malloc(rcv_wnd);
}

int tcp_write_buf(struct tcp_sock *tsk, uint8_t *data, int len)
{
    uint8_t *buf = tsk->rcv_buf;
    struct tcb *tcb = &tsk->tcb;
    
    if (!buf) {
        buf = tcp_alloc_buf(tcb->rcv_wnd);
        tsk->rcv_buf = buf;
    }

    memcpy(buf, data, len);
    
    return 0;
}


int tcp_read_buf(uint8_t *rcv_buf, void *user_buf, int len)
{
    if (!rcv_buf) return 0;

    int rlen = strnlen((char *)rcv_buf, len);

    memcpy(user_buf, rcv_buf, rlen);

    return rlen;
}

int tcp_data_queue(struct tcp_sock *tsk, struct tcphdr *th, struct tcp_segment *seg)
{
    struct tcb *tcb = &tsk->tcb;
    
    /* if (seg->seq == tcb->rcv_nxt) { */
    /*     if (!tcb->rcv_wnd) { */
    /*         goto out; */
    /*     } */

    /* } */

    tcp_write_buf(tsk, th->data, seg->dlen);

    if (th->psh) tsk->flags |= TCP_PSH;
    
    return tsk->sk.ops->recv_notify(&tsk->sk);
}

int tcp_data_close(struct tcp_sock *tsk, struct tcphdr *th, struct tcp_segment *seg)
{
    return 0;
}
