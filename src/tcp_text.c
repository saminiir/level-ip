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

    memcpy(user_buf, rcv_buf, len);

    return 0;
}
