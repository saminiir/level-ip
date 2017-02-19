#include "syshead.h"
#include "tcp.h"
#include "tcp_data.h"
#include "skbuff.h"
#include "sock.h"

static inline int tcp_drop(struct tcp_sock *tsk, struct sk_buff *skb)
{
    free_skb(skb);
    return 0;
}

static int tcp_verify_segment(struct tcp_sock *tsk, struct tcphdr *th, struct tcp_segment *seg)
{
    /* struct tcb *tcb = &tsk->tcb; */

    return 0;
}

/* TCP RST received */
static void tcp_reset(struct sock *sk)
{
    switch (sk->state) {
    case TCP_SYN_SENT:
        sk->err = -ECONNREFUSED;
        wait_wakeup(&sk->sock->sleep);
        break;
    case TCP_CLOSE_WAIT:
        sk->err = -EPIPE;
        break;
    case TCP_CLOSE:
        return;
    default:
        sk->err = -ECONNRESET;
    }

    tcp_done(sk);
}

static inline int tcp_discard(struct tcp_sock *tsk, struct sk_buff *skb, struct tcphdr *th)
{
    free_skb(skb);
    return 0;
}

static int tcp_listen(struct tcp_sock *tsk, struct sk_buff *skb, struct tcphdr *th)
{
    tcpstate_dbg("state is listen");
    free_skb(skb);
    return 0;
}

static int tcp_synsent(struct tcp_sock *tsk, struct sk_buff *skb, struct tcphdr *th)
{
    struct tcb *tcb = &tsk->tcb;
    struct sock *sk = &tsk->sk;

    tcpstate_dbg("state is synsent");
    
    if (th->ack) {
        if (th->ack_seq <= tcb->iss || th->ack_seq > tcb->snd_nxt) {
            if (th->rst) goto discard;

            goto reset_and_discard;
        }

        if (!(tcb->snd_una <= th->ack_seq && th->ack_seq <= tcb->snd_nxt))
            goto reset_and_discard;
    }

    /* ACK is acceptable */
    
    if (th->rst) {
        tcp_reset(&tsk->sk);
        goto discard;
    }

    /* third check the security and precedence -> ignored */

    /* fourth check the SYN bit */
    if (!th->syn) {
        goto discard;
    }

    tcb->rcv_nxt = th->seq + 1;
    tcb->irs = th->seq;
    if (th->ack) {
        tcb->snd_una = th->ack_seq;
        /* Any packets in RTO queue that are acknowledged here should be removed */
    }

    if (tcb->snd_una > tcb->iss) {
        tcp_set_state(sk, TCP_ESTABLISHED);
        tcb->seq = tcb->snd_nxt;
        tcp_send_ack(&tsk->sk);
        tsk->sk.err = 0;
        wait_wakeup(&tsk->sk.sock->sleep);
    } else {
        tcp_set_state(sk, TCP_SYN_RECEIVED);
        tcb->seq = tcb->iss;
        tcp_send_ack(&tsk->sk);
    }
    
discard:
    tcp_drop(tsk, skb);
    return 0;
reset_and_discard:
    //TODO reset
    tcp_drop(tsk, skb);
    return 0;
}

static int tcp_closed(struct tcp_sock *tsk, struct sk_buff *skb, struct tcphdr *th)
{
    /*
      All data in the incoming segment is discarded.  An incoming
      segment containing a RST is discarded.  An incoming segment not
      containing a RST causes a RST to be sent in response.  The
      acknowledgment and sequence field values are selected to make the
      reset sequence acceptable to the TCP that sent the offending
      segment.

      If the ACK bit is off, sequence number zero is used,

        <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>

      If the ACK bit is on,

        <SEQ=SEG.ACK><CTL=RST>

      Return.
    */

    int rc = -1;

    tcpstate_dbg("state is closed");

    if (th->rst) {
        tcp_discard(tsk, skb, th);
    }

    if (th->ack) {
 
    } else {
        
    
    }
    
    rc = tcp_send_reset(tsk);

    free_skb(skb);
    
    return rc;
}

/*
 * Follows RFC793 "Segment Arrives" section closely
 */ 
int tcp_input_state(struct sock *sk, struct sk_buff *skb, struct tcp_segment *seg)
{
    struct tcphdr *th = tcp_hdr(skb);
    struct tcp_sock *tsk = tcp_sk(sk);
    struct tcb *tcb = &tsk->tcb;

    tcptcb_dbg("INPUT", tcb);

    switch (sk->state) {
    case TCP_CLOSE:
        return tcp_closed(tsk, skb, th);
    case TCP_LISTEN:
        return tcp_listen(tsk, skb, th);
    case TCP_SYN_SENT:
        return tcp_synsent(tsk, skb, th);
    }

    /* "Otherwise" section in RFC793 */

    /* first check sequence number */
    if (tcp_verify_segment(tsk, th, seg) < 0) {
        return tcp_drop(tsk, skb);
    }
    
    /* second check the RST bit */

    if (th->rst) {

    }
    
    /* third check security and precedence */
    // Not implemented

    /* fourth check the SYN bit */
    if (th->syn) {

    }
    
    /* fifth check the ACK field */
    if (!th->ack) {
        return tcp_drop(tsk, skb);
    }

    // ACK bit is on
    
    switch (sk->state) {
    case TCP_SYN_RECEIVED:
    case TCP_ESTABLISHED:
        if (tcb->snd_una < seg->ack && seg->ack <= tcb->snd_nxt) {
            tcb->snd_una = seg->ack;
            tcb->seq = tcb->snd_una;
            /* TODO: Any segments on the retransmission queue which are thereby
               entirely acknowledged are removed. */

            /* TODO: Users should receive positive acknowledgements for buffers
               which have been sent and fully acknowledged */
        }

        if (seg->ack < tcb->snd_una) {
            // If the ACK is a duplicate, it can be ignored
            return tcp_drop(tsk, skb);
        }

        if (seg->ack > tcb->snd_nxt) {
            // If the ACK acks something not yet sent, then send an ACK, drop segment
            // and return
            tcp_send_ack(&tsk->sk);
            return tcp_drop(tsk, skb);
        }

        if (tcb->snd_una < seg->ack && seg->ack <= tcb->snd_nxt) {
            // Send window should be updated

        }
    }
    
    /* sixth, check the URG bit */
    if (th->urg) {

    }

    pthread_mutex_lock(&sk->receive_queue.lock);
    /* seventh, process the segment txt */
    switch (sk->state) {
    case TCP_ESTABLISHED:
    case TCP_FIN_WAIT_1:
    case TCP_FIN_WAIT_2:
        tcp_data_queue(tsk, skb, th, seg);
        tcb->rcv_nxt += seg->dlen;
        tcp_send_ack(&tsk->sk);
        tsk->sk.ops->recv_notify(&tsk->sk);
            
        break;
    case TCP_CLOSE_WAIT:
    case TCP_CLOSING:
    case TCP_LAST_ACK:
    case TCP_TIME_WAIT:
        /* This should not occur, since a FIN has been received from the
           remote side.  Ignore the segment text. */
        break;
    }

    /* eighth, check the FIN bit */
    if (th->fin) {
        switch (sk->state) {
        case TCP_CLOSE:
        case TCP_LISTEN:
        case TCP_SYN_SENT:
            // Do not process, since SEG.SEQ cannot be validated
            goto drop_and_unlock;
        }

        tcb->rcv_nxt += 1;
        tcp_send_finack(&tsk->sk);
        tsk->flags |= TCP_FIN;
        
        switch (sk->state) {
        case TCP_SYN_RECEIVED:
        case TCP_ESTABLISHED:
            tsk->sk.state = TCP_CLOSE_WAIT;
            break;
        case TCP_FIN_WAIT_1:
            /* TODO:  If our FIN has been ACKed (perhaps in this segment), then
               enter TIME-WAIT, start the time-wait timer, turn off the other
               timers; otherwise enter the CLOSING state. */
            break;
        case TCP_FIN_WAIT_2:
            /* TODO: Enter the TIME-WAIT state.  Start the time-wait timer, turn
               off the other timers. */
            break;
        case TCP_CLOSE_WAIT:
        case TCP_CLOSING:
        case TCP_LAST_ACK:
            /* Remain in the state */
            break;
        case TCP_TIME_WAIT:
            /* TODO: Remain in the TIME-WAIT state.  Restart the 2 MSL time-wait
               timeout. */
            break;
        }
    }

unlock:
    pthread_mutex_unlock(&sk->receive_queue.lock);
    return 0;
drop_and_unlock:
    tcp_drop(tsk, skb);
    goto unlock;
}

int tcp_receive(struct tcp_sock *tsk, void *buf, int len)
{
    int rlen = 0;
    int curlen = 0;

    memset(buf, 0, len);

    while (rlen < len) {
        curlen = tcp_data_dequeue(tsk, buf + rlen, len - 1 - rlen);

        rlen += curlen;

        if (tsk->flags & TCP_PSH) {
            tsk->flags &= ~TCP_PSH;
            break;
        }

        if (tsk->flags & TCP_FIN) break;

        wait_sleep(&tsk->sk.recv_wait);
    }
    
    return rlen;
}
