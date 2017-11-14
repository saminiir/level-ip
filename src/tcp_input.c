#include "syshead.h"
#include "tcp.h"
#include "tcp_data.h"
#include "skbuff.h"
#include "sock.h"

static int tcp_parse_opts(struct tcp_sock *tsk, struct tcphdr *th)
{
    uint8_t *ptr = th->data;
    uint8_t optlen = tcp_hlen(th) - 20;
    struct tcp_opt_mss *opt_mss = NULL;
    uint8_t sack_seen = 0;
    uint8_t tsopt_seen = 0;
    
    while (optlen > 0 && optlen < 20) {
        switch (*ptr) {
        case TCP_OPT_MSS:
            opt_mss = (struct tcp_opt_mss *)ptr;
            uint16_t mss = ntohs(opt_mss->mss);

            if (mss > 536 && mss <= 1460) {
                tsk->smss = mss;
            }

            ptr += sizeof(struct tcp_opt_mss);
            optlen -= 4;
            break;
        case TCP_OPT_NOOP:
            ptr += 1;
            optlen--;
            break;
        case TCP_OPT_SACK_OK:
            sack_seen = 1;
            optlen--;
            break;
        case TCP_OPT_TS:
            tsopt_seen = 1;
            optlen--;
            break;
        default:
            print_err("Unrecognized TCPOPT\n");
            optlen--;
            break;
        }
    }

    if (!tsopt_seen) {
        tsk->tsopt = 0;
    }

    if (sack_seen && tsk->sackok) {
        // There's room for 4 sack blocks without TS OPT
        if (tsk->tsopt) tsk->sacks_allowed = 3;
        else tsk->sacks_allowed = 4;
    } else {
        tsk->sackok = 0;
    }

    return 0;
}

/*
 * Acks all segments from retransmissionn queue that are "older"
 * than current unacknowledged sequence
 */ 
static int tcp_clean_rto_queue(struct sock *sk, uint32_t una)
{
    struct tcp_sock *tsk = tcp_sk(sk);
    struct sk_buff *skb;
    int rc = 0;
    
    while ((skb = skb_peek(&sk->write_queue)) != NULL) {
        if (skb->seq > 0 && skb->end_seq <= una) {
            /* skb fully acknowledged */
            skb_dequeue(&sk->write_queue);
            skb->refcnt--;
            free_skb(skb);
            if (tsk->inflight > 0) {
                tsk->inflight--;
            }
        } else {
            break;
        }
    };

    if (skb == NULL || tsk->inflight == 0) {
        /* No unacknowledged skbs, stop rto timer */
        tcp_stop_rto_timer(tsk);
    }

    return rc;
}

static inline int __tcp_drop(struct sock *sk, struct sk_buff *skb)
{
    free_skb(skb);
    return 0;
}

static int tcp_verify_segment(struct tcp_sock *tsk, struct tcphdr *th, struct sk_buff *skb)
{
    struct tcb *tcb = &tsk->tcb;

    if (skb->dlen > 0 && tcb->rcv_wnd == 0) return 0;

    if (th->seq < tcb->rcv_nxt ||
        th->seq > (tcb->rcv_nxt + tcb->rcv_wnd)) {
        tcpsock_dbg("Received invalid segment", (&tsk->sk));
        return 0;
    }

    return 1;
}

/* TCP RST received */
static void tcp_reset(struct sock *sk)
{
    sk->poll_events = (POLLOUT | POLLWRNORM | POLLERR | POLLHUP);
    switch (sk->state) {
    case TCP_SYN_SENT:
        sk->err = -ECONNREFUSED;
        break;
    case TCP_CLOSE_WAIT:
        sk->err = -EPIPE;
        break;
    case TCP_CLOSE:
        return;
    default:
        sk->err = -ECONNRESET;
        break;
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
    free_skb(skb);
    return 0;
}

static int tcp_synsent(struct tcp_sock *tsk, struct sk_buff *skb, struct tcphdr *th)
{
    struct tcb *tcb = &tsk->tcb;
    struct sock *sk = &tsk->sk;

    tcpsock_dbg("state is synsent", sk);
    
    if (th->ack) {
        if (th->ack_seq <= tcb->iss || th->ack_seq > tcb->snd_nxt) {
            tcpsock_dbg("ACK is unacceptable", sk);
            
            if (th->rst) goto discard;
            goto reset_and_discard;
        }

        if (th->ack_seq < tcb->snd_una || th->ack_seq > tcb->snd_nxt) {
            tcpsock_dbg("ACK is unacceptable", sk);
            goto reset_and_discard;
        }
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
        tcp_clean_rto_queue(sk, tcb->snd_una);
    }

    if (tcb->snd_una > tcb->iss) {
        tcp_set_state(sk, TCP_ESTABLISHED);
        tcb->snd_una = tcb->snd_nxt;
        tsk->backoff = 0;
        /* RFC 6298: Sender SHOULD set RTO <- 1 second */
        tsk->rto = 1000;
        tcp_send_ack(&tsk->sk);
        tcp_rearm_user_timeout(&tsk->sk);
        tcp_parse_opts(tsk, th);
        sock_connected(sk);
    } else {
        tcp_set_state(sk, TCP_SYN_RECEIVED);
        tcb->snd_una = tcb->iss;
        tcp_send_synack(&tsk->sk);
    }
    
discard:
    tcp_drop(sk, skb);
    return 0;
reset_and_discard:
    //TODO reset
    tcp_drop(sk, skb);
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

    tcpsock_dbg("state is closed", (&tsk->sk));

    if (th->rst) {
        tcp_discard(tsk, skb, th);
        rc = 0;
        goto out;
    }

    if (th->ack) {
 
    } else {
        
    
    }
    
    rc = tcp_send_reset(tsk);
    free_skb(skb);

out:
    return rc;
}

/*
 * Follows RFC793 "Segment Arrives" section closely
 */ 
int tcp_input_state(struct sock *sk, struct tcphdr *th, struct sk_buff *skb)
{
    struct tcp_sock *tsk = tcp_sk(sk);
    struct tcb *tcb = &tsk->tcb;

    tcpsock_dbg("input state", sk);

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
    if (!tcp_verify_segment(tsk, th, skb)) {
        /* RFC793: If an incoming segment is not acceptable, an acknowledgment
         * should be sent in reply (unless the RST bit is set, if so drop
         *  the segment and return): */
        if (!th->rst) {
            tcp_send_ack(sk);
        }
        return_tcp_drop(sk, skb);
    }
    
    /* second check the RST bit */
    if (th->rst) {
        free_skb(skb);
        tcp_enter_time_wait(sk);
        tsk->sk.ops->recv_notify(&tsk->sk);
        return 0;
    }
    
    /* third check security and precedence */
    // Not implemented

    /* fourth check the SYN bit */
    if (th->syn) {
        /* RFC 5961 Section 4.2 */
        tcp_send_challenge_ack(sk, skb);
        return_tcp_drop(sk, skb);
    }
    
    /* fifth check the ACK field */
    if (!th->ack) {
        return_tcp_drop(sk, skb);
    }

    // ACK bit is on
    switch (sk->state) {
    case TCP_SYN_RECEIVED:
        if (tcb->snd_una <= th->ack_seq && th->ack_seq < tcb->snd_nxt) {
            tcp_set_state(sk, TCP_ESTABLISHED);
        } else {
            return_tcp_drop(sk, skb);
        }
    case TCP_ESTABLISHED:
    case TCP_FIN_WAIT_1:
    case TCP_FIN_WAIT_2:
    case TCP_CLOSE_WAIT:
    case TCP_CLOSING:
    case TCP_LAST_ACK:
        if (tcb->snd_una < th->ack_seq && th->ack_seq <= tcb->snd_nxt) {
            tcb->snd_una = th->ack_seq;
            /* Any segments on the retransmission queue which are thereby
               entirely acknowledged are removed. */
            tcp_rtt(tsk);
            tcp_clean_rto_queue(sk, tcb->snd_una);
        }

        if (th->ack_seq < tcb->snd_una) {
            // If the ACK is a duplicate, it can be ignored
            return_tcp_drop(sk, skb);
        }

        if (th->ack_seq > tcb->snd_nxt) {
            // If the ACK acks something not yet sent, then send an ACK, drop segment
            // and return
            // TODO: Dropping the seg here, why would I respond with an ACK? Linux
            // does not respond either
            //tcp_send_ack(&tsk->sk);
            return_tcp_drop(sk, skb);
        }

        if (tcb->snd_una < th->ack_seq && th->ack_seq <= tcb->snd_nxt) {
            // TODO: Send window should be updated
        }

        break;
    }

    /* If the write queue is empty, it means our FIN was acked */
    if (skb_queue_empty(&sk->write_queue)) {
        switch (sk->state) {
        case TCP_FIN_WAIT_1:
            tcp_set_state(sk, TCP_FIN_WAIT_2);
        case TCP_FIN_WAIT_2:
            break;
        case TCP_CLOSING:
            /* In addition to the processing for the ESTABLISHED state, if
             * the ACK acknowledges our FIN then enter the TIME-WAIT state,
               otherwise ignore the segment. */
            tcp_set_state(sk, TCP_TIME_WAIT);
            break;
        case TCP_LAST_ACK:
            /* The only thing that can arrive in this state is an acknowledgment of our FIN.  
             * If our FIN is now acknowledged, delete the TCB, enter the CLOSED state, and return. */
            free_skb(skb);
            return tcp_done(sk);
        case TCP_TIME_WAIT:
            /* TODO: The only thing that can arrive in this state is a
               retransmission of the remote FIN.  Acknowledge it, and restart
               the 2 MSL timeout. */
            if (tcb->rcv_nxt == th->seq) {
                tcpsock_dbg("Remote FIN retransmitted?", sk);
//                tcb->rcv_nxt += 1;
                tsk->flags |= TCP_FIN;
                tcp_send_ack(sk);
            }
            break;
        }
    }
    
    /* sixth, check the URG bit */
    if (th->urg) {

    }

    int expected = skb->seq == tcb->rcv_nxt;

    /* seventh, process the segment txt */
    switch (sk->state) {
    case TCP_ESTABLISHED:
    case TCP_FIN_WAIT_1:
    case TCP_FIN_WAIT_2:
        if (th->psh || skb->dlen > 0) {
            tcp_data_queue(tsk, th, skb);
        }
                
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
    if (th->fin && expected) {
        tcpsock_dbg("Received in-sequence FIN", sk);

        switch (sk->state) {
        case TCP_CLOSE:
        case TCP_LISTEN:
        case TCP_SYN_SENT:
            // Do not process, since SEG.SEQ cannot be validated
            goto drop_and_unlock;
        }

        tcb->rcv_nxt += 1;
        tsk->flags |= TCP_FIN;
        sk->poll_events |= (POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND);
        
        tcp_send_ack(sk);
        tsk->sk.ops->recv_notify(&tsk->sk);

        switch (sk->state) {
        case TCP_SYN_RECEIVED:
        case TCP_ESTABLISHED:
            tcp_set_state(sk, TCP_CLOSE_WAIT);
            break;
        case TCP_FIN_WAIT_1:
            /* If our FIN has been ACKed (perhaps in this segment), then
               enter TIME-WAIT, start the time-wait timer, turn off the other
               timers; otherwise enter the CLOSING state. */
            if (skb_queue_empty(&sk->write_queue)) {
                tcp_enter_time_wait(sk);
            } else {
                tcp_set_state(sk, TCP_CLOSING);
            }

            break;
        case TCP_FIN_WAIT_2:
            /* Enter the TIME-WAIT state.  Start the time-wait timer, turn
               off the other timers. */
            tcp_enter_time_wait(sk);
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

    /* Congestion control and delacks */
    switch (sk->state) {
    case TCP_ESTABLISHED:
    case TCP_FIN_WAIT_1:
    case TCP_FIN_WAIT_2:
        if (expected) {
            tcp_stop_delack_timer(tsk);

            int pending = min(skb_queue_len(&sk->write_queue), 3);
            /* RFC1122:  A TCP SHOULD implement a delayed ACK, but an ACK should not
             * be excessively delayed; in particular, the delay MUST be less than
             * 0.5 seconds, and in a stream of full-sized segments there SHOULD 
             * be an ACK for at least every second segment. */
            if (tsk->inflight == 0 && pending > 0) {
                tcp_send_next(sk, pending);
                tsk->inflight += pending;
                tcp_rearm_rto_timer(tsk);
            } else if (th->psh || (skb->dlen > 1000 && ++tsk->delacks > 1)) {
                tsk->delacks = 0;
                tcp_send_ack(sk);
            } else if (skb->dlen > 0) {
                tsk->delack = timer_add(200, &tcp_send_delack, &tsk->sk);
            }
        }
    }

    free_skb(skb);

unlock:
    return 0;
drop_and_unlock:
    tcp_drop(sk, skb);
    goto unlock;
}

int tcp_receive(struct tcp_sock *tsk, void *buf, int len)
{
    int rlen = 0;
    int curlen = 0;
    struct sock *sk = &tsk->sk;
    struct socket *sock = sk->sock;

    memset(buf, 0, len);

    while (rlen < len) {
        curlen = tcp_data_dequeue(tsk, buf + rlen, len - rlen);

        rlen += curlen;

        if (tsk->flags & TCP_PSH) {

            tsk->flags &= ~TCP_PSH;
            break;
        }

        if (tsk->flags & TCP_FIN || rlen == len) break;

        if (sock->flags & O_NONBLOCK) {
            if (rlen == 0) {
                rlen = -EAGAIN;
            } 
            
            break;
        } else {
            pthread_mutex_lock(&tsk->sk.recv_wait.lock);
            socket_release(sock);
            wait_sleep(&tsk->sk.recv_wait);
            pthread_mutex_unlock(&tsk->sk.recv_wait.lock);
            socket_wr_acquire(sock);
        }
    }

    if (rlen >= 0) tcp_rearm_user_timeout(sk);
    
    return rlen;
}
