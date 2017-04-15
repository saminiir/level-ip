#include "syshead.h"
#include "inet.h"
#include "tcp.h"
#include "ip.h"
#include "sock.h"
#include "utils.h"
#include "timer.h"
#include "wait.h"

#ifdef DEBUG_TCP
const char *tcp_dbg_states[] = {
    "TCP_LISTEN", "TCP_SYNSENT", "TCP_SYN_RECEIVED", "TCP_ESTABLISHED", "TCP_FIN_WAIT_1",
    "TCP_FIN_WAIT_2", "TCP_CLOSE", "TCP_CLOSE_WAIT", "TCP_CLOSING", "TCP_LAST_ACK", "TCP_TIME_WAIT",
};
#endif

struct net_ops tcp_ops = {
    .alloc_sock = &tcp_alloc_sock,
    .init = &tcp_v4_init_sock,
    .connect = &tcp_v4_connect,
    .disconnect = &tcp_disconnect,
    .write = &tcp_write,
    .read = &tcp_read,
    .recv_notify = &tcp_recv_notify,
    .close = &tcp_close,
    .abort = &tcp_abort,
};

void tcp_init()
{
    
}

static void tcp_init_segment(struct tcphdr *th, struct iphdr *ih, struct sk_buff *skb)
{
    th->sport = ntohs(th->sport);
    th->dport = ntohs(th->dport);
    th->seq = ntohl(th->seq);
    th->ack_seq = ntohl(th->ack_seq);
    th->win = ntohs(th->win);
    th->csum = ntohs(th->csum);
    th->urp = ntohs(th->urp);

    skb->seq = th->seq;
    skb->dlen = ip_len(ih) - tcp_hlen(th);
    skb->len = skb->dlen + th->syn + th->fin;
    skb->end_seq = skb->seq + skb->dlen;
    skb->payload = th->data;
}

static void tcp_clear_queues(struct tcp_sock *tsk) {
    pthread_mutex_lock(&tsk->ofo_queue.lock);

    skb_queue_free(&tsk->ofo_queue);

    pthread_mutex_unlock(&tsk->ofo_queue.lock);
}

void tcp_in(struct sk_buff *skb)
{
    struct sock *sk;
    struct iphdr *iph;
    struct tcphdr *th;

    iph = ip_hdr(skb);
    th = (struct tcphdr*) iph->data;

    tcp_init_segment(th, iph, skb);
    
    sk = inet_lookup(skb, th->sport, th->dport);

    if (sk == NULL) {
        print_err("No TCP socket for sport %d dport %d\n",
                  th->sport, th->dport);
        free_skb(skb);
        return;
    }

    tcp_in_dbg(th, sk, skb);
    
    /* if (tcp_checksum(iph, th) != 0) { */
    /*     goto discard; */
    /* } */
        
    tcp_input_state(sk, th, skb);
}

int tcp_udp_checksum(uint32_t saddr, uint32_t daddr, uint8_t proto,
                     uint8_t *data, uint16_t len)
{
    uint32_t sum = 0;

    sum += saddr;
    sum += daddr;
    sum += htons(proto);
    sum += htons(len);
    
    return checksum(data, len, sum);
}

int tcp_v4_checksum(struct sk_buff *skb, uint32_t saddr, uint32_t daddr)
{
    return tcp_udp_checksum(saddr, daddr, IP_TCP, skb->data, skb->len);
}

struct sock *tcp_alloc_sock()
{
    struct tcp_sock *tsk = malloc(sizeof(struct tcp_sock));

    memset(tsk, 0, sizeof(struct tcp_sock));
    tsk->sk.state = TCP_CLOSE;
    tsk->flags = 0;
    tsk->backoff = 0;

    tsk->retransmit = NULL;
    tsk->delack = NULL;
    tsk->keepalive = NULL;

    tsk->delacks = 0;

    /* TODO: Determine mss properly */
    tsk->rmss = 1460;
    tsk->smss = 1460;

    skb_queue_init(&tsk->ofo_queue);
    
    return (struct sock *)tsk;
}

int tcp_v4_init_sock(struct sock *sk)
{
    tcp_init_sock(sk);
    return 0;
}

int tcp_init_sock(struct sock *sk)
{
    return 0;
}

void __tcp_set_state(struct sock *sk, uint32_t state)
{
    sk->state = state;
}

static uint16_t generate_port()
{
    /* TODO: Generate a proper port */
    static int port = 40000;
    return ++port + (timer_get_tick() % 10000);
}

int generate_iss()
{
    /* TODO: Generate a proper ISS */
    return (int)time(NULL) * rand();
}

int tcp_v4_connect(struct sock *sk, const struct sockaddr *addr, int addrlen, int flags)
{
    uint16_t dport = ((struct sockaddr_in *)addr)->sin_port;
    uint32_t daddr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;

    sk->dport = ntohs(dport);
    sk->sport = generate_port();
    sk->daddr = ntohl(daddr);
    /* TODO: Do not hardcode lvl-ip local interface */
    sk->saddr = parse_ipv4_string("10.0.0.4"); 

    return tcp_connect(sk);
}

int tcp_disconnect(struct sock *sk, int flags)
{
    return 0;
}

int tcp_write(struct sock *sk, const void *buf, int len)
{
    struct tcp_sock *tsk = tcp_sk(sk);
    int ret = sk->err;

    if (ret != 0) goto out;

    switch (sk->state) {
    case TCP_ESTABLISHED:
    case TCP_CLOSE_WAIT:
        break;
    default:
        goto out;
    }

    return tcp_send(tsk, buf, len);    

out: 
    return ret;
}

int tcp_read(struct sock *sk, void *buf, int len)
{
    struct tcp_sock *tsk = tcp_sk(sk);
    int ret = -1;

    switch (sk->state) {
    case TCP_CLOSE:
        print_err("error:  connection does not exist\n");
        goto out;
    case TCP_LISTEN:
    case TCP_SYN_SENT:
    case TCP_SYN_RECEIVED:
        /* Queue for processing after entering ESTABLISHED state.  If there
           is no room to queue this request, respond with "error:
           insufficient resources". */
    case TCP_ESTABLISHED:
    case TCP_FIN_WAIT_1:
    case TCP_FIN_WAIT_2:
        /* If insufficient incoming segments are queued to satisfy the
           request, queue the request. */
        
        break;
    case TCP_CLOSE_WAIT:
        /* If no text is awaiting delivery, the RECEIVE will get a
           "error:  connection closing" response.  Otherwise, any remaining
           text can be used to satisfy the RECEIVE. */
        if (!skb_queue_empty(&tsk->sk.receive_queue)) break;
        if (tsk->flags & TCP_FIN) {
            tsk->flags &= ~TCP_FIN;
            return 0;
        }

        break;
    case TCP_CLOSING:
    case TCP_LAST_ACK:
    case TCP_TIME_WAIT:
        print_err("error:  connection closing\n");
        goto out;
    default:
        goto out;
    }
    
    return tcp_receive(tsk, buf, len);    

out: 
    return ret;
}

int tcp_recv_notify(struct sock *sk)
{
    if (&(sk->recv_wait)) {
        return wait_wakeup(&sk->recv_wait);
    }

    // No recv wait lock
    return -1;
}

int tcp_close(struct sock *sk)
{
    switch (sk->state) {
    case TCP_CLOSE:
    case TCP_CLOSING:
    case TCP_LAST_ACK:
    case TCP_TIME_WAIT:
    case TCP_FIN_WAIT_1:
    case TCP_FIN_WAIT_2:
        /* Respond with "error:  connection closing". */
        sk->err = -EBADF;
        return -1;
    case TCP_LISTEN:
    case TCP_SYN_SENT:
    case TCP_SYN_RECEIVED:
    case TCP_ESTABLISHED:
        /* Queue this until all preceding SENDs have been segmentized, then
           form a FIN segment and send it.  In any case, enter FIN-WAIT-1
           state. */
        tcp_set_state(sk, TCP_FIN_WAIT_1);
        tcp_queue_fin(sk);
        break;
    case TCP_CLOSE_WAIT:
        /* Queue this request until all preceding SENDs have been
           segmentized; then send a FIN segment, enter LAST_ACK state. */
        tcp_queue_fin(sk);
        break;
    default:
        print_err("Unknown TCP state for close\n");
        return -1;
    }

    return 0;
}

int tcp_abort(struct sock *sk)
{
    struct tcp_sock *tsk = tcp_sk(sk);
    tcp_send_reset(tsk);
    return tcp_done(sk);
}

int tcp_free(struct sock *sk)
{
    struct tcp_sock *tsk = tcp_sk(sk);

    pthread_mutex_lock(&sk->lock);

    tcp_set_state(sk, TCP_CLOSE);
    tcp_clear_timers(sk);
    tcp_clear_queues(tsk);

    pthread_mutex_unlock(&sk->lock);

    wait_wakeup(&sk->sock->sleep);

    return 0;
}

int tcp_done(struct sock *sk)
{
    tcp_free(sk);
    return socket_free(sk->sock);
}

void tcp_clear_timers(struct sock *sk)
{
    struct tcp_sock *tsk = tcp_sk(sk);
    pthread_mutex_lock(&sk->write_queue.lock);
    tcp_stop_rto_timer(tsk);
    tcp_stop_delack_timer(tsk);
    pthread_mutex_unlock(&sk->write_queue.lock);

    timer_cancel(tsk->keepalive);
}

void tcp_stop_rto_timer(struct tcp_sock *tsk)
{
    if (tsk) {
        timer_cancel(tsk->retransmit);
        tsk->retransmit = NULL;
    }
}

void tcp_release_rto_timer(struct tcp_sock *tsk)
{
    if (tsk) {
        timer_release(tsk->retransmit);
        tsk->retransmit = NULL;
    }
}

void tcp_stop_delack_timer(struct tcp_sock *tsk)
{
    timer_cancel(tsk->delack);
    tsk->delack = NULL;
}

void tcp_release_delack_timer(struct tcp_sock *tsk)
{
    timer_release(tsk->delack);
    tsk->delack = NULL;
}

void tcp_handle_fin_state(struct sock *sk)
{
    switch (sk->state) {
    case TCP_CLOSE_WAIT:
        tcp_set_state(sk, TCP_LAST_ACK);
        break;
    case TCP_ESTABLISHED:
        tcp_set_state(sk, TCP_FIN_WAIT_1);
        break;
    }
}

static void tcp_linger(uint32_t ts, void *arg)
{
    struct sock *sk = (struct sock *) arg;
    struct tcp_sock *tsk = tcp_sk(sk);
    timer_release(tsk->linger);
    tsk->linger = NULL;

    tcp_done(sk);
}

void tcp_enter_time_wait(struct sock *sk)
{
    struct tcp_sock *tsk = tcp_sk(sk);

    tcp_set_state(sk, TCP_TIME_WAIT);

    tcp_clear_timers(sk);
    
    timer_cancel(tsk->linger);
    tsk->linger = timer_add(3000, &tcp_linger, sk);
}
