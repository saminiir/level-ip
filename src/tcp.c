#include "syshead.h"
#include "inet.h"
#include "tcp.h"
#include "ip.h"
#include "sock.h"
#include "utils.h"
#include "tcp_timer.h"
#include "wait.h"

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

static void tcp_init_segment(struct tcphdr *th, struct iphdr *ih, struct tcp_segment *seg)
{
    th->sport = ntohs(th->sport);
    th->dport = ntohs(th->dport);
    th->seq = ntohl(th->seq);
    th->ack_seq = ntohl(th->ack_seq);
    th->win = ntohs(th->win);
    th->csum = ntohs(th->csum);
    th->urp = ntohs(th->urp);

    seg->seq = th->seq;
    seg->ack = th->ack_seq;
    seg->dlen = ip_len(ih) - tcp_hlen(th);
    seg->len = seg->dlen + th->syn + th->fin;

    seg->win = th->win;
    seg->up = th->urp;
    seg->prc = 0;
    seg->seq_last = seg->seq + seg->len - 1;
}

void tcp_in(struct sk_buff *skb)
{
    struct sock *sk;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct tcp_segment seg;
    struct tcp_segment *dbg = &seg;

    iph = ip_hdr(skb);
    tcph = (struct tcphdr*) iph->data;

    tcp_init_segment(tcph, iph, &seg);
    tcphdr_dbg("INPUT", tcph);
    tcpseg_dbg("INPUT", dbg);
    
    sk = inet_lookup(skb, tcph->sport, tcph->dport);

    if (sk == NULL) {
        print_err("No TCP socket for sport %d dport %d\n",
                  tcph->sport, tcph->dport);
        free_skb(skb);
        return;
    }
    
    /* if (tcp_checksum(iph, tcph) != 0) { */
    /*     goto discard; */
    /* } */
        
    tcp_input_state(sk, skb, &seg);
    return;
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
    
    return (struct sock *)tsk;
}

int tcp_v4_init_sock(struct sock *sk)
{
    tcp_init_sock(sk);
    return 0;
}

int tcp_init_sock(struct sock *sk)
{
    tcp_init_timers(sk);
    return 0;
}

void tcp_set_state(struct sock *sk, uint32_t state)
{
    sk->state = state;
}

static uint16_t generate_port()
{
    return 10000 + (time(NULL) % 3000);
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

    printf("Connecting socket to %hhu.%hhu.%hhu.%hhu:%d\n", addr->sa_data[2], addr->sa_data[3], addr->sa_data[4], addr->sa_data[5], sk->dport);

    return tcp_connect(sk);
}

int tcp_disconnect(struct sock *sk, int flags)
{
    return 0;
}

int tcp_write(struct sock *sk, const void *buf, int len)
{
    struct tcp_sock *tsk = tcp_sk(sk);
    int ret = -1;

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
        printf("error:  connection does not exist\n");
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
    case TCP_CLOSING:
    case TCP_LAST_ACK:
    case TCP_TIME_WAIT:
        printf("error:  connection closing\n");
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
    if (&sk->recv_wait) {
        return wait_wakeup(&sk->recv_wait);
    }

    // No recv wait lock
    return -1;
}

int tcp_close(struct sock *sk)
{
    // TODO: Properly handle TCP socket closing
    return -1;
}

int tcp_abort(struct sock *sk)
{
    struct tcp_sock *tsk = tcp_sk(sk);
    return tcp_send_reset(tsk);
}
