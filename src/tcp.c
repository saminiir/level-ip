#include "syshead.h"
#include "inet.h"
#include "tcp.h"
#include "ip.h"
#include "sock.h"
#include "utils.h"
#include "tcp_timer.h"

struct net_ops tcp_ops = {
    .alloc_sock = &tcp_alloc_sock,
    .init = &tcp_v4_init_sock,
    .connect = &tcp_v4_connect,
    .disconnect = &tcp_disconnect,
};

void tcp_init()
{
    
}

static void tcp_init_segment(struct tcphdr *th)
{
    th->sport = ntohs(th->sport);
    th->dport = ntohs(th->dport);
    th->seq = ntohl(th->seq);
    th->ack_seq = ntohl(th->ack_seq);
    th->win = ntohs(th->win);
    th->csum = ntohs(th->csum);
    th->urp = ntohs(th->urp);
}

void tcp_in(struct sk_buff *skb)
{
    struct sock *sk;
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);
    tcph = (struct tcphdr*) iph->data;

    tcp_init_segment(tcph);
    
    sk = inet_lookup(skb, tcph->sport, tcph->dport);
    
    /* if (tcp_checksum(iph, tcph) != 0) { */
    /*     goto discard; */
    /* } */
        
    tcp_input_state(sk, skb);
    
discard:
    free_skb(skb);
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

    tsk->sk.state = TCP_CLOSE;
    
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

static uint16_t generate_port()
{
    return 12000;
}

int generate_iss()
{
    return 1525252;
}

int tcp_v4_connect(struct sock *sk, const struct sockaddr *addr, int addrlen, int flags)
{
    uint16_t dport = addr->sa_data[1];
    uint32_t daddr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;

    printf("Connecting socket to %hhu.%hhu.%hhu.%hhu:%d\n", addr->sa_data[2], addr->sa_data[3], addr->sa_data[4], addr->sa_data[5], dport);

    sk->dport = dport;
    sk->sport = generate_port();
    sk->daddr = ntohl(daddr);
    sk->saddr = parse_ipv4_string("10.0.0.4"); 

    return tcp_connect(sk);
}

int tcp_disconnect(struct sock *sk, int flags)
{
    return 0;
}
