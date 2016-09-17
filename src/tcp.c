#include "tcp.h"
#include "ip.h"
#include "sock.h"
#include "utils.h"

struct net_ops tcp_ops = {
    .alloc_sock = &tcp_alloc_sock,
    .connect = &tcp_v4_connect,
    .disconnect = &tcp_disconnect,
};

void tcp_init()
{

}

void tcp_in(struct sk_buff *skb)
{
    /* struct iphdr *iphdr = (struct iphdr *) hdr->payload; */
    /* struct tcphdr *thdr = (struct tcphdr *) iphdr->data; */

    /* if (tcp_checksum(iphdr, thdr) != 0) { */
    /*     printf("TCP segment checksum did not match, dropping\n"); */
    /*     return; */
    /* } */
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
    struct tcp_sock *tsk = tcp_sk(sk);
    
    uint16_t dport = addr->sa_data[1];
    uint32_t daddr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;

    printf("Connecting socket to %hhu.%hhu.%hhu.%hhu:%d\n", addr->sa_data[2], addr->sa_data[3], addr->sa_data[4], addr->sa_data[5], dport);

    tsk->dport = dport;
    tsk->sport = generate_port();
    tsk->daddr = daddr;
    tsk->saddr = parse_ipv4_string("10.0.0.4"); 

    return tcp_connect(sk);
}

int tcp_disconnect(struct sock *sk, int flags)
{
    return 0;
}
