#include "tcp.h"
#include "tcp_socket.h"
#include "ipv4.h"
#include "utils.h"

void tcp_init()
{
    init_tcp_sockets();
}

void tcp_in(struct netdev *netdev, struct eth_hdr *hdr)
{
    struct iphdr *iphdr = (struct iphdr *) hdr->payload;
    struct tcphdr *thdr = (struct tcphdr *) iphdr->data;

    if (tcp_checksum(iphdr, thdr) != 0) {
        printf("TCP segment checksum did not match, dropping\n");
        return;
    }

    tcp_out(netdev, hdr);
}

int tcp_checksum(struct iphdr *ihdr, struct tcphdr *thdr)
{
    struct tcpiphdr pseudo_hdr;
    int sum = 0;
    int tlen = ihdr->len - ihdr->ihl * 4;

    pseudo_hdr.saddr = ihdr->saddr;
    pseudo_hdr.daddr = ihdr->daddr;
    pseudo_hdr.zero = 0;
    pseudo_hdr.proto = ihdr->proto;
    pseudo_hdr.tlen = htons(tlen);

    sum = sum_every_16bits(&pseudo_hdr, sizeof(struct tcpiphdr));
        
    return checksum(thdr, tlen, sum);
}

void tcp_out(struct netdev *netdev, struct eth_hdr *hdr)
{
    struct iphdr *iphdr = (struct iphdr *) hdr->payload;
    struct tcphdr *thdr = (struct tcphdr *) iphdr->data;
    struct iphdr pseudo_hdr;
    uint16_t tmpport = thdr->sport;
    
    thdr->sport = thdr->dport;
    thdr->dport = tmpport;

    if (thdr->flags & TCP_SYN) {
        thdr->flags |= TCP_ACK;
        thdr->ack = htonl(ntohl(thdr->seq) + 1);
        thdr->seq = htonl(12345678);
    }

    /* Cut off TCP options, we'll implement the important ones later */
    thdr->hl = 5;
    iphdr->len -= TCP_HDR_LEN;
    
    pseudo_hdr.saddr = iphdr->daddr;
    pseudo_hdr.daddr = iphdr->saddr;
    pseudo_hdr.proto = iphdr->proto;
    pseudo_hdr.len = iphdr->len;
    pseudo_hdr.ihl = iphdr->ihl;
    
    thdr->csum = 0;
    thdr->csum = tcp_checksum(&pseudo_hdr, thdr);

    ipv4_outgoing(netdev, hdr);
}
