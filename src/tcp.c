#include "tcp.h"
#include "ipv4.h"
#include "utils.h"

void tcp_in(struct netdev *netdev, struct eth_hdr *hdr)
{
    struct iphdr *iphdr = (struct iphdr *) hdr->payload;
    struct tcphdr *thdr = (struct tcphdr *) iphdr->data;
    uint16_t tmpport = thdr->sport;

    if (tcp_checksum(iphdr, thdr) != 0) {
        printf("TCP segment checksum did not match, dropping\n");
        return;
    }

    
    return;
    /* thdr->sport = thdr->dport; */
    /* thdr->dport = tmpport; */

    /* if (thdr->flags & TCP_SYN) { */
    /*     thdr->flags |= TCP_ACK; */
    /* 	thdr->ack = 1; */
    /* } */

    /* thdr->csum = 0; */

    /* printf("tests\n"); */
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
