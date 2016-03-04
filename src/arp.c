#include "arp.h"

void arp_incoming(int tun_fd, struct eth_hdr *hdr)
{
    struct arp_hdr *arphdr;
    struct arp_ipv4 *arp_payload;

    arphdr = (struct arp_hdr *) hdr->payload;

    arphdr->hw_type = htons(arphdr->hw_type);
    arphdr->pro_type = htons(arphdr->pro_type);
    arphdr->opcode = htons(arphdr->opcode);

    if (arphdr->hw_type != ARP_ETHERNET) {
        printf("Unsupported HW type\n");
    }

    if (arphdr->pro_type != ARP_IPV4) {
        printf("Unsupported protocol\n");
    }

    arp_payload = (struct arp_ipv4 *) arphdr->payload;

    if (arphdr->opcode == ARP_REQUEST) {
        printf("Detected ARP request\n");
    }
}
