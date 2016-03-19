#include "arp.h"
#include "netdev.h"

/*
 * https://tools.ietf.org/html/rfc826
 */

static struct arp_cache_entry arp_cache[ARP_CACHE_LEN];

static int insert_arp_translation_table(struct arp_hdr *hdr, struct arp_ipv4 *data)
{
    struct arp_cache_entry *entry;
    for (int i = 0; i<ARP_CACHE_LEN; i++) {
        entry = &arp_cache[i];

        if (entry->state == ARP_FREE) {
            entry->state = ARP_RESOLVED;

            entry->hwtype = hdr->hwtype;
            entry->sip = data->sip;
            memcpy(entry->smac, data->smac, sizeof(entry->smac));

            return 0;
        }
    }

    return -1;
}

static int update_arp_translation_table(struct arp_hdr *hdr, struct arp_ipv4 *data)
{
    struct arp_cache_entry *entry;

    for (int i = 0; i<ARP_CACHE_LEN; i++) {
        entry = &arp_cache[i];

        if (entry->state == ARP_FREE) continue;

        if (entry->hwtype == hdr->hwtype && entry->sip == data->sip) {
            memcpy(entry->smac, data->smac, 6);
            return 1;
        }
    }
    
    return 0;
}

void arp_init()
{
    memset(arp_cache, 0, ARP_CACHE_LEN * sizeof(struct arp_cache_entry));
}

void arp_incoming(struct netdev *netdev, struct eth_hdr *hdr)
{
    struct arp_hdr *arphdr;
    struct arp_ipv4 *arpdata;
    int merge = 0;

    arphdr = (struct arp_hdr *) hdr->payload;

    arphdr->hwtype = ntohs(arphdr->hwtype);
    arphdr->protype = ntohs(arphdr->protype);
    arphdr->opcode = ntohs(arphdr->opcode);

    if (arphdr->hwtype != ARP_ETHERNET) {
        printf("Unsupported HW type\n");
        return;
    }

    if (arphdr->protype != ARP_IPV4) {
        printf("Unsupported protocol\n");
        return;
    }

    arpdata = (struct arp_ipv4 *) arphdr->data;

    merge = update_arp_translation_table(arphdr, arpdata);

    if (netdev->addr != arpdata->dip) {
        printf("ARP was not for us\n");
        return;
    }

    if (!merge && insert_arp_translation_table(arphdr, arpdata) != 0) {
       perror("ERR: No free space in ARP translation table\n"); 
    }

    switch (arphdr->opcode) {
    case ARP_REQUEST:
        arp_reply(netdev, hdr, arphdr);
        break;
    default:
        printf("Opcode not supported\n");
        break;
    }
}

void arp_reply(struct netdev *netdev, struct eth_hdr *hdr, struct arp_hdr *arphdr) 
{
    struct arp_ipv4 *arpdata;
    int len;

    arpdata = (struct arp_ipv4 *) arphdr->data;

    memcpy(arpdata->dmac, arpdata->smac, 6);
    arpdata->dip = arpdata->sip;
    memcpy(arpdata->smac, netdev->hwaddr, 6);
    arpdata->sip = netdev->addr;

    arphdr->opcode = ARP_REPLY;

    arphdr->opcode = htons(arphdr->opcode);
    arphdr->hwtype = htons(arphdr->hwtype);
    arphdr->protype = htons(arphdr->protype);

    len = sizeof(struct arp_hdr) + sizeof(struct arp_ipv4);
    netdev_transmit(netdev, hdr, ETH_P_ARP, len, arpdata->dmac);
}

/*
 * Returns the HW address of the given source IP address
 * NULL if not found
 */
unsigned char* arp_get_hwaddr(uint32_t *sip)
{
    struct arp_cache_entry *entry;

    for (int i = 0; i < ARP_CACHE_LEN; i++) {
        entry = &arp_cache[i];

        if (entry->state == ARP_RESOLVED && 
            entry->sip == *sip) {

            return entry->smac;
        }
    }

    return NULL;
}
