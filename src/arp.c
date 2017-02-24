#include "arp.h"
#include "netdev.h"
#include "skbuff.h"

/*
 * https://tools.ietf.org/html/rfc826
 */

static uint8_t broadcast_hw[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static struct arp_cache_entry arp_cache[ARP_CACHE_LEN];

static struct sk_buff *arp_alloc_skb()
{
    struct sk_buff *skb = alloc_skb(ETH_HDR_LEN + ARP_HDR_LEN + ARP_DATA_LEN);
    skb_reserve(skb, ETH_HDR_LEN + ARP_HDR_LEN + ARP_DATA_LEN);
    skb->protocol = htons(ETH_P_ARP);
    
    return skb;
}

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

void arp_rcv(struct sk_buff *skb)
{
    struct arp_hdr *arphdr;
    struct arp_ipv4 *arpdata;
    struct netdev *netdev;
    int merge = 0;

    arphdr = arp_hdr(skb);

    arphdr->hwtype = ntohs(arphdr->hwtype);
    arphdr->protype = ntohs(arphdr->protype);
    arphdr->opcode = ntohs(arphdr->opcode);
    arp_dbg("INPUT", arphdr);

    if (arphdr->hwtype != ARP_ETHERNET) {
        printf("Unsupported HW type\n");
        goto drop_pkt;
    }

    if (arphdr->protype != ARP_IPV4) {
        printf("Unsupported protocol\n");
        goto drop_pkt;
    }

    arpdata = (struct arp_ipv4 *) arphdr->data;

    arpdata->sip = ntohl(arpdata->sip);
    arpdata->dip = ntohl(arpdata->dip);
    arpdata_dbg("receive", arpdata);
    
    merge = update_arp_translation_table(arphdr, arpdata);

    if (!(netdev = netdev_get(arpdata->dip))) {
        printf("ARP was not for us\n");
        goto drop_pkt;
    }

    if (!merge && insert_arp_translation_table(arphdr, arpdata) != 0) {
        print_err("ERR: No free space in ARP translation table\n");
        goto drop_pkt;
    }

    switch (arphdr->opcode) {
    case ARP_REQUEST:
        arp_reply(skb, netdev);
        return;
    default:
        printf("Opcode not supported\n");
        goto drop_pkt;
    }

drop_pkt:
    free_skb(skb);
    return;
}

int arp_request(uint32_t sip, uint32_t dip, struct netdev *netdev)
{
    struct sk_buff *skb;
    struct arp_hdr *arp;
    struct arp_ipv4 *payload;
    int rc = 0;

    skb = arp_alloc_skb();

    if (!skb) return -1;
    
    skb->dev = netdev;

    payload = (struct arp_ipv4 *) skb_push(skb, ARP_DATA_LEN);

    memcpy(payload->smac, netdev->hwaddr, netdev->addr_len);
    payload->sip = sip;

    memcpy(payload->dmac, broadcast_hw, netdev->addr_len);
    payload->dip = dip;
    
    arp = (struct arp_hdr *) skb_push(skb, ARP_HDR_LEN);

    arp_dbg("Request", arp);
    arp->opcode = htons(ARP_REQUEST);
    arp->hwtype = htons(ARP_ETHERNET); 
    arp->protype = htons(ETH_P_IP);
    arp->hwsize = netdev->addr_len;
    arp->prosize = 4;

    arpdata_dbg("Request", payload);
    payload->sip = htonl(payload->sip);
    payload->dip = htonl(payload->dip);
    
    rc = netdev_transmit(skb, broadcast_hw, ETH_P_ARP);
    free_skb(skb);
    return rc;
}

void arp_reply(struct sk_buff *skb, struct netdev *netdev) 
{
    struct arp_hdr *arphdr;
    struct arp_ipv4 *arpdata;

    arphdr = arp_hdr(skb);

    skb_reserve(skb, ETH_HDR_LEN + ARP_HDR_LEN + ARP_DATA_LEN);
    skb_push(skb, ARP_HDR_LEN + ARP_DATA_LEN);

    arpdata = (struct arp_ipv4 *) arphdr->data;

    memcpy(arpdata->dmac, arpdata->smac, 6);
    arpdata->dip = arpdata->sip;

    memcpy(arpdata->smac, netdev->hwaddr, 6);
    arpdata->sip = netdev->addr;

    arphdr->opcode = ARP_REPLY;

    arp_dbg("REPLY", arphdr);
    arphdr->opcode = htons(arphdr->opcode);
    arphdr->hwtype = htons(arphdr->hwtype);
    arphdr->protype = htons(arphdr->protype);

    arpdata_dbg("reply", arpdata);
    arpdata->sip = htonl(arpdata->sip);
    arpdata->dip = htonl(arpdata->dip);

    skb->dev = netdev;

    netdev_transmit(skb, arpdata->dmac, ETH_P_ARP);
    free_skb(skb);
}

/*
 * Returns the HW address of the given source IP address
 * NULL if not found
 */
unsigned char* arp_get_hwaddr(uint32_t sip)
{
    struct arp_cache_entry *entry;
    
    print_debug("ARPCACHE: Searching for ARP entry with sip "
                "%hhu.%hhu.%hhu.%hhu\n", sip >> 24, sip >> 16,
                sip >> 8, sip >> 0);

    for (int i = 0; i < ARP_CACHE_LEN; i++) {
        entry = &arp_cache[i];
        arpcache_dbg("entry", entry);

        if (entry->state == ARP_RESOLVED && 
            entry->sip == sip) {

            return entry->smac;
        }
    }

    return NULL;
}
