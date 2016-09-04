#include "arp.h"
#include "netdev.h"
#include "skbuff.h"

/*
 * https://tools.ietf.org/html/rfc826
 */

static struct arp_cache_entry arp_cache[ARP_CACHE_LEN];

static struct sk_buff *arp_create(int type, int ptype, uint32_t dip,
                           struct netdev *netdev, uint32_t sip,
                           const unsigned char *dst_hw,
                           const unsigned char *src_hw,
                           const unsigned char *target_hw)
{
    struct sk_buff *skb;
    struct arp_hdr *arp;
    struct arp_ipv4 *payload;

    skb = alloc_skb(arp_hdr_len(netdev));
    arp = (struct arp_hdr *)skb->data;
    /* skb->dev = netdev; */
    skb->protocol = htons(ETH_P_ARP);

    arp->hwtype = ARP_ETHERNET; 
    arp->protype = ETH_P_IP;
    arp->hwsize = netdev->addr_len;
    arp->prosize = 4;

    payload = (struct arp_ipv4 *)arp->data;

    memcpy(payload->smac, src_hw, netdev->addr_len);
    payload->sip = sip;

    memcpy(payload->dmac, dst_hw, netdev->addr_len);
    payload->dip = dip;
    
    return skb;
}
                             
static void arp_send_dst(int type, int ptype, uint32_t dip,
                         struct netdev *netdev, uint32_t sip,
                         const unsigned char *dst_hw,
                         const unsigned char *src_hw,
                         const unsigned char *target_hw)
{
    struct sk_buff *skb;

    skb = arp_create(type, ptype, dip, netdev, sip,
                     dst_hw, src_hw, target_hw);

    if (!skb) return;
    
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

void arp_xmit(struct sk_buff *skb)
{

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

    if (!(netdev = netdev_get(arpdata->dip))) {
        printf("ARP was not for us\n");
        return;
    }

    if (!merge && insert_arp_translation_table(arphdr, arpdata) != 0) {
       perror("ERR: No free space in ARP translation table\n"); 
    }

    switch (arphdr->opcode) {
    case ARP_REQUEST:
        arp_reply(skb, netdev);
        break;
    default:
        printf("Opcode not supported\n");
        break;
    }
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

    arphdr->opcode = htons(arphdr->opcode);
    arphdr->hwtype = htons(arphdr->hwtype);
    arphdr->protype = htons(arphdr->protype);

    skb->netdev = netdev;

    netdev_transmit(skb, arpdata->dmac, ETH_P_ARP);
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
