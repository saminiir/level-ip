#include "arp.h"
#include "netdev.h"
#include "skbuff.h"
#include "list.h"

/*
 * https://tools.ietf.org/html/rfc826
 */

static uint8_t broadcast_hw[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static LIST_HEAD(arp_cache);
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static struct sk_buff *arp_alloc_skb()
{
    struct sk_buff *skb = alloc_skb(ETH_HDR_LEN + ARP_HDR_LEN + ARP_DATA_LEN);
    skb_reserve(skb, ETH_HDR_LEN + ARP_HDR_LEN + ARP_DATA_LEN);
    skb->protocol = htons(ETH_P_ARP);
    
    return skb;
}

static struct arp_cache_entry *arp_entry_alloc(struct arp_hdr *hdr, struct arp_ipv4 *data)
{
    struct arp_cache_entry *entry = malloc(sizeof(struct arp_cache_entry));
    list_init(&entry->list);

    entry->state = ARP_RESOLVED;
    entry->hwtype = hdr->hwtype;
    entry->sip = data->sip;
    memcpy(entry->smac, data->smac, sizeof(entry->smac));

    return entry;
}

static int insert_arp_translation_table(struct arp_hdr *hdr, struct arp_ipv4 *data)
{
    struct arp_cache_entry *entry = arp_entry_alloc(hdr, data);

    pthread_mutex_lock(&lock);
    list_add_tail(&entry->list, &arp_cache);
    pthread_mutex_unlock(&lock);

    return 0;
}

static int update_arp_translation_table(struct arp_hdr *hdr, struct arp_ipv4 *data)
{
    struct list_head *item;
    struct arp_cache_entry *entry;

    pthread_mutex_lock(&lock);
    list_for_each(item, &arp_cache) {
        entry = list_entry(item, struct arp_cache_entry, list);

        if (entry->hwtype == hdr->hwtype && entry->sip == data->sip) {
            memcpy(entry->smac, data->smac, 6);
            pthread_mutex_unlock(&lock);
            
            return 1;
        }
    }

    pthread_mutex_unlock(&lock);
    
    return 0;
}

void arp_init()
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
    arp_dbg("in", arphdr);

    if (arphdr->hwtype != ARP_ETHERNET) {
        printf("ARP: Unsupported HW type\n");
        goto drop_pkt;
    }

    if (arphdr->protype != ARP_IPV4) {
        printf("ARP: Unsupported protocol\n");
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
        printf("ARP: Opcode not supported\n");
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

    arp_dbg("req", arp);
    arp->opcode = htons(ARP_REQUEST);
    arp->hwtype = htons(ARP_ETHERNET); 
    arp->protype = htons(ETH_P_IP);
    arp->hwsize = netdev->addr_len;
    arp->prosize = 4;

    arpdata_dbg("req", payload);
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

    arp_dbg("reply", arphdr);
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
    struct list_head *item;
    struct arp_cache_entry *entry;
    
    pthread_mutex_lock(&lock);
    list_for_each(item, &arp_cache) {
        entry = list_entry(item, struct arp_cache_entry, list);

        if (entry->state == ARP_RESOLVED && 
            entry->sip == sip) {
            arpcache_dbg("entry", entry);

            uint8_t *copy = entry->smac;
            pthread_mutex_unlock(&lock);

            return copy;
        }
    }

    pthread_mutex_unlock(&lock);

    return NULL;
}

void free_arp()
{
    struct list_head *item, *tmp;
    struct arp_cache_entry *entry;

    list_for_each_safe(item, tmp, &arp_cache) {
        entry = list_entry(item, struct arp_cache_entry, list);
        list_del(item);

        free(entry);
    }
}
