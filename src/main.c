#include "syshead.h"
#include "basic.h"
#include "tuntap_if.h"
#include "utils.h"
#include "ethernet.h"
#include "arp.h"
#include "netdev.h"

#define BUFLEN 100

void handle_frame(struct netdev *netdev, struct eth_hdr *hdr)
{
    switch (hdr->ethertype) {
        case ETH_P_ARP:
            arp_incoming(netdev, hdr);
            break;
        case ETH_P_IP:
            printf("Found IPv4\n");
            break;
        default:
            printf("Unrecognized ethertype %x\n", hdr->ethertype);
            break;
    }
}

int main(int argc, char** argv)
{
    int tun_fd;
    char buf[BUFLEN];
    char *dev = calloc(10, 1);
    struct netdev netdev;

    CLEAR(buf);
    tun_fd = tun_alloc(dev);

    netdev_init(&netdev, "10.0.0.4", "00:0c:29:6d:50:25");

    if (set_if_route(dev, "10.0.0.0/24") != 0) {
        print_error("ERROR when setting route for if\n");
    }

    netdev_init(netdev, "10.0.0.4", "00:0c:29:6d:50:25");
    arp_init();

    while (1) {
        read(tun_fd, buf, BUFLEN);

        print_hexdump(buf, BUFLEN);

        struct eth_hdr *eth_hdr = init_eth_hdr(buf);

        handle_frame(&netdev, eth_hdr);
    }
}
