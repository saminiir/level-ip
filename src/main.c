#include "syshead.h"
#include "basic.h"
#include "tuntap_if.h"
#include "utils.h"
#include "ethernet.h"
#include "arp.h"

#define BUFLEN 100

void handle_frame(struct eth_hdr *hdr)
{
    switch (hdr->ethertype) {
        case ETH_P_ARP:
            arp_incoming(hdr);
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
    CLEAR(buf);
    tun_fd = tun_alloc(dev);

    if (set_if_up(dev) != 0) {
        print_error("ERROR when setting up if\n");
    }

    if (set_if_route(dev, "10.0.0.0/24") != 0) {
        print_error("ERROR when setting route for if\n");
    }

    while (1) {
        read(tun_fd, buf, BUFLEN);

        print_hexdump(buf, BUFLEN);

        struct eth_hdr *eth_hdr = init_eth_hdr(buf);

        handle_frame(eth_hdr);
    }

    free(dev);
}
