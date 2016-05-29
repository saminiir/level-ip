#include "syshead.h"
#include "basic.h"
#include "tuntap_if.h"
#include "utils.h"
#include "ethernet.h"
#include "arp.h"
#include "netdev.h"
#include "ipv4.h"

#define BUFLEN 100

typedef void (*sighandler_t)(int);

int running = 1;

static void usage(char *program) {
    printf("Usage: sudo %s [curl HOST]\n\n", program);
    printf("  curl HOST - act like curl, HOST as the target. Optional.\n");
    printf("\n");
    printf("  Elevated privileges are needed because of tuntap devices.\n");
    exit(1);
}

static void stop_stack_handler(int signo)
{
    running = 0;
}

static int _signal(int signo, sighandler_t handler)
{
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_flags |= SA_RESTART;
    sa.sa_handler = handler;
    
    if (sigaction(signo, &sa, NULL) < 0) {
        return SIG_ERR;
    }

    return 0;
}


static void init_signals()
{
    _signal(SIGINT, stop_stack_handler);
}

static void handle_frame(struct netdev *netdev, struct eth_hdr *hdr)
{
    switch (hdr->ethertype) {
        case ETH_P_ARP:
            arp_incoming(netdev, hdr);
            break;
        case ETH_P_IP:
            ipv4_incoming(netdev, hdr);
            break;
        default:
            printf("Unrecognized ethertype %x\n", hdr->ethertype);
            break;
    }
}

static int is_curl(int argc, char** argv)
{
    if (argc < 3) {
        return 0;
    }

    if (strncmp(argv[1], "curl", 4) == 0) {
        return 1;
    }

    usage(argv[0]);
    
    return -1;
}

int get_address(char *host, struct sockaddr *addr)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    s = getaddrinfo(host, NULL, &hints, &result);

    if (s != 0) {
        print_error("getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        *addr = *rp->ai_addr;
	freeaddrinfo(result);
        return 0;
    }
    
    return 1;
}

int main(int argc, char** argv)
{
    char buf[BUFLEN];
    char *dev = calloc(10, 1);
    struct netdev netdev;
    int curl = 0;
    struct sockaddr addr;
    
    CLEAR(buf);

    if (argc != 1 && argc != 3) {
        usage(argv[0]);
    }

    curl = is_curl(argc, argv);

    if (curl && get_address(argv[2], &addr) != 0) {
        print_error("Used curl but could not find anyone with HOST\n");
        exit(1);
    }

    init_signals();
    tun_init(dev);
    netdev_init(&netdev, "10.0.0.4", "00:0c:29:6d:50:25");

    if (curl) printf("%hhu.%hhu.%hhu.%hhu\n", addr.sa_data[2], addr.sa_data[3], addr.sa_data[4], addr.sa_data[5]);

    arp_init();

    while (running) {
        if (tun_read(buf, BUFLEN) < 0) {
            print_error("ERR: Read from tun_fd: %s\n", strerror(errno));
            return 1;
        }

        struct eth_hdr *hdr = init_eth_hdr(buf);

        handle_frame(&netdev, hdr);
    }

    free(dev);
}
