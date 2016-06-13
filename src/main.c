#include "syshead.h"
#include "basic.h"
#include "tuntap_if.h"
#include "utils.h"
#include "ethernet.h"
#include "arp.h"
#include "tcp.h"
#include "netdev.h"
#include "ipv4.h"
#include "curl.h"


#define BUFLEN 100

static void usage(int argc, char** argv);
extern void curl(int, char**);

typedef void (*sighandler_t)(int);

int running = 1;
pthread_t curl_tid;

struct command {
    int args;
    void (*cmd_func)(int, char **);
    char *cmd_str;
};

static struct command cmds[] = {
    { 0, usage, "help" },
    { 1, curl, "curl" },
    { 0, NULL, NULL }
};

static void usage(int argc, char **argv) {
    printf("Usage: sudo %s [curl HOST]\n\n", argv[0]);
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

void parse_args(int argc, char** argv)
{
    if (argc == 1) return;

    struct command *cmd;
    
    for (cmd = &cmds[0]; cmd->cmd_func; cmd++) {
	if (strncmp(argv[1], cmd->cmd_str, 5) == 0) {
	    cmd->cmd_func(argc, argv);
	    return;
	}
    }

    usage(argc, argv);
}

int main(int argc, char** argv)
{
    char buf[BUFLEN];
    char *dev = calloc(10, 1);
    struct netdev netdev;
    
    CLEAR(buf);

    parse_args(argc, argv);

    init_signals();
    tun_init(dev);
    netdev_init(&netdev, "10.0.0.4", "00:0c:29:6d:50:25");

    arp_init();
    tcp_init();

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
