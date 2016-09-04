#include "syshead.h"
#include "basic.h"
#include "cli.h"
#include "tuntap_if.h"
#include "utils.h"
#include "route.h"
#include "ethernet.h"
#include "arp.h"
#include "tcp.h"
#include "netdev.h"
#include "ip.h"
#include "curl.h"

#define MAX_CMD_LENGTH 6

typedef void (*sighandler_t)(int);

/*
 * 0 for core networking
 * 1 for possible integrated application
 */
static pthread_t threads[2];

int running = 1;

static struct command *cmd_to_run;

static void stop_stack_handler(int signo)
{
    printf("Stopping\n");
    running = 0;
}

static void *_signal(int signo, sighandler_t handler)
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

static void init_stack()
{
    tun_init();
    netdev_init("10.0.0.4", "00:0c:29:6d:50:25");

    route_init();
    arp_init();
    tcp_init();
}

static void run_threads()
{
    if (pthread_create(&threads[0], NULL,
		       &netdev_rx_loop, NULL) != 0) {
	print_error("Could not create netdev rx loop thread\n");
	return;
    }
    if (cmd_to_run != NULL && pthread_create(&threads[1], NULL,
					     cmd_to_run->cmd_func, cmd_to_run) != 0) {
	print_error("Could not create app thread for %s\n", cmd_to_run->cmd_str);
	return;
    }
}

static void wait_for_threads()
{
    for (int i = 0; i < 2; i++) {
	if (pthread_join(threads[i], NULL) != 0) {
	    print_error("Error when joining threads\n");
	    exit(1);
	}
    }
}

void free_stack()
{
    netdev_free();
    tun_free();
}

int main(int argc, char** argv)
{
    cmd_to_run = parse_args(argc, argv);

    init_signals();
    init_stack();

    run_threads();
    wait_for_threads();

    free_stack();
}
