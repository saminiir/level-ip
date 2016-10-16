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
 * 1 for signal processor
 * 2 for possible integrated application
 */
static pthread_t threads[3];

int running = 1;
sigset_t mask;

static struct command *cmd_to_run;

static void print_usage_if_needed(struct command *cmd) {
    if (strncmp(cmd->cmd_str, "help", 4) == 0) {
        cmd->cmd_func(cmd);
        exit(1);
    }
}

static void *stop_stack_handler(void *arg)
{
    int err, signo;

    for (;;) {
        err = sigwait(&mask, &signo);
        if (err != 0) {
            print_error("Sigwait failed: %d\n", err);
        }

        switch (signo) {
        case SIGINT:
        case SIGQUIT:
            running = 0;
            pthread_cancel(threads[0]);
            if (cmd_to_run != NULL) pthread_cancel(threads[2]);
            return 0;
        default:
            printf("Unexpected signal %d\n", signo);
        }
    }
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
    int err;
    
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGQUIT);

    if ((err = pthread_sigmask(SIG_BLOCK, &mask, NULL)) != 0) {
        print_error("SIG_BLOCK error\n");
        exit(1);
    }
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

    if (pthread_create(&threads[1], NULL, stop_stack_handler, 0)) {
        print_error("Could not create signal processor thread\n");
        return;
    }
    
    if (cmd_to_run != NULL && pthread_create(&threads[2], NULL,
					     cmd_to_run->cmd_func, cmd_to_run) != 0) {
	print_error("Could not create app thread for %s\n", cmd_to_run->cmd_str);
	return;
    }
}

static void wait_for_threads()
{
    for (int i = 0; i < 3; i++) {
	if (pthread_join(threads[i], NULL) != 0) {
	    print_error("Error when joining threads\n");
	    exit(1);
	}
    }
}

void free_stack()
{
    free_sockets();
    free_netdev();
    free_tun();
}

int main(int argc, char** argv)
{
    cmd_to_run = parse_args(argc, argv);

    print_usage_if_needed(cmd_to_run);

    init_signals();
    init_stack();

    run_threads();
    wait_for_threads();

    free_stack();
}
