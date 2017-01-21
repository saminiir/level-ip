#include "syshead.h"
#include "basic.h"
#include "cli.h"
#include "tuntap_if.h"
#include "utils.h"
#include "ipc.h"
#include "route.h"
#include "ethernet.h"
#include "arp.h"
#include "tcp.h"
#include "netdev.h"
#include "ip.h"

#define MAX_CMD_LENGTH 6

typedef void (*sighandler_t)(int);

#define THREAD_CORE 0
#define THREAD_IPC 1
#define THREAD_SIGNAL 2
static pthread_t threads[3];

int running = 1;
sigset_t mask;

static void *stop_stack_handler(void *arg)
{
    int err, signo;

    for (;;) {
        err = sigwait(&mask, &signo);
        if (err != 0) {
            print_err("Sigwait failed: %d\n", err);
        }

        switch (signo) {
        case SIGINT:
        case SIGQUIT:
            running = 0;
            pthread_cancel(threads[THREAD_IPC]);
            pthread_cancel(threads[THREAD_CORE]);
            return 0;
        default:
            printf("Unexpected signal %d\n", signo);
        }
    }
}

static void init_signals()
{
    int err;
    
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGQUIT);

    if ((err = pthread_sigmask(SIG_BLOCK, &mask, NULL)) != 0) {
        print_err("SIG_BLOCK error\n");
        exit(1);
    }
}

static void init_stack()
{
    tun_init();
    netdev_init();
    route_init();
    arp_init();
    tcp_init();
}

static void run_threads()
{
    if (pthread_create(&threads[THREAD_CORE], NULL,
                       netdev_rx_loop, NULL) != 0) {
        print_err("Could not create netdev rx loop thread\n");
        return; 
    }

    if (pthread_create(&threads[THREAD_IPC], NULL,
                       start_ipc_listener, NULL) != 0) {
        print_err("Could not create ipc listener thread\n");
        return;
    }

    if (pthread_create(&threads[THREAD_SIGNAL], NULL, stop_stack_handler, 0)) {
        print_err("Could not create signal processor thread\n");
        return;
    }
}

static void wait_for_threads()
{
    for (int i = 0; i < 3; i++) {
        if (pthread_join(threads[i], NULL) != 0) {
            print_err("Error when joining threads\n");
            exit(1);
        }
    }

    print_debug("All threads joined\n");
}

void free_stack()
{
    free_sockets();
    free_routes();
    free_netdev();
    free_tun();
}

int main(int argc, char** argv)
{
    parse_cli(argc, argv);
    
    init_signals();
    init_stack();

    run_threads();
    wait_for_threads();

    free_stack();
}
