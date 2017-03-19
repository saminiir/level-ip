#include "syshead.h"
#include "basic.h"
#include "cli.h"
#include "tuntap_if.h"
#include "utils.h"
#include "ipc.h"
#include "timer.h"
#include "route.h"
#include "ethernet.h"
#include "arp.h"
#include "tcp.h"
#include "netdev.h"
#include "ip.h"

#define MAX_CMD_LENGTH 6

typedef void (*sighandler_t)(int);

#define THREAD_CORE 0
#define THREAD_TIMERS 1
#define THREAD_IPC 2
#define THREAD_SIGNAL 3
static pthread_t threads[4];

int running = 1;
sigset_t mask;

static void create_thread(pthread_t id, void *(*func) (void *))
{
    if (pthread_create(&threads[id], NULL,
                       func, NULL) != 0) {
        print_err("Could not create core thread\n");
    }
}

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
            pthread_cancel(threads[THREAD_TIMERS]);
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
    create_thread(THREAD_CORE, netdev_rx_loop);
    create_thread(THREAD_TIMERS, timers_start);
    create_thread(THREAD_IPC, start_ipc_listener);
    create_thread(THREAD_SIGNAL, stop_stack_handler);
}

static void wait_for_threads()
{
    for (int i = 0; i < 3; i++) {
        if (pthread_join(threads[i], NULL) != 0) {
            print_err("Error when joining threads\n");
            exit(1);
        }
    }
}

void free_stack()
{
    abort_sockets();
    free_arp();
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
