#define _GNU_SOURCE
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int (*__start_main)(int (*main) (int, char * *, char * *), int argc, \
                           char * * ubp_av, void (*init) (void), void (*fini) (void), \
                           void (*rtld_fini) (void), void (* stack_end));

static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*_socket)(int domain, int type, int protocol) = NULL;

static int sockfd = 0;
#define BUFLEN 4096

int socket(int domain, int type, int protocol)
{
    return _socket(domain, type, protocol);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    return _connect(sockfd, addr, addrlen);
}

static int init_socket(char *sockname)
{
    struct sockaddr_un addr;
    int i;
    int ret;
    int data_socket;
    char buffer[BUFLEN];

    /* Create local socket. */

    data_socket = _socket(AF_UNIX, SOCK_STREAM, 0);
    if (data_socket == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    /*
     * For portability clear the whole structure, since some
     * implementations have additional (nonstandard) fields in
     * the structure.
     */

    memset(&addr, 0, sizeof(struct sockaddr_un));

    /* Connect socket to socket address */

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sockname, sizeof(addr.sun_path) - 1);

    ret = _connect(data_socket, (const struct sockaddr *) &addr,
                   sizeof(struct sockaddr_un));
    if (ret == -1) {
        fprintf(stderr, "Error connecting to level-ip. Is it up?\n");
        exit(EXIT_FAILURE);
    }

    return data_socket;
}

int __libc_start_main(int (*main) (int, char * *, char * *), int argc, char * * ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
    __start_main = dlsym(RTLD_NEXT, "__libc_start_main");

    _connect = dlsym(RTLD_NEXT, "connect");
    _socket = dlsym(RTLD_NEXT, "socket");
 
    sockfd = init_socket("/tmp/lvlip.socket");

    return __start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}
