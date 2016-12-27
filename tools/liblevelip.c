#define _GNU_SOURCE
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "liblevelip.h"

static int (*__start_main)(int (*main) (int, char * *, char * *), int argc, \
                           char * * ubp_av, void (*init) (void), void (*fini) (void), \
                           void (*rtld_fini) (void), void (* stack_end));

static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*_socket)(int domain, int type, int protocol) = NULL;

static int lvlfd = 0;
#define BUFLEN 4096

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

int socket(int domain, int type, int protocol)
{
    if (domain != AF_INET || type != SOCK_STREAM || protocol != 0) {
        printf("lvl-ip does not support these socket parameters, offloading to host stack\n");
        return _socket(domain, type, protocol);
    }
    
    int len = 512;
    char *buf[len];

    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_socket);

    struct ipc_msg *msg = calloc(msglen, 1);
    msg->type = IPC_SOCKET;

    struct ipc_socket sock = {
        .domain = domain,
        .type = type,
        .protocol = protocol
    };
    
    memcpy(msg->data, &sock, sizeof(struct ipc_socket));

    // Send mocked syscall to lvl-ip
    if (write(lvlfd, (char *)msg, msglen) == -1) {
        perror("Error on writing socket ");
    }

    free(msg);

    // Read return value from lvl-ip
    if (read(lvlfd, buf, len) == -1) {
        perror("Could not read IPC socket response ");
    }
    
    struct ipc_msg *response = (struct ipc_msg *) buf;

    if (response->type != IPC_SOCKET) {
        printf("Message did not contain socket\n");
        return -1;
    }

    int rc = *(int *) response->data;
        
    return rc;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    return _connect(sockfd, addr, addrlen);
}

int __libc_start_main(int (*main) (int, char * *, char * *), int argc, char * * ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
    __start_main = dlsym(RTLD_NEXT, "__libc_start_main");

    _connect = dlsym(RTLD_NEXT, "connect");
    _socket = dlsym(RTLD_NEXT, "socket");
 
    lvlfd = init_socket("/tmp/lvlip.socket");

    return __start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}
