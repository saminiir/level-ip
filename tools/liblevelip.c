#define _GNU_SOURCE
#include <sys/socket.h>
#include <stdio.h>
#include <dlfcn.h>

static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    _connect = dlsym(RTLD_NEXT, "connect");

    return _connect(sockfd, addr, addrlen);
}
