#define _GNU_SOURCE
#include <sys/socket.h>
#include <stdio.h>
#include <dlfcn.h>

static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*_socket)(int domain, int type, int protocol) = NULL;

int socket(int domain, int type, int protocol)
{
    _socket = dlsym(RTLD_NEXT, "socket");

    return _socket(domain, type, protocol);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    _connect = dlsym(RTLD_NEXT, "connect");

    return _connect(sockfd, addr, addrlen);
}
