#ifndef _INET_H
#define _INET_H

#include "syshead.h"
#include "socket.h"

int inet_create(struct socket *sock, int protocol);
int inet_socket(struct socket *sock, int protocol);
int inet_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags);
int inet_stream_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags);

#endif
