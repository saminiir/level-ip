#ifndef _INET_H
#define _INET_H

#include "syshead.h"
#include "socket.h"
#include "skbuff.h"

#ifdef DEBUG_SOCKET
#define inet_dbg(sock, msg, ...)                                            \
    do {                                                                \
        socket_dbg(sock, "INET "msg, ##__VA_ARGS__);                    \
    } while (0)
#else
#define inet_dbg(msg, th, ...)
#endif

int inet_create(struct socket *sock, int protocol);
int inet_socket(struct socket *sock, int protocol);
int inet_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags);
int inet_write(struct socket *sock, const void *buf, int len);
int inet_read(struct socket *sock, void *buf, int len);
int inet_close(struct socket *sock);
int inet_free(struct socket *sock);
int inet_abort(struct socket *sock);
int inet_getpeername(struct socket *sock, struct sockaddr *restrict address,
                     socklen_t *restrict address_len);
int inet_getsockname(struct socket *sock, struct sockaddr *restrict address,
                     socklen_t *restrict address_len);

struct sock *inet_lookup(struct sk_buff *skb, uint16_t sport, uint16_t dport);
#endif
