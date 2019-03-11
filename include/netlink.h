#ifndef _NETLINK_H
#define _NETLINK_H

#include "syshead.h"
#include "socket.h"
#include "skbuff.h"

#ifdef DEBUG_SOCKET
#define netlink_dbg(sock, msg, ...)                                            \
    do {                                                                \
        socket_dbg(sock, "NETLINK "msg, ##__VA_ARGS__);                    \
    } while (0)
#else
#define netlink_dbg(msg, th, ...)
#endif

int netlink_create(struct socket *sock, int protocol);
int netlink_socket(struct socket *sock, int protocol);
int netlink_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags);
int netlink_write(struct socket *sock, const void *buf, int len);
int netlink_read(struct socket *sock, void *buf, int len);
int netlink_close(struct socket *sock);
int netlink_free(struct socket *sock);
int netlink_abort(struct socket *sock);
int netlink_getpeername(struct socket *sock, struct sockaddr *restrict address,
                     socklen_t *restrict address_len);
int netlink_getsockname(struct socket *sock, struct sockaddr *restrict address,
                     socklen_t *restrict address_len);
int netlink_sendmsg(struct socket *sock, struct msghdr *message, int flags);
int netlink_recvmsg(struct socket *sock, struct msghdr *message, int flags);

struct sock *netlink_lookup(struct sk_buff *skb, uint16_t sport, uint16_t dport);
#endif
