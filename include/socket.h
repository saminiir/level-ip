#ifndef SOCKET_H_
#define SOCKET_H_

#include "sock.h"
#include "wait.h"
#include "list.h"

struct socket;

enum socket_state {
    SS_FREE = 0,                    /* not allocated                */
    SS_UNCONNECTED,                 /* unconnected to any socket    */
    SS_CONNECTING,                  /* in process of connecting     */
    SS_CONNECTED,                   /* connected to socket          */
    SS_DISCONNECTING                /* in process of disconnecting  */
};

struct sock_type {
    struct sock_ops *sock_ops;
    struct net_ops *net_ops;
    int type;
    int protocol;
};

struct sock_ops {
    int (*connect) (struct socket *sock, const struct sockaddr *addr,
                    int addr_len, int flags);
    int (*write) (struct socket *sock, const void *buf, int len);
    int (*read) (struct socket *sock, void *buf, int len);
    int (*close) (struct socket *sock);
    int (*free) (struct socket *sock);
    int (*abort) (struct socket *sock);
};

struct net_family {
    int (*create) (struct socket *sock, int protocol);    
};

struct socket {
    struct list_head list;
    int fd;
    pid_t pid;
    enum socket_state state;
    short type;
    struct sock *sk;
    struct sock_ops *ops;
    struct wait_lock sleep;
};

void *socket_ipc_open(void *args);
int _socket(pid_t pid, int domain, int type, int protocol);
int _connect(pid_t pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int _write(pid_t pid, int sockfd, const void *buf, const unsigned int count);
int _read(pid_t pid, int sockfd, void *buf, const unsigned int count);
int _close(pid_t pid, int sockfd);
struct socket *socket_lookup(uint16_t sport, uint16_t dport);
int socket_free(struct socket *sock);
void abort_sockets();

#endif
