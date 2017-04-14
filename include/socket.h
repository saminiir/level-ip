#ifndef SOCKET_H_
#define SOCKET_H_

#include "sock.h"
#include "wait.h"
#include "list.h"

#ifdef DEBUG_SOCKET
#define socket_dbg(sock)                                                \
    do {                                                                \
        print_debug("Socket fd %d pid %d state %d sk_state %d flags %d poll %d sport %d dport %d " \
                    "sock-sleep %d sk-sleep %d recv-q %d send-q %d",  \
                    sock->fd, sock->pid, sock->state, sock->sk->state, sock->flags, \
                    sock->sk->poll_events,                              \
                    sock->sk->sport, sock->sk->dport, sock->sleep.sleeping, \
                    sock->sk->recv_wait.sleeping, sock->sk->receive_queue.qlen, \
                    sock->sk->write_queue.qlen);                        \
    } while (0)
#else
#define socket_dbg(sock)
#endif

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
    int (*poll) (struct socket *sock);
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
    int flags;
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
int _poll(pid_t pid, struct pollfd fds[], nfds_t nfds, int timeout);
int _fcntl(pid_t pid, int fildes, int cmd, ...);
struct socket *socket_lookup(uint16_t sport, uint16_t dport);
int socket_free(struct socket *sock);
void abort_sockets();
void socket_debug();

#endif
