#ifndef SOCKET_H_
#define SOCKET_H_

#include "sock.h"
#include "wait.h"
#include "list.h"

#ifdef DEBUG_SOCKET
#define socket_dbg(sock, msg, ...)                                      \
    do {                                                                \
        print_debug("Socket fd %d pid %d state %d sk_state %d flags %d poll %d sport %d dport %d " \
                    "recv-q %d send-q %d: "msg,    \
                    sock->fd, sock->pid, sock->state, sock->sk->state, sock->flags, \
                    sock->sk->poll_events,                              \
                    sock->sk->sport, sock->sk->dport, \
                    sock->sk->receive_queue.qlen, \
                    sock->sk->write_queue.qlen, ##__VA_ARGS__);         \
    } while (0)
#else
#define socket_dbg(sock, msg, ...)
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
    int (*getpeername) (struct socket *sock, struct sockaddr *restrict addr,
                        socklen_t *restrict address_len);
    int (*getsockname) (struct socket *sock, struct sockaddr *restrict addr,
                        socklen_t *restrict address_len);
};

struct net_family {
    int (*create) (struct socket *sock, int protocol);    
};

struct socket {
    struct list_head list;
    int fd;
    pid_t pid;
    int refcnt;
    enum socket_state state;
    short type;
    int flags;
    struct sock *sk;
    struct sock_ops *ops;
    struct wait_lock sleep;
    pthread_rwlock_t lock;
};

void *socket_ipc_open(void *args);
int _socket(pid_t pid, int domain, int type, int protocol);
int _connect(pid_t pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int _write(pid_t pid, int sockfd, const void *buf, const unsigned int count);
int _read(pid_t pid, int sockfd, void *buf, const unsigned int count);
int _close(pid_t pid, int sockfd);
int _poll(pid_t pid, struct pollfd fds[], nfds_t nfds, int timeout);
int _fcntl(pid_t pid, int fildes, int cmd, ...);
int _getsockopt(pid_t pid, int fd, int level, int optname, void *optval, socklen_t *optlen);
int _getpeername(pid_t pid, int socket, struct sockaddr *restrict address,
                 socklen_t *restrict address_len);
int _getsockname(pid_t pid, int socket, struct sockaddr *restrict address,
                 socklen_t *restrict address_len);

struct socket *socket_lookup(uint16_t sport, uint16_t dport);
struct socket *socket_find(struct socket *sock);
int socket_rd_acquire(struct socket *sock);
int socket_wr_acquire(struct socket *sock);
int socket_release(struct socket *sock);
int socket_free(struct socket *sock);
int socket_delete(struct socket *sock);
void abort_sockets();
void socket_debug();

#endif
