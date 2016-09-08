#ifndef SOCKET_H_
#define SOCKET_H_

struct socket;

enum socket_state {
    SS_FREE = 0,                    /* not allocated                */
    SS_UNCONNECTED,                 /* unconnected to any socket    */
    SS_CONNECTING,                  /* in process of connecting     */
    SS_CONNECTED,                   /* connected to socket          */
    SS_DISCONNECTING                /* in process of disconnecting  */
};

struct proto_ops {
    int             (*connect)   (struct socket *sock,
                                  struct sockaddr *vaddr,
                                  int sockaddr_len, int flags);
};

struct socket {
    int fd;
    enum socket_state state;
    short type;
    struct proto_ops *ops;
};

int _socket(int domain, int type, int protocol);
int _connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

#endif
