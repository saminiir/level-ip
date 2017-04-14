#ifndef LIBLEVELIP_H_
#define LIBLEVELIP_H_

#include <poll.h>
#include <dlfcn.h>
#include "list.h"
#include "utils.h"

#ifdef DEBUG_API
#define lvl_dbg(msg, ...)                                               \
    do {                                                                \
        print_debug(msg, ##__VA_ARGS__);                                \
    } while (0)
#define lvl_sock_dbg(msg, sock)                                            \
    do {                                                                \
        print_debug("lvlip-sock lvlfd %d fd %d: %s", sock->lvlfd, sock->fd, msg); \
    } while (0)
#else
#define lvl_sock_dbg(msg, sock)
#define lvl_dbg(msg, ...)
#endif

struct lvlip_sock {
    struct list_head list;
    int lvlfd; /* For Level-IP IPC */
    int fd;
};

static inline struct lvlip_sock *lvlip_alloc() {
    struct lvlip_sock *sock = malloc(sizeof(struct lvlip_sock));
    memset(sock, 0, sizeof(struct lvlip_sock));

    return sock;
};

static inline void lvlip_free(struct lvlip_sock *sock) {
    free(sock);
}

#endif
