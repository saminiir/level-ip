#include "syshead.h"
#include "utils.h"
#include "socket.h"
#include "inet.h"
#include "wait.h"
#include "timer.h"

static int sock_amount = 0;
static LIST_HEAD(sockets);
static pthread_rwlock_t slock = PTHREAD_RWLOCK_INITIALIZER;

extern struct net_family inet;

static struct net_family *families[128] = {
    [AF_INET] = &inet,
};

static struct socket *alloc_socket(pid_t pid)
{
    // TODO: Figure out a way to not shadow kernel file descriptors.
    // Now, we'll just expect the fds for a process to never exceed this.
    static int fd = 4097;
    struct socket *sock = malloc(sizeof (struct socket));
    list_init(&sock->list);

    sock->pid = pid;

    pthread_rwlock_wrlock(&slock);
    sock->fd = fd++;
    pthread_rwlock_unlock(&slock);

    sock->state = SS_UNCONNECTED;
    sock->ops = NULL;
    sock->flags = O_RDWR;
    wait_init(&sock->sleep);
    pthread_rwlock_init(&sock->lock, NULL);
    
    return sock;
}

int socket_free(struct socket *sock)
{
    list_del(&sock->list);
    sock_amount--;

    if (sock->ops) {
        sock->ops->free(sock);
    }

    wait_free(&sock->sleep);
    pthread_rwlock_unlock(&sock->lock);    
    
    free(sock);
    
    return 0;
}

static void *socket_garbage_collect(void *arg)
{
    struct socket *sock = (struct socket *)arg;

    pthread_rwlock_wrlock(&slock);
    pthread_rwlock_wrlock(&sock->lock);
    socket_dbg(sock, "Garbage collecting (freeing) socket");
    socket_free(sock);

    pthread_rwlock_unlock(&slock);

    return NULL;
}

int socket_delete(struct socket *sock)
{
    int rc = 0;

    pthread_mutex_lock(&sock->sk->lock);

    if (sock->state == SS_DISCONNECTING) goto out;

    sock->state = SS_DISCONNECTING;
    timer_oneshot(10000, &socket_garbage_collect, sock);

out:
    pthread_mutex_unlock(&sock->sk->lock);
    return rc;
}

void abort_sockets() {
    struct list_head *item, *tmp;
    struct socket *sock;

    list_for_each_safe(item, tmp, &sockets) {
        sock = list_entry(item, struct socket, list);
        sock->ops->abort(sock);
    }
}

static struct socket *get_socket(pid_t pid, uint32_t fd)
{
    struct list_head *item;
    struct socket *sock = NULL;

    pthread_rwlock_rdlock(&slock);
    list_for_each(item, &sockets) {
        sock = list_entry(item, struct socket, list);
        if (sock->pid == pid && sock->fd == fd) goto out;
    }
    
    sock = NULL;

out:
    pthread_rwlock_unlock(&slock);
    return sock;
}

struct socket *socket_lookup(uint16_t remoteport, uint16_t localport)
{
    struct list_head *item;
    struct socket *sock = NULL;
    struct sock *sk = NULL;

    pthread_rwlock_rdlock(&slock);
    
    list_for_each(item, &sockets) {
        sock = list_entry(item, struct socket, list);

        if (sock == NULL || sock->sk == NULL) continue;
        sk = sock->sk;

        if (sk->sport == localport && sk->dport == remoteport) {
            goto found;
        }
    }

    sock = NULL;
found:
    pthread_rwlock_unlock(&slock);
    return sock;
}

#ifdef DEBUG_SOCKET
void socket_debug()
{
    struct list_head *item;
    struct socket *sock = NULL;

    pthread_rwlock_rdlock(&slock);

    list_for_each(item, &sockets) {
        sock = list_entry(item, struct socket, list);
        pthread_rwlock_rdlock(&sock->lock);
        socket_dbg(sock, "");
        pthread_rwlock_unlock(&sock->lock);
    }

    pthread_rwlock_unlock(&slock);
}
#else
void socket_debug()
{
    return;
}
#endif

int _socket(pid_t pid, int domain, int type, int protocol)
{
    struct socket *sock;
    struct net_family *family;

    if ((sock = alloc_socket(pid)) == NULL) {
        print_err("Could not alloc socket\n");
        return -1;
    }

    sock->type = type;

    family = families[domain];

    if (!family) {
        print_err("Domain not supported: %d\n", domain);
        goto abort_socket;
    }
    
    if (family->create(sock, protocol) != 0) {
        print_err("Creating domain failed\n");
        goto abort_socket;
    }

    pthread_rwlock_wrlock(&slock);
    
    list_add_tail(&sock->list, &sockets);
    sock_amount++;

    pthread_rwlock_rdlock(&sock->lock);
    pthread_rwlock_unlock(&slock);
    int rc = sock->fd;
    pthread_rwlock_unlock(&sock->lock);

    return rc;

abort_socket:
    socket_free(sock);
    return -1;
}

int _connect(pid_t pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct socket *sock;

    if ((sock = get_socket(pid, sockfd)) == NULL) {
        print_err("Connect: could not find socket (fd %u) for connection (pid %d)\n", sockfd, pid);
        return -EBADF;
    }

    pthread_rwlock_wrlock(&sock->lock);
    int rc = sock->ops->connect(sock, addr, addrlen, 0);
    pthread_rwlock_unlock(&sock->lock);
    
    return rc;
}

int _write(pid_t pid, int sockfd, const void *buf, const unsigned int count)
{
    struct socket *sock;

    if ((sock = get_socket(pid, sockfd)) == NULL) {
        print_err("Write: could not find socket (fd %u) for connection (pid %d)\n", sockfd, pid);
        return -EBADF;
    }

    pthread_rwlock_wrlock(&sock->lock);
    int rc = sock->ops->write(sock, buf, count);
    pthread_rwlock_unlock(&sock->lock);

    return rc;
}

int _read(pid_t pid, int sockfd, void *buf, const unsigned int count)
{
    struct socket *sock;

    if ((sock = get_socket(pid, sockfd)) == NULL) {
        print_err("Read: could not find socket (fd %u) for connection (pid %d)\n", sockfd, pid);
        return -EBADF;
    }

    pthread_rwlock_wrlock(&sock->lock);
    int rc = sock->ops->read(sock, buf, count);
    pthread_rwlock_unlock(&sock->lock);

    return rc;
}

int _close(pid_t pid, int sockfd)
{
    struct socket *sock;

    if ((sock = get_socket(pid, sockfd)) == NULL) {
        print_err("Close: could not find socket (fd %u) for connection (pid %d)\n", sockfd, pid);
        return -EBADF;
    }


    pthread_rwlock_wrlock(&sock->lock);
    int rc = sock->ops->close(sock);
    pthread_rwlock_unlock(&sock->lock);

    return rc;
}

int _poll(pid_t pid, struct pollfd fds[], nfds_t nfds, int timeout)
{
    for (;;) {
        int polled = 0;

        for (int i = 0; i < nfds; i++) {
            struct socket *sock;
            struct pollfd *poll = &fds[i];
            if ((sock = get_socket(pid, poll->fd)) == NULL) {
                print_err("Poll: could not find socket (fd %u) for connection (pid %d)\n", poll->fd, pid);
                return -EBADF;
            }

            pthread_rwlock_rdlock(&sock->lock);
            poll->revents = sock->sk->poll_events & (poll->events | POLLHUP | POLLERR | POLLNVAL);
            if (poll->revents > 0) {
                polled++;
            }
            pthread_rwlock_unlock(&sock->lock);
        }

        if (polled > 0 || timeout == 0) {
            return polled;
        } else {
            if (timeout > 0) {
                if (timeout > 10) {
                    timeout -= 10;
                } else {
                    timeout = 0;
                }
            }
            usleep(1000 * 10);
        }
    }

    return -EAGAIN;
}

int _fcntl(pid_t pid, int fildes, int cmd, ...)
{
    struct socket *sock;

    if ((sock = get_socket(pid, fildes)) == NULL) {
        print_err("Fcntl: could not find socket (fd %u) for connection (pid %d)\n", fildes, pid);
        return -EBADF;
    }

    pthread_rwlock_wrlock(&sock->lock);
    va_list ap;
    int rc = 0;

    switch (cmd) {
    case F_GETFL:
        rc = sock->flags;
        goto out;
    case F_SETFL:
        va_start(ap, cmd);
        sock->flags = va_arg(ap, int);
        va_end(ap);
        rc = 0;
        goto out;
    default:
        rc = -1;
        goto out;
    }

    rc = -1;

out:
    pthread_rwlock_unlock(&sock->lock);
    return rc;
}

int _getsockopt(pid_t pid, int fd, int level, int optname, void *optval, socklen_t *optlen)
{
    struct socket *sock;

    if ((sock = get_socket(pid, fd)) == NULL) {
        print_err("Getsockopt: could not find socket (fd %u) for connection (pid %d)\n", fd, pid);
        return -EBADF;
    }

    int rc = 0;

    pthread_rwlock_rdlock(&sock->lock);
    switch (level) {
    case SOL_SOCKET:
        switch (optname) {
        case SO_ERROR:
            *optlen = 4;
            *(int *)optval = sock->sk->err;
            rc = 0;
            break;
        default:
            print_err("Getsockopt unsupported optname %d\n", optname);
            rc =  -ENOPROTOOPT;
            break;
        }
        
        break;
    default:
        print_err("Getsockopt: Unsupported level %d\n", level);
        rc = -EINVAL;
        break;
    }

    pthread_rwlock_unlock(&sock->lock);

    return rc;
}

int _getpeername(pid_t pid, int socket, struct sockaddr *restrict address,
                 socklen_t *restrict address_len)
{
    struct socket *sock;

    if ((sock = get_socket(pid, socket)) == NULL) {
        print_err("Getpeername: could not find socket (fd %u) for connection (pid %d)\n", socket, pid);
        return -EBADF;
    }

    pthread_rwlock_rdlock(&sock->lock);
    int rc = sock->ops->getpeername(sock, address, address_len);
    pthread_rwlock_unlock(&sock->lock);

    return rc;
}

int _getsockname(pid_t pid, int socket, struct sockaddr *restrict address,
                 socklen_t *restrict address_len)
{
    struct socket *sock;

    if ((sock = get_socket(pid, socket)) == NULL) {
        print_err("Getsockname: could not find socket (fd %u) for connection (pid %d)\n", socket, pid);
        return -EBADF;
    }

    pthread_rwlock_rdlock(&sock->lock);
    int rc = sock->ops->getsockname(sock, address, address_len);
    pthread_rwlock_unlock(&sock->lock);

    return rc;
}
