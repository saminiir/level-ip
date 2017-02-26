#define _GNU_SOURCE
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include "liblevelip.h"

#define LVLIP_FD_BOUNDARY 4096
#define RCBUF_LEN 512

static int (*__start_main)(int (*main) (int, char * *, char * *), int argc, \
                           char * * ubp_av, void (*init) (void), void (*fini) (void), \
                           void (*rtld_fini) (void), void (* stack_end));

static int (*_fcntl)(int fildes, int cmd, ...) = NULL;
static int (*_setsockopt)(int fd, int level, int optname,
                         const void *optval, socklen_t optlen) = NULL;
static int (*_getsockopt)(int fd, int level, int optname,
                         const void *optval, socklen_t *optlen) = NULL;
static int (*_read)(int sockfd, void *buf, size_t len) = NULL;
static int (*_write)(int sockfd, const void *buf, size_t len) = NULL;
static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*_socket)(int domain, int type, int protocol) = NULL;
static int (*_close)(int fildes) = NULL;
static int (*_poll)(struct pollfd fds[], nfds_t nfds, int timeout) = NULL;
static ssize_t (*_sendto)(int sockfd, const void *message, size_t length,
                          int flags, const struct sockaddr *dest_addr,
                          socklen_t dest_len) = NULL;
static ssize_t (*_recvfrom)(int sockfd, void *buf, size_t len,
                            int flags, struct sockaddr *restrict address,
                            socklen_t *restrict addrlen) = NULL;

static int lvlfd = 0;

static int is_fd_ours(int sockfd)
{
    return sockfd > LVLIP_FD_BOUNDARY;
}

static int is_socket_supported(int domain, int type, int protocol)
{
    if (domain != AF_INET) return 0;

    if (!(type & SOCK_STREAM)) return 0;

    if (protocol != 0 && protocol != IPPROTO_TCP) return 0;

    return 1;
}

static int init_socket(char *sockname)
{
    struct sockaddr_un addr;
    int i;
    int ret;
    int data_socket;

    /* Create local socket. */

    data_socket = _socket(AF_UNIX, SOCK_STREAM, 0);
    if (data_socket == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    /*
     * For portability clear the whole structure, since some
     * implementations have additional (nonstandard) fields in
     * the structure.
     */

    memset(&addr, 0, sizeof(struct sockaddr_un));

    /* Connect socket to socket address */

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sockname, sizeof(addr.sun_path) - 1);

    ret = _connect(data_socket, (const struct sockaddr *) &addr,
                   sizeof(struct sockaddr_un));
    if (ret == -1) {
        fprintf(stderr, "Error connecting to level-ip. Is it up?\n");
        exit(EXIT_FAILURE);
    }

    return data_socket;
}

static int transmit_lvlip(struct ipc_msg *msg, int msglen)
{
    char *buf[RCBUF_LEN];

    // Send mocked syscall to lvl-ip
    if (_write(lvlfd, (char *)msg, msglen) == -1) {
        perror("Error on writing IPC");
    }

    // Read return value from lvl-ip
    if (_read(lvlfd, buf, RCBUF_LEN) == -1) {
        perror("Could not read IPC response");
    }
    
    struct ipc_msg *response = (struct ipc_msg *) buf;

    if (response->type != msg->type || response->pid != msg->pid) {
        printf("ERR: IPC msg response expected type %d, pid %d\n"
               "                      actual type %d, pid %d\n",
               msg->type, msg->pid, response->type, response->pid);
        return -1;
    }

    struct ipc_err *err = (struct ipc_err *) response->data;

    if (err->rc == -1) errno = err->err;

    return err->rc;
}

int socket(int domain, int type, int protocol)
{
    if (!is_socket_supported(domain, type, protocol)) {
        printf("lvl-ip does not support socket parameters "
               "(domain %x, type %x, prot %x), bouncing back to host stack\n",
               domain, type, protocol);
        return _socket(domain, type, protocol);
    }
    
    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_socket);

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_SOCKET;
    msg->pid = pid;

    struct ipc_socket sock = {
        .domain = domain,
        .type = type,
        .protocol = protocol
    };
    
    memcpy(msg->data, &sock, sizeof(struct ipc_socket));

    return transmit_lvlip(msg, msglen);
}

int close(int fd)
{
    if (!is_fd_ours(fd)) return _close(fd);

    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(int);

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_CLOSE;
    msg->pid = pid;

    memcpy(msg->data, &fd, sizeof(int));

    return transmit_lvlip(msg, msglen);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (!is_fd_ours(sockfd)) return _connect(sockfd, addr, addrlen);

    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_connect);
    int pid = getpid();
    
    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_CONNECT;
    msg->pid = pid;

    struct ipc_connect payload = {
        .sockfd = sockfd,
        .addr = *addr,
        .addrlen = addrlen
    };

    memcpy(msg->data, &payload, sizeof(struct ipc_connect));

    return transmit_lvlip(msg, msglen);
}

ssize_t write(int sockfd, const void *buf, size_t len)
{
    if (!is_fd_ours(sockfd)) return _write(sockfd, buf, len);

    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_write) + len;
    int pid = getpid();

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_WRITE;
    msg->pid = pid;

    struct ipc_write payload = {
        .sockfd = sockfd,
        .len = len
    };

    memcpy(msg->data, &payload, sizeof(struct ipc_write));
    memcpy(((struct ipc_write *)msg->data)->buf, buf, len);

    return transmit_lvlip(msg, msglen);
}

ssize_t read(int sockfd, void *buf, size_t len)
{
    if (!is_fd_ours(sockfd)) return _read(sockfd, buf, len);

    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_read);

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_READ;
    msg->pid = pid;

    struct ipc_read payload = {
        .sockfd = sockfd,
        .len = len
    };

    memcpy(msg->data, &payload, sizeof(struct ipc_read));

    // Send mocked syscall to lvl-ip
    if (_write(lvlfd, (char *)msg, msglen) == -1) {
        perror("Error on writing IPC read");
    }

    int rlen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_read) + len;
    char rbuf[rlen];
    memset(rbuf, 0, rlen);

    // Read return value from lvl-ip
    if (_read(lvlfd, rbuf, rlen) == -1) {
        perror("Could not read IPC read response");
    }
    
    struct ipc_msg *response = (struct ipc_msg *) rbuf;

    if (response->type != IPC_READ || response->pid != pid) {
        printf("ERR: IPC read response expected: type %d, pid %d\n"
               "                       actual: type %d, pid %d\n",
               IPC_READ, pid, response->type, response->pid);
        return -1;
    }

    struct ipc_err *error = (struct ipc_err *) response->data;
    if (error->rc < 0) {
        errno = error->err;
        return error->rc;
    }

    struct ipc_read *data = (struct ipc_read *) error->data;
    if (data->len < 0 || len < data->len) {
        printf("IPC read received len error: %d\n", data->len);
        return -1;
    }

    memset(buf, 0, len);
    memcpy(buf, data->buf, data->len);
        
    return data->len;
}

ssize_t send(int fd, const void *buf, size_t len, int flags)
{
    return sendto(fd, buf, len, flags, NULL, 0);
}

ssize_t sendto(int fd, const void *buf, size_t len,
               int flags, const struct sockaddr *dest_addr,
               socklen_t dest_len)
{
    if (!is_fd_ours(fd)) return _sendto(fd, buf, len,
                                        flags, dest_addr, dest_len);

    return write(fd, buf, len);
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
    return recvfrom(fd, buf, len, flags, NULL, 0);
}

ssize_t recvfrom(int fd, void *restrict buf, size_t len,
                 int flags, struct sockaddr *restrict address,
                 socklen_t *restrict addrlen)
{
    if (!is_fd_ours(fd)) return _recvfrom(fd, buf, len,
                                          flags, address, addrlen);

    return read(fd, buf, len);
}

int poll(struct pollfd fds[], nfds_t nfds, int timeout)
{
    /* TODO: Implement poll semantics. Curl uses this, won't work without it */
    return _poll(fds, nfds, timeout);
}

int setsockopt(int fd, int level, int optname,
               const void *optval, socklen_t optlen)
{
    if (!is_fd_ours(fd)) return _setsockopt(fd, level, optname, optval, optlen);

    printf("Setsockopt not supported yet\n");
    return 0;
}

int getsockopt(int fd, int level, int optname,
               void *optval, socklen_t *optlen)
{
    if (!is_fd_ours(fd)) return _getsockopt(fd, level, optname, optval, optlen);

    printf("Getsockopt not supported yet\n");
    return 0;
}

int fcntl(int fildes, int cmd, ...)
{
    va_list ap;
    void *arg;

    va_start(ap, cmd);

    arg = va_arg(ap, void*);

    va_end(ap);

    if (!is_fd_ours(fildes)) return _fcntl(fildes, cmd, arg);
    
    printf("Fcntl not supported yet\n");
    return 0;
}

int __libc_start_main(int (*main) (int, char * *, char * *), int argc,
                      char * * ubp_av, void (*init) (void), void (*fini) (void),
                      void (*rtld_fini) (void), void (* stack_end))
{
    __start_main = dlsym(RTLD_NEXT, "__libc_start_main");

    _sendto = dlsym(RTLD_NEXT, "sendto");
    _recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    _poll = dlsym(RTLD_NEXT, "poll");
    _fcntl = dlsym(RTLD_NEXT, "fcntl");
    _setsockopt = dlsym(RTLD_NEXT, "setsockopt");
    _getsockopt = dlsym(RTLD_NEXT, "getsockopt");
    _read = dlsym(RTLD_NEXT, "read");
    _write = dlsym(RTLD_NEXT, "write");
    _connect = dlsym(RTLD_NEXT, "connect");
    _socket = dlsym(RTLD_NEXT, "socket");
    _close = dlsym(RTLD_NEXT, "close");
 
    lvlfd = init_socket("/tmp/lvlip.socket");

    return __start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}
