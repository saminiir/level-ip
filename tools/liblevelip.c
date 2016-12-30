#define _GNU_SOURCE
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include "liblevelip.h"

#define LVLIP_FD_BOUNDARY 4096
#define RCBUF_LEN 512

static int (*__start_main)(int (*main) (int, char * *, char * *), int argc, \
                           char * * ubp_av, void (*init) (void), void (*fini) (void), \
                           void (*rtld_fini) (void), void (* stack_end));

static int (*_read)(int sockfd, void *buf, size_t len) = NULL;
static int (*_write)(int sockfd, const void *buf, size_t len) = NULL;
static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*_socket)(int domain, int type, int protocol) = NULL;

static int lvlfd = 0;
#define BUFLEN 4096

static int is_fd_ours(int sockfd)
{
    return sockfd > LVLIP_FD_BOUNDARY;
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

int socket(int domain, int type, int protocol)
{
    if (domain != AF_INET || type != SOCK_STREAM || protocol != 0) {
        printf("lvl-ip does not support socket parameters "
               "(domain %x, type %x, prot %x), bouncing back to host stack\n",
               domain, type, protocol);
        return _socket(domain, type, protocol);
    }
    
    char *buf[RCBUF_LEN];

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

    // Send mocked syscall to lvl-ip
    if (write(lvlfd, (char *)msg, msglen) == -1) {
        perror("Error on writing socket ");
    }

    // Read return value from lvl-ip
    if (read(lvlfd, buf, RCBUF_LEN) == -1) {
        perror("Could not read IPC socket response ");
    }

    struct ipc_msg *response = (struct ipc_msg *) buf;

    if (response->type != IPC_SOCKET) {
        printf("ERR: IPC socket response type %4x, pid %d\n",
               response->type, response->pid);
        return -1;
    }

    int rc = *(int *) response->data;

    printf("Got lvl-ip socket fd %d, our pid %d\n", rc, pid);
        
    return rc;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (!is_fd_ours(sockfd)) return _connect(sockfd, addr, addrlen);

    char *buf[RCBUF_LEN];

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

    // Send mocked syscall to lvl-ip
    if (write(lvlfd, (char *)msg, msglen) == -1) {
        perror("Error on writing IPC connect ");
    }

    // Read return value from lvl-ip
    if (read(lvlfd, buf, RCBUF_LEN) == -1) {
        perror("Could not read IPC connect response ");
    }
    
    struct ipc_msg *response = (struct ipc_msg *) buf;

    if (response->type != IPC_CONNECT || response->pid != pid) {
        printf("ERR: IPC connect response type %d, pid %d\n",
               response->type, response->pid);
        return -1;
    }

    struct ipc_error *err = (struct ipc_error *) response->data;

    if (err->rc == -1) errno = err->err;

    return err->rc;
}

ssize_t write(int sockfd, const void *buf, size_t len)
{
    if (!is_fd_ours(sockfd)) return _write(sockfd, buf, len);

    char *rbuf[RCBUF_LEN] = { 0 };
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_write) + len;

    struct ipc_msg *msg = alloca(msglen);

    if (msg == NULL) {
        printf("Could not allocate memory in IPC write\n");
        return -1;
    }

    int pid = getpid();
    msg->type = IPC_WRITE;
    msg->pid = pid;

    struct ipc_write payload = {
        .sockfd = sockfd,
        .len = len
    };

    memcpy(msg->data, &payload, sizeof(struct ipc_write));
    memcpy(((struct ipc_write *)msg->data)->buf, buf, len);

    // Send mocked syscall to lvl-ip
    if (write(lvlfd, (char *)msg, msglen) == -1) {
        perror("Error on writing IPC write ");
    }

    // Read return value from lvl-ip
    if (read(lvlfd, rbuf, RCBUF_LEN) == -1) {
        perror("Could not read IPC write response ");
    }
    
    struct ipc_msg *response = (struct ipc_msg *) buf;

    if (response->type != IPC_WRITE || response->pid != pid) {
        printf("ERR: IPC write response type %d, pid %d\n",
               response->type, response->pid);
        return -1;
    }

    int rc = *(int *) response->data;
        
    return rc;
}

ssize_t read(int sockfd, void *buf, size_t len)
{
    if (!is_fd_ours(sockfd)) return _read(sockfd, buf, len);

    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_read);
    struct ipc_msg *msg = alloca(msglen);

    if (msg == NULL) {
        printf("Could not allocate memory in IPC read\n");
        return -1;
    }
    
    msg->type = IPC_READ;
    msg->pid = pid;

    struct ipc_read payload = {
        .sockfd = sockfd,
        .len = len
    };

    memcpy(msg->data, &payload, sizeof(struct ipc_read));

    // Send mocked syscall to lvl-ip
    if (write(lvlfd, (char *)msg, msglen) == -1) {
        perror("Error on writing IPC read ");
    }

    int rlen = msglen + len;
    char *rbuf[rlen];
    memset(rbuf, 0, rlen);

    // Read return value from lvl-ip
    if (read(lvlfd, rbuf, rlen) == -1) {
        perror("Could not read IPC read response ");
    }
    
    struct ipc_msg *response = (struct ipc_msg *) buf;

    if (response->type != IPC_READ || response->pid != pid) {
        printf("ERR: IPC read response type %d, pid %d\n",
               response->type, response->pid);
        return -1;
    }

    struct ipc_read *data = (struct ipc_read *) msg->data;

    if (data->len < 0 || len < data->len) {
        printf("IPC read received len error: %d\n", data->len);
        return -1;
    }

    memcpy(buf, data->buf, data->len);
        
    return data->len;
}

int __libc_start_main(int (*main) (int, char * *, char * *), int argc,
                      char * * ubp_av, void (*init) (void), void (*fini) (void),
                      void (*rtld_fini) (void), void (* stack_end))
{
    __start_main = dlsym(RTLD_NEXT, "__libc_start_main");

    _read = dlsym(RTLD_NEXT, "read");
    _write = dlsym(RTLD_NEXT, "write");
    _connect = dlsym(RTLD_NEXT, "connect");
    _socket = dlsym(RTLD_NEXT, "socket");
 
    lvlfd = init_socket("/tmp/lvlip.socket");

    return __start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}
