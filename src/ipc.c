#include "syshead.h"
#include "utils.h"
#include "ipc.h"
#include "socket.h"

#define IPC_BUFLEN 4096

// TODO: dynamic socket pool
static pthread_t sockets[256];
static int cur_th = 0;

static int ipc_write_rc(int sockfd, pid_t pid, uint16_t type, int rc)
{
    int resplen = sizeof(struct ipc_msg) + sizeof(struct ipc_err);
    struct ipc_msg *response = alloca(resplen);

    if (response == NULL) {
        print_err("Could not allocate memory for IPC write response\n");
        return -1;
    }

    response->type = type;
    response->pid = pid;

    struct ipc_err err;

    if (rc < 0) {
        err.err = -rc;
        err.rc = -1;
    } else {
        err.err = 0;
        err.rc = rc;
    }
    
    memcpy(response->data, &err, sizeof(struct ipc_err));

    if (write(sockfd, (char *)response, resplen) == -1) {
        perror("Error on writing IPC write response");
    }

    return 0;
}

static int ipc_read(int sockfd, struct ipc_msg *msg)
{
    struct ipc_read *requested = (struct ipc_read *) msg->data;
    pid_t pid = msg->pid;
    int rlen = -1;
    char rbuf[requested->len];
    memset(rbuf, 0, requested->len);

    rlen = _read(pid, requested->sockfd, rbuf, requested->len);

    if (rlen < 0 || requested->len < rlen) {
        printf("Error on IPC read, requested len %lu, actual len %d, sockfd %d, pid %d\n",
               requested->len, rlen, requested->sockfd, pid);
    }

    int resplen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_read) + rlen;
    struct ipc_msg *response = alloca(resplen);
    struct ipc_err *error = (struct ipc_err *) response->data;
    struct ipc_read *actual = (struct ipc_read *) error->data;

    if (response == NULL) {
        print_err("Could not allocate memory for IPC read response\n");
        return -1;
    }
    
    response->type = IPC_READ;
    response->pid = pid;

    error->rc = rlen < 0 ? -1 : rlen;
    error->err = rlen < 0 ? -rlen : 0;

    actual->sockfd = requested->sockfd;
    actual->len = rlen;
    memcpy(actual->buf, rbuf, rlen > 0 ? rlen : 0);

    if (write(sockfd, (char *)response, resplen) == -1) {
        perror("Error on writing IPC write response");
    }

    return 0;
}

static int ipc_write(int sockfd, struct ipc_msg *msg)
{
    struct ipc_write *payload = (struct ipc_write *) msg->data;
    pid_t pid = msg->pid;
    int rc = -1;
    int dlen = payload->len - IPC_BUFLEN;
    char buf[payload->len];
    
    memset(buf, 0, payload->len);
    memcpy(buf, payload->buf, payload->len > IPC_BUFLEN ? IPC_BUFLEN : payload->len);
    
    // Guard for payload that is longer than IPC_BUFLEN
    if (payload->len > IPC_BUFLEN) {
        int res = read(sockfd, buf + IPC_BUFLEN, payload->len - IPC_BUFLEN);
        if (res == -1) {
            perror("Read on IPC payload guard");
            return -1;
        } else if (res != dlen) {
            print_err("Hmm, we did not read exact payload amount in IPC write\n");
        }
    }
        
    rc = _write(pid, payload->sockfd, buf, payload->len);

    return ipc_write_rc(sockfd, pid, IPC_WRITE, rc);
}

static int ipc_connect(int sockfd, struct ipc_msg *msg)
{
    struct ipc_connect *payload = (struct ipc_connect *)msg->data;
    pid_t pid = msg->pid;
    int rc = -1;

    rc = _connect(pid, payload->sockfd, &payload->addr, payload->addrlen);

    return ipc_write_rc(sockfd, pid, IPC_CONNECT, rc);
}

static int ipc_socket(int sockfd, struct ipc_msg *msg)
{
    struct ipc_socket *sock = (struct ipc_socket *)msg->data;
    pid_t pid = msg->pid;
    int rc = -1;

    rc = _socket(pid, sock->domain, sock->type, sock->protocol);

    return ipc_write_rc(sockfd, pid, IPC_SOCKET, rc);
}

static int ipc_close(int sockfd, struct ipc_msg *msg)
{
    int fd = *msg->data;
    pid_t pid = msg->pid;
    int rc = -1;

    rc = _close(pid, fd);

    return ipc_write_rc(sockfd, pid, IPC_CLOSE, rc);
}

static int demux_ipc_socket_call(int sockfd, char *cmdbuf, int blen)
{
    struct ipc_msg *msg = (struct ipc_msg *)cmdbuf;

    switch (msg->type) {
    case IPC_SOCKET:
        return ipc_socket(sockfd, msg);
        break;
    case IPC_CONNECT:
        return ipc_connect(sockfd, msg);
        break;
    case IPC_WRITE:
        return ipc_write(sockfd, msg);
        break;
    case IPC_READ:
        return ipc_read(sockfd, msg);
        break;
    case IPC_CLOSE:
        return ipc_close(sockfd, msg);
        break;
    default:
        print_err("No such IPC type %d\n", msg->type);
        break;
    };
    
    return 0;
}

void *socket_ipc_open(void *args) {
    int blen = IPC_BUFLEN;
    char buf[blen];
    int sockfd = *(int *)args;
    int rc = -1;

    while ((rc = read(sockfd, buf, blen)) > 0) {
        rc = demux_ipc_socket_call(sockfd, buf, blen);

        if (rc == -1) {
            printf("Error on demuxing IPC socket call\n");
            return NULL;
        };
    }

    if (rc == -1) {
        perror("socket ipc read");
    }
    
    return NULL;
}

void *start_ipc_listener()
{
    int fd, rc, datasock;
    struct sockaddr_un un;
    char *sockname = "/tmp/lvlip.socket";

    unlink(sockname);
    
    if (strnlen(sockname, sizeof(un.sun_path)) == sizeof(un.sun_path)) {
        // Path is too long
        print_err("Path for UNIX socket is too long\n");
        exit(-1);
    }
        
    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        perror("IPC listener UNIX socket");
        exit(EXIT_FAILURE);
    }

    memset(&un, 0, sizeof(struct sockaddr_un));
    un.sun_family = AF_UNIX;
    strncpy(un.sun_path, sockname, sizeof(un.sun_path) - 1);

    rc = bind(fd, (const struct sockaddr *) &un, sizeof(struct sockaddr_un));
  
    if (rc == -1) {
        perror("IPC bind");
        exit(EXIT_FAILURE);
    }

    rc = listen(fd, 20);

    if (rc == -1) {
        perror("IPC listen");
        exit(EXIT_FAILURE);
    }

    for (;;) {
        datasock = accept(fd, NULL, NULL);
        if (datasock == -1) {
            perror("IPC accept");
            exit(EXIT_FAILURE);
        }

        if (pthread_create(&sockets[cur_th++], NULL, &socket_ipc_open, &datasock) != 0) {
            printf("Error on socket thread creation\n");
            exit(1);
        };
    }

    close(fd);

    unlink(sockname);

    return NULL;
}
