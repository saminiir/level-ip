#include "syshead.h"
#include "utils.h"
#include "ipc.h"
#include "socket.h"

#define IPC_BUFLEN 8192

static LIST_HEAD(sockets);
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int socket_count = 0;

static struct ipc_thread *ipc_alloc_thread(int sock)
{
    struct ipc_thread *th = calloc(sizeof(struct ipc_thread), 1);
    list_init(&th->list);
    th->sock = sock;

    pthread_mutex_lock(&lock);
    list_add_tail(&th->list, &sockets);
    socket_count++;
    pthread_mutex_unlock(&lock);

    ipc_dbg("New IPC socket allocated", th);

    return th;
}

static void ipc_free_thread(int sock)
{
    struct list_head *item, *tmp = NULL;
    struct ipc_thread *th = NULL;

    pthread_mutex_lock(&lock);

    list_for_each_safe(item, tmp, &sockets) {
        th = list_entry(item, struct ipc_thread, list);

        if (th->sock == sock) {
            list_del(&th->list);
            ipc_dbg("IPC socket deleted", th);

            close(th->sock);
            free(th);
            socket_count--;
            break;
        }

    }

    pthread_mutex_unlock(&lock);
}

static int ipc_try_send(int sockfd, const void *buf, size_t len)
{
    return send(sockfd, buf, len, MSG_NOSIGNAL);
}

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

    if (ipc_try_send(sockfd, (char *)response, resplen) == -1) {
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

    int resplen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) +
        sizeof(struct ipc_read) + (rlen > 0 ? rlen : 0);
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

    if (ipc_try_send(sockfd, (char *)response, resplen) == -1) {
        perror("Error on writing IPC read response");
    }

    return 0;
}

static int ipc_write(int sockfd, struct ipc_msg *msg)
{
    struct ipc_write *payload = (struct ipc_write *) msg->data;
    pid_t pid = msg->pid;
    int rc = -1;
    int head = IPC_BUFLEN - sizeof(struct ipc_write) - sizeof(struct ipc_msg);

    char buf[payload->len];

    memset(buf, 0, payload->len);
    memcpy(buf, payload->buf, payload->len > head ? head : payload->len);

    // Guard for payload that is longer than initial IPC_BUFLEN
    if (payload->len > head) {
        int tail = payload->len - head;
        int res = read(sockfd, &buf[head], tail);

        if (res == -1) {
            perror("Read on IPC payload guard");
            return -1;
        } else if (res != tail) {
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

    struct sockaddr addr;

    addr.sa_family = payload->addr.sa_family;
    memcpy(addr.sa_data, payload->addr.sa_data, sizeof(addr.sa_data));

    rc = _connect(pid, payload->sockfd, &addr, payload->addrlen);

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
    struct ipc_close *payload = (struct ipc_close *)msg->data;
    pid_t pid = msg->pid;
    int rc = -1;

    rc = _close(pid, payload->sockfd);

    rc = ipc_write_rc(sockfd, pid, IPC_CLOSE, rc);

    return rc;
}

static int ipc_poll(int sockfd, struct ipc_msg *msg)
{
    struct ipc_poll *data = (struct ipc_poll *)msg->data;
    pid_t pid = msg->pid;
    int rc = -1;

    struct pollfd fds[data->nfds];

    for (int i = 0; i < data->nfds; i++) {
        fds[i].fd = data->fds[i].fd;
        fds[i].events = data->fds[i].events;
        fds[i].revents = data->fds[i].revents;
    }

    rc = _poll(pid, fds, data->nfds, data->timeout);

    int resplen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_pollfd) * data->nfds;
    struct ipc_msg *response = alloca(resplen);

    if (response == NULL) {
        print_err("Could not allocate memory for IPC write response\n");
        return -1;
    }

    response->type = IPC_POLL;
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

    struct ipc_pollfd *polled = (struct ipc_pollfd *) ((struct ipc_err *)response->data)->data;

    for (int i = 0; i < data->nfds; i++) {
        polled[i].fd = fds[i].fd;
        polled[i].events = fds[i].events;
        polled[i].revents = fds[i].revents;
    }

    if (ipc_try_send(sockfd, (char *)response, resplen) == -1) {
        perror("Error on writing IPC poll response");
    }

    return 0;
}

static int ipc_fcntl(int sockfd, struct ipc_msg *msg)
{
    struct ipc_fcntl *fc = (struct ipc_fcntl *)msg->data;
    pid_t pid = msg->pid;
    int rc = -1;

    switch (fc->cmd) {
        case F_GETFL:
            rc = _fcntl(pid, fc->sockfd, fc->cmd);
            break;
        case F_SETFL:
            rc = _fcntl(pid, fc->sockfd, fc->cmd, *(int *)fc->data);
            break;
        default:
            print_err("IPC Fcntl cmd not supported %d\n", fc->cmd);
            rc = -EINVAL;
    }

    return ipc_write_rc(sockfd, pid, IPC_FCNTL, rc);
}

static int ipc_getsockopt(int sockfd, struct ipc_msg *msg)
{
    struct ipc_sockopt *opts = (struct ipc_sockopt *)msg->data;

    pid_t pid = msg->pid;
    int rc = -1;

    socklen_t optlen;

    rc = _getsockopt(pid, opts->fd, opts->level, opts->optname, opts->optval, &optlen);

    int resplen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_sockopt) + optlen;
    struct ipc_msg *response = alloca(resplen);

    if (response == NULL) {
        print_err("Could not allocate memory for IPC getsockopt response\n");
        return -1;
    }

    response->type = IPC_GETSOCKOPT;
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

    struct ipc_sockopt *optres = (struct ipc_sockopt *) ((struct ipc_err *)response->data)->data;

    optres->fd = opts->fd;
    optres->level = opts->level;
    optres->optname = opts->optname;
    optres->optlen = optlen;
    memcpy(&optres->optval, opts->optval, optlen);

    if (ipc_try_send(sockfd, (char *)response, resplen) == -1) {
        perror("Error on writing IPC getsockopt response");
    }

    return rc;
}

static int ipc_getpeername(int sockfd, struct ipc_msg *msg)
{
    struct ipc_sockname *name = (struct ipc_sockname *)msg->data;

    pid_t pid = msg->pid;
    int rc = -1;

    int resplen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_sockname);
    struct ipc_msg *response = alloca(resplen);

    if (response == NULL) {
        print_err("Could not allocate memory for IPC getpeername response\n");
        return -1;
    }

    response->type = IPC_GETPEERNAME;
    response->pid = pid;

    struct ipc_sockname *nameres = (struct ipc_sockname *) ((struct ipc_err *)response->data)->data;
    rc = _getpeername(pid, name->socket, (struct sockaddr *)nameres->sa_data, &nameres->address_len);

    struct ipc_err err;

    if (rc < 0) {
        err.err = -rc;
        err.rc = -1;
    } else {
        err.err = 0;
        err.rc = rc;
    }

    memcpy(response->data, &err, sizeof(struct ipc_err));

    nameres->socket = name->socket;

    if (ipc_try_send(sockfd, (char *)response, resplen) == -1) {
        perror("Error on writing IPC getpeername response");
    }

    return rc;
}

static int ipc_getsockname(int sockfd, struct ipc_msg *msg)
{
    struct ipc_sockname *name = (struct ipc_sockname *)msg->data;

    pid_t pid = msg->pid;
    int rc = -1;

    int resplen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_sockname);
    struct ipc_msg *response = alloca(resplen);

    if (response == NULL) {
        print_err("Could not allocate memory for IPC getsockname response\n");
        return -1;
    }

    response->type = IPC_GETSOCKNAME;
    response->pid = pid;

    struct ipc_sockname *nameres = (struct ipc_sockname *) ((struct ipc_err *)response->data)->data;
    rc = _getsockname(pid, name->socket, (struct sockaddr *)nameres->sa_data, &nameres->address_len);

    struct ipc_err err;

    if (rc < 0) {
        err.err = -rc;
        err.rc = -1;
    } else {
        err.err = 0;
        err.rc = rc;
    }

    memcpy(response->data, &err, sizeof(struct ipc_err));

    nameres->socket = name->socket;

    if (ipc_try_send(sockfd, (char *)response, resplen) == -1) {
        perror("Error on writing IPC getsockname response");
    }

    return rc;
}

int deserialize_msghdr(struct ipc_msghdr *ipc, struct msghdr *message, struct iovec *iov)
{
    uint8_t *ptr = ipc->data;
    message->msg_name = ptr;
    message->msg_namelen = ipc->msg_namelen;
    ptr += message->msg_namelen;

    message->msg_control = ptr;
    message->msg_controllen = ipc->msg_controllen;
    ptr += message->msg_controllen;

    message->msg_iovlen = ipc->msg_iovlen;

    for (int i = 0; i < message->msg_iovlen; i++) {
        struct ipc_iovec *v = (struct ipc_iovec *) ptr;
        iov[i].iov_len = v->iov_len;
        iov[i].iov_base = v->iov_base;
        ptr = v->iov_base;
        ptr += iov[i].iov_len;
    }

    message->msg_iov = iov;

    return 0;
}

int serialize_msghdr(struct ipc_msghdr *imh, struct msghdr *hdr)
{
    imh->msg_namelen = hdr->msg_namelen;
    imh->msg_iovlen = hdr->msg_iovlen;
    imh->msg_controllen = hdr->msg_controllen;
    imh->flags = hdr->msg_flags;

    uint8_t *ptr = imh->data;
    for (int i = 0; i < hdr->msg_iovlen; i++) {
        struct ipc_iovec *v = (struct ipc_iovec *)ptr;
        struct iovec *iov = &hdr->msg_iov[i];

        v->iov_len = iov->iov_len;
        memcpy(v->iov_base, iov->iov_base, iov->iov_len);

        ptr += sizeof(struct ipc_iovec);
        ptr += v->iov_len;
    }

    return 0;
}

static int ipc_sendmsg(int sockfd, struct ipc_msg *msg)
{
    struct ipc_msghdr *payload = (struct ipc_msghdr *) msg->data;
    pid_t pid = msg->pid;
    int rc = -1;

    struct msghdr message;
    struct iovec iov[payload->msg_iovlen];

    deserialize_msghdr(payload, &message, iov);

    rc = _sendmsg(pid, payload->sockfd, &message, payload->flags);

    return ipc_write_rc(sockfd, pid, IPC_SENDMSG, rc);
}

static int ipc_recvmsg(int sockfd, struct ipc_msg *msg)
{
    struct ipc_msghdr *payload = (struct ipc_msghdr *) msg->data;
    pid_t pid = msg->pid;
    int rc = -1;

    struct msghdr message;
    struct iovec iov[payload->msg_iovlen];

    deserialize_msghdr(payload, &message, iov);

    rc = _recvmsg(pid, payload->sockfd, &message, payload->flags);

    int iovlen = 0;

    for (int i = 0; i < payload->msg_iovlen; i++) {
        iovlen += iov[i].iov_len;
        iovlen += sizeof(struct ipc_iovec);
    }

    int resplen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) +
        sizeof(struct ipc_msghdr) + iovlen;
    struct ipc_msg *response = alloca(resplen);
    struct ipc_err *error = (struct ipc_err *) response->data;
    struct ipc_msghdr *actual = (struct ipc_msghdr *) error->data;

    serialize_msghdr(actual, &message);
    actual->sockfd = sockfd;

    response->type = IPC_RECVMSG;
    response->pid = pid;

    error->rc = rc < 0 ? -1 : rc;
    error->err = rc < 0 ? -rc : 0;

    if (ipc_try_send(sockfd, (char *)response, resplen) == -1) {
        perror("Error on writing IPC recvmsg response");
     }

    return rc;
}

static int demux_ipc_socket_call(int sockfd, char *cmdbuf, int blen)
{
    struct ipc_msg *msg = (struct ipc_msg *)cmdbuf;

    switch (msg->type) {
        case IPC_SOCKET:
            return ipc_socket(sockfd, msg);
        case IPC_CONNECT:
            return ipc_connect(sockfd, msg);
        case IPC_WRITE:
            return ipc_write(sockfd, msg);
        case IPC_READ:
            return ipc_read(sockfd, msg);
        case IPC_CLOSE:
            return ipc_close(sockfd, msg);
        case IPC_POLL:
            return ipc_poll(sockfd, msg);
        case IPC_FCNTL:
            return ipc_fcntl(sockfd, msg);
        case IPC_GETSOCKOPT:
            return ipc_getsockopt(sockfd, msg);
        case IPC_GETPEERNAME:
            return ipc_getpeername(sockfd, msg);
        case IPC_GETSOCKNAME:
            return ipc_getsockname(sockfd, msg);
        case IPC_SENDMSG:
            return ipc_sendmsg(sockfd, msg);
        case IPC_RECVMSG:
            return ipc_recvmsg(sockfd, msg);
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
            print_err("Error on demuxing IPC socket call\n");
            close(sockfd);
            return NULL;
        };
    }

    ipc_free_thread(sockfd);

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
        exit_with_error(fd, "Unable to create IPC UNIX socket");
    }

    memset(&un, 0, sizeof(struct sockaddr_un));
    un.sun_family = AF_UNIX;
    strncpy(un.sun_path, sockname, sizeof(un.sun_path) - 1);

    if ((rc = bind(fd, (const struct sockaddr *) &un, sizeof(struct sockaddr_un))) == -1) {
        print_err("Check socket file permissions: %s\n", sockname);
        exit_with_error(rc, "Unable to bind to IPC socket");
    }

    if ((rc = listen(fd, 20)) == -1) {
        exit_with_error(rc, "Unable to listen on IPC socket");
    }

    if ((rc = chmod(sockname, S_IRUSR | S_IWUSR | S_IXUSR |
                    S_IRGRP | S_IWGRP | S_IXGRP |
                    S_IROTH | S_IWOTH | S_IXOTH)) == -1) {
        exit_with_error(rc, "Chmod on lvl-ip IPC UNIX socket failed");
    }

    for (;;) {
        if ((datasock = accept(fd, NULL, NULL)) == -1) {
            exit_with_error(datasock ,"IPC accept");
        }

        struct ipc_thread *th = ipc_alloc_thread(datasock);

        if ((rc = pthread_create(&th->id, NULL, &socket_ipc_open, &th->sock)) != 0) {
            exit_with_error(rc, "Error on socket thread creation");
        };
    }

    close(fd);

    unlink(sockname);

    return NULL;
}
