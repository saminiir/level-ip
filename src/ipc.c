#include "syshead.h"
#include "utils.h"
#include "ipc.h"
#include "socket.h"

#define IPC_BUFLEN 4096

static pthread_t sockets[256];
static int cur_th = 0;

static int ipc_connect(int sockfd, struct ipc_msg *msg)
{
    struct ipc_connect *payload = (struct ipc_connect *)msg->data;
    pid_t pid = msg->pid;
    int rc = -1;

    rc = _connect(pid, payload->sockfd, payload->addr, payload->addrlen);

    int resplen = sizeof(struct ipc_msg) + sizeof(int);
    struct ipc_msg *response = calloc(resplen, 1);

    if (response == NULL) {
        print_err("Could not allocate memory for IPC connect response\n");
    }
    
    response->type = IPC_CONNECT;
    memcpy(response->data, &rc, sizeof(int));

    if (write(sockfd, (char *)response, resplen) == -1) {
        perror("Error on writing IPC connect ");
    }

    free(response);

    return rc;
}

static int ipc_socket(int sockfd, struct ipc_msg *msg)
{
    struct ipc_socket *sock = (struct ipc_socket *)msg->data;
    int rc = -1;

    pid_t pid = msg->pid;

    rc = _socket(pid, sock->domain, sock->type, sock->protocol);

    int resplen = sizeof(struct ipc_msg) + sizeof(int);
    struct ipc_msg *response = calloc(resplen, 1);

    if (response == NULL) {
        print_err("Could not allocate memory for IPC socket response\n");
    }
    
    response->type = IPC_SOCKET;
    memcpy(response->data, &rc, sizeof(int));

    if (write(sockfd, (char *)response, resplen) == -1) {
        perror("Error on writing IPC socket ");
    }

    free(response);

    return rc;
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
    default:
        print_err("No such IPC type %d\n", msg->type);
        break;
    };
    
    return 0;
}

void *socket_ipc_open(void *args) {
    int blen = 4096;
    char buf[blen];
    int sockfd = *(int *)args;
    int rc;

    printf("socket ipc opened\n");

    while ((rc = read(sockfd, buf, blen)) > 0) {
        rc = demux_ipc_socket_call(sockfd, buf, blen);

        if (rc == -1) {
            printf("Error on demuxing IPC socket call\n");
            return NULL;
        };
    }

    if (rc == -1) {
        perror("socket ipc read\n");
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
        print_error("IPC listener UNIX socket\n");
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
