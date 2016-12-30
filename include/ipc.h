#ifndef IPC_H_
#define IPC_H_
void *start_ipc_listener();

#define IPC_SOCKET  0x0001
#define IPC_CONNECT 0x0002
#define IPC_WRITE   0x0003
#define IPC_READ    0x0004

struct ipc_msg {
    uint16_t type;
    pid_t pid;
    uint8_t data[];
} __attribute__((packed));

struct ipc_socket {
    int domain;
    int type;
    int protocol;
} __attribute__((packed));

struct ipc_connect {
    int sockfd;
    struct sockaddr *addr;
    socklen_t addrlen;
} __attribute__((packed));

struct ipc_write {
    int sockfd;
    size_t len;
    uint8_t buf[];
} __attribute__((packed));

struct ipc_read {
    int sockfd;
    size_t len;
    uint8_t buf[];
} __attribute__((packed));

#endif
