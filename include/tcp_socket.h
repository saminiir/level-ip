#ifndef TCP_SOCKET_H_
#define TCP_SOCKET_H_

enum tcp_states {
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK
};

struct tcb {
    uint16_t sport;
    uint16_t dport;
    uint8_t *snd_buf;
    uint8_t *rcv_buf;
    uint32_t snd_una;
    uint32_t snd_nxt;
    uint32_t snd_wnd;
    uint32_t snd_up;
    uint32_t snd_wl1;
    uint32_t snd_wl2;
    uint32_t iss;
    uint32_t rcv_nxt;
    uint32_t rcv_wnd;
    uint32_t rcv_up;
    uint32_t irs;
};

struct tcp_socket {
    enum tcp_states state;
    int fd;
    uint16_t sport;
    uint16_t dport;
    struct tcb tcb;
};

void init_tcp_sockets();
struct tcp_socket *alloc_tcp_socket();
void free_tcp_socket(struct tcp_socket *sock);
struct tcp_socket *get_tcp_socket(int sockfd);
int connect_tcp_socket(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

#endif
