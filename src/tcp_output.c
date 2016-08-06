#include "syshead.h"
#include "utils.h"
#include "tcp.h"

static int tcp_send_syn(struct tcp_socket *sock)
{
    if (sock->state != CLOSED && sock->state != LISTEN) {
        print_error("Socket was not in correct state (closed or listen)");
        return 1;
    }

    struct tcphdr thdr;

    thdr.sport = sock->sport;
    thdr.dport = sock->dport;
    thdr.seq = sock->tcb.iss;
    thdr.ack = 0;
    thdr.rsvd = 0;
    thdr.hl = 6;
    thdr.flags = TCP_SYN;
    thdr.win = sock->tcb.rcv_wnd;
    thdr.urp = 0;

    sock->state = SYN_SENT;

    tcp_out(sock, &thdr);

    return 0;
}

int tcp_connect(struct tcp_socket *sk)
{
    return tcp_send_syn(sk);
}
