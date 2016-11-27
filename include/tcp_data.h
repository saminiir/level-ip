#ifndef _TCP_DATA_H
#define _TCP_DATA_H

#include "tcp.h"

int tcp_data_dequeue(struct tcp_sock *tsk, void *user_buf, int len);
int tcp_data_queue(struct tcp_sock *tsk, struct sk_buff *skb, struct tcphdr *th,
                   struct tcp_segment *seg);
int tcp_data_close(struct tcp_sock *tsk, struct sk_buff *skb, struct tcphdr *th,
                   struct tcp_segment *seg);
#endif
