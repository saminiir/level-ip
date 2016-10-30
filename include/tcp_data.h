#ifndef _TCP_DATA_H
#define _TCP_DATA_H

#include "tcp.h"

int tcp_write_buf(struct tcp_sock *tsk, uint8_t *data, int len);
int tcp_read_buf(uint8_t *rcv_buf, void *user_buf, int len);
int tcp_data_queue(struct tcp_sock *tsk, struct tcphdr *th, struct tcp_segment *seg);
int tcp_data_close(struct tcp_sock *tsk, struct tcphdr *th, struct tcp_segment *seg);
#endif
