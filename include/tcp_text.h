#ifndef _TCP_TEXT_H
#define _TCP_TEXT_H

#include "tcp.h"

int tcp_write_buf(struct tcp_sock *tsk, uint8_t *data, int len);
int tcp_read_buf(uint8_t *rcv_buf, void *user_buf, int len);
#endif
