#ifndef SOCKET_H_
#define SOCKET_H_

int _socket(int domain, int type, int protocol);
int _connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

#endif
