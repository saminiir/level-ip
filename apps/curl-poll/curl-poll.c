#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <assert.h>

#define MAX_HOSTNAME 50
#define RLEN 4096

int get_address(char *host, char *port, struct sockaddr *addr)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    s = getaddrinfo(host, port, &hints, &result);

    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        *addr = *rp->ai_addr;
        freeaddrinfo(result);
        return 0;
    }
    
    return 1;
}

int main(int argc, char **argv)
{
    if (argc != 3 || strnlen(argv[1], MAX_HOSTNAME) == MAX_HOSTNAME) {
        fprintf(stderr, "Curl called but HOST or PORT not given or invalid\n");
        return 1;
    }

    struct sockaddr addr;
    int sock;

    if (strnlen(argv[2], 6) == 6) {
        fprintf(stderr, "Curl called but PORT malformed\n");
        return 1;
    }

    if (get_address(argv[1], argv[2], &addr) != 0) {
        fprintf(stderr, "Curl could not resolve hostname\n");
        return 1;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
        perror("Setting socket nonblocking");
        return 1;
    }

    if (connect(sock, &addr, 16) == -1) {
        if (errno != EINPROGRESS) {
            perror("Curl could not establish connection");
            return 1;
        }
    }

    struct pollfd fds[1];
    fds[0].fd = sock;
    fds[0].events = POLLOUT;

    int ret = poll(fds, 1, -1);

    if (ret < 1) {
        perror("Poll failed");
        return 1;
    }

    assert(fds[0].revents & POLLOUT);

    char str[512];

    snprintf(str, 512, "GET / HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n", argv[1], argv[2]);
    int len = strlen(str);

    if (write(sock, str, len) != len) {
        perror("Write error");
        return 1;
    }

    int rlen = 0;
    while (1) {
        fds[0].events = POLLIN;

        ret = poll(fds, 1, -1);

        if (ret < 0) {
            perror("Poll failed");
            return 1;
        }

        if (fds[0].revents & POLLIN) {
            char buf[RLEN] = { 0 };

            if ((rlen = read(sock, buf, RLEN)) == -1) {
                perror("Read error");
                return 1;
            }

            if (rlen == 0) {
                /* We're done */
                break;
            }

            printf("%s", buf);
        }

        if (fds[0].revents & (POLLHUP | POLLERR)) {
            fprintf(stderr, "POLLHUP/ERR received %d\n", fds[0].revents);
            break;
        }
    }

    close(sock);
}
