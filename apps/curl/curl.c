#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>

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
        printf("getaddrinfo: %s\n", gai_strerror(s));
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
        printf("Curl called but HOST or PORT not given or invalid\n");
        return 1;
    }

    struct sockaddr addr;
    int sock;

    if (strnlen(argv[2], 6) == 6) {
        printf("Curl called but PORT malformed\n");
        return 1;
    }

    if (get_address(argv[1], argv[2], &addr) != 0) {
        printf("Curl could not resolve hostname\n");
        return 1;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (connect(sock, &addr, 16) == -1) {
        perror("Curl could not establish connection");
        return 1;
    }

    char str[512];

    snprintf(str, 512, "GET / HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n", argv[1], argv[2]);
    int len = strlen(str);

    if (write(sock, str, len) != len) {
        printf("Write error\n");
        return 1;
    }

    char buf[RLEN] = { 0 };
    int rlen = 0;

    while ((rlen = read(sock, buf, RLEN)) > 0) {
        printf("%s", buf);
    }

    if (rlen == -1) {
        perror("Curl read error");
        return 1;
    }

    close(sock);
}
