#include "syshead.h"
#include "socket.h" 
#include "utils.h"
#include "cli.h"

#define MAX_HOSTNAME 50

extern int running;

void* curl(void *arg)
{
    struct command *cmd = arg;
    int argc = cmd->argc;
    char **argv = cmd->argv;
    
    if (argc != 2 || strnlen(argv[0], MAX_HOSTNAME) == MAX_HOSTNAME) {
        print_error("Curl called but HOST or PORT not given or invalid\n");
        return NULL;
    }

    struct sockaddr addr;
    int sock;

    if (strnlen(argv[1], 6) == 6) {
        print_error("Curl called but PORT malformed\n");
        return NULL;
    }

    if (get_address(argv[0], argv[1], &addr) != 0) {
        print_error("Curl could not resolve hostname\n");
        return NULL;
    }

    sock = _socket(AF_INET, SOCK_STREAM, 0);

    if (_connect(sock, &addr, 6) != 0) {
        print_error("Could not establish connection\n");
        return NULL;
    }

    char str[512];

    snprintf(str, 512, "GET / HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n", argv[0], argv[1]);
    int len = strlen(str);

    if (_write(sock, str, len) != len) {
        print_error("Write error\n");
        return NULL;
    }

    char buf[4096] = { 0 };
    int rlen = 0;

    while ((rlen = _read(sock, buf, 4096)) > 0) {
        printf("%s", buf);
    }

    if (rlen == -1) {
        print_error("Read error\n");
    }

    return NULL;
}
