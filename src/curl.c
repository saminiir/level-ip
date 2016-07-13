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
    
    if (argc != 3 || strnlen(argv[2], MAX_HOSTNAME) == MAX_HOSTNAME) {
        print_error("Curl called but HOST not given or invalid\n");
        return NULL;
    }

    struct sockaddr addr;
    int sock;

    if (get_address(argv[2], &addr) != 0) {
        print_error("Curl could not resolve hostname\n");
        return NULL;
    }

    sock = _socket(AF_INET, SOCK_STREAM, 0);

    if (_connect(sock, &addr, 6) != 0) {
        print_error("Could not establish connection\n");
        return NULL;
    }

    running = 0;
    return NULL;
}
