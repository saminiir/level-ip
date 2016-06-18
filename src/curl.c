#include "syshead.h"
#include "socket.h" 
#include "utils.h"

#define MAX_HOSTNAME 50

void curl(int argc, char **argv)
{
    if (argc != 3 || strnlen(argv[2], MAX_HOSTNAME) == MAX_HOSTNAME) {
        print_error("Curl called but HOST not given or invalid\n");
        exit(1);
    }

    struct sockaddr addr;
    int sock;

    if (get_address(argv[2], &addr) != 0) {
        print_error("Curl could not resolve hostname\n");
        exit(1);
    }

    sock = _socket(AF_INET, SOCK_STREAM, 0);

    if (_connect(sock, &addr, 6) != 0) {
        print_error("Could not establish connection\n");
        exit(1);
    }
}
