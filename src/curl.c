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

	sock = socket(AF_INET, SOCK_STREAM, 0);

	printf("%d\n", sock);

	printf("%hhu.%hhu.%hhu.%hhu\n", addr.sa_data[2], addr.sa_data[3], addr.sa_data[4], addr.sa_data[5]);
}
