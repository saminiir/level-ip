#include "syshead.h"

#define MAX_HOSTNAME 50

void curl(int argc, char **argv)
{
	if (argc != 3 || strnlen(argv[2], MAX_HOSTNAME) == MAX_HOSTNAME) {
		print_error("Curl called but HOST not given or invalid\n");
		exit(1);
	}

	struct sockaddr addr;

	if (get_address(argv[2], &addr) != 0) {
		print_error("Curl could not resolve hostname\n");
		exit(1);
	}

	printf("%hhu.%hhu.%hhu.%hhu\n", addr.sa_data[2], addr.sa_data[3], addr.sa_data[4], addr.sa_data[5]);
}
