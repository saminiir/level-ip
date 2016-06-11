#include "syshead.h"

static int is_curl(int argc, char** argv)
{
    if (argc < 3) {
        return 0;
    }

    if (strncmp(argv[1], "curl", 4) == 0) {
        return 1;
    }

    return -1;
}

int curl_init()
{
	/* if (curl) printf("%hhu.%hhu.%hhu.%hhu\n", addr.sa_data[2], addr.sa_data[3], addr.sa_data[4], addr.sa_data[5]); */

    struct sockaddr addr;
            /* craft_curl_packet(&netdev, addr.sa_data[2], 4); */
	return 0;
}

void *curl_main(void *arg)
{
	printf("Test\n");

	return NULL;
}
