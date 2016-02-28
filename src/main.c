#include "syshead.h"
#include "basic.h"
#include "tuntap_if.h"
#include "utils.h"

#define BUFLEN 100

int main(int argc, char** argv) {
    int tun_fd;
    char buf[BUFLEN];
    char *dev = calloc(10, 1);
    CLEAR(buf);
    tun_fd = tun_alloc(dev);

    if (set_if_up(dev) != 0) {
        print_error("ERROR when setting up if\n");
    }

    if (set_if_route(dev, "10.0.0.0/24") != 0) {
        print_error("ERROR when setting route for if\n");
    }

    while (1) {
        read(tun_fd, buf, BUFLEN);

        print_hexdump(buf, BUFLEN);
    }

    free(dev);
}
