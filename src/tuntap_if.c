#include "syshead.h"
#include "utils.h"
#include "basic.h"

static int tun_fd;
static char* dev;

char *tapaddr = "10.0.0.5";
char *cidr = "10.0.0.5/24";
char *taproute = "10.0.0.0/24";

/*
 * Taken from Kernel Documentation/networking/tuntap.txt
 */
static int tun_alloc(char *dev)
{
    struct ifreq ifr;
    int fd, err;

    if( (fd = open("/dev/net/tap", O_RDWR)) < 0 ) {
        perror("Cannot open TUN/TAP dev\n"
                    "Make sure one exists with " 
                    "'mknod /dev/net/tap c 10 200'");
        exit(1);
    }

    CLEAR(ifr);

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *
     *        IFF_NO_PI - Do not provide packet information
     */
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if( *dev ) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
        perror("ERR: Could not ioctl tun");
        close(fd);
        return err;
    }
    
    return fd;
}

int tun_read(char *buf, int len)
{
    return read(tun_fd, buf, len);
}

int tun_write(char *buf, int len)
{
    return write(tun_fd, buf, len);
}

void tun_init()
{
    tun_fd = tun_alloc("tap0");
}

void free_tun()
{
    free(dev);
}
