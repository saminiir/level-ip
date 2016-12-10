#include "syshead.h"
#include "utils.h"

#define BUFLEN 4096

void *start_ipc_listener()
{
    int fd, len, err, rc, datasock;
    struct sockaddr_un un;
    char *sockname = "/tmp/lvlip.socket";
    char buf[BUFLEN];

    unlink(sockname);
    
    if (strnlen(sockname, sizeof(un.sun_path)) == sizeof(un.sun_path)) {
        // Path is too long
        print_err("Path for UNIX socket is too long\n");
        exit(-1);
    }
        
    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        print_error("IPC listener UNIX socket\n");
        exit(EXIT_FAILURE);
    }

    memset(&un, 0, sizeof(struct sockaddr_un));
    un.sun_family = AF_UNIX;
    strncpy(un.sun_path, sockname, sizeof(un.sun_path) - 1);

    rc = bind(fd, (const struct sockaddr *) &un, sizeof(struct sockaddr_un));
  
    if (rc == -1) {
        perror("IPC bind");
        exit(EXIT_FAILURE);
    }

    rc = listen(fd, 20);

    if (rc == -1) {
        perror("IPC listen");
        exit(EXIT_FAILURE);
    }

    for (;;) {
        datasock = accept(fd, NULL, NULL);
        if (datasock == -1) {
            perror("IPC accept");
            exit(EXIT_FAILURE);
        }

        for (;;) {
            rc = read(datasock, buf, BUFLEN);
            if (rc == -1) {
                perror("IPC read");
                exit(EXIT_FAILURE);
            }

            buf[BUFLEN - 1] = 0;

            printf("%s\n", buf);
            break;
        }

        close(datasock);
    }

    close(fd);

    unlink(sockname);

    return NULL;
}
