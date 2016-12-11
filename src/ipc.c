#include "syshead.h"
#include "utils.h"
#include "socket.h"

#define IPC_BUFLEN 4096

static pthread_t sockets[256];
static int cur_th = 0;

void *start_ipc_listener()
{
    int fd, len, err, rc, datasock;
    struct sockaddr_un un;
    char *sockname = "/tmp/lvlip.socket";
    char buf[IPC_BUFLEN];

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

        if (pthread_create(&sockets[cur_th++], NULL, &socket_ipc_open, &datasock) != 0) {
            printf("Error on socket thread creation\n");
            exit(1);
        };
    }

    close(fd);

    unlink(sockname);

    return NULL;
}
