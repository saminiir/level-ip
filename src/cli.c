#include "syshead.h"
#include "cli.h"

static void usage(int argc, char **argv) {
    printf("Usage: sudo %s [command ARGS..]\n\n", argv[0]);
    printf("Commands:\n");
    printf("  curl HOST - act like curl, HOST as the target.\n");
    printf("\n");
    printf("Elevated privileges are needed because of tuntap devices.\n");
    printf("See https://www.kernel.org/doc/Documentation/networking/tuntap.txt\n");
    exit(1);
}

static struct command cmds[] = {
    { 0, usage, "help" },
    { 1, curl, "curl" },
    { 0, NULL, NULL }
};

struct command *parse_args(int argc, char** argv)
{
    struct command *cmd = NULL;
    if (argc == 1) return cmd;

    
    for (cmd = &cmds[0]; cmd->cmd_func; cmd++) {
        if (strncmp(argv[1], cmd->cmd_str, 6) == 0) {
             return cmd;
        }
    }

    usage(argc, argv);
    return NULL;
}
