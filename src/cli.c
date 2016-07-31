#include "syshead.h"
#include "cli.h"

extern int running;

void* noop(void *arg)
{
    return NULL;
}

void* usage(void *arg)
{
    struct command *cmd = arg;
    
    printf("Usage: sudo %s [command ARGS..]\n\n", cmd->argv[0]);
    printf("Commands:\n");
    printf("  curl HOST - act like curl, HOST as the target.\n");
    printf("\n");
    printf("Elevated privileges are needed because of tuntap devices.\n");
    printf("See https://www.kernel.org/doc/Documentation/networking/tuntap.txt\n");

    running = 0;
    return NULL;
}

static struct command cmds[] = {
    { 0, 0, NULL, usage, "help" },
    { 1, 0, NULL, curl, "curl" },
    { 0, 0, NULL, noop, "noop" },
    { 0, 0, NULL, NULL, NULL }
};

struct command *parse_args(int argc, char** argv)
{
    struct command *cmd = &cmds[2];
    if (argc == 1) return cmd;

    // Default to usage
    struct command *usage = &cmds[0];
    usage->argc = argc;
    usage->argv = argv;

    for (cmd = &cmds[0]; cmd->cmd_func; cmd++) {
        if (strncmp(argv[1], cmd->cmd_str, 6) == 0) {
            cmd->argc = argc - 2;

            if (cmd->argc != cmd->args) break;
        
            cmd->argv = &argv[2];
            return cmd;
        }
    }

    return usage;
}
