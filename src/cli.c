#include "syshead.h"
#include "cli.h"

int debug = 0;
int help = 0;

void* noop(void *arg)
{
    return NULL;
}

static void usage(char *app)
{
    print_err("Usage: sudo %s [command ARGS..]\n", app);
    print_err("\n");
    print_err("Linux TCP/IP stack implemented with TUN/TAP devices.\n");
    print_err("Elevated privileges are needed.\n");
    print_err("See https://www.kernel.org/doc/Documentation/networking/tuntap.txt\n");
    print_err("\n");
    print_err("Commands:\n");
    print_err("  curl HOST - act like curl, HOST as the target.\n");
    print_err("\n");
    print_err("Options:\n");
    print_err("  -d Debug logging and tracing\n");
    print_err("  -h Print usage\n");
    print_err("\n");
    exit(1);
}

static struct command cmds[] = {
    { 1, 0, NULL, curl, "curl" },
    { 0, 0, NULL, NULL, NULL }
};

static struct command *parse_cmds(int argc, char** argv)
{
    struct command *cmd = &cmds[1];

    if (argc == 0) return cmd;

    for (cmd = &cmds[0]; cmd->cmd_func; cmd++) {
        if (strncmp(argv[0], cmd->cmd_str, 6) == 0) {
            cmd->argc = argc - 1;

            if (cmd->argc != cmd->args) break;
        
            cmd->argv = &argv[1];
            return cmd;
        }
    }

    help = 1;
    return NULL;
}

extern int optind;

static int parse_opts(int *argc, char*** argv)
{
    int opt;

    while ((opt = getopt(*argc, *argv, "hd")) != -1) {
        switch (opt) {
        case 'd':
            debug = 1;
            break;
        case 'h':
            help = 1;
            break;
        default:
            help = 1;
            break;
        }
    }

    *argc -= optind;
    *argv += optind; 

    return optind;
}

struct command* parse_cli(int argc, char **argv)
{
    char *app = argv[0];
    struct command *cmd_to_run;
    parse_opts(&argc, &argv);
    cmd_to_run = parse_cmds(argc, argv);

    if (help) usage(app);

    return cmd_to_run;
}

int is_cmd_empty(struct command *cmd)
{
    return !(cmd == NULL || cmd->cmd_func == NULL);
}
