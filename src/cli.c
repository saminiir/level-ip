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
    fprintf(stderr, "Usage: sudo %s [command ARGS..]\n", app);
    fprintf(stderr, "\n");
    fprintf(stderr, "Linux TCP/IP stack implemented with TUN/TAP devices.\n");
    fprintf(stderr, "Elevated privileges are needed.\n");
    fprintf(stderr, "See https://www.kernel.org/doc/Documentation/networking/tuntap.txt\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  curl HOST - act like curl, HOST as the target.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -d Debug logging and tracing\n");
    fprintf(stderr, "  -h Print usage\n");
    fprintf(stderr, "\n");
    exit(1);
}

static struct command cmds[] = {
    { 1, 0, NULL, curl, "curl" },
    { 0, 0, NULL, noop, "noop" },
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
