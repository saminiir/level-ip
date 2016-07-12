#ifndef CLI_H_
#define CLI_H_

#include "curl.h"

extern void* curl(void *arg);

struct command {
    int args;
    int argc;
    char **argv;
    void* (*cmd_func)(void *arg);
    char *cmd_str;
};

struct command *parse_args(int argc, char** argv);

#endif
