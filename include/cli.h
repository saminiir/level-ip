#ifndef CLI_H_
#define CLI_H_

#include "curl.h"

extern void curl(int, char**);

struct command {
    int args;
    void (*cmd_func)(int, char **);
    char *cmd_str;
};

struct command *parse_args(int argc, char** argv);

#endif
