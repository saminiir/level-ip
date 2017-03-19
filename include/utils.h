#ifndef UTILS_H
#define UTILS_H

#define CMDBUFLEN 100

#define print_debug(str, ...)                       \
    printf(str" - %s:%u\n", ##__VA_ARGS__, __FILE__, __LINE__);

int run_cmd(char *cmd, ...);
void print_hexdump(char *str, int len);
void print_err(char *str, ...);
uint32_t sum_every_16bits(void *addr, int count);
uint16_t checksum(void *addr, int count, int start_sum);
int get_address(char *host, char *port, struct sockaddr *addr);
uint32_t parse_ipv4_string(char *addr);

#endif
