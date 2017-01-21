#ifndef UTILS_H
#define UTILS_H

#define CMDBUFLEN 100

int run_cmd(char *cmd, ...);
void print_hexdump(char *str, int len);
void print_err(char *str, ...);
void print_debug(char *str, ...);
uint32_t sum_every_16bits(void *addr, int count);
uint16_t checksum(void *addr, int count, int start_sum);
int get_address(char *host, char *port, struct sockaddr *addr);
uint32_t parse_ipv4_string(char *addr);

#endif
