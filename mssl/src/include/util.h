#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int mystrtol(const char *nptr, int base);
int str_to_args(char *str, int *argc, char **argv, int max_argc);

#endif /* __UTIL_H__ */
