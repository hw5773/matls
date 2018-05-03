#include <stdio.h>
#include <stdint.h>
#include <linux/ip.h>

int _process_ip(uint8_t *buf, int len);
void print_ip(int ip);
