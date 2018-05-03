#include <stdio.h>
#include <stdint.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include "pair_repo.h"

struct pseudo_tcp
{
  uint32_t saddr;
  uint32_t daddr;
  unsigned char reserved;
  unsigned char protocol;
  uint16_t len;
};

int process_packet(struct pair_entry *, struct iphdr *, int, struct tcphdr *, int, uint8_t *, int *len);
int _process_packet(struct pair_entry *, struct iphdr *, int, struct tcphdr *, int, uint8_t *, int *len);
int check_checksum(uint8_t *buf, int len);
int _ip_checksum(struct iphdr *buf, int len);
int _tcp_checksum(struct iphdr *, struct tcphdr *, int len);
int make_checksum(uint8_t *buf, int len);
int parse_entry(struct pair_entry *, uint8_t *buf, int len);
void print_ip(int addr);
