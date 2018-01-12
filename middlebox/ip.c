/**
 * @file ip.c
 * @author Hyunwoo Lee
 * @date 12 Jan 2018
 * @brief This file is to describe the functions for the IP header processor
 */

#include "ip.h"

int process_ip(uint8_t *buf, int len)
{
  return _process_ip(buf, len);
}

int _process_ip(uint8_t *buf, int len)
{
  struct iphdr *iph = (struct iphdr *)buf;
  printf("[MB] %s: Source IP: ", __func__);
  print_ip(iph->saddr);
  printf("[MB] %s: Dest IP: ", __func__);
  print_ip(iph->daddr);
  return 1;
}

void print_ip(int ip)
{
  unsigned char ipb[4];
  ipb[0] = ip & 0xFF;
  ipb[1] = (ip >> 8) & 0xFF;
  ipb[2] = (ip >> 16) & 0xFF;
  ipb[3] = (ip >> 24) & 0xFF;
  printf("%d.%d.%d.%d\n", ipb[0], ipb[1], ipb[2], ipb[3]);
}
