#include <assert.h>

#include "include/tcp_util.h"
#include "include/tcp_ring_buffer.h"
//#include "include/eventpoll.h"
#include "include/logs.h"
#include "include/ip_in.h"

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(b):(a))

// void parse_tcp_options
// inline int parse_tcp_timestamp
// void parse_sack_option

uint16_t tcp_calc_checksum(uint16_t *buf, uint16_t len, uint32_t saddr, uint32_t daddr)
{
  uint32_t sum;
  uint16_t *w;
  int nleft;

  sum = 0;
  nleft = len;
  w = buf;

  while (nleft > 1)
  {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft)
    sum += *w & ntohs(0xFF00);

  sum += (saddr & 0x0000FFFF) + (saddr >> 16);
  sum += (daddr & 0x0000FFFF) + (daddr >> 16);
  sum += htons(len);
  sum += htons(IPPROTO_TCP);

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);

  sum = ~sum;

  return (uint16_t)sum;
}
