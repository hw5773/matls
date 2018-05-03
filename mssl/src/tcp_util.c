#include <assert.h>

#include "include/tcp_in.h"
#include "include/tcp_util.h"
#include "include/tcp_ring_buffer.h"
#include "include/eventpoll.h"
#include "include/logs.h"
#include "include/ip_in.h"

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(b):(a))

void parse_tcp_options(tcp_stream *cur_stream, uint32_t cur_ts, uint8_t *tcpopt, int len)
{
  int i;
  unsigned int opt, optlen;

  for (i=0; i<len; )
  {
    opt = *(tcpopt + i++);

    if (opt == TCP_OPT_END)
    {
      break;
    }
    else if (opt == TCP_OPT_NOP)
    {
      continue;
    }
    else
    {
      optlen = *(tcpopt + i++);
      if (i + optlen - 2 > len)
      {
        break;
      }

      if (opt == TCP_OPT_MSS)
      {
        cur_stream->sndvar->mss = *(tcpopt + i++) << 8;
        cur_stream->sndvar->mss += *(tcpopt + i++);
        cur_stream->sndvar->eff_mss = cur_stream->sndvar->mss;
#if TCP_OPT_TIMESTAMP_ENABLED
        cur_stream->sndvar->eff_mss -= (TCP_OPT_TIMESTAMP_LEN + 2);
#endif
      }
      else if (opt == TCP_OPT_WSCALE)
      {
        cur_stream->sndvar->wscale_peer = *(tcpopt + i++);
      }
      else if (opt == TCP_OPT_SACK_PERMIT)
      {
        cur_stream->sack_permit = TRUE;
      }
      else if (opt == TCP_OPT_TIMESTAMP)
      {
        cur_stream->saw_timestamp = TRUE;
        cur_stream->rcvvar->ts_recent = ntohl(*(uint32_t *)(tcpopt + i));
        cur_stream->rcvvar->ts_last_ts_upd = cur_ts;
        i += 8;
      }
      else
      {
        i += optlen - 2;
      }
    }
  }
}

inline int parse_tcp_timestamp(tcp_stream *cur_stream, 
    struct tcp_timestamp *ts, uint8_t *tcpopt, int len)
{
  int i;
  unsigned int opt, optlen;

  for (i=0; i<len; )
  {
    opt = *(tcpopt + i++);

    if (opt == TCP_OPT_END)
    {
      break;
    }
    else if (opt == TCP_OPT_NOP)
    {
      continue;
    }
    else
    {
      optlen = *(tcpopt + i++);
      if (i + optlen - 2 > len)
      {
        break;
      }

      if (opt == TCP_OPT_TIMESTAMP)
      {
        ts->ts_val = ntohl(*(uint32_t *)(tcpopt + i));
        ts->ts_ref = ntohl(*(uint32_t *)(tcpopt + i + 4));
        return TRUE;
      }
      else
      {
        i += optlen - 2;
      }
    }
  }
  return FALSE;
}

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
