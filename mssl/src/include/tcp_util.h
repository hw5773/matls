#ifndef __TCP_UTIL_H__
#define __TCP_UTIL_H__

#include "mssl.h"
#include "tcp_stream.h"

struct tcp_timestamp
{
  uint32_t ts_val;
  uint32_t ts_ref;
};

void parse_tcp_options(tcp_stream *cur_stream, uint32_t cur_ts, uint8_t *tcpopt, int len);
extern inline int parse_tcp_timestamp(tcp_stream *cur_stream, 
    struct tcp_timestamp *ts, uint8_t *tcpopt, int len);

#if TCP_OPT_SACK_ENABLED
void parse_sack_option(tcp_stream *cur_stream, uint32_t ack_seq, uint8_t *tcpopt, int len);
#endif /* TCP_OPT_SACK_ENABLED */

uint16_t tcp_calc_checksum(uint16_t *buf, uint16_t len, uint32_t saddr, uint32_t daddr);

#endif /* __TCP_UTIL_H__ */
