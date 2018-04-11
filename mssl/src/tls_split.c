#include "include/tcp_stream.h"
#include "include/tls_split.h"

void do_split_session(mssl_manager_t mssl, struct tcp_stream *sendside_stream,
    struct tcp_stream *recvside_stream, struct pkt_ctx *pctx)
{
  MA_LOG("do split session");

  send_tcp_packet(mssl, sendside_stream, pctx->p.cur_ts, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0);
  MA_LOG ("send ACK to sender");

  send_tcp_packet_standalone(mssl, recvside_stream->saddr, recvside_stream->sport,
      recvside_stream->daddr, recvside_stream->dport, 0x12345678, 0,
      0, TCP_FLAG_SYN, NULL, 0, pctx->p.cur_ts, 0, 0, -1);
  MA_LOG("send SYN to receiver");
}

