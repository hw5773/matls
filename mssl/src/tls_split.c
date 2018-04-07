#include "include/tcp_stream.h"
#include "include/tls_split.h"

void do_split_session(struct tcp_stream *sendside_stream,
    struct tcp_stream *recvside_stream, struct pkt_ctx *pctx)
{
  MA_LOG("do split session");

  send_tcp_packet_standalone(mssl, sendside_stream->daddr, sendside_stream->dport,
      sendside_stream->saddr, sendside_stream->sport, 
      pctx->p.ack_seq, 
}

