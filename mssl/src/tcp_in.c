#include <assert.h>

#include "include/mos_api.h"
#include "include/tcp_util.h"
#include "include/tcp_in.h"
#include "include/tcp_out.h"
#include "include/tcp_ring_buffer.h"
//#include "include/eventpoll.h"
#include "include/logs.h"
//#include "include/timer.h"
#include "include/ip_in.h"
#include "include/tcp_rb.h"
#include "include/config.h"
#include "include/scalable_event.h"
#include "include/tls_split.h"

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

#define RECOVERY_AFTER_LOSS TRUE
#define SELECTIVE_WRITE_EVENT_NOTIFY TRUE

/*
void do_split_session(struct tcp_stream *sendside_stream,
    struct tcp_stream *recvside_stream, struct pkt_ctx *pctx)
{
  MA_LOG("do split session");

  MA_LOGip("sendside source ip", sendside_stream->saddr);
  MA_LOG1d("sendside source port", sendside_stream->sport);
  MA_LOGip("sendside dest ip", sendside_stream->daddr);
  MA_LOG1d("sendside dest port", sendside_stream->dport);

  MA_LOGip("recvside source ip", recvside_stream->saddr);
  MA_LOG1d("recvside source port", recvside_stream->sport);
  MA_LOGip("recvside dest ip", recvside_stream->daddr);
  MA_LOG1d("recvside dest port", recvside_stream->dport);
}
*/
