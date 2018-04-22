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

static inline int validate_sequence(mssl_manager_t mssl, tcp_stream *cur_stream,
    struct pkt_ctx *pctx)
{
  const struct tcphdr *tcph = pctx->p.tcph;

  if (!tcph->rst && cur_stream->saw_timestamp)
  {
    struct tcp_timestamp ts;

    if (!parse_tcp_timestamp(cur_stream, &ts,
          (uint8_t *)tcph + TCP_HEADER_LEN,
          (tcph->doff << 2) - TCP_HEADER_LEN))
    {
      return FALSE;
    }

    if (TCP_SEQ_LT(ts.ts_val, cur_stream->rcvvar->ts_recent))
    {
      cur_stream->actions |= MOS_ACT_SEND_ACK_NOW;
      return FALSE;
    }
    else
    {
      if (TCP_SEQ_GT(ts.ts_val, cur_stream->rcvvar->ts_recent))
      {
        cur_stream->rcvvar->ts_last_ts_upd = pctx->p.cur_ts;
      }

      cur_stream->rcvvar->ts_recent = ts.ts_val;
      cur_stream->rcvvar->ts_lastack_rcvd = ts.ts_ref;
    }
  }

  if (!TCP_SEQ_BETWEEN(pctx->p.seq + pctx->p.payloadlen, cur_stream->rcv_nxt,
        cur_stream->rcv_nxt + cur_stream->rcvvar->rcv_wnd))
  {
    if (tcph->rst)
      return FALSE;

    if (cur_stream->state == TCP_ST_ESTABLISHED)
    {
      if (pctx->p.seq + 1 == cur_stream->rcv_nxt)
      {
        cur_stream->actions |= MOS_ACT_SEND_ACK_AGG;
        return FALSE;
      }

      if (TCP_SEQ_LEQ(pctx->p.seq, cur_stream->rcv_nxt))
      {
        cur_stream->actions |= MOS_ACT_SEND_ACK_AGG;
      }
      else
      {
        cur_stream->actions |= MOS_ACT_SEND_ACK_NOW;
      }
    }
    else
    {
      if (cur_stream->state == TCP_ST_TIME_WAIT)
      {
        add_to_timewait_list(mssl, cur_stream, pctx->p.cur_ts);
      }
      cur_stream->actions |= MOS_ACT_SEND_CONTROL;
    }
    return FALSE;
  }
  return TRUE;
}

static inline void handle_TCP_ST_LISTEN(mssl_manager_t mssl, tcp_stream *cur_stream,
   struct pkt_ctx *pctx)
{
  const struct tcphdr *tcph = pctx->p.tcph;

  if (tcph->syn)
  {
    if (cur_stream->state == TCP_ST_LISTEN)
      cur_stream->rcv_nxt++;
    cur_stream->state = TCP_ST_SYN_RCVD;
    cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE | MOS_ON_CONN_START;
    cur_stream->actions |= MOS_ACT_SEND_CONTROL;

    // MOS_SOCK_MONITOR_STREAM_ACTIVE
  }
  else
  {
    MA_LOG("Packet without SYN");
  }
} 

static inline void handle_TCP_ST_SYN_SENT(mssl_manager_t mssl, tcp_stream *cur_stream,
    struct pkt_ctx *pctx)
{
  const struct tcphdr *tcph = pctx->p.tcph;

  if (tcph->ack)
  {
    if (TCP_SEQ_LEQ(pctx->p.ack_seq, cur_stream->sndvar->iss)
        || TCP_SEQ_GT(pctx->p.ack_seq, cur_stream->snd_nxt))
    {
      if (!tcph->rst)
      {
        cur_stream->actions |= MOS_ACT_SEND_RST;
      }
      return;
    }
    cur_stream->sndvar->snd_una++;
  }

  if (tcph->rst)
  {
    if (tcph->ack)
    {
      cur_stream->state = TCP_ST_CLOSED_RSVD;
      cur_stream->close_reason = TCP_RESET;
      cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
      if (cur_stream->socket)
      {
        raise_error_event(mssl, cur_stream);
      }
      else
      {
        cur_stream->actions |= MOS_ACT_DESTROY;
      }
    }
    return;
  }

  if (tcph->ack && tcph->syn)
  {
    int ret = handle_active_open(mssl, cur_stream, pctx);
    if (!ret)
      return;

    cur_stream->sndvar->nrtx = 0;
    remove_from_rto_list(mssl, cur_stream);
    cur_stream->state = TCP_ST_ESTABLISHED;
    cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;

    if (cur_stream->socket)
    {
      raise_write_event(mssl, cur_stream);
    }
    else
    {
      cur_stream->close_reason = TCP_ACTIVE_CLOSE;
      cur_stream->actions |= MOS_ACT_SEND_RST;
      cur_stream->actions |= MOS_ACT_DESTROY;
    }
    cur_stream->actions |= MOS_ACT_SEND_CONTROL;

    if (g_config.mos->tcp_timeout > 0)
      add_to_timeout_list(mssl, cur_stream);
  }
  else if (tcph->syn)
  {
    cur_stream->state = TCP_ST_SYN_RCVD;
    cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
    cur_stream->snd_nxt = cur_stream->sndvar->iss;
    cur_stream->actions |= MOS_ACT_SEND_CONTROL;
  }
}

static inline void handle_TCP_ST_SYN_RCVD(mssl_manager_t mssl, tcp_stream *cur_stream,
    struct pkt_ctx *pctx)
{
  const struct tcphdr *tcph = pctx->p.tcph;
  struct tcp_send_vars *sndvar = cur_stream->sndvar;
  int ret;

  if (tcph->ack)
  {

  }
}

void update_recv_tcp_context(mssl_manager_t mssl, struct tcp_stream *cur_stream,
    struct pkt_ctx *pctx)
{
  struct tcphdr *tcph = pctx->p.tcph;
  int ret;

  assert(cur_stream);

  if (cur_stream->state > TCP_ST_SYN_RCVD)
  {
    ret = validate_sequence(mssl, cur_stream, pctx);
    if (!ret)
    {
      MA_LOG("Unexpected sequence");
    }
  }

  if (tcph->syn)
  {
    cur_stream->sndvar->peer_wnd = pctx->p.window;
  }
  else
  {
    cur_stream->sndvar->peer_wnd =
      (uint32_t)pctx->p.window << cur_stream->sndvar->wscale_peer;
  }

  cur_stream->last_active_ts = pctx->p.cur_ts;

  update_timeout_list(mssl, cur_stream);

  if (tcph->rst)
  {
    cur_stream->have_reset = TRUE;
    if (cur_stream->state > TCP_ST_SYN_SENT)
    {
      if (process_rst(mssl, cur_stream, pctx))
        return;
    }
  }

/*
  if (tcph->fin)
  {
    if (cur_stream->state == TCP_ST_CLOSE_WAIT ||
        cur_stream->state == TCP_ST_LAST_ACK ||
        cur_stream->state == TCP_ST_CLOSING ||
        cur_stream->state == TCP_ST_TIME_WAIT)
    {
      if (pctx->p.seq == cur_stream->pair_stream->sndvar->
*/
  switch (cur_stream->state)
  {
    case TCP_ST_LISTEN:
      handle_TCP_ST_LISTEN(mssl, cur_stream, pctx);
      break;

    case TCP_ST_SYN_SENT:
      handle_TCP_ST_SENT(mssl, cur_stream, pctx);
      break;

    case TCP_ST_SYN_RCVD:
      if (tcph->syn && pctx->p.seq == cur_stream->rcvvar->irs)
        handle_TCP_ST_LISTEN(mssl, cur_stream, pctx);
      else
      {
        handle_TCP_ST_SYN_RCVD(mssl, cur_stream, pctx);
        if (pctx->p.payloadlen > 0 && cur_stream->state == TCP_ST_ESTABLISHED)
          handle_TCP_ST_ESTABLISHED(mssl, cur_stream, pctx);
      }
      break;

    case TCP_ST_ESTABLISHED:
      handle_TCP_ST_ESTABLISHED(mssl, cur_stream, pctx);
      break;

    case TCP_ST_CLOSE_WAIT:
      handle_TCP_ST_CLOSE_WAIT(mssl, cur_stream, pctx);
      break;

    case TCP_ST_LAST_ACK:
      handle_TCP_ST_LAST_ACK(mssl, cur_stream, pctx);
      break;

    case TCP_ST_FIN_WAIT_1:
      handle_TCP_ST_FIN_WAIT_1(mssl, cur_stream, pctx);
      break;

    case TCP_ST_FIN_WAIT_2:
      handle_TCP_ST_FIN_WAIT_2(mssl, cur_stream, pctx);
      break;

    case TCP_ST_CLOSING:
      handle_TCP_ST_CLOSING(mssl, cur_stream, pctx);
      break;

    case TCP_ST_TIME_WAIT:
      if (cur_stream->on_timewait_list)
      {
        remove_from_timewait_list(mssl, cur_stream);
        add_to_timewait_list(mssl, cur_stream, pctx->p.cur_ts);
      }
      cur_stream->actions |= MOS_ACT_SEND_CONTROL;
      break;

    case TCP_ST_CLOSED:
    case TCP_ST_CLOSED_RSVD:
      break;

    default:
      break;
  }

  return;
}

void do_action_end_tcp_packet(mssl_manager_t mssl, struct tcp_stream *cur_stream,
    struct pkt_ctx *pctx)
{
  int i;

  for (i=1; i<MOS_ACT_CNT; i = i << 1)
  {
    if (cur_stream->actions & i)
    {
      switch(i)
      {
        case MOS_ACT_SEND_DATA:
          add_to_send_list(mssl, cur_stream);
          break;
        case MOS_ACT_SEND_ACK_NOW:
          enqueue_ack(mssl, cur_stream, pctx->p.cur_ts, ACK_OPT_NOW);
          break;
        case MOS_ACT_SEND_ACK_AGG:
          enqueue_ack(mssl, cur_stream, pctx->p.cur_ts, ACK_OPT_AGGREGATE);
          break;
        case MOS_ACT_SEND_CONTROL:
          add_to_control_list(mssl, cur_stream, pctx->p.cur_ts);
          break;
        case MOS_ACT_SEND_RST:
          if (cur_stream->state <= TCP_ST_SYN_SENT)
            send_tcp_packet_standalone(mssl,
                pctx->p.iph->daddr, pctx->p.tcph->dest,
                pctx->p.iph->saddr, pctx->p.tcph->source,
                0, pctx->p.seq + 1, 0, TCP_FLAG_RST | TCP_FLAG_ACK,
                NULL, 0, pctx->p.cur_ts, 0, 0, -1);
          else
            send_tcp_packet_standalone(mssl,
                pctx->p.iph->daddr, pctx->p.tcph->dest,
                pctx->p.iph->saddr, pctx->p.tcph->source,
                pctx->p.ack_seq, 0, 0, TCP_FLAG_RST | TCP_FLAG_ACK,
                NULL, 0, pctx->p.cur_ts, 0, 0, -1);
          break;
        case MOS_ACT_DESTROY:
          destroy_tcp_stream(mssl, cur_stream);
          break;
        default:
          assert(1);
          break;
      }
    }
  }
  cur_stream->actions = 0;
}
