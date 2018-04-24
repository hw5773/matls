#include <assert.h>

#include "include/mos_api.h"
#include "include/tcp_util.h"
#include "include/tcp_in.h"
#include "include/tcp_out.h"
#include "include/tcp_send_buffer.h"
#include "include/tcp_ring_buffer.h"
#include "include/eventpoll.h"
#include "include/logs.h"
#include "include/timer.h"
#include "include/ip_in.h"
#include "include/tcp_rb.h"
#include "include/config.h"
#include "include/scalable_event.h"
#include "include/tls_split.h"

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

#define RECOVERY_AFTER_LOSS TRUE
#define SELECTIVE_WRITE_EVENT_NOTIFY TRUE

static inline void handle_TCP_ST_ESTABLISHED(mssl_manager_t mssl, tcp_stream *cur_stream,
    struct pkt_ctx *pctx);

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

static inline int filter_syn_packet(mssl_manager_t mssl, uint32_t ip, uint16_t port)
{
  struct sockaddr_in *addr;

  if (!mssl->listener)
  {
    return FALSE;
  }

  addr = &mssl->listener->socket->saddr;

  if (addr->sin_port == port)
  {
    if (addr->sin_addr.s_addr != INADDR_ANY)
    {
      if (ip == addr->sin_addr.s_addr)
      {
        return TRUE;
      }
      return FALSE;
    }
    else
    {
      int i;

      for (i=0; i<g_config.mos->netdev_table->num; i++)
      {
        if (ip == g_config.mos->netdev_table->ent[i]->ip_addr)
        {
          return TRUE;
        }
      }
      return FALSE;
    }
  }
  return FALSE;
}

static inline int handle_active_open(mssl_manager_t mssl, tcp_stream *cur_stream,
    struct pkt_ctx *pctx)
{
  MA_LOG("handle_active_open");
  const struct tcphdr *tcph = pctx->p.tcph;

  cur_stream->rcvvar->irs = pctx->p.seq;
  cur_stream->snd_nxt = pctx->p.ack_seq;
  cur_stream->sndvar->peer_wnd = pctx->p.window;
  cur_stream->rcvvar->snd_wl1 = cur_stream->rcvvar->irs - 1;
  cur_stream->rcv_nxt = cur_stream->rcvvar->irs + 1;
  cur_stream->rcvvar->last_ack_seq = pctx->p.ack_seq;
  parse_tcp_options(cur_stream, pctx->p.cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN,
      (tcph->doff << 2) - TCP_HEADER_LEN);
  cur_stream->sndvar->cwnd = ((cur_stream->sndvar->cwnd == 1)?
      (cur_stream->sndvar->mss * 2) : cur_stream->sndvar->mss);
  cur_stream->sndvar->ssthresh = cur_stream->sndvar->mss * 10;
  update_retransmission_timer(mssl, cur_stream, pctx->p.cur_ts);

  ///// Add for matls /////
  cur_stream->socket = allocate_socket(mssl->ctx, MOS_SOCK_SPLIT_TLS);
  cur_stream->socket->stream = cur_stream;
  /////////////////////////

  return TRUE;
}

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

static inline int process_rst(mssl_manager_t mssl, tcp_stream *cur_stream,
    struct pkt_ctx *pctx)
{
  if (cur_stream->state <= TCP_ST_SYN_SENT)
    return FALSE;

  if (cur_stream->state == TCP_ST_SYN_RCVD)
  {
    if (pctx->p.seq == 0 || pctx->p.ack_seq == cur_stream->snd_nxt)
    {
      MA_LOG("here?");
      cur_stream->state = TCP_ST_CLOSED_RSVD;
      cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
      cur_stream->close_reason = TCP_RESET;
      cur_stream->actions |= MOS_ACT_DESTROY;
    }
    else
    {
    }
    return TRUE;
  }

  if (cur_stream->state == TCP_ST_FIN_WAIT_1 ||
      cur_stream->state == TCP_ST_FIN_WAIT_2 ||
      cur_stream->state == TCP_ST_LAST_ACK ||
      cur_stream->state == TCP_ST_CLOSING ||
      cur_stream->state == TCP_ST_TIME_WAIT)
  {
      MA_LOG("here?");
    cur_stream->state = TCP_ST_CLOSED_RSVD;
    cur_stream->close_reason = TCP_ACTIVE_CLOSE;
    cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
    cur_stream->actions |= MOS_ACT_DESTROY;
    return TRUE;
  }

  if (cur_stream->state >= TCP_ST_ESTABLISHED &&
      cur_stream->state <= TCP_ST_CLOSE_WAIT)
  {
  }

  if (!(cur_stream->sndvar->on_closeq || cur_stream->sndvar->on_closeq_int ||
        cur_stream->sndvar->on_resetq || cur_stream->sndvar->on_resetq_int))
  {
      MA_LOG("here?");
    cur_stream->state = TCP_ST_CLOSED_RSVD;
    cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
    cur_stream->close_reason = TCP_RESET;
    raise_close_event(mssl, cur_stream);
  }

  return TRUE;
}

inline void estimate_rtt(mssl_manager_t mssl, tcp_stream *cur_stream, uint32_t mrtt)
{
#define TCP_RTO_MIN 0
  long m = mrtt;
  uint32_t tcp_rto_min = TCP_RTO_MIN;
  struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;

  if (m == 0)
  {
    m = 1;
  }

  if (rcvvar->srtt != 0)
  {
    m -= (rcvvar->srtt >> 3);
    rcvvar->srtt += m;
    if (m < 0)
    {
      m = -m;
      m -= (rcvvar->mdev >> 2);
      if (m > 0)
      {
        m >>= 3;
      }
    }
    else
    {
      m -= (rcvvar->mdev >> 2);
    }
    rcvvar->mdev += m;
    if (rcvvar->mdev > rcvvar->mdev_max)
    {
      rcvvar->mdev_max = rcvvar->mdev;
      if (rcvvar->mdev_max > rcvvar->rttvar)
      {
        rcvvar->rttvar = rcvvar->mdev_max;
      }
    }
    if (TCP_SEQ_GT(cur_stream->sndvar->snd_una, rcvvar->rtt_seq))
    {
      if (rcvvar->mdev_max < rcvvar->rttvar)
      {
        rcvvar->rttvar -= (rcvvar->rttvar - rcvvar->mdev_max) >> 2;
      }
      rcvvar->rtt_seq = cur_stream->snd_nxt;
      rcvvar->mdev_max = tcp_rto_min;
    }
  }
  else
  {
    rcvvar->srtt = m << 3;
    rcvvar->mdev = m << 1;
    rcvvar->mdev_max = rcvvar->rttvar = MAX(rcvvar->mdev, tcp_rto_min);
    rcvvar->rtt_seq = cur_stream->snd_nxt;
  }
}

static inline void process_ack(mssl_manager_t mssl, tcp_stream *cur_stream,
    struct pkt_ctx *pctx)
{
  const struct tcphdr *tcph = pctx->p.tcph;
  uint32_t seq = pctx->p.seq;
  uint32_t ack_seq = pctx->p.ack_seq;
  struct tcp_send_vars *sndvar = cur_stream->sndvar;
  uint32_t cwindow, cwindow_prev;
  uint32_t rmlen;
  uint32_t snd_wnd_prev;
  uint32_t right_wnd_edge;
  uint8_t dup;

  cwindow = pctx->p.window;

  if (!tcph->syn)
  {
    cwindow = cwindow << sndvar->wscale_peer;
  }
  right_wnd_edge = sndvar->peer_wnd + cur_stream->rcvvar->snd_wl2;

  if (cur_stream->state == TCP_ST_FIN_WAIT_1 ||
      cur_stream->state == TCP_ST_FIN_WAIT_2 ||
      cur_stream->state == TCP_ST_CLOSING ||
      cur_stream->state == TCP_ST_CLOSE_WAIT ||
      cur_stream->state == TCP_ST_LAST_ACK)
  {
    if (sndvar->is_fin_sent && ack_seq == sndvar->fss + 1)
      ack_seq--;
  }

  if (TCP_SEQ_GT(ack_seq, sndvar->sndbuf->head_seq + sndvar->sndbuf->len))
  {
    return;
  }

  if (TCP_SEQ_LT(cur_stream->rcvvar->snd_wl1, seq) ||
      (cur_stream->rcvvar->snd_wl1 == seq &&
      TCP_SEQ_LT(cur_stream->rcvvar->snd_wl2, ack_seq)) ||
      (cur_stream->rcvvar->snd_wl2 == ack_seq &&
       cwindow > sndvar->peer_wnd))
  {
    cwindow_prev = sndvar->peer_wnd;
    sndvar->peer_wnd = cwindow;
    cur_stream->rcvvar->snd_wl1 = seq;
    cur_stream->rcvvar->snd_wl2 = ack_seq;

    if (cwindow_prev < cur_stream->snd_nxt - sndvar->snd_una &&
        sndvar->peer_wnd >= cur_stream->snd_nxt - sndvar->snd_una)
    {
      raise_write_event(mssl, cur_stream);
    }
  }

  dup = FALSE;

  if (TCP_SEQ_LT(ack_seq, cur_stream->snd_nxt))
  {
    if (ack_seq == cur_stream->rcvvar->last_ack_seq && pctx->p.payloadlen == 0)
    {
      if (cur_stream->rcvvar->snd_wl2 + sndvar->peer_wnd == right_wnd_edge)
      {
        if (cur_stream->rcvvar->dup_acks + 1 > cur_stream->rcvvar->dup_acks)
        {
          cur_stream->rcvvar->dup_acks++;
        }
        dup = TRUE;
      }
    }
  }

  if (!dup) 
  {
    cur_stream->rcvvar->dup_acks = 0;
    cur_stream->rcvvar->last_ack_seq = ack_seq;
  }

  if (dup && cur_stream->rcvvar->dup_acks == 3)
  {
    if (TCP_SEQ_LT(ack_seq, cur_stream->snd_nxt))
    {
      cur_stream->snd_nxt = ack_seq;
    }

    sndvar->ssthresh = MIN(sndvar->cwnd, sndvar->peer_wnd) / 2;
    if (sndvar->ssthresh < 2 * sndvar->mss)
    {
      sndvar->ssthresh = 2 * sndvar->mss;
    }
    sndvar->cwnd = sndvar->ssthresh + 3 * sndvar->mss;

    if (sndvar->nrtx < TCP_MAX_RTX)
      sndvar->nrtx++;

    cur_stream->actions |= MOS_ACT_SEND_DATA;
  }
  else if (cur_stream->rcvvar->dup_acks > 3)
  {
    if ((uint32_t)(sndvar->cwnd + sndvar->mss) > sndvar->cwnd)
    {
      sndvar->cwnd += sndvar->mss;
    }
  }

  if (TCP_SEQ_GT(ack_seq, cur_stream->snd_nxt))
  {
    cur_stream->snd_nxt = ack_seq;
    if (sndvar->sndbuf->len == 0)
    {
      remove_from_send_list(mssl, cur_stream);
    }
  }

  if (TCP_SEQ_GEQ(sndvar->sndbuf->head_seq, ack_seq))
    return;

  rmlen = ack_seq - sndvar->sndbuf->head_seq;
  if (rmlen > 0)
  {
    uint16_t packets;
    packets = rmlen / sndvar->eff_mss;
    if ((rmlen/sndvar->eff_mss) * sndvar->eff_mss > rmlen)
      packets++;

    if (cur_stream->saw_timestamp)
    {
      estimate_rtt(mssl, cur_stream, 
            pctx->p.cur_ts - cur_stream->rcvvar->ts_lastack_rcvd);
      sndvar->rto = (cur_stream->rcvvar->srtt >> 3) + cur_stream->rcvvar->rttvar;
      assert(sndvar->rto > 0);
    }

    if (cur_stream->state >= TCP_ST_ESTABLISHED)
    {
      if (sndvar->cwnd < sndvar->ssthresh)
      {
        if ((sndvar->cwnd + sndvar->mss) > sndvar->cwnd)
        {
          sndvar->cwnd += (sndvar->mss * packets);
        }
      }
      else
      {
        uint32_t new_cwnd = sndvar->cwnd + packets * sndvar->mss * sndvar->mss /
          sndvar->cwnd;
        if (new_cwnd > sndvar->cwnd)
        {
          sndvar->cwnd = new_cwnd;
        }
      }
    }

    if (SBUF_LOCK(&sndvar->write_lock))
    {
      if (errno == EDEADLK)
        perror("process_ack: write_lock blocked\n");
      assert(0);
    }

    sb_remove(mssl->rbm_snd, sndvar->sndbuf, rmlen);
    sndvar->snd_una = ack_seq;
    snd_wnd_prev = sndvar->snd_wnd;
    sndvar->snd_wnd = sndvar->sndbuf->size - sndvar->sndbuf->len;

    raise_write_event(mssl, cur_stream);

    SBUF_UNLOCK(&sndvar->write_lock);
    update_retransmission_timer(mssl, cur_stream, pctx->p.cur_ts);
  }
}

static inline int process_tcp_payload(mssl_manager_t mssl, tcp_stream *cur_stream,
    struct pkt_ctx *pctx)
{
  MA_LOG("process_tcp_payload");
  struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;
  uint32_t prev_rcv_nxt;
  int ret = -1;
  bool read_lock;
  struct socket_map *walk;

  if (!cur_stream->buffer_mgmt)
    return FALSE;

  if (TCP_SEQ_LT(pctx->p.seq + pctx->p.payloadlen, cur_stream->rcv_nxt))
    return FALSE;

/*
  if (TCP_SEQ_GT(pctx->p.seq + pctx->p.payloadlen, cur_stream->rcv_nxt + rcvvar->rcv_wnd))
  {
    if (cur_stream->side == MOS_SIDE_CLI)
    {
*/

  if (!rcvvar->rcvbuf)
  {
    rcvvar->rcvbuf = tcprb_new(mssl->bufseg_pool, g_config.mos->rmem_size, cur_stream->buffer_mgmt);
    if (!rcvvar->rcvbuf)
    {
      MA_LOG("here?");
      cur_stream->state = TCP_ST_CLOSED_RSVD;
      cur_stream->close_reason = TCP_NO_MEM;
      cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
      raise_error_event(mssl, cur_stream);

      return ERROR;
    }
  }

  read_lock = HAS_STREAM_TYPE(cur_stream, MOS_SOCK_SPLIT_TLS);

  if (read_lock && SBUF_LOCK(&rcvvar->read_lock))
  {
    if (errno == EDEADLK)
      perror("process_tcp_payload: read_lock blocked\n");
    assert(0);
  }

  prev_rcv_nxt = cur_stream->rcv_nxt;

  tcprb_t *rb = rcvvar->rcvbuf;
  loff_t off = seq2loff(rb, pctx->p.seq, (rcvvar->irs + 1));

  if (off >= 0)
  {
    // MOS_SOCK_MONITOR_STREAM_ACTIVE code
    ret = tcprb_pwrite(rb, pctx->p.payload, pctx->p.payloadlen, off);
  }

  loff_t cftail = rb->pile + tcprb_cflen(rb);
  if (cur_stream->state == TCP_ST_FIN_WAIT_1 ||
      cur_stream->state == TCP_ST_FIN_WAIT_2)
  {
    tcprb_setpile(rb, cftail);
  }

  if (cftail > 0 && (rcvvar->irs + 1) + cftail > cur_stream->rcv_nxt)
  {
    cur_stream->rcv_nxt = (rcvvar->irs + 1) + cftail;
  }
  assert(cftail - rb->pile >= 0);
  rcvvar->rcv_wnd = rb->len - (cftail - rb->pile);

  if (read_lock)
    SBUF_UNLOCK(&rcvvar->read_lock);

  if (TCP_SEQ_LEQ(cur_stream->rcv_nxt, prev_rcv_nxt))
    return FALSE;

  if (cur_stream->state == TCP_ST_ESTABLISHED)
    raise_read_event(mssl, cur_stream);

  return TRUE;
}

static inline void handle_TCP_ST_LISTEN(mssl_manager_t mssl, tcp_stream *cur_stream,
   struct pkt_ctx *pctx)
{
  MA_LOG("handle_TCP_ST_LISTEN");
  const struct tcphdr *tcph = pctx->p.tcph;

  if (tcph->syn)
  {
    if (cur_stream->state == TCP_ST_LISTEN)
    {
      cur_stream->rcvvar->irs = cur_stream->rcv_nxt = pctx->p.seq;
      cur_stream->rcv_nxt++;
    }
    cur_stream->state = TCP_ST_SYN_RCVD;
    cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE | MOS_ON_CONN_START;
    cur_stream->actions |= MOS_ACT_SEND_CONTROL;

    cur_stream->rcvvar->irs = pctx->p.seq;
    cur_stream->rcv_nxt = pctx->p.seq + 1;
  }
  else
  {
    MA_LOG("Packet without SYN");
  }
} 

static inline void handle_TCP_ST_SYN_SENT(mssl_manager_t mssl, tcp_stream *cur_stream,
    struct pkt_ctx *pctx)
{
  MA_LOG("handle_TCP_ST_SYN_SENT");
  const struct tcphdr *tcph = pctx->p.tcph;

  if (tcph->ack)
  {
    MA_LOG1d("pctx->p.ack_seq", pctx->p.ack_seq);
    MA_LOG1d("cur_stream->sndvar->iss", cur_stream->sndvar->iss);
    MA_LOG1d("cur_stream->snd_nxt", cur_stream->snd_nxt);

    if (TCP_SEQ_LEQ(pctx->p.ack_seq, cur_stream->sndvar->iss)
        || TCP_SEQ_GT(pctx->p.ack_seq, cur_stream->snd_nxt))
    {
      MA_LOG("Wrong sequence number for SYN/ACK");
      if (!tcph->rst)
      {
        cur_stream->actions |= MOS_ACT_SEND_RST;
      }
      return;
    }
    else
    {
      MA_LOG("Right sequence number for SYN/ACK");
    }
    cur_stream->sndvar->snd_una++;
  }

  if (tcph->rst)
  {
    if (tcph->ack)
    {
      MA_LOG("here?");
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
  MA_LOG("handle_TCP_ST_SYN_RCVD");
  const struct tcphdr *tcph = pctx->p.tcph;
  struct tcp_send_vars *sndvar = cur_stream->sndvar;
  int ret;

  if (tcph->ack)
  {
    uint32_t prior_cwnd;
    sndvar->snd_una++;
    cur_stream->snd_nxt = pctx->p.ack_seq;
    prior_cwnd = sndvar->cwnd;
    sndvar->cwnd = ((prior_cwnd == 1)?
        (sndvar->mss * 2) : sndvar->mss);
    sndvar->nrtx = 0;
    cur_stream->state = TCP_ST_ESTABLISHED;
    cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;

    if (pctx->p.ack_seq != sndvar->iss + 1)
      handle_TCP_ST_ESTABLISHED(mssl, cur_stream, pctx);

    /*
    struct tcp_listener *listener = mssl->listener;

    ret = stream_enqueue(listener->acceptq, cur_stream);

    if (ret < 0)
    {
      cur_stream->close_reason = TCP_NOT_ACCEPTED;
      cur_stream->state = TCP_ST_CLOSED_RSVD;
      cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
      cur_stream->actions |= MOS_ACT_SEND_CONTROL;
    }

    if (listener->socket && (listener->socket->epoll & MOS_EPOLLIN))
    {
      add_epoll_event(mssl->ep, MOS_EVENT_QUEUE, listener->socket, MOS_EPOLLIN);
    }
    */

    if (g_config.mos->tcp_timeout > 0)
      add_to_timeout_list(mssl, cur_stream);
  }
  else
  {
    if (tcph->syn)
    {
      // handle retransmitted SYN packet
      MA_LOG("handle retransmitted SYN packet");
    }
    cur_stream->snd_nxt = sndvar->iss;
    cur_stream->actions |= MOS_ACT_SEND_CONTROL;
  }
  MA_LOG("handle_TCP_ST_SYN_RCVD end");
}

static inline void handle_TCP_ST_ESTABLISHED(mssl_manager_t mssl, tcp_stream *cur_stream,
    struct pkt_ctx *pctx)
{
  MA_LOG("handle_TCP_ST_ESTABLISHED");
  const struct tcphdr *tcph = pctx->p.tcph;

  if (tcph->syn)
  {
    // handle retransmitted SYN/ACK packet
    MA_LOG("handle retransmitted SYN/ACK packet");

    cur_stream->snd_nxt = pctx->p.ack_seq;
    cur_stream->actions |= MOS_ACT_SEND_CONTROL;
    return;
  }

  if (pctx->p.payloadlen > 0)
  {
    if (process_tcp_payload(mssl, cur_stream, pctx))
    {
      cur_stream->actions |= MOS_ACT_SEND_ACK_AGG;
    }
    else
    {
      cur_stream->actions |= MOS_ACT_SEND_ACK_NOW;
    }
  }

  if (tcph->ack)
  {
    if (cur_stream->sndvar->sndbuf)
    {
      process_ack(mssl, cur_stream, pctx);
    }
  }

  if (tcph->fin)
  {
    if (!cur_stream->buffer_mgmt || pctx->p.seq + pctx->p.payloadlen == cur_stream->rcv_nxt)
    {
      cur_stream->state = TCP_ST_CLOSE_WAIT;
      cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
      cur_stream->rcv_nxt++;
      cur_stream->actions |= MOS_ACT_SEND_CONTROL;

      raise_read_event(mssl, cur_stream);
    }
    else
    {
      cur_stream->actions |= MOS_ACT_SEND_ACK_NOW;
      return;
    }
  }
}

static inline void handle_TCP_ST_CLOSE_WAIT(mssl_manager_t mssl, tcp_stream *cur_stream,
    struct pkt_ctx *pctx)
{
  MA_LOG("handle_TCP_ST_CLOSE_WAIT");
  if (TCP_SEQ_LT(pctx->p.seq, cur_stream->rcv_nxt))
  {
    cur_stream->actions |= MOS_ACT_SEND_CONTROL;
    return;
  }

  if (cur_stream->sndvar->sndbuf)
  {
    process_ack(mssl, cur_stream, pctx);
  }
}

static inline void handle_TCP_ST_LAST_ACK(mssl_manager_t mssl, tcp_stream *cur_stream,
    struct pkt_ctx *pctx)
{
  MA_LOG("handle_TCP_ST_LAST_ACK");
  const struct tcphdr *tcph = pctx->p.tcph;

  if (TCP_SEQ_LT(pctx->p.seq, cur_stream->rcv_nxt))
  {
    return;
  }

  if (tcph->ack)
  {
    if (cur_stream->sndvar->sndbuf)
    {
      process_ack(mssl, cur_stream, pctx);
    }

    if (!cur_stream->sndvar->is_fin_sent)
      return;

    if (pctx->p.ack_seq == cur_stream->sndvar->fss +1)
    {
      cur_stream->sndvar->snd_una++;
      update_retransmission_timer(mssl, cur_stream, pctx->p.cur_ts);
      MA_LOG("here?");
      cur_stream->state = TCP_ST_CLOSED_RSVD;
      cur_stream->close_reason = TCP_PASSIVE_CLOSE;
      cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
      cur_stream->actions |= MOS_ACT_DESTROY;
    }
    else
    {
      cur_stream->actions |= MOS_ACT_SEND_CONTROL;
    }
  }
  else
  {
    cur_stream->actions |= MOS_ACT_SEND_CONTROL;
  }
}

static inline void handle_TCP_ST_FIN_WAIT_1(mssl_manager_t mssl, tcp_stream *cur_stream,
    struct pkt_ctx *pctx)
{
  MA_LOG("handle_TCP_ST_FIN_WAIT_1");
  const struct tcphdr *tcph = pctx->p.tcph;

  if (TCP_SEQ_LT(pctx->p.seq, cur_stream->rcv_nxt))
  {
    cur_stream->actions |= MOS_ACT_SEND_CONTROL;
    return;
  }

  if (tcph->ack)
  {
    if (cur_stream->sndvar->sndbuf)
    {
      process_ack(mssl, cur_stream, pctx);
    }

    if (cur_stream->sndvar->is_fin_sent
        &&pctx->p.ack_seq == cur_stream->sndvar->fss + 1)
    {
      cur_stream->sndvar->snd_una = pctx->p.ack_seq;
      if (TCP_SEQ_GT(pctx->p.ack_seq, cur_stream->snd_nxt))
      {
        cur_stream->snd_nxt = pctx->p.ack_seq;
      }

      cur_stream->sndvar->nrtx = 0;

      remove_from_rto_list(mssl, cur_stream);
      cur_stream->state = TCP_ST_FIN_WAIT_2;
      cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
    }
    else
    {
    }
  }
  else
  {
    return;
  }

  if (pctx->p.payloadlen > 0)
  {
    if (process_tcp_payload(mssl, cur_stream, pctx))
      cur_stream->actions |= MOS_ACT_SEND_ACK_AGG;
    else
      cur_stream->actions |= MOS_ACT_SEND_ACK_NOW;
  }

  if (tcph->fin)
  {
    if (!cur_stream->buffer_mgmt ||
        pctx->p.seq + pctx->p.payloadlen == cur_stream->rcv_nxt)
    {
      cur_stream->rcv_nxt++;

      if (cur_stream->state == TCP_ST_FIN_WAIT_1)
      {
        cur_stream->state = TCP_ST_CLOSING;
        cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
      }
      else if (cur_stream->state == TCP_ST_FIN_WAIT_2)
      {
        cur_stream->state = TCP_ST_TIME_WAIT;
        cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
        add_to_timewait_list(mssl, cur_stream, pctx->p.cur_ts);
      }
      cur_stream->actions |= MOS_ACT_SEND_CONTROL;
    }
    else
    {
      cur_stream->actions |= MOS_ACT_SEND_ACK_NOW;
      return;
    }
  }
}

static inline void handle_TCP_ST_FIN_WAIT_2(mssl_manager_t mssl, tcp_stream *cur_stream,
    struct pkt_ctx *pctx)
{
  MA_LOG("handle_TCP_ST_FIN_WAIT_2");
  const struct tcphdr *tcph = pctx->p.tcph;

  if (tcph->ack)
  {
    if (cur_stream->sndvar->sndbuf)
    {
      process_ack(mssl, cur_stream, pctx);
    }
  }
  else
  {
    return;
  }

  if (pctx->p.payloadlen > 0)
  {
    if (process_tcp_payload(mssl, cur_stream, pctx))
    {
      cur_stream->actions |= MOS_ACT_SEND_ACK_AGG;
    }
    else
    {
      cur_stream->actions |= MOS_ACT_SEND_ACK_NOW;
    }
  }

  if (tcph->fin)
  {
    if (!cur_stream->buffer_mgmt
        || pctx->p.seq + pctx->p.payloadlen == cur_stream->rcv_nxt)
    {
      cur_stream->state = TCP_ST_TIME_WAIT;
      cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
      cur_stream->rcv_nxt++;

      add_to_timewait_list(mssl, cur_stream, pctx->p.cur_ts);
      cur_stream->actions |= MOS_ACT_SEND_CONTROL;
    }
  }
  else
  {
  }
}

static inline void handle_TCP_ST_CLOSING(mssl_manager_t mssl, tcp_stream *cur_stream,
    struct pkt_ctx *pctx)
{
  MA_LOG("handle_TCP_ST_CLOSING");
  const struct tcphdr *tcph = pctx->p.tcph;

  if (tcph->ack)
  {
    if (cur_stream->sndvar->sndbuf)
    {
      process_ack(mssl, cur_stream, pctx);
    }

    if (!cur_stream->sndvar->is_fin_sent)
    {
      return;
    }

    if (pctx->p.ack_seq != cur_stream->sndvar->fss + 1)
    {
      return;
    }

    cur_stream->sndvar->snd_una = pctx->p.ack_seq;
    update_retransmission_timer(mssl, cur_stream, pctx->p.cur_ts);
    cur_stream->state = TCP_ST_TIME_WAIT;
    cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
    add_to_timewait_list(mssl, cur_stream, pctx->p.cur_ts);
  }
  else
  {
    return;
  }
}

static inline void do_split_tcp(mssl_manager_t mssl, tcp_stream *cur_stream,
    struct pkt_ctx *pctx)
{
  MA_LOG("do_split_tcp");
  tcp_stream *pair_stream;
  uint32_t stream_type;
  unsigned int hash = 0;
  stream_type = 0;

  ///// Add for matls /////
  uint16_t id;
  uint32_t seq;
  id = posix_seq_rand() % IP_MAX_ID;
  seq = posix_seq_rand() % TCP_MAX_SEQ;
  send_tcp_packet_standalone(mssl, pctx->p.iph->saddr, pctx->p.tcph->source,
      pctx->p.iph->daddr, pctx->p.tcph->dest, seq, 0, 1, TCP_FLAG_SYN, 
      pctx->p.payload, 0, pctx->p.cur_ts, 0, id, -1);
  ////////////////////////
  /*
  pair_stream = create_tcp_stream(mssl, NULL, MOS_SOCK_SPLIT_TLS,
      pctx->p.iph->saddr, pctx->p.tcph->source,
      pctx->p.iph->daddr, pctx->p.tcph->dest, &hash);
  pair_stream->state = TCP_ST_SYN_SENT;
  add_to_timewait_list(mssl, pair_stream, pctx->p.cur_ts);
  pair_stream->actions |= MOS_ACT_SEND_CONTROL;
  add_to_control_list(mssl, pair_stream, pctx->p.cur_ts);
  */
  MA_LOG("SYN sent to the server");
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
      ///// Add for MA_TLS /////
//      do_split_tcp(mssl, cur_stream, pctx);
      break;

    case TCP_ST_SYN_SENT:
      handle_TCP_ST_SYN_SENT(mssl, cur_stream, pctx);
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
  MA_LOG("do_action_end_tcp_packet");
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
