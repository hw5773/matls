#include <unistd.h>
#include <string.h>

#include "include/tcp_out.h"
#include "include/mssl.h"
#include "include/ip_in.h"
#include "include/ip_out.h"
#include "include/tcp_in.h"
#include "include/tcp.h"
#include "include/tcp_stream.h"
//#include "include/eventpoll.h"
#include "include/timer.h"
#include "include/logs.h"
#include "include/config.h"

#define TCP_CALCULATE_CHECKSUM TRUE
#define ACK_PIGGYBACK TRUE
#define TRY_SEND_BEFORE_QUEUE TRUE
#define TCP_MAX_WINDOW 65535

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

inline void fill_packet_context_tcp_info(struct pkt_ctx *pctx, struct tcphdr *tcph)
{
  pctx->p.tcph = tcph;
  pctx->p.payload = (uint8_t *)tcph + (tcph->doff << 2);
  pctx->p.payloadlen = pctx->p.ip_len - (pctx->p.payload - (uint8_t *)pctx->p.iph);
  pctx->p.seq = ntohl(tcph->seq);
  pctx->p.ack_seq = ntohl(tcph->ack_seq);
  pctx->p.window = ntohs(tcph->window);
  pctx->p.offset = 0;

  return;
}

static inline uint16_t calculate_option_length(uint8_t flags)
{
  uint16_t optlen = 0;

  if (flags & TCP_FLAG_SYN)
  {
    optlen += TCP_OPT_MSS_LEN;
#if TCP_OPT_SACK_ENABLED
    optlen += TCP_OPT_SACK_PERMIT_LEN;
#if !TCP_OPT_TIMESTAMP_ENABLED
    optlen += 2;
#endif
#endif

#if TCP_OPT_TIMESTAMP_ENABLED
    optlen += TCP_OPT_TIMESTAMP_LEN;
#if !TCP_OPT_SACK_ENABLED
    optlen += 2;
#endif
#endif

    optlen += TCP_OPT_WSCALE_LEN + 1;
  }
  else
  {
#if TCP_OPT_TIMESTAMP_ENABLED
    optlen += TCP_OPT_TIMESTAMP_LEN + 2;
#endif

#if TCP_OPT_SACK_ENABLED
    if (flags & TCP_FLAG_SACK)
    {
      optlen += TCP_OPT_SACK_LEN + 2;
    }
#endif
  }

  assert(optlen % 4 == 0);

  return optlen;
}

int send_tcp_packet_standalone(mssl_manager_t mssl, uint32_t saddr, uint16_t sport,
    uint32_t daddr, uint16_t dport, uint32_t seq, uint32_t ack_seq, uint16_t window,
    uint8_t flags, uint8_t *payload, uint16_t payloadlen, uint32_t cur_ts,
    uint32_t echo_ts, uint16_t ip_id, int8_t in_ifidx)
{
  struct tcphdr *tcph;
  uint8_t *tcpopt;
  uint32_t *ts;
  uint16_t optlen;
  struct pkt_ctx pctx;
  int rc = -1;

  memset(&pctx, 0, sizeof(pctx));
  pctx.p.in_ifidx = in_ifidx;
  optlen = calculate_option_length(flags);
  if (payloadlen > TCP_DEFAULT_MSS + optlen)
  {
    MA_LOG("payload size exceeds MSS");
    assert(0);
    return ERROR;
  }

  tcph = (struct tcphdr *)ip_output_standalone(mssl, htons(ip_id),
      saddr, daddr, TCP_HEADER_LEN + optlen + payloadlen, &pctx, cur_ts);

  if (!tcph)
    return ERROR;

  memset(tcph, 0, TCP_HEADER_LEN + optlen);

  tcph->source = sport;
  tcph->dest = dport;

  if (flags & TCP_FLAG_SYN)
    tcph->syn = TRUE;
  if (flags & TCP_FLAG_FIN)
    tcph->fin = TRUE;
  if (flags & TCP_FLAG_RST)
    tcph->rst = TRUE;
  if (flags & TCP_FLAG_PSH)
    tcph->psh = TRUE;

  tcph->seq = htonl(seq);
  if (flags & TCP_FLAG_ACK)
  {
    tcph->ack = TRUE;
    tcph->ack_seq = htonl(ack_seq);
  }

  tcph->window = htons(MIN(window, TCP_MAX_WINDOW));

  tcpopt = (uint8_t *)tcph + TCP_HEADER_LEN;
  ts = (uint32_t *)(tcpopt + 4);

  tcpopt[0] = TCP_OPT_NOP;
  tcpopt[1] = TCP_OPT_NOP;
  tcpopt[2] = TCP_OPT_TIMESTAMP;
  tcpopt[3] = TCP_OPT_TIMESTAMP_LEN;
  ts[0] = htonl(cur_ts);
  ts[1] = htonl(echo_ts);

  tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;

  if (payloadlen > 0)
  {
    memcpy((uint8_t *)tcph + TCP_HEADER_LEN + optlen, payload, payloadlen);
  }

#if TCP_CALCULATE_CHECKSUM
  if (likely(mssl->iom->dev_ioctl != NULL))
    rc = mssl->iom->dev_ioctl(mssl->ctx, pctx.out_ifidx, PKT_TX_TCP_CSUM, pctx.p.iph);

  if (rc == -1)
    tcph->check = tcp_calc_checksum((uint16_t *)tcph, TCP_HEADER_LEN + optlen + payloadlen,
        saddr, daddr);
#endif

  if (tcph->syn || tcph->fin)
  {
    payloadlen++;
  }

  return payloadlen;
}

int send_tcp_packet(mssl_manager_t mssl, tcp_stream *cur_stream,
    uint32_t cur_ts, uint8_t flags, uint8_t *payload, uint16_t payloadlen)
{
  struct tcphdr *tcph;
  uint16_t optlen;
  uint8_t wscale = 0;
  uint32_t window32 = 0;
  struct pkt_ctx pctx;
  int rc = -1;

  memset(&pctx, 0, sizeof(pctx));
  optlen = calculate_option_length(flags);

  if (payloadlen > cur_stream->sndvar->mss + optlen)
  {
    MA_LOG("Payload size exceeds MSS");
    return ERROR;
  }

  tcph = (struct tcphdr *)ip_output(mssl, cur_stream, TCP_HEADER_LEN + optlen + payloadlen,
      &pctx, cur_ts);

  MA_LOG("after ip output");

  if (!tcph)
    return -2;

  memset(tcph, 0, TCP_HEADER_LEN + optlen);

  tcph->source = cur_stream->sport;
  tcph->dest = cur_stream->dport;

  if (flags & TCP_FLAG_SYN)
  {
    tcph->syn = TRUE;

    if (cur_stream->snd_nxt != cur_stream->sndvar->iss)
    {
      MA_LOG("weird syn sequence");
    }
  }

  if (flags & TCP_FLAG_RST)
  {
    tcph->rst = TRUE;
  }

  if (flags & TCP_FLAG_PSH)
  {
    tcph->psh = TRUE;
  }

  if (flags & TCP_FLAG_WACK)
  {
    tcph->seq = htonl(cur_stream->snd_nxt - 1);
  }
  else if (flags & TCP_FLAG_FIN)
  {
    tcph->fin = TRUE;

    if (cur_stream->sndvar->fss == 0)
    {
      MA_LOG("fss set");
    }
    tcph->seq = htonl(cur_stream->sndvar->fss);
    cur_stream->sndvar->is_fin_sent = TRUE;
  }
  else
  {
    tcph->seq = htonl(cur_stream->snd_nxt);
  }

  if (flags & TCP_FLAG_ACK)
  {
    tcph->ack = TRUE;
    tcph->ack_seq = htonl(cur_stream->rcv_nxt);
    cur_stream->sndvar->ts_lastack_sent = cur_ts;
    cur_stream->last_active_ts = cur_ts;
    update_timeout_list(mssl, cur_stream);
  }

  if (flags & TCP_FLAG_SYN)
  {
    wscale = 0;
  }
  else
  {
    wscale = cur_stream->sndvar->wscale_mine;
  }

  window32 = cur_stream->rcvvar->rcv_wnd >> wscale;
  tcph->window = htons((uint16_t)MIN(window32, TCP_MAX_WINDOW));

  if (window32 == 0)
  {
    cur_stream->need_wnd_adv = TRUE;
  }

//  generate_tcp_options(cur_stream, cur_ts, flags, (uint8_t *)tcph + TCP_HEADER_LEN, optlen);

  tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;

  if (payloadlen > 0)
  {
    memcpy((uint8_t *)tcph + TCP_HEADER_LEN + optlen, payload, payloadlen);
  }

#if TCP_CALCULATE_CHECKSUM
  if (likely(mssl->iom->dev_ioctl != NULL))
    rc = mssl->iom->dev_ioctl(mssl->ctx, pctx.out_ifidx, PKT_TX_TCP_CSUM, pctx.p.iph);

  if (rc == -1)
    tcph->check = tcp_calc_checksum((uint16_t *)tcph, TCP_HEADER_LEN + optlen + payloadlen,
        cur_stream->saddr, cur_stream->daddr);
#endif
  cur_stream->snd_nxt += payloadlen;

  if (tcph->syn || tcph->fin)
  {
    cur_stream->snd_nxt++;
    payloadlen++;
  }

  if (payloadlen > 0)
  {
    if (cur_stream->state > TCP_ST_ESTABLISHED)
    {
      MA_LOG1d("payload after ESTABLISHED", payloadlen);
    }
    cur_stream->sndvar->ts_rto = cur_ts + cur_stream->sndvar->rto;
    add_to_rto_list(mssl, cur_stream);
  }

  // callback

  if (mssl->num_msp)
    fill_packet_context_tcp_info(&pctx, tcph);

  struct tcp_stream *recvside_stream = cur_stream->pair_stream;
  struct tcp_stream *sendside_stream = cur_stream;

  if (recvside_stream)
  {
    if (recvside_stream->rcvvar && recvside_stream->rcvvar->rcvbuf)
      pctx.p.offset = (uint64_t)seq2loff(recvside_stream->rcvvar->rcvbuf, 
          pctx.p.seq, recvside_stream->rcvvar->irs + 1);
    update_monitor(mssl, sendside_stream, recvside_stream, &pctx, false);
  }

  return payloadlen;
}

static int flush_tcp_sending_buffer(mssl_manager_t mssl, tcp_stream *cur_stream, uint32_t cur_ts)
{
  struct tcp_send_vars *sndvar = cur_stream->sndvar;
  const uint32_t maxlen = sndvar->mss - calculate_option_length(TCP_FLAG_ACK);
  uint8_t *data;
  uint32_t buffered_len;
  uint32_t seq;
  uint16_t len;
  int16_t sndlen;
  uint32_t window;
  int packets = 0;
  uint8_t wack_sent = 0;

  if (!sndvar->sndbuf)
  {
    MA_LOG1d("no send buffer", cur_stream->id);
    assert(0);
    return 0;
  }

  SBUF_LOCK(&sndvar->write_lock);

  if (sndvar->sndbuf->len == 0)
  {
    packets = 0;
    goto out;
  }

  window = MIN(sndvar->cwnd, sndvar->peer_wnd);

  while (1)
  {
    seq = cur_stream->snd_nxt;

    if (TCP_SEQ_LT(seq, sndvar->sndbuf->head_seq))
    {
      MA_LOG1d("invalid sequence to send", cur_stream->id);
      assert(0);
      break;
    }

    buffered_len = sndvar->sndbuf->head_seq + sndvar->sndbuf->len - seq;

    if (cur_stream->state > TCP_ST_ESTABLISHED)
    {
    }

    if (buffered_len == 0)
      break;

    data = sndvar->sndbuf->head + (seq - sndvar->sndbuf->head_seq);

    if (buffered_len > maxlen)
    {
      len = maxlen;
    }
    else
    {
      len = buffered_len;
    }

    if (len > window)
      len = window;

    if (len <= 0)
      break;

    if (cur_stream->state > TCP_ST_ESTABLISHED)
    {
      MA_LOG1d("Flushing after ESTABLISHED", cur_stream->id);
    }

    if (seq - sndvar->snd_una + len > window)
    {
      if (seq - sndvar->snd_una + len > sndvar->peer_wnd)
      {
        if (!wack_sent && TS_TO_MSEC(cur_ts - sndvar->ts_lastack_sent) > 500)
        {
          enqueue_ack(mssl, cur_stream, cur_ts, ACK_OPT_WACK);
        }
        else
          wack_sent = 1;
      }
      packets = -3;
      goto out;
    }

    sndlen = send_tcp_packet(mssl, cur_stream, cur_ts, TCP_FLAG_ACK, data, len);

    if (sndlen < 0)
    {
      packets = sndlen;
      goto out;
    }
    packets++;

    window -= len;
  }

out:
  SBUF_UNLOCK(&sndvar->write_lock);
  return packets;
}

static inline int send_control_packet(mssl_manager_t mssl, tcp_stream *cur_stream, uint32_t cur_ts)
{
  struct tcp_send_vars *sndvar = cur_stream->sndvar;
  int ret = 0;
  int flag = 0;

  switch(cur_stream->state)
  {
    case TCP_ST_SYN_SENT:
      flag = TCP_FLAG_SYN;
      break;
    case TCP_ST_SYN_RCVD:
      cur_stream->snd_nxt = sndvar->iss;
      flag = TCP_FLAG_SYN | TCP_FLAG_ACK;
      break;
    case TCP_ST_ESTABLISHED:
    case TCP_ST_CLOSE_WAIT:
    case TCP_ST_FIN_WAIT_2:
    case TCP_ST_TIME_WAIT:
      flag = TCP_FLAG_ACK;
      break;
    case TCP_ST_LAST_ACK:
    case TCP_ST_FIN_WAIT_1:
      if (sndvar->on_send_list || sndvar->on_ack_list)
        return -1;
      flag = TCP_FLAG_FIN | TCP_FLAG_ACK;
      break;
    case TCP_ST_CLOSING:
      if (sndvar->is_fin_sent)
      {
        flag = (cur_stream->snd_nxt == sndvar->fss) ?
          (TCP_FLAG_FIN | TCP_FLAG_ACK) : TCP_FLAG_ACK;
      }
      else
      {
        flag = TCP_FLAG_FIN | TCP_FLAG_ACK;
      }
    case TCP_ST_CLOSED_RSVD:
      if (sndvar->on_send_list || sndvar->on_ack_list)
        return -1;
      ret = send_tcp_packet(mssl, cur_stream, cur_ts, TCP_FLAG_RST, NULL, 0);
      if (ret >= 0)
        destroy_tcp_stream(mssl, cur_stream);
      return ret;
    default:
      assert(0);
      return 0;
  }

  return send_tcp_packet(mssl, cur_stream, cur_ts, flag, NULL, 0);
}

inline int write_tcp_control_list(mssl_manager_t mssl, 
    struct mssl_sender *sender, uint32_t cur_ts, int thresh)
{
  tcp_stream *cur_stream;
  tcp_stream *next, *last;
  int cnt = 0;
  int ret;

  thresh = MIN(thresh, sender->control_list_cnt);

  cnt = 0;
  cur_stream = TAILQ_FIRST(&sender->control_list);
  last = TAILQ_LAST(&sender->control_list, control_head);

  while (cur_stream)
  {
    if (++cnt > thresh)
      break;

    next = TAILQ_NEXT(cur_stream, sndvar->control_link);

    TAILQ_REMOVE(&sender->control_list, cur_stream, sndvar->control_link);
    sender->control_list_cnt--;

    if (cur_stream->sndvar->on_control_list)
    {
      cur_stream->sndvar->on_control_list = FALSE;
      ret = send_control_packet(mssl, cur_stream, cur_ts);

      if (ret < 0)
      {
        TAILQ_INSERT_HEAD(&sender->control_list, cur_stream, sndvar->control_link);
        cur_stream->sndvar->on_control_list = TRUE;
        sender->control_list_cnt++;
        break;
      }
    }
    else
    {
      MA_LOG1d("not on control list", cur_stream->id);
    }

    if (cur_stream == last)
      break;
    cur_stream = next;
  }

  return cnt;
}

inline int write_tcp_data_list(mssl_manager_t mssl, struct mssl_sender *sender,
    uint32_t cur_ts, int thresh)
{
  tcp_stream *cur_stream;
  tcp_stream *next, *last;
  int cnt = 0;
  int ret;

  cnt = 0;
  cur_stream = TAILQ_FIRST(&sender->send_list);
  last = TAILQ_LAST(&sender->send_list, send_head);

  while (cur_stream)
  {
    if (++cnt > thresh)
      break;

    next = TAILQ_NEXT(cur_stream, sndvar->send_link);

    TAILQ_REMOVE(&sender->send_list, cur_stream, sndvar->send_link);

    if (cur_stream->sndvar->on_send_list)
    {
      ret = 0;

      if (cur_stream->state == TCP_ST_ESTABLISHED)
      {
        if (cur_stream->sndvar->on_control_list)
        {
          ret = -1;
        }
        else 
        {
          ret = flush_tcp_sending_buffer(mssl, cur_stream, cur_ts);
        }
      }
      else if (cur_stream->state == TCP_ST_CLOSE_WAIT ||
          cur_stream->state == TCP_ST_FIN_WAIT_1 ||
          cur_stream->state == TCP_ST_LAST_ACK)
      {
        ret = flush_tcp_sending_buffer(mssl, cur_stream, cur_ts);
      }
      else
      {
      }

      if (ret < 0)
      {
        TAILQ_INSERT_TAIL(&sender->send_list, cur_stream, sndvar->send_link);
        break;
      }
      else
      {
        cur_stream->sndvar->on_send_list = FALSE;
        sender->send_list_cnt--;
#if ACK_PIGGYBACK
        if (cur_stream->sndvar->ack_cnt > 0)
        {
          if (cur_stream->sndvar->ack_cnt > ret)
          {
            cur_stream->sndvar->ack_cnt -= ret;
          }
          else
          {
            cur_stream->sndvar->ack_cnt = 0;
          }
        }
#endif
        if (cur_stream->control_list_waiting)
        {
          if (!cur_stream->sndvar->on_ack_list)
          {
            cur_stream->control_list_waiting = FALSE;
            add_to_control_list(mssl, cur_stream, cur_ts);
          }
        }
      }
    }
    else
    {
    }

    if (cur_stream == last)
      break;
    cur_stream = next;
  }
  return cnt;
}

inline int write_tcp_ack_list(mssl_manager_t mssl, struct mssl_sender *sender,
    uint32_t cur_ts, int thresh)
{
  tcp_stream *cur_stream;
  tcp_stream *next, *last;
  int to_ack;
  int cnt = 0;
  int ret;

  cur_stream = TAILQ_FIRST(&sender->ack_list);
  last = TAILQ_LAST(&sender->ack_list, ack_head);

  while (cur_stream)
  {
    if (++cnt > thresh)
      break;

    next = TAILQ_NEXT(cur_stream, sndvar->ack_link);

    if (cur_stream->sndvar->on_ack_list)
    {
      to_ack = FALSE;

      if (cur_stream->state == TCP_ST_ESTABLISHED ||
          cur_stream->state == TCP_ST_CLOSE_WAIT ||
          cur_stream->state == TCP_ST_FIN_WAIT_1 ||
          cur_stream->state == TCP_ST_FIN_WAIT_2 ||
          cur_stream->state == TCP_ST_TIME_WAIT)
      {
        tcprb_t *rb;

        if ((rb = cur_stream->rcvvar->rcvbuf) &&
            TCP_SEQ_LEQ(cur_stream->rcv_nxt, 
              (cur_stream->rcvvar->irs + 1) + rb->pile + tcprb_cflen(rb)))
        {
          to_ack = TRUE;
        }
      }
      else
      {
        MA_LOG("Try sending ack at not proper state");
      }

      if (to_ack)
      {
        while (cur_stream->sndvar->ack_cnt > 0)
        {
          ret = send_tcp_packet(mssl, cur_stream, cur_ts, TCP_FLAG_ACK, NULL, 0);

          if (ret < 0)
            break;

          cur_stream->sndvar->ack_cnt--;
        }

        if (cur_stream->sndvar->is_wack)
        {
          cur_stream->sndvar->is_wack = FALSE;
          ret = send_tcp_packet(mssl, cur_stream, cur_ts, TCP_FLAG_ACK | TCP_FLAG_WACK, NULL, 0);

          if (ret < 0)
            cur_stream->sndvar->is_wack = TRUE;
        }

        if (!(cur_stream->sndvar->ack_cnt || cur_stream->sndvar->is_wack))
        {
          cur_stream->sndvar->on_ack_list = FALSE;
          TAILQ_REMOVE(&sender->ack_list, cur_stream, sndvar->ack_link);
          sender->ack_list_cnt--;
        }
      }
      else
      {
        cur_stream->sndvar->on_ack_list = FALSE;
        cur_stream->sndvar->ack_cnt = 0;
        cur_stream->sndvar->is_wack = 0;
        TAILQ_REMOVE(&sender->ack_list, cur_stream, sndvar->ack_link);
        sender->ack_list_cnt--;
      }

      if (cur_stream->control_list_waiting)
      {
        if (!cur_stream->sndvar->on_send_list)
        {
          cur_stream->control_list_waiting = FALSE;
          add_to_control_list(mssl, cur_stream, cur_ts);
        }
      }
    }
    else
    {
      TAILQ_REMOVE(&sender->ack_list, cur_stream, sndvar->ack_link);
      sender->ack_list_cnt--;
    }

    if (cur_stream == last)
      break;
    cur_stream = next;
  }

  return cnt;
}

inline struct mssl_sender *get_sender(mssl_manager_t mssl, tcp_stream *cur_stream)
{
  if (cur_stream->sndvar->nif_out < 0)
  {
    return mssl->g_sender;
  }
  else if (cur_stream->sndvar->nif_out >= g_config.mos->netdev_table->num)
  {
    MA_LOG("Failed to find appropriate sender");
    return NULL;
  }
  else
  {
    return mssl->n_sender[cur_stream->sndvar->nif_out];
  }
}

inline void add_to_control_list(mssl_manager_t mssl, tcp_stream *cur_stream, uint32_t cur_ts)
{
/*
  int ret;
  struct mssl_sender *sender = get_sender(mssl, cur_stream);
  assert(sender != NULL);

  ret = send_control_packet(mssl, cur_stream, cur_ts);
  if (ret < 0)
  {
*/
  if (!cur_stream->sndvar->on_control_list)
  {
    struct mssl_sender *sender = get_sender(mssl, cur_stream);
    assert(sender != NULL);

    cur_stream->sndvar->on_control_list = TRUE;
    TAILQ_INSERT_TAIL(&sender->control_list, cur_stream, sndvar->control_link);
    sender->control_list_cnt++;
  }
/*
  } 
  else
  {
    if (cur_stream->sndvar->on_control_list)
    {
      cur_stream->sndvar->on_control_list = FALSE;
      TAILQ_REMOVE(&sender->control_list, cur_stream, sndvar->control_link);
      sender->control_list_cnt--;
    }
  }
*/
}

inline void add_to_send_list(mssl_manager_t mssl, tcp_stream *cur_stream)
{
  struct mssl_sender *sender = get_sender(mssl, cur_stream);
  assert(sender != NULL);

  if (!cur_stream->sndvar->sndbuf)
  {
    assert(0);
    return;
  }

  if (!cur_stream->sndvar->on_send_list)
  {
    cur_stream->sndvar->on_send_list = TRUE;
    TAILQ_INSERT_TAIL(&sender->send_list, cur_stream, sndvar->send_link);
    sender->send_list_cnt++;
  }
}

inline void add_to_ack_list(mssl_manager_t mssl, tcp_stream *cur_stream)
{
  struct mssl_sender *sender = get_sender(mssl, cur_stream);
  assert(sender != NULL);

  if (!cur_stream->sndvar->on_ack_list)
  {
    cur_stream->sndvar->on_ack_list = TRUE;
    TAILQ_INSERT_TAIL(&sender->ack_list, cur_stream, sndvar->ack_link);
    sender->ack_list_cnt++;
  }
}

inline void remove_from_control_list(mssl_manager_t mssl, tcp_stream *cur_stream)
{
  struct mssl_sender *sender = get_sender(mssl, cur_stream);
  assert(sender != NULL);

  if (cur_stream->sndvar->on_control_list)
  {
    cur_stream->sndvar->on_control_list = FALSE;
    TAILQ_REMOVE(&sender->control_list, cur_stream, sndvar->control_link);
    sender->control_list_cnt--;
  }
}

inline void remove_from_send_list(mssl_manager_t mssl, tcp_stream *cur_stream)
{
  struct mssl_sender *sender = get_sender(mssl, cur_stream);
  assert(sender != NULL);

  if (cur_stream->sndvar->on_ack_list)
  {
    cur_stream->sndvar->on_ack_list = FALSE;
    TAILQ_REMOVE(&sender->ack_list, cur_stream, sndvar->ack_link);
    sender->ack_list_cnt--;
  }
}

inline void enqueue_ack(mssl_manager_t mssl, tcp_stream *cur_stream, uint32_t cur_ts, uint8_t opt)
{
  if (!(cur_stream->state == TCP_ST_ESTABLISHED ||
        cur_stream->state == TCP_ST_CLOSE_WAIT ||
        cur_stream->state == TCP_ST_FIN_WAIT_1 ||
        cur_stream->state == TCP_ST_FIN_WAIT_2))
  {
  }

  if (opt == ACK_OPT_NOW)
  {
    if (cur_stream->sndvar->ack_cnt < cur_stream->sndvar->ack_cnt + 1)
    {
      cur_stream->sndvar->ack_cnt++;
    }
  }
  else if (opt == ACK_OPT_AGGREGATE)
  {
    if (cur_stream->sndvar->ack_cnt == 0)
    {
      cur_stream->sndvar->ack_cnt = 1;
    }
  }
  else if (opt == ACK_OPT_WACK)
  {
    cur_stream->sndvar->is_wack = TRUE;
  }

  add_to_ack_list(mssl, cur_stream);
}

static inline void update_passive_send_tcp_synsent(struct tcp_stream *cur_stream, 
    struct pkt_ctx *pctx)
{
  assert(cur_stream);
  assert(pctx);

  if (cur_stream->state < TCP_ST_SYN_SENT)
  {
    cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
    cur_stream->cb_events |= MOS_ON_CONN_START;
  }

  cur_stream->sndvar->cwnd = 1;
  cur_stream->sndvar->ssthresh = cur_stream->sndvar->mss * 10;
  cur_stream->sndvar->ip_id = htons(pctx->p.iph->id);
  cur_stream->sndvar->iss = pctx->p.seq;
  cur_stream->snd_nxt = pctx->p.seq + 1;
  cur_stream->state = TCP_ST_SYN_SENT;
  cur_stream->last_active_ts = pctx->p.cur_ts;
}

void update_passive_send_tcp_context(mssl_manager_t mssl, struct tcp_stream *cur_stream, 
    struct pkt_ctx *pctx)
{
  struct tcphdr *tcph;

  assert(cur_stream);
  tcph = pctx->p.tcph;

  if (tcph->syn && !tcph->ack && cur_stream->state <= TCP_ST_SYN_SENT)
  {
    MA_LOG("update_passive_send_tcp_context SYN");
    update_passive_send_tcp_synsent(cur_stream, pctx);
    add_to_timeout_list(mssl, cur_stream);
    return;
  }

  if (tcph->ack)
  {
    cur_stream->sndvar->ts_lastack_sent = pctx->p.cur_ts;
    cur_stream->last_active_ts = pctx->p.cur_ts;
  }

  cur_stream->snd_nxt = pctx->p.seq + pctx->p.payloadlen;

  if (tcph->rst)
  {
    cur_stream->have_reset = TRUE;
    cur_stream->state = TCP_ST_CLOSED_RSVD;
    cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
    return;
  }

  switch (cur_stream->state)
  {
    case TCP_ST_SYN_SENT:
/*
      if (tcph->ack && TCP_SEQ_GT(pctx->p.seq, cur_stream->sndvar->iss))
      {
        cur_stream->state = TCP_ST_ESTABLISHED;
        cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
        cur_stream->snd_nxt = pctx->p.seq;
        cur_stream->rcv_nxt = pctx->p.ack_seq;
        goto __handle_TCP_ST_ESTABLISHED;
      }
*/
      break;
    case TCP_ST_SYN_RCVD:
      if (!tcph->ack)
        break;

      MA_LOG("SYN Received");
      if (tcph->syn)
      {
        cur_stream->sndvar->iss = pctx->p.seq;
        cur_stream->snd_nxt = cur_stream->sndvar->iss + 1;
      }
/*
      else
      {
        cur_stream->state = TCP_ST_ESTABLISHED;
        cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
        cur_stream->snd_nxt = pctx->p.seq;
        cur_stream->rcv_nxt = pctx->p.ack_seq;
        goto __handle_TCP_ST_ESTABLISHED;
      }
*/
      break;
    case TCP_ST_ESTABLISHED:
/*
__handle_TCP_ST_ESTABLISHED:
      if (tcph->ack && TCP_SEQ_GT(ntohl(tcph->ack_seq), cur_stream->rcv_nxt))
      {
        cur_stream->rcv_nxt = ntohl(tcph->ack-seq);
      }
*/
      if (tcph->fin)
      {
        cur_stream->state = TCP_ST_FIN_WAIT_1;
        cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
        cur_stream->sndvar->fss = pctx->p.seq + pctx->p.payloadlen;
        cur_stream->sndvar->is_fin_sent = TRUE;
        cur_stream->snd_nxt++;
      }
      else
      {
      }
      break;
    case TCP_ST_CLOSE_WAIT:
/*
      if (tcph->ack && TCP_SEQ_GT(ntohl(tcph->ack_seq), cur_stream->rcv_nxt))
      {
        cur_stream->rcv_nxt = ntohl(tcph->ack_seq);
      }
*/
      if (tcph->fin)
      {
        cur_stream->sndvar->fss = pctx->p.seq + pctx->p.payloadlen;
        cur_stream->sndvar->is_fin_sent = TRUE;
        cur_stream->snd_nxt++;

        if ((tcph->ack) && (ntohl(tcph->ack_seq) == cur_stream->rcv_nxt))
          cur_stream->state = TCP_ST_LAST_ACK;
        else
          cur_stream->state = TCP_ST_CLOSING;

        cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
      }
      else if (tcph->ack)
      {
      }
      break;
    case TCP_ST_LAST_ACK:
      break;
    case TCP_ST_FIN_WAIT_1:
      break;
    case TCP_ST_FIN_WAIT_2:
      break;
    case TCP_ST_CLOSING:
      break;
    case TCP_ST_TIME_WAIT:
      if (tcph->ack)
      {
      }
      break;
    case TCP_ST_CLOSED:
    case TCP_ST_CLOSED_RSVD:
      break;
    default:
      MA_LOG("This should not happen");
      assert(0);
  }

  UNUSED(mssl);
  return;
}
