#include "include/timer.h"
#include "include/tcp_in.h"
#include "include/tcp_out.h"
#include "include/logs.h"
#include "include/memory_mgt.h"
#include "include/config.h"

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

struct rto_hashstore *init_rto_hashstore()
{
  int i;
  struct rto_hashstore *hs = calloc(1, sizeof(struct rto_hashstore));

  if (!hs)
  {
    MA_LOG("calloc: init_rto_hashstore");
    return 0;
  }

  for (i=0; i<RTO_HASH; i++)
    TAILQ_INIT(&hs->rto_list[i]);

  TAILQ_INIT(&hs->rto_list[RTO_HASH]);

  return hs;
}

inline void add_to_rto_list(mssl_manager_t mssl, tcp_stream *cur_stream)
{
  if (!mssl->rto_list_cnt)
  {
    mssl->rto_store->rto_now_idx = 0;
    mssl->rto_store->rto_now_ts = cur_stream->sndvar->ts_rto;
  }

  if (cur_stream->on_rto_idx < 0)
  {
    if (cur_stream->on_timewait_list)
    {
      MA_LOG1d("stream cannot be in both rto and timewait list", cur_stream->id);
      return;
    }

    int diff = (int32_t)(cur_stream->sndvar->ts_rto - mssl->rto_store->rto_now_ts);
    int offset = ((diff + mssl->rto_store->rto_now_idx) & (RTO_HASH - 1));
    cur_stream->on_rto_idx = offset;
    TAILQ_INSERT_TAIL(&(mssl->rto_store->rto_list[offset]),
        cur_stream, sndvar->timer_link);

    mssl->rto_list_cnt++;
  }
}

inline void remove_from_rto_list(mssl_manager_t mssl, tcp_stream *cur_stream)
{
  if (cur_stream->on_rto_idx < 0)
  {
    return;
  }

  TAILQ_REMOVE(&mssl->rto_store->rto_list[cur_stream->on_rto_idx],
      cur_stream, sndvar->timer_link);
  cur_stream->on_rto_idx = -1;

  mssl->rto_list_cnt--;
}

inline void add_to_timewait_list(mssl_manager_t mssl, tcp_stream *cur_stream, uint32_t cur_ts)
{
  cur_stream->rcvvar->ts_tw_expire = cur_ts + g_config.mos->tcp_tw_interval;

  if (cur_stream->on_timewait_list)
  {
    TAILQ_REMOVE(&mssl->timewait_list, cur_stream, sndvar->timer_link);
    TAILQ_INSERT_TAIL(&mssl->timewait_list, cur_stream, sndvar->timer_link);
  }
  else
  {
    if (cur_stream->on_rto_idx >= 0)
    {
      MA_LOG1d("stream cannot be in both timewait and rto list", cur_stream->id);
      remove_from_rto_list(mssl, cur_stream);
    }

    cur_stream->on_timewait_list = TRUE;
    TAILQ_INSERT_TAIL(&mssl->timewait_list, cur_stream, sndvar->timer_link);
    mssl->timewait_list_cnt++;
  }
}

inline void remove_from_timewait_list(mssl_manager_t mssl, tcp_stream *cur_stream)
{
  if (!cur_stream->on_timewait_list)
    return;

  TAILQ_REMOVE(&mssl->timewait_list, cur_stream, sndvar->timer_link);
  cur_stream->on_timewait_list = FALSE;
  mssl->timewait_list_cnt--;
}

inline void add_to_timeout_list(mssl_manager_t mssl, tcp_stream *cur_stream)
{
  if (cur_stream->on_timeout_list)
  {
    return;
  }

  cur_stream->on_timeout_list = TRUE;
  TAILQ_INSERT_TAIL(&mssl->timeout_list, cur_stream, sndvar->timeout_link);
  mssl->timeout_list_cnt++;
}

inline void remove_from_timeout_list(mssl_manager_t mssl, tcp_stream *cur_stream)
{
  if (cur_stream->on_timeout_list)
  {
    cur_stream->on_timeout_list = FALSE;
    TAILQ_REMOVE(&mssl->timeout_list, cur_stream, sndvar->timeout_link);
    mssl->timeout_list_cnt--;
  }
}

inline void update_timeout_list(mssl_manager_t mssl, tcp_stream *cur_stream)
{
  if (cur_stream->on_timeout_list)
  {
    TAILQ_REMOVE(&mssl->timeout_list, cur_stream, sndvar->timeout_link);
    TAILQ_INSERT_TAIL(&mssl->timeout_list, cur_stream, sndvar->timeout_link);
  }
}

inline void update_retransmission_timer(mssl_manager_t mssl, tcp_stream *cur_stream, uint32_t cur_ts)
{
  assert(cur_stream->sndvar->rto > 0);
  cur_stream->sndvar->nrtx = 0;

  if (cur_stream->on_rto_idx >= 0)
  {
    remove_from_rto_list(mssl, cur_stream);
  }

  if (TCP_SEQ_GT(cur_stream->snd_nxt, cur_stream->sndvar->snd_una))
  {
    cur_stream->sndvar->ts_rto = cur_ts + cur_stream->sndvar->rto;
    add_to_rto_list(mssl, cur_stream);
  }
  else
  {
    MA_LOG("all packets are ACKed");
  }
}

static inline int handle_rto(mssl_manager_t mssl, uint32_t cur_ts, tcp_stream *cur_stream)
{
  uint8_t backoff;

  if (cur_stream->sndvar->nrtx < TCP_MAX_RTX)
  {
    cur_stream->sndvar->nrtx++;
  }
  else
  {
    if (cur_stream->state < TCP_ST_ESTABLISHED)
    {
      cur_stream->state = TCP_ST_CLOSED_RSVD;
      cur_stream->close_reason = TCP_CONN_FAIL;
      cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
      destroy_tcp_stream(mssl, cur_stream);
    }
    else
    {
      cur_stream->state = TCP_ST_CLOSED_RSVD;
      cur_stream->close_reason = TCP_CONN_LOST;
      cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
      if (cur_stream->socket)
      {
        //raise_error_event(mssl, cur_stream);
      }
      else
      {
        destroy_tcp_stream(mssl, cur_stream);
      }
    }

    return 0;
  }

  if (cur_stream->sndvar->nrtx > cur_stream->sndvar->max_nrtx)
  {
    cur_stream->sndvar->max_nrtx = cur_stream->sndvar->nrtx;
  }

  if (cur_stream->state >= TCP_ST_ESTABLISHED)
  {
    uint32_t rto_prev;
    backoff = MIN(cur_stream->sndvar->nrtx, TCP_MAX_BACKOFF);

    rto_prev = cur_stream->sndvar->rto;
    cur_stream->sndvar->rto = 
      ((cur_stream->rcvvar->srtt >> 3) + cur_stream->rcvvar->rttvar) << backoff;

    if (cur_stream->sndvar->rto <= 0)
    {
      cur_stream->sndvar->rto = rto_prev;
    }
  }
  else if (cur_stream->state >= TCP_ST_SYN_SENT)
  {
    if (cur_stream->sndvar->nrtx < TCP_MAX_BACKOFF)
    {
      cur_stream->sndvar->rto <<= 1;
    }
  }

  cur_stream->sndvar->ssthresh = MIN(cur_stream->sndvar->cwnd, cur_stream->sndvar->peer_wnd) / 2;
  if (cur_stream->sndvar->ssthresh < (2 * cur_stream->sndvar->mss))
  {
    cur_stream->sndvar->ssthresh = cur_stream->sndvar->mss * 2;
  }

  cur_stream->sndvar->cwnd = cur_stream->sndvar->mss;

  if (cur_stream->on_rto_idx >= 0)
    remove_from_rto_list(mssl, cur_stream);

  if (cur_stream->state == TCP_ST_SYN_SENT)
  {
    if (cur_stream->sndvar->nrtx > TCP_MAX_SYN_RETRY)
    {
      cur_stream->state = TCP_ST_CLOSED_RSVD;
      cur_stream->close_reason = TCP_CONN_FAIL;
      cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;

      if (cur_stream->socket)
      {
        // raise_error_event(mssl, cur_stream);
      }
      else
      {
        destroy_tcp_stream(mssl, cur_stream);
      }

      return 0;
    }
  }
  else if (cur_stream->state == TCP_ST_SYN_RCVD)
  {
    MA_LOG1d("SYN/ACK retransmission", cur_stream->snd_nxt);
  }
  else if (cur_stream->state == TCP_ST_ESTABLISHED)
  {
    MA_LOG1d("data retransmission", cur_stream->snd_nxt);
  }
  else if (cur_stream->state == TCP_CLOSE_WAIT)
  {
    MA_LOG1d("data retransmission", cur_stream->snd_nxt);
  }
  else if (cur_stream->state == TCP_ST_LAST_ACK)
  {
    MA_LOG1d("FIN/ACK retransmission", cur_stream->snd_nxt);
  }
  else if (cur_stream->state == TCP_ST_FIN_WAIT_1)
  {
    MA_LOG1d("FIN retransmission", cur_stream->snd_nxt);
  }
  else if (cur_stream->state == TCP_ST_CLOSING)
  {
    MA_LOG1d("ACK retransmission", cur_stream->snd_nxt);
  }
  else if (cur_stream->state == TCP_ST_FIN_WAIT_2)
  {
    MA_LOG1d("ACK retransmission", cur_stream->snd_nxt);
  }
  else
  {
    MA_LOG("wierd state");
    assert(0);
    return 0;
  }
  
  cur_stream->snd_nxt = cur_stream->sndvar->snd_una;

  if (cur_stream->state == TCP_ST_ESTABLISHED ||
      cur_stream->state == TCP_ST_CLOSE_WAIT)
  {
    add_to_send_list(mssl, cur_stream);
  }
  else if (cur_stream->state == TCP_ST_FIN_WAIT_1 ||
      cur_stream->state == TCP_ST_CLOSING ||
      cur_stream->state == TCP_ST_LAST_ACK)
  {
    if (cur_stream->sndvar->fss == 0)
    {
      MA_LOG1d("fss is not set", cur_stream->id);
    }

    if (TCP_SEQ_LT(cur_stream->snd_nxt, cur_stream->sndvar->fss))
    {
      if (cur_stream->sndvar->on_control_list)
      {
        remove_from_control_list(mssl, cur_stream);
      }
      cur_stream->control_list_waiting = TRUE;
      add_to_send_list(mssl, cur_stream);
    }
    else
    {
      add_to_control_list(mssl, cur_stream, cur_ts);
    }
  }
  else
  {
    add_to_control_list(mssl, cur_stream, cur_ts);
  }

  return 1;
}

static inline void rearrange_rto_store(mssl_manager_t mssl)
{
  tcp_stream *walk, *next;
  struct rto_head *rto_list = &mssl->rto_store->rto_list[RTO_HASH];
  int cnt = 0;

  for (walk = TAILQ_FIRST(rto_list); walk != NULL; walk = next)
  {
    next = TAILQ_NEXT(walk, sndvar->timer_link);

    int diff = (int32_t)(mssl->rto_store->rto_now_ts - walk->sndvar->ts_rto);

    if (diff < RTO_HASH)
    {
      int offset = ((diff + mssl->rto_store->rto_now_idx) & (RTO_HASH - 1));

      if (!TAILQ_EMPTY(&mssl->rto_store->rto_list[RTO_HASH]))
      {
        TAILQ_REMOVE(&mssl->rto_store->rto_list[RTO_HASH], walk, sndvar->timer_link);
        walk->on_rto_idx = offset;
        TAILQ_INSERT_TAIL(&(mssl->rto_store->rto_list[offset]), walk, sndvar->timer_link);
      }
    }
    cnt++;
  }
}

void check_rtm_timeout(mssl_manager_t mssl, uint32_t cur_ts, int thresh)
{
  tcp_stream *walk, *next;
  struct rto_head *rto_list;
  int cnt;

  if (!mssl->rto_list_cnt)
  {
    return;
  }

  cnt = 0;

  while (1)
  {
    rto_list = &mssl->rto_store->rto_list[mssl->rto_store->rto_now_idx];
    if ((int32_t)(cur_ts - mssl->rto_store->rto_now_ts) < 0)
    {
      break;
    }

    for (walk = TAILQ_FIRST(rto_list); walk != NULL; walk = next)
    {
      if (++cnt > thresh)
      {
        break;
      }
      next = TAILQ_NEXT(walk, sndvar->timer_link);

      if (walk->on_rto_idx >= 0)
      {
        TAILQ_REMOVE(rto_list, walk, sndvar->timer_link);
        mssl->rto_list_cnt--;
        walk->on_rto_idx = -1;
        handle_rto(mssl, cur_ts, walk);
      }
      else
      {
      }
    }

    if (cnt > thresh)
    {
      break;
    }
    else
    {
      mssl->rto_store->rto_now_idx = ((mssl->rto_store->rto_now_idx + 1) & (RTO_HASH - 1));
      mssl->rto_store->rto_now_ts++;

      if (!((mssl->rto_store->rto_now_idx & (1024 - 1))))
      {
        rearrange_rto_store(mssl);
      }
    }
  }
  MA_LOG1d("checking retransmission timeout", cnt);
}

void check_timewait_expire(mssl_manager_t mssl, uint32_t cur_ts, int thresh)
{
  tcp_stream *walk, *next;
  int cnt;

  cnt = 0;

  for (walk = TAILQ_FIRST(&mssl->timewait_list); walk != NULL; walk = next)
  {
    if (++cnt > thresh)
      break;
    next = TAILQ_NEXT(walk, sndvar->timer_link);

    if (walk->on_timewait_list)
    {
      if ((walk->pair_stream != NULL)
          && (walk->pair_stream->state != TCP_ST_CLOSED_RSVD)
          && (walk->pair_stream->state != TCP_ST_TIME_WAIT))
        continue;

      if ((int32_t)(cur_ts - walk->rcvvar->ts_tw_expire) >= 0)
      {
        if (!walk->sndvar->on_control_list)
        {
          TAILQ_REMOVE(&mssl->timewait_list, walk, sndvar->timer_link);
          walk->on_timewait_list = FALSE;
          mssl->timewait_list_cnt--;

          walk->state = TCP_ST_CLOSED_RSVD;
          walk->close_reason = TCP_ACTIVE_CLOSE;
          walk->cb_events |= MOS_ON_TCP_STATE_CHANGE;
          destroy_tcp_stream(mssl, walk);
        }
      }
      else
      {
        break;
      }
    }
    else
    {
      MA_LOG1d("stream is not on timewait list", walk->id);
    }
  }

  //MA_LOG1d("checking timewait timeout", cnt);
}

void check_connection_timeout(mssl_manager_t mssl, uint32_t cur_ts, int thresh)
{
  tcp_stream *walk, *next;
  int cnt;

  cnt = 0;

  for (walk = TAILQ_FIRST(&mssl->timeout_list); walk != NULL; walk = next)
  {
    if (++cnt > thresh)
      break;
    next = TAILQ_NEXT(walk, sndvar->timeout_link);

    if ((int32_t)(cur_ts - walk->last_active_ts) >= g_config.mos->tcp_timeout)
    {
      walk->on_timeout_list = FALSE;
      TAILQ_REMOVE(&mssl->timeout_list, walk, sndvar->timeout_link);
      mssl->timeout_list_cnt--;
      walk->state = TCP_ST_CLOSED_RSVD;
      walk->close_reason = TCP_TIMEDOUT;
      walk->cb_events |= MOS_ON_TCP_STATE_CHANGE;

      if (walk->socket && HAS_STREAM_TYPE(walk, MOS_SOCK_STREAM))
      {
        //raise_error_event(mssl, walk);
      }
      else
      {
        destroy_tcp_stream(mssl, walk);
      }
    }
    else
    {
      break;
    }
  }
}

static int reg_timer(mssl_manager_t mssl, struct timer *timer)
{
  struct timer *walk;

  TAILQ_FOREACH_REVERSE(walk, &mssl->timer_list, timer_head, timer_link)
  {
    if (TIMEVAL_LT(&walk->exp, &timer->exp))
    {
      TAILQ_INSERT_AFTER(&mssl->timer_list, walk, timer, timer_link);
      return 0;
    }
  }

  assert(!walk);

  TAILQ_INSERT_HEAD(&mssl->timer_list, timer, timer_link);
  return 0;
}

static struct timer *new_timer(mssl_manager_t mssl, int id, struct timeval *timeout, callback_t cb)
{
#ifdef USE_TIMER_POOL
  struct timer *t = mp_allocate_chunk(mssl->timer_pool);
#else
  struct timer *t = calloc(1, sizeof(struct timer));
#endif
  if (!t)
    return NULL;

  t->id = id;
  t->cb = cb;
  gettimeofday(&t->exp, NULL);
  TIMEVAL_ADD(&t->exp, timeout);

  return t;
}

void del_timer(mssl_manager_t mssl, struct timer *timer)
{
  TAILQ_REMOVE(&mssl->timer_list, timer, timer_link);
#ifdef USE_TIMER_POOL
  mp_free_chunk(mssl->timer_pool, timer);
#else
  free(timer);
#endif
}

int mssl_settimer(mctx_t mctx, int id, struct timeval *timeout, callback_t cb)
{
  mssl_manager_t mssl = get_mssl_manager(mctx);
  if (!mssl || !timeout || !cb)
    return -1;

  struct timer *t = new_timer(mssl, id, timeout, cb);
  if (!t)
    return -1;

  reg_timer(mssl, t);

  return 0;
}

