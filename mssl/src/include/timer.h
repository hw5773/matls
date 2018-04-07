#ifndef __TIMER_H__
#define __TIMER_H__

#include "mssl.h"
#include "tcp_stream.h"
#include <sys/time.h>

#define RTO_HASH 2048

#define TIMEVAL_ADD(a, b) \
  do { (a)->tv_sec += (b)->tv_sec; \
    if (((a)->tv_usec += (b)->tv_usec) > 1000000) { \
      (a)->tv_sec++; (a)->tv_usec -= 1000000; } \
  } while (0)

#define TIMEVAL_LT(a, b) \
  timercmp(a, b, <)

struct timer 
{
  int id;
  struct timeval exp;
  callback_t cb;

  TAILQ_ENTRY(timer) timer_link;
};

struct rto_hashstore
{
  uint32_t rto_now_idx;
  uint32_t rto_now_ts;

  TAILQ_HEAD(rto_head, tcp_stream) rto_list[RTO_HASH + 1];
};

struct rto_hashstore *init_rto_hashstore();
extern inline void add_to_rto_list(mssl_manager_t mssl, tcp_stream *cur_stream);
extern inline void remove_from_rto_list(mssl_manager_t mssl, tcp_stream *cur_stream);
extern inline void add_to_timewait_list(mssl_manager_t mssl, tcp_stream *cur_stream, uint32_t cur_ts);
extern inline void remove_from_timewait_list(mssl_manager_t mssl, tcp_stream *cur_stream);
extern inline void add_to_timeout_list(mssl_manager_t mssl, tcp_stream *cur_stream);
extern inline void remove_from_timeout_list(mssl_manager_t mssl, tcp_stream *cur_stream);
extern inline void update_timeout_list(mssl_manager_t mssl, tcp_stream *cur_stream);
extern inline void update_retransmission_timer(mssl_manager_t mssl, tcp_stream *cur_stream, uint32_t cur_ts);

void check_rtm_timeout(mssl_manager_t mssl, uint32_t cur_ts, int thresh);
void check_timewait_expire(mssl_manager_t mssl, uint32_t cur_ts, int thresh);
void check_connection_timeout(mssl_manager_t mssl, uint32_t cur_ts, int thresh);
void del_timer(mssl_manager_t mssl, struct timer *timer);

#endif /* __TIMER_H__ */
