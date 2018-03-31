#ifndef __MSSL_H__
#define __MSSL_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <pthread.h>

#include "tcp_stream_queue.h"
#include "mssl_api.h"

#ifndef TRUE
#define TRUE (1)
#endif /* TRUE */

#ifndef FALSE
#define FALSE (0)
#endif /* FALSE */

#ifndef ERROR
#define ERROR (-1)
#endif /* ERROR */

#ifndef MAX_CPUS
#define MAX_CPUS 16
#endif /* MAX_CPUS */

#define ETH_NUM 16

struct timer;

struct route_table
{
  uint32_t daddr;
  uint32_t mask;
  uint32_t masked;
  int prefix;
  int nif;
};
/*
struct mssl_sender
{
  int ifidx;

  TAILQ_HEAD(control_head, tcp_stream) control_list;
  TAILQ_HEAD(send_head, tcp_stream) send_list;
  TAILQ_HEAD(ack_head, tcp_stream) ack_list;

  int control_list_cnt;
  int send_list_cnt;
  int ack_list_cnt;
};
*/
struct mssl_manager
{
/*
  mem_pool_t bufseg_pool;
  mem_pool_t sockent_pool;
#ifdef USE_TIMER_POOL
  mem_pool_t timer_pool;
#endif
  mem_pool_t evt_pool;
  mem_pool_t flow_pool;
  mem_pool_t rv_pool;
  mem_pool_t sv_pool;
  mem_pool_t mv_pool;

  kvs_t *ev_store;
  sb_manager_t rbm_snd;
*/
  struct hashtable *tls_flow_table;
  uint32_t s_index;
/*
  socket_map_t smap;
  socket_map_t msmap;
  TAILQ_HEAD (, socket_map) free_smap;
  TAILQ_HEAD (, socket_map) free_msmap;
  addr_pool_t ap;
*/

  uint32_t g_id;
  uint32_t flow_cnt;

  struct mssl_thread_context *ctx;

  // TODO: log related variables
  // TODO: event related variables

  struct tcp_listener *listener;
  TAILQ_HEAD(, mon_listener) monitors;
  uint32_t num_msp;
  uint32_t num_esp;
  struct pkt_ctx *pctx;

  stream_queue_t connectq;
  stream_queue_t sendq;
  stream_queue_t ackq;

  stream_queue_t closeq;
  stream_queue_int *closeq_int;
  stream_queue_t resetq;
  stream_queue_int *resetq_int;

  stream_queue_t destroyq;

  struct mssl_sender *g_sender;
  struct mssl_sender *n_sender[ETH_NUM];

/*
  struct rto_hashstore *rto_store;
  TAILQ_HEAD (timewait_head, tcp_stream) timewait_list;
  TAILQ_HEAD (timeout_head, tcp_stream) timeout_list;
  TAILQ_HEAD (timer_head, timer) timer_list;

  int rto_list_cnt;
  int timewait_list_cnt;
  int timeout_list_cnt;

  uint32_t cur_ts;

  int wakeup_flag;
  int is_sleeping;

  struct bcast_stat bstat;
  struct timeout_stat tstat;
#ifdef NETSTAT
  struct net_stat nstat;
  struct net_stat p_nstat;
  uint32_t p_nstat_ts;

  struct run_stat runstat;
  struct run_stat p_runstat;

  struct time_stat rtstat;
#endif
*/

  struct io_module_func *iom;

};
#ifndef __MSSL_MANAGER__
#define __MSSL_MANAGER__
  typedef struct mssl_manager *mssl_manager_t;
#endif

mssl_manager_t get_mssl_manager(mctx_t mctx);

struct mssl_thread_context
{
  int cpu;
  pthread_t thread;
  uint8_t done:1,
          exit:1,
          interrupt:1;

  struct mssl_manager *mssl_manager;

  void *io_private_context;

  pthread_mutex_t flow_pool_lock;
  pthread_mutex_t socket_pool_lock;

#if LOCK_STREAM_QUEUE
#if USE_SPIN_LOCK
  pthread_spinlock_t connect_lock;
  pthread_spinlock_t close_lock;
  pthread_spinlock_t reset_lock;
  pthread_spinlock_t sendq_lock;
  pthread_spinlock_t ackq_lock;
  pthread_spinlock_t destroyq_lock;
#else
  pthread_mutex_t connect_lock;
  pthread_mutex_t close_lock;
  pthread_mutex_t reset_lock;
  pthread_mutex_t sendq_lock;
  pthread_mutex_t ackq_lock;
  pthread_mutex_t destroyq_lock;
#endif /* USE_SPIN_LOCK */
#endif /* LOCK_STREAM_QUEUE */
};

typedef struct mssl_thread_context *mssl_thread_context_t;

struct mssl_manager *g_mssl[MAX_CPUS];
struct mssl_context *g_ctx[MAX_CPUS];

#endif /* __MSSL_H__ */
