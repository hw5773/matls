#define _GNU_SOURCE
#include <unistd.h>
#include <assert.h>
#include <semaphore.h>
#include <time.h>
#include <signal.h>
#include <sys/mman.h>

#include "include/logs.h"

#include "include/cpu.h"
#include "include/eth_in.h"
#include "include/fhash.h"
#include "include/tcp_send_buffer.h"
#include "include/tcp_ring_buffer.h"
#include "include/socket.h"
#include "include/eth_out.h"
#include "include/tcp.h"
#include "include/tcp_in.h"
#include "include/tcp_out.h"
#include "include/mssl_api.h"
#include "include/eventpoll.h"
#include "include/logs.h"
#include "include/config.h"
#include "include/arp.h"
#include "include/ip_out.h"
#include "include/timer.h"
#include "include/event_callback.h"
#include "include/tcp_rb.h"
#include "include/tcp_stream.h"
#include "include/io_module.h"
#include "include/tls_split.h"

#define LOG_FILE_NAME "log"
#define MAX_FILE_NAME 1024

struct mssl_thread_context *g_pctx[MAX_CPUS] = {0};
static pthread_t g_thread[MAX_CPUS] = {0};

static sem_t g_init_sem[MAX_CPUS];
static sem_t g_done_sem[MAX_CPUS];

static int running[MAX_CPUS] = {0};
static int sigint_cnt[MAX_CPUS] = {0};

static inline void flush_monitor_read_events(mssl_manager_t mssl)
{
	struct event_queue *msslq;
	struct tcp_stream *cur_stream;
	struct mon_listener *walk;
	
	/* check if monitor sockets should be passed data */
	TAILQ_FOREACH(walk, &mssl->monitors, link) {
		if (walk->socket->socktype != MOS_SOCK_MONITOR_STREAM ||
			!(msslq = walk->eq))
			continue;

		while (msslq->num_events > 0) {
			cur_stream =
				(struct tcp_stream *)msslq->events[msslq->start++].ev.data.ptr;
			/* only read events */
			if (cur_stream != NULL &&
			    (cur_stream->actions & MOS_ACT_READ_DATA)) {
				if (cur_stream->rcvvar != NULL &&
						cur_stream->rcvvar->rcvbuf != NULL) {
					/* no need to pass pkt context */
					struct socket_map *walk;
					if (cur_stream->side == MOS_SIDE_CLI) {
            /*
						SOCKQ_FOREACH_REVERSE(walk, &cur_stream->msocks) {
							HandleCallback(mssl, MOS_NULL, walk,
								       cur_stream->side, NULL, 
								       MOS_ON_CONN_NEW_DATA);
						} SOCKQ_FOREACH_END;
            */
					} else { /* cur_stream->side == MOS_SIDE_SVR */
            /*
						SOCKQ_FOREACH_START(walk, &cur_stream->msocks) {
							HandleCallback(mssl, MOS_NULL, walk,
								       cur_stream->side, NULL, 
								       MOS_ON_CONN_NEW_DATA);
						} SOCKQ_FOREACH_END;
            */
					}
				}
				/* reset the actions now */
				cur_stream->actions = 0;
			}
			if (msslq->start >= msslq->size)
				msslq->start = 0;
			msslq->num_events--;
		}
	}
}
/*----------------------------------------------------------------------------*/
static inline void flush_buffered_read_events(mssl_manager_t mssl)
{
	int i;
	int offset;
	struct event_queue *msslq;
	struct tcp_stream *cur_stream;

	if (mssl->ep == NULL) {
		return;
	} else {
		/* case when msslq exists */
		msslq = mssl->ep->mssl_queue;	
		offset = msslq->start;
	}

	/* we will use queued-up epoll read-in events
	 * to trigger buffered read monitor events */
	for (i = 0; i < msslq->num_events; i++) {
		cur_stream = mssl->smap[msslq->events[offset++].sockid].stream;
		/* only read events */
		/* Raise new data callback event */
		if (cur_stream != NULL &&
		    	(cur_stream->socket->events | MOS_EPOLLIN)) {
			if (cur_stream->rcvvar != NULL &&
					cur_stream->rcvvar->rcvbuf != NULL) {
				/* no need to pass pkt context */
				struct socket_map *walk;
				if (cur_stream->side == MOS_SIDE_CLI) {
          /*
					SOCKQ_FOREACH_REVERSE(walk, &cur_stream->msocks) {
						HandleCallback(mssl, MOS_NULL, walk, cur_stream->side,
							       NULL, MOS_ON_CONN_NEW_DATA);
					} SOCKQ_FOREACH_END;
          */
				} else { /* cur_stream->side == MOS_SIDE_SVR */
          /*
					SOCKQ_FOREACH_START(walk, &cur_stream->msocks) {
						HandleCallback(mssl, MOS_NULL, walk, cur_stream->side,
							       NULL, MOS_ON_CONN_NEW_DATA);
					} SOCKQ_FOREACH_END;
          */
				}
			}
		}
		if (offset >= msslq->size)
			offset = 0;
	}
}
/*----------------------------------------------------------------------------*/
static inline void 
flush_epoll_events(mssl_manager_t mssl, uint32_t cur_ts)
{
	struct mssl_epoll *ep = mssl->ep;
	struct event_queue *usrq = ep->usr_queue;
	struct event_queue *msslq = ep->mssl_queue;

	pthread_mutex_lock(&ep->epoll_lock);
	if (ep->mssl_queue->num_events > 0) {
		/* while mssl_queue have events */
		/* and usr_queue is not full */
		while (msslq->num_events > 0 && usrq->num_events < usrq->size) {
			/* copy the event from mssl_queue to usr_queue */
			usrq->events[usrq->end++] = msslq->events[msslq->start++];

			if (usrq->end >= usrq->size)
				usrq->end = 0;
			usrq->num_events++;

			if (msslq->start >= msslq->size)
				msslq->start = 0;
			msslq->num_events--;
		}
	}

	/* if there are pending events, wake up user */
	if (ep->waiting && (ep->usr_queue->num_events > 0 || 
				ep->usr_shadow_queue->num_events > 0)) {
		mssl->ts_last_event = cur_ts;
		ep->stat.wakes++;
		pthread_cond_signal(&ep->epoll_cond);
	}
	pthread_mutex_unlock(&ep->epoll_lock);
}

int mssl_init(const char *config_file)
{
  int i, ret;

  if (geteuid())
  {
    MA_LOG("Run the app as root!");
    exit(EXIT_FAILURE);
  }

  num_cpus = get_num_cpus();
  MA_LOG1d("num_cpus", num_cpus);
  assert(num_cpus >= 1);

  for (i=0; i<num_cpus; i++)
  {
    g_mssl[i] = NULL;
    running[i] = FALSE;
    sigint_cnt[i] = 0;
  }

  ret = load_configuration_upper_half(config_file);
  MA_LOG("After configuration upper half");
  if (ret)
  {
    MA_LOG("Error occured while loading configuration");
    return -1;
  }

  current_iomodule_func = &sock_module_func;

  MA_LOG("load sock module");
  if (current_iomodule_func->load_module_upper_half)
  {
    MA_LOG("before enter load module upper half");
    current_iomodule_func->load_module_upper_half();
  }
  
  // TODO: address pool
  // TODO: initialize arp table
  // TODO: signal handler
  
  MA_LOG("Load module lower half");
  if (current_iomodule_func->load_module_lower_half)
    current_iomodule_func->load_module_lower_half();

  load_configuration_lower_half();

  // CreateAddressPool

  print_arp_table();
  init_arp_table();

  return 0;
}

static int attach_device(struct mssl_thread_context *ctx)
{
  int working = -1;
  mssl_manager_t mssl = ctx->mssl_manager;

  if (mssl->iom->link_devices)
    working = mssl->iom->link_devices(ctx);
  else
    return 0;

  return working;
}

static inline void write_packets_to_chunks(mssl_manager_t mssl, uint32_t cur_ts)
{
  int thresh = g_config.mos->max_concurrency;
  int i;

  assert(mssl->g_sender != NULL);
  if (mssl->g_sender->control_list_cnt)
    write_tcp_control_list(mssl, mssl->g_sender, cur_ts, thresh);
  if (mssl->g_sender->ack_list_cnt)
    write_tcp_ack_list(mssl, mssl->g_sender, cur_ts, thresh);
  if (mssl->g_sender->send_list_cnt)
    write_tcp_data_list(mssl, mssl->g_sender, cur_ts, thresh);

  for (i=0; i<g_config.mos->netdev_table->num; i++)
  {
    assert(mssl->n_sender[i] != NULL);
    if (mssl->n_sender[i]->control_list_cnt)
      write_tcp_control_list(mssl, mssl->n_sender[i], cur_ts, thresh);
    if (mssl->n_sender[i]->ack_list_cnt)
      write_tcp_ack_list(mssl, mssl->n_sender[i], cur_ts, thresh);
    if (mssl->n_sender[i]->send_list_cnt)
      write_tcp_data_list(mssl, mssl->n_sender[i], cur_ts, thresh);
  }
}

static int destroy_remaining_flows(mssl_manager_t mssl)
{
  struct hashtable *ht = mssl->tcp_flow_table;
  tcp_stream *walk;
  int cnt, i;

  cnt = 0;

  for (i=0; i<NUM_BINS; i++)
  {
    TAILQ_FOREACH(walk, &ht->ht_table[i], rcvvar->he_link)
    {
      destroy_tcp_stream(mssl, walk);
      cnt++;
    }
  }

  return cnt;
}

static void interrupt_application(mssl_manager_t mssl)
{
  if (mssl->ep)
  {
    pthread_mutex_lock(&mssl->ep->epoll_lock);
    if (mssl->ep->waiting)
    {
      pthread_cond_signal(&mssl->ep->epoll_cond);
    }
    pthread_mutex_unlock(&mssl->ep->epoll_lock);
  }

  if (mssl->listener)
  {
    if (mssl->listener->socket)
    {
      pthread_mutex_lock(&mssl->listener->accept_lock);
      if (!(mssl->listener->socket->opts & MSSL_NONBLOCK))
      {
        pthread_cond_signal(&mssl->listener->accept_cond);
      }
      pthread_mutex_unlock(&mssl->listener->accept_lock);
    }
  }
}

void run_passive_loop(mssl_manager_t mssl)
{
  sem_wait(&g_done_sem[mssl->ctx->cpu]);
  sem_destroy(&g_done_sem[mssl->ctx->cpu]);
  return;
}

static void run_main_loop(struct mssl_thread_context *ctx)
{
  mssl_manager_t mssl = ctx->mssl_manager;
  int i, recv_cnt, rx_inf, tx_inf;
  struct timeval cur_ts = {0};
  uint32_t ts, ts_prev;

/*
#if TIME_STAT
  struct timeval prev_ts, processing_ts, tcheck_ts,
                 epoll_ts, handle_ts, xmit_ts, select_ts;
#endif
*/
  int thresh;

  gettimeofday(&cur_ts, NULL);

  MA_LOG1d("mssl thread running", ctx->cpu);
  MA_LOG1d("number of interfaces", g_config.mos->netdev_table->num);

  ts = ts_prev = 0;

  while ((!ctx->done || mssl->flow_cnt) && !ctx->exit)
  {
    // STAT_COUNT(mssl->runstat.rounds);
    recv_cnt = 0;
    gettimeofday(&cur_ts, NULL);
    // update_stat_counter();
    //prev_ts = cur_ts;

    ts = TIMEVAL_TO_TS(&cur_ts);
    mssl->cur_ts = ts;

    for (rx_inf = 0; rx_inf < g_config.mos->netdev_table->num; rx_inf++)
    {
      recv_cnt = mssl->iom->recv_pkts(ctx, rx_inf);

      // STAT_COUNT(mssl->runstat.rounds_rx_try);
      
      for (i=0; i<recv_cnt; i++)
      {
        uint16_t len;
        uint8_t *pktbuf;
        pktbuf = mssl->iom->get_rptr(ctx, rx_inf, i, &len);
        if (pktbuf)
          process_packet(mssl, rx_inf, i, ts, pktbuf, len);
      }
    }
  
    // user defined timeout control

    if (mssl->flow_cnt > 0)
    {
      thresh = g_config.mos->max_concurrency;

      if (thresh == -1)
        thresh = g_config.mos->max_concurrency;

      check_rtm_timeout(mssl, ts, thresh);
      check_timewait_expire(mssl, ts, thresh);

      if (g_config.mos->tcp_timeout > 0 && ts != ts_prev)
      {
        check_connection_timeout(mssl, ts, thresh);
      }
    }

    if (mssl->num_msp > 0)
      flush_monitor_read_events(mssl);


    if (mssl->ep)
    {
      flush_buffered_read_events(mssl);
      flush_epoll_events(mssl, ts);
    }

    write_packets_to_chunks(mssl, ts);

    int num_dev = g_config.mos->netdev_table->num;
    if (likely(mssl->iom->send_pkts != NULL))
    {
      for (tx_inf = 0; tx_inf < num_dev; tx_inf++)
      {
        mssl->iom->send_pkts(ctx, tx_inf);
      }
    }

    if (ts != ts_prev)
    {
      ts_prev = ts;
      arp_timer(mssl, ts);
    }

    if (mssl->iom->select)
    {
      mssl->iom->select(ctx);
    }

    if (ctx->interrupt)
    {
      interrupt_application(mssl);
    }
  }

  destroy_remaining_flows(mssl);
  interrupt_application(mssl);
}

struct mssl_sender *create_mssl_sender(int ifidx)
{
  struct mssl_sender *sender;

  sender = (struct mssl_sender *)calloc(1, sizeof(struct mssl_sender));
  if (!sender)
    return NULL;

  sender->ifidx = ifidx;

  TAILQ_INIT(&sender->control_list);
  TAILQ_INIT(&sender->send_list);
  TAILQ_INIT(&sender->ack_list);

  sender->control_list_cnt = 0;
  sender->send_list_cnt = 0;
  sender->ack_list_cnt = 0;

  return sender;
}

void destroy_mssl_sender(struct mssl_sender *sender)
{
  free(sender);
}

static mssl_manager_t initialize_mssl_manager(struct mssl_thread_context *ctx)
{
  MA_LOG("initialize mssl manager");
  int i;
  mssl_manager_t mssl;
  char log_name[MAX_FILE_NAME];

  posix_seq_srand((unsigned) pthread_self());
  
  mssl = (mssl_manager_t)calloc(1, sizeof(struct mssl_manager));

  if (!mssl)
  {
    perror("malloc");
    MA_LOG("Failed to allocate mssl_manager");
    return NULL;
  }

  g_mssl[ctx->cpu] = mssl;
  create_hashtable(&mssl->tcp_flow_table);

  if (!mssl->tcp_flow_table)
  {
    MA_LOG("Failed to allocate tcp flow table");
    return NULL;
  }
/*
#ifdef HUGEPAGE
#define IS_HUGEPAGE 1
#else
*/
#define IS_HUGEPAGE 0
//#endif 


  if (mon_app_exists)
  {
/*
#ifdef NEWEV
    init_event(mssl);
#else
    init_event(mssl, NUM_EV_TABLE);
#endif
*/
  }

  if (!(mssl->bufseg_pool = mp_create(sizeof(tcpbufseg_t),
          sizeof(tcpbufseg_t) * g_config.mos->max_concurrency *
          ((g_config.mos->rmem_size - 1) / UNITBUFSIZE + 1), 0)))
  {
    MA_LOG("Failed to allocate buf_seg pool");
    exit(0);
  }

  if (!(mssl->sockent_pool = mp_create(sizeof(struct sockent),
          sizeof(struct sockent) * g_config.mos->max_concurrency * 3, 0)))
  {
    MA_LOG("Failed to allocate sockent_pool");
    exit(0);
  }

#ifdef USE_TIMER_POOL
  if (!(mssl->timer_pool = mp_create(sizeof(struct timer),
          sizeof(struct timer) * g_config.mos->max_concurrency * 10, 0)))
  {
    MA_LOG("Failed to allocate timer pool");
    exit(0);
  }
#endif

  mssl->flow_pool = mp_create(sizeof(tcp_stream), 
      sizeof(tcp_stream) * g_config.mos->max_concurrency, IS_HUGEPAGE);

  if (!mssl->flow_pool)
  {
    MA_LOG("Failed to allocate tcp flow pool");
    return NULL;
  }

  mssl->rv_pool = mp_create(sizeof(struct tcp_recv_vars),
      sizeof(struct tcp_recv_vars) * g_config.mos->max_concurrency, IS_HUGEPAGE);

  if (!mssl->rv_pool)
  {
    MA_LOG("Failed to allocate tcp recv variable pool");
    return NULL;
  }

  mssl->sv_pool = mp_create(sizeof(struct tcp_send_vars),
      sizeof(struct tcp_send_vars) * g_config.mos->max_concurrency, IS_HUGEPAGE);

  if (!mssl->sv_pool)
  {
    MA_LOG("Failed to allocate tcp send variable pool");
    return NULL;
  }

  mssl->rbm_snd = sb_manager_create(g_config.mos->wmem_size, g_config.mos->no_ring_buffers,
      g_config.mos->max_concurrency);
  
  if (!mssl->rbm_snd)
  {
    MA_LOG("Failed to create send ring buffer");
    return NULL;
  }

  mssl->smap = (socket_map_t)calloc(g_config.mos->max_concurrency, sizeof(struct socket_map));
  if (!mssl->smap)
  {
    perror("calloc");
    MA_LOG("Failed to allocate memory for stream map");
    return NULL;
  }

  if (mon_app_exists)
  {
    mssl->msmap = (socket_map_t)calloc(g_config.mos->max_concurrency, sizeof(struct socket_map));
    if (!mssl->msmap)
    {
      perror("calloc");
      MA_LOG("Failed to allocate memory for monitor stream map");
      return NULL;
    }

    for (i=0; i<g_config.mos->max_concurrency; i++)
    {
      mssl->msmap[i].monitor_stream = calloc(1, sizeof(struct mon_stream));
      if (!mssl->msmap[i].monitor_stream)
      {
        perror("calloc");
        MA_LOG("Failed to allocate memory for monitor stream map");
        return NULL;
      }
    }
  }

  TAILQ_INIT(&mssl->timer_list);
  TAILQ_INIT(&mssl->monitors);
  TAILQ_INIT(&mssl->free_smap);

  MA_LOG1d("max_concurrency", g_config.mos->max_concurrency);

  for (i=0; i<g_config.mos->max_concurrency; i++)
  {
    mssl->smap[i].id = i;
    mssl->smap[i].socktype = MOS_SOCK_UNUSED;
    memset(&mssl->smap[i].saddr, 0, sizeof(struct sockaddr_in));
    mssl->smap[i].stream = NULL;
    TAILQ_INSERT_TAIL(&mssl->free_smap, &mssl->smap[i], link);
  }

  mssl->ctx = ctx;
  mssl->ep = NULL;

// Queue related commands
  mssl->connectq = create_stream_queue(BACKLOG_SIZE);
  if (!mssl->connectq)
  {
    MA_LOG("Failed to create connect queue");
    return NULL;
  }

  mssl->sendq = create_stream_queue(g_config.mos->max_concurrency);
  if (!mssl->sendq)
  {
    MA_LOG("Failed to create send queue");
    return NULL;
  }

  mssl->ackq = create_stream_queue(g_config.mos->max_concurrency);
  if (!mssl->ackq)
  {
    MA_LOG("Failed to create ack queue");
    return NULL;
  }

  mssl->closeq = create_stream_queue(g_config.mos->max_concurrency);
  if (!mssl->closeq)
  {
    MA_LOG("Failed to create close queue");
    return NULL;
  }

  mssl->closeq_int = create_internal_stream_queue(g_config.mos->max_concurrency);
  if (!mssl->closeq_int)
  {
    MA_LOG("Failed to create close queue");
    return NULL;
  }

  mssl->resetq = create_stream_queue(g_config.mos->max_concurrency);
  if (!mssl->resetq)
  {
    MA_LOG("Failed to create reset queue");
    return NULL;
  }

  mssl->resetq_int = create_internal_stream_queue(g_config.mos->max_concurrency);
  if (!mssl->resetq_int)
  {
    MA_LOG("Failed to create reset queue");
    return NULL;
  }

  mssl->destroyq = create_stream_queue(g_config.mos->max_concurrency);
  if (!mssl->destroyq)
  {
    MA_LOG("Failed to create destroy queue");
    return NULL;
  }

  mssl->g_sender = create_mssl_sender(-1);
  if (!mssl->g_sender)
  {
    MA_LOG("Failed to create mssl sender");
    return NULL;
  }

  for (i=0; i<g_config.mos->netdev_table->num; i++)
  {
    mssl->n_sender[i] = create_mssl_sender(i);
    if (!mssl->n_sender[i])
    {
      MA_LOG("failed to create mssl sender");
      return NULL;
    }
  }

  mssl->rto_store = init_rto_hashstore();
  TAILQ_INIT(&mssl->timewait_list);
  TAILQ_INIT(&mssl->timeout_list);

  return mssl;
}

static void *mssl_run_thread(void *arg)
{
  MA_LOG("mssl_run_thread");
  mctx_t mctx = (mctx_t)arg;
  int cpu = mctx->cpu;
  int working;
  struct mssl_manager *mssl;
  struct mssl_thread_context *ctx;

  mssl_core_affinitize(cpu);

  ctx = calloc(1, sizeof(*ctx));
  if (!ctx)
  {
    MA_LOG("Error calloc");
    exit(EXIT_FAILURE);
  }
  ctx->thread = pthread_self();
  ctx->cpu = cpu;
  mssl = ctx->mssl_manager = initialize_mssl_manager(ctx);
  if (!mssl)
  {
    MA_LOG("Failed to initialize mssl manager");
    exit(EXIT_FAILURE);
  }
  MA_LOG("Succeed to initialize mssl manager");

  mssl->iom = current_iomodule_func;

  if (mssl->iom->init_handle)
    mssl->iom->init_handle(ctx);

  if (pthread_mutex_init(&ctx->flow_pool_lock, NULL))
  {
    perror("pthread_mutex_init of ctx->flow_pool_lock\n");
    exit(-1);
  }

  if (pthread_mutex_init(&ctx->socket_pool_lock, NULL))
  {
    perror("pthread_mutex_init of ctx->socket_pool_lock\n");
    exit(-1);
  }

  MA_LOG("Succeed to initialize mutex");

  SQ_LOCK_INIT(&ctx->connect_lock, "ctx->connect_lock", exit(-1));
  SQ_LOCK_INIT(&ctx->close_lock, "ctx->close_lock", exit(-1));
  SQ_LOCK_INIT(&ctx->reset_lock, "ctx->reset_lock", exit(-1));
  SQ_LOCK_INIT(&ctx->sendq_lock, "ctx->sendq_lock", exit(-1));
  SQ_LOCK_INIT(&ctx->ackq_lock, "ctx->ackq_lock", exit(-1));
  SQ_LOCK_INIT(&ctx->destroyq_lock, "ctx->destroyq_lock", exit(-1));

  MA_LOG("Succeed to initialize locks");

  g_pctx[cpu] = ctx;
  mlockall(MCL_CURRENT);
  
  MA_LOG("Before attach device");

  working = attach_device(ctx);

  MA_LOG("After attach device");

  if (working != 0)
  {
    sem_post(&g_init_sem[ctx->cpu]);
    pthread_exit(NULL);
  }

  MA_LOG("Before sem post");

  sem_post(&g_init_sem[ctx->cpu]);
  
  MA_LOG("before run main loop");
  run_main_loop(ctx);
  MA_LOG("after run main loop");

  sem_post(&g_done_sem[mctx->cpu]);

  return 0;
}

mctx_t mssl_create_context(int cpu)
{
  MA_LOG("Create the context");
  mctx_t mctx;
  int ret;

  if (cpu >= g_config.mos->num_cores)
  {
    MA_LOG("Failed to initialize new mctx context");
    return NULL;
  }

  ret = sem_init(&g_init_sem[cpu], 0, 0);
  if (ret)
  {
    MA_LOG("Failed to initialize init_sem");
    return NULL;
  }

  ret = sem_init(&g_done_sem[cpu], 0, 0);
  if (ret)
  {
    MA_LOG("Failed to initialize done_sem");
    return NULL;
  }

  mctx = (mctx_t)calloc(1, sizeof(struct mssl_context));
  if (!mctx)
  {
    MA_LOG("Failed to allocate memory for mssl_context");
    return NULL;
  }
  mctx->cpu = cpu;
  g_ctx[cpu] = mctx;

  if (pthread_create(&g_thread[cpu], NULL, mssl_run_thread, (void *)mctx) != 0)
  {
    MA_LOG("pthread_create of mssl thread failed");
    return NULL;
  }

  sem_wait(&g_init_sem[cpu]);
  sem_destroy(&g_init_sem[cpu]);

  running[cpu] = TRUE;

  return mctx;
}

int mssl_destroy_context(mctx_t mctx)
{
	struct mssl_thread_context *ctx = g_pctx[mctx->cpu];
	if (ctx != NULL)
		ctx->done = 1;

	struct mssl_context m;
	m.cpu = mctx->cpu;
	mssl_free_context(&m);
	
	free(mctx);

	return 0;
}

void mssl_free_context(mctx_t mctx)
{
	struct mssl_thread_context *ctx = g_pctx[mctx->cpu];
	struct mssl_manager *mssl = ctx->mssl_manager;
	int ret, i;

	if (g_pctx[mctx->cpu] == NULL) return;

	/* close all stream sockets that are still open */
	if (!ctx->exit) {
		for (i = 0; i < g_config.mos->max_concurrency; i++) {
			if (mssl->smap[i].socktype == MOS_SOCK_STREAM) {
				mssl_close(mctx, i);
			}
		}
	}

	ctx->done = 1;
	ctx->exit = 1;

#ifdef ENABLE_DPDK
	if (current_iomodule_func == &dpdk_module_func) {
		int master = rte_get_master_lcore();
		if (master == mctx->cpu)
			pthread_join(g_thread[mctx->cpu], NULL);
		else
			rte_eal_wait_lcore(mctx->cpu);
	} else 
#endif /* !ENABLE_DPDK */
		{
			pthread_join(g_thread[mctx->cpu], NULL);
		}
	
	running[mctx->cpu] = FALSE;

#ifdef NETSTAT
#if NETSTAT_TOTAL
	if (printer == mctx->cpu) {
		for (i = 0; i < num_cpus; i++) {
			if (i != mctx->cpu && running[i]) {
				printer = i;
				break;
			}
		}
	}
#endif
#endif

	if (mssl->connectq) {
		destroy_stream_queue(mssl->connectq);
		mssl->connectq = NULL;
	}
	if (mssl->sendq) {
		destroy_stream_queue(mssl->sendq);
		mssl->sendq = NULL;
	}
	if (mssl->ackq) {
		destroy_stream_queue(mssl->ackq);
		mssl->ackq = NULL;
	}
	if (mssl->closeq) {
		destroy_stream_queue(mssl->closeq);
		mssl->closeq = NULL;
	}
	if (mssl->closeq_int) {
		destroy_internal_stream_queue(mssl->closeq_int);
		mssl->closeq_int = NULL;
	}
	if (mssl->resetq) {
		destroy_stream_queue(mssl->resetq);
		mssl->resetq = NULL;
	}
	if (mssl->resetq_int) {
		destroy_internal_stream_queue(mssl->resetq_int);
		mssl->resetq_int = NULL;
	}
	if (mssl->destroyq) {
		destroy_stream_queue(mssl->destroyq);
		mssl->destroyq = NULL;
	}

	destroy_mssl_sender(mssl->g_sender);
	for (i = 0; i < g_config.mos->netdev_table->num; i++) {
		destroy_mssl_sender(mssl->n_sender[i]);
	}

	mp_destroy(mssl->rv_pool);
	mp_destroy(mssl->sv_pool);
	mp_destroy(mssl->flow_pool);
	
	if (mssl->ap) {
		destroy_address_pool(mssl->ap);
		mssl->ap = NULL;
	}

	SQ_LOCK_DESTROY(&ctx->connect_lock);
	SQ_LOCK_DESTROY(&ctx->close_lock);
	SQ_LOCK_DESTROY(&ctx->reset_lock);
	SQ_LOCK_DESTROY(&ctx->sendq_lock);
	SQ_LOCK_DESTROY(&ctx->ackq_lock);
	SQ_LOCK_DESTROY(&ctx->destroyq_lock);
	
	//TRACE_INFO("mssl thread %d destroyed.\n", mctx->cpu);
	if (mssl->iom->destroy_handle)
		mssl->iom->destroy_handle(ctx);
	free(ctx);
	g_pctx[mctx->cpu] = NULL;
}

int mssl_getconf(struct mssl_conf *conf)
{
	int i, j;

	if (!conf) {
		errno = EINVAL;
		return -1;
	}

	conf->num_cores = g_config.mos->num_cores;
	conf->max_concurrency = g_config.mos->max_concurrency;
	conf->cpu_mask = g_config.mos->cpu_mask;

	conf->rcvbuf_size = g_config.mos->rmem_size;
	conf->sndbuf_size = g_config.mos->wmem_size;

	conf->tcp_timewait = g_config.mos->tcp_tw_interval;
	conf->tcp_timeout = g_config.mos->tcp_timeout;

	i = 0;
	struct conf_block *bwalk;
	TAILQ_FOREACH(bwalk, &g_config.app_blkh, link) {
		struct app_conf *app_conf = (struct app_conf *)bwalk->conf;
		for (j = 0; j < app_conf->app_argc; j++)
			conf->app_argv[i][j] = app_conf->app_argv[j];
		conf->app_argc[i] = app_conf->app_argc;
		conf->app_cpu_mask[i] = app_conf->cpu_mask;
		i++;
	}
	conf->num_app = i;

	return 0;
}
/*----------------------------------------------------------------------------*/
int 
mssl_setconf(const struct mssl_conf *conf)
{
	if (!conf)
		return -1;

	g_config.mos->num_cores = conf->num_cores;
	g_config.mos->max_concurrency = conf->max_concurrency;

	g_config.mos->rmem_size = conf->rcvbuf_size;
	g_config.mos->wmem_size = conf->sndbuf_size;

	g_config.mos->tcp_tw_interval = conf->tcp_timewait;
	g_config.mos->tcp_timeout = conf->tcp_timeout;

	return 0;
}

int mssl_destroy()
{
  int i;
  for (i=0; i<g_config.mos->netdev_table->num; i++)
    destroy_address_pool(ap[i]);

  return 0;
}
