#include <unistd.h>
#include <assert.h>
#include <semaphore.h>

#include "../include/mssl/mssl.h"
#include "../include/mssl/logs.h"

#include "include/config.h"
#include "include/cpu.h"
#include "include/mssl.h"

struct mssl_thread_context *g_pctx[MAX_CPUS] = {0};
static pthread_t g_thread[MAX_CPUS] = {0};

static sem_t g_init_sem[MAX_CPUS];
static sem_t g_done_sem[MAX_CPUS];

static int running[MAX_CPUS] = {0};
static int sigint_cnt[MAX_CPUS] = {0};

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
  if (ret)
  {
    MA_LOG("Error occured while loading configuration");
    return -1;
  }

  current_iomodule_func = &sock_module_func;

  if (current_iomodule_func->load_module_upper_half)
    current_iomodule_func->load_module_upper_half();
  
  load_configuration_lower_half();

  // TODO: address pool
  // TODO: initialize arp table
  // TODO: signal handler
  
  if (current_iomodule_func->load_module_lower_half)
    current_iomodule_func->load_module_lower_half();

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

  ts = ts_prev = 0;

  while ((!ctx->done || mssl->flow_cnt) && !ctx->exit)
  {
    // STAT_COUNT(mssl->runstat.rounds);
    recv_cnt = 0;
    gettimeofday(&cur_ts, NULL);
    // update_stat_counter();
    //prev_ts = cur_ts;

    ts = TIMEVAL_TO_TS(&cur_ts);
    //mssl->cur_ts = ts;

    for (rx_inf = 0; rx_inf < g_config.mos->netdev_table->num; rx_inf++)
    {
      MA_LOG1d("Read packets from the interface", rx_inf);
      recv_cnt = mssl->iom->recv_pkts(ctx, rx_inf);
      // STAT_COUNT(mssl->runstat.rounds_rx_try);
      
      for (i=0; i<recv_cnt; i++)
      {
        uint16_t len;
        uint8_t *pktbuf;
        pktbuf = mssl->iom->get_rptr(mssl->ctx, rx_inf, i, &len);
        process_packet(mssl, rx_inf, i, ts, pktbuf, len);
      }
    }
  }
}

static mssl_manager_t initialize_mssl_manager(struct mssl_thread_context *ctx)
{
}

static void *mssl_run_thread(void *arg)
{
  mctx_t mctx = (mctx_t)arg;
  int cpu = mctx->cpu;
  int working;
  struct mssl_manager *mssl;
  struct mssl_thread_context *ctx;

  //TODO: affinitize
  //mssl_core_affinitze(cpu);

  ctx = calloc(1, sizeof(*ctx));
  if (!ctx)
  {
    MA_LOG("Error calloc");
    exit(EXIT_FAILURE);
  }
  //ctx->thread = pthread_self();
  ctx->cpu = cpu;
  mssl = ctx->mssl_manager = initialize_mssl_manager(ctx);
  if (!mssl)
  {
    MA_LOG("Failed to initialize mssl manager");
    exit(EXIT_FAILURE);
  }

  mssl->iom = current_iomodule_func;

  if (mssl->iom->init_handle)
    mssl->iom->init_handle(ctx);

  // TODO: pthread_mutex_init
  // TODO: lock related work

  g_pctx[cpu] = ctx;
  // TODO: mlockall(MCL_CURRENT);
  
  working = attach_device(ctx);
  // TODO: error handling
  
  run_main_loop(ctx);

  // TODO: semaphore related work

  return 0;
}

mctx_t mssl_create_context(int cpu)
{
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

  mssl_run_thread(mctx);
  running[cpu] = TRUE;

  return mctx;
}
