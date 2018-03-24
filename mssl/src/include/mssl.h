#ifndef __MSSL_H__
#define __MSSL_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <pthread.h>

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
*/
  uint32_t s_index;
};

struct mssl_manager *g_mssl[MAX_CPUS];

#endif /* __MSSL_H__ */
