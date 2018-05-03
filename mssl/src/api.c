#include <sys/queue.h>
#include <sys/ioctl.h>
#include <limits.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>

#ifdef DARWIN
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#endif

#include "include/mssl.h"
#include "include/mssl_api.h"
#include "include/tcp_in.h"
#include "include/tcp_stream.h"
#include "include/tcp_out.h"
#include "include/ip_out.h"
//#include "include/eventpoll.h"
//#include "include/pipe.h"
#include "include/fhash.h"
//#include "include/addr_pool.h"
#include "include/util.h"
#include "include/config.h"
#include "include/logs.h"
#include "include/mos_api.h"
#include "include/tcp_rb.h"

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

inline mssl_manager_t get_mssl_manager(mctx_t mctx)
{
  if (!mctx)
  {
    errno = EACCES;
    return NULL;
  }

  if (mctx->cpu < 0 || mctx->cpu >= num_cpus)
  {
    errno = EINVAL;
    return NULL;
  }

  if (!g_mssl[mctx->cpu])
    MA_LOG1p("g_mssl[mctx->cpu]", g_mssl[mctx->cpu]);

  if (g_mssl[mctx->cpu]->ctx->done)
    MA_LOG("g_mssl[mctx->cpu]->ctx->done");

  if (g_mssl[mctx->cpu]->ctx->exit)
    MA_LOG("g_mssl[mctx->cpu]->ctx->exit");

  if (!g_mssl[mctx->cpu] || g_mssl[mctx->cpu]->ctx->done || g_mssl[mctx->cpu]->ctx->exit)
  {
    errno = EPERM;
    return NULL;
  }

  return g_mssl[mctx->cpu];
}

static int mssl_monitor(mctx_t mctx, socket_map_t sock)
{
  mssl_manager_t mssl;
  struct mon_listener *monitor;
  int sockid = sock->id;

  mssl = get_mssl_manager(mctx);
  if (!mssl)
  {
    errno = EACCES;
    return -1;
  }

  if (sockid < 0 || sockid >= g_config.mos->max_concurrency)
  {
    MA_LOG("Socket id is out of range");
    errno = EBADF;
    return -1;
  }

  if (mssl->msmap[sockid].socktype == MOS_SOCK_UNUSED)
  {
    MA_LOG1d("Invalid socket id", sockid);
    errno = EBADF;
    return -1;
  }

  if (!(mssl->msmap[sockid].socktype == MOS_SOCK_SPLIT_TLS ||
        mssl->msmap[sockid].socktype == MOS_SOCK_MONITOR_STREAM))
  {
    MA_LOG("Not a monitor socket");
    errno = ENOTSOCK;
    return -1;
  }

  monitor = (struct mon_listener *)calloc(1, sizeof(struct mon_listener));
  if (!monitor)
  {
    errno = ENOMEM;
    return -1;
  }

  monitor->eq = create_event_queue(g_config.mos->max_concurrency);
  if (!monitor->eq)
  {
    MA_LOG("Cannot create event queue for monitor read event registration");
    free(monitor);
    errno = ENOMEM;
    return -1;
  }

#ifndef NEWEV
  monitor->ude_id = UDE_OFFSET;
#endif
  monitor->socket = sock;
  monitor->client_mon = monitor->server_mon = 1;

  TAILQ_INSERT_TAIL(&mssl->monitors, monitor, link);

  mssl->msmap[sockid].monitor_listener = monitor;

///// Add for MA_TLS /////
  struct tcp_listener *listener;
  listener = (struct tcp_listener *)calloc(1, sizeof(struct tcp_listener));
  if (!listener)
  {
    errno = ENOMEM;
    return -1;
  }

  listener->sockid = sockid;
  listener->backlog = g_config.mos->max_concurrency;
  listener->socket = sock;

  if (pthread_cond_init(&listener->accept_cond, NULL))
  {
    perror("pthread_cond_init of ctx->accept_cond");
    free(listener);
    return -1;
  }

  if (pthread_mutex_init(&listener->accept_lock, NULL))
  {
    perror("pthread_mutex_init of ctx->accept_lock");
    free(listener);
    return -1;
  }

  listener->acceptq = create_stream_queue(listener->backlog);
  if (!listener->acceptq)
  {
    free(listener);
    errno = ENOMEM;
    return -1;
  }

  mssl->smap[sockid].listener = listener;
  mssl->listener = listener;
  MA_LOG1p("mssl->listener init", mssl->listener);
//////////////////////////

  return 0;
} 

int mssl_socket(mctx_t mctx, int domain, int type, int protocol)
{
  MA_LOG("Socket Create");
  mssl_manager_t mssl;
  socket_map_t socket;

  mssl = get_mssl_manager(mctx);

  if (!mssl)
  {
    errno = EACCES;
    return -1;
  }

  if (domain != AF_INET)
  {
    errno = EAFNOSUPPORT;
    return -1;
  }

  socket = allocate_socket(mctx, type);

  if (!socket)
  {
    errno = ENFILE;
    return -1;
  }

  mssl_monitor(mctx, socket);
  return socket->id;
}
