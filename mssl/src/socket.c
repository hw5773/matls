#include <string.h>

#include "include/mssl.h"
#include "include/socket.h"
#include "include/logs.h"
#include "include/config.h"

void free_mon_listener(mssl_manager_t mssl, socket_map_t socket)
{
}

static inline void free_mon_stream(mssl_manager_t mssl, socket_map_t socket)
{
}

socket_map_t allocate_socket(mctx_t mctx, int socktype)
{
  mssl_manager_t mssl = g_mssl[mctx->cpu];
  socket_map_t socket = NULL;

  switch (socktype)
  {
    case MOS_SOCK_MONITOR_STREAM:
      mssl->num_msp++;
    case MOS_SOCK_MONITOR_STREAM_ACTIVE:
    case MOS_SOCK_MONITOR_RAW:
      socket = TAILQ_FIRST(&mssl->free_msmap);

      if (!socket)
        goto alloc_error;

      TAILQ_REMOVE(&mssl->free_msmap, socket, link);

      if (socket->events)
      {
        TAILQ_INSERT_TAIL(&mssl->free_msmap, socket, link);
        socket = NULL;
        goto alloc_error;
      }

      break;

    default:
      mssl->num_esp++;
      socket = TAILQ_FIRST(&mssl->free_smap);

      if (!socket)
        goto alloc_error;
      TAILQ_REMOVE(&mssl->free_smap, socket, link);

      if (socket->events)
      {
        socket = NULL;
        goto alloc_error;
      }
      socket->stream = NULL;

      memset(&socket->saddr, 0, sizeof(struct sockaddr_in));
      memset(&socket->ep_data, 0, sizeof(mssl_epoll_data_t));
  }

  socket->socktype = socktype;
  socket->opts = 0;
  socket->epoll = 0;
  socket->events = 0;

  MA_LOG("Socket allocate success");

  return socket;

alloc_error:
  MA_LOG("The concurrent sockets are at maximum");
  return NULL;
}

void free_socket(mctx_t mctx, int sockid, int socktype)
{
  mssl_manager_t mssl = g_mssl[mctx->cpu];
  socket_map_t socket = NULL;

  switch (socktype)
  {
    case MOS_SOCK_UNUSED:
      return;
    case MOS_SOCK_MONITOR_STREAM_ACTIVE:
      socket = &mssl->msmap[sockid];
      free_mon_stream(mssl, socket);
      TAILQ_INSERT_TAIL(&mssl->free_msmap, socket, link);
      break;
    case MOS_SOCK_MONITOR_STREAM:
      mssl->num_msp--;
    case MOS_SOCK_MONITOR_RAW:
      socket = &mssl->msmap[sockid];
      free_mon_listener(mssl, socket);
      TAILQ_INSERT_TAIL(&mssl->free_msmap, socket, link);
      break;
    default: // MOS_SOCK_STREAM, MOS_SOCK_MATLS, MOS_SOCK_SPLIT_TLS
      mssl->num_esp--;
      socket = &mssl->smap[sockid];
      TAILQ_INSERT_TAIL(&mssl->free_smap, socket, link);
      mssl->smap[sockid].stream = NULL;
      break;
  }

  socket->socktype = MOS_SOCK_UNUSED;
  socket->epoll = MOS_EPOLLNONE;
  socket->events = 0;
}

socket_map_t get_socket(mctx_t mctx, int sockid)
{
  if (sockid < 0 || sockid >= g_config.mos->max_concurrency)
  {
    errno = EBADF;
    return NULL;
  }

  return &g_mssl[mctx->cpu]->smap[sockid];
}

