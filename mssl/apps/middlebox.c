#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>

#include <mssl/mssl_api.h>
#include <mssl/logs.h>

#define MAX_CPUS 8
#define MSSL_CONFIG_FILE "config/mos.conf"

struct mssl_conf g_mcfg;
static pthread_t mssl_thread[MAX_CPUS];

static int num_cores;
static int core_limit;

static close_connection(struct thread_context *ctx, int sockid)
{
  mssl_epoll_ctl(ctx->mctx, ctx->ep, MOS_EPOLL_CTX_DEL, sockid, NULL);
  mssl_close(ctx->mctx, sockid);
}

static int send_until_available(struct thread_context *ctx, int sockid)
{
  int sent = 0;
  return sent;
}

static int handle_read_event(struct thread_context *ctx, int sockid)
{
  MA_LOG("handle_read_event");
  char buf[1024];
  int i, rd;
  rd = mssl_read(ctx->mctx, sockid, buf, 1024);

  if (rd <= 0)
  {
    MA_LOG("Error in read");
    return rd;
  }

  MA_LOG("read", rd);

  for (i=0; i<rd; i++)
  {
    if (i % 10 == 9)
      printf("\n");
    printf("%02X ", buf[i]);
  }

  return rd;
}

static int accept_connection(struct thread_context *ctx, int listener)
{
  mctx_t mctx = ctx->mctx;
  struct mssl_epoll_event ev;
  int c;

  c = mssl_accept(mctx, listener, NULL, NULL);

  if (c >= 0)
  {
    if (c >= MAX_FLOW_NUM)
    {
      MA_LOG1d("Invalid socket id", c);
    }

    ev.events = MOS_EPOLLIN;
    ev.data.sock = c;
    mssl_setsock_nonblock(ctx->mctx, c);
    mssl_epoll_ctl(mctx, ctx->ep, MOS_EPOLL_CTL_ADD, c, &ev);
  }
  else
  {
    if (errno != EAGAIN)
    {
    }
  }

  return c;
}

static int create_listening_socket(struct thread_context *ctx)
{
  int listener;
  struct mssl_epoll_event ev;
  struct sockaddr_in saddr;
  int ret;

static void glob_init_middlebox()
{
  // initialize new contexts and so on...
  return;
}

static void init_middlebox(mctx_t mctx, void **app_ctx)
{
  struct thread_context *ctx;

  ctx = (struct thread_context *)calloc(1, sizeof(struct thread_context));
  if (!ctx)
  {
    MA_LOG("Failed to create thread context!");
    exit(EXIT_FAILURE);
  }

  ctx->mctx = mctx;

  ctx->ep = mssl_epoll_create(mctx, MAX_EVENTS);
  if (ctx->ep < 0)
  {
    MA_LOG("Failed to create epoll descriptor!");
    exit(EXIT_FAILURE);
  }

//  ctx->svars define variables for our context if needed

  ctx->listener = create_listening_socket(ctx);
  if (ctx->listener < 0)
  {
    MA_LOG("Failed to create listening socket");
    exit(EXIT_FAILURE);
  }

  *app_ctx = (void *)ctx;

  return;
}

static void run_server(mctx_t mctx, void **app_ctx)
{
  struct thread_context *ctx = (*app_ctx);
  int nevents;
  int i, ret;
  int do_accept;
  struct mssl_epoll_event *events;

  assert(ctx);
  int ep = ctx->ep;

  events = (struct mssl_epoll_event *)calloc(MAX_EVENTS, sizeof(struct mssl_epoll_event));

  if (!events)
  {
    MA_LOG("Failed to create event struct");
    exit(EXIT_FAILURE);
  }

  while (1)
  {
    nevents = mssl_epoll_wait(mctx, ep, events, MAX_EVENTS, -1);
    if (nevents < 0)
    {
      if (errno != EINTR)
        perror("mssl_epoll_wait");
      break;
    }

    do_accept = FALSE;

    for (i=0; i<nevents; i++)
    {
      if (events[i].data.sock == ctx.listener)
      {
        do_accept = TRUE;
      }
      else if (events[i].events & MOS_EPOLLERR)
      {
        int err;
        socklen_t len = sizeof(err);

        if (mssl_getsockopt(mctx, events[i].data.sock,
              SOL_SOCKET, SO_ERROR, (void *)&err, &len) == 0)
        {
          if (err != ETIMEDOUT)
          {
          }
        }
        else
        {
        }
        close_connection(ctx, events[i].data.sock);


void run_application(mctx_t mctx)
{
  void *app_ctx;

  app_ctx = (void *)calloc(1, sizeof(void *));
  if (!app_ctx)
  {
    MA_LOG("Failed to calloc");
    return;
  }

  init_server(mctx, &app_ctx);
  run_server(mctx, &app_ctx);
}

void *run_mssl(void *arg)
{
  int core = *(int *)arg;
  mctx_t mctx;

  mssl_core_affinitize(core);
  mctx = mssl_create_context(core);
  if (!mctx)
  {
    MA_LOG("Failed to create mssl context");
    return NULL;
  }

  run_application(mctx);
  mssl_destroy_context(mctx);
  pthread_exit(NULL);

  return NULL;
}

int main(int argc, char *argv[])
{
  int ret, i;
  int cores[MAX_CPUS];
  char *fname = MSSL_CONFIG_FILE;

  int opt;
  
  core_limit = sysconf(_SC_NPROCESSORS_ONLN);
  MA_LOG1d("core_limit", core_limit);

  ret = mssl_init(fname);
  if (ret)
  {
    MA_LOG("Failed to initialize mssl");
    exit(EXIT_FAILURE);
  }

//  mssl_getconf(&g_mcfg);

//  core_limit = g_mcfg.num_cores;

  glob_init_middlebox();

  for (i=0; i<core_limit; i++)
  {
    cores[i] = i;

    if ((g_mcfg.cpu_mask & (1L << i)) &&
        pthread_create(&mssl_thread[i], NULL, run_mssl, (void *)&cores[i]))
    {
      perror("pthread_create");
      exit(EXIT_FAILURE);
    }
  }

  for (i=0; i < core_limit; i++)
  {
    if (g_mcfg.cpu_mask & (1L << i))
      pthread_join(mssl_thread[i], NULL);
  }

//  mssl_destroy();

  return 0;
}
