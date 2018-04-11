#ifndef __MSSL_API_H__
#define __MSSL_API_H__

#include <stdint.h>
#include <netinet/in.h>
#include <sys/uio.h>

#ifndef UNUSED
#define UNUSED(x) (void) x
#endif

#ifndef INPORT_ANY
#define INPORT_ANY (uint16_t) 0
#endif

typedef unsigned char byte;

struct mssl_context
{
  int cpu;
};

typedef struct mssl_context *mctx_t;
typedef void (*mssl_sighandler_t)(int);

enum socket_type
{
  MOS_SOCK_UNUSED,
  MOS_SOCK_STREAM_LISTEN,
  MOS_SOCK_PROXY_LISTEN,
  MOS_SOCK_MONITOR_STREAM,
  MOS_SOCK_STREAM,
  MOS_SOCK_PROXY,
  MOS_SOCK_SPLIT_TLS,
  MOS_SOCK_MATLS,
  MOS_SOCK_MONITOR_RAW,
  MOS_SOCK_EPOLL,
  MOS_SOCK_PIPE,
};

struct mssl_conf
{
#define APP_NAME_LEN 40
#define MOS_APP 20

  int num_cores;
  int max_concurrency;
  uint64_t cpu_mask;

  int max_num_buffers;
  int clnt_rcvbuf_size;
  int clnt_sndbuf_size;
  int serv_rcvbuf_size;
  int serv_sndbuf_size;

  int tcp_timewait;
  int tcp_timeout;

#define MOS_APP_ARGC 20
  uint64_t app_cpu_mask[MOS_APP];
  char *app_argv[MOS_APP][MOS_APP_ARGC];
  int app_argc[MOS_APP];
  int num_app;
};

struct app_context
{
  mctx_t mctx;
  int socket_id;
  struct conn_filter *cf;
  int ep_id;
};

int mssl_init();
int mssl_destroy();
int mssl_getconf(struct mssl_conf *conf);
int mssl_setconf(const struct mssl_conf *conf);
int mssl_core_affinitize(int cpu);
mctx_t mssl_create_context(int cpu);
int mssl_destroy_context(mctx_t mctx);
mssl_sighandler_t mssl_register_signal(int signum, mssl_sighandler_t handler);
int mssl_pipe(mctx_t mctx, int pipeid[2]);
int mssl_getsockopt(mctx_t mctx, int sock, int level, int optname, 
    void *optval, socklen_t *optlen);
int mssl_setsockopt(mctx_t mctx, int sock, int level, int optname,
    const void *optval, socklen_t optlen);
int mssl_ioctl(mctx_t mctx, int sock, int request, void *argp);
int mssl_socket(mctx_t mctx, int domain, int type, int protocol);

int get_num_cpus(void);
#endif /* __MSSL_API_H__ */
