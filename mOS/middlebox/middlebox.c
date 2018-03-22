#define _LARGEFILE64_SOURCE
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
#include <linux/if_ether.h>
#include <linux/tcp.h>

#include <sys/queue.h>

#include <mos_api.h>
#include <mtcp_util.h>

#include "cpu.h"
#include "http_parsing.h"
#include "debug.h"
#include "applib.h"
#include "func.h"

#define OFFSET_DST_IP   16
#define OFFSET_SRC_IP   12
#define OFFSET_DST_PORT 2
#define OFFSET_SRC_PORT 0

#define MOS_CONFIG_FILE "config/mos.conf"

#define MAX_CORES 16

enum {
  SRC,
  DST,
};

static int g_core_limit = 1;

static void print_ip(unsigned long ip, int side)
{
  unsigned char ipb[4];
  ipb[0] = ip & 0xFF;
  ipb[1] = (ip >> 8) & 0xFF;
  ipb[2] = (ip >> 16) & 0xFF;
  ipb[3] = (ip >> 24) & 0xFF;

  if (side == SRC)
    printf("Sender IP: %d.%d.%d.%d\n", ipb[0], ipb[1], ipb[2], ipb[3]);
  else if (side == DST)
    printf("Dest IP: %d.%d.%d.%d\n", ipb[0], ipb[1], ipb[2], ipb[3]);
  else
  {
    printf("%s: Error in side\n", __func__);
    exit(EXIT_FAILURE);
  }
}

static void https_message_process(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
  fprintf(stderr, "[mOS] %s: https, MOS_HK_SND\n", __func__);
  struct pkt_info p;

  if (mtcp_getlastpkt(mctx, sock, side, &p) < 0)
    exit(EXIT_FAILURE);
/*
  print_ip(p.iph->saddr, SRC);
  print_ip(p.iph->daddr, DST);
  fprintf(stderr, "[mOS] %s: Source Port: %d\n", __func__, ntohs(p.tcph->source));
  fprintf(stderr, "[mOS] %s: Destination Port: %d\n", __func__, ntohs(p.tcph->dest));
  fprintf(stderr, "[mOS] %s: Payload Length: %d\n", __func__, p.payloadlen);
  fprintf(stderr, "[mOS] %s: PSH: %d\n", __func__, p.tcph->psh);
  fprintf(stderr, "[mOS] %s: SYN: %d\n", __func__, p.tcph->syn);
  fprintf(stderr, "[mOS] %s: ACK: %d\n", __func__, p.tcph->ack);
  fprintf(stderr, "[mOS] %s: FIN: %d\n", __func__, p.tcph->fin);
*/
}


static bool is_https_message(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
  struct pkt_info p;

  if (mtcp_getlastpkt(mctx, sock, side, &p) < 0)
    exit(EXIT_FAILURE);

  print_ip(p.iph->saddr, SRC);
  print_ip(p.iph->daddr, DST);

  fprintf(stderr, "[mOS] %s: Source Port: %d\n", __func__, ntohs(p.tcph->source));
  fprintf(stderr, "[mOS] %s: Destination Port: %d\n", __func__, ntohs(p.tcph->dest));
  fprintf(stderr, "[mOS] %s: Payload Length: %d\n", __func__, p.payloadlen);
  fprintf(stderr, "[mOS] %s: PSH: %d\n", __func__, p.tcph->psh);
  fprintf(stderr, "[mOS] %s: SYN: %d\n", __func__, p.tcph->syn);
  fprintf(stderr, "[mOS] %s: ACK: %d\n", __func__, p.tcph->ack);
  fprintf(stderr, "[mOS] %s: FIN: %d\n", __func__, p.tcph->fin);

  return ((ntohs(p.tcph->source) == 443) || (ntohs(p.tcph->dest) == 443)) && (p.tcph->syn != 1) && (p.tcph->fin != 1);
}

static void init_monitor(mctx_t mctx, event_t https)
{
  int sock = mtcp_socket(mctx, AF_INET, MOS_SOCK_MONITOR_STREAM, 0);
  if (sock < 0)
  {
    TRACE_ERROR("Failed to create monitor raw socket!\n");
    return;
  }

  if (mtcp_register_callback(mctx, sock, https, MOS_HK_SND, https_message_process) < 0)
  {
    TRACE_ERROR("Failed to register callback function!\n");
    exit(EXIT_FAILURE);
  }
}

int main(int argc, char **argv)
{
  int i, opt;
  char *fname = MOS_CONFIG_FILE;
  struct mtcp_conf mcfg;
  mctx_t mctx_list[MAX_CORES];
  event_t https;

  g_core_limit = GetNumCPUs();

  while ((opt = getopt(argc, argv, "c:f:")) != -1)
  {
    switch (opt)
    {
      case 'f':
        fname = optarg;
        break;
      case 'c':
        if (atoi(optarg) > g_core_limit)
        {
          printf("Available number of CPU cores is %d\n", g_core_limit);
          return -1;
        }
        g_core_limit = atoi(optarg);
        break;
      default:
        printf("Usage: %s [-f mos_config_file] [-c #_of_cpu]\n", argv[0]);
        return 0;
    }
  }

  if (mtcp_init(fname))
  {
    fprintf(stderr, "Failed to initialize mtcp.\n");
    exit(EXIT_FAILURE);
  }

  mtcp_getconf(&mcfg);
  mcfg.num_cores = g_core_limit;
  mtcp_setconf(&mcfg);

  https = mtcp_define_event(MOS_ON_PKT_IN, is_https_message, NULL);
  if (https == MOS_NULL_EVENT)
  {
    TRACE_ERROR("mtcp_define_event() failed!");
    exit(EXIT_FAILURE);
  }

  for (i=0; i<g_core_limit; i++)
  {
    if (!(mctx_list[i] = mtcp_create_context(i)))
    {
      fprintf(stderr, "Failed to create mtcp context.\n");
      return -1;
    }

    fprintf(stderr, "Initialize the monitor on %d\n", i);
    init_monitor(mctx_list[i], https);
  }

  for (i=0; i<g_core_limit; i++)
    mtcp_app_join(mctx_list[i]);

  mtcp_destroy();

  return 0;
}
