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

static void print_state1(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
  //fprintf(stderr, "[mOS] %s: MOS_ON_CONN_START, MOS_HK_SND\n", __func__);
}

static void print_state2(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
  //fprintf(stderr, "[mOS] %s: MOS_ON_CONN_START, MOS_HK_RCV\n", __func__);
}

static void print_state3(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
  //fprintf(stderr, "[mOS] %s: MOS_ON_CONN_END, MOS_HK_SND\n", __func__);
}

static void print_state4(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
  fprintf(stderr, "[mOS] %s: MOS_ON_PKT_IN, MOS_HK_SND\n", __func__);
  struct pkt_info *p;
  p = (struct pkt_info *)malloc(sizeof(struct pkt_info));

  if (mtcp_getlastpkt(mctx, sock, side, p) < 0)
    exit(EXIT_FAILURE);

  print_ip(p->iph->saddr, SRC);
  print_ip(p->iph->daddr, DST);
  printf("SYN: %d\n", p->tcph->syn);
  printf("ACK: %d\n", p->tcph->ack);
  printf("PSH: %d\n", p->tcph->psh);
  printf("FIN: %d\n", p->tcph->fin);

  if (p->payloadlen > 0)
  {
    if (strstr((char *)p->payload, "Apache") != NULL)
    {
      uint8_t *modified;
      //printf("Before: %s\n", (p->payload));
      modified = strrep(p->payload, (uint8_t *)"Apache", (uint8_t *)"Nginx!");
      //printf("After: %s\n", modified);
      //printf("Before Length: %lu\n", strlen((char *)p->payload));
      //printf("After Length: %lu\n", strlen((char *)modified));

      if (mtcp_setlastpkt(mctx, sock, 0, 0,
          modified, strlen((char *)modified), MOS_TCP_PAYLOAD | MOS_OVERWRITE
          | MOS_UPDATE_IP_CHKSUM | MOS_UPDATE_TCP_CHKSUM) < 0)
      {
        printf("%s: Error in sending the modified packet\n", __func__);
        exit(EXIT_FAILURE);
      }
      free(modified);
    }
  }
  free(p);
}


static void print_state5(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
  fprintf(stderr, "[mOS] %s: MOS_ON_PKT_IN, MOS_HK_RCV\n", __func__);
  struct pkt_info p;

  if (mtcp_getlastpkt(mctx, sock, side, &p) < 0)
    exit(EXIT_FAILURE);

  if (p.payloadlen > 0)
  {
    printf("%s: Payload: %s\n", __func__, (p.payload));
  }
}


static void print_state6(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
}

static void print_state7(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
}

static void init_monitor(mctx_t mctx)
{
  int lsock = mtcp_socket(mctx, AF_INET, MOS_SOCK_MONITOR_STREAM, 0);
  if (lsock < 0)
  {
    TRACE_ERROR("Failed to create monitor raw socket!\n");
    return;
  }

  if (mtcp_register_callback(mctx, lsock, MOS_ON_CONN_START, MOS_HK_SND, print_state1))
    exit(EXIT_FAILURE);

  if (mtcp_register_callback(mctx, lsock, MOS_ON_CONN_START, MOS_HK_RCV, print_state2))
    exit(EXIT_FAILURE);
  
  if (mtcp_register_callback(mctx, lsock, MOS_ON_CONN_END, MOS_HK_SND, print_state3))
    exit(EXIT_FAILURE);

  if (mtcp_register_callback(mctx, lsock, MOS_ON_PKT_IN, MOS_HK_SND, print_state4))
    exit(EXIT_FAILURE);

  if (mtcp_register_callback(mctx, lsock, MOS_ON_PKT_IN, MOS_HK_RCV, print_state5))
    exit(EXIT_FAILURE);

  if (mtcp_register_callback(mctx, lsock, MOS_ON_TCP_STATE_CHANGE, MOS_HK_SND, print_state6))
    exit(EXIT_FAILURE);

  if (mtcp_register_callback(mctx, lsock, MOS_ON_ORPHAN, MOS_NULL, print_state7))
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
  int i, opt;
  char *fname = MOS_CONFIG_FILE;
  struct mtcp_conf mcfg;
  mctx_t mctx_list[MAX_CORES];

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

  for (i=0; i<g_core_limit; i++)
  {
    if (!(mctx_list[i] = mtcp_create_context(i)))
    {
      fprintf(stderr, "Failed to create mtcp context.\n");
      return -1;
    }

    fprintf(stderr, "Initialize the monitor on %d\n", i);
    init_monitor(mctx_list[i]);
  }

  for (i=0; i<g_core_limit; i++)
    mtcp_app_join(mctx_list[i]);

  mtcp_destroy();

  return 0;
}
