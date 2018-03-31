#include <stdio.h>

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#ifdef DARWIN
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#else
#include <linux/if_ether.h>
#include <linux/tcp.h>
#endif
#include <string.h>
#include <netinet/ip.h>

#include "include/mssl.h"
//#include "include/arp.h"
#include "include/eth_out.h"
#include "include/mos_api.h"
#include "include/config.h"
#include "include/logs.h"

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef ERROR
#define ERROR (-1)
#endif

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

#define MAX_WINDOW_SIZE 65535

enum ETH_BUFFER_RETURN {BUF_RET_MAYBE, BUF_RET_ALWAYS};

int flush_send_chunk_buf(mssl_manager_t mssl, int nif)
{
  return 0;
}

inline void fillout_packet_eth_context(struct pkt_ctx *pctx, uint32_t cur_ts, int out_ifidx,
    struct ethhdr *ethh, int eth_len)
{
  pctx->p.cur_ts = cur_ts;
  pctx->p.in_ifidx = -1;
  pctx->out_ifidx = out_ifidx;
  pctx->p.ethh = ethh;
  pctx->p.eth_len = eth_len;
}

uint8_t *ethernet_output(mssl_manager_t mssl, struct pkt_ctx *pctx,
    uint16_t proto, int nif, unsigned char *dst_haddr, uint16_t iplen,
    uint32_t cur_ts)
{
  uint8_t *buf;
  struct ethhdr *ethh;
  int i;

  if (nif < 0)
  {
    MA_LOG("No interface set!");
    return NULL;
  }

  if (!mssl->iom->get_wptr)
  {
    MA_LOG("get_wptr() in io_module is undefined");
    return NULL;
  }

  buf = mssl->iom->get_wptr(mssl->ctx, nif, iplen + ETHERNET_HEADER_LEN);
  if (!buf)
  {
    MA_LOG("Failed to get available write buffer");
    return NULL;
  }

  ethh = (struct ethhdr *)buf;
  for (i=0; i<ETH_ALEN; i++)
  {
    ethh->h_source[i] = g_config.mos->netdev_table->ent[nif]->haddr[i];
    ethh->h_dest[i] = dst_haddr[i];
  }
  ethh->h_proto = htons(proto);

  if (pctx)
    fillout_packet_eth_context(pctx, cur_ts, nif, ethh, iplen + ETHERNET_HEADER_LEN);

  return (uint8_t *)(ethh + 1);
}

void forward_ethernet_frame(mssl_manager_t mssl, struct pkt_ctx *pctx)
{
  uint8_t *buf;

  if (g_config.mos->nic_forward_table != NULL)
  {
    pctx->out_ifidx = g_config.mos->nic_forward_table->nic_fwd_table[pctx->p.in_ifidx];
    MA_LOG1d("In interface", pctx->p.in_ifidx);
    MA_LOG1d("Out interface", pctx->out_ifidx);

    if (pctx->out_ifidx < 0)
    {
      MA_LOG("Could not find outgoing index!");
      return;
    }

    if (!mssl->iom->get_wptr)
    {
      MA_LOG("get_wptr() in io_module is undefined");
      return;
    }

    buf = mssl->iom->get_wptr(mssl->ctx, pctx->out_ifidx, pctx->p.eth_len);

    if (!buf)
    {
      MA_LOG("Failed to get available write buffer");
      return;
    }

    memcpy(buf, pctx->p.ethh, pctx->p.eth_len);
  }
  else
  {
    MA_LOG("Ethernet forwarding table entry does not exist");
  }
}
