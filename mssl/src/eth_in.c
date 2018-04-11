#include <string.h>

#include "include/ip_in.h"
#include "include/ip_out.h"
#include "include/eth_in.h"
#include "include/eth_out.h"
//#include "include/arp.h"
//#include "include/debug.h"
#include "include/config.h"
#include "include/logs.h"

inline void fillin_packet_eth_context(struct pkt_ctx *pctx, uint32_t cur_ts, int in_ifidx,
    int index, struct ethhdr *ethh, int eth_len)
{
  pctx->p.cur_ts = cur_ts;
  pctx->p.in_ifidx = in_ifidx;
  pctx->out_ifidx = -1;
  pctx->p.ethh = ethh;
  pctx->p.eth_len = eth_len;
  pctx->batch_index = index;
  pctx->forward = g_config.mos->forward;

  return;
}

int process_packet(mssl_manager_t mssl, const int ifidx, const int index, uint32_t cur_ts, unsigned char *pkt_data, int len)
{
  MA_LOG("process_packet");
  struct pkt_ctx pctx;
  struct ethhdr *ethh = (struct ethhdr *)pkt_data;
  int ret = -1;
  uint16_t proto = ntohs(ethh->h_proto);

  fillin_packet_eth_context(&pctx, cur_ts, ifidx, index, ethh, len);

  if (proto == ETH_P_IP)
  {
    MA_LOG("This is IPv4 packet");
    ret = process_in_ipv4_packet(mssl, &pctx);
    MA_LOG("Process IPv4 packet success");
  }
  else
  {
    MA_LOG("This is not IPv4 packet");
    if (!mssl->num_msp || !pctx.forward)
    {
      if (proto == ETH_P_ARP)
      {
        ret = process_arp_packet(mssl, cur_ts, ifidx, pkt_data, len);
        return TRUE;
      }
      else
      {
        if (mssl->iom->release_pkt)
          mssl->iom->release_pkt(mssl->ctx, ifidx, pkt_data, len);
      }
    }
    else
    {
      forward_ethernet_frame(mssl, &pctx);
      ret = TRUE;
    }
  }

  MA_LOG("Process success");
  return ret;
}
