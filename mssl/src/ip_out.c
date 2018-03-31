#include <string.h>

#include "include/ip_out.h"
#include "include/ip_in.h"
#include "include/eth_out.h"
#include "include/eth_in.h"
#include "include/arp.h"
#include "include/config.h"
#include "include/logs.h"

inline int get_output_interface(uint32_t daddr)
{
  int nif = -1;
  int i;
  int prefix = -1;

  for (i=0; i<g_config.mos->route_table->num; i++)
  {
    if ((daddr & g_config.mos->route_table->ent[i]->mask)
        == g_config.mos->route_table->ent[i]->masked_ip)
    {
      if (g_config.mos->route_table->ent[i]->prefix > prefix)
      {
        nif = g_config.mos->route_table->ent[i]->nif;
        prefix = g_config.mos->route_table->ent[i]->prefix;
      }
    }
  }

  if (nif < 0)
  {
    MA_LOGip("No route to", daddr);
    assert(0);
  }

  return nif;
}

void forward_ip_packet(mssl_manager_t mssl, struct pkt_ctx *pctx)
{
  MA_LOG("Now Forward IP Packet");
  unsigned char *haddr;
  struct iphdr *iph;
  uint32_t daddr = 0;

  if (g_config.mos->nic_forward_table != NULL)
  {
    pctx->out_ifidx = g_config.mos->nic_forward_table->nic_fwd_table[pctx->p.in_ifidx];
    if (pctx->out_ifidx != -1)
    {
      haddr = pctx->p.ethh->h_dest;
      MA_LOG("Go to fast tx");
      goto fast_tx;
    }
  }

  daddr = pctx->p.iph->daddr;

  if (pctx->out_ifidx <0)
  {
    pctx->out_ifidx = get_output_interface(pctx->p.iph->daddr);
    if (pctx->out_ifidx < 0)
      return;
  }

  haddr = get_destination_hwaddr(daddr);

  if (!haddr)
  {
    MA_LOGip("No route to", daddr);

    if (!pctx->forward)
    {
      MA_LOG("Request ARP");
      request_arp(mssl, daddr, pctx->out_ifidx, pctx->p.cur_ts);
    }
    return;
  }

#ifdef SHARE_IO_BUFFER
  if (!(mssl->iom->set_wptr))
  {
    int i;
    for (i=0; i<ETH_ALEN; i++)
    {
      pctx->p.ethh->h_source[i] = g_config.mos->netdev_table->ent[pctx->out_ifidx]->haddr[i];
      pctx->p.ethh->h_dest[i] = haddr[i];
    }
    mssl->iom->set_wptr(mssl->ctx, pctx->out_ifidx, pctx->p.in_ifidx, pctx->batch_index);
    return;
  }
#endif /* SHARE_IO_BUFFER */

fast_tx:
  iph = (struct iphdr *)ethernet_output(mssl, pctx, ETH_P_IP, pctx->out_ifidx, haddr, pctx->p.ip_len, pctx->p.cur_ts);

  if (iph)
    memcpy(iph, pctx->p.iph, pctx->p.ip_len);
  else
    MA_LOG("Failed to send packet");
}

inline void fillout_packet_ip_context(struct pkt_ctx *pctx, struct iphdr *iph, int ip_len)
{
  pctx->p.iph = iph;
  pctx->p.ip_len = ip_len;

  return;
}
