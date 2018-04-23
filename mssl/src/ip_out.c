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
    return nif;
  }

  return nif;
}

void forward_ip_packet(mssl_manager_t mssl, struct pkt_ctx *pctx)
{
//  MA_LOG("Now Forward IP Packet");
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
//  MA_LOG1d("Get output interface number", pctx->out_ifidx);
//  MA_LOG1s("Get output interface", g_config.mos->netdev_table->ent[pctx->out_ifidx]->dev_name);

  haddr = get_destination_hwaddr(daddr);

  if (!haddr)
  {
    MA_LOGip("No route to", daddr);

    if (!pctx->forward)
    {
      MA_LOG("Request ARP");
      request_arp(mssl, daddr, pctx->out_ifidx, pctx->p.cur_ts);
    }
    // ARP?
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

void reverse_ip_packet(mssl_manager_t mssl, struct pkt_ctx *pctx)
{
  uint32_t saddr, daddr;
  uint16_t sport, dport;

  saddr = pctx->p.iph->daddr;
  daddr = pctx->p.iph->saddr;
  sport = pctx->p.tcph->dest;
  dport = pctx->p.tcph->source;

  pctx->p.iph->saddr = saddr;
  pctx->p.iph->daddr = daddr;
  pctx->p.tcph->source = sport;
  pctx->p.tcph->dest = dport;

  pctx->p.iph->check = 0;
  pctx->p.iph->check = ip_fast_csum(pctx->p.iph, pctx->p.iph->ihl);
  pctx->p.tcph->check = 0;
  pctx->p.tcph->check = tcp_calc_checksum((uint16_t *)pctx->p.tcph,
      ntohs(pctx->p.iph->tot_len) - (pctx->p.iph->ihl << 2),
      pctx->p.iph->saddr, pctx->p.iph->daddr);

  forward_ip_packet(mssl, pctx);
}

inline void fillout_packet_ip_context(struct pkt_ctx *pctx, struct iphdr *iph, int ip_len)
{
  pctx->p.iph = iph;
  pctx->p.ip_len = ip_len;

  return;
}

uint8_t *ip_output_standalone(mssl_manager_t mssl, uint16_t ip_id, uint32_t saddr, 
    uint32_t daddr, uint16_t tcplen, struct pkt_ctx *pctx, uint32_t cur_ts)
{
  struct iphdr *iph;
  int nif;
  unsigned char *haddr;
  int rc = -1;

  nif = get_output_interface(daddr);
  if (nif < 0)
    return NULL;

  haddr = get_destination_hwaddr(daddr);

  if (!haddr)
  {
#ifdef RUN_ARP
    if (!pctx->forward)
      request_arp(mssl, daddr, nif, mssl->cur_ts);
#else
    MA_LOG("Destination IP is not in ARP table");
#endif
    return NULL;
  }

  iph = (struct iphdr *)ethernet_output(mssl, pctx, ETH_P_IP, nif, haddr, 
      tcplen + IP_HEADER_LEN, cur_ts);

  MA_LOG("after ethernet output");

  if (!iph)
    return NULL;

  iph->ihl = IP_HEADER_LEN >> 2;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = htons(IP_HEADER_LEN + tcplen);
  iph->id = htons(ip_id);
  iph->frag_off = htons(0x4000);
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->saddr = saddr;
  iph->daddr = daddr;
  iph->check = 0;

  if (likely(mssl->iom->dev_ioctl != NULL))
    rc = mssl->iom->dev_ioctl(mssl->ctx, nif, PKT_TX_IP_CSUM, iph);

  MA_LOG("before ip checksum");
  if (rc < 0)
    iph->check = ip_fast_csum(iph, iph->ihl);

  fillout_packet_ip_context(pctx, iph, tcplen + IP_HEADER_LEN);

  MA_LOG("after fillout ip context");
  return (uint8_t *)(iph + 1);
}

uint8_t *ip_output(mssl_manager_t mssl, tcp_stream *stream, uint16_t tcplen,
    struct pkt_ctx *pctx, uint32_t cur_ts)
{
  struct iphdr *iph;
  int nif;
  unsigned char *haddr;
  int rc = -1;

  if (stream->sndvar->nif_out >= 0)
  {
    nif = stream->sndvar->nif_out;
  }
  else
  {
    nif = get_output_interface(stream->daddr);
    stream->sndvar->nif_out = nif;
  }

  haddr = get_destination_hwaddr(stream->daddr);

  if (!haddr)
  {
    if (!pctx->forward)
      request_arp(mssl, stream->daddr, stream->sndvar->nif_out, mssl->cur_ts);

    return NULL;
  }
  
  iph = (struct iphdr *)ethernet_output(mssl, pctx, ETH_P_IP,
      stream->sndvar->nif_out, haddr, tcplen + IP_HEADER_LEN, cur_ts);

  if (!iph)
    return NULL;

  iph->ihl = IP_HEADER_LEN >> 2;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = htons(IP_HEADER_LEN + tcplen);
  iph->id = htons(stream->sndvar->ip_id++);
  iph->frag_off = htons(0x4000);
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->saddr = stream->saddr;
  iph->daddr = stream->daddr;
  iph->check = 0;

  if (mssl->iom->dev_ioctl)
    rc = mssl->iom->dev_ioctl(mssl->ctx, nif, PKT_TX_IP_CSUM, iph);

  if (rc == -1)
    iph->check = ip_fast_csum(iph, iph->ihl);

  fillout_packet_ip_context(pctx, iph, tcplen + IP_HEADER_LEN);
  MA_LOG("after fillout ip context");

  return (uint8_t *)(iph + 1);
}
