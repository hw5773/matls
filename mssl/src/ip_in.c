#include <string.h>
#include <netinet/ip.h>
#include <stdbool.h>

#include "include/ip_in.h"
#include "include/ip_out.h"
//#include "include/tcp.h"
#include "include/mssl_api.h"
#include "include/mos_api.h"
#include "include/config.h"
#include "include/logs.h"

#define ETH_P_IP_FRAG   0xF800
#define ETH_P_IPV6_FRAG 0xF6DD

inline void fillin_packet_ip_context(struct pkt_ctx *pctx, struct iphdr *iph, int ip_len)
{
  pctx->p.iph = iph;
  pctx->p.ip_len = ip_len;

  return;
}

inline int process_in_ipv4_packet(mssl_manager_t mssl, struct pkt_ctx *pctx)
{
  MA_LOG("Processing IPv4 packet");
  bool release = false;
  int ret;
//  struct mon_listener *walk;
  struct iphdr *iph = (struct iphdr *)((char *)pctx->p.ethh + sizeof(struct ethhdr));
  int ip_len = ntohs(iph->tot_len);

  if (ip_len < sizeof(struct iphdr))
  {
    MA_LOG1d("Wrong Length", ip_len);
    ret = ERROR;
    goto __return;
  }

  MA_LOG1d("Length of IP Packet", ip_len);

  if (iph->version != 0x4)
  {
    MA_LOG1d("Wrong Version", iph->version);
    release = true;
    ret = FALSE;
    goto __return;
  }

  MA_LOG1d("Version of IP Packet", iph->version);

  fillin_packet_ip_context(pctx, iph, ip_len);

  if (mssl->num_msp == 0 && mssl->num_esp == 0)
  {
    MA_LOG("No sockets, forward");
    if (pctx->forward)
    {
      forward_ip_packet(mssl, pctx);
    }
    return TRUE;
  }

  if (ip_fast_csum(iph, iph->ihl))
  {
    ret = ERROR;
    goto __return;
  }

  switch (iph->protocol)
  {
    case IPPROTO_TCP:
      MA_LOG("This is TCP Packet");
      //return process_in_tcp_packet(mssl, pctx);
      break;
    case IPPROTO_ICMP:
      MA_LOG("This is ICMP Packet");
      //if (process_icmp_packet(mssl, pctx))
      //  return TRUE;
    default:
      if (!mssl->num_msp || !pctx->forward)
        release = true;
      else
        forward_ip_packet(mssl, pctx);

      ret = false;
      goto __return;
  }

__return:
  if (release && mssl->iom->release_pkt)
    mssl->iom->release_pkt(mssl->ctx, pctx->p.in_ifidx, 
        (unsigned char *)pctx->p.ethh, pctx->p.eth_len);
  MA_LOG("Process IPv4 Packet success");
  return ret;
}

