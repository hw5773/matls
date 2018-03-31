#include <string.h>

#include "include/ip_in.h"
#include "include/eth_in.h"
#include "include/eth_out.h"
//#include "include/arp.h"
//#include "include/debug.h"
#include "include/ip_out.h"
//#include "include/config.h"
#include "include/logs.h"

int process_packet(mssl_manager_t mssl, const int ifidx, const int index, uint32_t cur_ts, unsigned char *pkt_data, int len)
{
  MA_LOG("process_packet");
  struct pkt_ctx pctx;
  struct ethhdr *ethh = (struct ethhdr *)pkt_data;
  int ret = -1;
  uint16_t proto = ntohs(ethh->h_proto);

  switch (proto)
  {
  case ETH_P_IP:
    MA_LOG("This is IPv4 Packet");
    break;
  case ETH_P_ARP:
    MA_LOG("This is ARP Packet");
    break;
  default:
    MA_LOG("Other Packet");
  }

  return 0;
}
