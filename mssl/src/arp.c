#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "include/mssl.h"
#include "include/arp.h"
#include "include/eth_out.h"
#include "include/config.h"
#include "include/logs.h"

#define ARP_PAD_LEN 18
#define ARP_HEAD_LEN 8
#define TS_GEQ(a, b) ((int32_t)((a)-(b)) >= 0)
#define SEC_TO_TS(a) (a * 1000)

enum arp_hrd_format
{
  arp_hrd_ethernet = 1,
};

enum arp_opcode
{
  arp_op_request = 1,
  arp_op_reply = 2,
};

struct arphdr
{
  uint16_t ar_hrd;
  uint16_t ar_pro;
  uint8_t ar_hln;
  uint8_t ar_pln;
  uint16_t ar_op;

  uint8_t ar_sha[ETH_ALEN];
  uint32_t ar_sip;
  uint8_t ar_tha[ETH_ALEN];
  uint32_t ar_tip;

  uint8_t pad[ARP_PAD_LEN];
};

struct arp_queue_entry
{
  uint32_t ip;
  int nif_out;
  uint32_t ts_out;

  TAILQ_ENTRY(arp_queue_entry) arp_link;
};

struct arp_manager
{
  TAILQ_HEAD (, arp_queue_entry) list;
  pthread_mutex_t lock;
};

struct arp_manager g_arpm;

int init_arp_table()
{
  TAILQ_INIT(&g_arpm.list);
  pthread_mutex_init(&g_arpm.lock, NULL);

  return 0;
}

unsigned char *get_hwaddr(uint32_t ip)
{
  int i;
  unsigned char *haddr = NULL;

  for (i=0; i<g_config.mos->netdev_table->num; i++)
  {
    if (ip == g_config.mos->netdev_table->ent[i]->ip_addr)
    {
      haddr = g_config.mos->netdev_table->ent[i]->haddr;
      break;
    }
  }

  return haddr;
}

unsigned char *get_destination_hwaddr(uint32_t dip)
{
  unsigned char *d_haddr = NULL;
  int prefix = 0;
  int i;

  for (i=0; i<g_config.mos->arp_table->num; i++)
  {
    if (g_config.mos->arp_table->ent[i]->prefix == 1)
    {
      if (g_config.mos->arp_table->ent[i]->ip == dip)
      {
        d_haddr = g_config.mos->arp_table->ent[i]->haddr;
        break;
      }
    }
    else
    {
      if ((dip & g_config.mos->arp_table->ent[i]->mask)
          == g_config.mos->arp_table->ent[i]->masked_ip)
      {
        if (g_config.mos->arp_table->ent[i]->prefix > prefix)
        {
          d_haddr = g_config.mos->arp_table->ent[i]->haddr;
          prefix = g_config.mos->arp_table->ent[i]->prefix;
        }
      }
    }
  }

  return d_haddr;
}

static int arp_output(mssl_manager_t mssl, int nif, int opcode,
    uint32_t dst_ip, unsigned char *dst_haddr, unsigned char *target_haddr)
{
  if (!dst_haddr)
    return -1;

  struct arphdr *arph = (struct arphdr *)ethernet_output(mssl, NULL, ETH_P_ARP, 
      nif, dst_haddr, sizeof(struct arphdr), 0);

  if (!arph)
  {
    MA_LOG("Make ARP request failed");
    return -1;
  }

  arph->ar_hrd = htons(arp_hrd_ethernet);
  arph->ar_pro = htons(ETH_P_IP);
  arph->ar_hln = ETH_ALEN;
  arph->ar_pln = 4;
  arph->ar_op = htons(opcode);

  arph->ar_sip = g_config.mos->netdev_table->ent[nif]->ip_addr;
  arph->ar_tip = dst_ip;

  memcpy(arph->ar_sha, g_config.mos->netdev_table->ent[nif]->haddr, arph->ar_hln);

  if (target_haddr)
  {
    memcpy(arph->ar_tha, target_haddr, arph->ar_hln);
  }
  else
  {
    memcpy(arph->ar_tha, dst_haddr, arph->ar_hln);
  }
  memset(arph->pad, 0, ARP_PAD_LEN);

  return 0;
}

int register_arp_entry(uint32_t ip, const unsigned char *haddr)
{
  int idx = g_config.mos->arp_table->num;
  g_config.mos->arp_table->ent[idx] = calloc(1, sizeof(struct _arp_entry));

  if (!g_config.mos->arp_table->ent[idx])
    exit(0);
  g_config.mos->arp_table->ent[idx]->prefix = 32;
  g_config.mos->arp_table->ent[idx]->ip = ip;
  memcpy(g_config.mos->arp_table->ent[idx]->haddr, haddr, ETH_ALEN);
  g_config.mos->arp_table->ent[idx]->mask = -1;
  g_config.mos->arp_table->ent[idx]->masked_ip = ip;

  g_config.mos->arp_table->num = idx + 1;

  MA_LOG("Learned new ARP entry");
  print_arp_table();

  return 0;
}

void request_arp(mssl_manager_t mssl, uint32_t ip, int nif, uint32_t cur_ts)
{
  MA_LOG("Request ARP");
  struct arp_queue_entry *ent;
  unsigned char haddr[ETH_ALEN];
  unsigned char taddr[ETH_ALEN];

  pthread_mutex_lock(&g_arpm.lock);

  TAILQ_FOREACH(ent, &g_arpm.list, arp_link)
  {
    if (ent->ip == ip)
    {
      pthread_mutex_unlock(&g_arpm.lock);
      return;
    }
  }

  ent = (struct arp_queue_entry *)calloc(1, sizeof(struct arp_queue_entry));

  if (!ent)
  {
    MA_LOG("Unable to allocate memory for ARP entry");
    exit(EXIT_FAILURE);
  }

  ent->ip = ip;
  ent->nif_out = nif;
  ent->ts_out = cur_ts;
  TAILQ_INSERT_TAIL(&g_arpm.list, ent, arp_link);
  pthread_mutex_unlock(&g_arpm.lock);

  memset(haddr, 0xFF, ETH_ALEN);
  memset(taddr, 0x00, ETH_ALEN);
  arp_output(mssl, nif, arp_op_request, ip, haddr, taddr);
}

static int process_arp_request(mssl_manager_t mssl, struct arphdr *arph, int nif, uint32_t cur_ts)
{
  MA_LOG("Process ARP Request");
  unsigned char *temp;

  temp = get_destination_hwaddr(arph->ar_sip);
  if (!temp)
  {
    register_arp_entry(arph->ar_sip, arph->ar_sha);
  }

  arp_output(mssl, nif, arp_op_reply, arph->ar_sip, arph->ar_sha, NULL);

  return 0;
}

static int process_arp_reply(mssl_manager_t mssl, struct arphdr *arph, uint32_t cur_ts)
{
  unsigned char *temp;
  struct arp_queue_entry *ent;

  temp = get_destination_hwaddr(arph->ar_sip);
  if (!temp)
  {
    register_arp_entry(arph->ar_sip, arph->ar_sha);
  }

  pthread_mutex_lock(&g_arpm.lock);
  TAILQ_FOREACH(ent, &g_arpm.list, arp_link)
  {
    if (ent->ip == arph->ar_sip)
    {
      TAILQ_REMOVE(&g_arpm.list, ent, arp_link);
      free(ent);
      break;
    }
  }
  pthread_mutex_unlock(&g_arpm.lock);

  return 0;
}

int process_arp_packet(mssl_manager_t mssl, uint32_t cur_ts,
    const int ifidx, unsigned char *pkt_data, int len)
{
  struct arphdr *arph = (struct arphdr *)(pkt_data + sizeof(struct ethhdr));
  int i;
  int to_me = FALSE;

  for (i=0; i<g_config.mos->netdev_table->num; i++)
  {
    if (arph->ar_tip == g_config.mos->netdev_table->ent[i]->ip_addr)
    {
      to_me = TRUE;
    }
  }

  if (!to_me)
    return TRUE;

  switch (ntohs(arph->ar_op))
  {
    case arp_op_request:
      process_arp_request(mssl, arph, ifidx, cur_ts);
      break;

    case arp_op_reply:
      process_arp_reply(mssl, arph, cur_ts);
      break;

    default:
      break;
  }

  return TRUE;
}

void publish_arp(mssl_manager_t mssl)
{
  int i;
  for (i=0; i<g_config.mos->netdev_table->num; i++)
  {
    arp_output(mssl, g_config.mos->netdev_table->ent[i]->ifindex, arp_op_request, 0, NULL, NULL);
  }
}

void arp_timer(mssl_manager_t mssl, uint32_t cur_ts)
{
  struct arp_queue_entry *ent, *ent_tmp;

  pthread_mutex_lock(&g_arpm.lock);
  TAILQ_FOREACH_SAFE(ent, &g_arpm.list, arp_link, ent_tmp)
  {
    if (TS_GEQ(cur_ts, ent->ts_out + SEC_TO_TS(ARP_TIMEOUT_SEC)))
    {
      MA_LOG1d("ARP request timed out", mssl->ctx->cpu);
    }
  }
    pthread_mutex_unlock(&g_arpm.lock);
}

void print_arp_table()
{
  int i;

  MA_LOG("ARP Table:");
  for (i=0; i<g_config.mos->arp_table->num; i++)
  {
    MA_LOGip("IP addr", g_config.mos->arp_table->ent[i]->ip);
    MA_LOGmac("MAC addr", g_config.mos->arp_table->ent[i]->haddr);
  }

  if (g_config.mos->arp_table->num == 0)
  {
    MA_LOG("No ARP Entries in ARP Table");
  }
}

void forward_arp_packet(mssl_manager_t mssl, struct pkt_ctx *pctx)
{
  unsigned char *haddr;

  if  (g_config.mos->nic_forward_table != NULL)
  {
    pctx->out_ifidx = g_config.mos->nic_forward_table->nic_fwd_table[pctx->p.in_ifidx];

    if (pctx->out_ifidx != -1)
    {
      haddr = pctx->p.ethh->h_dest;
      struct arphdr *arph 
        = (struct arphdr *)ethernet_output(mssl, NULL, ETH_P_ARP, 
            pctx->out_ifidx, haddr, sizeof(struct arphdr), 0);

      if (!arph)
        return;
      memcpy(arph, (pctx->p.ethh + 1), sizeof(struct arphdr));
    }
  }
}
