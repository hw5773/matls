#include <assert.h>
#include <string.h>

#include "include/mssl.h"
#include "include/arp.h"
#include "include/socket.h"
#include "include/eth_out.h"
#include "include/ip_out.h"
#include "include/mos_api.h"
#include "include/tls_split.h"
#include "include/tcp_util.h"
#include "include/tcp_in.h"
#include "include/tcp_out.h"
//#include "include/tcp_ring_buffer.h"
//#include "include/eventpoll.h"
#include "include/logs.h"
#include "include/timer.h"
#include "include/ip_in.h"
#include "include/config.h"

extern struct pkt_info *clone_packet_ctx(struct pkt_info *to, unsigned char *frame, struct pkt_info *from);

#define VERIFY_RX_CHECKSUM TRUE

static inline uint32_t detect_stream_type(mssl_manager_t mssl, struct pkt_ctx *pctx,
    uint32_t ip, uint16_t port)
{
  struct sockaddr_in *addr;
  int rc, cnt_match, socktype;
  struct mon_listener *walk;
  struct sfbpf_program fcode;

  cnt_match = 0;
  rc = 0;

  MA_LOG1d("mssl->num_msp", mssl->num_msp);
  if (mssl->num_msp > 0)
  {
    TAILQ_FOREACH(walk, &mssl->monitors, link)
    {
      socktype = walk->socket->socktype;
      if (socktype != MOS_SOCK_SPLIT_TLS)
        continue;

      fcode = walk->stream_syn_fcode;
    /*
      if (!(ISSET_BPFFILTER(fcode) && pctx &&
            EVAL_BPFFILTER(fcode, (uint8_t *)pctx->p.iph - sizeof(struct ethhdr),
              pctx->p.ip_len + sizeof(struct ethhdr)) == 0))
      {
      */
      walk->is_stream_syn_filter_hit = 1;
      cnt_match++;
    //  }

    }

    if (cnt_match > 0)
    {
      rc = STREAM_TYPE(MOS_SOCK_SPLIT_TLS);
      MA_LOG1d("rc result", rc);
    }
  }

  if (mssl->listener)
  {
    addr = &mssl->listener->socket->saddr;
    if (addr->sin_port == port)
    {
      if (addr->sin_addr.s_addr != INADDR_ANY)
      {
        if (ip == addr->sin_addr.s_addr)
        {
          rc |= STREAM_TYPE(MOS_SOCK_STREAM);
        }
        else
        {
          int i;

          for (i=0; i<g_config.mos->netdev_table->num; i++)
          {
            if (ip == g_config.mos->netdev_table->ent[i]->ip_addr)
            {
              rc |= STREAM_TYPE(MOS_SOCK_STREAM);
            }
          }
        }
      }
    }
  }

  return rc;
}

inline void fill_packet_context_tcp_info(struct pkt_ctx *pctx, struct tcphdr *tcph)
{
  pctx->p.tcph = tcph;
  pctx->p.payload = (uint8_t *)tcph + (tcph->doff << 2);
  pctx->p.payloadlen = pctx->p.ip_len - (pctx->p.payload - (uint8_t *)pctx->p.iph);
  pctx->p.seq = ntohl(tcph->seq);
  pctx->p.ack_seq = ntohl(tcph->ack_seq);
  pctx->p.window = ntohs(tcph->window);
  pctx->p.offset = 0;

  return;
}

static inline struct tcp_stream *create_stream(mssl_manager_t mssl, struct pkt_ctx *pctx,
    unsigned int *hash)
{
  MA_LOG("Create Stream");
  tcp_stream *cur_stream = NULL;
  uint32_t stream_type;
  const struct iphdr *iph = pctx->p.iph;
  const struct tcphdr *tcph = pctx->p.tcph;

  if (tcph->syn && !tcph->ack)
  {
    /*
    stream_type = detect_stream_type(mssl, pctx, iph->daddr, tcph->dest);
    if (!stream_type)
    {
      MA_LOG("Refusing SYN packet.");
      return NULL;
    }

    if (stream_type & STREAM_TYPE(MOS_SOCK_SPLIT_TLS))
    {
    */
    /*
      cur_stream = create_client_tcp_stream(mssl, NULL, stream_type,
          pctx->p.iph->saddr, pctx->p.tcph->source,
          pctx->p.iph->daddr, pctx->p.tcph->dest, hash);
    */
      cur_stream = create_dual_tcp_stream(mssl, NULL, MOS_SOCK_SPLIT_TLS,
          pctx->p.iph->saddr, pctx->p.tcph->source,
          pctx->p.iph->daddr, pctx->p.tcph->dest, hash);

      if (!cur_stream)
      {
        MA_LOG("No available space in flow pool");
      }
    /*
    }
    else
    {
    }
    */
    return cur_stream;

  }
  else
  {
    MA_LOG("Weird packet comes");
    return NULL;
  }
}

/*
static inline struct tcp_stream *find_stream(mssl_manager_t mssl, tcp_stream *ret, struct pkt_ctx *pctx, 
    unsigned int *hash)
{
  struct tcp_stream temp_stream;

  // Exchange the source info. and the dest info.
  temp_stream.saddr = pctx->p.iph->daddr;
  temp_stream.sport = pctx->p.tcph->dest;
  temp_stream.daddr = pctx->p.iph->saddr;
  temp_stream.dport = pctx->p.tcph->source;

  ret = HTSearch(mssl->tcp_flow_table, &temp_stream, hash);
  return ret;
}
*/

/*
static void handle_sock_stream(mssl_manager_t mssl, struct tcp_stream *cur_stream,
    struct pkt_ctx *pctx)
{
  update_recv_tcp_context(mssl, cur_stream, pctx);
  do_action_end_tcp_packet(mssl, cur_stream, pctx);
}
*/

void update_monitor(mssl_manager_t mssl, struct tcp_stream *sendside_stream,
    struct tcp_stream *recvside_stream, struct pkt_ctx *pctx, bool is_pkt_reception)
{
  MA_LOG("update monitor");
  struct socket_map *walk;
  assert(pctx);

// clone_packet_ctx

  if (sendside_stream->status_mgmt)
  {
    sendside_stream->cb_events = MOS_ON_PKT_IN;

    if (is_pkt_reception)
    {
      MA_LOG("before update_passive_send_tcp_context");
      update_passive_send_tcp_context(mssl, sendside_stream, pctx);
    }
  }
}

static void handle_monitor_stream(mssl_manager_t mssl, struct tcp_stream *sendside_stream,
    struct tcp_stream *recvside_stream, struct pkt_ctx *pctx)
{
  update_monitor(mssl, sendside_stream, recvside_stream, pctx, true);
  recvside_stream = sendside_stream->pair_stream;

  if (pctx->p.tcph->syn)
  {
    MA_LOG("SYN packet. Now split the session");
    do_split_session(mssl, sendside_stream, recvside_stream, pctx);
  }
  MA_LOG("after do split session");
}
/*
void do_split_session(struct tcp_stream *sendside_stream,
    struct tcp_stream *recvside_stream, struct pkt_ctx *pctx)
{
  MA_LOG("do split session");

  MA_LOGip("sendside source ip", sendside_stream->saddr);
  MA_LOG1d("sendside source port", sendside_stream->sport);
  MA_LOGip("sendside dest ip", sendside_stream->daddr);
  MA_LOG1d("sendside dest port", sendside_stream->dport);

  MA_LOGip("recvside source ip", recvside_stream->saddr);
  MA_LOG1d("recvside source port", recvside_stream->sport);
  MA_LOGip("recvside dest ip", recvside_stream->daddr);
  MA_LOG1d("recvside dest port", recvside_stream->dport);
}
*/
int process_in_tcp_packet(mssl_manager_t mssl, struct pkt_ctx *pctx)
{
  MA_LOG("");
  MA_LOG("process_in_tcp_packet");
  uint64_t events = 0;
  struct tcp_stream *cur_stream;
  struct iphdr *iph;
  struct tcphdr *tcph;
  struct mon_listener *walk;
  unsigned int hash = 0;

  iph = pctx->p.iph;
  tcph = (struct tcphdr *)((uint8_t *)pctx->p.iph + (pctx->p.iph->ihl << 2));

  fill_packet_context_tcp_info(pctx, tcph);

  if (pctx->p.ip_len < ((iph->ihl + tcph->doff) << 2))
    return ERROR;

#if VERIFY_RX_CHECKSUM

  if ((uint16_t) tcp_calc_checksum((uint16_t *)pctx->p.tcph, (tcph->doff << 2) + pctx->p.payloadlen,
        iph->saddr, iph->daddr))
  {
    if (pctx->forward && mssl->num_msp)
      forward_ip_packet(mssl, pctx);
    return ERROR;
  }

#endif
  
  if (ntohs(tcph->dest) != 443)
  {
    if (pctx->forward)
      forward_ip_packet(mssl, pctx);
    return TRUE;
  }

  events |= MOS_ON_PKT_IN;


  struct tcp_stream temp_stream;
  temp_stream.saddr = pctx->p.iph->daddr;
  temp_stream.sport = pctx->p.tcph->dest;
  temp_stream.daddr = pctx->p.iph->saddr;
  temp_stream.dport = pctx->p.tcph->source;
  HTSearch(mssl->tcp_flow_table, cur_stream, &temp_stream, &hash);

  if (!cur_stream)
  {
    /*
    if (mssl->listener == NULL && mssl->num_msp == 0)
    {
      if (pctx->forward)
        forward_ip_packet(mssl, pctx);
      return TRUE;
    }
    */

    cur_stream = create_stream(mssl, pctx, &hash);

    if (!cur_stream)
      events = MOS_ON_ORPHAN;
  }

  if (cur_stream)
  {
    if (cur_stream->rcvvar && cur_stream->rcvvar->rcvbuf)
    {
      MA_LOG("current stream condition success");
      pctx->p.offset = (uint64_t)seq2loff(cur_stream->rcvvar->rcvbuf, pctx->p.seq, 
          cur_stream->rcvvar->irs + 1);
      MA_LOG("seq2loff success");
    }
    handle_monitor_stream(mssl, cur_stream, cur_stream->pair_stream, pctx);
  }
  else
  {
    /*
    struct mon_listener *walk;
    struct sfbpf_program fcode;

    TAILQ_FOREACH(walk, &mssl->monitors, link)
    {
      fcode = walk->stream_orphan_fcode;
      if (!(ISSET_BPFFILTER(fcode) && pctx && 
            EVAL_BPFFILTER(fcode, (uint8_t *)pctx->p.iph - sizeof(struct ethhdr),
              pctx->p.ip_len + sizeof(struct ethhdr)) == 0))
      {
        handle_callback(mssl, MOS_NULL, walk->socket, MOS_SIDE_BOTH, pctx, events);
      }
    }
    */

    if (mssl->listener)
    {
      /*
      if (!tcph->rst)
        send_tcp_packet_standalone(mssl, iph->daddr, tcph->dest, iph->saddr, tcph->source,
            0, pctx->p.seq + pctx->p.payloadlen + 1, 0, TCP_FLAG_RST | TCP_FLAG_ACK, NULL,
            0, pctx->p.cur_ts, 0, 0, -1);
      */
    }
    else if (pctx->forward)
    {
      forward_ip_packet(mssl, pctx);
    }
  }

  return TRUE;
}
