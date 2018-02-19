#include "mb_log.h"
#include "packet.h"
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>

int process_packet(struct pair_entry *p, struct iphdr *iph, int ipl, struct tcphdr *tcph, int tl, uint8_t *reply, int *len)
{
  return _process_packet(p, iph, ipl, tcph, tl, reply, len);
}

int _process_packet(struct pair_entry *p, struct iphdr *iph, int ipl, struct tcphdr *tcph, int tl, uint8_t *reply, int *len)
{
  *len = 0;
  if (tcph->syn)
  {
    MB_LOG1x("SYN packet", tcph->syn);
    MB_LOG1x("ACK packet", tcph->ack);
    iph->ihl = 5;
    iph->version = 4;
    iph->protocol = IPPROTO_TCP;
    iph->ttl = 255;
    iph->saddr = p->daddr;
    iph->daddr = p->saddr;
    iph->tot_len = ipl + tl;
    iph->check = 0x0;
    iph->check = _ip_checksum(iph, ipl);

    tcph->source = htons(p->dport);
    tcph->dest = htons(p->sport);
    tcph->ack_seq = htonl(p->seq + 1);
    tcph->seq = htonl(p->ack);
    tcph->syn = 1;
    tcph->ack = 1;
    tcph->check = 0x0;
    tcph->check = _tcp_checksum(iph, tcph, tl);

    memcpy(reply, iph, ipl);
    memcpy(reply + ipl, tcph, tl);
    *len = ipl + tl;
  }

  return 1;
}

int check_checksum(uint8_t *header, int len)
{
  MB_LOG("Check Checksum");
  int ret;
  struct iphdr *iph = (struct iphdr *) (header);
  int ihl = iph->ihl * 4;
  MB_LOG1d("IP header length", ihl);
  MB_LOG1d("IP packet length", ntohs(iph->tot_len));

  ret = _ip_checksum(iph, ihl);
  if (ret < 0 || ret > 0)
    return -1;

  MB_LOG("IP Checksum verification success");

  struct tcphdr *tcph = (struct tcphdr *) (header + ihl);
  int tl = ntohs(iph->tot_len) - ihl;
  int thl = tcph->doff * 4;
  int pl = tl - thl;

  MB_LOG1d("TCP Segment Length", tl);
  MB_LOG1d("TCP Header Length", thl);
  MB_LOG1d("TCP Payload Length", pl);

  ret = _tcp_checksum(iph, tcph, tl);
  if (ret < 0 || ret > 0)
    return -1;

  MB_LOG("TCP Checksum verification success");

  return 1;
}

int _ip_checksum(struct iphdr *iph, int ihl)
{
  return make_checksum((uint8_t *)iph, ihl);
}

int _tcp_checksum(struct iphdr *iph, struct tcphdr *tcph, int tl)
{
  int ret;
  struct pseudo_tcp *ptcph = (struct pseudo_tcp *)malloc(sizeof(struct pseudo_tcp));
  ptcph->saddr = iph->saddr;
  MB_LOG1x("IP source addr", iph->saddr);
  MB_LOG1x("Pseudo TCP Header", ptcph->saddr);
  ptcph->daddr = iph->daddr;
  ptcph->reserved = 0;
  ptcph->protocol = iph->protocol;
  ptcph->len = htons(tl); // Caution!

  unsigned char check[sizeof(struct pseudo_tcp) + tl];
  memset(check, 0x00, sizeof(struct pseudo_tcp) + tl);
  memcpy(check, ptcph, sizeof(struct pseudo_tcp));
  memcpy(check + sizeof(struct pseudo_tcp), tcph, tl);  
  
  ret = make_checksum((uint8_t *)check, sizeof(struct pseudo_tcp) + tl);
  if (ret < 0)
    return -1;

  free(ptcph);
  return ret;
}

int make_checksum(uint8_t *header, int len)
{
  int i, tmp1, tmp2;
  int checksum = 0;

  if (len == 0)
    return 1;

  for (i=0; i<len; i+=2)
  {
    tmp1 = header[i];
    if (i+1 >= len)
    {
      checksum = checksum + (int)((tmp1 & 0xFF) << 8);
    }
    else
    {
      tmp2 = header[i+1];
      checksum = checksum + (int)(((tmp1 & 0xFF) << 8) | (tmp2 & 0xFF));
    }
  }

  checksum = (checksum & 0xFFFF) + (checksum >> 16);
  checksum = ~checksum & 0xFFFF;

  MB_LOG1x("Checksum Result", checksum);

  return checksum;
}

int parse_entry(struct pair_entry *tmp, uint8_t *buf, int len)
{
  struct iphdr *iph = (struct iphdr *)buf;
  struct tcphdr *tcph = (struct tcphdr *)(buf + iph->ihl * 4);

  tmp->saddr = iph->saddr;
  tmp->daddr = iph->daddr;
  tmp->sport = ntohs(tcph->source);
  tmp->dport = ntohs(tcph->dest);
  tmp->seq = ntohl(tcph->seq);
  if (tcph->ack_seq == 0)
  {
    srand(time(NULL));
    tmp->ack = rand() % INT_MAX;
  }
  else
    tmp->ack = tcph->ack_seq;

  return 1;
}
