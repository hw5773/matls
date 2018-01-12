/**
 * @file middlebox.c
 * @author Hyunwoo Lee
 * @date 12 Jan 2018
 * @brief This file is the main of the middlebox
 */

#include "middlebox.h"
#include "mb_log.h"

int main(int argc, char *argv[])
{
  int sock, ret, i;
  int sockopt;
  int numbytes;
  struct ifreq ifopts;
  struct ifreq if_ip;
  uint8_t buf[BUF_SIZE];
  char if_name[IFNAMSIZ];

  if (argc > 1)
    strcpy(if_name, argv[1]);
  else
    strcpy(if_name, DEFAULT_IF);

  struct ethhdr *eh = (struct ethhdr *) (buf);
  struct iphdr *iph = (struct iphdr *) (buf + sizeof(struct ethhdr));

  memset(&if_ip, 0, sizeof(struct ifreq));

  if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
  {
    perror("listener: socket");
    return -1;
  }

  strncpy(ifopts.ifr_name, if_name, IFNAMSIZ-1);
  ioctl(sock, SIOCGIFFLAGS, &ifopts);
  ifopts.ifr_flags |= IFF_PROMISC;
  ioctl(sock, SIOCSIFFLAGS, &ifopts);

  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) == -1)
  {
    perror("setsockopt");
    close(sock);
    exit(EXIT_FAILURE);
  }

  if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, if_name, IFNAMSIZ-1) == -1) 
  {
    perror("SO_BINDTODEVICE");
    close(sock);
    exit(EXIT_FAILURE);
  }

repeat:
  MB_LOG("listener: Waiting to recvfrom...");
  numbytes = recvfrom(sock, buf, BUF_SIZE, 0, NULL, NULL);
  MB_LOG1d("listener: got packet", numbytes);

  // Check whether the packet is IP packet
  if (ntohs(eh->h_proto) == ETH_P_IP)
  {
    MB_LOG("This is a IP packet");
    MB_LOG1d("IP packet length", ntohs(iph->tot_len));
    MB_LOG1d("IP header length", iph->ihl * 4);
    ret = process_ip((uint8_t *)iph, ntohs(iph->tot_len));

    if (ret < 0)
      goto repeat;
  }
  else
  {
    MB_LOG1d("This is not a IP protocol", eh->h_proto);
    goto repeat;
  }

  // Check whether the transport layer protocol for the packet
  if (iph->protocol == IPPROTO_TCP)
  {
    MB_LOG("This is TCP segment");
    struct tcphdr *tcph = (struct tcphdr *)(buf + sizeof(struct ethhdr) + iph->ihl * 4);
    int tl = ntohs(iph->tot_len) - iph->ihl * 4;
    MB_LOG1d("TCP segment length", tl);
    MB_LOG1d("TCP header length", tcph->doff * 4);
    ret = process_tcp((uint8_t *)tcph, tl);
    
    goto repeat;
  }
  else if (iph->protocol == IPPROTO_UDP)
  {
    MB_LOG("This is UDP segment");
    struct udphdr *udph = (struct udphdr *)(buf + sizeof(struct ethhdr) + iph->ihl * 4);
    int ul = ntohs(iph->tot_len) - iph->ihl * 4;
    MB_LOG1d("UDP segment length", ul);
    MB_LOG1lu("UDP header length", sizeof(struct udphdr));
    ret = process_udp((uint8_t *)udph, ul);
    goto repeat;
  }
  else if (iph->protocol == IPPROTO_ICMP)
  {
    MB_LOG("This is ICMP packet");
    goto repeat;
  }
  else 
  {
    MB_LOG("We don't know what packet this is");
    goto repeat;
  }

done:
  close(sock);
  return ret;
}
